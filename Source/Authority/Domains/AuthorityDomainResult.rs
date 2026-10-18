// SPDX-License-Identifier: MIT
// Domain consumers reconstruct exact certified changes and re-evaluate current authority independently.
use super::ssh::{Grant, Service};
use super::*;
use crate::{
    authority_domains as domains,
    authority_governance::Governance,
    authority_membership as membership,
    authority_objects::Object,
    authority_proof::{Disposition, ExecutedResult, OperationResult},
    trust_bootstrap::Verified,
};
fn references(records: &[Vec<u8>], n: Digest, i: Digest) -> Result<Vec<VersionRef>> {
    Governance::record_versions(n, i, records)
}
fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let f = value.array(arity)?;
    ensure!(
        f[0].uint()? == kind && f[1].uint()? == 1,
        "domain result kind or version differs"
    );
    Ok(f)
}
fn parse_versions(value: &V) -> Result<Vec<VersionRef>> {
    let refs = value
        .list(64)?
        .iter()
        .map(version)
        .collect::<Result<Vec<_>>>()?;
    validate_versions(&refs, 64)?;
    Ok(refs)
}
pub struct Candidate {
    pub value: V,
    pub versions: Vec<VersionRef>,
    pub updates: Vec<(VersionRef, VersionRef)>,
    pub state: State,
    pub records: Vec<Vec<u8>>,
}
pub fn merge(bootstrap: &Verified, records: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let scope = bootstrap.descriptor().scope();
    let mut selected = BTreeMap::new();
    for bytes in bootstrap.governance_records().iter().chain(records) {
        let r = references(
            std::slice::from_ref(bytes),
            scope.network,
            scope.incarnation,
        )?
        .remove(0);
        if let Some((old, _)) = selected.get(&r.index()) {
            let old: &VersionRef = old;
            ensure!(
                r.generation >= old.generation
                    && (r.generation != old.generation || r.digest == old.digest),
                "domain context conflicts with retained governance"
            );
        }
        selected.insert(r.index(), (r, bytes.clone()));
    }
    Ok(selected.into_values().map(|(_, v)| v).collect())
}
pub fn minimum(versions: &[VersionRef], floor: &[VersionRef]) -> Result<()> {
    for current in versions {
        if let Some(old) = floor.iter().find(|r| r.index() == current.index()) {
            ensure!(
                current.generation >= old.generation
                    && (current.generation != old.generation || current.digest == old.digest),
                "domain result is below a retained generation"
            );
        }
    }
    for restriction in floor.iter().filter(|r| matches!(r.kind, 126 | 128 | 130)) {
        let target = match restriction.kind {
            126 => 102,
            128 => 127,
            _ => 129,
        };
        ensure!(
            !versions
                .iter()
                .any(|r| r.kind == target && r.id == restriction.id)
                || versions.contains(restriction),
            "domain result omitted a retained restriction"
        );
    }
    Ok(())
}
pub fn inputs(
    command: &Command,
    state: &State,
    objects: &[crate::authority_objects::Object],
) -> Result<crate::authority_objects::Resolved> {
    let references = command.required_inputs(state)?;
    crate::authority_objects::Resolved::exact(
        &references,
        objects
            .iter()
            .filter(|object| references.contains(object.reference()))
            .cloned()
            .collect(),
    )
}
pub fn derive_keys(state: &mut State) -> Result<()> {
    let records = state.records.values().cloned().collect::<Vec<_>>();
    for record in records {
        if sealed_identity::persistent_kind(record.reference.kind) {
            sealed_identity::reserve_record(state, &record)?;
        } else if record.reference.kind == 132 {
            let s = Service::parse(&record.payload, state.network, state.incarnation)?;
            state.reserve(0, s.profile.native, s.profile.service)?;
        } else if record.reference.kind == 137 {
            let mailbox = domains::mail::Mailbox::parse(&record.payload, state.network)?;
            domains::mail::reserve(state, &mailbox)?;
        } else if record.reference.kind == 133 {
            let g = Grant::parse(&record.payload, state.network)?;
            if g.accepted {
                state.reserve(1, g.native, g.member)?;
            }
        }
    }
    domains::backup::validate_state(state, true)?;
    domains::ssh::validate_state(state)?;
    domains::transfer::validate_state(state)?;
    domains::mail::validate_state(state)?;
    domains::page::validate_context(state)?;
    domains::sealed_identity::validate_state(state, true)?;
    domains::federation::validate_state(state, true)
}
#[allow(clippy::too_many_arguments)]
pub fn verify(
    bootstrap: &Verified,
    prior_state: &State,
    prior_records: &[Vec<u8>],
    intent: &Intent,
    result: &OperationResult,
    executed: &ExecutedResult,
    objects: &[Object],
) -> Result<Candidate> {
    ensure!(
        intent.action == "AuthorityDomain"
            && result.disposition == Disposition::Permit
            && executed.maximum_effect == 1,
        "domain result does not bind its exact pending request"
    );
    let operation = Operation::parse(intent)?;
    let value = wire::decode(&result.value)?;
    let f = record(&value, 201, 5)?;
    ensure!(
        f[2].text()? == "AuthorityDomain",
        "incorrect domain result action"
    );
    let versions = parse_versions(&f[3])?;
    let body = f[4].array(4)?;
    ensure!(
        body[0].text()? == operation.command.name(),
        "domain result has another command"
    );
    let scope = bootstrap.descriptor().scope();
    let returned = body[1]
        .list(
            if matches!(
                &operation.command,
                Command::Page(_)
                    | Command::Backup(_)
                    | Command::Federation(_)
                    | Command::SealedIdentity(_)
                    | Command::SealedPublication(_)
            ) {
                domains::page::MAXIMUM_CONTEXT_RECORDS
            } else {
                domains::mail::MAXIMUM_CONTEXT_RECORDS
            },
        )?
        .iter()
        .map(|r| Record::parse(r.bytes()?, scope.network, scope.incarnation))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        returned
            .windows(2)
            .all(|p| p[0].reference.index() < p[1].reference.index()),
        "domain result records are not sorted and unique"
    );
    let governance = body[2]
        .list(64)?
        .iter()
        .map(|r| Ok(r.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let gov_refs = references(&governance, scope.network, scope.incarnation)?;
    let mut exact_refs = gov_refs.clone();
    exact_refs.extend(returned.iter().map(|r| r.reference.clone()));
    exact_refs.sort_by_key(VersionRef::index);
    ensure!(
        exact_refs == versions,
        "domain result references differ from its exact records"
    );
    let mut selected = prior_records.to_vec();
    for (r, bytes) in gov_refs.iter().zip(&governance) {
        selected.retain(|old| {
            !references(std::slice::from_ref(old), scope.network, scope.incarnation)
                .is_ok_and(|v| v[0].index() == r.index())
        });
        selected.push(bytes.clone());
    }
    membership::sort_records(&mut selected)?;
    let source = merge(bootstrap, &selected)?;
    let source_context = matches!(
        &operation.command,
        Command::Federation(federation::Command::SourceContext { .. })
    );
    let mut before = if source_context {
        // The quorum-selected discovery window does not claim that an older cache is complete.
        // Keep its governance restrictions, and independently check every returned domain floor.
        let mut retained = prior_state
            .records
            .values()
            .map(|r| r.reference.clone())
            .collect::<Vec<_>>();
        retained.extend(references(prior_records, scope.network, scope.incarnation)?);
        minimum(&versions, &retained)?;
        State::empty(scope.network, scope.incarnation)
    } else {
        prior_state.clone()
    };
    let page_indices = if let Command::Page(command) = &operation.command {
        let command_refs = command.command_inputs();
        let command_inputs = crate::authority_objects::Resolved::exact(
            &command_refs,
            objects
                .iter()
                .filter(|o| command_refs.contains(o.reference()))
                .cloned()
                .collect(),
        )?;
        Some(command.mutation_indices(&before, intent, &command_inputs)?)
    } else if let Command::Federation(command) = &operation.command {
        // Returned immutable dependencies are used only to derive exact command-selected identities.
        let mut context = before.clone();
        for r in &returned {
            context
                .records
                .entry(r.reference.index())
                .or_insert_with(|| r.clone());
        }
        Some(
            command
                .mutation_indices(&context)?
                .into_iter()
                .collect::<Vec<_>>(),
        )
    } else if let Command::SealedPublication(command) = &operation.command {
        let mut context = before.clone();
        for r in &returned {
            context
                .records
                .entry(r.reference.index())
                .or_insert_with(|| r.clone());
        }
        Some(command.mutation_indices(&context)?)
    } else if let Command::SealedIdentity(command) = &operation.command {
        Some(command.mutation_indices())
    } else {
        None
    };
    if let Some(indices) = &page_indices {
        ensure!(
            indices
                .iter()
                .all(|index| returned.iter().any(|r| r.reference.index() == *index)),
            "Page result omits a command-derived mutation record"
        );
    }
    let is_mutation = |r: &Record| {
        page_indices.as_ref().map_or_else(
            || Some(r.reference.kind) == operation.command.mutation_kind(),
            |indices| indices.contains(&r.reference.index()),
        )
    };
    let replay = operation.mutation()
        && returned.iter().any(|r| {
            before
                .records
                .get(&r.reference.index())
                .is_some_and(|old| old.reference == r.reference)
                && is_mutation(r)
                && !intent.expected.contains(&r.reference)
        });
    for r in &returned {
        if !operation.mutation() || replay || !is_mutation(r) {
            before.records.insert(r.reference.index(), r.clone());
        }
    }
    derive_keys(&mut before)?;
    let inputs = inputs(&operation.command, &before, objects)?;
    let d = if matches!(
        operation.command,
        Command::SealedIdentity(sealed_identity::Command::Directory { .. })
    ) {
        sealed_identity::verify_directory_result(
            &operation,
            &before,
            &source,
            intent,
            executed.evaluated_at_ms,
            &value,
        )?
    } else {
        operation.prepare_with_inputs(
            &before,
            &source,
            &Reservations(bootstrap.reservations().to_vec()),
            intent,
            executed.evaluated_at_ms,
            replay,
            true,
            &inputs,
        )?
    };
    ensure!(
        d.code == 0
            && d.value == value
            && d.versions == versions
            && executed.expires_at_ms <= d.expires_ms,
        "domain result differs from independent current authorization"
    );
    let mut updates = vec![];
    for r in &returned {
        if let Some(old) = intent
            .expected
            .iter()
            .find(|v| v.index() == r.reference.index())
            && old != &r.reference
        {
            ensure!(
                page_indices
                    .as_ref()
                    .is_none_or(|indices| indices.contains(&r.reference.index())),
                "Page result changed a dependency outside its exact command mutation"
            );
            ensure!(
                old.generation.checked_add(1) == Some(r.reference.generation)
                    && r.predecessor == Some(old.digest),
                "domain update does not bind its exact predecessor"
            );
            updates.push((old.clone(), r.reference.clone()));
        }
    }
    let mut state = d.state.unwrap_or(before);
    for r in returned {
        state.records.insert(r.reference.index(), r);
    }
    if source_context {
        let mut retained = prior_state.clone();
        retained.records.extend(state.records);
        state = retained;
    }
    derive_keys(&mut state)?;
    state.charge()?;
    Ok(Candidate {
        value,
        versions,
        updates,
        state,
        records: selected,
    })
}
