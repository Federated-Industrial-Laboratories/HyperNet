// SPDX-License-Identifier: MIT
// Preview discloses complete bounded impact and apply compares the reviewed policy view atomically.
use super::{
    State,
    transactions::{Decision, Evaluation},
};
use crate::{
    authority_domains::{self as domains, page},
    authority_governance::{Governance, Requirement},
    authority_membership::reference,
    authority_proof::{Digest, Intent, VersionRef},
    authority_tiers::{self as tiers, Operation, Spec},
    consensus::records::Configuration,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn value(name: &str, versions: &[VersionRef], body: V) -> V {
    a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(name.into()),
        a(versions.iter().map(reference).collect()),
        body,
    ])
}
fn refused(expires: u64, code: u64) -> Decision {
    Decision {
        code,
        value: V::Null,
        expires,
        records: None,
        domains: None,
        terminal: None,
        restrictions: Default::default(),
        admissions: vec![],
        created: None,
    }
}
fn identifiers(value: &V, ids: &mut BTreeSet<Digest>) {
    match value {
        V::Bytes(bytes) => {
            if let Ok(id) = bytes.as_slice().try_into() {
                ids.insert(id);
            }
        }
        V::Array(values) => {
            for value in values {
                identifiers(value, ids);
            }
        }
        _ => (),
    }
}
fn domain_dependencies(
    record: &domains::Record,
    state: &domains::State,
) -> Result<BTreeSet<Digest>> {
    let mut ids = BTreeSet::from([record.reference.id]);
    // Signed recipient and sealed records retain their validated decoded payload here.
    // Other byte strings stay opaque unless their record schema names signed metadata.
    identifiers(&record.payload, &mut ids);
    match record.reference.kind {
        141 => {
            let author =
                page::Revision::parse(&record.payload, state.network, state.incarnation)?.author;
            ids.extend([author.intent.requester, author.intent.resource]);
            identifiers(&wire::decode(&author.intent.parameters)?, &mut ids);
        }
        142 => {
            let review =
                page::Review::parse(&record.payload, state.network, state.incarnation)?.statement;
            ids.extend([review.intent.requester, review.intent.resource]);
            identifiers(&wire::decode(&review.intent.parameters)?, &mut ids);
        }
        148 => {
            let policy = page::ApplicationPolicy::parse(
                record.payload.bytes()?,
                state.network,
                state.incarnation,
            )?;
            ids.extend([
                policy.application,
                policy.owner,
                policy.registration.id,
                policy.grant.id,
            ]);
            ids.extend(policy.previous.map(|r| r.id));
            ids.extend(policy.review.map(|(_, id)| id));
        }
        _ => (),
    }
    Ok(ids)
}
pub(super) fn impacts(state: &State, tier: Digest, proposal: Digest) -> Result<Vec<V>> {
    let mut changed = BTreeSet::from([tier]);
    let mut records = state
        .records
        .iter()
        .map(|r| {
            let mut ids = BTreeSet::new();
            identifiers(&wire::decode(r)?, &mut ids);
            Ok((crate::authority_applications::record_reference(r)?, ids))
        })
        .collect::<Result<Vec<_>>>()?;
    records.extend(
        state
            .domains
            .records
            .values()
            .map(|r| Ok((r.reference.clone(), domain_dependencies(r, &state.domains)?)))
            .collect::<Result<Vec<_>>>()?,
    );
    let mut selected = BTreeMap::new();
    // Every discovered dependency strictly enlarges the finite selected set.
    loop {
        let before = changed.len();
        for (r, dependencies) in &records {
            if r.kind == 101 {
                continue;
            }
            if !dependencies.is_disjoint(&changed) {
                changed.insert(r.id);
                selected.insert(r.index(), r.clone());
            }
        }
        if before == changed.len() {
            break;
        }
    }
    let mut subjects: BTreeMap<(u64, Digest), Vec<VersionRef>> = BTreeMap::new();
    for r in selected.into_values() {
        let category = match r.kind {
            102 | 125 | 127 | 128 => 0,
            105 | 117 | 129 | 130 | 132 | 134 | 136 | 143 | 147 | 152 | 165 => 1,
            159..=161 => 2,
            107..=111 => 4,
            150 | 151 | 157 => 5,
            _ => 3,
        };
        subjects.entry((category, r.id)).or_default().push(r);
    }
    ensure!(
        subjects.len() <= tiers::MAX_IMPACTS,
        "tier preview impact bound exceeded"
    );
    subjects
        .into_iter()
        .map(|((category, id), versions)| {
            let before = wire::digest(&wire::encode_state(&a(versions
                .iter()
                .map(reference)
                .collect()))?);
            Ok(a(vec![
                V::Uint(category),
                b(&id),
                b(&before),
                b(&proposal),
                V::Uint(4),
            ]))
        })
        .collect()
}
fn view_digest(state: &State, proposal: Digest) -> Result<Digest> {
    let mut refs = state
        .records
        .iter()
        .map(|v| crate::authority_applications::record_reference(v))
        .collect::<Result<Vec<_>>>()?;
    refs.extend(state.domains.records.values().map(|r| r.reference.clone()));
    refs.sort_by_key(VersionRef::index);
    Ok(wire::digest(&wire::encode_state(&a(vec![
        V::Text("TierPolicyView".into()),
        b(&proposal),
        a(refs.iter().map(reference).collect()),
    ]))?))
}
fn cursor(view: Digest, page: usize) -> Result<Digest> {
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Text("TierImpactCursor".into()),
        b(&view),
        V::Uint(page as u64),
    ]))?))
}
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate(
    operation: &Operation,
    state: &State,
    config: &Configuration,
    prior: &[u8],
    intent: &Intent,
    ev: Evaluation,
) -> Result<Decision> {
    let mut out = refused(ev.expires, 3);
    let governance = Governance::parse(intent.network, intent.incarnation, &state.records)?;
    let snapshot = operation.snapshot();
    if snapshot.epoch != config.scope.epoch
        || snapshot.height > state.height
        || snapshot.height == state.height && snapshot.state != wire::digest(prior)
    {
        out.code = 12;
        return Ok(out);
    }
    let current = governance.versions();
    let mut dependencies = BTreeMap::new();
    let mut expiry = ev.expires;
    let authority = (|| -> Result<()> {
        ensure!(
            governance.record_bytes(127, intent.requester).is_err(),
            "applications cannot administer tiers"
        );
        let mut scopes = vec![(0, intent.network)];
        match operation {
            Operation::Context { tier: Some(id), .. } => {
                scopes = Spec::from_record(
                    governance.record_bytes(101, *id)?,
                    intent.network,
                    intent.incarnation,
                )?
                .0
                .scopes
            }
            Operation::Context { tier: None, .. } => {
                let grant = wire::decode(governance.record_bytes(102, operation.grant())?)?;
                let scope = grant.array(17)?[11]
                    .list(64)?
                    .first()
                    .context("administrative grant has no scope")?
                    .array(2)?;
                scopes = vec![(scope[0].uint()?, scope[1].fixed()?)];
            }
            Operation::Change { previous, spec, .. } => {
                scopes = spec.scopes.clone();
                if let Some(bytes) = previous {
                    scopes.extend(
                        Spec::from_record(bytes, intent.network, intent.incarnation)?
                            .0
                            .scopes,
                    );
                }
            }
            _ => {}
        }
        scopes.sort();
        scopes.dedup();
        for scope in scopes {
            let cap = governance.current_capability(
                operation.grant(),
                &Requirement {
                    subject: intent.requester,
                    actions: &[9],
                    scope,
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: ev.at,
                    expected: &[],
                },
            )?;
            expiry = expiry.min(cap.expires_ms);
            for r in cap.dependencies {
                dependencies.insert(r.index(), r);
            }
        }
        Ok(())
    })();
    if authority.is_err() {
        return Ok(out);
    }
    out.expires = expiry;
    match operation {
        Operation::Context { tier, .. } => {
            if let Some(tier) = tier {
                let Some(r) = current.iter().find(|r| r.kind == 101 && r.id == *tier) else {
                    return Ok(out);
                };
                dependencies.insert(r.index(), r.clone());
            }
            let refs = dependencies.into_values().collect::<Vec<_>>();
            out.value = value(
                &intent.action,
                &refs,
                a(refs
                    .iter()
                    .map(|r| Ok(b(governance.record_bytes(r.kind, r.id)?)))
                    .collect::<Result<Vec<_>>>()?),
            );
        }
        Operation::List { after, .. } => {
            let selected = current
                .iter()
                .filter(|r| r.kind == 101 && after.is_none_or(|id| r.id > id))
                .take(33)
                .cloned()
                .collect::<Vec<_>>();
            let rows = selected.iter().take(32).collect::<Vec<_>>();
            let next = if selected.len() > 32 {
                rows.last().map(|r| r.id)
            } else {
                None
            };
            for r in &rows {
                dependencies.insert(r.index(), (*r).clone());
            }
            let refs = dependencies.into_values().collect::<Vec<_>>();
            let mut f = value(
                &intent.action,
                &refs,
                a(rows
                    .iter()
                    .map(|r| Ok(b(governance.record_bytes(101, r.id)?)))
                    .collect::<Result<Vec<_>>>()?),
            )
            .array(5)?
            .to_vec();
            f.push(next.map_or(V::Null, |v| b(&v)));
            out.value = a(f);
        }
        Operation::Change {
            previous,
            spec,
            token,
            apply,
            ..
        } => {
            if previous.is_none() && current.iter().filter(|r| r.kind == 101).count() >= 256 {
                out.code = 2;
                return Ok(out);
            }
            let old = previous
                .as_ref()
                .map(|v| Spec::from_record(v, intent.network, intent.incarnation))
                .transpose()?;
            if !ev.replay
                && match &old {
                    Some((_, r)) => {
                        !current.contains(r)
                            || governance.record_bytes(101, r.id)? != previous.as_ref().unwrap()
                    }
                    None => current.iter().any(|r| r.kind == 101 && r.id == spec.id),
                }
            {
                out.code = 12;
                return Ok(out);
            }
            if let Some((_, r)) = &old {
                dependencies.insert(r.index(), r.clone());
            }
            let deps = dependencies.into_values().collect::<Vec<_>>();
            if deps.len() > 64 {
                out.code = 2;
                return Ok(out);
            }
            if !ev.replay && deps != intent.expected {
                out.code = 12;
                return Ok(out);
            }
            let proposal = operation.request_digest(intent)?;
            let view = view_digest(state, proposal)?;
            if *apply {
                if impacts(state, spec.id, proposal).is_err() {
                    out.code = 33;
                    return Ok(out);
                }
                let record = operation
                    .derive(intent)?
                    .context("tier apply produced no record")?;
                let created = tiers::record_reference(&record, intent.network, intent.incarnation)?;
                if ev.replay {
                    if governance.record_bytes(101, spec.id).ok() != Some(record.as_slice()) {
                        out.code = 12;
                        return Ok(out);
                    }
                } else {
                    if *token != Some(view) {
                        out.code = 12;
                        return Ok(out);
                    }
                    let mut records = state
                        .records
                        .iter()
                        .filter(|v| {
                            crate::authority_applications::record_reference(v)
                                .is_ok_and(|r| r.index() != created.index())
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    records.push(record.clone());
                    crate::authority_membership::sort_records(&mut records)?;
                    if records.len() > crate::authority_capacity::MAX_RECORDS
                        || Governance::parse(intent.network, intent.incarnation, &records).is_err()
                    {
                        out.code = 2;
                        return Ok(out);
                    }
                    out.records = Some(records);
                }
                let height = if ev.replay {
                    state.evidence.creation_height(&created)?
                } else {
                    state
                        .height
                        .checked_add(1)
                        .context("tier creation height exhausted")?
                };
                let mut refs = deps;
                refs.retain(|r| r.index() != created.index());
                refs.push(created.clone());
                refs.sort_by_key(VersionRef::index);
                let mut f = value(&intent.action, &refs, b(&record)).array(5)?.to_vec();
                f.push(V::Uint(height));
                out.value = a(f);
                out.created = Some(created);
            } else {
                let impacts = match impacts(state, spec.id, proposal) {
                    Ok(v) => v,
                    Err(_) => {
                        out.code = 33;
                        return Ok(out);
                    }
                };
                let pages = impacts.len().div_ceil(tiers::IMPACT_PAGE).max(1);
                let page = match token {
                    None => 0,
                    Some(token) => {
                        let found = (1..pages).find(|p| cursor(view, *p).ok() == Some(*token));
                        let Some(page) = found else {
                            out.code = 32;
                            return Ok(out);
                        };
                        page
                    }
                };
                let start = page * tiers::IMPACT_PAGE;
                let end = (start + tiers::IMPACT_PAGE).min(impacts.len());
                let digest = wire::digest(&wire::encode_state(&a(impacts.clone()))?);
                let next = if page + 1 < pages {
                    Some(cursor(view, page + 1)?)
                } else {
                    None
                };
                out.value = value(
                    &intent.action,
                    &deps,
                    a(vec![
                        b(&proposal),
                        b(&view),
                        b(&digest),
                        V::Uint(impacts.len() as u64),
                        V::Uint(page as u64),
                        a(impacts[start..end].to_vec()),
                        next.map_or(V::Null, |v| b(&v)),
                    ]),
                );
            }
        }
    }
    wire::encode(&out.value)?;
    out.code = 0;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn grant_evaluate(
    reviewed: &crate::authority_grant_review::Operation,
    state: &State,
    config: &Configuration,
    prior: &[u8],
    intent: &Intent,
    ev: Evaluation,
    inputs: &crate::authority_objects::Resolved,
) -> Result<Decision> {
    let operation = super::transactions::Operation::parse(&reviewed.inner, config)?;
    let proposal = reviewed.request_digest()?;
    let view = view_digest(state, proposal)?;
    if reviewed.apply && !ev.replay && reviewed.token != Some(view) {
        return Ok(refused(ev.expires, 12));
    }
    let target = match &operation {
        super::transactions::Operation::Mutation(
            crate::authority_membership::Mutation::Delegate { parent, .. },
        ) => parent.id,
        super::transactions::Operation::Revoke { target, .. } => target.id,
        _ => anyhow::bail!("unsupported reviewed grant mutation"),
    };
    let impacts = match impacts(state, target, proposal) {
        Ok(v) => v,
        Err(_) => return Ok(refused(ev.expires, 33)),
    };
    let mut selected = super::transactions::evaluate(
        &operation,
        state,
        config,
        prior,
        &reviewed.inner,
        ev,
        inputs,
    )?;
    if selected.code != 0 {
        return Ok(selected);
    }
    let fields = selected.value.list(6)?;
    let dependencies = a(fields[3]
        .list(64)?
        .iter()
        .filter(|v| {
            selected
                .created
                .as_ref()
                .is_none_or(|created| **v != reference(created))
        })
        .cloned()
        .collect());
    if reviewed.apply {
        let mut fields = fields.to_vec();
        fields[2] = V::Text(intent.action.clone());
        selected.value = a(fields);
        return Ok(selected);
    }
    let pages = impacts.len().div_ceil(tiers::IMPACT_PAGE).max(1);
    let page = match reviewed.token {
        None => 0,
        Some(token) => {
            let Some(page) = (1..pages).find(|p| cursor(view, *p).ok() == Some(token)) else {
                return Ok(refused(selected.expires, 32));
            };
            page
        }
    };
    let start = page * tiers::IMPACT_PAGE;
    let end = (start + tiers::IMPACT_PAGE).min(impacts.len());
    let impact_digest = wire::digest(&wire::encode_state(&a(impacts.clone()))?);
    let next = if page + 1 < pages {
        Some(cursor(view, page + 1)?)
    } else {
        None
    };
    let mut out = refused(selected.expires, 0);
    out.value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(intent.action.clone()),
        dependencies,
        a(vec![
            b(&proposal),
            b(&view),
            b(&impact_digest),
            V::Uint(impacts.len() as u64),
            V::Uint(page as u64),
            a(impacts[start..end].to_vec()),
            next.map_or(V::Null, |v| b(&v)),
        ]),
    ]);
    wire::encode(&out.value)?;
    Ok(out)
}
