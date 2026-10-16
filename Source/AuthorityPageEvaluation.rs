// SPDX-License-Identifier: MIT
// Every Page effect rechecks exact publication provenance, capability scope and host consent.
use super::*;
use crate::{
    authority_deployment_records::Index,
    authority_governance::{Governance, Requirement},
    authority_membership::current,
};

#[path = "AuthorityPageServing.rs"]
mod serving;
use serving::evaluate_serving;

#[path = "AuthorityPageContext.rs"]
pub(crate) mod context;
use context::Evaluation;

#[derive(Debug)]
struct Capacity;
impl std::fmt::Display for Capacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Page capacity reached")
    }
}
impl std::error::Error for Capacity {}
fn capacity(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Capacity.into())
    }
}

fn result_view(
    c: &Evaluation<'_>,
    command: &Command,
    continuation: Option<Digest>,
) -> Result<(V, Vec<VersionRef>)> {
    capacity(c.selected.len() <= MAXIMUM_CONTEXT_RECORDS)?;
    let mut dependencies = c.dependencies.clone();
    sorted(&mut dependencies).map_err(|_| Capacity)?;
    let mut versions = dependencies
        .iter()
        .filter(|r| !c.selected.contains_key(&r.index()))
        .cloned()
        .collect::<Vec<_>>();
    versions.extend(c.selected.values().map(|r| r.reference.clone()));
    sorted(&mut versions).map_err(|_| Capacity)?;
    let governance = dependencies
        .iter()
        .filter(|r| r.kind < 132 && !c.selected.contains_key(&r.index()))
        .map(|r| Ok(b(c.governance.record_bytes(r.kind, r.id)?)))
        .collect::<Result<Vec<_>>>()?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(c.selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance),
            continuation.map_or(V::Null, |v| b(&v)),
        ]),
    ]);
    wire::encode(&value).map_err(|_| Capacity)?;
    Ok((value, versions))
}

// Admit each complete provenance closure against the same bound as the final response.
fn page_item<T>(
    c: &mut Evaluation<'_>,
    command: &Command,
    id: Digest,
    last: &mut Option<Digest>,
    continuation: &mut Option<Digest>,
    select: impl FnOnce(&mut Evaluation<'_>) -> Result<T>,
) -> Result<bool> {
    let prior = (c.dependencies.clone(), c.selected.clone(), c.expires);
    if c.optional(select).is_none() {
        return Ok(true);
    }
    if let Err(error) = result_view(c, command, Some(id)) {
        c.dependencies = prior.0;
        c.selected = prior.1;
        c.expires = prior.2;
        if !error.is::<Capacity>() || last.is_none() {
            return Err(error);
        }
        *continuation = *last;
        return Ok(false);
    }
    *last = Some(id);
    Ok(true)
}

pub(super) fn grant(operation: &Operation) -> Result<&VersionRef> {
    operation
        .grant
        .as_ref()
        .context("explicit Page capability missing")
}
pub(super) fn add(
    next: &mut State,
    changes: &mut BTreeSet<(u64, Digest)>,
    kind: u64,
    id: Digest,
    payload: V,
) -> Result<()> {
    let generation = next.records.get(&(kind, id)).map_or(Ok(1), |r| {
        r.reference
            .generation
            .checked_add(1)
            .context("Page record generation exhausted")
    })?;
    validate_record(
        kind,
        &payload,
        next.network,
        next.incarnation,
        id,
        generation,
    )?;
    // A semantically valid candidate can still exceed the exact encoded record bound.
    let record = Record::next(next, kind, id, payload).map_err(|_| Capacity)?;
    changes.insert(record.reference.index());
    // Capacity is checked once after the entire deterministic candidate has been built.
    next.records.insert(record.reference.index(), record);
    Ok(())
}
pub fn expected_recipient(
    command: &Command,
    state: &State,
    _records: &[Vec<u8>],
    _reserved: &Reservations,
    intent: &Intent,
) -> Result<Key> {
    match command {
        Command::Content(content::Command::Authorise { host, .. }) => {
            let record = state.record(147, host.id)?;
            ensure!(record.reference == *host, "content host version differs");
            let configured = Host::parse(&record.payload, state.network, state.incarnation)?;
            ensure!(
                !configured.withdrawn && configured.profile.content.is_some(),
                "content host has no current durable consent"
            );
            Ok(configured.profile.service)
        }
        Command::MediaAuthorise { host, .. } => {
            let record = state.record(143, host.id)?;
            ensure!(record.reference == *host, "media host version differs");
            let profile = Host::parse(&record.payload, state.network, state.incarnation)?;
            ensure!(!profile.withdrawn, "media host withdrawn");
            Ok(profile.profile.service)
        }
        _ => Ok(intent.requester),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    operation: &Operation,
    command: &Command,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
    exact: bool,
    inputs: &Resolved,
) -> Result<Decision> {
    ensure!(
        intent.network == state.network && intent.incarnation == state.incarnation,
        "Page context differs"
    );
    let expected = command.required_inputs(state)?;
    ensure!(
        inputs.references() == expected,
        "Page evaluation input closure differs"
    );
    let mut c = Evaluation {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        index: Index::parse(records, reserved, state.network, state.incarnation)?,
        at,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    let mut next = state.clone();
    let mut changed = BTreeSet::new();
    let mut continuation = None;
    let result = (|| -> Result<()> {
        match command {
            Command::LocalSearchLease { items } => {
                for (publication, device) in items {
                    if publication.kind == 113 {
                        super::super::sealed_publication::local_search(
                            &mut c,
                            publication,
                            device.as_ref().context("sealed search device absent")?,
                            intent.requester,
                            grant(operation)?,
                        )?;
                    } else {
                        let record = c.exact(publication)?;
                        let review =
                            Review::parse(&record.payload, state.network, state.incarnation)?;
                        let revision = c.revision(&review.statement.revision, true)?;
                        let (_, ledger, _, _) = c.publication(revision.author.raw_page)?;
                        ensure!(
                            ledger.published.as_ref() == Some(publication),
                            "local search publication changed"
                        );
                        c.principal(
                            intent.requester,
                            grant(operation)?,
                            None,
                            "PagesRead",
                            &revision.author.namespace,
                            Some(revision.author.raw_page),
                            revision.author.source.len() as u64,
                        )?;
                        c.read_capability(
                            grant(operation)?,
                            intent.requester,
                            &[0, 1],
                            (2, revision.author.intent.resource),
                            Some(&revision.author.namespace),
                            0,
                        )?;
                        c.application(
                            intent.requester,
                            grant(operation)?,
                            None,
                            "PagesSearch",
                            &revision.author.namespace,
                            Some(revision.author.raw_page),
                        )?;
                    }
                }
            }
            Command::Content(command) => content::evaluate(
                &mut c,
                operation,
                command,
                intent,
                &mut next,
                &mut changed,
                replay,
            )?,
            Command::Context {
                action,
                scope_kind,
                resource,
                namespace,
            } => {
                if matches!(*action, 0 | 1) {
                    c.read_capability(
                        grant(operation)?,
                        intent.requester,
                        &[*action],
                        (*scope_kind, *resource),
                        namespace.as_deref(),
                        0,
                    )?;
                } else {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[*action],
                        (*scope_kind, *resource),
                        namespace.as_deref(),
                        0,
                    )?;
                }
                if c.governance.record_bytes(127, intent.requester).is_ok()
                    && state.records.contains_key(&(148, intent.requester))
                {
                    c.select(148, intent.requester)?;
                }
                if *action == 26 && *scope_kind == 5 {
                    let r = c
                        .index
                        .deployments
                        .get(resource)
                        .context("Page deployment absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(resource),
                        "Page deployment withdrawn"
                    );
                    c.dependencies.extend([r.reference, r.profile, r.consent]);
                    c.capability(&r.grant, r.registrar, &[13], (5, *resource), None, 0)?;
                }
                if *scope_kind == 2 && state.records.contains_key(&(140, *resource)) {
                    let record = c.select(140, *resource)?;
                    let ledger = Ledger::parse(&record.payload)?;
                    ensure!(
                        namespace.as_ref() == Some(&ledger.namespace)
                            && (*action != 2 || ledger.author == intent.requester),
                        "Page context differs from the existing author or namespace"
                    );
                }
            }
            Command::ApplicationGet { application } => {
                ensure!(
                    operation.grant.is_none(),
                    "Page application context is intrinsic"
                );
                let registration = crate::authority_applications::Registration::parse(
                    c.governance.record_bytes(127, *application)?,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    (intent.requester == registration.owner || intent.requester == *application)
                        && current(at, registration.validity)
                        && c.governance.record_bytes(128, *application).is_err(),
                    "Page application context is not currently owned or active"
                );
                let cap = wire::decode(c.governance.record_bytes(102, registration.grant.id)?)?;
                let cap = cap.array(17)?;
                let action = cap[10]
                    .list(32)?
                    .first()
                    .context("empty application actions")?
                    .uint()?;
                let scope = cap[11]
                    .list(64)?
                    .first()
                    .context("empty application scopes")?
                    .array(2)?;
                c.capability(
                    &registration.grant,
                    *application,
                    &[action],
                    (scope[0].uint()?, id(&scope[1])?),
                    None,
                    0,
                )?;
                c.dependencies.push(registration.reference);
                c.expires = c.expires.min(registration.validity.1);
                if state.records.contains_key(&(148, *application)) {
                    c.select(148, *application)?;
                }
            }
            Command::Application { policy } => {
                ensure!(
                    intent.requester == policy.owner && operation.grant.is_none(),
                    "Page application policy requires its exact owner"
                );
                let registration = crate::authority_applications::Registration::parse(
                    c.governance.record_bytes(127, policy.application)?,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    registration.reference == policy.registration
                        && registration.owner == policy.owner
                        && registration.grant == policy.grant
                        && current(at, registration.validity)
                        && c.governance.record_bytes(128, policy.application).is_err()
                        && policy.expires_ms > at.saturating_add(1250)
                        && policy.expires_ms <= registration.validity.1
                        && !reserved.contains(&policy.application)
                        && !c.index.reserved.contains(&policy.application),
                    "Page application policy exceeds its admitted identity"
                );
                c.dependencies.push(registration.reference);
                for namespace in &policy.namespaces {
                    let pages = policy.pages.clone().unwrap_or_default();
                    for permission in &policy.permissions {
                        let action = match permission.as_str() {
                            "PagesRead" | "MediaRead" => 0,
                            "PagesSearch" => 1,
                            "PagesSubmit" | "MediaSubmit" => 2,
                            _ => 3,
                        };
                        if pages.is_empty() {
                            c.capability(
                                &policy.grant,
                                policy.application,
                                &[action],
                                (1, namespace_id(namespace)?),
                                Some(namespace),
                                0,
                            )?;
                        } else {
                            for page in &pages {
                                c.capability(
                                    &policy.grant,
                                    policy.application,
                                    &[action],
                                    (2, page_id(page)?),
                                    Some(namespace),
                                    0,
                                )?;
                            }
                        }
                    }
                }
                c.expires = c.expires.min(policy.expires_ms);
                if replay {
                    let old = c.select(148, policy.application)?;
                    ensure!(
                        old.payload == b(&policy.envelope),
                        "Page application policy replay differs"
                    );
                } else {
                    match &policy.previous {
                        None => ensure!(
                            !state.records.contains_key(&(148, policy.application)),
                            "Page application policy already exists"
                        ),
                        Some(r) => {
                            c.exact(r)?;
                        }
                    }
                    add(
                        &mut next,
                        &mut changed,
                        148,
                        policy.application,
                        b(&policy.envelope),
                    )?;
                }
            }
            Command::HostRegister { profile } => {
                let grant = grant(operation)?;
                c.capability(
                    grant,
                    intent.requester,
                    &[26],
                    (5, profile.manifest.deployment),
                    None,
                    0,
                )?;
                c.capability(grant, intent.requester, &[5], (3, profile.service), None, 0)?;
                c.profile(profile, true)?;
                let kind = if profile.role == 1 { 147 } else { 143 };
                let host = Host {
                    profile: profile.as_ref().clone(),
                    manager: intent.requester,
                    grant: grant.clone(),
                    withdrawn: false,
                };
                if replay {
                    ensure!(
                        c.select(kind, profile.service)?.payload == host.value(),
                        "Page hosting replay differs"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(kind, profile.service)),
                        "Page host already configured"
                    );
                    add(&mut next, &mut changed, kind, profile.service, host.value())?;
                }
            }
            Command::HostWithdraw {
                role,
                host,
                generation,
            } => {
                let record = c.select(if *role == 1 { 147 } else { 143 }, *host)?;
                let mut configured =
                    Host::parse(&record.payload, state.network, state.incarnation)?;
                ensure!(
                    intent.requester == configured.manager
                        || intent.requester == configured.profile.manifest.operator,
                    "Page hosting withdrawal is not from its owner"
                );
                ensure!(operation.grant.is_none(), "hosting withdrawal is intrinsic");
                if replay {
                    ensure!(
                        configured.withdrawn
                            && generation.checked_add(1) == Some(record.reference.generation),
                        "Page host withdrawal replay differs"
                    );
                } else {
                    ensure!(
                        !configured.withdrawn && record.reference.generation == *generation,
                        "Page host generation differs"
                    );
                    configured.withdrawn = true;
                    add(
                        &mut next,
                        &mut changed,
                        record.reference.kind,
                        *host,
                        configured.value(),
                    )?;
                }
            }
            Command::HostGet { role, host } => {
                let record = c.select(if *role == 1 { 147 } else { 143 }, *host)?;
                let configured = if let Some(grant) = &operation.grant {
                    c.capability(grant, intent.requester, &[5], (3, *host), None, 0)?;
                    c.host(&record.reference, None, true)?
                } else {
                    let configured = c.host(&record.reference, None, false)?;
                    ensure!(
                        intent.requester == configured.manager
                            || intent.requester == configured.profile.manifest.operator,
                        "Page host inspection belongs to another principal"
                    );
                    // Historical ownership supplies withdrawal context only;
                    // it does not restore serving or discretionary permissions.
                    configured
                };
                ensure!(configured.profile.role == *role, "Page host role differs");
            }
            Command::Hosts {
                role,
                namespace,
                after,
            } => {
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[2],
                    (1, namespace_id(namespace)?),
                    Some(namespace),
                    0,
                )?;
                let mut last = None;
                for record in state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == if *role == 1 { 147 } else { 143 })
                {
                    if after.is_some_and(|id| record.reference.id <= id) {
                        continue;
                    }
                    let h = Host::parse(&record.payload, state.network, state.incarnation)?;
                    if h.withdrawn || !h.profile.namespaces.contains(namespace) {
                        continue;
                    }
                    if !page_item(
                        &mut c,
                        command,
                        record.reference.id,
                        &mut last,
                        &mut continuation,
                        |c| c.host(&record.reference, Some(namespace), true),
                    )? {
                        break;
                    }
                }
            }
            Command::Submit { author } => {
                crate::authority_domains::publication_modes::permitted(
                    &mut c,
                    &author.namespace,
                    Some(author.intent.resource),
                    0,
                )?;
                ensure!(
                    intent.requester == author.intent.requester
                        && grant(operation)? == &author.grant
                        && author.expires_ms > at.saturating_add(1250),
                    "Page submission differs from exact author statement"
                );
                let revision = Revision::from_author(author.clone())?;
                let policy = c.principal(
                    intent.requester,
                    &author.grant,
                    author.application.as_ref(),
                    "PagesSubmit",
                    &author.namespace,
                    Some(author.raw_page),
                    author.source.len() as u64,
                )?;
                ensure!(
                    policy.is_some() == author.application.is_some(),
                    "Page author statement omits its exact native application policy"
                );
                let bytes =
                    revision
                        .assets
                        .iter()
                        .try_fold(author.source.len() as u64, |sum, asset| {
                            sum.checked_add(asset.bytes)
                                .context("Page admission bytes overflow")
                        })?;
                c.capability_usage(
                    &author.grant,
                    intent.requester,
                    &[2],
                    (2, author.intent.resource),
                    Some(&author.namespace),
                    [bytes, 1 + revision.assets.len() as u64, 1, 1],
                )?;
                c.expires = c.expires.min(author.expires_ms);
                let old = state.records.get(&(140, author.intent.resource));
                let mut ledger = if let Some(old) = old {
                    let old = c.select(140, old.reference.id)?;
                    Ledger::parse(&old.payload)?
                } else {
                    Ledger {
                        raw_page: author.raw_page,
                        author: intent.requester,
                        namespace: author.namespace.clone(),
                        last_revision: author.intent.revision,
                        pending: None,
                        published: None,
                    }
                };
                ensure!(
                    ledger.author == intent.requester && ledger.namespace == author.namespace,
                    "Page identity has another owner or namespace"
                );
                if replay {
                    let r = c.select(141, revision.identity()?)?;
                    ensure!(
                        r.payload == revision.value()
                            && ledger.pending.as_ref() == Some(&r.reference),
                        "Page submission replay no longer pending"
                    );
                } else {
                    ensure!(
                        old.map_or(Some(1), |r| r.reference.generation.checked_add(1))
                            == Some(author.intent.revision),
                        "Page expected version differs"
                    );
                    let rid = revision.identity()?;
                    ensure!(
                        !state.records.contains_key(&(141, rid)),
                        "Page revision identity reused"
                    );
                    add(&mut next, &mut changed, 141, rid, revision.value())?;
                    let revision_ref = next.record(141, rid)?.reference.clone();
                    let minimum = c.minimum_copies(&author.namespace)?;
                    for manifest in &revision.assets {
                        c.principal(
                            intent.requester,
                            &author.grant,
                            author.application.as_ref(),
                            "MediaSubmit",
                            &author.namespace,
                            Some(author.raw_page),
                            manifest.bytes,
                        )?;
                        let mut hosts = vec![];
                        let mut host_capacities = vec![];
                        let mut expires = author.expires_ms;
                        for host in &manifest.hosts {
                            let host = key(&V::Bytes(hex::decode(host)?))?;
                            let record = c.select(143, host)?;
                            let h = c.host(&record.reference, Some(&author.namespace), true)?;
                            ensure!(
                                manifest.bytes <= h.profile.maximum_asset_bytes,
                                "media asset exceeds selected host maximum"
                            );
                            host_capacities.push((host, h.profile.state_bytes));
                            expires = expires
                                .min(h.profile.manifest.validity.1)
                                .min(at.saturating_add(h.profile.retention_ms));
                            hosts.push(record.reference);
                        }
                        sorted(&mut hosts)?;
                        let copies = u64::from(manifest.copies).max(minimum);
                        ensure!(
                            copies <= hosts.len() as u64,
                            "media placement policy requires more consenting hosts"
                        );
                        let asset = Asset {
                            revision: revision_ref.clone(),
                            manifest: manifest.clone(),
                            hosts,
                            required_copies: copies,
                            upload_expires_ms: expires.min(at.saturating_add(86400000)),
                            expires_ms: expires,
                        };
                        for (host, physical_bytes) in host_capacities {
                            let retained = next
                                .records
                                .values()
                                .filter(|r| r.reference.kind == 144)
                                .map(|r| Asset::parse(&r.payload))
                                .collect::<Result<Vec<_>>>()?
                                .into_iter()
                                .filter(|a| {
                                    a.expires_ms > at && a.hosts.iter().any(|r| r.id == host)
                                })
                                .try_fold(0u64, |sum, a| {
                                    sum.checked_add(media_storage_charge(&a)?)
                                        .context("media reservation accounting overflow")
                                })?;
                            capacity(
                                retained
                                    .checked_add(media_storage_charge(&asset)?)
                                    .is_some_and(|n| {
                                        media_storage_budget(physical_bytes)
                                            .is_ok_and(|budget| n <= budget)
                                    }),
                            )?;
                        }
                        add(
                            &mut next,
                            &mut changed,
                            144,
                            asset.identity()?,
                            asset.value(),
                        )?;
                    }
                    ledger.last_revision = author.intent.revision;
                    ledger.pending = Some(revision_ref);
                    add(
                        &mut next,
                        &mut changed,
                        140,
                        author.intent.resource,
                        ledger.value(),
                    )?;
                }
            }
            Command::Queue { namespace, after }
            | Command::List { namespace, after }
            | Command::SearchList { namespace, after } => {
                let searching = matches!(command, Command::SearchList { .. });
                let queued = matches!(command, Command::Queue { .. });
                let permission = if queued { "ReviewInspect" } else { "PagesRead" };
                let reader_grant = grant(operation)?;
                let own_queue = queued
                    && c.optional(|c| {
                        c.principal(
                            intent.requester,
                            reader_grant,
                            None,
                            permission,
                            namespace,
                            None,
                            0,
                        )
                    })
                    .is_none();
                if own_queue {
                    c.principal(
                        intent.requester,
                        reader_grant,
                        None,
                        "PagesSubmit",
                        namespace,
                        None,
                        0,
                    )?;
                } else if !queued {
                    c.principal(
                        intent.requester,
                        reader_grant,
                        None,
                        permission,
                        namespace,
                        None,
                        0,
                    )?;
                }
                if searching {
                    c.read_capability(
                        reader_grant,
                        intent.requester,
                        &[0, 1],
                        (1, namespace_id(namespace)?),
                        Some(namespace),
                        0,
                    )?;
                    c.application(
                        intent.requester,
                        reader_grant,
                        None,
                        "PagesSearch",
                        namespace,
                        None,
                    )?;
                }
                let mut last = None;
                for record in state.records.values().filter(|r| r.reference.kind == 140) {
                    if after.is_some_and(|id| record.reference.id <= id) {
                        continue;
                    }
                    let ledger = Ledger::parse(&record.payload)?;
                    if ledger.namespace != *namespace
                        || (own_queue && ledger.author != intent.requester)
                    {
                        continue;
                    }
                    let selected = if queued {
                        ledger.pending.as_ref()
                    } else {
                        ledger.published.as_ref()
                    };
                    if selected.is_none() {
                        continue;
                    }
                    if !page_item(
                        &mut c,
                        command,
                        record.reference.id,
                        &mut last,
                        &mut continuation,
                        |c| {
                            if queued {
                                c.select(140, record.reference.id)?;
                                c.revision(selected.unwrap(), true)?;
                            } else {
                                let (_, _, _, revision) = c.publication(ledger.raw_page)?;
                                c.principal(
                                    intent.requester,
                                    reader_grant,
                                    None,
                                    "PagesRead",
                                    namespace,
                                    Some(ledger.raw_page),
                                    revision.author.source.len() as u64,
                                )?;
                                if searching {
                                    c.read_capability(
                                        reader_grant,
                                        intent.requester,
                                        &[0, 1],
                                        (2, revision.author.intent.resource),
                                        Some(namespace),
                                        0,
                                    )?;
                                    c.application(
                                        intent.requester,
                                        reader_grant,
                                        None,
                                        "PagesSearch",
                                        namespace,
                                        Some(ledger.raw_page),
                                    )?;
                                }
                            }
                            Ok(())
                        },
                    )? {
                        break;
                    }
                }
            }
            Command::Inspect { page } => {
                let (_, ledger) = c.ledger(*page)?;
                let pending = ledger.pending.context("Page has no pending revision")?;
                let revision = c.revision(&pending, true)?;
                let permission = if ledger.author == intent.requester {
                    "PagesSubmit"
                } else {
                    "ReviewInspect"
                };
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    permission,
                    &ledger.namespace,
                    Some(*page),
                    revision.author.source.len() as u64,
                )?;
                c.media_metadata(&pending, &revision)?;
                content::select_placement(&mut c, &pending, &revision, false)?;
            }
            Command::Review { review, bundle } => {
                ensure!(
                    intent.requester == review.intent.requester
                        && grant(operation)? == &review.grant
                        && review.expires_ms > at.saturating_add(1250)
                        && review.expires_ms <= at.saturating_add(REVIEW_LIFETIME_MS),
                    "Page decision differs from exact review provenance"
                );
                let revision = c.revision(&review.revision, true)?;
                let (head, mut ledger) = c.ledger(revision.author.raw_page)?;
                ensure!(
                    review.intent.resource == head.reference.id
                        && review.intent.revision == revision.author.intent.revision
                        && review.author == revision.author.intent.requester
                        && review.author_statement == revision.author.intent.digest
                        && review.source == revision.author.source,
                    "Page reviewer statement differs from exact author provenance"
                );
                let policy = c.principal(
                    intent.requester,
                    &review.grant,
                    review.application.as_ref(),
                    "ReviewDecide",
                    &ledger.namespace,
                    Some(ledger.raw_page),
                    revision.author.source.len() as u64,
                )?;
                ensure!(
                    policy.is_some() == review.application.is_some()
                        && policy.as_ref().map(|p| p.review)
                            == review.policy.map(|p| Some((review.mode, p))),
                    "Page review mode differs from current native consent"
                );
                if bundle.is_some() {
                    c.media_complete(&review.revision, &revision, review)?;
                    content::select_placement(&mut c, &review.revision, &revision, true)?;
                }
                c.expires = c.expires.min(review.expires_ms);
                let decision = Review {
                    statement: review.clone(),
                    bundle: bundle.clone(),
                    recorded_ms: if replay {
                        Review::parse(
                            &state.record(142, review.revision.id)?.payload,
                            state.network,
                            state.incarnation,
                        )?
                        .recorded_ms
                    } else {
                        at
                    },
                };
                if replay {
                    ensure!(
                        c.select(142, review.revision.id)?.payload == decision.value()
                            && ledger.pending.is_none()
                            && (!review.approve
                                || ledger
                                    .published
                                    .as_ref()
                                    .is_some_and(|r| r.id == review.revision.id)),
                        "Page review replay differs from retained decision"
                    );
                } else {
                    ensure!(
                        ledger.pending.as_ref() == Some(&review.revision)
                            && !state.records.contains_key(&(142, review.revision.id)),
                        "Page pending revision changed"
                    );
                    add(
                        &mut next,
                        &mut changed,
                        142,
                        review.revision.id,
                        decision.value(),
                    )?;
                    if review.approve {
                        ledger.published =
                            Some(next.record(142, review.revision.id)?.reference.clone());
                    }
                    ledger.pending = None;
                    add(
                        &mut next,
                        &mut changed,
                        140,
                        head.reference.id,
                        ledger.value(),
                    )?;
                }
            }
            Command::Withdraw { page, as_reviewer } => {
                let (head, mut ledger) = c.ledger(*page)?;
                ensure!(
                    *as_reviewer || intent.requester == ledger.author,
                    "Page withdrawal is not from its author"
                );
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    if *as_reviewer {
                        "ReviewDecide"
                    } else {
                        "PagesSubmit"
                    },
                    &ledger.namespace,
                    Some(*page),
                    0,
                )?;
                if replay {
                    ensure!(
                        ledger.pending.is_none() && ledger.published.is_none(),
                        "Page withdrawal replay differs"
                    );
                } else {
                    ledger.pending = None;
                    ledger.published = None;
                    add(
                        &mut next,
                        &mut changed,
                        140,
                        head.reference.id,
                        ledger.value(),
                    )?;
                }
            }
            Command::Read { page } => {
                let (_, _, review, revision) = c.publication(*page)?;
                c.media_metadata(&review.statement.revision, &revision)?;
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    "PagesRead",
                    &revision.author.namespace,
                    Some(*page),
                    revision.author.source.len() as u64,
                )?;
                content::select_placement(&mut c, &review.statement.revision, &revision, false)?;
            }
            _ => evaluate_serving(
                &mut c,
                operation,
                command,
                intent,
                inputs,
                &mut next,
                &mut changed,
                &mut continuation,
                replay,
            )?,
        }
        Ok(())
    })();
    if let Err(error) = result {
        return Ok(Decision::refused(if error.is::<Capacity>() {
            2
        } else {
            3
        }));
    }
    if sorted(&mut c.dependencies).is_err() {
        return Ok(Decision::refused(2));
    }
    if exact
        && !replay
        && ((operation.mutation() && intent.expected != c.dependencies)
            || (!operation.mutation()
                && intent.expected.iter().any(|r| !c.dependencies.contains(r))))
    {
        return Ok(Decision::refused(12));
    }
    if next.charge().is_err() {
        return Ok(Decision::refused(2));
    }
    for index in &changed {
        c.selected.insert(
            *index,
            next.records
                .get(index)
                .context("Page candidate record missing")?
                .clone(),
        );
    }
    let (value, versions) = match result_view(&c, command, continuation) {
        Ok(result) => result,
        Err(error) if error.is::<Capacity>() => return Ok(Decision::refused(2)),
        Err(error) => return Err(error),
    };
    Ok(Decision {
        state: (!changed.is_empty()).then_some(next),
        value,
        versions,
        dependencies: c.dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
