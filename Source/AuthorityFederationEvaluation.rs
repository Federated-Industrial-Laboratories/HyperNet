// SPDX-License-Identifier: MIT
// Ordered federation decisions recheck local rights and exact current counterpart evidence.
use super::*;
use crate::{authority_deployment_records::Index, authority_governance::Governance};
#[path = "AuthorityFederationPublication.rs"]
mod publication;
use publication::*;
#[path = "AuthorityFederationResult.rs"]
mod output;
use output::*;
#[path = "AuthorityFederationContent.rs"]
mod content;
#[path = "AuthorityFederationMedia.rs"]
mod media;

fn grant(operation: &Operation) -> Result<&VersionRef> {
    operation
        .grant
        .as_ref()
        .context("explicit federation capability missing")
}
fn put(
    c: &mut page::Evaluation<'_>,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    kind: u64,
    id: Digest,
    payload: V,
    replay: bool,
) -> Result<()> {
    if replay {
        ensure!(
            c.select(kind, id)?.payload == payload,
            "federation retry differs from retained exact result"
        );
    } else {
        let record = Record::next(next, kind, id, payload)?;
        changed.insert(record.reference.index());
        next.records.insert(record.reference.index(), record);
    }
    Ok(())
}
fn expected(c: &mut page::Evaluation<'_>, reference: &VersionRef, replay: bool) -> Result<Record> {
    let r = c.select(reference.kind, reference.id)?;
    ensure!(
        r.reference == *reference
            || replay
                && reference.generation.checked_add(1) == Some(r.reference.generation)
                && r.predecessor == Some(reference.digest),
        "federation exact predecessor changed"
    );
    Ok(r)
}
fn service(
    c: &mut page::Evaluation<'_>,
    intent: &Intent,
    operation: &Operation,
    agreement: &Agreement,
    bridge: &VersionRef,
) -> Result<Bridge> {
    ensure!(
        operation.grant.is_none(),
        "bridge maintenance cannot borrow a member capability"
    );
    let b = c.federation_bridge(bridge, &agreement.treaty)?;
    ensure!(
        intent.requester == b.profile.service,
        "operation is not from its exact local bridge"
    );
    Ok(b)
}
fn foreign_floor(
    c: &mut page::Evaluation<'_>,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    verified: &VerifiedForeign,
    replay: bool,
) -> Result<()> {
    put(
        c,
        next,
        changed,
        157,
        verified.floor.trust,
        verified.floor.value()?,
        replay,
    )
}
pub fn expected_recipient(
    command: &Command,
    state: &State,
    _records: &[Vec<u8>],
    _reserved: &Reservations,
    intent: &Intent,
) -> Result<Key> {
    if let Command::ContentAuthorise { host, .. } = command {
        let r = state.record(147, host.id)?;
        ensure!(
            r.reference == *host,
            "foreign content recipient host changed"
        );
        let selected = page::Host::parse(&r.payload, state.network, state.incarnation)?;
        ensure!(
            selected.profile.role == 1 && selected.profile.content.is_some() && !selected.withdrawn,
            "foreign content recipient lacks active role1 consent"
        );
        Ok(selected.profile.service)
    } else if let Command::MediaAuthorise { host, .. } = command {
        let r = state.record(143, host.id)?;
        ensure!(r.reference == *host, "foreign media recipient host changed");
        let selected = page::Host::parse(&r.payload, state.network, state.incarnation)?;
        ensure!(
            selected.profile.role == 2 && !selected.withdrawn,
            "foreign media recipient is not an active role2"
        );
        Ok(selected.profile.service)
    } else {
        Ok(intent.requester)
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
    let mut c = page::Evaluation {
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
    let mut cursor = None;
    let decision = (|| -> Result<()> {
        match command {
            Command::ContentAuthorise { .. } => content::authorise(
                &mut c,
                operation,
                command,
                intent,
                &mut next,
                &mut changed,
                replay,
            )?,
            Command::MediaGet { .. }
            | Command::MediaAuthorise { .. }
            | Command::MediaReceipt { .. }
            | Command::MediaInspect { .. } => media::evaluate_media(
                &mut c,
                operation,
                command,
                intent,
                &mut next,
                &mut changed,
                replay,
            )?,
            Command::InventoryContext { agreement, action } => {
                let selected = c.select(151, *agreement)?;
                let accepted = c.federation_agreement(&selected.reference)?;
                ensure!(
                    accepted
                        .treaty
                        .destination
                        .matches(state.network, state.incarnation),
                    "foreign inventory belongs to destination network"
                );
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[*action],
                    (
                        1,
                        page::namespace_id(&accepted.treaty.destination_namespace)?,
                    ),
                    Some(&accepted.treaty.destination_namespace),
                    0,
                )?;
                c.application(
                    intent.requester,
                    grant(operation)?,
                    None,
                    if *action == 0 {
                        "PagesRead"
                    } else {
                        "ReviewInspect"
                    },
                    &accepted.treaty.destination_namespace,
                    None,
                )?;
                c.select(157, accepted.foreign.id)?;
            }
            Command::PageContext {
                agreement,
                page: raw,
                action,
            } => {
                let r = c.select(151, *agreement)?;
                let accepted = c.federation_agreement(&r.reference)?;
                c.select(157, accepted.foreign.id)?;
                if *action == 4 {
                    ensure!(
                        accepted
                            .treaty
                            .source
                            .matches(state.network, state.incarnation),
                        "author context belongs to source network"
                    );
                    let (_, _, _, revision) = c.publication(*raw)?;
                    ensure!(
                        revision.author.intent.requester == intent.requester
                            && revision.author.namespace == accepted.treaty.source_namespace,
                        "share context belongs to another author or namespace"
                    );
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[4],
                        (2, page::page_id(raw)?),
                        Some(&revision.author.namespace),
                        0,
                    )?;
                    c.application(
                        intent.requester,
                        grant(operation)?,
                        revision.author.application.as_ref(),
                        "PagesSubmit",
                        &revision.author.namespace,
                        Some(*raw),
                    )?;
                    let id = share_id(*agreement, *raw)?;
                    if state.records.contains_key(&(153, id)) {
                        c.select(153, id)?;
                    }
                } else {
                    ensure!(
                        accepted
                            .treaty
                            .destination
                            .matches(state.network, state.incarnation),
                        "reader context belongs to destination network"
                    );
                    let id = qualified_page(*agreement, &accepted.treaty.source, *raw)?;
                    let selected = c.select(154, id)?;
                    let head = ForeignPage::parse(&selected.payload)?;
                    let revision = if *action == 0 {
                        Some(c.federation_revision(id, true)?.3)
                    } else if let Some(pending) = &head.pending {
                        Some(ForeignRevision::parse(&c.exact(pending)?.payload)?)
                    } else if let Some(published) = &head.published {
                        let reviewed = ForeignReview::parse(
                            &c.exact(published)?.payload,
                            state.network,
                            state.incarnation,
                        )?;
                        Some(ForeignRevision::parse(
                            &c.exact(&reviewed.revision)?.payload,
                        )?)
                    } else {
                        None
                    };
                    c.federation_principal(
                        intent.requester,
                        grant(operation)?,
                        None,
                        *action,
                        &accepted.treaty,
                        id,
                        *raw,
                        0,
                    )?;
                    if *action == 0 {
                        current_review(
                            &mut c,
                            &head,
                            &accepted.treaty,
                            revision
                                .as_ref()
                                .context("foreign publication context missing")?,
                        )?;
                    }
                    if let Some(revision) = revision {
                        let record = state.record(155, revision.identity()?)?;
                        c.federation_page_media_context(
                            &record.reference,
                            &revision,
                            &accepted.treaty,
                        )?;
                    }
                }
            }
            Command::Context {
                action,
                resource,
                namespace,
            } => {
                let scope = if *action == 26 { 5 } else { 2 };
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[*action],
                    (scope, *resource),
                    namespace.as_deref(),
                    0,
                )?;
                if scope == 5 {
                    let d = c
                        .index
                        .deployments
                        .get(resource)
                        .context("federation deployment context absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(resource),
                        "federation deployment withdrawn"
                    );
                    c.dependencies.extend([d.reference, d.profile, d.consent]);
                    c.capability(&d.grant, d.registrar, &[13], (5, *resource), None, 0)?;
                }
                for kind in [150, 151, 152, 153, 154, 155, 156, 157] {
                    if state.records.contains_key(&(kind, *resource)) {
                        c.select(kind, *resource)?;
                    }
                }
                if state.records.contains_key(&(140, *resource)) {
                    let ledger = page::Ledger::parse(&c.select(140, *resource)?.payload)?;
                    c.publication(ledger.raw_page)?;
                }
            }
            Command::TrustAccept {
                bootstrap,
                identity,
            } => {
                let id = command.resource();
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[22],
                    (2, id),
                    None,
                    bootstrap.len() as u64,
                )?;
                let trust = ForeignTrust {
                    bootstrap: bootstrap.clone(),
                    identity: identity.clone(),
                    approver: intent.requester,
                    grant: grant(operation)?.clone(),
                    withdrawn: false,
                };
                ForeignTrust::parse(&trust.value(), state.network, state.incarnation)?;
                ensure!(
                    replay || !state.records.contains_key(&(150, id)),
                    "foreign identity is already accepted or withdrawn"
                );
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    150,
                    id,
                    trust.value(),
                    replay,
                )?;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    157,
                    id,
                    ForeignFloor::initial(id).value()?,
                    replay,
                )?;
            }
            Command::TrustGet { trust } => {
                let existing = ForeignTrust::parse(
                    &c.select(150, *trust)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                if operation.grant.is_none() {
                    ensure!(
                        existing.approver == intent.requester,
                        "trust metadata belongs to another owner"
                    );
                } else {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[22],
                        (2, *trust),
                        None,
                        0,
                    )?;
                }
                c.select(150, *trust)?;
                c.select(157, *trust)?;
            }
            Command::TrustWithdraw { trust } => {
                let r = expected(&mut c, trust, replay)?;
                let mut value = ForeignTrust::parse(&r.payload, state.network, state.incarnation)?;
                if intent.requester != value.approver {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[22],
                        (2, trust.id),
                        None,
                        0,
                    )?;
                }
                value.withdrawn = true;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    150,
                    trust.id,
                    value.value(),
                    replay,
                )?;
            }
            Command::Accept { treaty, foreign } => {
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[22],
                    (2, treaty.id),
                    None,
                    0,
                )?;
                let trust = ForeignTrust::parse(
                    &c.exact(foreign)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                let source = treaty.source_side(state.network, state.incarnation)?;
                ensure!(
                    !trust.withdrawn
                        && &trust.identity == treaty.foreign(source)
                        && treaty.expires_ms > at.saturating_add(1250)
                        && (replay || !state.records.contains_key(&(151, treaty.id))),
                    "treaty is expired, mismatched or already accepted"
                );
                c.capability(
                    &trust.grant,
                    trust.approver,
                    &[22],
                    (2, trust.identity()?),
                    None,
                    0,
                )?;
                let value = Agreement {
                    treaty: treaty.clone(),
                    foreign: foreign.clone(),
                    approver: intent.requester,
                    grant: grant(operation)?.clone(),
                    withdrawn: false,
                };
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    151,
                    treaty.id,
                    value.value(),
                    replay,
                )?;
                c.expires = c.expires.min(treaty.expires_ms);
            }
            Command::Get { agreement } => {
                let r = c.select(151, *agreement)?;
                let value = Agreement::parse(&r.payload, state.network, state.incarnation)?;
                if intent.requester
                    == value
                        .treaty
                        .bridge(value.treaty.source_side(state.network, state.incarnation)?)
                {
                    let bridge = c.select(152, intent.requester)?;
                    c.federation_bridge(&bridge.reference, &value.treaty)?;
                    ensure!(
                        operation.grant.is_none(),
                        "bridge context must use intrinsic service authority"
                    );
                } else if operation.grant.is_none() {
                    ensure!(
                        value.approver == intent.requester,
                        "agreement metadata belongs to another owner"
                    );
                } else {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[22],
                        (2, *agreement),
                        None,
                        0,
                    )?;
                }
                c.select(150, value.foreign.id)?;
                c.select(157, value.foreign.id)?;
            }
            Command::Agreements { after } => {
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[22],
                    (0, state.network),
                    None,
                    0,
                )?;
                let ids = state
                    .records
                    .values()
                    .filter(|r| {
                        r.reference.kind == 151 && after.is_none_or(|id| r.reference.id > id)
                    })
                    .map(|r| r.reference.id)
                    .collect();
                inventory(
                    &mut c,
                    &next,
                    &changed,
                    command,
                    ids,
                    &mut cursor,
                    |c, id| {
                        c.select(151, id)?;
                        Ok(())
                    },
                )?;
            }
            Command::Withdraw { agreement } => {
                let r = expected(&mut c, agreement, replay)?;
                let mut value = Agreement::parse(&r.payload, state.network, state.incarnation)?;
                if intent.requester != value.approver {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[22],
                        (2, agreement.id),
                        None,
                        0,
                    )?;
                }
                value.withdrawn = true;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    151,
                    agreement.id,
                    value.value(),
                    replay,
                )?;
            }
            Command::BridgeRegister { profile } => {
                c.federation_profile(profile)?;
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[26],
                    (5, profile.manifest.deployment),
                    None,
                    0,
                )?;
                ensure!(
                    replay || !state.records.contains_key(&(152, profile.service)),
                    "bridge service is already registered or withdrawn"
                );
                let value = Bridge {
                    profile: profile.clone(),
                    manager: intent.requester,
                    grant: grant(operation)?.clone(),
                    withdrawn: false,
                };
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    152,
                    profile.service,
                    value.value(),
                    replay,
                )?;
            }
            Command::BridgeGet { service } => {
                let record = c.select(152, *service)?;
                let bridge = Bridge::parse(&record.payload, state.network, state.incarnation)?;
                if intent.requester == *service {
                    ensure!(
                        operation.grant.is_none() && !bridge.withdrawn,
                        "intrinsic bridge context is withdrawn"
                    );
                    c.federation_profile(&bridge.profile)?;
                    c.capability(
                        &bridge.grant,
                        bridge.manager,
                        &[26],
                        (5, bridge.profile.manifest.deployment),
                        None,
                        0,
                    )?;
                } else if operation.grant.is_none() {
                    ensure!(
                        intent.requester == bridge.profile.manifest.operator,
                        "bridge metadata belongs to another operator"
                    );
                } else {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[26],
                        (5, bridge.profile.manifest.deployment),
                        None,
                        0,
                    )?;
                }
            }
            Command::BridgeWithdraw { bridge } => {
                let selected = expected(&mut c, bridge, replay)?;
                let mut value = Bridge::parse(&selected.payload, state.network, state.incarnation)?;
                if intent.requester != value.profile.manifest.operator
                    && intent.requester != value.profile.service
                {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[26],
                        (5, value.profile.manifest.deployment),
                        None,
                        0,
                    )?;
                }
                value.withdrawn = true;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    152,
                    bridge.id,
                    value.value(),
                    replay,
                )?;
            }
            Command::Share { share } => {
                let agreement = c.select(151, share.agreement)?;
                let agreement = c.federation_agreement(&agreement.reference)?;
                ensure!(
                    agreement
                        .treaty
                        .source
                        .matches(state.network, state.incarnation),
                    "only the source author can share"
                );
                let (_, ledger, review, revision) = c.publication(share.page)?;
                ensure!(
                    share.author == intent.requester
                        && share.author == revision.author.intent.requester
                        && ledger.published.as_ref() == Some(&share.publication)
                        && share.revision == review.statement.revision
                        && revision.author.namespace == agreement.treaty.source_namespace,
                    "share differs from the exact source publication"
                );
                c.capability(
                    &share.grant,
                    intent.requester,
                    &[4],
                    (2, page::page_id(&share.page)?),
                    Some(&revision.author.namespace),
                    revision.author.source.len() as u64,
                )?;
                c.application(
                    intent.requester,
                    &share.grant,
                    revision.author.application.as_ref(),
                    "PagesSubmit",
                    &revision.author.namespace,
                    Some(share.page),
                )?;
                ensure!(
                    operation.grant.as_ref() == Some(&share.grant),
                    "share grant differs from signed author provenance"
                );
                let mut value = share.clone();
                if let Some(previous) = state.records.get(&(153, share.identity()?)) {
                    let old = Share::parse(
                        &c.select(153, previous.reference.id)?.payload,
                        state.network,
                        state.incarnation,
                    )?;
                    value.withdrawal_generation = old.withdrawal_generation;
                }
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    153,
                    share.identity()?,
                    value.value(),
                    replay,
                )?;
            }
            Command::ShareStatus {
                agreement,
                page: raw,
            } => {
                let r = c.select(153, share_id(*agreement, *raw)?)?;
                let value = Share::parse(&r.payload, state.network, state.incarnation)?;
                ensure!(
                    value.author == intent.requester,
                    "share status belongs to another author"
                );
                if operation.grant.is_some() {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[4],
                        (2, page::page_id(raw)?),
                        None,
                        0,
                    )?;
                }
            }
            Command::Unshare { share } => {
                let r = expected(&mut c, share, replay)?;
                let mut value = Share::parse(&r.payload, state.network, state.incarnation)?;
                ensure!(
                    value.author == intent.requester,
                    "unshare is not from the source author"
                );
                value.allowed = false;
                value.withdrawal_generation = if replay {
                    r.reference.generation
                } else {
                    r.reference
                        .generation
                        .checked_add(1)
                        .context("share generation exhausted")?
                };
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    153,
                    share.id,
                    value.value(),
                    replay,
                )?;
            }
            Command::SourceContext {
                agreement,
                page: raw,
                after,
            } => {
                ensure!(
                    raw.is_none() || after.is_none(),
                    "source context mixes Page and inventory"
                );
                let current = c.select(151, *agreement)?;
                let value = c.federation_agreement(&current.reference)?;
                ensure!(
                    value.treaty.source_side(state.network, state.incarnation)?,
                    "source context belongs to the source network"
                );
                let bridge = c.select(152, intent.requester)?;
                service(&mut c, intent, operation, &value, &bridge.reference)?;
                c.select(157, value.foreign.id)?;
                if let Some(raw) = raw {
                    c.federation_source(&value.treaty, *raw)?;
                } else {
                    let ids = state
                        .records
                        .values()
                        .filter(|r| {
                            r.reference.kind == 153 && after.is_none_or(|id| r.reference.id > id)
                        })
                        .map(|r| r.reference.id)
                        .collect();
                    inventory(
                        &mut c,
                        &next,
                        &changed,
                        command,
                        ids,
                        &mut cursor,
                        |c, id| {
                            let share = Share::parse(
                                &state.record(153, id)?.payload,
                                state.network,
                                state.incarnation,
                            )?;
                            ensure!(
                                share.agreement == *agreement,
                                "unrelated inventory agreement"
                            );
                            c.federation_source(&value.treaty, share.page)?;
                            Ok(())
                        },
                    )?;
                    // A partial authenticated context can reproduce this cursor without unseen records.
                    cursor = c
                        .selected
                        .values()
                        .filter(|r| r.reference.kind == 153)
                        .map(|r| r.reference.id)
                        .max();
                }
            }
            Command::Admission {
                agreement,
                bridge,
                page,
                ..
            } => {
                let value = c.federation_agreement(agreement)?;
                ensure!(
                    !value.treaty.source_side(state.network, state.incarnation)?,
                    "admission belongs to the destination network"
                );
                service(&mut c, intent, operation, &value, bridge)?;
                if let Some(raw) = page {
                    c.federation_destination_context(&value.treaty, *raw)?;
                }
            }
            Command::Export {
                agreement,
                bridge,
                admission,
                include_bundle,
                inventory: selection,
            } => {
                let value = c.federation_agreement(agreement)?;
                ensure!(
                    value.treaty.source_side(state.network, state.incarnation)?,
                    "export belongs to the source network"
                );
                service(&mut c, intent, operation, &value, bridge)?;
                let verified = c.federation_foreign(admission, &value.treaty, inputs, replay)?;
                let Command::Admission {
                    agreement: remote,
                    page: raw,
                    revision,
                    after,
                    ..
                } = &verified.command
                else {
                    anyhow::bail!("export requires destination admission")
                };
                ensure!(
                    remote.id == agreement.id,
                    "destination admission names another agreement"
                );
                Command::parse_inventory(&Command::inventory_value(selection), *raw, *after)?;
                foreign_floor(&mut c, &mut next, &mut changed, &verified, replay)?;
                if let Some(raw) = raw {
                    let (_, review, _, _, _) = c.federation_source(&value.treaty, *raw)?;
                    ensure!(
                        revision
                            .as_ref()
                            .is_none_or(|r| *r == review.statement.revision),
                        "source revision changed after inspection"
                    );
                } else {
                    ensure!(
                        !include_bundle,
                        "inventory export cannot return Page bodies"
                    );
                    let ids = selection
                        .as_ref()
                        .context("inventory export selection absent")?
                        .clone();
                    let through = ids.last().copied();
                    inventory(
                        &mut c,
                        &next,
                        &changed,
                        command,
                        ids,
                        &mut cursor,
                        |c, id| {
                            let share = Share::parse(
                                &state.record(153, id)?.payload,
                                state.network,
                                state.incarnation,
                            )?;
                            ensure!(
                                share.agreement == agreement.id,
                                "unrelated inventory agreement"
                            );
                            c.federation_source(&value.treaty, share.page)?;
                            Ok(())
                        },
                    )?;
                    // A prepared prefix always advances, even when the context ended at the last share.
                    // The next empty context terminates discovery without assuming cache completeness.
                    if cursor.is_none() {
                        cursor = through;
                    }
                }
            }
            Command::Import {
                agreement,
                bridge,
                export,
                bundle,
            } => {
                let value = c.federation_agreement(agreement)?;
                ensure!(
                    !value.treaty.source_side(state.network, state.incarnation)?,
                    "import belongs to the destination network"
                );
                service(&mut c, intent, operation, &value, bridge)?;
                let verified = c.federation_foreign(export, &value.treaty, inputs, replay)?;
                import(
                    &mut c,
                    &mut next,
                    &mut changed,
                    intent,
                    &value,
                    &verified,
                    bundle,
                    inputs,
                    replay,
                )?;
                foreign_floor(&mut c, &mut next, &mut changed, &verified, replay)?;
            }
            Command::Queue { agreement, after } => {
                let current = c.select(151, *agreement)?;
                let value = c.federation_agreement(&current.reference)?;
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[3],
                    (1, page::namespace_id(&value.treaty.destination_namespace)?),
                    Some(&value.treaty.destination_namespace),
                    0,
                )?;
                let ids = state
                    .records
                    .values()
                    .filter(|r| {
                        r.reference.kind == 154 && after.is_none_or(|id| r.reference.id > id)
                    })
                    .map(|r| r.reference.id)
                    .collect();
                inventory(
                    &mut c,
                    &next,
                    &changed,
                    command,
                    ids,
                    &mut cursor,
                    |c, id| {
                        let p = ForeignPage::parse(&state.record(154, id)?.payload)?;
                        ensure!(
                            p.agreement == *agreement && p.pending.is_some(),
                            "foreign queue item is not pending in this agreement"
                        );
                        c.select(154, id)?;
                        Ok(())
                    },
                )?;
            }
            Command::Inspect { page, export } | Command::Read { page, export } => {
                let published = matches!(command, Command::Read { .. });
                let (_, head, revision, value) = c.federation_revision(*page, published)?;
                let selected = c.select(151, value.agreement)?;
                let agreement = c.federation_agreement(&selected.reference)?;
                let verified = c.federation_foreign(export, &agreement.treaty, inputs, replay)?;
                exact_export(
                    &verified,
                    &agreement.treaty,
                    &value,
                    intent.minimum_policy_epoch,
                )?;
                c.federation_principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    if published { 0 } else { 3 },
                    &agreement.treaty,
                    *page,
                    head.raw_page,
                    value.bundle.len() as u64,
                )?;
                if published {
                    current_review(&mut c, &head, &agreement.treaty, &value)?;
                }
                c.federation_media(&revision.reference, &value, &agreement.treaty, None)?;
                foreign_floor(&mut c, &mut next, &mut changed, &verified, replay)?;
            }
            Command::Review { review, export } => {
                let revision = c.exact(&review.revision)?;
                let value = ForeignRevision::parse(&revision.payload)?;
                let selected = c.select(151, value.agreement)?;
                let agreement = c.federation_agreement(&selected.reference)?;
                let head_record = c.select(154, value.page)?;
                let mut head = ForeignPage::parse(&head_record.payload)?;
                ensure!(
                    intent.requester == review.reviewer
                        && operation.grant.as_ref() == Some(&review.grant)
                        && (replay || head.pending.as_ref() == Some(&review.revision)),
                    "review does not name the exact inspected pending revision"
                );
                c.federation_principal(
                    review.reviewer,
                    &review.grant,
                    review.application.as_ref(),
                    3,
                    &agreement.treaty,
                    value.page,
                    head.raw_page,
                    value.bundle.len() as u64,
                )?;
                review_mode(&mut c, review, &agreement.treaty, head.raw_page)?;
                let verified = c.federation_foreign(export, &agreement.treaty, inputs, replay)?;
                exact_export(
                    &verified,
                    &agreement.treaty,
                    &value,
                    intent.minimum_policy_epoch,
                )?;
                if review.approve {
                    c.federation_media(
                        &revision.reference,
                        &value,
                        &agreement.treaty,
                        Some(review),
                    )?;
                }
                let mut review = review.clone();
                review.decided_at_ms = if replay {
                    ForeignReview::parse(
                        &c.select(156, review.revision.id)?.payload,
                        state.network,
                        state.incarnation,
                    )?
                    .decided_at_ms
                } else {
                    at
                };
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    156,
                    review.revision.id,
                    review.value(),
                    replay,
                )?;
                if review.approve {
                    head.published = Some(next.record(156, review.revision.id)?.reference.clone());
                    head.withdrawn = false;
                }
                head.pending = None;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    154,
                    value.page,
                    head.value(),
                    replay,
                )?;
                foreign_floor(&mut c, &mut next, &mut changed, &verified, replay)?;
            }
            Command::List { agreement, export } => {
                let record = c.select(151, *agreement)?;
                let accepted = c.federation_agreement(&record.reference)?;
                let verified = c.federation_foreign(export, &accepted.treaty, inputs, replay)?;
                foreign_floor(&mut c, &mut next, &mut changed, &verified, replay)?;
                list(
                    &mut c,
                    intent,
                    operation,
                    &accepted.treaty,
                    &verified,
                    &next,
                    &changed,
                    &mut cursor,
                )?;
            }
            Command::PageWithdraw { page } => {
                let r = expected(&mut c, page, replay)?;
                let mut value = ForeignPage::parse(&r.payload)?;
                let agreement = c.select(151, value.agreement)?;
                let agreement = c.federation_agreement(&agreement.reference)?;
                c.federation_principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    3,
                    &agreement.treaty,
                    page.id,
                    value.raw_page,
                    0,
                )?;
                value.pending = None;
                value.published = None;
                value.withdrawn = true;
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    154,
                    page.id,
                    value.value(),
                    replay,
                )?;
            }
            Command::ForeignSeal {
                trust,
                floor,
                evidence,
                history,
            } => {
                maintenance(&mut c, intent, operation, trust)?;
                let accepted = ForeignTrust::parse(
                    &c.exact(trust)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                let selected = expected(&mut c, floor, replay)?;
                let mut value = ForeignFloor::parse(&selected.payload)?;
                if replay {
                    let sealed = value
                        .sealed
                        .as_ref()
                        .context("foreign seal replay has no seal")?;
                    ensure!(
                        sealed.evidence()? == *evidence && sealed.history()? == *history,
                        "foreign seal replay differs"
                    );
                } else {
                    ensure!(value.sealed.is_none(), "foreign authority already sealed");
                    let resolved = value.resolve(&accepted)?;
                    let terminal = crate::authority_epoch::verify_terminal(
                        &resolved.descriptor,
                        &resolved.prefix,
                        resolved.checkpoint.as_ref().map(|c| c.head()),
                        evidence,
                        history,
                    )?;
                    value.sealed = Some(crate::authority_epoch::archive::Seal::new(
                        &terminal,
                        value.retained.clone(),
                    )?);
                }
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    157,
                    trust.id,
                    value.value()?,
                    replay,
                )?;
            }
            Command::ForeignActivate {
                trust,
                floor,
                ready,
            } => {
                maintenance(&mut c, intent, operation, trust)?;
                let accepted = ForeignTrust::parse(
                    &c.exact(trust)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                let selected = expected(&mut c, floor, replay)?;
                let mut value = ForeignFloor::parse(&selected.payload)?;
                if replay {
                    let epoch = value
                        .epochs
                        .last()
                        .context("foreign activation replay has no handoff")?;
                    let mut previous = value.epochs.clone();
                    previous.pop();
                    let old = crate::authority_epoch::archive::resolve(
                        accepted.verified()?.descriptor(),
                        &previous,
                    )?
                    .descriptor;
                    ensure!(
                        epoch.verify(&old)?.ready() == ready,
                        "foreign activation retry differs"
                    );
                } else {
                    let resolved = value.resolve(&accepted)?;
                    let seal = value
                        .sealed
                        .as_ref()
                        .context("foreign activation requires retained terminal seal")?;
                    let activation = crate::authority_epoch::verify_activation(
                        seal.verify(&resolved.descriptor)?,
                        ready,
                    )?;
                    value.epochs.push(seal.activate(&activation)?);
                    value.sealed = None;
                    value.retained = crate::authority_epoch::archive::Retained {
                        certificate: None,
                        node: None,
                        checkpoint: None,
                    };
                    value.resolve(&accepted)?;
                }
                put(
                    &mut c,
                    &mut next,
                    &mut changed,
                    157,
                    trust.id,
                    value.value()?,
                    replay,
                )?;
            }
        }
        Ok(())
    })();
    if decision.is_err() {
        return Ok(Decision::refused(3));
    }
    if sorted(&mut c.dependencies).is_err() || next.charge().is_err() {
        return Ok(Decision::refused(2));
    }
    if exact
        && !replay
        && (operation.mutation() && intent.expected != c.dependencies
            || !operation.mutation() && intent.expected.iter().any(|r| !c.dependencies.contains(r)))
    {
        return Ok(Decision::refused(12));
    }
    let (value, versions) = match result(&c, &next, &changed, command, cursor) {
        Ok(v) => v,
        Err(_) => return Ok(Decision::refused(2)),
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
