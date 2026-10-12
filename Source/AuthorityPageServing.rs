// SPDX-License-Identifier: MIT
// Local serving metadata names one current publication, exact consenting host and finite byte range.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_serving(
    c: &mut Evaluation<'_>,
    operation: &Operation,
    command: &Command,
    intent: &Intent,
    inputs: &Resolved,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    continuation: &mut Option<Digest>,
    replay: bool,
) -> Result<()> {
    let state = c.state;
    let at = c.at;
    match command {
        Command::Sync {
            host,
            namespace,
            after,
            fetch,
        } => {
            ensure!(
                intent.requester == *host && operation.grant.is_none(),
                "Page inventory requires the exact role-one service"
            );
            let r = c.select(147, *host)?;
            let configured = c.host(&r.reference, Some(namespace), true)?;
            if let Some(page) = fetch {
                let (_, _, review, revision) = c.publication(*page)?;
                c.media_metadata(&review.statement.revision, &revision)?;
                ensure!(
                    revision.author.namespace == *namespace,
                    "Page host fetch namespace differs"
                );
                let reference = review.bundle.as_ref().context("Page bundle absent")?;
                ensure!(
                    reference.len() as u64 <= configured.profile.maximum_asset_bytes,
                    "Page bundle exceeds host consent"
                );
                let object = objects::Bundle::parse(
                    inputs.get(reference)?,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    object.author.bytes == revision.author.bytes
                        && object.review.bytes == review.statement.bytes,
                    "Page host bundle differs"
                );
            } else {
                let mut last = None;
                for record in state.records.values().filter(|r| r.reference.kind == 140) {
                    if after.is_some_and(|id| record.reference.id <= id) {
                        continue;
                    }
                    let ledger = Ledger::parse(&record.payload)?;
                    if ledger.namespace != *namespace || ledger.published.is_none() {
                        continue;
                    }
                    if !page_item(
                        c,
                        command,
                        record.reference.id,
                        &mut last,
                        continuation,
                        |c| c.publication(ledger.raw_page),
                    )? {
                        break;
                    }
                }
            }
        }
        Command::ReplicaQueue {
            host,
            namespace,
            after,
        } => {
            ensure!(
                intent.requester == *host && operation.grant.is_none(),
                "Page ticket inventory requires the exact role-one service"
            );
            let registered = c.select(147, *host)?;
            c.host(&registered.reference, Some(namespace), true)?;
            let mut last = None;
            for record in state.records.values().filter(|r| r.reference.kind == 146) {
                if after.is_some_and(|id| record.reference.id <= id) {
                    continue;
                }
                let ticket = Ticket::parse(&record.payload)?;
                if ticket.host != registered.reference
                    || ticket.delivered.is_some()
                    || ticket.expires_ms <= at.saturating_add(1250)
                {
                    continue;
                }
                if !page_item(
                    c,
                    command,
                    record.reference.id,
                    &mut last,
                    continuation,
                    |c| {
                        let (_, _, revision) = c.ticket(&record.reference)?;
                        ensure!(
                            revision.author.namespace == *namespace,
                            "ticket namespace differs"
                        );
                        Ok(())
                    },
                )? {
                    break;
                }
            }
        }
        Command::ReplicaContext { page, host } => {
            let (_, _, _, revision) = c.publication(*page)?;
            c.principal(
                intent.requester,
                grant(operation)?,
                None,
                "PagesRead",
                &revision.author.namespace,
                Some(*page),
                revision.author.source.len() as u64,
            )?;
            c.host(host, Some(&revision.author.namespace), true)?;
            let slot = ticket_id(intent.requester, host.id)?;
            if state.records.contains_key(&(146, slot)) {
                c.select(146, slot)?;
            }
        }
        Command::ReplicaRequest {
            page,
            host,
            expires_ms,
        } => {
            let (_, ledger, _, revision) = c.publication(*page)?;
            c.principal(
                intent.requester,
                grant(operation)?,
                None,
                "PagesRead",
                &revision.author.namespace,
                Some(*page),
                revision.author.source.len() as u64,
            )?;
            let application = if c.governance.record_bytes(127, intent.requester).is_ok() {
                Some(c.select(148, intent.requester)?.reference)
            } else {
                None
            };
            let destination = c.host(host, Some(&revision.author.namespace), true)?;
            ensure!(
                *expires_ms > at.saturating_add(1250)
                    && *expires_ms <= at.saturating_add(TICKET_LIFETIME_MS)
                    && *expires_ms <= c.expires,
                "Page replica ticket exceeds current authority"
            );
            let ticket = Ticket {
                publication: ledger.published.context("publication missing")?,
                reader: intent.requester,
                grant: grant(operation)?.clone(),
                application,
                host: host.clone(),
                expires_ms: *expires_ms,
                delivered: None,
                creation: intent.digest,
            };
            let id = ticket.identity()?;
            if replay {
                let old = c.select(146, id)?;
                let current = Ticket::parse(&old.payload)?;
                ensure!(
                    current.creation == intent.digest
                        && current.publication == ticket.publication
                        && current.host == ticket.host
                        && current.reader == ticket.reader
                        && current.expires_ms == ticket.expires_ms,
                    "Page ticket replay differs"
                );
            } else {
                if let Some(old) = state.records.get(&(146, id)) {
                    let old = c.select(146, old.reference.id)?;
                    ensure!(
                        Ticket::parse(&old.payload)?.expires_ms <= at,
                        "previous reader-host ticket still active"
                    );
                }
                let active = state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == 146)
                    .map(|r| Ticket::parse(&r.payload))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|t| t.expires_ms > at)
                    .collect::<Vec<_>>();
                let reader_concurrency = active
                    .iter()
                    .filter(|t| t.reader == intent.requester)
                    .count() as u64
                    + 1;
                let host_concurrency =
                    active.iter().filter(|t| t.host.id == host.id).count() as u64 + 1;
                // Active tickets consume the currently signed concurrent-operation budgets.
                c.capability_usage(
                    grant(operation)?,
                    intent.requester,
                    &[0],
                    (2, page_id(page)?),
                    Some(&revision.author.namespace),
                    [
                        revision.author.source.len() as u64,
                        1,
                        1,
                        reader_concurrency,
                    ],
                )?;
                c.capability_usage(
                    &destination.grant,
                    destination.manager,
                    &[5],
                    (3, destination.profile.service),
                    None,
                    [revision.author.source.len() as u64, 1, 1, host_concurrency],
                )?;
                add(next, changed, 146, id, ticket.value())?;
            }
            c.expires = c.expires.min(*expires_ms);
        }
        Command::ReplicaDeliver { ticket, bundle } => {
            let (mut value, review, revision) = if replay {
                let current = c.select(146, ticket.id)?;
                ensure!(
                    ticket.generation.checked_add(1) == Some(current.reference.generation)
                        && current.predecessor == Some(ticket.digest),
                    "Page delivery replay predecessor differs"
                );
                c.ticket(&current.reference)?
            } else {
                c.ticket(ticket)?
            };
            ensure!(
                intent.requester == value.host.id
                    && operation.grant.is_none()
                    && review.bundle.as_ref() == Some(bundle),
                "Page replica delivery differs from exact host and publication"
            );
            let object =
                objects::Bundle::parse(inputs.get(bundle)?, state.network, state.incarnation)?;
            ensure!(
                object.author.bytes == revision.author.bytes
                    && object.review.bytes == review.statement.bytes,
                "Page replica bytes differ from exact approved content"
            );
            if replay {
                ensure!(
                    value.delivered.as_ref() == Some(bundle),
                    "Page replica completion differs"
                );
            } else {
                ensure!(value.delivered.is_none(), "Page replica already delivered");
                value.delivered = Some(bundle.clone());
                add(next, changed, 146, ticket.id, value.value())?;
            }
        }
        Command::ReplicaResult { ticket } => {
            let current = c.select(146, ticket.id)?;
            ensure!(
                current.reference == *ticket
                    || ticket.generation.checked_add(1) == Some(current.reference.generation)
                        && current.predecessor == Some(ticket.digest),
                "Page replica result no longer names the requested ticket"
            );
            let (value, review, revision) = c.ticket(&current.reference)?;
            c.media_metadata(&review.statement.revision, &revision)?;
            ensure!(
                value.reader == intent.requester && operation.grant.is_none(),
                "Page replica result belongs to another reader"
            );
            if let Some(reference) = value.delivered {
                let object = objects::Bundle::parse(
                    inputs.get(&reference)?,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    object.author.bytes == revision.author.bytes
                        && object.review.bytes == review.statement.bytes,
                    "Page delivered result differs"
                );
            }
        }
        Command::MediaGet { asset } => {
            let (value, revision, ledger) = c.asset(asset, true)?;
            c.media_metadata(&value.revision, &revision)?;
            let permission = if revision.author.intent.requester == intent.requester {
                "MediaSubmit"
            } else if ledger
                .published
                .as_ref()
                .is_some_and(|p| p.id == value.revision.id)
            {
                "MediaRead"
            } else {
                "MediaInspect"
            };
            c.principal(
                intent.requester,
                grant(operation)?,
                None,
                permission,
                &revision.author.namespace,
                Some(revision.author.raw_page),
                0,
            )?;
            if state.records.contains_key(&(145, asset.id)) {
                c.select(145, asset.id)?;
            }
        }
        Command::MediaAuthorise {
            asset,
            host,
            effect,
            offset,
            bytes,
            ..
        } => {
            let (value, revision, ledger) = c.asset(asset, true)?;
            ensure!(
                value.hosts.contains(host)
                    && offset
                        .checked_add(*bytes)
                        .is_some_and(|end| end <= value.manifest.bytes),
                "media operation exceeds exact asset placement or range"
            );
            let configured = c.host(host, Some(&revision.author.namespace), true)?;
            ensure!(
                value.manifest.bytes <= configured.profile.maximum_asset_bytes,
                "media payload exceeds current host consent"
            );
            let permission = match effect {
                MediaEffect::Upload => {
                    ensure!(
                        intent.requester == revision.author.intent.requester
                            && ledger.pending.as_ref() == Some(&value.revision)
                            && value.upload_expires_ms > at.saturating_add(1250),
                        "media upload is not from current pending author"
                    );
                    c.expires = c.expires.min(value.upload_expires_ms);
                    "MediaSubmit"
                }
                MediaEffect::Read => {
                    let (_, published, _, _) = c.publication(revision.author.raw_page)?;
                    ensure!(
                        published
                            .published
                            .as_ref()
                            .is_some_and(|p| p.id == value.revision.id),
                        "media read is not published"
                    );
                    "MediaRead"
                }
                MediaEffect::Inspect => {
                    ensure!(
                        ledger.pending.as_ref() == Some(&value.revision),
                        "media review has no current pending source"
                    );
                    "MediaInspect"
                }
            };
            c.principal(
                intent.requester,
                grant(operation)?,
                None,
                permission,
                &revision.author.namespace,
                Some(revision.author.raw_page),
                *bytes,
            )?;
        }
        Command::MediaReceipt { receipt } => {
            let (asset, revision, ledger) = c.asset(&receipt.asset, true)?;
            ensure!(
                ledger.pending.as_ref() == Some(&asset.revision)
                    && asset.hosts.contains(&receipt.host)
                    && receipt.bytes == asset.manifest.bytes
                    && hex::encode(receipt.digest) == asset.manifest.digest
                    && receipt.recorded_ms <= at.saturating_add(250)
                    && asset.upload_expires_ms > at.saturating_add(1250),
                "media receipt differs from current pending asset"
            );
            c.host(&receipt.host, Some(&revision.author.namespace), true)?;
            if intent.requester == receipt.host.id {
                ensure!(
                    operation.grant.is_none(),
                    "media service receipt uses intrinsic authority"
                );
            } else {
                ensure!(
                    intent.requester == revision.author.intent.requester,
                    "media receipt is not from host or author"
                );
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    "MediaSubmit",
                    &revision.author.namespace,
                    Some(revision.author.raw_page),
                    0,
                )?;
            }
            let mut evidence = if state.records.contains_key(&(145, receipt.asset.id)) {
                Evidence::parse(
                    &c.select(145, receipt.asset.id)?.payload,
                    state.network,
                    state.incarnation,
                )?
            } else {
                Evidence {
                    asset: receipt.asset.clone(),
                    copies: vec![],
                    inspections: vec![],
                }
            };
            if replay {
                ensure!(
                    evidence
                        .copies
                        .iter()
                        .any(|r| r.envelope == receipt.envelope),
                    "media receipt replay differs"
                );
            } else {
                evidence.copies.retain(|r| r.host.id != receipt.host.id);
                evidence.copies.push(receipt.clone());
                evidence.copies.sort_by_key(|r| r.host.id);
                add(next, changed, 145, receipt.asset.id, evidence.value())?;
            }
        }
        Command::MediaInspect {
            asset,
            receipt,
            expires_ms,
        } => {
            let (value, revision, ledger) = c.asset(asset, true)?;
            ensure!(
                ledger.pending.as_ref() == Some(&value.revision)
                    && *expires_ms > at.saturating_add(1250)
                    && *expires_ms <= at.saturating_add(REVIEW_LIFETIME_MS),
                "media inspection deadline or pending revision differs"
            );
            c.principal(
                intent.requester,
                grant(operation)?,
                None,
                "MediaInspect",
                &revision.author.namespace,
                Some(revision.author.raw_page),
                value.manifest.bytes,
            )?;
            c.host(&receipt.host, Some(&revision.author.namespace), true)?;
            let record = c.select(145, asset.id)?;
            let mut evidence = Evidence::parse(&record.payload, state.network, state.incarnation)?;
            ensure!(
                evidence.asset == *asset
                    && evidence
                        .copies
                        .iter()
                        .any(|r| r.envelope == receipt.envelope),
                "media inspection lacks exact retained copy receipt"
            );
            let application = if c.governance.record_bytes(127, intent.requester).is_ok() {
                Some(c.select(148, intent.requester)?.reference)
            } else {
                None
            };
            if replay {
                ensure!(
                    evidence
                        .inspections
                        .iter()
                        .any(|v| v.intent == intent.digest
                            && v.reviewer == intent.requester
                            && v.expires_ms == *expires_ms),
                    "media inspection replay differs"
                );
            } else {
                evidence
                    .inspections
                    .retain(|v| v.reviewer != intent.requester);
                capacity(evidence.inspections.len() < 4096)?;
                evidence.inspections.push(Inspection {
                    reviewer: intent.requester,
                    grant: grant(operation)?.clone(),
                    application,
                    intent: intent.digest,
                    expires_ms: *expires_ms,
                });
                evidence.inspections.sort_by_key(|r| r.reviewer);
                add(next, changed, 145, asset.id, evidence.value())?;
            }
            c.expires = c.expires.min(*expires_ms);
        }
        Command::MediaPolicy { namespace, copies } => {
            c.capability(
                grant(operation)?,
                intent.requester,
                &[21],
                (1, namespace_id(namespace)?),
                Some(namespace),
                0,
            )?;
            let id = namespace_id(namespace)?;
            let policy = PlacementPolicy {
                namespace: namespace.clone(),
                minimum_copies: *copies,
                administrator: intent.requester,
                grant: grant(operation)?.clone(),
            };
            if replay {
                ensure!(
                    c.select(149, id)?.payload == policy.value(),
                    "media placement replay differs"
                );
            } else {
                if state.records.contains_key(&(149, id)) {
                    c.select(149, id)?;
                }
                add(next, changed, 149, id, policy.value())?;
            }
        }
        _ => anyhow::bail!("unsupported Page serving command"),
    }
    Ok(())
}
