// SPDX-License-Identifier: MIT
// Qualified media preserves source bytes while independently consenting to local placement and effects.
use super::*;

fn revision(
    c: &mut page::Evaluation<'_>,
    asset: &VersionRef,
) -> Result<(page::Asset, ForeignRevision, ForeignPage, Agreement)> {
    let selected = c.exact(asset)?;
    let value = page::Asset::parse(&selected.payload)?;
    ensure!(
        value.revision.kind == 155 && value.expires_ms > c.at.saturating_add(1250),
        "foreign media origin or expiry differs"
    );
    let source = ForeignRevision::parse(&c.exact(&value.revision)?.payload)?;
    let head = ForeignPage::parse(&c.select(154, source.page)?.payload)?;
    let agreement = c.select(151, source.agreement)?;
    let agreement = c.federation_agreement(&agreement.reference)?;
    ensure!(
        source.native == head.observed
            && source.share == head.source_share
            && source.metadata.assets.contains(&value.manifest)
            && value
                .hosts
                .iter()
                .all(|h| agreement.treaty.destination_hosts.contains(&h.id)),
        "foreign media is not exact currently imported content"
    );
    c.expires = c.expires.min(value.expires_ms);
    Ok((value, source, head, agreement))
}
fn lease(
    c: &mut page::Evaluation<'_>,
    proof: &ForeignProof,
    treaty: &Treaty,
    value: &ForeignRevision,
    intent: &Intent,
    replay: bool,
) -> Result<VerifiedForeign> {
    let verified = c.federation_foreign(proof, treaty, &Resolved::default(), replay)?;
    exact_export(&verified, treaty, value, intent.minimum_policy_epoch)?;
    Ok(verified)
}
fn bridge(
    c: &mut page::Evaluation<'_>,
    intent: &Intent,
    operation: &Operation,
    treaty: &Treaty,
) -> Result<()> {
    ensure!(
        operation.grant.is_none(),
        "bridge media maintenance cannot borrow member grants"
    );
    let selected = c.select(152, intent.requester)?;
    c.federation_bridge(&selected.reference, treaty)?;
    Ok(())
}
#[allow(
    clippy::too_many_arguments,
    reason = "Media authority binds the exact asset, foreign revision, treaty, participant and requested extent."
)]
fn principal(
    c: &mut page::Evaluation<'_>,
    intent: &Intent,
    operation: &Operation,
    asset: &page::Asset,
    value: &ForeignRevision,
    head: &ForeignPage,
    treaty: &Treaty,
    effect: page::MediaEffect,
    bytes: u64,
) -> Result<()> {
    match effect {
        page::MediaEffect::Upload => {
            bridge(c, intent, operation, treaty)?;
            ensure!(
                head.pending.as_ref() == Some(&asset.revision)
                    && asset.upload_expires_ms > c.at.saturating_add(1250),
                "bridge upload is not for current pending foreign content"
            );
            c.expires = c.expires.min(asset.upload_expires_ms);
        }
        page::MediaEffect::Read => {
            let review = current_review(c, head, treaty, value)?;
            ensure!(
                review.revision == asset.revision,
                "media is not locally approved"
            );
            c.federation_principal(
                intent.requester,
                grant(operation)?,
                None,
                0,
                treaty,
                value.page,
                head.raw_page,
                bytes,
                true,
            )?;
            c.application(
                intent.requester,
                grant(operation)?,
                None,
                "MediaRead",
                &treaty.destination_namespace,
                Some(head.raw_page),
            )?;
        }
        page::MediaEffect::Inspect => {
            ensure!(
                head.pending.as_ref() == Some(&asset.revision),
                "foreign media has no current pending review"
            );
            c.federation_principal(
                intent.requester,
                grant(operation)?,
                None,
                3,
                treaty,
                value.page,
                head.raw_page,
                bytes,
                true,
            )?;
            c.application(
                intent.requester,
                grant(operation)?,
                None,
                "MediaInspect",
                &treaty.destination_namespace,
                Some(head.raw_page),
            )?;
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_media(
    c: &mut page::Evaluation<'_>,
    operation: &Operation,
    command: &Command,
    intent: &Intent,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    replay: bool,
) -> Result<()> {
    match command {
        Command::MediaGet { asset, proof } => {
            let (value, source, head, agreement) = revision(c, asset)?;
            let verified = lease(c, proof, &agreement.treaty, &source, intent, replay)?;
            let effect = if intent.requester == agreement.treaty.destination_bridge {
                page::MediaEffect::Upload
            } else if head
                .published
                .as_ref()
                .is_some_and(|r| r.id == value.revision.id)
            {
                page::MediaEffect::Read
            } else {
                page::MediaEffect::Inspect
            };
            principal(
                c,
                intent,
                operation,
                &value,
                &source,
                &head,
                &agreement.treaty,
                effect,
                0,
            )?;
            c.federation_media(&value.revision, &source, &agreement.treaty, None)?;
            foreign_floor(c, next, changed, &verified, replay)?;
        }
        Command::MediaAuthorise {
            asset,
            host,
            effect,
            offset,
            bytes,
            proof,
            ..
        } => {
            let selected = c.exact(asset)?;
            let value = page::Asset::parse(&selected.payload)?;
            ensure!(
                value.hosts.contains(host)
                    && offset
                        .checked_add(*bytes)
                        .is_some_and(|end| end <= value.manifest.bytes),
                "bridge media effect exceeds its exact placement or byte range"
            );
            let (treaty, verified) = if value.revision.kind == 141 {
                let Command::Admission {
                    agreement,
                    page: Some(raw),
                    revision: requested,
                    ..
                } = proof.command()?
                else {
                    anyhow::bail!("source media requires exact destination admission")
                };
                let accepted = c.select(151, agreement.id)?;
                let accepted = c.federation_agreement(&accepted.reference)?;
                bridge(c, intent, operation, &accepted.treaty)?;
                ensure!(
                    *effect == page::MediaEffect::Read
                        && accepted
                            .treaty
                            .source
                            .matches(c.state.network, c.state.incarnation),
                    "source bridge can only read shared native media"
                );
                c.asset(asset, true)?;
                let (_, review, _, _, _) = c.federation_source(&accepted.treaty, raw)?;
                ensure!(
                    review.statement.revision == value.revision
                        && requested.as_ref() == Some(&value.revision)
                        && accepted.treaty.source_hosts.contains(&host.id),
                    "source media differs from exact destination request"
                );
                let verified =
                    c.federation_foreign(proof, &accepted.treaty, &Resolved::default(), replay)?;
                let placement = c.host(host, Some(&accepted.treaty.source_namespace), true)?;
                ensure!(
                    value.manifest.bytes <= placement.profile.maximum_asset_bytes,
                    "source media exceeds exact host asset consent"
                );
                (accepted.treaty, verified)
            } else {
                let (value, source, head, agreement) = revision(c, asset)?;
                let verified = lease(c, proof, &agreement.treaty, &source, intent, replay)?;
                principal(
                    c,
                    intent,
                    operation,
                    &value,
                    &source,
                    &head,
                    &agreement.treaty,
                    *effect,
                    *bytes,
                )?;
                let placement =
                    c.host(host, Some(&agreement.treaty.destination_namespace), true)?;
                ensure!(
                    value.manifest.bytes <= placement.profile.maximum_asset_bytes,
                    "foreign media exceeds exact host asset consent"
                );
                (agreement.treaty, verified)
            };
            let _ = treaty;
            foreign_floor(c, next, changed, &verified, replay)?;
        }
        Command::MediaReceipt { receipt, proof } => {
            let (asset, source, head, agreement) = revision(c, &receipt.asset)?;
            let verified = lease(c, proof, &agreement.treaty, &source, intent, replay)?;
            ensure!(
                head.pending.as_ref() == Some(&asset.revision)
                    && asset.hosts.contains(&receipt.host)
                    && receipt.bytes == asset.manifest.bytes
                    && hex::encode(receipt.digest) == asset.manifest.digest
                    && receipt.recorded_ms <= c.at.saturating_add(250),
                "foreign copy receipt does not bind current exact pending media"
            );
            c.host(
                &receipt.host,
                Some(&agreement.treaty.destination_namespace),
                true,
            )?;
            if intent.requester == receipt.host.id {
                ensure!(
                    operation.grant.is_none(),
                    "host receipt authority is intrinsic"
                );
            } else {
                bridge(c, intent, operation, &agreement.treaty)?;
            }
            let mut evidence = if c.state.records.contains_key(&(145, receipt.asset.id)) {
                page::Evidence::parse(
                    &c.select(145, receipt.asset.id)?.payload,
                    c.state.network,
                    c.state.incarnation,
                )?
            } else {
                page::Evidence {
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
                    "foreign copy receipt replay differs"
                );
            } else {
                evidence.copies.retain(|r| r.host.id != receipt.host.id);
                evidence.copies.push(receipt.clone());
                evidence.copies.sort_by_key(|r| r.host.id);
            }
            put(
                c,
                next,
                changed,
                145,
                receipt.asset.id,
                evidence.value(),
                replay,
            )?;
            foreign_floor(c, next, changed, &verified, replay)?;
        }
        Command::MediaInspect {
            asset,
            receipt,
            expires_ms,
            proof,
        } => {
            let (value, source, head, agreement) = revision(c, asset)?;
            let verified = lease(c, proof, &agreement.treaty, &source, intent, replay)?;
            principal(
                c,
                intent,
                operation,
                &value,
                &source,
                &head,
                &agreement.treaty,
                page::MediaEffect::Inspect,
                value.manifest.bytes,
            )?;
            ensure!(
                *expires_ms > c.at.saturating_add(1250)
                    && *expires_ms <= c.at.saturating_add(page::REVIEW_LIFETIME_MS),
                "foreign inspection exceeds its bounded review interval"
            );
            c.host(
                &receipt.host,
                Some(&agreement.treaty.destination_namespace),
                true,
            )?;
            let mut evidence = page::Evidence::parse(
                &c.select(145, asset.id)?.payload,
                c.state.network,
                c.state.incarnation,
            )?;
            ensure!(
                evidence.asset == *asset
                    && evidence
                        .copies
                        .iter()
                        .any(|r| r.envelope == receipt.envelope),
                "foreign inspection lacks exact retained copy evidence"
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
                        .any(|r| r.intent == intent.digest
                            && r.reviewer == intent.requester
                            && r.expires_ms == *expires_ms),
                    "foreign inspection retry differs"
                );
            } else {
                evidence
                    .inspections
                    .retain(|r| r.reviewer != intent.requester);
                evidence.inspections.push(page::Inspection {
                    reviewer: intent.requester,
                    grant: grant(operation)?.clone(),
                    application,
                    intent: intent.digest,
                    expires_ms: *expires_ms,
                });
                evidence.inspections.sort_by_key(|r| r.reviewer);
            }
            put(c, next, changed, 145, asset.id, evidence.value(), replay)?;
            foreign_floor(c, next, changed, &verified, replay)?;
            c.expires = c.expires.min(*expires_ms);
        }
        _ => anyhow::bail!("unsupported federation media operation"),
    }
    Ok(())
}
