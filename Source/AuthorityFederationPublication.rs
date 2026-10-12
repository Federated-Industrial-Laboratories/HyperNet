// SPDX-License-Identifier: MIT
// Foreign source bytes retain their signed origin and require an independent local decision.
use super::*;

#[cfg(test)]
#[path = "AuthorityFederationAdmissionTests.rs"]
mod admission_tests;

pub(super) fn exported(
    proof: &VerifiedForeign,
    treaty: &Treaty,
    local_epoch: u64,
) -> Result<(page::Revision, page::Review, Record, Share)> {
    let Command::Export {
        agreement,
        admission,
        ..
    } = &proof.command
    else {
        anyhow::bail!("current source Export required")
    };
    ensure!(
        agreement.id == treaty.id,
        "source export names another treaty"
    );
    let Command::Admission {
        page: Some(raw),
        revision: requested,
        agreement: destination,
        ..
    } = admission.command()?
    else {
        anyhow::bail!("exact Page admission required")
    };
    let admitted = admission.intent()?;
    ensure!(
        admitted.minimum_policy_epoch == local_epoch && destination.id == treaty.id,
        "source export relies on another local authority epoch"
    );
    let head = page::Ledger::parse(&proof.state.record(140, page::page_id(&raw)?)?.payload)?;
    let review_ref = head.published.context("foreign source is not published")?;
    let review = page::Review::parse(
        &proof.state.record(142, review_ref.id)?.payload,
        treaty.source.network,
        treaty.source.incarnation,
    )?;
    let native = proof.state.record(141, review.statement.revision.id)?;
    ensure!(
        native.reference == review.statement.revision
            && requested.as_ref().is_none_or(|r| r == &native.reference),
        "foreign native revision differs"
    );
    let metadata = page::Revision::parse(
        &native.payload,
        treaty.source.network,
        treaty.source.incarnation,
    )?;
    let share = proof.state.record(153, share_id(treaty.id, raw)?)?.clone();
    let rights = Share::parse(
        &share.payload,
        treaty.source.network,
        treaty.source.incarnation,
    )?;
    ensure!(
        rights.allowed
            && rights.publication == review_ref
            && rights.revision == native.reference
            && metadata.author.raw_page == raw
            && metadata.author.namespace == treaty.source_namespace,
        "foreign export provenance differs"
    );
    Ok((metadata, review, share, rights))
}
pub(super) fn exact_export(
    proof: &VerifiedForeign,
    treaty: &Treaty,
    value: &ForeignRevision,
    local_epoch: u64,
) -> Result<()> {
    let (metadata, review, share, _) = exported(proof, treaty, local_epoch)?;
    ensure!(
        review.statement.revision == value.native
            && share.reference == value.share
            && review.bundle.as_ref() == Some(&value.bundle)
            && metadata.value() == value.metadata.value(),
        "source rights or exact inspected revision changed"
    );
    Ok(())
}
pub(super) fn review_mode(
    c: &mut page::Evaluation<'_>,
    review: &ForeignReview,
    treaty: &Treaty,
    raw: [u8; 16],
) -> Result<()> {
    let policy = c.application(
        review.reviewer,
        &review.grant,
        review.application.as_ref(),
        "ReviewDecide",
        &treaty.destination_namespace,
        Some(raw),
    )?;
    ensure!(
        policy.is_some() == review.application.is_some()
            && policy.as_ref().map(|p| p.review) == review.policy.map(|p| Some((review.mode, p))),
        "foreign review application mode or policy changed"
    );
    Ok(())
}
pub(super) fn current_review(
    c: &mut page::Evaluation<'_>,
    head: &ForeignPage,
    treaty: &Treaty,
    value: &ForeignRevision,
) -> Result<ForeignReview> {
    let r = c.exact(
        head.published
            .as_ref()
            .context("foreign publication has no local review")?,
    )?;
    let review = ForeignReview::parse(&r.payload, c.state.network, c.state.incarnation)?;
    ensure!(
        review.approve && review.revision.id == value.identity()? && !head.withdrawn,
        "foreign local publication is withdrawn or unapproved"
    );
    c.federation_principal(
        review.reviewer,
        &review.grant,
        review.application.as_ref(),
        3,
        treaty,
        value.page,
        head.raw_page,
        value.bundle.len() as u64,
    )?;
    review_mode(c, &review, treaty, head.raw_page)?;
    Ok(review)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn import(
    c: &mut page::Evaluation<'_>,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    intent: &Intent,
    agreement: &Agreement,
    proof: &VerifiedForeign,
    bundle: &Reference,
    inputs: &Resolved,
    replay: bool,
) -> Result<()> {
    let t = &agreement.treaty;
    let (metadata, review, share, _) = exported(proof, t, intent.minimum_policy_epoch)?;
    ensure!(
        review.bundle.as_ref() == Some(bundle),
        "import is not the exact exported bundle"
    );
    let parsed =
        page::objects::Bundle::parse(inputs.get(bundle)?, t.source.network, t.source.incarnation)?;
    ensure!(
        parsed.author.bytes == metadata.author.bytes
            && parsed.review.bytes == review.statement.bytes,
        "import bytes differ from source approvals"
    );
    metadata.verify_source(&parsed.source)?;
    let id = qualified_page(t.id, &t.source, metadata.author.raw_page)?;
    let revision_id = revision_id(id, &review.statement.revision, &share.reference)?;
    let prior = next.records.get(&(154, id)).cloned();
    let mut head = if let Some(r) = &prior {
        c.select(154, id)?;
        let head = ForeignPage::parse(&r.payload)?;
        ensure!(
            head.source == t.source && head.agreement == t.id,
            "foreign Page origin cannot change"
        );
        let old_id = revision_id_for(&head)?;
        let old = c.select(155, old_id)?;
        let old = ForeignRevision::parse(&old.payload)?;
        ensure!(
            metadata.author.intent.revision >= old.metadata.author.intent.revision
                && (metadata.author.intent.revision != old.metadata.author.intent.revision
                    || old.native == review.statement.revision),
            "foreign revision rolled back or equivocated"
        );
        head
    } else {
        ForeignPage {
            agreement: t.id,
            source: t.source.clone(),
            raw_page: metadata.author.raw_page,
            observed: review.statement.revision.clone(),
            source_share: share.reference.clone(),
            pending: None,
            published: None,
            withdrawn: false,
        }
    };
    let value = ForeignRevision {
        page: id,
        agreement: t.id,
        source: t.source.clone(),
        native: review.statement.revision.clone(),
        share: share.reference.clone(),
        bundle: bundle.clone(),
        imported_at_ms: c.at,
        evidence: proof.digest,
        metadata,
    };
    if let Some(old) = next.records.get(&(155, revision_id)) {
        let existing = ForeignRevision::parse(&old.payload)?;
        ensure!(
            existing.native == value.native
                && existing.share == value.share
                && existing.bundle == value.bundle
                && existing.metadata.value() == value.metadata.value(),
            "retained immutable foreign revision differs"
        );
        c.select(155, revision_id)?;
    } else {
        put(c, next, changed, 155, revision_id, value.value(), false)?;
    }
    let revision = next.record(155, revision_id)?.reference.clone();
    if !replay {
        if head.observed != value.native || head.source_share != value.share {
            head.published = None;
        }
        head.observed = value.native.clone();
        head.source_share = value.share.clone();
        // Re-import never clears a local withdrawal or revives a rejected/approved revision.
        if prior.is_none()
            || prior.as_ref().is_some_and(|r| {
                ForeignPage::parse(&r.payload)
                    .is_ok_and(|p| p.observed != value.native || p.source_share != value.share)
            })
        {
            head.pending = Some(revision.clone());
        }
    }
    put(c, next, changed, 154, id, head.value(), replay)?;
    for manifest in &value.metadata.assets {
        let asset_id = page::asset_id(&revision, &manifest.id)?;
        if let Some(old) = next.records.get(&(144, asset_id)) {
            c.select(144, old.reference.id)?;
            continue;
        }
        let mut hosts = vec![];
        let mut expires = t.expires_ms.min(value.metadata.author.expires_ms);
        for host in &t.destination_hosts {
            let r = c.select(143, *host)?;
            let h = c.host(&r.reference, Some(&t.destination_namespace), true)?;
            ensure!(
                manifest.bytes <= h.profile.maximum_asset_bytes,
                "foreign asset exceeds destination object consent"
            );
            expires = expires.min(
                c.at.checked_add(h.profile.retention_ms)
                    .context("foreign media expiry overflow")?,
            );
            hosts.push(r.reference);
        }
        ensure!(
            t.media_profiles.contains(&manifest.profile) && t.copies >= manifest.copies.into(),
            "foreign media placement does not meet signed source requirements"
        );
        let asset = page::Asset {
            revision: revision.clone(),
            manifest: manifest.clone(),
            hosts,
            required_copies: t.copies.max(c.minimum_copies(&t.destination_namespace)?),
            upload_expires_ms: expires,
            expires_ms: expires,
        };
        page::Asset::parse(&asset.value())?;
        for host in &asset.hosts {
            let h = c.host(host, Some(&t.destination_namespace), true)?;
            let mut charge = page::media_storage_charge(&asset)?;
            for r in next.records.values().filter(|r| r.reference.kind == 144) {
                let old = page::Asset::parse(&r.payload)?;
                if old.expires_ms > c.at && old.hosts.iter().any(|v| v.id == host.id) {
                    charge = charge
                        .checked_add(page::media_storage_charge(&old)?)
                        .context("foreign media storage overflow")?;
                }
            }
            ensure!(
                charge <= page::media_storage_budget(h.profile.state_bytes)?,
                "foreign media exceeds physical destination storage consent"
            );
        }
        put(c, next, changed, 144, asset_id, asset.value(), false)?;
    }
    Ok(())
}
pub(super) fn revision_id_for(head: &ForeignPage) -> Result<Digest> {
    revision_id(head.identity()?, &head.observed, &head.source_share)
}
pub(super) fn maintenance(
    c: &mut page::Evaluation<'_>,
    intent: &Intent,
    operation: &Operation,
    trust: &VersionRef,
) -> Result<()> {
    c.exact(trust)?;
    if let Some(grant) = &operation.grant {
        return c.capability(grant, intent.requester, &[22], (2, trust.id), None, 0);
    }
    let bridge = c.select(152, intent.requester)?;
    let registered = Bridge::parse(&bridge.payload, c.state.network, c.state.incarnation)?;
    for (id, _) in &registered.profile.agreements {
        let r = c.select(151, *id)?;
        let agreement = c.federation_agreement(&r.reference)?;
        if agreement.foreign == *trust {
            c.federation_bridge(&bridge.reference, &agreement.treaty)?;
            return Ok(());
        }
    }
    anyhow::bail!("bridge has no current consent for this foreign authority")
}
