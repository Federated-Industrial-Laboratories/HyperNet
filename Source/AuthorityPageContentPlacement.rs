// SPDX-License-Identifier: MIT
// Approval requires durable acknowledgements; reads retain placement metadata even when copies degrade.
use super::*;
pub(crate) fn select_replica(
    c: &mut Evaluation<'_>,
    revision_ref: &VersionRef,
    revision: &Revision,
    host: &VersionRef,
) -> Result<bool> {
    let selected = select_placement(c, revision_ref, revision, false)?;
    let placement = live(c, &selected)?;
    ensure!(
        placement.hosts.contains(host),
        "replica host is outside the author's exact content placement"
    );
    if !c.state.records.contains_key(&(COPIES_KIND, selected.id)) {
        return Ok(false);
    }
    let record = c.select(COPIES_KIND, selected.id)?;
    let copies = Copies::parse(&record.payload, c.state.network, c.state.incarnation)?;
    Ok(copies.copies.iter().any(|copy| copy.host == *host))
}
pub(crate) fn select_placement(
    c: &mut Evaluation<'_>,
    revision_ref: &VersionRef,
    revision: &Revision,
    require_complete: bool,
) -> Result<VersionRef> {
    let id = identity(
        "PageContentPlacement",
        vec![
            reference(revision_ref),
            b(&revision.author.source.content_sha256()),
        ],
    )?;
    let record = c.select(PLACEMENT_KIND, id)?;
    let placement = Placement::parse(&record.payload)?;
    let withdrawn = if c.state.records.contains_key(&(TOMBSTONE_KIND, id)) {
        let tombstone = c.select(TOMBSTONE_KIND, id)?;
        ensure!(
            Tombstone::parse(&tombstone.payload)?.placement == record.reference,
            "content withdrawal names another placement"
        );
        true
    } else {
        false
    };
    let available = !withdrawn && placement.expires_ms > c.at;
    if require_complete {
        live(c, &record.reference)?;
    }
    ensure!(
        placement.revision == *revision_ref
            && placement.owner == revision.author.intent.requester
            && placement.namespace == revision.author.namespace
            && placement.digest == revision.author.source.content_sha256()
            && placement.bytes == revision.author.source.len() as u64
            && !placement.opaque,
        "content placement differs from selected source revision"
    );
    // Retain current host records even after withdrawal. A missing live copy changes availability,
    // while publication and requester permissions continue to be checked independently.
    for host in &placement.hosts {
        let current = c.select(147, host.id)?;
        c.host(&current.reference, Some(&placement.namespace), false)?;
    }
    let mut count = 0u64;
    let mut domains = BTreeSet::new();
    if c.state.records.contains_key(&(COPIES_KIND, id)) {
        let copies = c.select(COPIES_KIND, id)?;
        let copies = Copies::parse(&copies.payload, c.state.network, c.state.incarnation)?;
        ensure!(
            copies.placement == record.reference,
            "content acknowledgements name another placement"
        );
        for receipt in &copies.copies {
            ensure!(
                placement.hosts.contains(&receipt.host)
                    && receipt.digest == placement.digest
                    && receipt.bytes == placement.bytes
                    && receipt.expires_ms == placement.expires_ms
                    && receipt.recorded_ms <= c.at,
                "content acknowledgement differs from exact object"
            );
            if available
                && let Some(host) =
                    c.optional(|c| c.host(&receipt.host, Some(&placement.namespace), true))
            {
                let policy = host
                    .profile
                    .content
                    .as_ref()
                    .context("complete content host lacks storage consent")?;
                ensure!(
                    placement.bytes <= host.profile.maximum_asset_bytes,
                    "complete content exceeds host consent"
                );
                count += 1;
                domains.insert(policy.failure_domain);
            }
        }
    }
    ensure!(
        !require_complete
            || (count >= placement.copies && domains.len() as u64 >= placement.failure_domains),
        "content acknowledgements do not meet required copies and failure domains"
    );
    Ok(record.reference)
}
