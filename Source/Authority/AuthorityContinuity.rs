// SPDX-License-Identifier: MIT
// Body-free evidence reconnects durable certified floors without retaining protected operation results.
use super::{CertifiedPoint, Node, Prefix, Scope, TrustDescriptor};
use crate::{
    authority_history::{self as history, TreeHead, ValidatedCheckpoint},
    trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct ContinuityEvidence {
    pub ancestry: Vec<Vec<u8>>,
    pub history: Option<Vec<u8>>,
}
pub(crate) fn ancestry(scope: &Scope, bytes: &[Vec<u8>]) -> Result<Vec<Node>> {
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 128
            && bytes
                .iter()
                .try_fold(0usize, |sum, b| sum.checked_add(b.len()))
                .is_some_and(|n| n <= wire::MAXIMUM),
        "ancestry exceeds bounded repair limit"
    );
    let nodes = bytes
        .iter()
        .map(|b| Node::parse(b))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        nodes.iter().all(|n| &n.scope == scope),
        "ancestry belongs to another configuration"
    );
    let mut seen = BTreeSet::new();
    ensure!(
        nodes.iter().all(|n| seen.insert(n.digest)),
        "repeated ancestry node"
    );
    for pair in nodes.windows(2) {
        ensure!(
            pair[0].height.checked_add(1) == Some(pair[1].height)
                && pair[1].parent == pair[0].digest
                && pair[1].view > pair[0].view
                && pair[1].evaluated_at_ms >= pair[0].evaluated_at_ms,
            "noncontiguous result ancestry"
        );
    }
    Ok(nodes)
}
pub(crate) fn extends(point: &CertifiedPoint, ancestry: &[Node], floor: &Prefix) -> Result<()> {
    ensure!(
        point.prefix.scope == floor.scope && point.prefix.height >= floor.height,
        "authority result is below the accepted configuration or prefix"
    );
    if point.prefix.height == floor.height {
        ensure!(
            point.prefix == *floor,
            "conflicting result at retained prefix"
        );
        return Ok(());
    }
    let next = floor
        .height
        .checked_add(1)
        .context("prefix height exhausted")?;
    let start = ancestry
        .iter()
        .position(|n| n.height == next)
        .context("missing ancestry to retained prefix")?;
    let mut previous_digest = floor.node;
    let mut previous_view = floor.view;
    let mut previous_time = floor.evaluated_at_ms;
    let mut height = floor.height;
    for node in &ancestry[start..] {
        height = height.checked_add(1).context("prefix height exhausted")?;
        ensure!(
            node.height == height
                && node.parent == previous_digest
                && node.view > previous_view
                && node.evaluated_at_ms >= previous_time,
            "invalid certified prefix ancestry"
        );
        previous_digest = node.digest;
        previous_view = node.view;
        previous_time = node.evaluated_at_ms;
    }
    ensure!(
        previous_digest == point.prefix.node,
        "ancestry misses certified point"
    );
    Ok(())
}
/// Both endpoints retain their independently validated certificates; this evidence contains no result body.
pub fn validate_continuity(
    descriptor: &TrustDescriptor,
    old_prefix: &Prefix,
    old_head: Option<&TreeHead>,
    next_point: &CertifiedPoint,
    next_checkpoint: Option<&ValidatedCheckpoint>,
    evidence: &ContinuityEvidence,
) -> Result<()> {
    ensure!(
        old_prefix.scope() == descriptor.scope()
            && next_point.prefix().scope() == descriptor.scope()
            && old_head.is_none_or(|h| h.scope() == descriptor.scope()),
        "floor continuity belongs to another configuration"
    );
    if let Some(checkpoint) = next_checkpoint {
        ensure!(
            !checkpoint.terminal()
                && checkpoint.head().scope() == descriptor.scope()
                && checkpoint.height() <= next_point.prefix().height()
                && checkpoint.prefix().view() <= next_point.prefix().view()
                && checkpoint.prefix().evaluated_at_ms() <= next_point.prefix().evaluated_at_ms()
                && (checkpoint.height() != next_point.prefix().height()
                    || checkpoint.prefix() == *next_point.prefix()),
            "next checkpoint conflicts with the retained certified point"
        );
    }
    let anchor = if let Some(proof) = &evidence.history {
        ensure!(
            proof.len() <= wire::MAXIMUM,
            "history continuity exceeds its bound"
        );
        let checkpoint = next_checkpoint.context("history transition omitted its checkpoint")?;
        let verified = history::verify_history(checkpoint, old_prefix, old_head, proof)?;
        verified.ordinary_checkpoint()?.prefix()
    } else {
        ensure!(
            old_head == next_checkpoint.map(ValidatedCheckpoint::head),
            "checkpoint head changed without its authenticated history transition"
        );
        old_prefix.clone()
    };
    if evidence.ancestry.is_empty() {
        ensure!(
            evidence.history.is_none() && next_point.prefix() == old_prefix,
            "advancing floor omitted its ancestry"
        );
        return Ok(());
    }
    let nodes = ancestry(descriptor.scope(), &evidence.ancestry)?;
    let tip = nodes.last().context("missing continuity tip")?;
    ensure!(
        tip.canonical == next_point.node(),
        "continuity ancestry ends at another certified point"
    );
    extends(next_point, &nodes, &anchor)
}
