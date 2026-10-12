// SPDX-License-Identifier: MIT
//! Certified applied-state checkpoints retain signer-local safety obligations.
use super::*;
use crate::authority_history as history;
use std::collections::BTreeSet;

pub const INTERVAL: u64 = 32;
pub const MAX_STATE: usize = crate::authority_capacity::MAX_STATE_BYTES;
pub const CHUNK: usize = 16384;
#[derive(Debug)]
pub struct HistoryOvertaken;
impl std::fmt::Display for HistoryOvertaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Certified checkpoint overtook the requested history target")
    }
}
impl std::error::Error for HistoryOvertaken {}

pub fn chunk(input: &[u8]) -> Result<(Digest, usize, usize, Vec<u8>)> {
    let value = wire::decode(input)?;
    let a = record(&value, 48, 6)?;
    let total = usize::try_from(a[3].uint()?)?;
    let index = usize::try_from(a[4].uint()?)?;
    let data = a[5].bytes()?;
    ensure!(
        (1..=MAX_STATE).contains(&total)
            && index < total.div_ceil(CHUNK)
            && data.len() == (total - index * CHUNK).min(CHUNK),
        "Checkpoint chunk dimensions differ"
    );
    Ok((records::nonzero(&a[2])?, total, index, data.to_vec()))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Candidate {
    pub state: Vec<u8>,
    pub share: Vec<u8>,
    pub deciding: Digest,
    pub target: Digest,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Certified {
    pub state: Vec<u8>,
    pub proof: Vec<u8>,
}
pub fn verified(config: &Configuration, proof: &[u8]) -> Result<history::ValidatedCheckpoint> {
    let checkpoint = history::verify_checkpoint(config.descriptor(), proof)?;
    ensure!(
        !checkpoint.terminal(),
        "Terminal checkpoint requires epoch activation"
    );
    Ok(checkpoint)
}
pub fn share(config: &Configuration, input: &[u8]) -> Result<(Vec<u8>, Key, [u8; 64])> {
    let value = wire::decode(input)?;
    let a = value.array(2)?;
    let (statement, signatures) = wire::envelope(a[0].bytes()?, 1)?;
    ensure!(signatures.len() == 1, "Checkpoint share has one signer");
    config.member(&signatures[0].0)?;
    let v = wire::decode(&statement)?;
    let s = record(&v, 45, 10)?;
    let anchor = Node::parse(config, a[1].bytes()?)?;
    ensure!(
        Scope::parse(&s[2])? == config.scope
            && anchor.height > 0
            && anchor.height.is_multiple_of(INTERVAL)
            && s[3].uint()? == anchor.height
            && s[4].fixed::<32>()? == anchor.digest()?
            && s[5].uint()? == anchor.evaluated_at
            && s[7].uint()? == anchor.height
            && anchor.height <= archive::MAX_LEAVES as u64
            && !s[9].boolean()?,
        "Checkpoint share binding differs"
    );
    s[6].fixed::<32>()?;
    s[8].fixed::<32>()?;
    Ok((statement, signatures[0].0, signatures[0].1))
}
fn fields(proof: &[u8]) -> Result<Vec<u8>> {
    let value = wire::decode(proof)?;
    let a = record(&value, 46, 4)?;
    Ok(a[3].bytes()?.to_vec())
}
fn certified_prefix(
    config: &Configuration,
    n: &Node,
    height: u64,
    leaves: &[Digest],
) -> Result<bool> {
    Ok(n.height == 0 && *n == config.genesis()
        || n.height > 0
            && n.height <= height
            && leaves.get(n.height as usize - 1) == Some(&n.digest()?))
}
fn verify_safety_paths(
    config: &Configuration,
    state: &Snapshot,
    height: u64,
    leaves: &[Digest],
) -> Result<()> {
    for reference in [state.highest_prepare, state.locked] {
        let qc = certificate(config, state, &reference)?;
        let mut cursor = qc.node;
        let mut seen = BTreeSet::new();
        loop {
            ensure!(
                seen.insert(cursor) && seen.len() <= MAX_NODES,
                "Safety ancestry exceeds its bound"
            );
            let n = node(config, state, &cursor)?;
            if certified_prefix(config, &n, height, leaves)? {
                break;
            }
            // A detached lock remains a verified local branch. Only an exact
            // archive-authenticated common prefix can terminate its ancestry.
            let parent_digest = n
                .parent
                .context("Safety branch has no authenticated prefix")?;
            let parent = node(config, state, &parent_digest)?;
            let justify = certificate(
                config,
                state,
                &n.justify.context("Safety justification is missing")?,
            )?;
            ensure!(
                justify.phase == Phase::Prepare
                    && justify.node == parent_digest
                    && justify.view < n.view
                    && n.height == parent.height.checked_add(1).context("Height overflow")?
                    && n.view > parent.view
                    && n.evaluated_at >= parent.evaluated_at,
                "Safety ancestry is not a verified branch"
            );
            let command = state
                .commands
                .get(&id(&n.command.context("Safety command is missing")?))
                .context("Safety command dependency is missing")?;
            ensure!(
                Command::parse(config, &body(state, command)?)?.minimum_height() <= n.height,
                "Safety branch precedes its request floor"
            );
            cursor = parent_digest;
        }
    }
    Ok(())
}
impl Engine {
    pub(super) fn checkpoint_admission(&self, height: u64) -> Result<()> {
        ensure!(
            height <= archive::MAX_LEAVES as u64,
            "Committed history capacity exhausted"
        );
        Ok(())
    }
    pub(super) fn validate_checkpoint_snapshot(&self) -> Result<()> {
        let s = &self.snapshot;
        ensure!(
            s.archive_size == self.applied()?.height
                && s.archive_root == self.archive.tree_root()
                && s.archive_size as usize == self.archive.leaves().len()
                && s.candidates.len() <= 2,
            "Signer history position differs from applied state"
        );
        if s.archive_size > 0 {
            ensure!(
                self.archive.leaves().last() == Some(&s.applied),
                "Applied node differs from history"
            );
        }
        let height = if let Some(c) = &s.checkpoint {
            let verified = verified(&self.configuration, &c.proof)?;
            ensure!(
                verified.height() <= s.archive_size
                    && s.prefix_nodes.get(&id(verified.node())) == Some(&verified.height())
                    && c.state.len() <= MAX_STATE
                    && wire::digest(&c.state) == *verified.state()
                    && self.archive.leaves()[verified.height() as usize - 1] == *verified.node()
                    && archive::root(&self.archive.leaves()[..verified.height() as usize])
                        == *verified.head().root(),
                "Retained checkpoint differs from archive or state"
            );
            wire::decode_state(&c.state)?;
            verify_safety_paths(
                &self.configuration,
                s,
                verified.height(),
                self.archive.leaves(),
            )?;
            verified.height()
        } else {
            ensure!(
                s.prefix_nodes.is_empty(),
                "Archived prefix lacks a checkpoint"
            );
            0
        };
        ensure!(
            s.retired_view <= s.sync.entered.saturating_sub(2),
            "Retired view exceeds entered-view floor"
        );
        for (digest, h) in &s.prefix_nodes {
            let n = node(
                &self.configuration,
                s,
                &hex::decode(digest)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid prefix identifier"))?,
            )?;
            ensure!(
                n.height == *h
                    && *h <= height
                    && if *h == 0 {
                        n == self.configuration.genesis()
                    } else {
                        self.archive.leaves().get(*h as usize - 1) == Some(&n.digest()?)
                    },
                "Retained prefix header is not archived"
            );
        }
        ensure!(
            s.checkpoint_floor == height,
            "Checkpoint signing floor differs from certified state"
        );
        for (h, c) in &s.candidates {
            let (statement, signer, _) = share(&self.configuration, &c.share)?;
            let v = wire::decode(&statement)?;
            let a = record(&v, 45, 10)?;
            ensure!(
                signer == self.signer()
                    && *h > height
                    && *h <= s.archive_size
                    && a[3].uint()? == *h
                    && c.state.len() <= MAX_STATE
                    && wire::digest(&c.state) == a[6].fixed::<32>()?
                    && self.archive.leaves()[*h as usize - 1] == a[4].fixed::<32>()?
                    && archive::root(&self.archive.leaves()[..*h as usize])
                        == a[8].fixed::<32>()?,
                "Durable checkpoint candidate differs"
            );
            wire::decode_state(&c.state)?;
            let deciding = certificate(&self.configuration, s, &c.deciding)?;
            ensure!(
                deciding.phase == Phase::Commit
                    && deciding.node == c.target
                    && extends(&self.configuration, s, c.target, a[4].fixed::<32>()?)?,
                "Candidate lost actual deciding ancestry"
            );
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn install_checkpoint(
        &mut self,
        proof: &[u8],
        state: &[u8],
        leaves: &[Digest],
        validate: impl FnOnce(&[u8], u64) -> Result<()>,
        expired_before: Option<u64>,
    ) -> Result<()> {
        self.install_checkpoint_with_inputs(proof, state, leaves, &[], validate, expired_before)
    }
    pub fn install_checkpoint_with_inputs(
        &mut self,
        proof: &[u8],
        state: &[u8],
        leaves: &[Digest],
        references: &[crate::authority_objects::Reference],
        validate: impl FnOnce(&[u8], u64) -> Result<()>,
        expired_before: Option<u64>,
    ) -> Result<()> {
        self.active()?;
        let c = verified(&self.configuration, proof)?;
        ensure!(
            c.height() > self.applied()?.height
                && state.len() <= MAX_STATE
                && wire::digest(state) == *c.state()
                && leaves.len() as u64 == c.height()
                && leaves.len() <= archive::MAX_LEAVES
                && leaves.last() == Some(c.node())
                && archive::root(leaves) == *c.head().root(),
            "Transferred checkpoint state or archive differs"
        );
        wire::decode_state(state)?;
        validate(state, c.height())?;
        self.input_reader()?.verify(references)?;
        ensure!(
            leaves.starts_with(self.archive.leaves()),
            "Transferred archive replaces the retained committed prefix"
        );
        let committed = self.committed()?;
        if committed.height <= c.height() {
            ensure!(
                committed.height == 0
                    || leaves[committed.height as usize - 1] == committed.digest()?,
                "Transferred checkpoint conflicts with committed state"
            );
        } else {
            ensure!(
                extends(
                    &self.configuration,
                    &self.snapshot,
                    self.snapshot.committed,
                    *c.node()
                )?,
                "Transfer does not extend the locally committed suffix"
            );
        }
        let mut next = self.snapshot.clone();
        let anchor = fields(proof)?;
        let object = objects(&next)?.staged(14, *c.node(), &anchor)?;
        next.nodes.insert(id(c.node()), object);
        next.apply_cursor = None;
        next.checkpoint_floor = next.checkpoint_floor.max(c.height());
        next.applied = *c.node();
        if committed.height < c.height() {
            next.committed = *c.node();
        }
        next.application = state.to_vec();
        next.inputs.set_application(references)?;
        next.inputs.checkpoint(wire::digest(state), references)?;
        next.archive_size = c.height();
        next.archive_root = *c.head().root();
        next.checkpoint = Some(Certified {
            proof: proof.to_vec(),
            state: state.to_vec(),
        });
        next.candidates.retain(|h, _| *h > c.height());
        // An applied-state certificate permits state adoption, not a new
        // vote or an unlock. Preserve the existing signer's exact voting safety
        // fields; normal phase processing alone can later replace its lock.
        self.compact_snapshot(&mut next, expired_before, leaves, false)?;
        ensure!(
            next.highest_prepare == self.snapshot.highest_prepare
                && next.locked == self.snapshot.locked
                && next.own_votes == self.snapshot.own_votes
                && next.retired_view == self.snapshot.retired_view,
            "Checkpoint changed local voting safety fields"
        );
        self.publish_applied(next, &leaves[self.snapshot.archive_size as usize..])
    }
    pub fn checkpoint_shares(&self) -> Vec<Vec<u8>> {
        self.snapshot
            .candidates
            .values()
            .map(|c| c.share.clone())
            .collect()
    }
    pub fn checkpoint_proof(&self) -> Option<&[u8]> {
        self.snapshot
            .checkpoint
            .as_ref()
            .map(|c| c.proof.as_slice())
    }
    pub fn checkpoint_state(&self, digest: Digest) -> Result<&[u8]> {
        let value = self
            .snapshot
            .checkpoint
            .as_ref()
            .context("Certified checkpoint is unavailable")?;
        ensure!(
            *verified(&self.configuration, &value.proof)?.digest() == digest,
            "Checkpoint identity differs"
        );
        Ok(&value.state)
    }
    pub fn checkpoint_leaves(&self, digest: Digest) -> Result<&[Digest]> {
        let proof = self
            .checkpoint_proof()
            .context("Certified checkpoint is unavailable")?;
        let c = verified(&self.configuration, proof)?;
        ensure!(*c.digest() == digest, "Checkpoint identity differs");
        Ok(&self.archive.leaves()[..c.height() as usize])
    }
    pub fn combine_checkpoint(
        &self,
        statement: &[u8],
        signatures: &BTreeMap<Key, [u8; 64]>,
    ) -> Result<Vec<u8>> {
        let candidate = self
            .snapshot
            .candidates
            .values()
            .find(|c| share(&self.configuration, &c.share).is_ok_and(|s| s.0 == statement))
            .context("Checkpoint shares do not match a durable local candidate")?;
        let value = wire::decode(&candidate.share)?;
        let a = value.array(2)?;
        let b = records::bytes;
        let envelope = wire::encode(&V::Array(vec![
            V::Uint(0),
            V::Uint(1),
            b(statement),
            V::Array(
                signatures
                    .iter()
                    .map(|(k, s)| V::Array(vec![b(k), b(s)]))
                    .collect(),
            ),
        ]))?;
        let proof = wire::encode(&V::Array(vec![
            V::Uint(46),
            V::Uint(1),
            b(&envelope),
            a[1].clone(),
        ]))?;
        verified(&self.configuration, &proof)?;
        Ok(proof)
    }
    pub fn accept_checkpoint(&mut self, proof: &[u8], expired_before: Option<u64>) -> Result<bool> {
        self.active()?;
        let c = verified(&self.configuration, proof)?;
        if let Some(old) = self.snapshot.checkpoint.as_ref() {
            let old = verified(&self.configuration, &old.proof)?;
            if old.height() >= c.height() {
                ensure!(
                    old.height() != c.height() || old.digest() == c.digest(),
                    "Conflicting checkpoint at a retained height"
                );
                return Ok(false);
            }
        }
        let Some(candidate) = self.snapshot.candidates.get(&c.height()) else {
            return Ok(false);
        };
        let (statement, _, _) = share(&self.configuration, &candidate.share)?;
        ensure!(
            statement == c.statement() && wire::digest(&candidate.state) == *c.state(),
            "Certified state differs from local applied candidate"
        );
        let mut next = self.snapshot.clone();
        next.checkpoint = Some(Certified {
            state: candidate.state.clone(),
            proof: proof.to_vec(),
        });
        next.candidates.retain(|h, _| *h > c.height());
        next.checkpoint_floor = next.checkpoint_floor.max(c.height());
        self.compact_snapshot(&mut next, expired_before, self.archive.leaves(), true)?;
        self.persist(next)?;
        Ok(true)
    }
    pub(super) fn candidate(
        &self,
        next: &mut Snapshot,
        applied: &Node,
        state: Vec<u8>,
    ) -> Result<()> {
        if !applied.height.is_multiple_of(INTERVAL) {
            return Ok(());
        }
        let references = next.inputs.application().to_vec();
        next.inputs.checkpoint(wire::digest(&state), &references)?;
        ensure!(
            applied.height > next.checkpoint_floor
                && !next.candidates.contains_key(&applied.height)
                && next.candidates.len() < 2
                && state.len() <= MAX_STATE,
            "Checkpoint candidate capacity or signing floor refuses"
        );
        let b = records::bytes;
        let statement = wire::encode(&V::Array(vec![
            V::Uint(45),
            V::Uint(1),
            self.configuration.scope.value(),
            V::Uint(applied.height),
            b(&applied.digest()?),
            V::Uint(applied.evaluated_at),
            b(&wire::digest(&state)),
            V::Uint(next.archive_size),
            b(&next.archive_root),
            V::Bool(false),
        ]))?;
        let envelope = wire::sign_envelope(&statement, &self.key)?;
        let (deciding, target) = self.applied_candidate_commitment(applied)?;
        let share = wire::encode(&V::Array(vec![b(&envelope), b(&applied.encode()?)]))?;
        next.candidates.insert(
            applied.height,
            Candidate {
                state,
                share,
                deciding,
                target,
            },
        );
        Ok(())
    }
    pub fn compact(&mut self, expired_before: Option<u64>) -> Result<()> {
        let mut next = self.snapshot.clone();
        self.compact_snapshot(&mut next, expired_before, self.archive.leaves(), true)?;
        if next.nodes.len() != self.snapshot.nodes.len()
            || next.commands.len() != self.snapshot.commands.len()
            || next.certificates.len() != self.snapshot.certificates.len()
            || next.votes.len() != self.snapshot.votes.len()
            || next.own_votes.len() != self.snapshot.own_votes.len()
            || next.reports.len() != self.snapshot.reports.len()
            || next.proposals.len() != self.snapshot.proposals.len()
            || next.commit_certificates.len() != self.snapshot.commit_certificates.len()
            || next.executed.len() != self.snapshot.executed.len()
            || next.retired_view != self.snapshot.retired_view
        {
            self.persist(next)?;
        }
        Ok(())
    }
    pub(super) fn compact_snapshot(
        &self,
        next: &mut Snapshot,
        expired_before: Option<u64>,
        leaves: &[Digest],
        retire_votes: bool,
    ) -> Result<()> {
        let (height, anchor) = if let Some(checkpoint) = &next.checkpoint {
            let c = verified(&self.configuration, &checkpoint.proof)?;
            ensure!(
                c.height() <= next.archive_size
                    && leaves[c.height() as usize - 1] == *c.node()
                    && archive::root(&leaves[..c.height() as usize]) == *c.head().root(),
                "Checkpoint archive binding differs"
            );
            let bytes = fields(&checkpoint.proof)?;
            (c.height(), Some((*c.node(), bytes)))
        } else {
            (0, None)
        };
        let prefix = |n: &Node| certified_prefix(&self.configuration, n, height, leaves);
        verify_safety_paths(&self.configuration, next, height, leaves)?;
        if retire_votes {
            // Entered views never decrease, independently of application progress.
            // Retire exact old signatures atomically with their no-resign floor.
            let floor = next.sync.entered.saturating_sub(2).max(next.retired_view);
            next.retired_view = floor;
            next.votes.retain(|_, v| {
                SignedVote::parse(&self.configuration, v).is_ok_and(|s| s.vote.view > floor)
            });
            next.own_votes.retain(|_, v| {
                SignedVote::parse(&self.configuration, v).is_ok_and(|s| s.vote.view > floor)
            });
            next.reports.retain(|_, v| {
                NewView::parse(&self.configuration, v).is_ok_and(|s| s.view > floor)
            });
            next.proposals.retain(|view, _| *view > floor);
        }
        next.executed.retain(|_, e| {
            !(e.height <= height && expired_before.is_some_and(|at| e.expires <= at))
        });
        let mut nodes = BTreeSet::from([
            self.configuration.genesis().digest()?,
            next.committed,
            next.applied,
        ]);
        if let Some((digest, bytes)) = anchor {
            nodes.insert(digest);
            let object = objects(next)?.staged(14, digest, &bytes)?;
            next.nodes.insert(id(&digest), object);
        }
        nodes.extend(Self::cursor_roots(next));
        for candidate in next.candidates.values() {
            nodes.insert(candidate.target);
        }
        let mut certs = BTreeSet::from([
            self.configuration.genesis_qc()?.digest(),
            next.highest_prepare,
            next.locked,
        ]);
        if let Some(qc) = Self::cursor_certificate(next) {
            certs.insert(qc);
        }
        for candidate in next.candidates.values() {
            certs.insert(candidate.deciding);
        }
        for object in next.certificates.values() {
            let qc = Certificate::parse(&self.configuration, &body(next, object)?)?;
            if qc.view > next.retired_view {
                certs.insert(qc.digest());
            }
        }
        if let Some(qc) = next.commit_certificates.get(&id(&next.committed)) {
            certs.insert(*qc);
        }
        for bytes in next.reports.values() {
            certs.insert(NewView::parse(&self.configuration, bytes)?.prepare);
        }
        for bytes in next.votes.values().chain(next.own_votes.values()) {
            nodes.insert(SignedVote::parse(&self.configuration, bytes)?.vote.node);
        }
        for bytes in next.proposals.values() {
            nodes.insert(Node::parse(&self.configuration, &wire::envelope(bytes, 1)?.0)?.digest()?);
        }
        for digest in next.executed.keys() {
            nodes.insert(
                hex::decode(digest)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid executed node"))?,
            );
        }
        let mut pending_nodes: std::collections::VecDeque<_> = nodes.iter().copied().collect();
        let mut pending_certs: std::collections::VecDeque<_> = certs.iter().copied().collect();
        while !pending_nodes.is_empty() || !pending_certs.is_empty() {
            while let Some(digest) = pending_certs.pop_front() {
                let target = certificate(&self.configuration, next, &digest)?.node;
                if nodes.insert(target) {
                    pending_nodes.push_back(target);
                }
            }
            if let Some(digest) = pending_nodes.pop_front() {
                let n = node(&self.configuration, next, &digest)?;
                if !prefix(&n)? {
                    if let Some(parent) = n.parent
                        && nodes.insert(parent)
                    {
                        pending_nodes.push_back(parent);
                    }
                    if let Some(justify) = n.justify
                        && certs.insert(justify)
                    {
                        pending_certs.push_back(justify);
                    }
                }
            }
            ensure!(
                nodes.len() <= MAX_NODES && certs.len() <= MAX_CERTIFICATES,
                "Safety closure exceeds bound"
            );
        }
        next.prefix_nodes.clear();
        let mut commands = BTreeSet::new();
        for digest in &nodes {
            let n = node(&self.configuration, next, digest)?;
            if height > 0 && prefix(&n)? {
                next.prefix_nodes.insert(id(digest), n.height);
            }
            if let Some(command) = n.command {
                commands.insert(id(&command));
            }
        }
        let node_keys: BTreeSet<_> = nodes.iter().map(id).collect();
        let cert_keys: BTreeSet<_> = certs.iter().map(id).collect();
        next.nodes.retain(|key, _| node_keys.contains(key));
        next.certificates.retain(|key, _| cert_keys.contains(key));
        next.commands.retain(|key, _| commands.contains(key));
        let checkpoints = next
            .candidates
            .values()
            .map(|c| id(&wire::digest(&c.state)))
            .chain(next.checkpoint.iter().map(|c| id(&wire::digest(&c.state))))
            .collect();
        next.inputs.retain(&commands, &checkpoints);
        next.commit_certificates
            .retain(|_, digest| certs.contains(digest));
        Ok(())
    }
    pub fn history_reply(
        &self,
        height: u64,
        from: Digest,
        target: Digest,
        prior_size: u64,
        prior_root: Option<Digest>,
    ) -> Result<Vec<u8>> {
        self.active()?;
        let proof = self
            .checkpoint_proof()
            .context("Certified checkpoint unavailable")?;
        let c = verified(&self.configuration, proof)?;
        ensure!(
            height <= c.height()
                && prior_size <= height
                && (prior_size == 0) == prior_root.is_none(),
            "History retained position differs"
        );
        let leaves = &self.archive.leaves()[..c.height() as usize];
        ensure!(
            if height == 0 {
                from == self.configuration.genesis().digest()?
            } else {
                leaves[height as usize - 1] == from
            },
            "History retained node differs"
        );
        if let Some(root) = prior_root {
            ensure!(
                archive::root(&leaves[..prior_size as usize]) == root,
                "History retained root differs"
            );
        }
        if let Some(index) = leaves.iter().position(|digest| *digest == target)
            && (index as u64 + 1) < c.height()
        {
            ensure!(
                index as u64 + 1 >= height,
                "History target precedes retained position"
            );
            return Err(HistoryOvertaken.into());
        }
        let b = records::bytes;
        let inclusion = if height == 0 {
            vec![]
        } else {
            archive::inclusion(leaves, height as usize - 1)?
        };
        let consistency = if prior_size == 0 {
            vec![]
        } else {
            archive::consistency(leaves, prior_size as usize)?
        };
        let history = wire::encode(&V::Array(vec![
            V::Uint(47),
            V::Uint(1),
            self.configuration.scope.value(),
            V::Uint(height),
            b(&from),
            b(c.digest()),
            V::Array(inclusion.iter().map(|v| b(v)).collect()),
            V::Uint(prior_size),
            prior_root.as_ref().map_or(V::Null, |r| b(r)),
            V::Array(consistency.iter().map(|v| b(v)).collect()),
        ]))?;
        let suffix = self.ancestry(c.height(), *c.node(), target)?;
        wire::encode(&V::Array(vec![
            V::Uint(54),
            V::Uint(1),
            self.configuration.scope.value(),
            b(&target),
            b(proof),
            b(&history),
            V::Array(suffix.into_iter().map(V::Bytes).collect()),
        ]))
    }
}

#[cfg(test)]
#[path = "ConsensusCheckpointTests.rs"]
pub(crate) mod tests;
