// SPDX-License-Identifier: MIT
//! Bounded requested checkpoint transfer; single shares never publish remote state.
use super::super::archive::History;
use super::super::checkpoint;
use super::peer::InputAnchor;
use super::*;
use crate::authority_objects::{Object, Reference, Unavailable};
use std::collections::BTreeSet;

const TRANSFER_LIFETIME: Duration = Duration::from_secs(120);
pub(super) struct ServedCheckpoint {
    id: Digest,
    digest: Digest,
    height: usize,
    root: Digest,
    state: Vec<u8>,
    deadline: Instant,
}

pub(super) struct Transfer {
    proof: Vec<u8>,
    digest: Digest,
    height: usize,
    id: Digest,
    state: Vec<u8>,
    total: Option<usize>,
    leaves: super::super::archive::Staged,
    pending: Message,
    deadline: Instant,
}
impl Transfer {
    pub(super) fn pending_message(&self) -> &Message {
        &self.pending
    }
}
impl Driver {
    fn checkpoint_expired_before(&self) -> Option<u64> {
        self.now().ok().and_then(|n| n.checked_sub(1250))
    }
    pub(super) fn checkpoint_emit(&mut self) -> Result<()> {
        let mut active: Vec<_> = self
            .engine
            .checkpoint_shares()
            .into_iter()
            .map(Message::CheckpointShare)
            .collect();
        if let Some(proof) = self.engine.checkpoint_proof() {
            active.push(Message::CheckpointProof(proof.to_vec()));
        }
        let identities: BTreeSet<_> = active
            .iter()
            .map(|m| m.payload().map(|p| wire::digest(&p)))
            .collect::<Result<_>>()?;
        self.outbox.retain(|_, (_, m, _)| {
            !matches!(m, Message::CheckpointShare(_) | Message::CheckpointProof(_))
                || m.payload()
                    .is_ok_and(|p| identities.contains(&wire::digest(&p)))
        });
        let candidate_ids: BTreeSet<_> = self
            .engine
            .checkpoint_shares()
            .iter()
            .map(|s| checkpoint::share(self.config(), s).map(|s| wire::digest(&s.0)))
            .collect::<Result<_>>()?;
        self.checkpoint_votes
            .retain(|key, _| candidate_ids.contains(key));
        for message in active {
            self.broadcast(message)?;
        }
        self.prune_queues()
    }
    pub(super) fn checkpoint_tick(&mut self) -> Result<()> {
        if self.engine.snapshot.nodes.len() >= 128
            || self.engine.snapshot.executed.len() >= super::super::storage::MAX_RESULTS
        {
            self.engine.compact(self.checkpoint_expired_before())?;
        }
        let applied = self.engine.applied()?.height;
        let expired: Vec<_> = self
            .transfers
            .iter()
            .filter(|(_, t)| t.deadline <= Instant::now() || t.height as u64 <= applied)
            .map(|(peer, t)| (*peer, t.id))
            .collect();
        for (peer, id) in expired {
            self.transfers.remove(&peer);
            self.engine.unpin_checkpoint_inputs(&id);
        }
        self.expire_served(Instant::now());
        self.engine.prune_input_orphans()?;
        for (peer, t) in &self.transfers {
            self.send_checkpoint_pending(*peer, &t.pending)?;
        }
        self.checkpoint_emit()
    }
    pub(super) fn checkpoint_receive(&mut self, sender: Key, message: Message) -> Result<()> {
        match message {
            Message::CheckpointShare(bytes) => {
                let (statement, signer, signature) = checkpoint::share(self.config(), &bytes)?;
                let known =
                    self.engine.checkpoint_shares().iter().any(|s| {
                        checkpoint::share(self.config(), s).is_ok_and(|s| s.0 == statement)
                    });
                if !known {
                    return Ok(());
                }
                let votes = self
                    .checkpoint_votes
                    .entry(wire::digest(&statement))
                    .or_default();
                votes.entry(signer).or_insert(signature);
                if votes.len() >= 3 {
                    let proof = self.engine.combine_checkpoint(&statement, votes)?;
                    self.engine
                        .accept_checkpoint(&proof, self.checkpoint_expired_before())?;
                    self.checkpoint_emit()?;
                }
            }
            Message::CheckpointProof(proof) => {
                let c = checkpoint::verified(self.config(), &proof)?;
                if c.height() <= self.engine.applied()?.height {
                    self.engine
                        .accept_checkpoint(&proof, self.checkpoint_expired_before())?;
                    self.checkpoint_emit()?;
                    return Ok(());
                }
                if sender == self.engine.signer() || self.transfers.contains_key(&sender) {
                    return Ok(());
                }
                ensure!(
                    self.transfers.len() < 3,
                    "Checkpoint transfer capacity exhausted"
                );
                let digest = *c.digest();
                let height = c.height() as usize;
                let id = rand::random();
                let pending = Message::StateRequest(id, digest, 0);
                self.send(sender, &pending)?;
                self.transfers.insert(
                    sender,
                    Transfer {
                        proof,
                        digest,
                        height,
                        id,
                        state: vec![],
                        total: None,
                        leaves: self.engine.archive.stage()?,
                        pending,
                        deadline: Instant::now() + TRANSFER_LIFETIME,
                    },
                );
            }
            Message::CheckpointSuperseded(id, digest, proof) => {
                let checkpoint = checkpoint::verified(self.config(), &proof)?;
                let owner = self
                    .transfers
                    .iter()
                    .find(|(_, t)| t.id == id && t.digest == digest)
                    .map(|(owner, _)| *owner)
                    .context("Unsolicited checkpoint replacement")?;
                let previous = &self.transfers[&owner];
                // Alternate object sources cannot redirect another peer's snapshot.
                if owner != sender {
                    return Ok(());
                }
                ensure!(
                    previous.id == id
                        && previous.digest == digest
                        && previous.deadline > Instant::now()
                        && checkpoint.height() as usize > previous.height
                        && checkpoint.height() > self.engine.applied()?.height,
                    "Checkpoint replacement differs from the active request"
                );
                let deadline = previous.deadline;
                self.engine.unpin_checkpoint_inputs(&previous.id);
                let digest = *checkpoint.digest();
                let height = checkpoint.height() as usize;
                let id = rand::random();
                let pending = Message::StateRequest(id, digest, 0);
                self.send(sender, &pending)?;
                self.transfers.insert(
                    sender,
                    Transfer {
                        proof,
                        digest,
                        height,
                        id,
                        state: vec![],
                        total: None,
                        leaves: self.engine.archive.stage()?,
                        pending,
                        deadline,
                    },
                );
            }
            Message::StateRequest(id, digest, index) => {
                if !self.serve_checkpoint(sender, id, digest)? {
                    return Ok(());
                }
                let state = &self.served_checkpoints[&sender].state;
                let index = usize::try_from(index)?;
                ensure!(
                    index < state.len().div_ceil(checkpoint::CHUNK),
                    "State request index is outside checkpoint"
                );
                let start = index * checkpoint::CHUNK;
                let end = (start + checkpoint::CHUNK).min(state.len());
                let b = super::super::records::bytes;
                let chunk = wire::encode(&V::Array(vec![
                    V::Uint(48),
                    V::Uint(1),
                    b(&digest),
                    V::Uint(state.len() as u64),
                    V::Uint(index as u64),
                    b(&state[start..end]),
                ]))?;
                self.send(sender, &Message::StateResponse(id, chunk))?;
            }
            Message::StateResponse(id, bytes) => {
                let (digest, total, index, data) = checkpoint::chunk(&bytes)?;
                let transfer = self
                    .transfers
                    .get_mut(&sender)
                    .context("Unsolicited state chunk")?;
                ensure!(
                    id == transfer.id
                        && digest == transfer.digest
                        && matches!(transfer.pending,Message::StateRequest(i,d,n) if i==id && d==digest && n==index as u64)
                        && transfer.total.is_none_or(|t| t == total)
                        && transfer.state.len() == index * checkpoint::CHUNK,
                    "State response differs from exact pending request"
                );
                transfer.total = Some(total);
                transfer.state.extend(data);
                self.transfer_progress(sender)?;
            }
            Message::ArchiveRequest(id, digest, index, count) => {
                if !self.serve_checkpoint(sender, id, digest)? {
                    return Ok(());
                }
                let served = &self.served_checkpoints[&sender];
                let leaves = &self.engine.archive;
                ensure!(
                    leaves.root_at(served.height)? == served.root,
                    "Pinned checkpoint history changed"
                );
                let (index, count) = (usize::try_from(index)?, usize::try_from(count)?);
                ensure!(
                    (1..=512).contains(&count)
                        && index.checked_add(count).is_some_and(|n| n <= served.height),
                    "Archive request index or count differs"
                );
                self.send(
                    sender,
                    &Message::ArchiveResponse(
                        id,
                        digest,
                        index as u64,
                        leaves.range(index, count)?,
                    ),
                )?;
            }
            Message::ArchiveResponse(id, digest, index, leaves) => {
                let transfer = self
                    .transfers
                    .get_mut(&sender)
                    .context("Unsolicited archive chunk")?;
                ensure!(
                    id == transfer.id
                        && digest == transfer.digest
                        && index as usize == transfer.leaves.archive.len()
                        && matches!(transfer.pending,Message::ArchiveRequest(i,d,n,count) if i==id && d==digest && n==index && count==leaves.len() as u64)
                        && transfer.leaves.archive.len() + leaves.len() <= transfer.height,
                    "Archive response differs from exact pending range"
                );
                transfer.leaves.archive.append(
                    index,
                    transfer.leaves.archive.tree_root(),
                    &leaves,
                )?;
                self.transfer_progress(sender)?;
            }
            _ => anyhow::bail!("Unexpected checkpoint transport message"),
        }
        Ok(())
    }
    fn serve_checkpoint(&mut self, sender: Key, id: Digest, digest: Digest) -> Result<bool> {
        self.config().member(&sender)?;
        ensure!(
            sender != self.engine.signer(),
            "A local signer cannot allocate a peer snapshot"
        );
        self.engine.active()?;
        let now = Instant::now();
        self.expire_served(now);
        if let Some(served) = self.served_checkpoints.get(&sender)
            && served.id == id
        {
            ensure!(
                served.digest == digest && served.deadline > now,
                "Pinned transfer identity changed or expired"
            );
            return Ok(true);
        }
        let proof = self
            .engine
            .checkpoint_proof()
            .context("Certified checkpoint is unavailable")?;
        let checkpoint = checkpoint::verified(self.config(), proof)?;
        if *checkpoint.digest() != digest {
            self.send(
                sender,
                &Message::CheckpointSuperseded(id, digest, proof.to_vec()),
            )?;
            return Ok(false);
        }
        ensure!(
            self.served_checkpoints.contains_key(&sender) || self.served_checkpoints.len() < 3,
            "Served checkpoint capacity exhausted"
        );
        let state = self.engine.checkpoint_state(digest)?.to_vec();
        let height = self.engine.checkpoint_leaves(digest)?;
        ensure!(
            state.len() <= checkpoint::MAX_STATE
                && wire::digest(&state) == *checkpoint.state()
                && self.engine.archive.root_at(height)? == *checkpoint.head().root(),
            "Served checkpoint contents differ"
        );
        // The archive is append-only; retain its certified prefix identity rather
        // than a second archive copy. Repeats cannot extend the fixed lease.
        // Release this peer's old body before allocating its replacement.
        let height = checkpoint.height() as usize;
        let root = *checkpoint.head().root();
        let references = self.application.retained_inputs(&state)?;
        if let Some(old) = self.served_checkpoints.remove(&sender) {
            self.engine.unpin_checkpoint_inputs(&old.id);
        }
        self.engine.pin_checkpoint_inputs(id, &references)?;
        self.served_checkpoints.insert(
            sender,
            ServedCheckpoint {
                id,
                digest,
                height,
                root,
                state,
                deadline: now + TRANSFER_LIFETIME,
            },
        );
        Ok(true)
    }
    fn expire_served(&mut self, now: Instant) {
        for served in self.served_checkpoints.values_mut() {
            if served.deadline <= now {
                // Retain the current ID's finite lease marker so its retries
                // cannot revive an expired pin. A new transfer uses a fresh ID.
                self.engine.unpin_checkpoint_inputs(&served.id);
                served.state = Vec::new();
            }
        }
    }
    fn send_checkpoint_pending(&self, owner: Key, message: &Message) -> Result<()> {
        if matches!(message, Message::InputRequest(..)) {
            for peer in self.senders.keys() {
                self.send(*peer, message)?;
            }
            Ok(())
        } else {
            self.send(owner, message)
        }
    }
    pub(super) fn checkpoint_input_allowed(
        &mut self,
        sender: Key,
        id: Digest,
        digest: Digest,
        reference: &Reference,
    ) -> Result<bool> {
        if !self.serve_checkpoint(sender, id, digest)? {
            return Ok(false);
        }
        let refs = self
            .application
            .retained_inputs(&self.served_checkpoints[&sender].state)?;
        Ok(refs.binary_search(reference).is_ok())
    }
    pub(super) fn checkpoint_input_response(
        &mut self,
        _sender: Key,
        id: Digest,
        digest: Digest,
        reference: Reference,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        let owner = self
            .transfers
            .iter()
            .find(|(_, t)| t.id == id && t.digest == digest)
            .map(|(peer, _)| *peer)
            .context("unsolicited checkpoint input response")?;
        let t = &self.transfers[&owner];
        ensure!(
            t.deadline > Instant::now()
                && matches!(&t.pending,
            Message::InputRequest(i, InputAnchor::Checkpoint(d), r) if *i == id && *d == digest && r == &reference),
            "checkpoint input response differs from exact pending request"
        );
        let Some(body) = body else {
            return Ok(());
        };
        let refs = self.application.retained_inputs(&t.state)?;
        let object = Object::verify(reference, body)?;
        self.engine
            .import_checkpoint_input(id, &t.proof, &t.state, &refs, &object)?;
        self.transfer_progress(owner)
    }
    fn transfer_progress(&mut self, sender: Key) -> Result<()> {
        let mut t = self
            .transfers
            .remove(&sender)
            .context("Checkpoint transfer is missing")?;
        let outcome = (|| -> Result<bool> {
            ensure!(t.deadline > Instant::now(), "Checkpoint transfer expired");
            if t.total.is_none_or(|n| t.state.len() < n) {
                t.pending = Message::StateRequest(
                    t.id,
                    t.digest,
                    (t.state.len() / checkpoint::CHUNK) as u64,
                );
            } else {
                let c = checkpoint::verified(self.config(), &t.proof)?;
                ensure!(
                    wire::digest(&t.state) == *c.state(),
                    "Transferred state digest differs"
                );
                wire::decode_state(&t.state)?;
                self.application.validate_checkpoint(&t.state, c.height())?;
                let refs = self.application.retained_inputs(&t.state)?;
                self.engine.reserve_checkpoint_inputs(t.id, &refs)?;
                if t.leaves.archive.len() < t.height {
                    let count = (t.height - t.leaves.archive.len()).min(512);
                    t.pending = Message::ArchiveRequest(
                        t.id,
                        t.digest,
                        t.leaves.archive.len() as u64,
                        count as u64,
                    );
                } else {
                    match self.engine.input_reader()?.verify(&refs) {
                        Err(error) if error.downcast_ref::<Unavailable>().is_some() => {
                            let reference = error.downcast_ref::<Unavailable>().unwrap().0.clone();
                            t.pending = Message::InputRequest(
                                t.id,
                                InputAnchor::Checkpoint(t.digest),
                                reference,
                            );
                        }
                        Err(error) => return Err(error),
                        Ok(()) => {
                            let application = self.application.clone();
                            let expired = self.checkpoint_expired_before();
                            self.engine.install_checkpoint_with_inputs(
                                &t.proof,
                                &t.state,
                                &t.leaves.archive,
                                &refs,
                                |state, height| application.validate_checkpoint(state, height),
                                expired,
                            )?;
                            self.repairs.clear();
                            self.pending_votes.clear();
                            self.checkpoint_votes.clear();
                            self.input_flight = None;
                            self.input_waiting.clear();
                            self.apply()?;
                            self.checkpoint_emit()?;
                            return Ok(true);
                        }
                    }
                }
            }
            self.send_checkpoint_pending(sender, &t.pending)?;
            Ok(false)
        })();
        match outcome {
            Ok(false) => {
                self.transfers.insert(sender, t);
                Ok(())
            }
            other => {
                self.engine.unpin_checkpoint_inputs(&t.id);
                other.map(|_| ())
            }
        }
    }
}

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusDriverCheckpoint.rs");
