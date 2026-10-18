// SPDX-License-Identifier: MIT
//! Storage admission reserves complete phase evidence before a proposal is signed.
use super::*;
use std::collections::BTreeSet;

impl Engine {
    fn state_objects(state: &Snapshot) -> impl Iterator<Item = &storage::Object> {
        let mut seen = BTreeSet::new();
        std::iter::once(&state.application)
            .chain(state.checkpoint.iter().map(|c| &c.state))
            .chain(state.candidates.values().map(|c| &c.state))
            .map(|state| &state.object)
            .filter(move |object| seen.insert(object.key()))
    }
    pub(super) fn resolve_states(state: &mut Snapshot) -> Result<()> {
        ensure!(
            state.candidates.len() <= 2,
            "State root count exceeds its bound"
        );
        let store = state
            .objects
            .clone()
            .context("State object store unavailable")?;
        let mut known = BTreeMap::new();
        for root in std::iter::once(&mut state.application)
            .chain(state.checkpoint.iter_mut().map(|c| &mut c.state))
            .chain(state.candidates.values_mut().map(|c| &mut c.state))
        {
            root.resolve(&store, &mut known)?;
        }
        Ok(())
    }
    pub(super) fn pending_objects(state: &Snapshot) -> impl Iterator<Item = &storage::Object> {
        state
            .nodes
            .values()
            .chain(state.commands.values())
            .chain(state.certificates.values())
            .chain(state.inputs.objects())
            .chain(Self::state_objects(state))
    }
    fn pending_allocation(state: &Snapshot) -> Result<(usize, u64)> {
        let store = objects(state)?;
        let (reserved_inputs, reserved_bytes) = state.inputs.reservation(store)?;
        let count = state.nodes.len()
            + state.commands.len()
            + state.certificates.len()
            + state.inputs.objects().count()
            + Self::state_objects(state).count()
            + reserved_inputs;
        // Each retained node may acquire one certificate in each of three phases.
        // Reserve those future immutable objects now, not after signing its vote.
        let certificate_reserve = state
            .nodes
            .len()
            .checked_mul(3)
            .and_then(|n| n.checked_sub(state.certificates.len()))
            .context("Certificate reservation differs")?;
        let count = count
            .checked_add(certificate_reserve)
            .context("Object count overflow")?;
        let mut charged = reserved_bytes;
        let mut keys = BTreeSet::new();
        for object in Self::pending_objects(state) {
            ensure!(
                keys.insert(object.key()),
                "Repeated immutable object identity"
            );
            charged = charged
                .checked_add(object.charged())
                .context("Object accounting overflow")?;
        }
        charged = charged
            .checked_add(
                store
                    .charge(storage::maximum(12)?)?
                    .checked_mul(certificate_reserve as u64)
                    .context("Certificate reservation overflow")?,
            )
            .context("Object accounting overflow")?;
        Ok((count, charged))
    }
    pub(super) fn state_reservation(state: &Snapshot) -> Result<bool> {
        let (count, charged) = Self::pending_allocation(state)?;
        let prospective = objects(state)?.charge(checkpoint::MAX_STATE)?;
        Ok(count
            .checked_add(1)
            .is_some_and(|n| n <= storage::MAX_OBJECTS)
            && charged
                .checked_add(prospective)
                .is_some_and(|n| n <= storage::MAX_BYTES))
    }
    pub(super) fn object_budget(state: &Snapshot, ordinary: bool) -> Result<Vec<u8>> {
        let (node_limit, object_limit, byte_limit) = if ordinary {
            (
                storage::ORDINARY_NODES,
                storage::ORDINARY_OBJECTS,
                storage::ORDINARY_BYTES,
            )
        } else {
            (MAX_NODES, storage::MAX_OBJECTS, storage::MAX_BYTES)
        };
        ensure!(
            state.nodes.len() <= node_limit,
            "Pending node capacity exhausted"
        );
        let (count, charged) = Self::pending_allocation(state)?;
        ensure!(count <= object_limit, "Pending object capacity exhausted");
        ensure!(charged <= byte_limit, "Pending byte capacity exhausted");
        let started = std::time::Instant::now();
        let encoded = serde_json::to_vec(state)?;
        timing::metadata_encoding(started.elapsed(), encoded.len());
        ensure!(
            encoded.len() <= journal::MAXIMUM,
            "Signer metadata capacity exhausted"
        );
        Ok(encoded)
    }
    pub(super) fn all_objects(state: &Snapshot) -> impl Iterator<Item = &storage::Object> {
        Self::pending_objects(state).chain(state.executed.values().map(|e| &e.object))
    }
    pub(super) fn result_reservation(state: &Snapshot) -> Result<bool> {
        let charged = state.executed.values().try_fold(0u64, |n, e| {
            n.checked_add(e.object.charged())
                .context("Result accounting overflow")
        })?;
        let prospective = objects(state)?.charge(peer::MAX_PAYLOAD)?;
        Ok(charged
            .checked_add(prospective)
            .is_some_and(|n| n <= 17 * 1024 * 1024))
    }
    // Objects precede archive visibility, which precedes the journal pointer.
    // Any uncertain write stops this instance; reopen verifies the committed
    // archive prefix and truncates only its uncommitted suffix.
    pub(super) fn publish_applied(&mut self, next: Snapshot, suffix: &[Digest]) -> Result<()> {
        let publication = Self::publish_objects(&next).and_then(|encoded| {
            self.archive.append(
                self.snapshot.archive_size,
                self.snapshot.archive_root,
                suffix,
            )?;
            Ok(encoded)
        });
        let encoded = match publication {
            Ok(encoded) => encoded,
            Err(error) => {
                self.faulted = true;
                return Err(error);
            }
        };
        self.persist_published(next, &encoded)
    }
    pub(super) fn publish_objects(state: &Snapshot) -> Result<Vec<u8>> {
        let encoded = Self::object_budget(state, false)?;
        let store = objects(state)?;
        ensure!(
            state.executed.len() <= storage::MAX_RESULTS,
            "Retained result count exhausted"
        );
        let result_bytes = state.executed.values().try_fold(0u64, |n, e| {
            n.checked_add(e.object.charged())
                .context("Result accounting overflow")
        })?;
        ensure!(
            result_bytes <= 17 * 1024 * 1024,
            "Retained result byte budget exhausted"
        );
        let mut created = false;
        for object in Self::all_objects(state) {
            created |= store.publish(object)?;
        }
        if created {
            store.sync()?;
        }
        Ok(encoded)
    }
    pub(super) fn unstage_objects(state: &mut Snapshot) {
        state.inputs.unstage();
        for root in std::iter::once(&mut state.application)
            .chain(state.checkpoint.iter_mut().map(|c| &mut c.state))
            .chain(state.candidates.values_mut().map(|c| &mut c.state))
        {
            root.object.unstaged();
        }
        for object in state
            .nodes
            .values_mut()
            .chain(state.commands.values_mut())
            .chain(state.certificates.values_mut())
        {
            object.unstaged();
        }
        for record in state.executed.values_mut() {
            record.object.unstaged();
        }
    }
    pub(super) fn collect_objects(&self) -> Result<()> {
        let retained = Self::all_objects(&self.snapshot)
            .map(storage::Object::key)
            .collect();
        objects(&self.snapshot)?.collect(&retained)
    }
    pub fn needs_inert_progress(&self) -> Result<bool> {
        let high = self.known_certificate(&self.snapshot.highest_prepare)?;
        Ok(self.known_node(&high.node)?.height > self.committed()?.height)
    }
    pub fn command(&self, digest: &Digest) -> Result<Vec<u8>> {
        let object = self
            .snapshot
            .commands
            .get(&id(digest))
            .context("Verified command dependency is missing")?;
        Ok(body(&self.snapshot, object)?.as_ref().clone())
    }
}
