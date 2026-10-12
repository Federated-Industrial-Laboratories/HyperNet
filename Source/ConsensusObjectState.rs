// SPDX-License-Identifier: MIT
//! Storage admission reserves complete phase evidence before a proposal is signed.
use super::*;
use std::collections::BTreeSet;

impl Engine {
    pub(super) fn pending_objects(state: &Snapshot) -> impl Iterator<Item = &storage::Object> {
        state
            .nodes
            .values()
            .chain(state.commands.values())
            .chain(state.certificates.values())
            .chain(state.inputs.objects())
    }
    pub(super) fn object_budget(state: &Snapshot, ordinary: bool) -> Result<()> {
        let store = objects(state)?;
        let node_limit = if ordinary {
            storage::ORDINARY_NODES
        } else {
            MAX_NODES
        };
        let object_limit = if ordinary {
            storage::ORDINARY_OBJECTS
        } else {
            storage::MAX_OBJECTS
        };
        let byte_limit = if ordinary {
            storage::ORDINARY_BYTES
        } else {
            storage::MAX_BYTES
        };
        ensure!(
            state.nodes.len() <= node_limit,
            "Pending node capacity exhausted"
        );
        let (reserved_inputs, reserved_bytes) = state.inputs.reservation(store)?;
        let count = state.nodes.len()
            + state.commands.len()
            + state.certificates.len()
            + state.inputs.objects().count()
            + reserved_inputs;
        // Each retained node may acquire one certificate in each of three phases.
        // Reserve those future immutable objects now, not after signing its vote.
        let certificate_reserve = state
            .nodes
            .len()
            .checked_mul(3)
            .and_then(|n| n.checked_sub(state.certificates.len()))
            .context("Certificate reservation differs")?;
        ensure!(
            count
                .checked_add(certificate_reserve)
                .is_some_and(|n| n <= object_limit),
            "Pending object capacity exhausted"
        );
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
        ensure!(charged <= byte_limit, "Pending byte capacity exhausted");
        ensure!(
            serde_json::to_vec(state)?.len() <= journal::MAXIMUM,
            "Signer metadata capacity exhausted"
        );
        Ok(())
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
        if let Err(error) = Self::publish_objects(&next).and_then(|_| {
            self.archive.append(
                self.snapshot.archive_size,
                self.snapshot.archive_root,
                suffix,
            )
        }) {
            self.faulted = true;
            return Err(error);
        }
        self.persist(next)
    }
    pub(super) fn publish_objects(state: &Snapshot) -> Result<()> {
        Self::object_budget(state, false)?;
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
        Ok(())
    }
    pub(super) fn unstage_objects(state: &mut Snapshot) {
        state.inputs.unstage();
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
