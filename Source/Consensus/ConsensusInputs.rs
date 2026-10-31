// SPDX-License-Identifier: MIT
//! Journal-owned immutable inputs follow command, application and checkpoint reachability.
use super::{records::Digest, storage};
use crate::authority_objects::{self as inputs, Object, Reference, Resolved};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const STORAGE_KIND: u16 = 4097;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    reference: Reference,
    object: storage::Object,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    objects: BTreeMap<String, Stored>,
    commands: BTreeMap<String, Vec<Reference>>,
    application: Vec<Reference>,
    checkpoints: BTreeMap<String, Vec<Reference>>,
    // A process restart ends peer transfers. Reopen prunes their unrooted objects.
    #[serde(skip)]
    pins: BTreeMap<Digest, Vec<Reference>>,
}

#[derive(Clone)]
pub(crate) struct Reader {
    store: Arc<storage::Store>,
    objects: BTreeMap<String, Stored>,
}
impl Reader {
    pub fn verify(&self, references: &[Reference]) -> Result<()> {
        inputs::validate_references(references)?;
        for reference in references {
            self.resolve(std::slice::from_ref(reference))?;
        }
        Ok(())
    }
    pub fn resolve(&self, references: &[Reference]) -> Result<Resolved> {
        inputs::validate_references(references)?;
        let mut result = Vec::with_capacity(references.len());
        for reference in references {
            let Some(stored) = self.objects.get(&hex::encode(reference.identity())) else {
                return Err(inputs::Unavailable(reference.clone()).into());
            };
            ensure!(
                &stored.reference == reference,
                "immutable input identity collision"
            );
            result.push(Object::verify_shared(
                reference.clone(),
                self.store.read(&stored.object)?,
            )?);
        }
        Resolved::exact(references, result)
    }
}

impl State {
    pub fn reader(&self, store: Arc<storage::Store>) -> Reader {
        Reader {
            store,
            objects: self.objects.clone(),
        }
    }
    pub fn objects(&self) -> impl Iterator<Item = &storage::Object> {
        self.objects.values().map(|stored| &stored.object)
    }
    pub fn unstage(&mut self) {
        for stored in self.objects.values_mut() {
            stored.object.unstaged();
        }
    }
    pub fn insert(&mut self, store: &storage::Store, object: &Object) -> Result<()> {
        let reference = object.reference();
        let identity = reference.identity();
        let index = hex::encode(identity);
        if let Some(old) = self.objects.get(&index) {
            ensure!(
                &old.reference == reference,
                "immutable input identity collision"
            );
            reference.verify(&store.read(&old.object)?)?;
            return Ok(());
        }
        let stored = store.staged(STORAGE_KIND, identity, object.bytes())?;
        self.objects.insert(
            index,
            Stored {
                reference: reference.clone(),
                object: stored,
            },
        );
        Ok(())
    }
    pub fn bind_command(&mut self, digest: Digest, references: &[Reference]) -> Result<()> {
        inputs::validate_references(references)?;
        let index = hex::encode(digest);
        if let Some(old) = self.commands.get(&index) {
            ensure!(old == references, "durable command input references differ");
        } else {
            self.commands.insert(index, references.to_vec());
        }
        Ok(())
    }
    pub fn stage_command(
        &mut self,
        store: &storage::Store,
        digest: Digest,
        resolved: &Resolved,
    ) -> Result<()> {
        self.bind_command(digest, &resolved.references())?;
        for object in resolved.objects() {
            self.insert(store, object)?;
        }
        Ok(())
    }
    pub fn command(&self, digest: Digest) -> Result<&[Reference]> {
        self.commands
            .get(&hex::encode(digest))
            .map(Vec::as_slice)
            .context("durable command input declaration is absent")
    }
    pub fn application(&self) -> &[Reference] {
        &self.application
    }
    fn available(&self, references: &[Reference]) -> Result<()> {
        inputs::validate_references(references)?;
        for reference in references {
            let Some(stored) = self.objects.get(&hex::encode(reference.identity())) else {
                return Err(inputs::Unavailable(reference.clone()).into());
            };
            ensure!(
                &stored.reference == reference,
                "immutable input identity collision"
            );
        }
        Ok(())
    }
    pub fn set_application(&mut self, references: &[Reference]) -> Result<()> {
        self.available(references)?;
        self.application = references.to_vec();
        Ok(())
    }
    pub fn checkpoint(&mut self, digest: Digest, references: &[Reference]) -> Result<()> {
        self.available(references)?;
        let index = hex::encode(digest);
        if let Some(old) = self.checkpoints.get(&index) {
            ensure!(old == references, "checkpoint input declaration differs");
        } else {
            self.checkpoints.insert(index, references.to_vec());
        }
        Ok(())
    }
    pub fn pin(&mut self, transfer: Digest, references: &[Reference]) -> Result<()> {
        self.available(references)?;
        self.reserve_transfer(transfer, references)
    }
    pub fn reserve_transfer(&mut self, transfer: Digest, references: &[Reference]) -> Result<()> {
        inputs::validate_references(references)?;
        if let Some(old) = self.pins.get(&transfer) {
            ensure!(old == references, "checkpoint transfer input pin differs");
        } else {
            self.pins.insert(transfer, references.to_vec());
        }
        Ok(())
    }
    pub fn reservation(&self, store: &storage::Store) -> Result<(usize, u64)> {
        let mut reserved = BTreeSet::new();
        let mut bytes = 0u64;
        for reference in self.pins.values().flatten() {
            let identity = reference.identity();
            if !self.objects.contains_key(&hex::encode(identity)) && reserved.insert(identity) {
                bytes = bytes
                    .checked_add(store.charge(reference.len())?)
                    .context("input reservation overflow")?;
            }
        }
        Ok((reserved.len(), bytes))
    }
    pub fn unpin(&mut self, transfer: &Digest) {
        self.pins.remove(transfer);
    }

    /// Pruning happens in the same next snapshot as command and checkpoint retirement.
    pub fn retain(&mut self, commands: &BTreeSet<String>, checkpoints: &BTreeSet<String>) {
        self.commands.retain(|key, _| commands.contains(key));
        self.checkpoints.retain(|key, _| checkpoints.contains(key));
        let references: BTreeSet<_> = self
            .commands
            .values()
            .flatten()
            .chain(self.application.iter())
            .chain(self.checkpoints.values().flatten())
            .chain(self.pins.values().flatten())
            .map(|r| hex::encode(r.identity()))
            .collect();
        self.objects.retain(|key, _| references.contains(key));
    }

    /// Reopen verifies metadata and immutable bytes before any retained vote can be sent.
    pub fn validate(
        &self,
        store: &storage::Store,
        command_inputs: &BTreeMap<String, Vec<Reference>>,
        application_inputs: &[Reference],
        checkpoint_inputs: &BTreeMap<String, Vec<Reference>>,
    ) -> Result<()> {
        ensure!(
            &self.commands == command_inputs
                && self.application == application_inputs
                && &self.checkpoints == checkpoint_inputs,
            "journal input reachability differs from authenticated records"
        );
        self.validate_metadata(store)
    }
    pub fn validate_metadata(&self, store: &storage::Store) -> Result<()> {
        inputs::validate_references(&self.application)?;
        for references in self.commands.values().chain(self.checkpoints.values()) {
            inputs::validate_references(references)?;
        }
        self.available(&self.application)?;
        for references in self.checkpoints.values() {
            self.available(references)?;
        }
        for (identity, stored) in &self.objects {
            ensure!(
                identity == &hex::encode(stored.reference.identity())
                    && stored.object.kind == STORAGE_KIND
                    && stored.object.identity == stored.reference.identity()
                    && stored.object.len() == stored.reference.len(),
                "stored input descriptor differs"
            );
            stored.reference.verify(&store.read(&stored.object)?)?;
        }
        Ok(())
    }
}

impl super::Engine {
    pub(super) fn prune_input_orphans(&mut self) -> Result<()> {
        let mut next = self.snapshot.clone();
        let commands = next.commands.keys().cloned().collect();
        let checkpoints = next
            .candidates
            .values()
            .map(|c| hex::encode(super::wire::digest(&c.state)))
            .chain(
                next.checkpoint
                    .iter()
                    .map(|c| hex::encode(super::wire::digest(&c.state))),
            )
            .collect();
        next.inputs.retain(&commands, &checkpoints);
        if next.inputs.objects.len() != self.snapshot.inputs.objects.len() {
            self.persist(next)?;
        }
        Ok(())
    }
    pub(crate) fn input_reader(&self) -> Result<Reader> {
        Ok(self.snapshot.inputs.reader(
            self.snapshot
                .objects
                .clone()
                .context("object store unavailable")?,
        ))
    }
    pub(super) fn retained_command_inputs(&self, digest: Digest) -> Result<&[Reference]> {
        self.snapshot.inputs.command(digest)
    }
    pub(super) fn input_branch(
        &self,
        state: &super::Snapshot,
        tip: Digest,
    ) -> Result<Vec<Reference>> {
        let applied = super::node(&self.configuration, state, &state.applied)?;
        let mut cursor = tip;
        let mut seen = BTreeSet::new();
        let mut references = BTreeSet::new();
        loop {
            ensure!(
                seen.insert(cursor) && seen.len() <= super::MAX_NODES,
                "input branch exceeds retained ancestry"
            );
            let node = super::node(&self.configuration, state, &cursor)?;
            if node.height <= applied.height {
                break;
            }
            if let Some(command) = node.command {
                references.extend(state.inputs.command(command)?.iter().cloned());
            }
            cursor = node
                .parent
                .context("input branch lacks its applied ancestor")?;
        }
        Ok(references.into_iter().collect())
    }
    pub(super) fn require_input_branch(&self, state: &super::Snapshot, tip: Digest) -> Result<()> {
        let references = self.input_branch(state, tip)?;
        state
            .inputs
            .reader(state.objects.clone().context("object store unavailable")?)
            .verify(&references)?;
        Ok(())
    }
    pub(super) fn validate_input_bindings(
        &self,
        application: &dyn super::runtime::Application,
    ) -> Result<()> {
        let commands = self
            .snapshot
            .commands
            .iter()
            .map(|(digest, object)| {
                let bytes = super::body(&self.snapshot, object)?;
                Ok((digest.clone(), application.command_inputs(&bytes)?))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut checkpoints = BTreeMap::new();
        for state in self
            .snapshot
            .candidates
            .values()
            .map(|c| c.state.as_slice())
            .chain(self.snapshot.checkpoint.iter().map(|c| c.state.as_slice()))
        {
            checkpoints.insert(
                hex::encode(super::wire::digest(state)),
                application.retained_inputs(state)?,
            );
        }
        self.snapshot.inputs.validate(
            super::objects(&self.snapshot)?,
            &commands,
            &application.retained_inputs(&self.snapshot.application)?,
            &checkpoints,
        )
    }
    pub(super) fn certificate_input_references(
        &self,
        certificate: Digest,
    ) -> Result<Vec<Reference>> {
        let certificate = self.known_certificate(&certificate)?;
        let mut cursor = certificate.node;
        let mut seen = BTreeSet::new();
        let mut references = BTreeSet::new();
        loop {
            ensure!(
                seen.insert(cursor) && seen.len() <= super::MAX_NODES,
                "certified input ancestry exceeds retained history"
            );
            let node = self.known_node(&cursor)?;
            // A serving peer may already have applied this branch. Its applied
            // height cannot narrow another replica's certified input closure.
            if let Some(command) = node.command {
                if self.snapshot.commands.contains_key(&super::id(&command)) {
                    references.extend(self.snapshot.inputs.command(command)?.iter().cloned());
                } else {
                    ensure!(
                        node.height <= self.snapshot.checkpoint_floor,
                        "certified input command is missing above checkpoint"
                    );
                }
            }
            if node.height <= self.snapshot.checkpoint_floor {
                break;
            }
            cursor = node
                .parent
                .context("certified input ancestry lacks checkpoint or genesis")?;
        }
        Ok(references.into_iter().collect())
    }
    pub(super) fn application_input_certificate(&self) -> Option<Digest> {
        Self::cursor_certificate(&self.snapshot)
    }
    pub(super) fn import_certificate_input(
        &mut self,
        certificate: Digest,
        object: &Object,
    ) -> Result<()> {
        self.active()?;
        let references = self.certificate_input_references(certificate)?;
        ensure!(
            references.binary_search(object.reference()).is_ok(),
            "input lies outside verified certificate ancestry"
        );
        let mut next = self.snapshot.clone();
        next.inputs
            .insert(super::objects(&self.snapshot)?, object)?;
        self.persist(next)
    }
    pub(super) fn pin_checkpoint_inputs(
        &mut self,
        transfer: Digest,
        references: &[Reference],
    ) -> Result<()> {
        self.snapshot.inputs.pin(transfer, references)
    }
    pub(super) fn reserve_checkpoint_inputs(
        &mut self,
        transfer: Digest,
        references: &[Reference],
    ) -> Result<()> {
        let mut next = self.snapshot.clone();
        next.inputs.reserve_transfer(transfer, references)?;
        Self::object_budget(&next, false)?;
        self.snapshot.inputs.reserve_transfer(transfer, references)
    }
    pub(super) fn import_checkpoint_input(
        &mut self,
        transfer: Digest,
        proof: &[u8],
        state: &[u8],
        references: &[Reference],
        object: &Object,
    ) -> Result<()> {
        self.active()?;
        let checkpoint = super::checkpoint::verified(&self.configuration, proof)?;
        ensure!(
            super::wire::digest(state) == *checkpoint.state()
                && references.binary_search(object.reference()).is_ok(),
            "input differs from verified checkpoint closure"
        );
        let mut next = self.snapshot.clone();
        next.inputs.reserve_transfer(transfer, references)?;
        next.inputs
            .insert(super::objects(&self.snapshot)?, object)?;
        self.persist(next)
    }
    pub(super) fn unpin_checkpoint_inputs(&mut self, transfer: &Digest) {
        self.snapshot.inputs.unpin(transfer);
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Consensus/ConsensusInputsUnitTests.rs"]
mod tests;
