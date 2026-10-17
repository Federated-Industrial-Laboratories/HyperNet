// SPDX-License-Identifier: MIT
//! Fixed-committee Basic HotStuff with durable votes and separately certified execution.
#[path = "ConsensusApply.rs"]
mod application;
#[path = "ConsensusArchive.rs"]
pub mod archive;
#[path = "ConsensusCheckpoint.rs"]
pub mod checkpoint;
#[path = "ConsensusEpoch.rs"]
mod epoch;
#[path = "ConsensusInputs.rs"]
mod inputs;
#[path = "ConsensusJournal.rs"]
pub mod journal;
#[path = "ConsensusObjectState.rs"]
mod object_state;
#[path = "ConsensusPeer.rs"]
pub mod peer;
#[path = "ConsensusRead.rs"]
mod read;
#[path = "ConsensusWire.rs"]
pub mod records;
#[path = "ConsensusRepair.rs"]
pub mod repair;
#[path = "ConsensusRuntime.rs"]
pub mod runtime;
#[path = "ConsensusStorage.rs"]
pub mod storage;
#[path = "ConsensusSync.rs"]
pub mod synchronizer;
#[path = "ConsensusStorageTiming.rs"]
pub(crate) mod timing;

use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use journal::Journal;
use records::{
    Certificate, Command, Configuration, Digest, Key, NewView, Node, Phase, Scope, SignedVote,
    Vote, record,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

pub const MAX_NODES: usize = storage::MAX_NODES;
pub const MAX_CERTIFICATES: usize = MAX_NODES * 3;
pub const MAX_VOTES: usize = 4096;
pub const MAX_REPORTS: usize = 1024;
pub const MAX_INCIDENTS: usize = 16;
pub const MAX_RESULT_BYTES: usize = peer::MAX_PAYLOAD - 8192;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    #[serde(skip)]
    objects: Option<std::sync::Arc<storage::Store>>,
    version: u64,
    archive_size: u64,
    archive_root: Digest,
    checkpoint: Option<checkpoint::Certified>,
    candidates: BTreeMap<u64, checkpoint::Candidate>,
    prefix_nodes: BTreeMap<String, u64>,
    retired_view: u64,
    checkpoint_floor: u64,
    apply_cursor: Option<application::Cursor>,
    terminal: Option<epoch::Terminal>,
    prepared: Option<epoch::Prepared>,
    configuration: Vec<u8>,
    signer: Key,
    sync: synchronizer::State,
    wishes: [Option<Vec<u8>>; 4],
    nodes: BTreeMap<String, storage::Object>,
    commands: BTreeMap<String, storage::Object>,
    inputs: inputs::State,
    certificates: BTreeMap<String, storage::Object>,
    votes: BTreeMap<String, Vec<u8>>,
    own_votes: BTreeMap<String, Vec<u8>>,
    reports: BTreeMap<String, Vec<u8>>,
    proposals: BTreeMap<u64, Vec<u8>>,
    highest_prepare: Digest,
    locked: Digest,
    committed: Digest,
    commit_certificates: BTreeMap<String, Digest>,
    applied: Digest,
    application: storage::StateObject,
    executed: BTreeMap<String, application::StoredExecution>,
    incidents: Vec<[Vec<u8>; 2]>,
    quarantined: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub result: Vec<u8>,
    pub attestation: Vec<u8>,
}
pub struct Execution {
    pub state: Vec<u8>,
    pub output: ExecutionOutput,
}
pub enum ExecutionOutput {
    Inert,
    Result {
        result: Vec<u8>,
        attestation: Vec<u8>,
    },
}
#[derive(Clone, Debug)]
pub struct Committed {
    pub node: Digest,
    pub height: u64,

    pub evaluated_at: u64,
    pub command: Vec<u8>,
}
#[derive(Clone, Default)]
pub struct Outputs {
    pub wish: Option<Vec<u8>>,
    pub new_view: Option<Vec<u8>>,
}
enum Decision {
    Known,
    Advanced,
    Conflict,
}
pub struct Engine {
    configuration: Configuration,
    key: SigningKey,
    journal: Journal,
    archive: archive::Archive,
    snapshot: Snapshot,
    faulted: bool,
}
fn id(digest: &Digest) -> String {
    hex::encode(digest)
}
fn vote_id(view: u64, phase: Phase, signer: &Key) -> String {
    format!("{view:020}:{}:{}", phase.number(), hex::encode(signer))
}
fn report_id(view: u64, signer: &Key) -> String {
    format!("{view:020}:{}", hex::encode(signer))
}
fn objects(state: &Snapshot) -> Result<&storage::Store> {
    state
        .objects
        .as_deref()
        .context("Exclusive object store is unavailable")
}
fn body(state: &Snapshot, object: &storage::Object) -> Result<std::sync::Arc<Vec<u8>>> {
    objects(state)?.read(object)
}
fn node(config: &Configuration, state: &Snapshot, digest: &Digest) -> Result<Node> {
    let object = state
        .nodes
        .get(&id(digest))
        .context("Verified node dependency is missing")?;
    Node::parse(config, &body(state, object)?)
}
fn certificate(config: &Configuration, state: &Snapshot, digest: &Digest) -> Result<Certificate> {
    let object = state
        .certificates
        .get(&id(digest))
        .context("Verified certificate dependency is missing")?;
    Certificate::parse(config, &body(state, object)?)
}
fn extends(
    config: &Configuration,
    state: &Snapshot,
    mut child: Digest,
    ancestor: Digest,
) -> Result<bool> {
    let ancestor_height = node(config, state, &ancestor)?.height;
    for _ in 0..=MAX_NODES {
        if child == ancestor {
            return Ok(true);
        }
        let current = node(config, state, &child)?;
        if current.height <= ancestor_height {
            return Ok(false);
        }
        if state.prefix_nodes.contains_key(&id(&child)) {
            // Every retained canonical prefix header is authenticated by the
            // committed archive. A different retained branch is not its ancestor.
            return Ok(state.prefix_nodes.contains_key(&id(&ancestor)));
        }
        let Some(parent) = current.parent else {
            return Ok(false);
        };
        child = parent;
    }
    anyhow::bail!("Node ancestry exceeds its bound")
}
fn insert_command(config: &Configuration, state: &mut Snapshot, command: &[u8]) -> Result<Digest> {
    Command::parse(config, command)?;
    let digest = wire::digest(command);
    ensure!(
        state.commands.contains_key(&id(&digest)) || state.commands.len() < MAX_NODES,
        "Command history capacity exhausted"
    );
    let object = objects(state)?.staged(22, digest, command)?;
    state.commands.entry(id(&digest)).or_insert(object);
    Ok(digest)
}
fn check_certificate(
    config: &Configuration,
    state: &Snapshot,
    input: &[u8],
) -> Result<Certificate> {
    let qc = Certificate::parse(config, input)?;
    let target = node(config, state, &qc.node)?;
    ensure!(
        qc.view == target.view,
        "Certificate view differs from its node"
    );
    ensure!(
        state.certificates.contains_key(&id(&qc.digest()))
            || state.certificates.len() < MAX_CERTIFICATES,
        "Certificate history capacity exhausted"
    );
    if !state.certificates.contains_key(&id(&qc.digest())) {
        ensure!(
            !input.is_empty() && input.len() <= storage::maximum(12)?,
            "Object exceeds its kind bound"
        );
        objects(state)?.charge(input.len())?;
    }
    Ok(qc)
}
fn stage_certificate(state: &mut Snapshot, qc: &Certificate, input: &[u8]) -> Result<()> {
    if !state.certificates.contains_key(&id(&qc.digest())) {
        let object = objects(state)?.staged(12, qc.digest(), input)?;
        state.certificates.insert(id(&qc.digest()), object);
    }
    Ok(())
}
fn insert_certificate(
    config: &Configuration,
    state: &mut Snapshot,
    input: &[u8],
) -> Result<Certificate> {
    let qc = check_certificate(config, state, input)?;
    stage_certificate(state, &qc, input)?;
    Ok(qc)
}
fn check_node(config: &Configuration, state: &Snapshot, input: &[u8]) -> Result<Node> {
    let incoming = Node::parse(config, input)?;
    if state.prefix_nodes.contains_key(&id(&incoming.digest()?)) {
        let old = state
            .nodes
            .get(&id(&incoming.digest()?))
            .context("Archived prefix node missing")?;
        ensure!(
            body(state, old)?.as_slice() == input,
            "Archived prefix node differs"
        );
        return Ok(incoming);
    }
    ensure!(
        state.nodes.contains_key(&id(&incoming.digest()?))
            || state
                .prefix_nodes
                .values()
                .max()
                .is_none_or(|height| incoming.height > *height),
        "Retired prefix nodes require certified checkpoint transfer"
    );
    if incoming.height > 0 {
        let parent_digest = incoming.parent.context("Parent missing")?;
        let parent = node(config, state, &parent_digest)?;
        let qc = certificate(
            config,
            state,
            &incoming.justify.context("Justification missing")?,
        )?;
        ensure!(
            qc.phase == Phase::Prepare && qc.node == parent_digest && qc.view < incoming.view,
            "Proposal does not directly extend its preceding Prepare certificate"
        );
        ensure!(
            incoming.height == parent.height.checked_add(1).context("Height overflow")?
                && incoming.view > parent.view
                && incoming.evaluated_at >= parent.evaluated_at,
            "Proposal ancestry or time is not increasing"
        );
        let command = state
            .commands
            .get(&id(&incoming.command.context("Command missing")?))
            .context("Proposal command is missing")?;
        ensure!(
            Command::parse(config, &body(state, command)?)?.minimum_height() <= incoming.height,
            "Proposal precedes the request's causal floor"
        );
    }
    Ok(incoming)
}
fn insert_node(config: &Configuration, state: &mut Snapshot, input: &[u8]) -> Result<Node> {
    let incoming = check_node(config, state, input)?;
    let digest = incoming.digest()?;
    ensure!(
        state.nodes.contains_key(&id(&digest)) || state.nodes.len() < MAX_NODES - 1,
        "Node history capacity exhausted; one slot is reserved for a certified anchor"
    );
    let object = objects(state)?.staged(14, digest, input)?;
    state.nodes.entry(id(&digest)).or_insert(object);
    Ok(incoming)
}
impl Engine {
    pub fn create(
        directory: &Path,
        configuration: Configuration,
        key: SigningKey,
        initial_state: Vec<u8>,
    ) -> Result<Self> {
        ensure!(
            configuration.scope.epoch == 0,
            "Successor journal requires typed epoch preparation"
        );
        Self::create_prepared(directory, configuration, key, initial_state, None)
    }
    fn create_prepared(
        directory: &Path,
        configuration: Configuration,
        key: SigningKey,
        initial_state: Vec<u8>,
        prepared: Option<epoch::Prepared>,
    ) -> Result<Self> {
        Self::create_prepared_inputs(
            directory,
            configuration,
            key,
            initial_state,
            prepared,
            &[],
            |_| anyhow::bail!("undeclared initial input"),
        )
    }
    fn create_prepared_inputs(
        directory: &Path,
        configuration: Configuration,
        key: SigningKey,
        initial_state: Vec<u8>,
        prepared: Option<epoch::Prepared>,
        references: &[crate::authority_objects::Reference],
        mut load: impl FnMut(&crate::authority_objects::Reference) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        crate::authority_objects::validate_references(references)?;
        configuration.member(&key.verifying_key().to_bytes())?;
        wire::decode_state(&initial_state)?;
        ensure!(
            wire::digest(&initial_state) == configuration.genesis_governance,
            "Initial state differs from the descriptor-pinned governance bundle"
        );
        let genesis = configuration.genesis();
        let genesis_digest = genesis.digest()?;
        let qc = configuration.genesis_qc()?;
        let mut journal = Journal::initialise(directory)?;
        let store = storage::Store::open(directory, true)?;
        let mut snapshot = Snapshot {
            objects: Some(store.clone()),
            version: 3,
            archive_size: 0,
            archive_root: archive::empty_root(),
            checkpoint: None,
            candidates: BTreeMap::new(),
            prefix_nodes: BTreeMap::new(),
            retired_view: 0,
            checkpoint_floor: 0,
            apply_cursor: None,
            terminal: None,
            prepared,
            configuration: configuration.bytes.clone(),
            signer: key.verifying_key().to_bytes(),
            sync: synchronizer::State::default(),
            wishes: [None, None, None, None],
            nodes: BTreeMap::from([(
                id(&genesis_digest),
                store.staged(14, genesis_digest, &genesis.encode()?)?,
            )]),
            commands: BTreeMap::new(),
            inputs: inputs::State::default(),
            certificates: BTreeMap::from([(
                id(&qc.digest()),
                store.staged(12, qc.digest(), &qc.bytes)?,
            )]),
            votes: BTreeMap::new(),
            own_votes: BTreeMap::new(),
            reports: BTreeMap::new(),
            proposals: BTreeMap::new(),
            highest_prepare: qc.digest(),
            locked: qc.digest(),
            committed: genesis_digest,
            commit_certificates: BTreeMap::new(),
            applied: genesis_digest,
            application: storage::StateObject::staged(&store, initial_state)?,
            executed: BTreeMap::new(),
            incidents: Vec::new(),
            quarantined: false,
        };
        // Bound the complete closure before reading bodies. Publish one immutable
        // input at a time, then publish the journal and its readiness signature.
        snapshot.inputs.reserve_transfer([0; 32], references)?;
        Self::object_budget(&snapshot, false)?;
        for reference in references {
            let object =
                crate::authority_objects::Object::verify(reference.clone(), load(reference)?)?;
            snapshot.inputs.insert(&store, &object)?;
            let stored = snapshot
                .inputs
                .objects()
                .find(|stored| stored.identity == reference.identity())
                .context("staged initial input missing")?;
            store.publish(stored)?;
            snapshot.inputs.unstage();
        }
        store.sync()?;
        snapshot.inputs.set_application(references)?;
        snapshot.inputs.unpin(&[0; 32]);
        let encoded = Self::publish_objects(&snapshot)?;
        journal.commit_encoded(&encoded)?;
        Self::unstage_objects(&mut snapshot);
        let archive = archive::Archive::open(
            directory,
            configuration.scope.configuration,
            snapshot.archive_size,
            snapshot.archive_root,
        )?;
        Ok(Self {
            configuration,
            key,
            journal,
            archive,
            snapshot,
            faulted: false,
        })
    }
    pub fn open(
        directory: &Path,
        configuration: Configuration,
        key: SigningKey,
        minimum_generation: u64,
    ) -> Result<Self> {
        let (journal, mut snapshot): (_, Snapshot) = Journal::open(directory, minimum_generation)?;
        ensure!(snapshot.version == 3, "Unsupported signer snapshot format");
        snapshot.objects = Some(storage::Store::open(directory, false)?);
        Self::resolve_states(&mut snapshot)?;
        let archive = archive::Archive::open(
            directory,
            configuration.scope.configuration,
            snapshot.archive_size,
            snapshot.archive_root,
        )?;
        let mut engine = Self {
            configuration,
            key,
            journal,
            archive,
            snapshot,
            faulted: false,
        };
        engine.validate_snapshot()?;
        engine.prune_input_orphans()?;
        engine.collect_objects()?;
        Ok(engine)
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    // Protocol entry can lag the synchronizer's order-statistic view.
    #[allow(clippy::misnamed_getters)]
    pub fn view(&self) -> u64 {
        self.snapshot.sync.entered
    }
    pub fn generation(&self) -> u64 {
        self.journal.generation()
    }
    pub fn application(&self) -> &[u8] {
        &self.snapshot.application
    }
    pub fn signer(&self) -> Key {
        self.snapshot.signer
    }
    /// Transport signatures have a separate, finite schema from consensus votes.
    pub fn sign_peer(&self, message: &peer::Message) -> Result<Vec<u8>> {
        self.active()?;
        let payload = peer::payload(&self.configuration, self.signer(), message)?;
        wire::sign_envelope(&payload, &self.key)
    }
    pub fn known_node(&self, digest: &Digest) -> Result<Node> {
        node(&self.configuration, &self.snapshot, digest)
    }
    pub fn known_certificate(&self, digest: &Digest) -> Result<Certificate> {
        certificate(&self.configuration, &self.snapshot, digest)
    }
    pub fn ancestry(
        &self,
        floor_height: u64,
        floor: Digest,
        target: Digest,
    ) -> Result<Vec<Vec<u8>>> {
        self.active()?;
        ensure!(
            self.known_node(&floor)?.height == floor_height,
            "Ancestry floor height differs"
        );
        let mut cursor = target;
        let mut nodes = Vec::new();
        while cursor != floor {
            ensure!(nodes.len() < 128, "Ancestry response exceeds its bound");
            let current = self.known_node(&cursor)?;
            ensure!(
                current.height > floor_height,
                "Target does not extend the requested floor"
            );
            nodes.push(current.encode()?);
            cursor = current.parent.context("Ancestry floor is absent")?;
        }
        nodes.reverse();
        Ok(nodes)
    }
    pub fn current_proposal(&self) -> Option<&[u8]> {
        self.snapshot.proposals.get(&self.view()).map(Vec::as_slice)
    }
    fn has_new_view_quorum(&self) -> bool {
        // Insertion and journal restoration authenticate these exact keys.
        // This only avoids premature application work; propose_with_inputs
        // still verifies every selected report, QC and proposal dependency.
        self.configuration
            .voters
            .iter()
            .filter(|signer| {
                self.snapshot
                    .reports
                    .contains_key(&report_id(self.view(), signer))
            })
            .count()
            >= 3
    }
    pub fn retransmission_records(&self) -> Result<Vec<peer::Message>> {
        self.active()?;
        let mut records = Vec::new();
        for vote in self.snapshot.own_votes.values() {
            if SignedVote::parse(&self.configuration, vote)?.vote.view
                >= self.view().saturating_sub(1)
            {
                records.push(peer::Message::Vote(vote.clone()));
            }
        }
        if let Some(report) = self
            .snapshot
            .reports
            .get(&report_id(self.view(), &self.signer()))
        {
            let parsed = NewView::parse(&self.configuration, report)?;
            records.push(peer::Message::NewView(
                report.clone(),
                self.known_certificate(&parsed.prepare)?.bytes,
            ));
        }
        for object in self.snapshot.certificates.values() {
            let qc = body(&self.snapshot, object)?;
            let certificate = Certificate::parse(&self.configuration, &qc)?;
            if certificate.view > 0
                && (certificate.view >= self.view().saturating_sub(1)
                    || self
                        .snapshot
                        .commit_certificates
                        .get(&id(&self.snapshot.committed))
                        == Some(&certificate.digest()))
            {
                records.push(peer::Message::Certificate(qc.as_ref().clone()));
            }
        }
        Ok(records)
    }
    pub fn executed_request(&self, command: Digest) -> Result<Option<(Node, ExecutionRecord)>> {
        // One ordered request can be committed at multiple positions. Prefer
        // the newest retained execution, independent of node digest ordering.
        let Some((digest, _)) = self
            .snapshot
            .executed
            .iter()
            .filter(|(_, record)| record.command == command)
            .max_by_key(|(digest, record)| (record.height, *digest))
        else {
            return Ok(None);
        };
        let digest: Digest = hex::decode(digest)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid node key"))?;
        let node = self.known_node(&digest)?;
        let record = self
            .execution(digest)?
            .context("Indexed execution is unavailable")?;
        ensure!(
            node.command == Some(command),
            "Execution command index differs"
        );
        Ok(Some((node, record)))
    }
    fn unapplied_commands(&self) -> Result<std::collections::BTreeSet<Digest>> {
        self.active()?;
        let mut commands = std::collections::BTreeSet::new();
        let mut cursor = self.snapshot.committed;
        if cursor == self.snapshot.applied {
            return Ok(commands);
        }
        let floor = self.applied()?.height;
        let mut height = self.committed()?.height;
        // Only the decided branch suppresses submissions. Prepared or proposed
        // nodes can still be abandoned and must not consume a request.
        for _ in 0..MAX_NODES {
            if cursor == self.snapshot.applied {
                ensure!(
                    height == floor,
                    "Committed application floor height differs"
                );
                return Ok(commands);
            }
            let current = self.known_node(&cursor)?;
            ensure!(
                current.height == height && height > floor,
                "Committed branch does not extend the application floor"
            );
            commands.insert(current.command.context("Committed command missing")?);
            cursor = current.parent.context("Committed parent missing")?;
            height -= 1;
        }
        anyhow::bail!("Committed application suffix exceeds retained storage")
    }
    pub fn committed(&self) -> Result<Node> {
        node(
            &self.configuration,
            &self.snapshot,
            &self.snapshot.committed,
        )
    }
    pub fn applied(&self) -> Result<Node> {
        node(&self.configuration, &self.snapshot, &self.snapshot.applied)
    }
    pub fn committed_certificate(&self) -> Result<Option<Vec<u8>>> {
        self.active()?;
        if let Some(digest) = self
            .snapshot
            .commit_certificates
            .get(&id(&self.snapshot.committed))
        {
            return Ok(Some(self.known_certificate(digest)?.bytes));
        }
        Ok(None)
    }
    fn active(&self) -> Result<()> {
        ensure!(
            !self.faulted,
            "Object publication failed; reopen the exclusive journal"
        );
        self.journal.healthy()?;
        self.archive.healthy()?;
        ensure!(
            self.archive.leaves().len() as u64 == self.snapshot.archive_size
                && self.archive.tree_root() == self.snapshot.archive_root,
            "History publication was interrupted; reopen the exclusive signer journal"
        );
        ensure!(!self.snapshot.quarantined, "Replica is quarantined");
        Ok(())
    }
    fn persist(&mut self, next: Snapshot) -> Result<()> {
        let encoded = match Self::publish_objects(&next) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.faulted = true;
                return Err(error);
            }
        };
        self.persist_published(next, &encoded)
    }
    // The encoding belongs to this unchanged snapshot. Its immutable objects
    // have reached durable storage before the journal can name them.
    fn persist_published(&mut self, mut next: Snapshot, encoded: &[u8]) -> Result<()> {
        let retained: std::collections::BTreeSet<_> =
            Self::all_objects(&next).map(storage::Object::key).collect();
        let collect = Self::all_objects(&self.snapshot).any(|o| !retained.contains(&o.key()));
        if let Err(error) = self.journal.commit_encoded(encoded) {
            self.faulted = true;
            return Err(error);
        }
        Self::unstage_objects(&mut next);
        self.snapshot = next;
        if collect && let Err(error) = self.collect_objects() {
            self.faulted = true;
            return Err(error);
        }
        Ok(())
    }
    fn stage_sync_effects(
        &self,
        next: &mut Snapshot,
        effects: synchronizer::Effects,
    ) -> Result<Outputs> {
        if effects.entered.is_some() {
            // The new view, retired signature floor and retained dependencies
            // reach durable storage together before any NewView is emitted.
            self.compact_snapshot(next, None, self.archive.leaves(), true)?;
        }
        let prepared = certificate(&self.configuration, next, &next.highest_prepare)?;
        let new_view = if let Some(view) = effects.entered.filter(|view| *view > prepared.view) {
            let report = NewView::sign(&self.configuration, view, next.highest_prepare, &self.key)?;
            ensure!(
                next.reports.len() < MAX_REPORTS,
                "New-view history capacity exhausted"
            );
            next.reports
                .insert(report_id(view, &next.signer), report.envelope.clone());
            Some(report.envelope)
        } else {
            None
        };
        let wish = effects
            .wish
            .map(|target| synchronizer::sign(&self.configuration, target, &self.key))
            .transpose()?;
        Ok(Outputs { wish, new_view })
    }
    pub fn advance_view(&mut self) -> Result<Outputs> {
        self.voting()?;
        let mut next = self.snapshot.clone();
        let mut effects = next.sync.advance()?;
        let target = effects.wish.context("Advance omitted its WISH target")?;
        let member = self.configuration.member(&next.signer)?;
        if target > next.sync.maxima[member] {
            // Own evidence and its synchronizer transition are durable before
            // broadcast; ordinary loopback delivery is then an exact duplicate.
            next.wishes[member] = Some(synchronizer::sign(&self.configuration, target, &self.key)?);
            effects.entered = next.sync.receive(member, target)?.entered;
        }
        let output = self.stage_sync_effects(&mut next, effects)?;
        self.persist(next)?;
        Ok(output)
    }
    pub fn retransmit_wish(&mut self) -> Result<Outputs> {
        self.voting()?;
        let effects = self.snapshot.sync.periodic()?;
        Ok(Outputs {
            wish: effects
                .wish
                .map(|target| synchronizer::sign(&self.configuration, target, &self.key))
                .transpose()?,
            new_view: None,
        })
    }
    pub fn receive_wish(&mut self, envelope: &[u8]) -> Result<Outputs> {
        self.voting()?;
        let (signer, target) = synchronizer::verify(&self.configuration, envelope)?;
        let member = self.configuration.member(&signer)?;
        if target <= self.snapshot.sync.maxima[member] {
            return Ok(Outputs::default());
        }
        let mut next = self.snapshot.clone();
        let output = self.stage_wish(&mut next, member, target, envelope)?;
        self.persist(next)?;
        Ok(output)
    }
    fn stage_wish(
        &self,
        next: &mut Snapshot,
        member: usize,
        target: u64,
        envelope: &[u8],
    ) -> Result<Outputs> {
        next.wishes[member] = Some(envelope.to_vec());
        let effects = next.sync.receive(member, target)?;
        self.stage_sync_effects(next, effects)
    }
    // Staged effects cannot escape until the entire accepted prefix is durable.
    // A rejected candidate leaves both the prefix and its outputs unchanged.
    fn receive_wishes(&mut self, inputs: &[Vec<u8>]) -> Result<Vec<Outputs>> {
        self.voting()?;
        ensure!(
            !inputs.is_empty() && inputs.len() <= runtime::MAX_EVENTS,
            "Queued WISH evidence exceeds ingress bound"
        );
        let (_, target) = synchronizer::verify(&self.configuration, &inputs[0])?;
        let mut next = self.snapshot.clone();
        let mut outputs = Vec::new();
        let mut changed = false;
        for input in inputs {
            let Ok((signer, received)) = synchronizer::verify(&self.configuration, input) else {
                break;
            };
            if received != target {
                break;
            }
            let member = self.configuration.member(&signer)?;
            if target <= next.sync.maxima[member] {
                outputs.push(Outputs::default());
                continue;
            }
            let mut candidate = next.clone();
            let Ok(output) = self.stage_wish(&mut candidate, member, target, input) else {
                break;
            };
            next = candidate;
            changed = true;
            outputs.push(output);
        }
        if changed {
            self.persist(next)?;
        }
        Ok(outputs)
    }
    fn checked_new_view(&self, state: &Snapshot, envelope: &[u8]) -> Result<NewView> {
        let report = NewView::parse(&self.configuration, envelope)?;
        ensure!(
            report.view == state.sync.entered,
            "New-view report is outside the entered view"
        );
        let qc = certificate(&self.configuration, state, &report.prepare)?;
        ensure!(
            qc.phase == Phase::Prepare && qc.view < report.view,
            "New-view report has invalid Prepare evidence"
        );
        Ok(report)
    }
    fn stage_new_view(next: &mut Snapshot, report: &NewView) -> Result<bool> {
        let entry = report_id(report.view, &report.signer);
        if let Some(old) = next.reports.get(&entry) {
            ensure!(
                old == &report.envelope,
                "Conflicting authenticated consensus evidence"
            );
            return Ok(false);
        }
        ensure!(
            next.reports.len() < MAX_REPORTS,
            "New-view history capacity exhausted"
        );
        next.reports.insert(entry, report.envelope.clone());
        Ok(true)
    }
    pub fn receive_new_view(&mut self, envelope: &[u8]) -> Result<()> {
        self.voting()?;
        let report = self.checked_new_view(&self.snapshot, envelope)?;
        if let Some(old) = self
            .snapshot
            .reports
            .get(&report_id(report.view, &report.signer))
        {
            if old == envelope {
                return Ok(());
            }
            return self.incident(old.clone(), envelope.to_vec(), false);
        }
        let mut next = self.snapshot.clone();
        Self::stage_new_view(&mut next, &report)?;
        self.persist(next)
    }
    fn receive_new_views(&mut self, inputs: &[Vec<u8>]) -> Result<usize> {
        self.voting()?;
        ensure!(
            !inputs.is_empty() && inputs.len() <= runtime::MAX_EVENTS,
            "Queued NewView evidence exceeds ingress bound"
        );
        let mut next = self.snapshot.clone();
        let mut accepted = 0;
        let mut changed = false;
        for input in inputs {
            let Ok(report) = self.checked_new_view(&next, input) else {
                break;
            };
            let Ok(added) = Self::stage_new_view(&mut next, &report) else {
                break;
            };
            changed |= added;
            accepted += 1;
        }
        if changed {
            self.persist(next)?;
        }
        Ok(accepted)
    }
    fn incident<T>(&mut self, first: Vec<u8>, second: Vec<u8>, quarantine: bool) -> Result<T> {
        let mut next = self.snapshot.clone();
        if next.incidents.len() < MAX_INCIDENTS {
            next.incidents.push([first, second]);
        }
        next.quarantined |= quarantine;
        self.persist(next)?;
        anyhow::bail!("Conflicting authenticated consensus evidence")
    }
    pub fn propose(&mut self, command: &[u8], evaluated_at: u64) -> Result<Vec<u8>> {
        self.propose_with_inputs(
            command,
            evaluated_at,
            &crate::authority_objects::Resolved::default(),
        )
    }
    pub fn propose_with_inputs(
        &mut self,
        command: &[u8],
        evaluated_at: u64,
        inputs: &crate::authority_objects::Resolved,
    ) -> Result<Vec<u8>> {
        self.voting()?;
        ensure!(
            self.configuration.leader(self.view())? == self.snapshot.signer,
            "Only this view's designated leader may propose"
        );
        if let Some(previous) = self.snapshot.proposals.get(&self.view()) {
            let (payload, _) = wire::envelope(previous, 1)?;
            let old = Node::parse(&self.configuration, &payload)?;
            ensure!(
                old.command == Some(wire::digest(command)) && old.evaluated_at == evaluated_at,
                "A different leader proposal is already durable"
            );
            ensure!(
                self.snapshot.inputs.command(wire::digest(command))? == inputs.references(),
                "repeated proposal immutable input closure differs"
            );
            self.require_input_branch(&self.snapshot, old.digest()?)?;
            return Ok(previous.clone());
        }
        let mut reports = Vec::new();
        for signer in &self.configuration.voters {
            let Some(bytes) = self.snapshot.reports.get(&report_id(self.view(), signer)) else {
                continue;
            };
            let report = NewView::parse(&self.configuration, bytes)?;
            ensure!(
                report.signer == *signer && report.view == self.view(),
                "Indexed new-view report differs from its signer or view"
            );
            let qc = certificate(&self.configuration, &self.snapshot, &report.prepare)?;
            ensure!(
                qc.phase == Phase::Prepare && qc.view < report.view,
                "New-view report has invalid Prepare evidence"
            );
            reports.push(qc);
        }
        ensure!(reports.len() >= 3, "New-view quorum is missing");
        reports.sort_by_key(|qc| qc.view);
        let best = reports.last().context("New-view quorum missing")?;
        ensure!(
            reports
                .iter()
                .all(|qc| qc.view != best.view || qc.node == best.node),
            "New-view reports contain conflicting Prepare certificates"
        );
        let parent = node(&self.configuration, &self.snapshot, &best.node)?;
        ensure!(
            evaluated_at >= parent.evaluated_at && evaluated_at >= self.committed()?.evaluated_at,
            "Proposal evaluation time moved backwards"
        );
        let mut next = self.snapshot.clone();
        let command = insert_command(&self.configuration, &mut next, command)?;
        next.inputs
            .stage_command(objects(&self.snapshot)?, command, inputs)?;
        let proposal = Node {
            scope: self.configuration.scope.clone(),
            view: self.view(),
            height: parent.height.checked_add(1).context("Height overflow")?,
            parent: Some(best.node),
            command: Some(command),
            evaluated_at,
            justify: Some(best.digest()),
        };
        self.checkpoint_admission(proposal.height)?;
        insert_node(&self.configuration, &mut next, &proposal.encode()?)?;
        self.require_input_branch(&next, proposal.digest()?)?;
        epoch::branch(&self.configuration, &next, proposal.digest()?)?;
        let inert = matches!(
            Command::parse(
                &self.configuration,
                &body(&next, &next.commands[&id(&command)])?
            )?,
            Command::Inert | Command::Noop(_)
        );
        Self::object_budget(&next, !inert)?;
        let signed = wire::sign_envelope(&proposal.encode()?, &self.key)?;
        next.proposals.insert(self.view(), signed.clone());
        self.persist(next)?;
        Ok(signed)
    }
    #[cfg(test)]
    pub fn prepare(
        &mut self,
        proposal: &[u8],
        command: &[u8],
        admit_time: impl FnOnce(u64) -> Result<()>,
        validate_intent: impl FnOnce(&[u8], u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.prepare_with_inputs(
            proposal,
            command,
            &crate::authority_objects::Resolved::default(),
            admit_time,
            validate_intent,
        )
    }
    pub fn prepare_with_inputs(
        &mut self,
        proposal: &[u8],
        command: &[u8],
        inputs: &crate::authority_objects::Resolved,
        admit_time: impl FnOnce(u64) -> Result<()>,
        validate_intent: impl FnOnce(&[u8], u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.voting()?;
        let (payload, signatures) = wire::envelope(proposal, 1)?;
        let incoming = Node::parse(&self.configuration, &payload)?;
        ensure!(
            incoming.view == self.view()
                && signatures[0].0 == self.configuration.leader(self.view())?,
            "Proposal view or leader differs"
        );
        self.checkpoint_admission(incoming.height)?;
        let digest = incoming.digest()?;
        let own_id = vote_id(self.view(), Phase::Prepare, &self.snapshot.signer);
        if let Some(old) = self.snapshot.own_votes.get(&own_id) {
            ensure!(
                SignedVote::parse(&self.configuration, old)?.vote.node == digest,
                "A different Prepare statement is already durable"
            );
            self.require_input_branch(&self.snapshot, digest)?;
            return Ok(old.clone());
        }
        let mut next = self.snapshot.clone();
        ensure!(
            Some(insert_command(&self.configuration, &mut next, command)?) == incoming.command,
            "Proposal command digest differs"
        );
        insert_node(&self.configuration, &mut next, &payload)?;
        next.inputs.stage_command(
            objects(&self.snapshot)?,
            incoming.command.context("proposal command absent")?,
            inputs,
        )?;
        Self::object_budget(
            &next,
            !matches!(
                Command::parse(&self.configuration, command)?,
                Command::Inert | Command::Noop(_)
            ),
        )?;
        let justify = certificate(
            &self.configuration,
            &next,
            &incoming.justify.context("Justification missing")?,
        )?;
        let locked = certificate(&self.configuration, &next, &next.locked)?;
        ensure!(
            incoming.view > self.committed()?.view
                && extends(&self.configuration, &next, digest, next.committed)?,
            "Proposal does not extend the known committed prefix"
        );
        ensure!(
            extends(&self.configuration, &next, digest, locked.node)? || justify.view > locked.view,
            "Proposal violates the locked-branch safety rule"
        );
        ensure!(
            incoming.evaluated_at >= self.committed()?.evaluated_at,
            "Proposal evaluation precedes committed time"
        );
        admit_time(incoming.evaluated_at)?;
        validate_intent(command, incoming.evaluated_at)?;
        self.sign_vote(
            next,
            Vote {
                scope: self.configuration.scope.clone(),
                view: incoming.view,
                phase: Phase::Prepare,
                node: digest,
            },
        )
    }
    fn check_vote(&self, state: &Snapshot, vote: &Vote) -> Result<Option<Vec<u8>>> {
        self.voting()?;
        self.require_input_branch(state, vote.node)?;
        epoch::branch(&self.configuration, state, vote.node)?;
        ensure!(
            vote.view > state.retired_view,
            "Vote view has been durably retired"
        );
        let entry = vote_id(vote.view, vote.phase, &state.signer);
        if let Some(old) = state.own_votes.get(&entry) {
            ensure!(
                SignedVote::parse(&self.configuration, old)?.vote == *vote,
                "A different vote is already durable"
            );
            return Ok(Some(old.clone()));
        }
        Ok(None)
    }
    fn stage_vote(&self, next: &mut Snapshot, vote: Vote) -> Result<(Vec<u8>, bool)> {
        if let Some(old) = self.check_vote(next, &vote)? {
            return Ok((old, false));
        }
        ensure!(
            next.own_votes.len() < MAX_VOTES && next.votes.len() < MAX_VOTES,
            "Vote history capacity exhausted"
        );
        let entry = vote_id(vote.view, vote.phase, &next.signer);
        let signed = SignedVote::sign(&self.configuration, vote, &self.key)?;
        next.own_votes
            .insert(entry.clone(), signed.envelope.clone());
        next.votes.insert(entry, signed.envelope.clone());
        Ok((signed.envelope, true))
    }
    fn sign_vote(&mut self, mut next: Snapshot, vote: Vote) -> Result<Vec<u8>> {
        let (signed, changed) = self.stage_vote(&mut next, vote)?;
        if changed {
            self.persist(next)?;
        }
        Ok(signed)
    }
    // All fallible checks and signing precede mutation, so a learned QC can still
    // be retained when this replica must defer its own phase vote.
    fn stage_phase_vote(&self, next: &mut Snapshot, qc: &Certificate) -> Result<(Vec<u8>, bool)> {
        self.voting()?;
        ensure!(
            qc.view == self.view() && qc.view > 0,
            "Phase certificate is outside the entered view"
        );
        ensure!(
            qc.view > node(&self.configuration, next, &next.committed)?.view
                && extends(&self.configuration, next, qc.node, next.committed)?,
            "Phase vote would leave the known committed prefix"
        );
        let mut highest_prepare = next.highest_prepare;
        let mut locked = next.locked;
        let phase = match qc.phase {
            Phase::Prepare => {
                let high = certificate(&self.configuration, next, &highest_prepare)?;
                ensure!(qc.view >= high.view, "Prepare floor moved backwards");
                if qc.view > high.view {
                    highest_prepare = qc.digest();
                }
                Phase::PreCommit
            }
            Phase::PreCommit => {
                let expected = Vote {
                    scope: self.configuration.scope.clone(),
                    view: qc.view,
                    phase: Phase::Prepare,
                    node: qc.node,
                };
                let prepare = certificate(
                    &self.configuration,
                    next,
                    &Certificate::vote_digest(&expected)?,
                )
                .context("Matching Prepare certificate is required before Commit voting")?;
                ensure!(
                    prepare.vote.as_ref() == Some(&expected),
                    "Indexed Prepare certificate differs from the exact vote"
                );
                let high = certificate(&self.configuration, next, &highest_prepare)?;
                if prepare.view > high.view {
                    highest_prepare = prepare.digest();
                }
                let lock = certificate(&self.configuration, next, &locked)?;
                ensure!(qc.view >= lock.view, "Lock floor moved backwards");
                if qc.view > lock.view {
                    locked = qc.digest();
                }
                Phase::Commit
            }
            Phase::Commit => anyhow::bail!("Commit evidence is decided, not voted again"),
        };
        let vote = Vote {
            scope: self.configuration.scope.clone(),
            view: qc.view,
            phase,
            node: qc.node,
        };
        let (signed, changed) = self.stage_vote(next, vote)?;
        if changed {
            next.highest_prepare = highest_prepare;
            next.locked = locked;
        }
        Ok((signed, changed))
    }
    pub fn advance_phase(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.voting()?;
        let qc = check_certificate(&self.configuration, &self.snapshot, input)?;
        let mut next = self.snapshot.clone();
        let (signed, changed) = self.stage_phase_vote(&mut next, &qc)?;
        if changed {
            stage_certificate(&mut next, &qc, input)?;
            self.persist(next)?;
        }
        Ok(signed)
    }
    fn stage_certificate_progress(&self, next: &mut Snapshot, qc: &Certificate) -> Result<bool> {
        let mut changed = false;
        if qc.phase == Phase::Prepare
            && qc.view > certificate(&self.configuration, next, &next.highest_prepare)?.view
        {
            next.highest_prepare = qc.digest();
            changed = true;
        }
        // Ordinary local Certificate delivery still reports missing inputs or
        // conflicting decisions. Neither condition may discard the learned QC.
        if qc.phase == Phase::Commit {
            changed |= matches!(self.stage_decision(next, qc), Ok(Decision::Advanced));
        } else if qc.view == self.view()
            && let Ok((_, voted)) = self.stage_phase_vote(next, qc)
        {
            changed |= voted;
        }
        Ok(changed)
    }
    // The node's consensus ancestry and command closure are already durable.
    // Publish its newly learned QC and eligible local transition together.
    fn receive_certificate(&mut self, input: &[u8]) -> Result<()> {
        self.active()?;
        let qc = check_certificate(&self.configuration, &self.snapshot, input)?;
        let mut next = self.snapshot.clone();
        let added = !next.certificates.contains_key(&id(&qc.digest()));
        stage_certificate(&mut next, &qc, input)?;
        let progressed = self.stage_certificate_progress(&mut next, &qc)?;
        if added || progressed {
            self.persist(next)?;
        }
        Ok(())
    }
    fn received_vote(&self, input: &[u8]) -> Result<SignedVote> {
        let signed = SignedVote::parse(&self.configuration, input)?;
        ensure!(
            signed.vote.view > self.snapshot.retired_view,
            "Vote view has been durably retired"
        );
        let target = node(&self.configuration, &self.snapshot, &signed.vote.node)?;
        ensure!(
            signed.vote.view == target.view && signed.vote.view <= self.view(),
            "Vote view is not an entered known proposal"
        );
        Ok(signed)
    }
    fn stage_received_vote(
        &self,
        next: &mut Snapshot,
        signed: &SignedVote,
        input: &[u8],
    ) -> Result<(Option<Vec<u8>>, bool)> {
        let entry = vote_id(signed.vote.view, signed.vote.phase, &signed.signer);
        if let Some(old) = next.votes.get(&entry) {
            ensure!(old == input, "Conflicting authenticated consensus evidence");
            return Ok((self.received_quorum(next, signed)?, false));
        }
        ensure!(
            next.votes.contains_key(&entry) || next.votes.len() < MAX_VOTES,
            "Vote history capacity exhausted"
        );
        next.votes.insert(entry, input.to_vec());
        let mut matching = Vec::new();
        for signer in &self.configuration.voters {
            let index = vote_id(signed.vote.view, signed.vote.phase, signer);
            let Some(value) = next.votes.get(&index) else {
                continue;
            };
            let candidate = SignedVote::parse(&self.configuration, value)?;
            ensure!(
                candidate.signer == *signer
                    && candidate.vote.view == signed.vote.view
                    && candidate.vote.phase == signed.vote.phase,
                "Indexed vote differs from its exact signer, view or phase"
            );
            if candidate.vote == signed.vote {
                matching.push(candidate);
            }
        }
        let qc = if matching.len() >= 3 {
            let qc = Certificate::collect(&self.configuration, &matching)?;
            insert_certificate(&self.configuration, next, &qc.bytes)?;
            self.stage_certificate_progress(next, &qc)?;
            Some(qc.bytes)
        } else {
            None
        };
        Ok((qc, true))
    }
    fn received_quorum(&self, state: &Snapshot, signed: &SignedVote) -> Result<Option<Vec<u8>>> {
        let digest = Certificate::vote_digest(&signed.vote)?;
        let Some(object) = state.certificates.get(&id(&digest)) else {
            return Ok(None);
        };
        let bytes = body(state, object)?;
        let known = Certificate::parse(&self.configuration, &bytes)?;
        ensure!(
            known.vote.as_ref() == Some(&signed.vote),
            "Indexed certificate differs from the exact duplicate vote"
        );
        Ok(Some(bytes.as_ref().clone()))
    }
    /// Gossip votes to all replicas; any honest collector can reconstruct withheld decisions.
    pub fn receive_vote(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>> {
        self.voting()?;
        let signed = self.received_vote(input)?;
        let entry = vote_id(signed.vote.view, signed.vote.phase, &signed.signer);
        if let Some(old) = self.snapshot.votes.get(&entry) {
            if old != input {
                return self.incident(old.clone(), input.to_vec(), false);
            }
            return self.received_quorum(&self.snapshot, &signed);
        }
        let mut next = self.snapshot.clone();
        let (qc, changed) = self.stage_received_vote(&mut next, &signed, input)?;
        if changed {
            self.persist(next)?;
        }
        Ok(qc)
    }
    // A short accepted prefix is returned only after publication. Its first
    // rejected event remains for ordinary refusal/incident handling. Persistence
    // errors instead escape without any output and poison this signer.
    fn receive_votes(&mut self, inputs: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.voting()?;
        ensure!(
            !inputs.is_empty() && inputs.len() <= runtime::MAX_EVENTS,
            "Vote batch exceeds the ingress bound"
        );
        let mut next = self.snapshot.clone();
        let mut outputs = Vec::new();
        let mut statement = None;
        let mut changed = false;
        for input in inputs {
            let Ok(signed) = self.received_vote(input) else {
                break;
            };
            if statement.as_ref().is_some_and(|vote| vote != &signed.vote) {
                break;
            }
            statement = Some(signed.vote.clone());
            let entry = vote_id(signed.vote.view, signed.vote.phase, &signed.signer);
            if let Some(old) = next.votes.get(&entry) {
                if old != input {
                    break;
                }
                let Ok(qc) = self.received_quorum(&next, &signed) else {
                    break;
                };
                outputs.push(qc);
                continue;
            }
            // A failed candidate cannot leave partially staged evidence in the
            // accepted prefix, including when a capacity or index check fails.
            let mut candidate = next.clone();
            let Ok((qc, added)) = self.stage_received_vote(&mut candidate, &signed, input) else {
                break;
            };
            next = candidate;
            changed |= added;
            outputs.push(qc);
        }
        if changed {
            self.persist(next)?;
        }
        Ok(outputs)
    }
    fn stage_decision(&self, next: &mut Snapshot, qc: &Certificate) -> Result<Decision> {
        self.voting()?;
        ensure!(
            qc.phase == Phase::Commit && qc.view > 0,
            "Only a Commit certificate decides"
        );
        if extends(&self.configuration, next, next.committed, qc.node)? {
            return Ok(Decision::Known);
        }
        if !extends(&self.configuration, next, qc.node, next.committed)? {
            return Ok(Decision::Conflict);
        }
        self.stage_direct_application(next, qc)?;
        next.committed = qc.node;
        next.commit_certificates.insert(id(&qc.node), qc.digest());
        Ok(Decision::Advanced)
    }
    pub fn decide(&mut self, input: &[u8]) -> Result<()> {
        self.voting()?;
        let qc = check_certificate(&self.configuration, &self.snapshot, input)?;
        let mut next = self.snapshot.clone();
        match self.stage_decision(&mut next, &qc)? {
            Decision::Known => return Ok(()),
            Decision::Advanced => {}
            Decision::Conflict => {
                let old = self
                    .snapshot
                    .commit_certificates
                    .get(&id(&self.snapshot.committed))
                    .and_then(|digest| self.snapshot.certificates.get(&id(digest)))
                    .map(|object| body(&self.snapshot, object).map(|b| b.as_ref().clone()))
                    .transpose()?
                    .unwrap_or_default();
                return self.incident(old, input.to_vec(), true);
            }
        }
        stage_certificate(&mut next, &qc, input)?;
        self.persist(next)
    }
    fn validate_snapshot(&self) -> Result<()> {
        let state = &self.snapshot;
        state.inputs.validate_metadata(objects(state)?)?;
        ensure!(
            state.version == 3
                && state.configuration == self.configuration.bytes
                && state.signer == self.key.verifying_key().to_bytes(),
            "Signer snapshot identity differs"
        );
        self.configuration.member(&state.signer)?;
        self.validate_checkpoint_snapshot()?;
        state.sync.validate()?;
        for (member, wish) in state.wishes.iter().enumerate() {
            if let Some(envelope) = wish {
                let (signer, target) = synchronizer::verify(&self.configuration, envelope)?;
                ensure!(
                    self.configuration.member(&signer)? == member
                        && target == state.sync.maxima[member],
                    "Durable WISH evidence differs"
                );
            } else {
                ensure!(
                    state.sync.maxima[member] == 0,
                    "Durable WISH evidence is missing"
                );
            }
        }
        ensure!(
            state.nodes.len() <= MAX_NODES
                && state.commands.len() <= MAX_NODES
                && state.certificates.len() <= MAX_CERTIFICATES
                && state.votes.len() <= MAX_VOTES
                && state.own_votes.len() <= MAX_VOTES
                && state.reports.len() <= MAX_REPORTS
                && state.proposals.len() <= MAX_NODES
                && state.executed.len() <= storage::MAX_RESULTS
                && state.commit_certificates.len() <= MAX_NODES
                && state.incidents.len() <= MAX_INCIDENTS,
            "Signer snapshot exceeds history bounds"
        );
        for (digest, object) in &state.commands {
            let bytes = body(state, object)?;
            ensure!(
                *digest == id(&wire::digest(&bytes)),
                "Command digest differs"
            );
            ensure!(
                object.kind == 22 && id(&object.identity) == *digest,
                "Command object index differs"
            );
            Command::parse(&self.configuration, &bytes)?;
        }
        for (digest, object) in &state.nodes {
            let bytes = body(state, object)?;
            ensure!(*digest == id(&wire::digest(&bytes)), "Node digest differs");
            ensure!(
                object.kind == 14 && id(&object.identity) == *digest,
                "Node object index differs"
            );
            check_node(&self.configuration, state, &bytes)?;
        }
        for (digest, object) in &state.certificates {
            let bytes = body(state, object)?;
            ensure!(
                *digest == id(&Certificate::parse(&self.configuration, &bytes)?.digest()),
                "Certificate digest differs"
            );
            ensure!(
                object.kind == 12 && id(&object.identity) == *digest,
                "Certificate object index differs"
            );
            let qc = Certificate::parse(&self.configuration, &bytes)?;
            ensure!(
                node(&self.configuration, state, &qc.node)?.view == qc.view,
                "Certificate node view differs"
            );
        }
        let high = certificate(&self.configuration, state, &state.highest_prepare)?;
        let lock = certificate(&self.configuration, state, &state.locked)?;
        ensure!(
            high.phase == Phase::Prepare && (lock.view == 0 || lock.phase == Phase::PreCommit),
            "Signer Prepare or lock floor has the wrong phase"
        );
        for (entry, bytes) in &state.votes {
            let vote = SignedVote::parse(&self.configuration, bytes)?;
            ensure!(
                *entry == vote_id(vote.vote.view, vote.vote.phase, &vote.signer)
                    && vote.vote.view > state.retired_view
                    && node(&self.configuration, state, &vote.vote.node)?.view == vote.vote.view,
                "Stored vote differs from its index or ancestry"
            );
        }
        for (entry, bytes) in &state.own_votes {
            let vote = SignedVote::parse(&self.configuration, bytes)?;
            self.require_input_branch(state, vote.vote.node)?;
            ensure!(
                vote.signer == state.signer
                    && state.votes.get(entry) == Some(bytes)
                    && vote.vote.view <= self.view(),
                "Own vote history differs"
            );
            if vote.vote.phase == Phase::Commit {
                ensure!(
                    lock.view >= vote.vote.view,
                    "Commit vote has lost its durable lock"
                );
            }
        }
        for (entry, bytes) in &state.reports {
            let report = NewView::parse(&self.configuration, bytes)?;
            let qc = certificate(&self.configuration, state, &report.prepare)?;
            ensure!(
                *entry == report_id(report.view, &report.signer)
                    && qc.phase == Phase::Prepare
                    && qc.view < report.view
                    && report.view <= self.view(),
                "New-view history differs"
            );
        }
        for (view, bytes) in &state.proposals {
            let (payload, signatures) = wire::envelope(bytes, 1)?;
            let proposal = Node::parse(&self.configuration, &payload)?;
            ensure!(
                proposal.view == *view
                    && *view <= self.view()
                    && signatures[0].0 == state.signer
                    && self.configuration.leader(*view)? == state.signer
                    && node(&self.configuration, state, &proposal.digest()?)? == proposal,
                "Leader proposal history differs"
            );
        }
        ensure!(
            extends(&self.configuration, state, state.committed, state.applied)?,
            "Applied state is outside the committed prefix"
        );
        let committed_at_anchor = state.checkpoint.as_ref().is_some_and(|c| {
            checkpoint::verified(&self.configuration, &c.proof)
                .is_ok_and(|c| *c.node() == state.committed)
        });
        if self.committed()?.height > 0 && !committed_at_anchor {
            let digest = state
                .commit_certificates
                .get(&id(&state.committed))
                .context("Committed certificate missing")?;
            let qc = certificate(&self.configuration, state, digest)?;
            ensure!(
                qc.phase == Phase::Commit && qc.node == state.committed,
                "Committed evidence differs"
            );
        }
        wire::decode_state(&state.application)?;
        for digest in state.executed.keys() {
            let digest: Digest = hex::decode(digest)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid executed node index"))?;
            ensure!(
                extends(&self.configuration, state, state.committed, digest)?,
                "Stored execution is outside the committed prefix"
            );
            let n = node(&self.configuration, state, &digest)?;
            let saved = self
                .execution(digest)?
                .context("Stored execution body missing")?;
            let (payload, signatures) = wire::envelope(&saved.attestation, 1)?;
            let value = wire::decode(&payload)?;
            let a = record(&value, 23, 23)?;
            ensure!(
                signatures[0].0 == state.signer
                    && Scope::parse(&a[2])? == self.configuration.scope
                    && a[3].uint()? == n.height
                    && a[4].fixed::<32>()? == digest
                    && a[5].fixed::<32>()? == n.command.context("Executed command missing")?
                    && a[15].fixed::<32>()? == wire::digest(&saved.result)
                    && a[18].uint()? == n.evaluated_at
                    && a[19].uint()? == state.executed[&id(&digest)].expires,
                "Stored execution binding differs"
            );
            let result = wire::decode(&saved.result)?;
            record(&result, 24, 6)?;
        }
        let applied_at_anchor = state.checkpoint.as_ref().is_some_and(|c| {
            checkpoint::verified(&self.configuration, &c.proof).is_ok_and(|c| {
                *c.node() == state.applied && *c.state() == wire::digest(&state.application)
            })
        });
        if self.applied()?.height > 0 && !applied_at_anchor {
            let n = self.applied()?;
            let command = self.command(&n.command.context("Applied command missing")?)?;
            let output = match Command::parse(&self.configuration, &command)? {
                Command::Inert | Command::Noop(_) => ExecutionOutput::Inert,
                Command::Ordered(_) => {
                    let result = self
                        .execution(state.applied)?
                        .context("Applied result missing")?;
                    let (payload, signatures) = wire::envelope(&result.attestation, 1)?;
                    ensure!(
                        signatures[0].0 == state.signer,
                        "Applied result signer differs"
                    );
                    ExecutionOutput::Result {
                        result: result.result,
                        attestation: payload,
                    }
                }
            };
            let position = Committed {
                node: state.applied,
                height: n.height,

                evaluated_at: n.evaluated_at,
                command,
            };
            validate_execution(
                &self.configuration,
                &position,
                &Execution {
                    state: state.application.to_vec(),
                    output,
                },
            )?;
        }
        self.validate_application_cursor()?;
        self.validate_terminal()?;
        self.validate_prepared()?;
        Self::object_budget(state, false)?;
        Ok(())
    }
}
fn validate_execution(
    config: &Configuration,
    position: &Committed,
    execution: &Execution,
) -> Result<()> {
    wire::decode_state(&execution.state)?;
    ensure!(
        execution.state.len() <= checkpoint::MAX_STATE,
        "Executed state exceeds its bound"
    );
    let request = match (
        Command::parse(config, &position.command)?,
        &execution.output,
    ) {
        (Command::Inert | Command::Noop(_), ExecutionOutput::Inert) => return Ok(()),
        (Command::Ordered(request), ExecutionOutput::Result { .. }) => request,
        _ => anyhow::bail!("Execution output differs from committed command kind"),
    };
    let ExecutionOutput::Result {
        result: result_bytes,
        attestation,
    } = &execution.output
    else {
        unreachable!()
    };
    ensure!(
        result_bytes.len() <= MAX_RESULT_BYTES && attestation.len() <= 3984,
        "Executed result exceeds transport reservation"
    );
    let result = wire::decode(result_bytes)?;
    let result = record(&result, 24, 6)?;
    let attestation = wire::decode(attestation)?;
    let a = record(&attestation, 23, 23)?;
    ensure!(
        Scope::parse(&a[2])? == config.scope
            && a[3].uint()? == position.height
            && a[4].fixed::<32>()? == position.node
            && a[5].fixed::<32>()? == wire::digest(&position.command)
            && a[6].fixed::<32>()? == request.intent
            && a[7].fixed::<32>()? == request.challenge
            && a[8].fixed::<32>()? == request.requester
            && a[9].fixed::<32>()? == request.recipient
            && a[10].text()? == request.action
            && a[10].text()? == result[2].text()?
            && a[11].fixed::<32>()? == request.resource
            && a[12].uint()? == request.revision
            && a[13].uint()? == request.profile_generation
            && a[15].fixed::<32>()? == wire::digest(result_bytes)
            && a[16].fixed::<32>()? == wire::digest(&execution.state)
            && a[17].uint()? == request.minimum_height
            && position.height >= request.minimum_height
            && a[18].uint()? == position.evaluated_at
            && a[19].uint()? <= request.expires,
        "Executed result differs from committed execution"
    );
    let disposition = result[3].uint()?;
    let code = result[4].uint()?;
    ensure!(
        match disposition {
            0 => code == 0,
            1 => (1..=38).contains(&code) && a[14].uint()? == 0,
            2 => matches!(code, 25 | 27 | 30) && a[14].uint()? == 0,
            _ => false,
        },
        "Invalid result disposition, code or effect"
    );
    a[14].uint()?;
    wire::decode(result[5].bytes()?)?;
    for field in &a[20..] {
        if *field != V::Null {
            records::nonzero(field)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "ConsensusTests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "ConsensusStorageTests.rs"]
mod storage_tests;

#[cfg(test)]
#[path = "ConsensusTransactionTests.rs"]
mod transaction_tests;
