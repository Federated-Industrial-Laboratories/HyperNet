// SPDX-License-Identifier: MIT
//! Four independent replicas exchange signed protocol messages over pinned mutual TLS.
#[path = "ConsensusDriverCheckpoint.rs"]
mod checkpoint_driver;
#[path = "ConsensusDiagnostics.rs"]
mod diagnostics;
#[path = "ConsensusIngress.rs"]
mod ingress;
#[path = "ConsensusDriverInputs.rs"]
mod input_driver;
#[path = "ConsensusQueue.rs"]
mod queue;
#[path = "ConsensusDriverRepair.rs"]
mod repair_driver;
use super::{
    Committed, Engine, Execution, Outputs,
    peer::{self, Message},
    records::{
        Certificate, Configuration, Digest, Key, NewView, Node, OrderedRequest, Phase, SignedVote,
        Vote,
    },
    repair::{Item, Reference},
};
use crate::{
    authority_objects::{self as input_objects, Reference as InputReference, Resolved},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use input_driver::Submission;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::Instant,
};

pub const MAX_PENDING: usize = 32;
const MAX_OUTBOX: usize = 128;
pub(super) const MAX_EVENTS: usize = 64;
const RETRANSMIT: Duration = Duration::from_millis(250);
const MAX_EARLY_EXECUTION_BYTES: usize = 4 * peer::MAX_PAYLOAD;

pub trait Application: Send + Sync + 'static {
    fn command_inputs(&self, _ordered: &[u8]) -> Result<Vec<InputReference>> {
        Ok(vec![])
    }
    fn result_inputs(&self, _ordered: &[u8], _result: &[u8]) -> Result<Vec<InputReference>> {
        Ok(vec![])
    }
    fn retained_inputs(&self, _state: &[u8]) -> Result<Vec<InputReference>> {
        Ok(vec![])
    }
    fn required_inputs(&self, _prior: &[u8], ordered: &[u8]) -> Result<Vec<InputReference>> {
        self.command_inputs(ordered)
    }
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()>;
    fn validate(
        &self,
        prior: &[u8],
        ordered: &[u8],
        evaluated_at: u64,
        inputs: &Resolved,
    ) -> Result<()>;
    fn execute(&self, prior: &[u8], committed: &Committed, inputs: &Resolved) -> Result<Execution>;
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub peers: [peer::Endpoint; 4],
    pub tls: peer::Credentials,
    pub clock: crate::authority_clock_handoff::Source,
    pub control_socket: PathBuf,
}
pub(super) enum Event {
    Peer {
        sender: Key,
        body: Vec<u8>,
        answer: oneshot::Sender<Vec<u8>>,
        queued: Instant,
    },
    Local {
        body: Vec<u8>,
        answer: oneshot::Sender<Vec<u8>>,
        queued: Instant,
    },
}
#[derive(PartialEq, Eq)]
enum EvidenceStatement {
    Vote(Vote),
    Wish(u64),
    NewView(u64),
}
impl EvidenceStatement {
    fn number(&self) -> u64 {
        match self {
            Self::Wish(_) => 0,
            Self::NewView(_) => 1,
            Self::Vote(_) => 3,
        }
    }
}
enum EvidenceOutput {
    Vote(Option<Vec<u8>>),
    Synchronizer(Outputs),
    Report,
}
struct ShareSet {
    command: Digest,
    height: u64,
    node: Vec<u8>,
    payload: Vec<u8>,
    result: Vec<u8>,
    signatures: BTreeMap<Key, [u8; 64]>,
}
struct EarlyExecution {
    node: Digest,
    bytes: usize,
    claims: BTreeMap<Key, Box<[u8]>>,
}
struct Driver {
    config: Config,
    engine: Engine,
    application: Arc<dyn Application>,
    senders: BTreeMap<Key, ingress::Mailbox>,
    outbox: BTreeMap<Digest, (u64, Message, Vec<u8>)>,
    local: VecDeque<Message>,
    requests: BTreeMap<Digest, Submission>,
    request_order: VecDeque<Digest>,
    input_flight: Option<input_driver::Flight>,
    input_waiting: BTreeMap<Digest, (Key, Message)>,
    query_times: BTreeMap<Digest, Instant>,
    diagnostics: diagnostics::Diagnostics,
    shares: BTreeMap<Digest, ShareSet>,
    early_execution: Option<EarlyExecution>,
    repairs: BTreeMap<Key, repair_driver::Repair>,
    pending_votes: BTreeMap<(u64, u64, Key), SignedVote>,
    checkpoint_votes: BTreeMap<Digest, BTreeMap<Key, [u8; 64]>>,
    transfers: BTreeMap<Key, checkpoint_driver::Transfer>,
    served_checkpoints: BTreeMap<Key, checkpoint_driver::ServedCheckpoint>,
    expires: Option<Instant>,
    last_view: u64,
    last_commit: u64,
    attempted_proposal: u64,
    blocked_application: Option<&'static str>,
    application_ready: bool,
    retransmit_cursor: usize,
}
fn view_timeout(view: u64) -> Duration {
    if view == 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(1000 + 250 * u64::from(view.ilog2()))
    }
}
fn view_deadline(view: u64, now: Instant) -> Result<Option<Instant>> {
    if view == 0 {
        return Ok(None);
    }
    Ok(Some(
        now.checked_add(view_timeout(view))
            .context("View deadline overflow")?,
    ))
}
/// The caller opens the exclusive signer journal and authenticates its complete bootstrap.
pub async fn serve(
    config: Config,
    engine: Engine,
    application: Arc<dyn Application>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    engine.validate_input_bindings(application.as_ref())?;
    let transport = peer::transport(
        engine.configuration(),
        engine.signer(),
        &config.peers,
        &config.tls,
    )?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let (socket, _socket_guard) = ingress::local_socket(&config.control_socket)?;
    let (events, mut receiver) = mpsc::channel(MAX_EVENTS);
    let (diagnostics, monitor) = diagnostics::Diagnostics::new();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(monitor.run());
    tasks.spawn(ingress::accept_peers(
        listener,
        transport.acceptor,
        transport.pins,
        events.clone(),
    ));
    tasks.spawn(ingress::accept_local(
        socket,
        events.clone(),
        diagnostics.clone(),
    ));
    let mut senders = BTreeMap::new();
    for (key, origin, client) in transport.clients {
        if key == engine.signer() {
            continue;
        }
        let mailbox = ingress::Mailbox::new();
        senders.insert(key, mailbox.clone());
        tasks.spawn(ingress::send_peer(
            key,
            origin,
            client,
            mailbox,
            events.clone(),
        ));
    }
    drop(events);
    let expires = view_deadline(engine.view(), Instant::now())?;
    let mut driver = Driver {
        config,
        last_view: engine.view(),
        last_commit: engine.committed()?.height,
        engine,
        application,
        senders,
        outbox: BTreeMap::new(),
        local: VecDeque::new(),
        requests: BTreeMap::new(),
        request_order: VecDeque::new(),
        input_flight: None,
        input_waiting: BTreeMap::new(),
        query_times: BTreeMap::new(),
        diagnostics: diagnostics.clone(),
        shares: BTreeMap::new(),
        early_execution: None,
        repairs: BTreeMap::new(),
        pending_votes: BTreeMap::new(),
        checkpoint_votes: BTreeMap::new(),
        transfers: BTreeMap::new(),
        served_checkpoints: BTreeMap::new(),
        expires,
        attempted_proposal: 0,
        blocked_application: None,
        application_ready: false,
        retransmit_cursor: 0,
    };
    {
        let _turn = diagnostics.begin(diagnostics::Stage::Restore, driver.engine.view(), None);
        driver.restore()?;
        if driver.engine.view() == 0 && driver.engine.can_vote() {
            let output = driver.engine.advance_view()?;
            driver.outputs(output)?;
        }
    }
    let mut interval = tokio::time::interval(RETRANSMIT);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = None;
    let result = loop {
        match driver
            .turn(
                &mut receiver,
                &mut pending,
                &mut shutdown,
                &mut tasks,
                &mut interval,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => break Ok(()),
            Err(error) => break Err(error),
        }
    };
    if result.is_ok() {
        diagnostics.finish(driver.engine.view());
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
impl Driver {
    fn certificate_timing(&self, bytes: &[u8]) {
        let Ok(qc) = Certificate::parse(self.config(), bytes) else {
            return;
        };
        let Ok(node) = self.engine.known_node(&qc.node) else {
            return;
        };
        let (phase, next_vote) = match qc.phase {
            Phase::Prepare => (
                diagnostics::Phase::PrepareQc,
                Some((Phase::PreCommit, diagnostics::Phase::PreCommitVote)),
            ),
            Phase::PreCommit => (
                diagnostics::Phase::PreCommitQc,
                Some((Phase::Commit, diagnostics::Phase::CommitVote)),
            ),
            Phase::Commit => (diagnostics::Phase::CommitQc, None),
        };
        self.diagnostics.phase(&node, phase);
        if let Some((vote, phase)) = next_vote {
            let index = super::vote_id(qc.view, vote, &self.engine.signer());
            if self
                .engine
                .snapshot
                .own_votes
                .get(&index)
                .and_then(|bytes| SignedVote::parse(self.config(), bytes).ok())
                .is_some_and(|signed| signed.vote.node == qc.node)
            {
                self.diagnostics.phase(&node, phase);
            }
        }
        if qc.phase == Phase::Commit && self.engine.snapshot.committed == qc.node {
            self.diagnostics.phase(&node, diagnostics::Phase::Committed);
        }
    }
    async fn turn(
        &mut self,
        receiver: &mut mpsc::Receiver<Event>,
        pending: &mut Option<Event>,
        shutdown: &mut watch::Receiver<bool>,
        tasks: &mut tokio::task::JoinSet<Result<()>>,
        interval: &mut tokio::time::Interval,
    ) -> Result<bool> {
        tokio::select! {
            change = shutdown.changed() => {
                if change.is_err() || *shutdown.borrow() {
                    self.diagnostics.emit(diagnostics::Code::ShutdownObserved, diagnostics::Stage::Shutdown, Duration::ZERO, self.engine.view());
                    return Ok(false);
                }
            }
            ended = tasks.join_next() => {
                anyhow::bail!("Replica transport task stopped: {}", ended.is_some());
            }
            event = async {
                if let Some(event) = pending.take() { Some(event) } else { receiver.recv().await }
            } => {
                let event = event.context("Replica event channel closed")?;
                *pending = self.queued_event(event, receiver)?;
            }
            _ = async {}, if self.application_ready => {
                {
                    let _turn = self.diagnostics.begin(diagnostics::Stage::Apply, self.engine.view(), None);
                    self.apply()?;
                }
                self.drain_turn()?;
                // Yield after the selected bounded turn. A yield used as a
                // readiness condition can be cancelled by continuously ready ingress.
                tokio::task::yield_now().await;
            }
            _ = interval.tick() => {
                {
                    let _turn = self.diagnostics.begin(diagnostics::Stage::Tick, self.engine.view(), None);
                    self.tick()?;
                }
                self.drain_turn()?;
            }
        }
        Ok(true)
    }
    fn queued_evidence(&self, event: &Event) -> Option<(EvidenceStatement, Vec<u8>)> {
        let Event::Peer { sender, body, .. } = event else {
            return None;
        };
        // Classification authenticates queued proofs before event processing.
        // Its separate synchronous boundary also covers deferred and unbatched inputs.
        let _turn =
            self.diagnostics
                .begin(diagnostics::Stage::Classification, self.engine.view(), None);
        self.engine.voting().ok()?;
        match peer::decode(self.config(), *sender, body).ok()? {
            Message::Vote(input) => {
                let signed = self.engine.received_vote(&input).ok()?;
                if signed.vote.view < self.engine.view().saturating_sub(1) {
                    return None;
                }
                let entry = super::vote_id(signed.vote.view, signed.vote.phase, &signed.signer);
                if self
                    .engine
                    .snapshot
                    .votes
                    .get(&entry)
                    .is_some_and(|old| old != &input)
                {
                    return None;
                }
                Some((EvidenceStatement::Vote(signed.vote), input))
            }
            Message::Wish(input) => {
                let (_, target) = super::synchronizer::verify(self.config(), &input).ok()?;
                Some((EvidenceStatement::Wish(target), input))
            }
            Message::NewView(input, _) => {
                // Decode authenticates the attached QC. Batching requires its
                // exact dependency closure already available; repair and input
                // waiting retain their ordinary event path.
                let report = self
                    .engine
                    .checked_new_view(&self.engine.snapshot, &input)
                    .ok()?;
                let entry = super::report_id(report.view, &report.signer);
                if self
                    .engine
                    .snapshot
                    .reports
                    .get(&entry)
                    .is_some_and(|old| old != &input)
                {
                    return None;
                }
                let references = self
                    .engine
                    .certificate_input_references(report.prepare)
                    .ok()?;
                self.engine.input_reader().ok()?.verify(&references).ok()?;
                Some((EvidenceStatement::NewView(report.view), input))
            }
            _ => None,
        }
    }
    fn acknowledge_peer(&self, body: &[u8], answer: oneshot::Sender<Vec<u8>>, disposition: u64) {
        // Outbound HTTP responses have no reply receiver. Incoming requests
        // receive a signed transport-only acknowledgement after publication.
        if !answer.is_closed()
            && let Ok(reply) = self
                .engine
                .sign_peer(&Message::Ack(wire::digest(body), disposition))
        {
            let _ = answer.send(reply);
        }
    }
    fn queued_event(
        &mut self,
        first: Event,
        receiver: &mut mpsc::Receiver<Event>,
    ) -> Result<Option<Event>> {
        if receiver.is_empty() {
            self.event(first)?;
            return Ok(None);
        }
        let Some((statement, input)) = self.queued_evidence(&first) else {
            self.event(first)?;
            return Ok(None);
        };
        let mut batch = vec![(first, input)];
        let mut deferred = None;
        // Take only the queue prefix already present, bounded by the existing
        // ingress capacity. Never wait for a quorum or cross another event.
        for _ in 0..receiver.len().min(MAX_EVENTS - 1) {
            let Ok(event) = receiver.try_recv() else {
                break;
            };
            match self.queued_evidence(&event) {
                Some((next, input)) if next == statement => batch.push((event, input)),
                _ => {
                    deferred = Some(event);
                    break;
                }
            }
        }
        if batch.len() == 1 {
            self.event(batch.pop().unwrap().0)?;
            return Ok(deferred);
        }
        let Event::Peer { queued, .. } = &batch[0].0 else {
            unreachable!()
        };
        let mut turn =
            self.diagnostics
                .begin(diagnostics::Stage::Peer, self.engine.view(), Some(*queued));
        let kind = statement.number();
        turn.message_kind(kind);
        let inputs: Vec<_> = batch.iter().map(|(_, input)| input.clone()).collect();
        let outputs: Vec<_> = match statement {
            EvidenceStatement::Vote(_) => self
                .engine
                .receive_votes(&inputs)?
                .into_iter()
                .map(EvidenceOutput::Vote)
                .collect(),
            EvidenceStatement::Wish(_) => self
                .engine
                .receive_wishes(&inputs)?
                .into_iter()
                .map(EvidenceOutput::Synchronizer)
                .collect(),
            EvidenceStatement::NewView(_) => (0..self.engine.receive_new_views(&inputs)?)
                .map(|_| EvidenceOutput::Report)
                .collect(),
        };
        let remaining = batch.split_off(outputs.len());
        let accepted = !batch.is_empty();
        for ((event, _), output) in batch.into_iter().zip(outputs) {
            let emitted = match output {
                EvidenceOutput::Vote(Some(qc)) => {
                    self.certificate_timing(&qc);
                    self.broadcast(Message::Certificate(qc))
                }
                EvidenceOutput::Synchronizer(output) => self.outputs(output),
                EvidenceOutput::Vote(None) | EvidenceOutput::Report => Ok(()),
            };
            let disposition = match emitted {
                Ok(_) => 0,
                Err(error) => {
                    diagnostic("protocol", self.engine.view(), kind, &error);
                    2
                }
            };
            let Event::Peer { body, answer, .. } = event else {
                unreachable!()
            };
            self.acknowledge_peer(&body, answer, disposition);
        }
        if accepted {
            self.prune_queues()?;
            self.try_propose()?;
        }
        drop(turn);
        if accepted {
            self.drain_turn()?;
        }
        // A validation/capacity rejection leaves the accepted prefix durable.
        // Its event and every following event retain ordinary FIFO handling.
        for (event, _) in remaining {
            self.event(event)?;
        }
        Ok(deferred)
    }
    fn event(&mut self, event: Event) -> Result<()> {
        let acknowledgement = match event {
            Event::Peer {
                sender,
                body,
                answer,
                queued,
            } => {
                let mut turn = self.diagnostics.begin(
                    diagnostics::Stage::Peer,
                    self.engine.view(),
                    Some(queued),
                );
                let mut acknowledgement = false;
                let disposition = match peer::decode(self.engine.configuration(), sender, &body) {
                    Ok(Message::Ack(..)) => {
                        turn.message_kind(10);
                        acknowledgement = true;
                        0
                    }
                    Ok(message) => {
                        let kind = message.number();
                        turn.message_kind(kind);
                        match self.receive(sender, message) {
                            Ok(()) => 0,
                            Err(error) => {
                                diagnostic("protocol", self.engine.view(), kind, &error);
                                2
                            }
                        }
                    }
                    Err(error) => {
                        diagnostic("wire", self.engine.view(), 0, &error);
                        2
                    }
                };
                self.acknowledge_peer(&body, answer, disposition);
                acknowledgement
            }
            Event::Local {
                body,
                answer,
                queued,
            } => {
                let _turn = self.diagnostics.begin(
                    diagnostics::Stage::Local,
                    self.engine.view(),
                    Some(queued),
                );
                let _ = answer.send(self.local_request(&body));
                false
            }
        };
        // An ACK changes no proposal prerequisite. Preserve any already queued
        // local work; NewView delivery and the clock tick still trigger proposals.
        if !acknowledgement || !self.local.is_empty() {
            self.drain_turn()?;
        }
        Ok(())
    }
    fn drain_turn(&mut self) -> Result<()> {
        let _turn =
            self.diagnostics
                .begin(diagnostics::Stage::LocalDrain, self.engine.view(), None);
        self.drain_local()
    }
    fn config(&self) -> &Configuration {
        self.engine.configuration()
    }
    fn now(&self) -> Result<u64> {
        Ok(self.config.clock.health()?.observe()?.wall_ms)
    }
    fn send(&self, recipient: Key, message: &Message) -> Result<()> {
        if let Some(sender) = self.senders.get(&recipient) {
            let class = match message {
                Message::Submit(command, _) => queue::Class::Submission(wire::digest(command)),
                Message::RepairRequest(..)
                | Message::StateRequest(..)
                | Message::ArchiveRequest(..)
                | Message::InputRequest(..) => queue::Class::Request {
                    family: message.number() as u8,
                    token: wire::digest(&message.payload()?),
                },
                Message::RepairResponse(..)
                | Message::StateResponse(..)
                | Message::ArchiveResponse(..)
                | Message::CheckpointProof(_)
                | Message::CheckpointShare(_)
                | Message::CheckpointSuperseded(..)
                | Message::InputResponse(..) => queue::Class::Response {
                    family: message.number() as u8,
                },
                _ => queue::Class::Transient,
            };
            let _ = sender.push_class(self.engine.sign_peer(message)?, class);
        }
        Ok(())
    }
    fn broadcast(&mut self, message: Message) -> Result<()> {
        self.engine.active()?;
        // The bounded outbox already holds authenticated, signed bytes for an
        // exact message. Its existing retransmission path remains responsible
        // for delivery; a duplicate need not validate and sign those bytes again.
        if self.outbox.values().any(|(_, known, _)| known == &message) {
            return Ok(());
        }
        let bytes = self.engine.sign_peer(&message)?;
        let digest = wire::digest(&bytes);
        if self.outbox.contains_key(&digest) {
            return Ok(());
        }
        ensure!(
            self.outbox.len() < MAX_OUTBOX,
            "Replica retransmission capacity exhausted"
        );
        for sender in self.senders.values() {
            let _ = sender.push_class(
                bytes.clone(),
                queue::Class::Broadcast {
                    recovery: matches!(
                        message,
                        Message::CheckpointShare(_) | Message::CheckpointProof(_)
                    ),
                },
            );
        }
        self.outbox
            .insert(digest, (self.engine.view(), message.clone(), bytes));
        ensure!(
            self.local.len() < MAX_OUTBOX,
            "Local delivery capacity exhausted"
        );
        self.local.push_back(message);
        Ok(())
    }
    fn outputs(&mut self, output: Outputs) -> Result<()> {
        if self.engine.view() != self.last_view {
            self.last_view = self.engine.view();
            #[cfg(test)]
            eprintln!(
                "Replica {} entered view {}",
                self.config().member(&self.engine.signer())?,
                self.last_view
            );
            self.expires = view_deadline(self.engine.view(), Instant::now())?;
            let view = self.engine.view();
            let committed = self.engine.committed()?.digest()?;
            let configuration = self.engine.configuration();
            self.outbox.retain(|_, (record_view, message, _)| {
                let retained_commit = matches!(message, Message::Certificate(bytes) if Certificate::parse(configuration, bytes).is_ok_and(|qc| qc.phase == Phase::Commit && qc.node == committed));
                retained_commit || matches!(message,Message::CheckpointShare(_) | Message::CheckpointProof(_)) || (*record_view >= view.saturating_sub(1) && !matches!(message, Message::Wish(_) | Message::Submit(..)))
            });
            self.repairs.retain(|_, r| r.view >= view.saturating_sub(1));
            self.pending_votes
                .retain(|(v, _, _), _| *v >= view.saturating_sub(1) && *v <= view);
        }
        if let Some(wish) = output.wish {
            self.outbox
                .retain(|_, (_, m, _)| !matches!(m, Message::Wish(_)));
            self.broadcast(Message::Wish(wish))?;
        }
        if let Some(report) = output.new_view {
            let r = NewView::parse(self.config(), &report)?;
            let qc = self.engine.known_certificate(&r.prepare)?.bytes;
            self.broadcast(Message::NewView(report, qc))?;
        }
        self.prune_queues()
    }
    fn prune_queues(&mut self) -> Result<()> {
        self.prune_early_execution()?;
        if !self.requests.is_empty() && self.engine.committed()?.height > self.last_commit {
            // apply advances last_commit only after this purge. Later arrivals
            // are checked by submit, so unchanged suffixes need no rescan here.
            let committed = self.engine.unapplied_commands()?;
            self.requests
                .retain(|digest, _| !committed.contains(digest));
            self.request_order
                .retain(|digest| self.requests.contains_key(digest));
        }
        let broadcasts = self.outbox.keys().copied().collect();
        let submissions = self.requests.keys().copied().collect();
        for (peer, sender) in &self.senders {
            let mut requests = std::collections::BTreeSet::new();
            if let Some(repair) = self.repairs.get(peer)
                && let Some(message) = repair.pending_message()
            {
                requests.insert(wire::digest(&message.payload()?));
            }
            if let Some(transfer) = self.transfers.get(peer) {
                requests.insert(wire::digest(&transfer.pending_message().payload()?));
            }
            if let Some(token) = self.input_request_token()? {
                requests.insert(token);
            }
            for transfer in self.transfers.values() {
                if matches!(transfer.pending_message(), Message::InputRequest(..)) {
                    requests.insert(wire::digest(&transfer.pending_message().payload()?));
                }
            }
            sender.retain_live(&broadcasts, &submissions, &requests)?;
        }
        Ok(())
    }
    fn restore(&mut self) -> Result<()> {
        for message in self.engine.retransmission_records()? {
            self.broadcast(message)?;
        }
        self.apply()?;
        Ok(())
    }
    fn drain_local(&mut self) -> Result<()> {
        let own = self.engine.signer();
        for _ in 0..512 {
            let Some(message) = self.local.pop_front() else {
                self.try_propose()?;
                return Ok(());
            };
            // A duplicate or superseded durable local vote is not a new protocol failure.
            let _ = self.receive(own, message);
        }
        ensure!(self.local.is_empty(), "Local delivery failed to converge");
        Ok(())
    }
    fn tick(&mut self) -> Result<()> {
        self.expire_queries(Instant::now());
        self.prune_queues()?;
        if self.engine.can_vote() {
            let outputs = self.engine.retransmit_wish()?;
            self.outputs(outputs)?;
        }
        if self.engine.can_vote()
            && self
                .expires
                .is_some_and(|expires| Instant::now() >= expires)
        {
            // One timer event per entered view. WISH retransmission handles
            // waiting for quorum entry without inflating the next deadline.
            self.expires = None;
            let outputs = self.engine.advance_view()?;
            self.outputs(outputs)?;
        }
        let messages: Vec<_> = self.outbox.values().collect();
        for offset in 0..messages.len().min(8) {
            let (_, message, bytes) = messages[(self.retransmit_cursor + offset) % messages.len()];
            for sender in self.senders.values() {
                let _ = sender.push_class(
                    bytes.clone(),
                    queue::Class::Broadcast {
                        recovery: matches!(
                            message,
                            Message::CheckpointShare(_) | Message::CheckpointProof(_)
                        ),
                    },
                );
            }
        }
        if !messages.is_empty() {
            self.retransmit_cursor = (self.retransmit_cursor + 8) % messages.len();
        }
        if let Ok(now) = self.now() {
            self.requests.retain(|_, bytes| {
                OrderedRequest::parse(self.engine.configuration(), &bytes.command)
                    .is_ok_and(|r| r.expires.saturating_add(5000) > now)
            });
            self.request_order
                .retain(|digest| self.requests.contains_key(digest));
        }
        let pending: Vec<_> = self.requests.values().cloned().collect();
        for command in pending {
            for sender in self.senders.keys() {
                self.send(
                    *sender,
                    &Message::Submit(
                        command.command.clone(),
                        wire::encode(&command.inputs.value())?,
                    ),
                )?;
            }
        }
        let peers: Vec<_> = self.repairs.keys().copied().collect();
        for peer in peers {
            self.repair_progress(peer)?;
        }
        self.checkpoint_tick()?;
        self.input_tick()?;
        self.apply()?;
        self.prune_queues()?;
        self.try_propose()
    }
    fn remember_request(&mut self, submission: Submission) -> Result<Digest> {
        let digest = wire::digest(&submission.command);
        if self.requests.contains_key(&digest) {
            return Ok(digest);
        }
        ensure!(
            self.requests.len() < MAX_PENDING,
            "pending request capacity reached"
        );
        self.requests.insert(digest, submission);
        self.request_order.push_back(digest);
        self.diagnostics.accepted(digest);
        Ok(digest)
    }
    fn remove_request(&mut self, digest: &Digest) {
        self.requests.remove(digest);
        self.request_order.retain(|pending| pending != digest);
    }
    fn submit(&mut self, submission: Submission) -> Result<Digest> {
        submission.encode()?;
        let command = &submission.command;
        let request = OrderedRequest::parse(self.config(), command)?;
        ensure!(
            command.len() < peer::MAX_PAYLOAD / 2,
            "request exceeds transport bound"
        );
        let digest = wire::digest(command);
        if self.engine.unapplied_commands()?.contains(&digest) {
            self.remove_request(&digest);
            self.prune_queues()?;
            return Ok(digest);
        }
        if self.engine.executed_request(digest)?.is_some() {
            return Ok(digest);
        }
        if self.requests.contains_key(&digest) {
            return Ok(digest);
        }
        ensure!(
            self.requests.len() < MAX_PENDING,
            "pending request capacity reached"
        );
        let now = self.now()?;
        ensure!(now <= request.expires, "request expired");
        let resolved = input_driver::evaluation_inputs(
            self.application.as_ref(),
            &self.engine.input_reader()?,
            self.engine.application(),
            command,
            Some(&submission.inputs),
        )?;
        self.application
            .validate(self.engine.application(), command, now, &resolved)?;
        self.remember_request(submission)
    }

    fn try_propose(&mut self) -> Result<()> {
        self.prune_queues()?;
        if self.engine.halted()
            || self.engine.view() == 0
            || self.config().leader(self.engine.view())? != self.engine.signer()
            || self.attempted_proposal == self.engine.view()
        {
            return Ok(());
        }
        if let Some(proposal) = self.engine.current_proposal() {
            let proposal = proposal.to_vec();
            self.attempted_proposal = self.engine.view();
            return self.broadcast_proposal(proposal);
        }
        if !self.engine.has_new_view_quorum() {
            return Ok(());
        }
        let Ok(now) = self.now() else {
            return Ok(());
        };
        if let Some(command) = self.engine.terminal_progress()? {
            if let Ok(proposal) = self.engine.propose(&command, now) {
                self.attempted_proposal = self.engine.view();
                self.broadcast_proposal(proposal)?;
            }
            return Ok(());
        }
        // A later digest cannot displace older eligible work; future requests retain their place.
        let commands: Vec<_> = self
            .request_order
            .iter()
            .filter_map(|digest| self.requests.get(digest))
            .filter(|command| request_eligible_at(&command.command).is_ok_and(|time| time <= now))
            .cloned()
            .collect();
        // A missing quorum or a future causal floor cannot manufacture a smaller position.
        for command in commands {
            // A committed fence can invalidate a request admitted in an earlier view.
            let Ok(resolved) = input_driver::evaluation_inputs(
                self.application.as_ref(),
                &self.engine.input_reader()?,
                self.engine.application(),
                &command.command,
                Some(&command.inputs),
            ) else {
                continue;
            };
            if self
                .application
                .validate(self.engine.application(), &command.command, now, &resolved)
                .is_err()
            {
                continue;
            }
            if let Ok(proposal) =
                self.engine
                    .propose_with_inputs(&command.command, now, &command.inputs)
            {
                self.attempted_proposal = self.engine.view();
                return self.broadcast_proposal(proposal);
            }
        }
        if self.engine.needs_inert_progress()? {
            let command = super::records::Command::inert(self.config())?;
            if let Ok(proposal) = self.engine.propose(&command, now) {
                self.attempted_proposal = self.engine.view();
                self.broadcast_proposal(proposal)?;
            }
        }
        Ok(())
    }

    fn broadcast_proposal(&mut self, proposal: Vec<u8>) -> Result<()> {
        let (body, _) = wire::envelope(&proposal, 1)?;
        let node = Node::parse(self.config(), &body)?;
        self.diagnostics.proposed(&node, diagnostics::Stamp::now());
        let command = self
            .engine
            .repair_export(&[reference(
                22,
                node.command.context("Proposal command absent")?,
            )])?
            .pop()
            .context("Proposal command is unavailable")?
            .bytes;
        let qc = self
            .engine
            .known_certificate(&node.justify.context("Proposal justification absent")?)?
            .bytes;
        let inputs = self
            .engine
            .input_reader()?
            .resolve(self.engine.retained_command_inputs(node.command.unwrap())?)?;
        self.broadcast(Message::Proposal(
            proposal,
            command,
            qc,
            wire::encode(&inputs.value())?,
        ))
    }
    fn receive(&mut self, sender: Key, message: Message) -> Result<()> {
        match message.clone() {
            Message::Wish(bytes) => {
                let outputs = self.engine.receive_wish(&bytes)?;
                self.outputs(outputs)?;
            }
            Message::NewView(report, qc) => {
                let parsed = NewView::parse(self.config(), &report)?;
                ensure!(
                    parsed.view >= self.engine.view().saturating_sub(1)
                        && parsed.view <= self.engine.view().saturating_add(1),
                    "NewView is outside repair window"
                );
                if !self.dependencies(
                    sender,
                    message,
                    vec![item(self.config(), 12, qc.clone())?],
                )? {
                    return Ok(());
                }
                self.engine.receive_new_view(&report)?;
                let references = self.engine.certificate_input_references(parsed.prepare)?;
                if let Err(error) = self.engine.input_reader()?.verify(&references) {
                    if let Some(missing) = error.downcast_ref::<input_objects::Unavailable>() {
                        self.wait_input(
                            sender,
                            Message::NewView(report, qc),
                            parsed.prepare,
                            missing.0.clone(),
                        )?;
                        return Ok(());
                    }
                    return Err(error);
                }
            }
            Message::Proposal(proposal, command, qc, sidecar) => {
                let observed = diagnostics::Stamp::now();
                let (payload, _) = wire::envelope(&proposal, 1)?;
                let node = Node::parse(self.config(), &payload)?;
                ensure!(
                    node.view == self.engine.view(),
                    "Proposal is outside entered view"
                );
                if !self.dependencies(
                    sender,
                    message,
                    vec![item(self.config(), 12, qc.clone())?],
                )? {
                    return Ok(());
                }
                let health = self.config.clock.health()?;
                let app = self.application.clone();
                let prior = self.engine.application().to_vec();
                let diagnostics = self.diagnostics.clone();
                let view = self.engine.view();
                let inputs =
                    Resolved::parse(&app.command_inputs(&command)?, &wire::decode(&sidecar)?)?;
                let resolved = input_driver::evaluation_inputs(
                    app.as_ref(),
                    &self.engine.input_reader()?,
                    &prior,
                    &command,
                    Some(&inputs),
                )?;
                let vote = self.engine.prepare_with_inputs(
                    &proposal,
                    &command,
                    &inputs,
                    |time| {
                        let age = health.observe()?.wall_ms.abs_diff(time);
                        if age > 1000 {
                            diagnostics.emit(
                                diagnostics::Code::ProposalClockAge,
                                diagnostics::Stage::Peer,
                                Duration::from_millis(age),
                                view,
                            );
                            anyhow::bail!("Proposal clock differs");
                        }
                        Ok(())
                    },
                    |ordered, time| app.validate(&prior, ordered, time, &resolved),
                );
                let vote = match vote {
                    Ok(vote) => vote,
                    Err(error) => {
                        if let Some(missing) = error.downcast_ref::<input_objects::Unavailable>() {
                            self.wait_input(
                                sender,
                                Message::Proposal(proposal, command, qc, sidecar),
                                node.justify.unwrap(),
                                missing.0.clone(),
                            )?;
                            return Ok(());
                        }
                        return Err(error);
                    }
                };
                self.diagnostics.proposed(&node, observed);
                self.diagnostics
                    .phase(&node, diagnostics::Phase::PrepareVote);
                self.broadcast(Message::Vote(vote))?;
            }
            Message::Vote(vote) => {
                let parsed = SignedVote::parse(self.config(), &vote)?;
                ensure!(
                    parsed.vote.view <= self.engine.view()
                        && parsed.vote.view >= self.engine.view().saturating_sub(1),
                    "Vote is outside repair window"
                );
                if self.engine.known_node(&parsed.vote.node).is_err() {
                    // A lone eligible vote is not authority to write its node. A
                    // transient collector can still recover a withheld certificate.
                    let entry = (parsed.vote.view, parsed.vote.phase.number(), parsed.signer);
                    if let Some(old) = self.pending_votes.get(&entry) {
                        ensure!(old.vote == parsed.vote, "Conflicting staged vote");
                    } else {
                        ensure!(
                            self.pending_votes.len() < 24,
                            "Staged vote capacity exhausted"
                        );
                        self.pending_votes.insert(entry, parsed.clone());
                    }
                    let matching: Vec<_> = self
                        .pending_votes
                        .values()
                        .filter(|v| v.vote == parsed.vote)
                        .cloned()
                        .collect();
                    if matching.len() >= 3 {
                        let qc = Certificate::collect(self.config(), &matching)?.bytes;
                        self.broadcast(Message::Certificate(qc.clone()))?;
                        self.receive(sender, Message::Certificate(qc))?;
                    }
                    return Ok(());
                }
                if let Some(qc) = self.engine.receive_vote(&vote)? {
                    self.certificate_timing(&qc);
                    self.broadcast(Message::Certificate(qc))?;
                }
            }
            Message::Certificate(bytes) => {
                let qc = Certificate::parse(self.config(), &bytes)?;
                ensure!(
                    qc.view <= self.engine.view().saturating_add(1),
                    "Certificate is beyond repair window"
                );
                if self.engine.known_node(&qc.node).is_ok() {
                    self.engine.receive_certificate(&bytes)?;
                } else if !self.dependencies(
                    sender,
                    message,
                    vec![item(self.config(), 12, bytes.clone())?],
                )? {
                    return Ok(());
                }
                self.certificate_timing(&bytes);
                if qc.phase == Phase::Commit {
                    self.engine.decide(&bytes)?;
                    self.certificate_timing(&bytes);
                    self.apply()?;
                } else if qc.view == self.engine.view() {
                    match self.engine.advance_phase(&bytes) {
                        Ok(vote) => {
                            self.certificate_timing(&bytes);
                            self.broadcast(Message::Vote(vote))?;
                        }
                        Err(error) => {
                            if let Some(missing) =
                                error.downcast_ref::<input_objects::Unavailable>()
                            {
                                self.wait_input(
                                    sender,
                                    Message::Certificate(bytes),
                                    qc.digest(),
                                    missing.0.clone(),
                                )?;
                            }
                        }
                    }
                }
            }
            Message::RepairRequest(id, refs) => {
                let mut exported = self.engine.repair_export(&refs)?;
                while Message::RepairResponse(id, exported.clone())
                    .payload()?
                    .len()
                    > peer::MAX_PAYLOAD
                {
                    exported
                        .pop()
                        .context("Repair record exceeds transport bound")?;
                }
                self.send(sender, &Message::RepairResponse(id, exported))?;
            }
            Message::RepairResponse(id, items) => self.repair_response(sender, id, items)?,
            Message::Execution(node, attestation, result) => {
                // Early claims remain untrusted until exact local execution is
                // durable. Their unsigned node bodies cannot initiate repair.
                self.collect_share(node, attestation, result)?;
            }
            Message::Submit(command, sidecar) => {
                let references = self.application.command_inputs(&command)?;
                let inputs = Resolved::parse(&references, &wire::decode(&sidecar)?)?;
                self.submit(Submission { command, inputs })?;
            }
            Message::InputRequest(id, anchor, reference) => {
                self.input_request(sender, id, anchor, reference)?
            }
            Message::InputResponse(id, anchor, reference, body) => {
                self.input_response(sender, id, anchor, reference, body)?
            }
            Message::Query(digest) => {
                // This channel is exclusively committee mTLS; it is not a reader endpoint.
                if let Some((node, record)) = self.engine.executed_request(digest)? {
                    if let Some(qc) = self.engine.committed_certificate()? {
                        self.send(sender, &Message::Certificate(qc))?;
                    } else if let Some(proof) = self.engine.checkpoint_proof() {
                        self.send(sender, &Message::CheckpointProof(proof.to_vec()))?;
                    }
                    self.send(
                        sender,
                        &Message::Execution(node.encode()?, record.attestation, record.result),
                    )?;
                }
            }
            Message::Ack(..) => {}
            checkpoint @ (Message::CheckpointShare(_)
            | Message::CheckpointProof(_)
            | Message::StateRequest(..)
            | Message::StateResponse(..)
            | Message::ArchiveRequest(..)
            | Message::ArchiveResponse(..)
            | Message::CheckpointSuperseded(..)) => self.checkpoint_receive(sender, checkpoint)?,
        }
        self.prune_queues()?;
        self.try_propose()?;
        Ok(())
    }
    fn apply(&mut self) -> Result<()> {
        self.prune_queues()?;
        let app = self.application.clone();
        let reader = self.engine.input_reader()?;
        let progress = self.engine.apply_turn_with_inputs(|prior, commit| {
            let resolved = input_driver::evaluation_inputs(
                app.as_ref(),
                &reader,
                prior,
                &commit.command,
                None,
            )?;
            let execution = app.execute(prior, commit, &resolved)?;
            let retained = input_driver::executed_inputs(
                app.as_ref(),
                prior,
                &commit.command,
                &execution.state,
            )?;
            Ok((execution, retained))
        })?;
        // Continue a durable application cursor in a separate cooperative turn.
        // Progress must not wait for another packet or the gossip retry timer.
        self.application_ready = matches!(
            progress,
            super::application::Turn::Progress
                | super::application::Turn::Inert
                | super::application::Turn::Result(..)
        );
        if let super::application::Turn::Unavailable(reference) = &progress {
            let certificate = self
                .engine
                .application_input_certificate()
                .context("missing input lacks deciding certificate")?;
            self.request_input(certificate, reference.clone())?;
        }
        if let super::application::Turn::Blocked(reason) = &progress {
            if self.blocked_application != Some(*reason) {
                diagnostic(
                    "application",
                    self.engine.view(),
                    0,
                    &anyhow::anyhow!(*reason),
                );
            }
            self.blocked_application = Some(*reason);
        } else {
            self.blocked_application = None;
        }
        if let super::application::Turn::Result(node, record) = progress {
            self.diagnostics.phase(&node, diagnostics::Phase::Executed);
            self.reconcile_early_execution(&node, &record)?;
            let command = node.command.context("Applied result command missing")?;
            self.remove_request(&command);
            // Earlier replies may have arrived before this exact execution was
            // durable. New progress permits one prompt recovery query.
            self.query_times.remove(&command);
            self.broadcast(Message::Execution(
                node.encode()?,
                record.attestation,
                record.result,
            ))?;
        }
        self.checkpoint_emit()?;
        let height = self.engine.committed()?.height;
        if height > self.last_commit {
            self.last_commit = height;
            self.expires = None;
            #[cfg(test)]
            eprintln!(
                "Replica {} committed height {}",
                self.config().member(&self.engine.signer())?,
                height
            );
            if self.engine.can_vote() {
                let output = self.engine.advance_view()?;
                self.outputs(output)?;
            }
        }
        Ok(())
    }
    fn collect_share(
        &mut self,
        node_bytes: Vec<u8>,
        envelope: Vec<u8>,
        result: Vec<u8>,
    ) -> Result<()> {
        let node = Node::parse(self.config(), &node_bytes)?;
        let command = node.command.context("Execution command missing")?;
        let digest = node.digest()?;
        let (payload, signatures) = wire::envelope(&envelope, 1)?;
        ensure!(
            signatures.len() == 1,
            "Execution share has more than one signer"
        );
        self.config().member(&signatures[0].0)?;
        let Some(local) = self.engine.execution(digest)? else {
            return self.retain_early_execution(
                node_bytes,
                envelope,
                result,
                digest,
                signatures[0].0,
            );
        };
        let (own_payload, own_signatures) = wire::envelope(&local.attestation, 1)?;
        ensure!(
            own_payload == payload && local.result == result,
            "Execution share differs from locally committed execution"
        );
        if !self.shares.contains_key(&digest) && self.shares.len() == MAX_PENDING {
            let evict = self
                .shares
                .iter()
                .min_by_key(|(key, set)| (set.height, **key))
                .map(|(key, _)| *key)
                .context("Execution cache is empty")?;
            self.shares.remove(&evict);
        }
        let shares = self.shares.entry(digest).or_insert(ShareSet {
            command,
            height: node.height,
            node: node_bytes,
            payload: payload.clone(),
            result: result.clone(),
            signatures: BTreeMap::new(),
        });
        ensure!(
            shares.payload == payload && shares.result == result,
            "Execution share context changed"
        );
        // The local share is already durable for this exact node. Keeping it
        // with peer shares also permits an older complete execution to answer
        // while a newer execution of the same request is still incomplete.
        shares
            .signatures
            .insert(own_signatures[0].0, own_signatures[0].1);
        shares.signatures.insert(signatures[0].0, signatures[0].1);
        if shares.signatures.len() >= 3 {
            self.diagnostics.phase(&node, diagnostics::Phase::Quorum);
        }
        Ok(())
    }
    fn prune_early_execution(&mut self) -> Result<()> {
        if let Some(early) = &self.early_execution
            && (self.engine.committed()?.digest()? != early.node
                || self.engine.applied()?.digest()? == early.node)
        {
            self.early_execution = None;
        }
        Ok(())
    }
    fn retain_early_execution(
        &mut self,
        node: Vec<u8>,
        attestation: Vec<u8>,
        result: Vec<u8>,
        digest: Digest,
        signer: Key,
    ) -> Result<()> {
        self.prune_early_execution()?;
        if self.engine.committed()?.digest()? != digest
            || self.engine.applied()?.digest()? == digest
        {
            return Ok(());
        }
        // Use the normal message validation even for direct local callers. One
        // encoded, bounded claim per committee signer owns all retained bytes.
        let message = Message::Execution(node, attestation, result);
        let bytes = message.payload()?;
        Message::parse(self.config(), message.number(), &bytes)?;
        let early = self.early_execution.get_or_insert(EarlyExecution {
            node: digest,
            bytes: 0,
            claims: BTreeMap::new(),
        });
        if early.claims.contains_key(&signer) {
            return Ok(());
        }
        let total = early
            .bytes
            .checked_add(bytes.len())
            .context("Early execution size overflow")?;
        ensure!(
            early.claims.len() < 4 && total <= MAX_EARLY_EXECUTION_BYTES,
            "Early execution claims exceed the committee bound"
        );
        early.claims.insert(signer, bytes.into_boxed_slice());
        early.bytes = total;
        Ok(())
    }
    fn reconcile_early_execution(
        &mut self,
        node: &Node,
        local: &super::ExecutionRecord,
    ) -> Result<()> {
        let digest = node.digest()?;
        if self
            .early_execution
            .as_ref()
            .is_none_or(|early| early.node != digest)
        {
            return Ok(());
        }
        let early = self.early_execution.take().unwrap();
        let (own_payload, _) = wire::envelope(&local.attestation, 1)?;
        for bytes in early.claims.into_values() {
            let Message::Execution(node, attestation, result) =
                Message::parse(self.config(), 7, &bytes)?
            else {
                unreachable!("Only validated Execution claims are retained");
            };
            let (payload, _) = wire::envelope(&attestation, 1)?;
            // A signed but incorrect claim cannot select the canonical result
            // or stop other signers from completing the locally executed proof.
            if payload == own_payload && result == local.result {
                self.collect_share(node, attestation, result)?;
            }
        }
        Ok(())
    }
    fn local_request(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.local_checked(bytes)
            .unwrap_or_else(|_| self.reply(2, 2, None, None).unwrap_or_default())
    }
    fn local_checked(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let value = wire::decode(bytes)?;
        let a = super::records::record(&value, 41, 5)?;
        ensure!(
            super::records::Scope::parse(&a[2])? == self.config().scope,
            "Local scope differs"
        );
        match a[3].uint()? {
            0 => {
                let command =
                    Submission::parse(self.config(), self.application.as_ref(), a[4].bytes()?)?;
                let digest = self.submit(command.clone())?;
                if self.requests.contains_key(&digest) {
                    for key in self.senders.keys() {
                        self.send(
                            *key,
                            &Message::Submit(
                                command.command.clone(),
                                wire::encode(&command.inputs.value())?,
                            ),
                        )?;
                    }
                }
                self.try_propose()?;
                self.result(digest)
            }
            1 => {
                let digest: Digest = a[4].bytes()?.try_into()?;
                self.result(digest)
            }
            2 => {
                wire::decode(a[4].bytes()?)?.array(0)?;
                self.reply(0, if self.now().is_ok() { 0 } else { 4 }, None, None)
            }
            3 => {
                let input = wire::decode(a[4].bytes()?)?;
                let input = input.array(3)?;
                let floor = input[0].uint()?;
                let from = input[1].fixed::<32>()?;
                let target = input[2].fixed::<32>()?;
                let Ok(nodes) = self.engine.ancestry(floor, from, target) else {
                    return self.reply(2, 1, None, None);
                };
                wire::encode(&V::Array(vec![
                    V::Uint(43),
                    V::Uint(1),
                    self.config().scope.value(),
                    V::Array(nodes.into_iter().map(V::Bytes).collect()),
                ]))
            }
            4 => {
                let input = wire::decode(a[4].bytes()?)?;
                let input = input.array(5)?;
                let prior = if input[4] == V::Null {
                    None
                } else {
                    Some(input[4].fixed::<32>()?)
                };
                if input[2] == V::Null {
                    return match self.engine.latest_history_reply(
                        input[0].uint()?,
                        input[1].fixed::<32>()?,
                        input[3].uint()?,
                        prior,
                    )? {
                        Some(reply) => Ok(reply),
                        None => self.reply(2, 1, None, None),
                    };
                }
                match self.engine.history_reply(
                    input[0].uint()?,
                    input[1].fixed::<32>()?,
                    input[2].fixed::<32>()?,
                    input[3].uint()?,
                    prior,
                ) {
                    Err(error) if error.is::<super::checkpoint::HistoryOvertaken>() => {
                        self.reply(2, 5, None, None)
                    }
                    reply => reply,
                }
            }
            5 => {
                wire::decode(a[4].bytes()?)?.array(0)?;
                // Local diagnostics do not send peer traffic or attest quorum readiness.
                wire::encode(&V::Array(vec![
                    V::Uint(59),
                    V::Uint(1),
                    self.config().scope.value(),
                    V::Bytes(self.engine.signer().to_vec()),
                    V::Uint(self.engine.generation()),
                    V::Uint(self.engine.view()),
                    V::Uint(self.engine.committed()?.height),
                    V::Uint(self.engine.applied()?.height),
                    V::Bool(self.now().is_ok()),
                ]))
            }
            _ => anyhow::bail!("Unknown local operation"),
        }
    }
    fn expire_queries(&mut self, now: Instant) {
        self.query_times
            .retain(|_, last| now.saturating_duration_since(*last) < RETRANSMIT);
    }
    fn result(&mut self, digest: Digest) -> Result<Vec<u8>> {
        self.result_at(digest, Instant::now())
    }
    fn result_at(&mut self, digest: Digest, now: Instant) -> Result<Vec<u8>> {
        self.expire_queries(now);
        if let Some((node, record)) = self.engine.executed_request(digest)? {
            self.collect_share(node.encode()?, record.attestation, record.result)?;
        }
        if let Some((node, shares)) = self
            .shares
            .iter()
            .filter(|(_, s)| s.command == digest && s.signatures.len() >= 3)
            .max_by_key(|(node, s)| (s.height, **node))
        {
            return match self.reply(1, 0, Some(digest), Some(shares)) {
                Ok(reply) => {
                    if let Ok(node) = self.engine.known_node(node) {
                        self.diagnostics
                            .phase(&node, diagnostics::Phase::ReplyReady);
                    }
                    Ok(reply)
                }
                Err(error)
                    if error
                        .downcast_ref::<crate::authority_objects::Unavailable>()
                        .is_some() =>
                {
                    self.reply(2, 1, Some(digest), None)
                }
                reply => reply,
            };
        }
        if !self.query_times.contains_key(&digest) && self.query_times.len() < MAX_PENDING {
            self.query_times.insert(digest, now);
            for key in self.senders.keys() {
                self.send(*key, &Message::Query(digest))?;
            }
        }
        self.reply(0, 0, Some(digest), None)
    }
    fn reply(
        &self,
        status: u64,
        code: u64,
        request: Option<Digest>,
        shares: Option<&ShareSet>,
    ) -> Result<Vec<u8>> {
        let b = super::records::bytes;
        let (node, certificate, result, outputs) = if let Some(s) = shares {
            ensure!(
                status == 1 && code == 0 && s.signatures.len() >= 3,
                "object delivery requires a complete certified result"
            );
            let operation = crate::authority_proof::OperationResult::parse(&s.result)?;
            let references = if operation.disposition == crate::authority_proof::Disposition::Permit
            {
                self.application
                    .result_inputs(&self.engine.command(&s.command)?, &s.result)?
            } else {
                vec![]
            };
            let outputs = self.engine.input_reader()?.resolve(&references)?;
            let signatures = s
                .signatures
                .iter()
                .map(|(key, signature)| V::Array(vec![b(key), b(signature)]))
                .collect();
            (
                b(&s.node),
                b(&wire::encode(&V::Array(vec![
                    V::Uint(0),
                    V::Uint(1),
                    b(&s.payload),
                    V::Array(signatures),
                ]))?),
                b(&s.result),
                outputs.value(),
            )
        } else {
            (V::Null, V::Null, V::Null, V::Array(vec![]))
        };
        wire::encode(&V::Array(vec![
            V::Uint(42),
            V::Uint(1),
            self.config().scope.value(),
            V::Uint(status),
            V::Uint(code),
            request.as_ref().map_or(V::Null, |d| b(d)),
            node,
            certificate,
            result,
            outputs,
        ]))
    }
}
fn reference(kind: u64, digest: Digest) -> Reference {
    Reference {
        kind,
        digest,
        signer: None,
    }
}
fn item(config: &Configuration, kind: u64, bytes: Vec<u8>) -> Result<Item> {
    Ok(Item {
        reference: reference(
            kind,
            if kind == 12 {
                Certificate::parse(config, &bytes)?.digest()
            } else {
                wire::digest(&bytes)
            },
        ),
        bytes,
    })
}

fn request_eligible_at(command: &[u8]) -> Result<u64> {
    let value = wire::decode(command)?;
    let fields = value.array(6)?;
    let (payload, _) = wire::envelope(fields[4].bytes()?, 1)?;
    let value = wire::decode(&payload)?;
    Ok(value.array(12)?[9]
        .uint()?
        .saturating_sub(crate::authority_governance::UNCERTAINTY_MS))
}

#[cfg(test)]
#[path = "ConsensusInspectionTests.rs"]
mod inspection_tests;
#[cfg(test)]
#[path = "ConsensusRuntimeTests.rs"]
pub(crate) mod tests;

fn diagnostic(stage: &str, view: u64, kind: u64, error: &anyhow::Error) {
    #[cfg(test)]
    {
        static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 96 {
            eprintln!("Replica {stage} refusal: view={view} message={kind} reason={error:#}");
        }
    }
    #[cfg(not(test))]
    let _ = (stage, view, kind, error);
}
