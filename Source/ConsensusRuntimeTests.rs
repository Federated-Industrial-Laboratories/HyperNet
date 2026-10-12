// SPDX-License-Identifier: MIT
use super::super::{
    journal::tests::Directory,
    records::tests::{fixture, initial},
    tests as fixtures,
};
use super::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest as ShaDigest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "ConsensusHistoryOvertakenTests.rs"]
mod history_overtaken;

struct ExampleApplication(Configuration);
impl Application for ExampleApplication {
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()> {
        ensure!(
            wire::decode(state)?.array(1)?[0].uint()? == height,
            "Checkpoint application height differs"
        );
        Ok(())
    }
    fn validate(&self, _: &[u8], command: &[u8], _: u64, inputs: &Resolved) -> Result<()> {
        ensure!(
            inputs.is_empty(),
            "example application has no immutable inputs"
        );
        super::super::records::Command::parse(&self.0, command)?;
        Ok(())
    }
    fn execute(&self, _: &[u8], committed: &Committed, inputs: &Resolved) -> Result<Execution> {
        ensure!(
            inputs.is_empty(),
            "example application has no immutable inputs"
        );
        Ok(fixtures::execution(&self.0, committed))
    }
}
struct CountedApplication {
    inner: ExampleApplication,
    validations: Arc<AtomicUsize>,
}
impl Application for CountedApplication {
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()> {
        self.inner.validate_checkpoint(state, height)
    }
    fn validate(&self, prior: &[u8], command: &[u8], at: u64, inputs: &Resolved) -> Result<()> {
        self.validations.fetch_add(1, Ordering::Relaxed);
        self.inner.validate(prior, command, at, inputs)
    }
    fn execute(&self, prior: &[u8], committed: &Committed, inputs: &Resolved) -> Result<Execution> {
        self.inner.execute(prior, committed, inputs)
    }
}
fn runtime_clock(directory: &Path) -> (PathBuf, u64) {
    let now = crate::consensus_clock::moment().unwrap();
    // Synthetic unit observation; this does not qualify the native NTS monitor.
    let witness = crate::consensus_clock::Witness {
        version: 1,
        kernel_boot: crate::consensus_clock::kernel_boot().unwrap(),
        sample_wall_ms: now.wall_ms,
        sample_boot_ms: now.boot_ms,
        valid_until_boot_ms: now.boot_ms + crate::consensus_clock::SAMPLE_LIFETIME_MS,
        maximum_error_ms: 1,
        source: "192.0.2.1".parse().unwrap(),
    };
    crate::authority_clock_handoff::publish_private(directory, &witness).unwrap();
    (directory.join("ClockHealth.json"), now.wall_ms)
}
fn runtime_peer_event(driver: &mut Driver, key: &SigningKey, message: &Message) -> u64 {
    let sender = key.verifying_key().to_bytes();
    // Encode directly so malformed nested evidence reaches the real decoder.
    let body = wire::sign_envelope(
        &wire::encode(&V::Array(vec![
            V::Uint(40),
            V::Uint(1),
            driver.config().scope.value(),
            V::Bytes(sender.to_vec()),
            V::Uint(message.number()),
            V::Bytes(message.payload().unwrap()),
        ]))
        .unwrap(),
        key,
    )
    .unwrap();
    let digest = wire::digest(&body);
    let (answer, mut response) = oneshot::channel();
    driver
        .event(Event::Peer {
            sender,
            body,
            answer,
            queued: Instant::now(),
        })
        .unwrap();
    let Message::Ack(returned, disposition) = peer::decode(
        driver.config(),
        driver.engine.signer(),
        &response.try_recv().unwrap(),
    )
    .unwrap() else {
        panic!("Expected a signed transport acknowledgement")
    };
    assert_eq!(returned, digest);
    disposition
}
pub(crate) fn config(clock: PathBuf, root: &Path, keys: &[SigningKey; 4]) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        peers: std::array::from_fn(|i| peer::Endpoint {
            key: keys[i].verifying_key().to_bytes(),
            origin: format!("https://127.0.0.1:{}/", 10000 + i),
            certificate_sha256: [i as u8 + 1; 32],
        }),
        tls: peer::Credentials {
            certificate: root.join("Certificate.pem"),
            private_key: root.join("Private.pem"),
            certificate_authority: root.join("Ca.pem"),
        },
        clock: crate::authority_clock_handoff::Source::Private { path: clock },
        control_socket: root.join("Control.sock"),
    }
}
fn repair_driver(
    engine: Engine,
    root: &Path,
    keys: &[SigningKey; 4],
    sender: Key,
    mailbox: ingress::Mailbox,
) -> Driver {
    let configuration = engine.configuration().clone();
    let view = engine.view();
    Driver {
        config: config(root.join("AbsentClock.json"), root, keys),
        engine,
        application: Arc::new(ExampleApplication(configuration)),
        senders: BTreeMap::from([(sender, mailbox)]),
        outbox: BTreeMap::new(),
        local: VecDeque::new(),
        requests: BTreeMap::new(),
        input_flight: None,
        input_waiting: BTreeMap::new(),
        query_times: BTreeMap::new(),
        diagnostics: diagnostics::Diagnostics::new().0,
        shares: BTreeMap::new(),
        repairs: BTreeMap::new(),
        pending_votes: BTreeMap::new(),
        checkpoint_votes: BTreeMap::new(),
        transfers: BTreeMap::new(),
        served_checkpoints: BTreeMap::new(),
        expires: view_deadline(view, Instant::now()).unwrap(),
        last_view: view,
        last_commit: 0,
        attempted_proposal: 0,
        blocked_application: None,
        application_ready: false,
        retransmit_cursor: 0,
    }
}
#[test]
fn missing_new_view_quorum_defers_validation_until_authenticated_report_arrives() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    for engine in &mut engines {
        for key in &keys[..3] {
            engine
                .receive_wish(&super::super::synchronizer::sign(&configuration, 1, key).unwrap())
                .unwrap();
        }
        assert_eq!(engine.view(), 1);
    }
    let reports: Vec<_> = engines
        .iter()
        .map(|engine| {
            engine.snapshot.reports[&super::super::report_id(1, &engine.signer())].clone()
        })
        .collect();
    let directory = Directory::new();
    let (clock, now) = runtime_clock(&directory.0);
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox,
    );
    driver.config.clock = crate::authority_clock_handoff::Source::Private { path: clock };
    let validations = Arc::new(AtomicUsize::new(0));
    driver.application = Arc::new(CountedApplication {
        inner: ExampleApplication(configuration.clone()),
        validations: validations.clone(),
    });
    let genesis = configuration.genesis_qc().unwrap();
    assert_eq!(
        runtime_peer_event(
            &mut driver,
            &keys[1],
            &Message::NewView(reports[1].clone(), genesis.bytes.clone())
        ),
        0
    );
    assert!(!driver.engine.has_new_view_quorum());
    let command = current_request(&configuration, 71, now - 1250);
    let request = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        configuration.scope.value(),
        V::Uint(0),
        V::Bytes(
            wire::encode(&V::Array(vec![V::Bytes(command.clone()), V::Array(vec![])])).unwrap(),
        ),
    ]))
    .unwrap();
    let (answer, mut response) = oneshot::channel();
    driver
        .event(Event::Local {
            body: request,
            answer,
            queued: Instant::now(),
        })
        .unwrap();
    assert_eq!(
        wire::decode(&response.try_recv().unwrap())
            .unwrap()
            .array(10)
            .unwrap()[3]
            .uint()
            .unwrap(),
        0
    );
    assert_eq!(
        validations.load(Ordering::Relaxed),
        1,
        "Only initial admission may validate before NewView quorum"
    );
    let baseline = driver.engine.generation();
    let ack = wire::sign_envelope(
        &peer::payload(
            &configuration,
            configuration.voters[1],
            &Message::Ack([1; 32], 0),
        )
        .unwrap(),
        &keys[1],
    )
    .unwrap();
    for _ in 0..32 {
        let (answer, response) = oneshot::channel();
        drop(response);
        driver
            .event(Event::Peer {
                sender: configuration.voters[1],
                body: ack.clone(),
                answer,
                queued: Instant::now(),
            })
            .unwrap();
    }
    // Non-ACK events also cannot start application work without the quorum.
    for _ in 0..4 {
        runtime_clock(&directory.0);
        assert_eq!(
            runtime_peer_event(&mut driver, &keys[1], &Message::Query([90; 32])),
            0
        );
    }
    assert_eq!(driver.engine.generation(), baseline);
    assert_eq!(validations.load(Ordering::Relaxed), 1);
    assert!(driver.engine.current_proposal().is_none());
    let future = NewView::sign(&configuration, 2, genesis.digest(), &keys[2]).unwrap();
    assert_eq!(
        runtime_peer_event(
            &mut driver,
            &keys[2],
            &Message::NewView(future.envelope, genesis.bytes.clone())
        ),
        2
    );
    let mut invalid = reports[2].clone();
    *invalid.last_mut().unwrap() ^= 1;
    assert_eq!(
        runtime_peer_event(
            &mut driver,
            &keys[2],
            &Message::NewView(invalid, genesis.bytes.clone())
        ),
        2
    );
    assert!(!driver.engine.has_new_view_quorum());
    assert_eq!(validations.load(Ordering::Relaxed), 1);
    runtime_clock(&directory.0);
    assert_eq!(
        runtime_peer_event(
            &mut driver,
            &keys[2],
            &Message::NewView(reports[2].clone(), genesis.bytes)
        ),
        0
    );
    assert!(driver.engine.has_new_view_quorum());
    let proposal = driver
        .engine
        .current_proposal()
        .expect("The third authenticated report enables proposal");
    let (body, _) = wire::envelope(proposal, 1).unwrap();
    assert_eq!(
        Node::parse(&configuration, &body).unwrap().command,
        Some(wire::digest(&command))
    );
    assert!(validations.load(Ordering::Relaxed) >= 2);

    // ACKs must not strand existing local work, including startup WISH delivery.
    driver.local.push_back(Message::Query([91; 32]));
    assert_eq!(
        runtime_peer_event(&mut driver, &keys[1], &Message::Ack([2; 32], 0)),
        0
    );
    assert!(driver.local.is_empty());
}

#[test]
fn quorum_ready_clock_tick_proposes_only_eligible_requests_and_rebroadcasts_durable_proposal() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let directory = Directory::new();
    let (clock, now) = runtime_clock(&directory.0);
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox,
    );
    driver.config.clock = crate::authority_clock_handoff::Source::Private { path: clock };
    let validations = Arc::new(AtomicUsize::new(0));
    driver.application = Arc::new(CountedApplication {
        inner: ExampleApplication(configuration.clone()),
        validations: validations.clone(),
    });
    let eligible = current_request(&configuration, 72, now);
    let future = current_request(&configuration, 73, now + 60000);
    for command in [eligible.clone(), future] {
        driver.requests.insert(
            wire::digest(&command),
            Submission {
                command,
                inputs: Resolved::default(),
            },
        );
    }
    // Neither request arrival nor a transport ACK is needed for clock eligibility.
    driver.tick().unwrap();
    assert_eq!(validations.load(Ordering::Relaxed), 1);
    let proposal = driver.engine.current_proposal().unwrap().to_vec();
    let (body, _) = wire::envelope(&proposal, 1).unwrap();
    assert_eq!(
        Node::parse(&configuration, &body).unwrap().command,
        Some(wire::digest(&eligible))
    );
    driver.outbox.clear();
    driver.attempted_proposal = 0;
    driver.config.clock = crate::authority_clock_handoff::Source::Private {
        path: directory.0.join("AbsentClock.json"),
    };
    driver.try_propose().unwrap();
    assert_eq!(validations.load(Ordering::Relaxed), 1);
    assert!(driver.outbox.values().any(
        |(_, message, _)| matches!(message, Message::Proposal(bytes, ..) if bytes == &proposal)
    ));
}
#[test]
fn committed_unapplied_requests_stop_gossip_without_consuming_alternatives() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let command = fixtures::request(&configuration, 71);
    let digest = wire::digest(&command);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let commit = fixtures::phases(&configuration, &mut engines, &command);
    for engine in &mut engines {
        engine.decide(&commit.bytes).unwrap();
    }
    fixtures::enter(&configuration, &keys, &mut engines, 5);
    let following = fixtures::request(&configuration, 69);
    let following_digest = wire::digest(&following);
    let commit = fixtures::phases(&configuration, &mut engines, &following);
    for engine in &mut engines {
        engine.decide(&commit.bytes).unwrap();
    }
    // A known successor with a prepared quorum is still speculative until its
    // CommitQC is accepted. It cannot suppress that command's submission.
    fixtures::enter(&configuration, &keys, &mut engines, 9);
    let speculative = fixtures::request(&configuration, 72);
    let speculative_commit = fixtures::phases(&configuration, &mut engines, &speculative);
    let speculative_digest = wire::digest(&speculative);
    let refreshed = wire::decode(&current_request(&configuration, 71, 10001)).unwrap();
    let mut refreshed = refreshed.array(6).unwrap().to_vec();
    let (challenge, _) = wire::envelope(refreshed[4].bytes().unwrap(), 1).unwrap();
    let challenge = wire::decode(&challenge).unwrap();
    let mut challenge = challenge.array(12).unwrap().to_vec();
    challenge[6] = V::Bytes(vec![199; 32]);
    refreshed[4] = V::Bytes(
        wire::sign_envelope(
            &wire::encode(&V::Array(challenge)).unwrap(),
            &SigningKey::from_bytes(&[31; 32]),
        )
        .unwrap(),
    );
    let fresh = wire::encode(&V::Array(refreshed)).unwrap();
    let fresh_digest = wire::digest(&fresh);
    let original = OrderedRequest::parse(&configuration, &command).unwrap();
    let refreshed = OrderedRequest::parse(&configuration, &fresh).unwrap();
    assert_eq!(original.intent, refreshed.intent);
    assert_ne!(original.challenge, refreshed.challenge);
    assert_ne!(digest, fresh_digest);
    let directory = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox.clone(),
    );
    assert_eq!(driver.engine.applied().unwrap().height, 0);
    assert_eq!(driver.engine.committed().unwrap().height, 2);
    assert_eq!(
        driver
            .engine
            .known_node(&speculative_commit.node)
            .unwrap()
            .command,
        Some(speculative_digest)
    );
    assert_eq!(
        driver.engine.unapplied_commands().unwrap(),
        std::collections::BTreeSet::from([digest, following_digest])
    );
    let empty = wire::encode(&Resolved::default().value()).unwrap();
    for bytes in [&command, &following, &fresh, &speculative] {
        driver.requests.insert(
            wire::digest(bytes),
            Submission {
                command: bytes.clone(),
                inputs: Resolved::default(),
            },
        );
        driver
            .send(
                configuration.voters[1],
                &Message::Submit(bytes.clone(), empty.clone()),
            )
            .unwrap();
    }
    let drain_submissions = || {
        let mut submissions = std::collections::BTreeSet::new();
        while let Some(bytes) = mailbox.try_pop().unwrap() {
            if let Message::Submit(command, _) =
                peer::decode(&configuration, configuration.voters[0], &bytes).unwrap()
            {
                submissions.insert(wire::digest(&command));
            }
        }
        submissions
    };
    let alternatives = std::collections::BTreeSet::from([fresh_digest, speculative_digest]);
    driver.try_propose().unwrap();
    assert_eq!(
        driver
            .requests
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        alternatives
    );
    assert_eq!(drain_submissions(), alternatives);
    // Repeated peer and local submissions return pending results without
    // requiring a new clock observation or retransmitting a decided command.
    driver
        .receive(
            configuration.voters[1],
            Message::Submit(command.clone(), empty),
        )
        .unwrap();
    let request = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        configuration.scope.value(),
        V::Uint(0),
        V::Bytes(
            Submission {
                command: command.clone(),
                inputs: Resolved::default(),
            }
            .encode()
            .unwrap(),
        ),
    ]))
    .unwrap();
    let reply = wire::decode(&driver.local_checked(&request).unwrap()).unwrap();
    assert_eq!(reply.array(10).unwrap()[3].uint().unwrap(), 0);
    assert!(!driver.requests.contains_key(&digest));
    assert!(drain_submissions().is_empty());
    driver.tick().unwrap();
    assert_eq!(drain_submissions(), alternatives);
    // Discovery remains a separate bounded turn; voting progression and the
    // remaining requests do not wait for application to finish.
    assert_eq!(driver.engine.applied().unwrap().height, 0);
    assert!(
        driver
            .local
            .iter()
            .any(|message| matches!(message, Message::Wish(_)))
    );
    assert_eq!(
        driver
            .requests
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        alternatives
    );
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 1);
    assert_eq!(
        driver.engine.unapplied_commands().unwrap(),
        std::collections::BTreeSet::from([following_digest])
    );
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 2);
    assert!(driver.engine.unapplied_commands().unwrap().is_empty());
}

#[test]
fn committed_application_cursor_remains_ready_without_a_retry_tick() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let command = fixtures::request(&configuration, 73);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let commit = fixtures::phases(&configuration, &mut engines, &command);
    let mut engine = engines.remove(0);
    engine.decide(&commit.bytes).unwrap();
    let directory = Directory::new();
    let mut driver = repair_driver(
        engine,
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 0);
    assert!(driver.application_ready);
    // The cooperative branch can finish the next bounded turn without gossip,
    // an additional peer message or advancing any clock.
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 1);
    assert!(driver.application_ready);
    driver.apply().unwrap();
    assert!(!driver.application_ready);
}

#[test]
fn early_execution_shares_recover_by_query_after_committed_request_suppression() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let command = fixtures::request(&configuration, 70);
    let digest = wire::digest(&command);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let commit = fixtures::phases(&configuration, &mut engines, &command);
    for (i, engine) in engines.iter_mut().enumerate() {
        engine.decide(&commit.bytes).unwrap();
        if i > 0 {
            engine
                .apply_committed(|_, c| Ok(fixtures::execution(&configuration, c)))
                .unwrap();
        }
    }
    let directory = Directory::new();
    let requests = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        requests.clone(),
    );
    driver.requests.insert(
        digest,
        Submission {
            command: command.clone(),
            inputs: Resolved::default(),
        },
    );
    for engine in &engines[..2] {
        let node = engine.applied().unwrap();
        let execution = engine.execution(node.digest().unwrap()).unwrap().unwrap();
        driver
            .collect_share(
                node.encode().unwrap(),
                execution.attestation,
                execution.result,
            )
            .unwrap();
    }
    assert!(driver.shares.is_empty());
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 0);
    assert!(!driver.requests.contains_key(&digest));
    driver.apply().unwrap();
    assert_eq!(driver.engine.applied().unwrap().height, 1);
    let pending = wire::decode(&driver.result(digest).unwrap()).unwrap();
    assert_eq!(pending.array(10).unwrap()[3].uint().unwrap(), 0);
    let mut query = None;
    while let Some(bytes) = requests.try_pop().unwrap() {
        match peer::decode(&configuration, configuration.voters[0], &bytes).unwrap() {
            message @ Message::Query(value) if value == digest => query = Some(message),
            Message::Submit(..) => panic!("committed request was retransmitted"),
            _ => {}
        }
    }
    let query = query.expect("missing normal execution query");
    for engine in engines.into_iter().take(2) {
        let signer = engine.signer();
        let responses = ingress::Mailbox::new();
        let mut source = repair_driver(
            engine,
            &directory.0,
            &keys,
            configuration.voters[0],
            responses.clone(),
        );
        source
            .receive(configuration.voters[0], query.clone())
            .unwrap();
        let mut delivered = false;
        while let Some(bytes) = responses.try_pop().unwrap() {
            if let message @ Message::Execution(..) =
                peer::decode(&configuration, signer, &bytes).unwrap()
            {
                driver.receive(signer, message).unwrap();
                delivered = true;
            }
        }
        assert!(
            delivered,
            "query did not regenerate the durable execution share"
        );
    }
    let completed = wire::decode(&driver.result(digest).unwrap()).unwrap();
    let fields = completed.array(10).unwrap();
    assert_eq!(fields[3].uint().unwrap(), 1);
    assert_eq!(fields[5].fixed::<32>().unwrap(), digest);
    assert_eq!(
        Node::parse(&configuration, fields[6].bytes().unwrap())
            .unwrap()
            .height,
        1
    );
    assert_eq!(
        wire::envelope(fields[7].bytes().unwrap(), 4)
            .unwrap()
            .1
            .len(),
        3
    );
    assert!(driver.requests.is_empty());
}

#[test]
fn repeated_result_polls_do_not_amplify_queries_or_delay_a_complete_proof() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let command = fixtures::request(&configuration, 73);
    let commit = fixtures::phases(&configuration, &mut engines[..3], &command);
    // Every result share comes from the same normally committed execution.
    for engine in &mut engines[..3] {
        engine.decide(&commit.bytes).unwrap();
        engine
            .apply_committed(|_, c| Ok(fixtures::execution(&configuration, c)))
            .unwrap();
    }
    let engine = engines.remove(0);
    let directory = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engine,
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox.clone(),
    );
    let digest = wire::digest(&command);
    let now = Instant::now();
    let generation = driver.engine.generation();
    let first = wire::decode(&driver.result_at(digest, now).unwrap()).unwrap();
    assert_eq!(first.array(10).unwrap()[3].uint().unwrap(), 0);
    let query = mailbox.try_pop().unwrap().unwrap();
    assert!(
        matches!(peer::decode(&configuration, driver.engine.signer(), &query).unwrap(), Message::Query(value) if value == digest)
    );
    // Drain each time: outbound queue deduplication cannot hide repeated sends.
    for _ in 0..100 {
        driver
            .result_at(digest, now + Duration::from_millis(1))
            .unwrap();
        assert!(mailbox.try_pop().unwrap().is_none());
    }
    for engine in &engines[..2] {
        let node = engine.applied().unwrap();
        let execution = engine.execution(node.digest().unwrap()).unwrap().unwrap();
        driver
            .collect_share(
                node.encode().unwrap(),
                execution.attestation,
                execution.result,
            )
            .unwrap();
    }
    let completed = wire::decode(
        &driver
            .result_at(digest, now + Duration::from_millis(2))
            .unwrap(),
    )
    .unwrap();
    let reply = completed.array(10).unwrap();
    assert_eq!(reply[3].uint().unwrap(), 1);
    assert_eq!(
        wire::envelope(reply[7].bytes().unwrap(), 4)
            .unwrap()
            .1
            .len(),
        3
    );
    assert_eq!(reply[5].fixed::<32>().unwrap(), digest);
    assert_eq!(driver.query_times.len(), 1);
    assert!(mailbox.try_pop().unwrap().is_none());
    assert_eq!(driver.engine.generation(), generation);
}

#[test]
fn duplicate_request_executions_collect_independent_quorums_in_either_arrival_order() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let command = fixtures::request(&configuration, 74);
    let digest = wire::digest(&command);
    let mut executions = Vec::new();
    // Both positions are reached through ordinary leader, phase and apply handlers.
    for view in [1, 5] {
        fixtures::enter(&configuration, &keys, &mut engines, view);
        let commit = fixtures::phases(&configuration, &mut engines, &command);
        for engine in &mut engines {
            engine.decide(&commit.bytes).unwrap();
            engine
                .apply_committed(|_, c| Ok(fixtures::execution(&configuration, c)))
                .unwrap();
        }
        let node = engines[0].applied().unwrap();
        let records: Vec<_> = engines
            .iter()
            .map(|engine| engine.execution(node.digest().unwrap()).unwrap().unwrap())
            .collect();
        executions.push((node, records));
    }
    assert_eq!(executions[0].0.height, 1);
    assert_eq!(executions[1].0.height, 2);
    assert_ne!(executions[0].1[0].result, executions[1].1[0].result);
    for engine in &engines {
        let (node, record) = engine.executed_request(digest).unwrap().unwrap();
        assert_eq!(node.digest().unwrap(), executions[1].0.digest().unwrap());
        assert_eq!(record.result, executions[1].1[0].result);
    }
    let directory = Directory::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let generation = driver.engine.generation();
    let deliver = |driver: &mut Driver, position: usize, signer: usize| {
        let (node, records) = &executions[position];
        driver
            .collect_share(
                node.encode().unwrap(),
                records[signer].attestation.clone(),
                records[signer].result.clone(),
            )
            .unwrap();
    };
    let assert_complete = |reply: Vec<u8>, position: usize| {
        let decoded = wire::decode(&reply).unwrap();
        let fields = decoded.array(10).unwrap();
        assert_eq!(fields[3].uint().unwrap(), 1);
        assert_eq!(fields[4].uint().unwrap(), 0);
        assert_eq!(fields[5].fixed::<32>().unwrap(), digest);
        assert_eq!(
            fields[6].bytes().unwrap(),
            executions[position].0.encode().unwrap()
        );
        assert_eq!(fields[8].bytes().unwrap(), executions[position].1[0].result);
        let (payload, signatures) = wire::envelope(fields[7].bytes().unwrap(), 4).unwrap();
        assert_eq!(signatures.len(), 3);
        for (key, _) in signatures {
            configuration.member(&key).unwrap();
        }
        let expected = wire::envelope(&executions[position].1[0].attestation, 1)
            .unwrap()
            .0;
        assert_eq!(payload, expected);
    };
    for order in [[0, 1], [1, 0]] {
        driver.shares.clear();
        for position in order {
            deliver(&mut driver, position, position + 1);
        }
        // Own+peer1 on the older node and own+peer2 on the newer node
        // contain three distinct signers, but neither node has a quorum.
        assert_eq!(driver.shares.len(), 2);
        assert!(driver.shares.values().all(|s| s.signatures.len() == 2));
        let pending = wire::decode(&driver.result(digest).unwrap()).unwrap();
        assert_eq!(pending.array(10).unwrap()[3].uint().unwrap(), 0);
        assert!(
            driver
                .collect_share(
                    executions[0].0.encode().unwrap(),
                    executions[1].1[2].attestation.clone(),
                    executions[0].1[2].result.clone(),
                )
                .is_err()
        );
        assert!(driver.shares.values().all(|s| s.signatures.len() == 2));
        // An incomplete newer execution must not hide a complete older one.
        deliver(&mut driver, 0, 2);
        assert_complete(driver.result(digest).unwrap(), 0);
        deliver(&mut driver, 1, 1);
        assert_complete(driver.result(digest).unwrap(), 1);
        // A late older share cannot change deterministic newest-complete selection.
        deliver(&mut driver, 0, 1);
        assert_complete(driver.result(digest).unwrap(), 1);
        assert_eq!(driver.shares.len(), 2);
    }
    assert_eq!(driver.engine.generation(), generation);
}

#[test]
fn pending_query_flood_is_bounded_and_exact_queries_retry_after_interval() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let directory = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox.clone(),
    );
    let generation = driver.engine.generation();
    let now = Instant::now();
    for serial in 0..MAX_PENDING + 100 {
        let digest = wire::digest(&(serial as u64).to_be_bytes());
        let reply = wire::decode(&driver.result_at(digest, now).unwrap()).unwrap();
        assert_eq!(reply.array(10).unwrap()[3].uint().unwrap(), 0);
        assert_eq!(mailbox.try_pop().unwrap().is_some(), serial < MAX_PENDING);
        assert!(driver.query_times.len() <= MAX_PENDING);
    }
    let original = wire::digest(&0u64.to_be_bytes());
    driver
        .result_at(original, now + RETRANSMIT - Duration::from_nanos(1))
        .unwrap();
    assert!(mailbox.try_pop().unwrap().is_none());
    driver.result_at(original, now + RETRANSMIT).unwrap();
    let bytes = mailbox.try_pop().unwrap().unwrap();
    assert!(
        matches!(peer::decode(&configuration, driver.engine.signer(), &bytes).unwrap(), Message::Query(value) if value == original)
    );
    assert_eq!(driver.query_times.len(), 1);
    let previously_refused = wire::digest(&(MAX_PENDING as u64).to_be_bytes());
    driver
        .result_at(previously_refused, now + RETRANSMIT)
        .unwrap();
    assert!(mailbox.try_pop().unwrap().is_some());
    assert_eq!(driver.query_times.len(), 2);
    assert_eq!(driver.engine.generation(), generation);
}

#[test]
fn peer_records_bind_tls_identity_type_scope_and_requested_references() {
    let (configuration, keys) = fixture();
    let command = fixtures::request(&configuration, 70);
    let message = Message::Submit(command, wire::encode(&V::Array(vec![])).unwrap());
    let payload =
        peer::payload(&configuration, keys[0].verifying_key().to_bytes(), &message).unwrap();
    let signed = wire::sign_envelope(&payload, &keys[0]).unwrap();
    assert!(matches!(
        peer::decode(&configuration, keys[0].verifying_key().to_bytes(), &signed).unwrap(),
        Message::Submit(..)
    ));
    assert!(peer::decode(&configuration, keys[1].verifying_key().to_bytes(), &signed).is_err());
    let reference = reference(14, [1; 32]);
    assert!(
        peer::payload(
            &configuration,
            keys[0].verifying_key().to_bytes(),
            &Message::RepairRequest([2; 32], vec![reference.clone(), reference])
        )
        .is_err()
    );
    assert!(
        peer::payload(
            &configuration,
            keys[0].verifying_key().to_bytes(),
            &Message::Ack([1; 32], 3)
        )
        .is_err()
    );
    let mut wrong = configuration.clone();
    wrong.scope.incarnation = [200; 32];
    assert!(peer::decode(&wrong, keys[0].verifying_key().to_bytes(), &signed).is_err());
    assert!(
        peer::Message::parse(
            &configuration,
            11,
            &wire::encode(&V::Array(vec![])).unwrap()
        )
        .is_err()
    );
}
#[tokio::test]
async fn missing_decision_dependencies_are_requested_and_verified_before_apply() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let commit = fixtures::phases(
        &configuration,
        &mut engines[..3],
        &fixtures::request(&configuration, 72),
    );
    engines[0].decide(&commit.bytes).unwrap();
    engines[0]
        .apply_committed(|_, c| Ok(fixtures::execution(&configuration, c)))
        .unwrap();
    let engine = engines.pop().unwrap();
    let temp = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engine,
        &temp.0,
        &keys,
        configuration.voters[0],
        mailbox.clone(),
    );
    let initial_generation = driver.engine.generation();
    let committed_vote = commit.vote.as_ref().unwrap();
    for key in &keys[..3] {
        let vote = SignedVote::sign(&configuration, committed_vote.clone(), key).unwrap();
        driver
            .receive(configuration.voters[0], Message::Vote(vote.envelope))
            .unwrap();
        assert_eq!(driver.engine.generation(), initial_generation);
        assert_eq!(driver.engine.snapshot.nodes.len(), 1);
    }

    assert_eq!(driver.engine.applied().unwrap().height, 0);
    assert!(
        driver
            .receive(
                configuration.voters[0],
                Message::RepairResponse([88; 32], vec![])
            )
            .is_err()
    );
    for _ in 0..16 {
        driver.apply().unwrap();
        if driver.engine.applied().unwrap().height == 1 {
            break;
        }
        let bytes = mailbox.try_pop().unwrap().unwrap();
        if let Message::RepairRequest(id, refs) =
            peer::decode(&configuration, driver.engine.signer(), &bytes).unwrap()
        {
            let items = engines[0].repair_export(&refs).unwrap();
            let response = Message::RepairResponse(id, items);
            let checked = peer::Message::parse(
                &configuration,
                response.number(),
                &response.payload().unwrap(),
            )
            .unwrap();
            driver.receive(configuration.voters[0], checked).unwrap();
        }
    }
    assert_eq!(driver.engine.applied().unwrap().height, 1);
    assert!(
        driver
            .engine
            .execution(driver.engine.applied().unwrap().digest().unwrap())
            .unwrap()
            .is_some()
    );
    assert!(driver.now().is_err());
    let floor = configuration.genesis().digest().unwrap();
    let target = driver.engine.applied().unwrap().digest().unwrap();
    let generation = driver.engine.generation();
    let chain = driver.engine.ancestry(0, floor, target).unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(
        Node::parse(&configuration, &chain[0]).unwrap().parent,
        Some(floor)
    );
    assert!(driver.engine.ancestry(1, floor, target).is_err());
    assert!(driver.engine.ancestry(1, target, floor).is_err());
    let request = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        configuration.scope.value(),
        V::Uint(3),
        V::Bytes(
            wire::encode(&V::Array(vec![
                V::Uint(0),
                V::Bytes(floor.to_vec()),
                V::Bytes(target.to_vec()),
            ]))
            .unwrap(),
        ),
    ]))
    .unwrap();
    let response = wire::decode(&driver.local_request(&request)).unwrap();
    assert_eq!(response.array(4).unwrap()[0], V::Uint(43));
    assert_eq!(response.array(4).unwrap()[3].list(128).unwrap().len(), 1);
    assert_eq!(driver.engine.generation(), generation);
    while mailbox.try_pop().unwrap().is_some() {}
    driver
        .receive(
            configuration.voters[0],
            Message::Query(wire::digest(&fixtures::request(&configuration, 72))),
        )
        .unwrap();
    let mut certificate = false;
    let mut execution = false;
    while let Some(body) = mailbox.try_pop().unwrap() {
        match peer::decode(&configuration, driver.engine.signer(), &body).unwrap() {
            Message::Certificate(bytes) => {
                let qc = Certificate::parse(&configuration, &bytes).unwrap();
                assert_eq!(qc.phase, Phase::Commit);
                assert_eq!(qc.node, driver.engine.applied().unwrap().digest().unwrap());
                certificate = true;
            }
            Message::Execution(..) => execution = true,
            _ => panic!("Unexpected result-query response"),
        }
    }
    assert!(certificate && execution);
}
#[test]
fn byzantine_unsigned_dependencies_cannot_fill_history_before_honest_progress() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let engine = engines.remove(2);
    let temp = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let byzantine = configuration.voters[3];
    let mut driver = repair_driver(engine, &temp.0, &keys, byzantine, mailbox);
    let baseline = driver.engine.generation();
    let command = fixtures::request(&configuration, 90);
    let genesis = configuration.genesis().digest().unwrap();
    let justify = configuration.genesis_qc().unwrap();
    for i in 0..(super::super::MAX_NODES + 8) {
        let node = Node {
            scope: configuration.scope.clone(),
            view: 1,
            height: 1,
            parent: Some(genesis),
            command: Some(wire::digest(&command)),
            evaluated_at: 20000 + i as u64,
            justify: Some(justify.digest()),
        };
        let vote = SignedVote::sign(
            &configuration,
            super::super::records::Vote {
                scope: configuration.scope.clone(),
                view: 1,
                phase: Phase::Prepare,
                node: node.digest().unwrap(),
            },
            &keys[3],
        )
        .unwrap();
        let _ = driver.receive(byzantine, Message::Vote(vote.envelope));
        let execution = fixtures::execution(
            &configuration,
            &Committed {
                node: node.digest().unwrap(),
                height: 1,

                evaluated_at: node.evaluated_at,
                command: command.clone(),
            },
        );
        let super::super::ExecutionOutput::Result {
            result,
            attestation,
        } = execution.output
        else {
            panic!("Expected result")
        };
        let message = Message::Execution(
            node.encode().unwrap(),
            wire::sign_envelope(&attestation, &keys[3]).unwrap(),
            result,
        );
        let message = peer::Message::parse(
            &configuration,
            message.number(),
            &message.payload().unwrap(),
        )
        .unwrap();
        driver.receive(byzantine, message).unwrap();
        assert_eq!(driver.engine.generation(), baseline);
        assert_eq!(driver.engine.snapshot.nodes.len(), 1);
        assert!(driver.engine.snapshot.commands.is_empty());
        assert!(driver.repairs.is_empty());
        assert!(driver.pending_votes.len() <= 1);
    }
    // Even the designated leader cannot publish a stream of commands before
    // the normal Prepare admission (including the real clock check) succeeds.
    for serial in 1..=32 {
        let command = fixtures::request(&configuration, serial);
        let node = Node {
            scope: configuration.scope.clone(),
            view: 1,
            height: 1,
            parent: Some(genesis),
            command: Some(wire::digest(&command)),
            evaluated_at: 10000,
            justify: Some(justify.digest()),
        };
        let message = Message::Proposal(
            wire::sign_envelope(&node.encode().unwrap(), &keys[0]).unwrap(),
            command,
            justify.bytes.clone(),
            wire::encode(&V::Array(vec![])).unwrap(),
        );
        let message = peer::Message::parse(
            &configuration,
            message.number(),
            &message.payload().unwrap(),
        )
        .unwrap();
        assert!(driver.receive(configuration.voters[0], message).is_err());
        assert_eq!(driver.engine.generation(), baseline);
        assert!(driver.engine.snapshot.commands.is_empty());
    }
    // Three honest signers still complete the ordinary phases after the attack.
    let proposal = engines[0].propose(&command, 10000).unwrap();
    let mut honest = [&mut engines[..2], std::slice::from_mut(&mut driver.engine)];
    let mut votes = Vec::new();
    for group in &mut honest {
        for engine in group.iter_mut() {
            votes.push(
                SignedVote::parse(
                    &configuration,
                    &engine
                        .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                        .unwrap(),
                )
                .unwrap(),
            );
        }
    }
    let mut qc = Certificate::collect(&configuration, &votes).unwrap();
    for _ in 0..2 {
        votes.clear();
        for group in &mut honest {
            for engine in group.iter_mut() {
                votes.push(
                    SignedVote::parse(&configuration, &engine.advance_phase(&qc.bytes).unwrap())
                        .unwrap(),
                );
            }
        }
        qc = Certificate::collect(&configuration, &votes).unwrap();
    }
    driver
        .receive(configuration.voters[0], Message::Certificate(qc.bytes))
        .unwrap();
    for _ in 0..4 {
        if driver.engine.applied().unwrap().height == 1 {
            break;
        }
        driver.apply().unwrap();
    }
    assert_eq!(driver.engine.applied().unwrap().height, 1);
}

#[test]
fn live_status_reports_local_progress_without_signing_or_peer_queries() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let command = fixtures::request(&configuration, 73);
    let commit = fixtures::phases(&configuration, &mut engines[..3], &command);
    engines[0].decide(&commit.bytes).unwrap();
    engines[0]
        .apply_committed(|_, c| Ok(fixtures::execution(&configuration, c)))
        .unwrap();
    let directory = Directory::new();
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox.clone(),
    );
    let generation = driver.engine.generation();
    let mut request = vec![
        V::Uint(41),
        V::Uint(1),
        configuration.scope.value(),
        V::Uint(5),
        V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
    ];
    let reply = driver
        .local_checked(&wire::encode(&V::Array(request.clone())).unwrap())
        .unwrap();
    assert_eq!(
        wire::decode(&reply).unwrap(),
        V::Array(vec![
            V::Uint(59),
            V::Uint(1),
            configuration.scope.value(),
            V::Bytes(driver.engine.signer().to_vec()),
            V::Uint(generation),
            V::Uint(driver.engine.view()),
            V::Uint(1),
            V::Uint(1),
            V::Bool(false),
        ])
    );
    request[4] = V::Bytes(wire::encode(&V::Array(vec![V::Uint(0)])).unwrap());
    assert!(
        driver
            .local_checked(&wire::encode(&V::Array(request.clone())).unwrap())
            .is_err()
    );
    request[4] = V::Bytes(wire::encode(&V::Array(vec![])).unwrap());
    let mut wrong_scope = configuration.scope.clone();
    wrong_scope.network[0] ^= 1;
    request[2] = wrong_scope.value();
    assert!(
        driver
            .local_checked(&wire::encode(&V::Array(request)).unwrap())
            .is_err()
    );
    assert_eq!(driver.engine.generation(), generation);
    assert!(mailbox.try_pop().unwrap().is_none());
    assert!(driver.query_times.is_empty());
    assert!(driver.outbox.is_empty());
}

#[tokio::test]
async fn local_socket_is_private_and_reconciles_only_its_stale_inode() {
    let directory = Directory::new();
    let path = directory.0.join("Control.sock");
    let (socket, guard) = ingress::local_socket(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(ingress::local_socket(&path).is_err());
    drop(socket);
    drop(guard);
    assert!(!path.exists());
    std::fs::write(&path, b"unrelated").unwrap();
    assert!(ingress::local_socket(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"unrelated");
}
fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("/usr/bin/openssl")
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Bounded fixture certificate issuance failed"
    );
}
pub(crate) fn certificates(
    root: &Path,
    keys: &[SigningKey; 4],
) -> ([peer::Endpoint; 4], Vec<peer::Credentials>, Vec<SocketAddr>) {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "CaKey.pem",
            "-out",
            "Ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=HyperNetTestCA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
    let mut credentials = Vec::new();
    let mut addresses = Vec::new();
    let mut endpoints = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let private = format!("Peer{i}Key.pem");
        let request = format!("Peer{i}.csr");
        let certificate = format!("Peer{i}.pem");
        let extensions = format!("Peer{i}.txt");
        std::fs::write(root.join(&extensions), b"subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n").unwrap();
        openssl(
            root,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &private,
                "-out",
                &request,
                "-subj",
                "/CN=HyperNetTestPeer",
            ],
        );
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &request,
                "-CA",
                "Ca.pem",
                "-CAkey",
                "CaKey.pem",
                "-set_serial",
                &(i + 1).to_string(),
                "-out",
                &certificate,
                "-days",
                "1",
                "-extfile",
                &extensions,
            ],
        );
        std::fs::set_permissions(root.join(&private), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let cert = CertificateDer::from_pem_slice(&std::fs::read(root.join(&certificate)).unwrap())
            .unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        endpoints.push(peer::Endpoint {
            key: key.verifying_key().to_bytes(),
            origin: format!("https://{address}/"),
            certificate_sha256: Sha256::digest(cert.as_ref()).into(),
        });
        addresses.push(address);
        credentials.push(peer::Credentials {
            certificate: root.join(certificate),
            private_key: root.join(private),
            certificate_authority: root.join("Ca.pem"),
        });
    }
    (endpoints.try_into().unwrap(), credentials, addresses)
}
fn current_request(configuration: &Configuration, serial: u8, now: u64) -> Vec<u8> {
    let old = wire::decode(&fixtures::request(configuration, serial)).unwrap();
    let mut fields = old.array(6).unwrap().to_vec();
    let (challenge, _) = wire::envelope(fields[4].bytes().unwrap(), 1).unwrap();
    let challenge = wire::decode(&challenge).unwrap();
    let mut challenge = challenge.array(12).unwrap().to_vec();
    challenge[9] = V::Uint(now);
    challenge[10] = V::Uint(now + 5000);
    fields[4] = V::Bytes(
        wire::sign_envelope(
            &wire::encode(&V::Array(challenge)).unwrap(),
            &SigningKey::from_bytes(&[31; 32]),
        )
        .unwrap(),
    );
    fields[5] = V::Uint(now + 5000);
    wire::encode(&V::Array(fields)).unwrap()
}
async fn local(
    path: &Path,
    configuration: &Configuration,
    operation: u64,
    payload: Vec<u8>,
) -> Result<Vec<V>> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    let payload = if operation == 0 {
        wire::encode(&V::Array(vec![V::Bytes(payload), V::Array(vec![])]))?
    } else {
        payload
    };
    let bytes = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        configuration.scope.value(),
        V::Uint(operation),
        V::Bytes(payload),
    ]))?;
    stream.write_u32(bytes.len().try_into()?).await?;
    stream.write_all(&bytes).await?;
    let length = stream.read_u32().await? as usize;
    ensure!(length <= wire::MAXIMUM, "Local reply bound");
    let mut reply = vec![0; length];
    stream.read_exact(&mut reply).await?;
    let reply = wire::decode(&reply)?;
    Ok(super::super::records::record(&reply, 42, 10)?.to_vec())
}
async fn certified(path: &Path, configuration: &Configuration, command: &[u8]) -> Result<Vec<V>> {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let reply = local(path, configuration, 1, wire::digest(command).to_vec()).await?;
            if reply[3].uint()? == 1 {
                let (payload, signatures) = wire::envelope(reply[7].bytes()?, 4)?;
                ensure!(signatures.len() >= 3, "Missing executed-result quorum");
                for (key, _) in signatures {
                    configuration.member(&key)?;
                }
                let value = wire::decode(&payload)?;
                let fields = value.array(23)?;
                ensure!(
                    fields[5].fixed::<32>()? == wire::digest(command)
                        && fields[15].fixed::<32>()? == wire::digest(reply[8].bytes()?),
                    "Certified reply identity differs"
                );
                return Ok(reply);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires a live normally produced NTS clock witness; run explicitly for native qualification"]
async fn four_tls_replicas_recover_results() {
    let clock = PathBuf::from(
        std::env::var("HYPERNET_TEST_CLOCK_WITNESS")
            .expect("HYPERNET_TEST_CLOCK_WITNESS is a required native prerequisite"),
    );
    crate::authority_clock_monitor::health(&clock)
        .unwrap()
        .observe()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        let (configuration, keys) = fixture();
        let root = Directory::new();
        let (peers, credentials, addresses) = certificates(&root.0, &keys);
        let directories: Vec<_> = (0..4).map(|_| Directory::new()).collect();
        let mut configs = Vec::new();
        let mut stops = Vec::new();
        let mut tasks = Vec::new();
        for i in 0..4 {
            let mut runtime = config(clock.clone(), &directories[i].0, &keys);
            runtime.peers = peers.clone();
            runtime.tls = credentials[i].clone();
            runtime.listen = addresses[i];
            let engine = Engine::create(
                &directories[i].0,
                configuration.clone(),
                keys[i].clone(),
                initial(),
            )
            .unwrap();
            let (stop, receiver) = watch::channel(false);
            tasks.push(tokio::spawn(serve(
                runtime.clone(),
                engine,
                Arc::new(ExampleApplication(configuration.clone())),
                receiver,
            )));
            configs.push(runtime);
            stops.push(stop);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // A CA-valid leaf with another replica's pin must fail during the handshake.
        let mut wrong = peers.clone();
        wrong[1].certificate_sha256 = [200; 32];
        let transport = peer::transport(
            &configuration,
            configuration.voters[0],
            &wrong,
            &credentials[0],
        )
        .unwrap();
        let (_, url, client) = &transport.clients[1];
        assert!(
            client
                .post(url)
                .header("content-type", "application/cbor")
                .body(vec![0])
                .send()
                .await
                .is_err()
        );
        let now = crate::authority_clock_monitor::health(&clock)
            .unwrap()
            .observe()
            .unwrap()
            .wall_ms;
        let command = current_request(&configuration, 80, now);
        let reply = local(
            &configs[0].control_socket,
            &configuration,
            0,
            command.clone(),
        )
        .await
        .unwrap();
        assert_eq!(reply[3].uint().unwrap(), 0);
        // The initiating replica's reply is discarded; another eligible replica supplies proof.
        let first = certified(&configs[2].control_socket, &configuration, &command)
            .await
            .unwrap();
        let again = local(
            &configs[3].control_socket,
            &configuration,
            0,
            command.clone(),
        )
        .await
        .unwrap();
        assert!(again[3].uint().unwrap() <= 1);
        let replay = certified(&configs[3].control_socket, &configuration, &command)
            .await
            .unwrap();
        assert_eq!(first[6], replay[6]);
        assert_eq!(first[8], replay[8]);
        // Losing the next designated leader still leaves three independent replicas.
        stops[1].send(true).unwrap();
        let removed = tasks.remove(1);
        removed.await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let now = crate::authority_clock_monitor::health(&clock)
            .unwrap()
            .observe()
            .unwrap()
            .wall_ms;
        let next = current_request(&configuration, 81, now);
        local(&configs[2].control_socket, &configuration, 0, next.clone())
            .await
            .unwrap();
        certified(&configs[3].control_socket, &configuration, &next)
            .await
            .unwrap();
        // The stopped replica retains its signer journal and repairs the missed executed prefix.
        let engine =
            Engine::open(&directories[1].0, configuration.clone(), keys[1].clone(), 0).unwrap();
        let (stop, receiver) = watch::channel(false);
        stops[1] = stop;
        tasks.push(tokio::spawn(serve(
            configs[1].clone(),
            engine,
            Arc::new(ExampleApplication(configuration.clone())),
            receiver,
        )));
        tokio::time::sleep(Duration::from_millis(500)).await;
        certified(&configs[1].control_socket, &configuration, &next)
            .await
            .unwrap();
        for stop in &stops {
            stop.send(true).unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    })
    .await
    .expect("Native protocol qualification exceeded its bound");
}

#[test]
fn retransmission_duplicates_cannot_starve_requests_or_repairs() {
    let mailbox = ingress::Mailbox::new();
    for i in 0..8 {
        mailbox.push(vec![i]).unwrap();
    }
    for _ in 0..32 {
        for i in 0..8 {
            mailbox.push(vec![i]).unwrap();
        }
    }
    mailbox.push(vec![90]).unwrap();
    mailbox.push(vec![91]).unwrap();
    for i in 0..8 {
        assert_eq!(mailbox.try_pop().unwrap(), Some(vec![i]));
    }
    assert_eq!(mailbox.try_pop().unwrap(), Some(vec![90]));
    assert_eq!(mailbox.try_pop().unwrap(), Some(vec![91]));
    assert_eq!(mailbox.try_pop().unwrap(), None);
    for i in 0..112 {
        mailbox.push(vec![i]).unwrap();
    }
    assert!(mailbox.push(vec![112]).is_err());
    mailbox
        .push_class(vec![128], queue::Class::Response { family: 14 })
        .unwrap();
    assert_eq!(mailbox.try_pop().unwrap(), Some(vec![128]));
}

#[test]
fn checkpoint_transfer_requires_exact_requests_before_atomic_adoption() {
    use super::super::checkpoint::tests::{certify, step};
    let (configuration, keys) = fixture();
    let source_dir = Directory::new();
    let target_dir = Directory::new();
    let mut source = Engine::create(
        &source_dir.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    for height in 1..=32 {
        step(&mut source, &keys, height);
    }
    let share = source.checkpoint_shares()[0].clone();
    let proof = certify(&mut source, &keys);
    let target = Engine::create(
        &target_dir.0,
        configuration.clone(),
        keys[1].clone(),
        initial(),
    )
    .unwrap();
    let source_key = keys[0].verifying_key().to_bytes();
    let target_key = keys[1].verifying_key().to_bytes();
    let requests = ingress::Mailbox::new();
    let responses = ingress::Mailbox::new();
    let mut source = repair_driver(source, &source_dir.0, &keys, target_key, responses.clone());
    let mut target = repair_driver(target, &target_dir.0, &keys, source_key, requests.clone());
    let generation = target.engine.generation();
    target
        .checkpoint_receive(source_key, Message::CheckpointShare(share))
        .unwrap();
    assert!(target.checkpoint_votes.is_empty());
    assert_eq!(target.engine.generation(), generation);
    target
        .checkpoint_receive(source_key, Message::CheckpointProof(proof))
        .unwrap();
    let request = peer::decode(
        &configuration,
        target_key,
        &requests.try_pop().unwrap().unwrap(),
    )
    .unwrap();
    source.checkpoint_receive(target_key, request).unwrap();
    let response = peer::decode(
        &configuration,
        source_key,
        &responses.try_pop().unwrap().unwrap(),
    )
    .unwrap();
    let Message::StateResponse(id, chunk) = response.clone() else {
        panic!("Expected state response")
    };
    assert!(
        target
            .checkpoint_receive(source_key, Message::StateResponse([42; 32], chunk))
            .is_err()
    );
    assert_eq!(target.engine.generation(), generation);
    target
        .checkpoint_receive(source_key, response.clone())
        .unwrap();
    assert!(target.checkpoint_receive(source_key, response).is_err());
    assert_eq!(target.engine.generation(), generation);
    let request = peer::decode(
        &configuration,
        target_key,
        &requests.try_pop().unwrap().unwrap(),
    )
    .unwrap();
    source.checkpoint_receive(target_key, request).unwrap();
    let response = peer::decode(
        &configuration,
        source_key,
        &responses.try_pop().unwrap().unwrap(),
    )
    .unwrap();
    let Message::ArchiveResponse(_, digest, index, leaves) = response.clone() else {
        panic!("Expected archive response")
    };
    assert!(
        target
            .checkpoint_receive(
                source_key,
                Message::ArchiveResponse(id, digest, index + 1, leaves)
            )
            .is_err()
    );
    assert_eq!(target.engine.generation(), generation);
    target
        .checkpoint_receive(source_key, response.clone())
        .unwrap();
    assert!(target.checkpoint_receive(source_key, response).is_err());
    assert_eq!(target.engine.applied().unwrap().height, 32);
    assert_eq!(
        target.engine.archive.leaves(),
        source.engine.archive.leaves()
    );
    assert!(target.transfers.is_empty());

    let request = |payload: V| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            configuration.scope.value(),
            V::Uint(3),
            V::Bytes(wire::encode(&payload).unwrap()),
        ]))
        .unwrap()
    };
    let unavailable = target.local_request(&request(V::Array(vec![
        V::Uint(1),
        V::Bytes([77; 32].to_vec()),
        V::Bytes([88; 32].to_vec()),
    ])));
    let value = wire::decode(&unavailable).unwrap();
    assert_eq!(value.array(10).unwrap()[4].uint().unwrap(), 1);
    let malformed = target.local_request(&request(V::Array(vec![])));
    let value = wire::decode(&malformed).unwrap();
    assert_eq!(value.array(10).unwrap()[4].uint().unwrap(), 2);
}

#[path = "ConsensusCheckpointRecoveryTests.rs"]
mod checkpoint_recovery;

#[path = "ConsensusAvailabilityTests.rs"]
mod availability;

#[path = "ConsensusInputTests.rs"]
mod immutable_inputs;
