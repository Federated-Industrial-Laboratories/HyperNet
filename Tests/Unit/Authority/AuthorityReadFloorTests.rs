// SPDX-License-Identifier: MIT
// Fresh evidence survives floor recovery without completing or replacing an ordinary operation.
use super::*;
use crate::authority_read::{self as read, Query, Request, Statement, VerifiedRead};

fn later(sample: ClockHealth, elapsed: u64) -> ClockHealth {
    let now = sample.observe().unwrap();
    ClockHealth::new(
        now.wall_ms + elapsed,
        now.boot_ms + elapsed,
        now.boot_ms + elapsed + 30_000,
        100,
    )
    .unwrap()
    .frozen()
}

pub(crate) struct Read {
    request: Vec<u8>,
    challenge: Vec<u8>,
    result: Vec<u8>,
    certificate: Vec<u8>,
    node: Vec<u8>,
    versions: Vec<VersionRef>,
}
impl Read {
    pub(crate) fn new(store: &Store, session: &mut Session, sample: ClockHealth) -> Self {
        Self::with_nonce(store, session, sample, [97; 32])
    }
    fn with_nonce(
        store: &Store,
        session: &mut Session,
        sample: ClockHealth,
        nonce: Digest,
    ) -> Self {
        let scope = store.descriptor().scope();
        let versions = [100, 114]
            .into_iter()
            .map(|kind| VersionRef {
                kind,
                id: scope.network,
                generation: 1,
                digest: [kind as u8; 32],
            })
            .collect::<Vec<_>>();
        Self::with_query(
            store,
            session,
            sample,
            nonce,
            versions,
            Query::PolicyContext,
        )
    }
    pub(crate) fn with_versions(
        store: &Store,
        session: &mut Session,
        sample: ClockHealth,
        versions: Vec<VersionRef>,
    ) -> Self {
        let scope = store.descriptor().scope();
        let query = Query::Domain(crate::authority_domains::Operation {
            grant: None,
            command: crate::authority_domains::routes::Command::Lookup { service: [7; 32] }.into(),
            snapshot: crate::authority_domains::snapshot(&V::Array(vec![
                V::Array(vec![
                    V::Uint(scope.epoch),
                    V::Uint(store.prefix().height()),
                    b(store.prefix().policy_state()),
                ]),
                V::Array(vec![]),
            ]))
            .unwrap(),
        });
        Self::with_query(store, session, sample, [97; 32], versions, query)
    }
    fn with_query(
        store: &Store,
        session: &mut Session,
        sample: ClockHealth,
        nonce: Digest,
        versions: Vec<VersionRef>,
        query: Query,
    ) -> Self {
        let action = query.action();
        let signer = SigningKey::from_bytes(&[1; 32]);
        let scope = store.descriptor().scope();
        let request = Request::sign(
            scope,
            &signer,
            store.requester(),
            nonce,
            store.prefix().height(),
            query,
        )
        .unwrap();
        let challenge = session
            .issue_read(&request, &signer, nonce, 5000, None, sample)
            .unwrap();
        let value = encoded(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(action.into()),
            V::Array(
                versions
                    .iter()
                    .map(crate::authority_membership::reference)
                    .collect(),
            ),
            V::Array(vec![]),
        ]);
        let result = encoded(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text(action.into()),
            V::Uint(0),
            V::Uint(0),
            b(&value),
        ]);
        let request_digest = Request::from_signed(&request).unwrap().digest;
        let parsed = proof::Challenge::from_signed(&challenge).unwrap();
        let evaluated_at_ms = (parsed.created_at_ms + crate::authority_governance::UNCERTAINTY_MS)
            .max(store.prefix().evaluated_at_ms());
        let statement = Statement {
            scope: scope.clone(),
            request: request_digest,
            challenge: parsed.digest,
            requester: store.requester(),
            recipient: store.requester(),
            height: store.prefix().height(),
            node: *store.prefix().node(),
            state: *store.prefix().policy_state(),
            evaluated_at_ms,
            expires_at_ms: parsed
                .evaluation_expiry(evaluated_at_ms, parsed.expires_at_ms)
                .unwrap(),
            result: wire::digest(&result),
        };
        let certificate = quorum(
            wire::decode(&statement.encode().unwrap())
                .unwrap()
                .array(13)
                .unwrap()
                .to_vec(),
        );
        let node = hex::decode(store.stored.node.as_ref().unwrap()).unwrap();
        Self {
            request,
            challenge,
            result,
            certificate,
            node,
            versions,
        }
    }
    pub(crate) fn verify(&self, store: &Store) -> VerifiedRead {
        read::verify_response(
            store.descriptor(),
            &self.request,
            &self.challenge,
            read::Response {
                node: &self.node,
                certificate: &self.certificate,
                result: &self.result,
                ancestry: std::slice::from_ref(&self.node),
            },
            |_, result, _| {
                ensure!(
                    result.value == OperationResult::parse(&self.result)?.value,
                    "floor fixture result changed"
                );
                Ok(self.versions.clone())
            },
        )
        .unwrap()
    }

    fn certify_later_prefix(&mut self, height: u64, branch: u8) {
        let (payload, _) = wire::envelope(&self.certificate, 4).unwrap();
        let mut statement = Statement::parse(&payload).unwrap();
        let value = wire::decode(&self.node).unwrap();
        let mut node = value.array(9).unwrap().to_vec();
        assert!(height > statement.height);
        node[3] = V::Uint(height);
        node[4] = V::Uint(node[4].uint().unwrap() + height - statement.height);
        node[5] = b(&statement.node);
        node[6] = b(&[branch; 32]);
        node[7] = V::Uint(statement.evaluated_at_ms);
        self.node = encoded(node);
        statement.height = height;
        statement.node = wire::digest(&self.node);
        self.certificate = quorum(
            wire::decode(&statement.encode().unwrap())
                .unwrap()
                .array(13)
                .unwrap()
                .to_vec(),
        );
    }
}

#[test]
fn fresh_read_floor_recovers_without_changing_completed_ordinary_tracker() {
    let (directory, sample, mut session, mut store) = setup();
    let (pending, operation) = prepare(&mut store, sample);
    let verified = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    store
        .accept(verified, &mut session, sample, 0)
        .unwrap()
        .perform(
            &mut store,
            &mut session,
            sample,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    let tracker = store.stored.tracker.clone();
    assert!(tracker.ordinary.as_ref().unwrap().complete);
    let prefix = store.prefix().clone();
    let old_floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let old_witness: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join(WITNESS)).unwrap()).unwrap();
    let sample = later(sample, 500);
    let query = Read::new(&store, &mut session, sample);
    let verified = query.verify(&store);
    assert!(verified.statement.evaluated_at_ms > prefix.evaluated_at_ms());
    store
        .accept_read(verified, &mut session, sample, 0, |_, store| {
            assert_eq!(store.stored.tracker, tracker);
            assert!(
                query
                    .versions
                    .iter()
                    .all(|v| store.generations().contains(v))
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(store.prefix(), &prefix);
    assert_eq!(store.stored.tracker, tracker);
    let new_floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let new_witness: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join(WITNESS)).unwrap()).unwrap();
    let transaction = serde_json::to_vec(&serde_json::json!({
        "format":"HyperNetAuthorityPending/1", "network":store.stored.network,
        "incarnation":store.stored.incarnation, "requester":store.stored.requester,
        "descriptor":store.stored.descriptor, "oldWitness":old_witness, "nextWitness":new_witness,
        "nextFloorBytes":hex::encode(&new_floor),
        "transition":{"learnRead":{"result":hex::encode(&query.result)}},
        "continuity":{"ancestry":[hex::encode(&query.node)],"history":null}
    }))
    .unwrap();
    // The new witness and pending transaction must complete an interrupted floor replacement.
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(FLOOR),
        &old_floor,
        true,
    )
    .unwrap();
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(transaction::PENDING),
        &transaction,
        false,
    )
    .unwrap();
    let descriptor = store.descriptor().clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), new_floor);
    assert_eq!(store.stored.tracker, tracker);
    assert_eq!(store.prefix(), &prefix);
    let payload = store
        .descriptor()
        .quorum(&hex::decode(store.stored.certificate.as_ref().unwrap()).unwrap())
        .unwrap();
    assert!(Statement::parse(&payload).is_ok());
    assert!(proof::ExecutedResult::parse(&payload).is_err());
    assert!(!transaction::exists(store.profile_directory(), transaction::PENDING).unwrap());
    let mut restarted = Session::new().unwrap();
    assert!(
        store
            .accept_read(
                query.verify(&store),
                &mut restarted,
                sample,
                0,
                |_, _| -> Result<()> { panic!("restart revived a read challenge") }
            )
            .is_err()
    );
}

#[test]
fn failed_fresh_read_publication_keeps_floors_without_recording_an_ordinary_effect() {
    let (directory, sample, mut session, mut store) = setup();
    let tracker = store.stored.tracker.clone();
    let sample = later(sample, 500);
    let query = Read::new(&store, &mut session, sample);
    assert!(
        store
            .accept_read_consumed(
                query.verify(&store),
                &mut session,
                sample,
                0,
                |_, _| -> Result<()> { anyhow::bail!("context publication failed") }
            )
            .is_err()
    );
    assert_eq!(store.stored.tracker, tracker);
    assert!(store.resume_ordinary().unwrap().is_none());
    assert!(!directory.0.join(BODY).exists());
    assert!(
        store
            .accept_read(
                query.verify(&store),
                &mut session,
                sample,
                0,
                |_, _| -> Result<()> { panic!("consumed failed read was used twice") }
            )
            .is_err()
    );
    let descriptor = store.descriptor().clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    assert_eq!(store.stored.tracker, tracker);
    assert!(
        query
            .versions
            .iter()
            .all(|v| store.generations().contains(v))
    );
    let query = Read::new(&store, &mut session, sample);
    store
        .accept_read(query.verify(&store), &mut session, sample, 0, |_, _| Ok(()))
        .unwrap();
    assert_eq!(store.stored.tracker, tracker);
}

#[test]
fn consumed_fresh_read_cleanup_never_waits_for_support_or_reuses_authority() {
    use std::{
        fs::File,
        io::{Read as _, Write as _},
        os::{
            fd::AsRawFd,
            unix::{fs::PermissionsExt, net::UnixListener},
        },
        time::{Duration, Instant},
    };
    for refused in [false, true] {
        let (directory, sample, mut session, mut store) = setup();
        let sample = later(sample, 500);
        let mut query = Read::new(&store, &mut session, sample);
        if refused {
            query.result = encoded(vec![
                V::Uint(24),
                V::Uint(1),
                V::Text("AuthorityPolicyContext".into()),
                V::Uint(1),
                V::Uint(2),
                b(&encoded(vec![])),
            ]);
            let payload = store.descriptor().quorum(&query.certificate).unwrap();
            let mut statement = Statement::parse(&payload).unwrap();
            statement.result = wire::digest(&query.result);
            query.certificate = quorum(
                wire::decode(&statement.encode().unwrap())
                    .unwrap()
                    .array(13)
                    .unwrap()
                    .to_vec(),
            );
        }
        let verified = query.verify(&store);
        let statement = verified.statement.clone();
        let consumed = if refused {
            store
                .observe_read_consumed(verified, &mut session, sample, 0)
                .unwrap()
        } else {
            let (value, consumed) = store
                .accept_read_consumed(verified, &mut session, sample, 0, |_, _| Ok(42))
                .unwrap();
            assert_eq!(value, 42);
            consumed
        };
        let key = SigningKey::from_bytes(&[1; 32]);
        let observed = sample.observe().unwrap();
        let short = consumed
            .acknowledgement(&key, observed.boot_ms + 10)
            .unwrap();
        let short = read::Acknowledgement::from_signed(&short).unwrap();
        assert_eq!(short.not_after_ms, observed.wall_ms + 10);
        let path = directory.0.join("Ack.sock");
        let parent = File::open(&directory.0).unwrap();
        let listener =
            UnixListener::bind(format!("/proc/self/fd/{}/Ack.sock", parent.as_raw_fd())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 2000;
        // A legacy listener receives no cleanup traffic; a different socket is not support.
        crate::authority_local_transport::acknowledge_read(&consumed, &key, deadline, &path);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let alias = directory
            .0
            .join(crate::authority_local_transport::READ_ACK_SOCKET);
        let other = UnixListener::bind(format!(
            "/proc/self/fd/{}/ReadAcknowledgements.sock",
            parent.as_raw_fd()
        ))
        .unwrap();
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o600)).unwrap();
        other.set_nonblocking(true).unwrap();
        crate::authority_local_transport::acknowledge_read(&consumed, &key, deadline, &path);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            other.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(other);
        std::fs::remove_file(&alias).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let started = Instant::now();
        crate::authority_local_transport::acknowledge_read(&consumed, &key, deadline, &path);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cleanup waited for a server that has not read or replied"
        );
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut size = [0; 4];
        socket.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size) as usize;
        assert!(size <= read::Acknowledgement::MAXIMUM);
        let mut packet = vec![0; size];
        socket.read_exact(&mut packet).unwrap();
        assert!(crate::authority_local_transport::is_read_acknowledgement(
            &packet
        ));
        let value = wire::decode(&packet).unwrap();
        let fields = value.array(5).unwrap();
        let acknowledgement =
            read::Acknowledgement::from_signed(fields[4].bytes().unwrap()).unwrap();
        assert_eq!(
            acknowledgement.id,
            read::read_id(&query.request, &query.challenge).unwrap()
        );
        assert_eq!(
            acknowledgement.statement,
            wire::digest(&statement.encode().unwrap())
        );
        assert_eq!(acknowledgement.result, wire::digest(&query.result));
        assert!(acknowledgement.not_after_ms <= statement.expires_at_ms);
        assert_eq!(
            socket.read(&mut [0; 1]).unwrap(),
            0,
            "cleanup retained a response waiter"
        );
        // An older server's unsupported-operation reply cannot alter a consumed result.
        let unsupported = encoded(vec![
            V::Uint(42),
            V::Uint(1),
            store.descriptor().scope().value(),
            V::Uint(2),
            V::Uint(2),
            V::Null,
            V::Null,
            V::Null,
            V::Null,
            V::Array(vec![]),
        ]);
        let _ = socket.write_all(&unsupported);
        crate::authority_local_transport::acknowledge_read(&consumed, &key, 0, &path);
        crate::authority_local_transport::acknowledge_read(
            &consumed,
            &SigningKey::from_bytes(&[2; 32]),
            deadline,
            &path,
        );
        crate::authority_local_transport::acknowledge_read(
            &consumed,
            &key,
            deadline,
            &directory.0.join("Absent.sock"),
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        if refused {
            assert!(
                store
                    .observe_read_consumed(query.verify(&store), &mut session, sample, 0)
                    .is_err()
            );
        } else {
            assert!(
                store
                    .accept_read_consumed(
                        query.verify(&store),
                        &mut session,
                        sample,
                        0,
                        |_, _| -> Result<()> { panic!("cleanup replayed consumed authority") }
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn fresh_read_cannot_replace_pending_ordinary_or_fence_and_expiry_cannot_advance_floor() {
    for mode in 0..3 {
        let (directory, sample, mut session, mut store) = setup();
        let query = Read::new(&store, &mut session, later(sample, 500));
        if mode == 0 {
            prepare(&mut store, sample);
        } else if mode == 1 {
            let old = store.stream_metadata().unwrap().unwrap();
            let prior = old.state().unwrap();
            let scope = store.descriptor().scope();
            let signed = wire::sign_envelope(
                &encoded(vec![
                    V::Uint(57),
                    V::Uint(1),
                    b(&scope.network),
                    b(&scope.incarnation),
                    b(&store.requester()),
                    b(&[96; 32]),
                    V::Uint(scope.epoch),
                    V::Uint(store.prefix().height()),
                    V::Uint(prior.generation),
                    b(&prior.generation_id),
                    b(&wire::digest(old.canonical())),
                ]),
                &SigningKey::from_bytes(&[1; 32]),
            )
            .unwrap();
            store.prepare_fence(&signed, old.canonical()).unwrap();
        }
        let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
        let witness = std::fs::read(directory.0.join(WITNESS)).unwrap();
        let now = later(sample, if mode == 2 { 5500 } else { 500 });
        assert!(
            store
                .accept_read(
                    query.verify(&store),
                    &mut session,
                    now,
                    0,
                    |_, _| -> Result<()> { panic!("blocked fresh read published a result") }
                )
                .is_err()
        );
        assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
        assert_eq!(std::fs::read(directory.0.join(WITNESS)).unwrap(), witness);
    }
}

#[test]
fn distinct_fresh_reads_at_one_floor_complete_out_of_order_once_each() {
    let (_directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let first = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let second = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    let prefix = store.prefix().clone();
    let tracker = store.stored.tracker.clone();
    let mut effects = 0;
    for query in [&second, &first] {
        store
            .accept_read_consumed(query.verify(&store), &mut session, sample, 0, |_, _| {
                effects += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.prefix(), &prefix);
        assert_eq!(store.stored.tracker, tracker);
    }
    assert_eq!(effects, 2);
    for query in [&first, &second] {
        assert!(
            store
                .accept_read_consumed(
                    query.verify(&store),
                    &mut session,
                    sample,
                    0,
                    |_, _| -> Result<()> { panic!("completed concurrent read was consumed twice") }
                )
                .is_err()
        );
    }
}

#[test]
fn fresh_completion_cannot_roll_back_a_floor_advanced_after_issue() {
    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let query = Read::new(&store, &mut session, sample);
    let issued_height = store.prefix().height();
    let (pending, operation) = prepare(&mut store, sample);
    let verified = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    store
        .accept(verified, &mut session, sample, 0)
        .unwrap()
        .perform(
            &mut store,
            &mut session,
            sample,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(store.prefix().height() > issued_height);
    let prefix = store.prefix().clone();
    let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let witness = std::fs::read(directory.0.join(WITNESS)).unwrap();
    let error = store
        .accept_read_consumed(
            query.verify(&store),
            &mut session,
            sample,
            0,
            |_, _| -> Result<()> { panic!("overtaken read published its old context") },
        )
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("below the accepted"),
        "{error:#}"
    );
    assert_eq!(store.prefix(), &prefix);
    assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
    assert_eq!(std::fs::read(directory.0.join(WITNESS)).unwrap(), witness);
    session.discard(&query.challenge).unwrap();
}

#[test]
fn concurrent_lower_bound_reads_accept_same_newer_certified_prefix_once_each() {
    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let issued_height = store.prefix().height();
    let tracker = store.stored.tracker.clone();
    let mut first = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let mut second = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    for query in [&mut first, &mut second] {
        query.certify_later_prefix(issued_height + 1, 83);
        assert_eq!(
            Request::from_signed(&query.request).unwrap().minimum_height,
            issued_height
        );
    }
    let first_result = first.verify(&store);
    let second_result = second.verify(&store);
    let mut effects = 0;
    for result in [second_result, first_result] {
        store
            .accept_read_consumed(result, &mut session, sample, 0, |_, _| {
                effects += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(store.prefix().height(), issued_height + 1);
        assert_eq!(store.stored.tracker, tracker);
    }
    assert_eq!(effects, 2);
    for query in [&first, &second] {
        assert!(
            store
                .accept_read_consumed(
                    query.verify(&store),
                    &mut session,
                    sample,
                    0,
                    |_, _| -> Result<()> { panic!("completed read was consumed twice") },
                )
                .is_err()
        );
    }
    let prefix = store.prefix().clone();
    let descriptor = store.descriptor().clone();
    drop(store);
    assert_eq!(
        Store::open(&directory.0, descriptor).unwrap().prefix(),
        &prefix
    );
}

#[test]
fn newer_floor_still_rejects_stale_or_conflicting_read_results() {
    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    let mut accepted = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let stale = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    let mut conflicting = Read::with_nonce(&store, &mut session, sample, [99; 32]);
    let height = store.prefix().height() + 1;
    accepted.certify_later_prefix(height, 83);
    conflicting.certify_later_prefix(height, 84);
    store
        .accept_read_consumed(accepted.verify(&store), &mut session, sample, 0, |_, _| {
            Ok(())
        })
        .unwrap();
    let prefix = store.prefix().clone();
    let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let witness = std::fs::read(directory.0.join(WITNESS)).unwrap();
    for (query, expected) in [
        (&stale, "below the accepted"),
        (&conflicting, "conflicting result"),
    ] {
        let error = store
            .accept_read_consumed(
                query.verify(&store),
                &mut session,
                sample,
                0,
                |_, _| -> Result<()> { panic!("stale or conflicting read published") },
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_eq!(store.prefix(), &prefix);
        assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
        assert_eq!(std::fs::read(directory.0.join(WITNESS)).unwrap(), witness);
    }
}

#[test]
fn history_bound_before_concurrent_publication_is_not_rebased() {
    use sha2::{Digest as _, Sha256};

    let (directory, sample, mut session, mut store) = setup();
    let sample = later(sample, 500);
    assert_eq!(store.prefix().height(), 1);
    let mut first = Read::with_nonce(&store, &mut session, sample, [97; 32]);
    let mut second = Read::with_nonce(&store, &mut session, sample, [98; 32]);
    first.certify_later_prefix(32, 83);
    second.certify_later_prefix(32, 83);
    let (payload, _) = wire::envelope(&first.certificate, 4).unwrap();
    let statement = Statement::parse(&payload).unwrap();
    let mut nodes = [[85; 32]; 32];
    nodes[0] = *store.prefix().node();
    nodes[31] = statement.node;
    let mut hashes = nodes
        .iter()
        .map(|node| Sha256::digest([&[0][..], node].concat()).into())
        .collect::<Vec<Digest>>();
    let mut inclusion = Vec::new();
    while hashes.len() > 1 {
        inclusion.push(hashes[1]);
        hashes = hashes
            .chunks_exact(2)
            .map(|pair| Sha256::digest([&[1][..], &pair[0], &pair[1]].concat()).into())
            .collect();
    }
    let checkpoint = encoded(vec![
        V::Uint(46),
        V::Uint(1),
        b(&quorum(vec![
            V::Uint(45),
            V::Uint(1),
            statement.scope.value(),
            V::Uint(32),
            b(&statement.node),
            V::Uint(statement.evaluated_at_ms),
            b(&statement.state),
            V::Uint(32),
            b(&hashes[0]),
            V::Bool(false),
        ])),
        b(&first.node),
    ]);
    let verified_checkpoint = history::verify_checkpoint(store.descriptor(), &checkpoint).unwrap();
    let proof = encoded(vec![
        V::Uint(47),
        V::Uint(1),
        statement.scope.value(),
        V::Uint(store.prefix().height()),
        b(store.prefix().node()),
        b(verified_checkpoint.digest()),
        V::Array(inclusion.iter().map(|hash| b(hash)).collect()),
        V::Uint(0),
        V::Null,
        V::Array(vec![]),
    ]);
    let first_result = store
        .attach_read_history(first.verify(&store), &checkpoint, &proof)
        .unwrap();
    let second_result = store
        .attach_read_history(second.verify(&store), &checkpoint, &proof)
        .unwrap();
    store
        .accept_read_consumed(first_result, &mut session, sample, 0, |_, _| Ok(()))
        .unwrap();
    let floor = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let error = store
        .accept_read_consumed(
            second_result,
            &mut session,
            sample,
            0,
            |_, _| -> Result<()> { panic!("old history was silently rebased") },
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("history differs"), "{error:#}");
    assert_eq!(store.prefix().height(), 32);
    assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), floor);
    assert!(
        store
            .attach_read_history(second.verify(&store), &checkpoint, &proof)
            .is_err()
    );
}

#[test]
fn scoped_admission_fresh_result_preserves_policy_shape() {
    fn result(action: &str, kinds: &[u64]) -> proof::OperationResult {
        let refs = kinds
            .iter()
            .map(|kind| {
                V::Array(vec![
                    V::Uint(*kind),
                    b(&[*kind as u8; 32]),
                    V::Uint(1),
                    b(&[7; 32]),
                ])
            })
            .collect();
        proof::OperationResult {
            action: action.into(),
            disposition: Disposition::Permit,
            code: 0,
            value: wire::encode(&V::Array(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text(action.into()),
                V::Array(refs),
                V::Array(vec![]),
            ]))
            .unwrap(),
        }
    }
    let native =
        read::result_versions(&result("AuthorityAdmissionContext", &[100, 114, 180, 181])).unwrap();
    assert_eq!(
        native.iter().map(|r| r.kind).collect::<Vec<_>>(),
        [100, 114, 180, 181]
    );
    assert!(read::result_versions(&result("AuthorityPolicyContext", &[100, 114])).is_ok());
    assert!(read::result_versions(&result("AuthorityPolicyContext", &[100, 114, 180])).is_err());
    assert!(read::result_versions(&result("UnrecognisedContext", &[180, 181])).is_err());
}
