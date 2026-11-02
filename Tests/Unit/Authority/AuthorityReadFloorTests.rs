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

struct Read {
    request: Vec<u8>,
    challenge: Vec<u8>,
    result: Vec<u8>,
    certificate: Vec<u8>,
    node: Vec<u8>,
    versions: Vec<VersionRef>,
}
impl Read {
    fn new(store: &Store, session: &mut Session, sample: ClockHealth) -> Self {
        let signer = SigningKey::from_bytes(&[1; 32]);
        let scope = store.descriptor().scope();
        let request = Request::sign(
            scope,
            &signer,
            store.requester(),
            [97; 32],
            store.prefix().height(),
            Query::PolicyContext,
        )
        .unwrap();
        let challenge = session
            .issue_read(&request, &signer, [97; 32], 5000, None, sample)
            .unwrap();
        let versions = [100, 114]
            .into_iter()
            .map(|kind| VersionRef {
                kind,
                id: scope.network,
                generation: 1,
                digest: [kind as u8; 32],
            })
            .collect::<Vec<_>>();
        let value = encoded(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityPolicyContext".into()),
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
            V::Text("AuthorityPolicyContext".into()),
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
    fn verify(&self, store: &Store) -> VerifiedRead {
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
