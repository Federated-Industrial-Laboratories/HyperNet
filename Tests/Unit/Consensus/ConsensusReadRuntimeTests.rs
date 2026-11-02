// SPDX-License-Identifier: MIT
// Real policy evaluation and signed peer records exercise the volatile collection path.
use super::*;
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_read as read,
};
#[path = "ConsensusReadAcknowledgementInteropTests.rs"]
mod interop;
fn control(driver: &Driver, operation: u64, payload: &[u8]) -> Vec<u8> {
    wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        driver.config().scope.value(),
        V::Uint(operation),
        V::Bytes(payload.to_vec()),
    ]))
    .unwrap()
}
#[test]
fn fresh_policy_quorum_uses_current_local_state_without_journal_or_stream_writes() {
    policy_quorum(false, false, false);
}
#[test]
fn fresh_read_delayed_shares_survive_retransmission_and_recollection_until_exact_expiry() {
    policy_quorum(true, false, false);
}
#[test]
fn completed_fresh_read_capacity_recovers_for_the_same_original_challenge() {
    policy_quorum(false, true, false);
}
#[test]
fn consumed_fresh_read_acknowledgement_releases_only_complete_bound_results() {
    policy_quorum(false, true, true);
}
#[tokio::test]
async fn consumed_read_cleanup_ingress_delivers_one_framed_receipt() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let directory = Directory::new();
    let path = directory.0.join("Control.sock");
    let (listener, _guard) = ingress::local_socket(&path).unwrap();
    let (events, mut receiver) = tokio::sync::mpsc::channel(1);
    let (diagnostics, _monitor) = diagnostics::Diagnostics::new();
    let task = tokio::spawn(ingress::accept_local(listener, events, diagnostics));
    let fixture = crate::authority_proof::tests::Fixture::new(10000);
    let packet = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        fixture.descriptor.scope().value(),
        V::Uint(8),
        V::Bytes(vec![]),
    ]))
    .unwrap();
    // The connector drains a framed receipt while a local notification may close immediately.
    let send = async {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_u32(packet.len() as u32).await.unwrap();
        stream.write_all(&packet).await.unwrap();
        let Event::Local { body, answer, .. } = receiver.recv().await.unwrap() else {
            panic!("cleanup was not local")
        };
        assert_eq!(body, packet);
        answer.send(vec![64, 1]).unwrap();
        assert_eq!(stream.read_u32().await.unwrap(), 2);
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [64, 1]);
        assert!(receiver.try_recv().is_err());
    };
    tokio::time::timeout(Duration::from_secs(1), send)
        .await
        .unwrap();
    task.abort();
}
fn policy_quorum(delayed: bool, capacity: bool, acknowledge: bool) {
    let now = crate::consensus_clock::moment().unwrap();
    let fixture = crate::authority_application::tests::Fixture::at(now.wall_ms - 1000);
    let configuration = fixture.configuration().clone();
    let (_, keys) = crate::consensus::records::tests::fixture();
    let directories = (0..4).map(|_| Directory::new()).collect::<Vec<_>>();
    let mailboxes = (0..4).map(|_| ingress::Mailbox::new()).collect::<Vec<_>>();
    let mut drivers = directories
        .iter()
        .zip(&keys)
        .map(|(directory, key)| {
            let engine = Engine::create(
                &directory.0,
                configuration.clone(),
                key.clone(),
                fixture.initial.clone(),
            )
            .unwrap();
            let mut driver = repair_driver(
                engine,
                &directory.0,
                &keys,
                configuration.voters[0],
                mailboxes[0].clone(),
            );
            driver.application = Arc::new(crate::authority_application::PolicyApplication::new(
                configuration.clone(),
            ));
            driver
        })
        .collect::<Vec<_>>();
    drivers[0].senders = (1..4)
        .map(|index| (configuration.voters[index], mailboxes[index].clone()))
        .collect();
    for (driver, directory) in drivers.iter_mut().zip(&directories) {
        driver.config.clock = crate::authority_clock_handoff::Source::Private {
            path: runtime_clock(&directory.0).0,
        };
    }
    let now = crate::consensus_clock::moment().unwrap();
    let mut session = Session::new().unwrap();
    let requester = fixture.requester.verifying_key().to_bytes();
    let request = read::Request::sign(
        configuration.descriptor().scope(),
        &fixture.requester,
        requester,
        [67; 32],
        0,
        read::Query::PolicyContext,
    )
    .unwrap();
    let challenge = session
        .issue_read(
            &request,
            &fixture.requester,
            [67; 32],
            if capacity && !acknowledge { 3000 } else { 5000 },
            None,
            ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 1)
                .unwrap()
                .frozen(),
        )
        .unwrap();
    let id = read::read_id(&request, &challenge).unwrap();
    let before = drivers
        .iter()
        .map(|d| (d.engine.generation(), d.engine.application().to_vec()))
        .collect::<Vec<_>>();
    let submission = wire::encode(&V::Array(vec![
        V::Bytes(request.clone()),
        V::Bytes(challenge.clone()),
    ]))
    .unwrap();
    let command = control(&drivers[0], 6, &submission);
    let first = drivers[0].local_request(&command);
    assert_eq!(
        wire::decode(&first).unwrap().array(10).unwrap()[3]
            .uint()
            .unwrap(),
        0
    );
    let probes = mailboxes
        .iter()
        .skip(1)
        .map(|mailbox| mailbox.try_pop().unwrap().expect("fresh probe"))
        .collect::<Vec<_>>();
    let Message::ReadProbe(_, _, initial_payload) =
        peer::decode(&configuration, configuration.voters[0], &probes[0]).unwrap()
    else {
        panic!("expected read probe")
    };
    let initial = read::Statement::parse(&initial_payload).unwrap();
    if acknowledge {
        let premature =
            read::Acknowledgement::sign(&initial, &fixture.requester, initial.expires_at_ms)
                .unwrap();
        assert!(drivers[0].read_acknowledge(&premature).is_err());
        assert_eq!(drivers[0].reads.len(), 1);
    }
    let started = Instant::now();
    if delayed {
        // Drive the actual retry timer without sleeps: 300 ms transit exceeds RETRANSMIT.
        let pending = drivers[0]
            .read_poll_at(
                id,
                started + Duration::from_millis(300),
                Ok(initial.evaluated_at_ms + 300),
            )
            .unwrap();
        assert_eq!(
            wire::decode(&pending).unwrap().array(10).unwrap()[3]
                .uint()
                .unwrap(),
            0
        );
        for (mailbox, original) in mailboxes.iter().skip(1).zip(&probes) {
            assert_eq!(
                mailbox.try_pop().unwrap().expect("exact retransmission"),
                *original
            );
        }
    }
    for index in 1..3 {
        let bytes = &probes[index - 1];
        let message = peer::decode(&configuration, configuration.voters[0], bytes).unwrap();
        drivers[index]
            .receive(configuration.voters[0], message)
            .unwrap();
        let reply = mailboxes[0].try_pop().unwrap().expect("fresh share");
        let message = peer::decode(&configuration, configuration.voters[index], &reply).unwrap();
        if index == 1 {
            let Message::ReadShare(read_id, node, share, result) = message.clone() else {
                panic!("expected read share")
            };
            let mut wrong = result.clone();
            wrong.push(0);
            drivers[0]
                .read_share(
                    configuration.voters[index],
                    read_id,
                    node.clone(),
                    share.clone(),
                    wrong,
                )
                .unwrap();
            let still_pending = drivers[0].read_poll(id).unwrap();
            assert_eq!(
                wire::decode(&still_pending).unwrap().array(10).unwrap()[3]
                    .uint()
                    .unwrap(),
                0
            );
            drivers[0]
                .read_share(configuration.voters[index], [93; 32], node, share, result)
                .unwrap();
        }
        drivers[0]
            .receive(configuration.voters[index], message)
            .unwrap();
        if delayed && index == 1 {
            // The old candidate already has two shares. Recollect at a fresh evaluation instant,
            // then deliver the remaining old share: separate candidates must never erase or mix it.
            let pending = drivers[0]
                .read_poll_at(
                    id,
                    started + Duration::from_millis(1100),
                    Ok(initial.evaluated_at_ms + 1100),
                )
                .unwrap();
            assert_eq!(
                wire::decode(&pending).unwrap().array(10).unwrap()[3]
                    .uint()
                    .unwrap(),
                0
            );
            for mailbox in mailboxes.iter().skip(1) {
                let bytes = mailbox.try_pop().unwrap().expect("fresh recollection");
                let Message::ReadProbe(_, _, payload) =
                    peer::decode(&configuration, configuration.voters[0], &bytes).unwrap()
                else {
                    panic!("expected fresh probe")
                };
                let current = read::Statement::parse(&payload).unwrap();
                assert_eq!(current.evaluated_at_ms, initial.evaluated_at_ms + 1100);
                assert_ne!(payload, initial_payload);
            }
        }
    }
    let command = control(&drivers[0], 7, &id);
    let reply = if delayed {
        drivers[0]
            .read_poll_at(
                id,
                started + Duration::from_millis(1400),
                Ok(initial.evaluated_at_ms + 1400),
            )
            .unwrap()
    } else {
        drivers[0].local_request(&command)
    };
    let value = wire::decode(&reply).unwrap();
    let fields = value.array(10).unwrap();
    assert_eq!(fields[3].uint().unwrap(), 1);
    let node = fields[6].bytes().unwrap();
    let ancestry = vec![node.to_vec()];
    let verified = read::verify_response(
        configuration.descriptor(),
        &request,
        &challenge,
        read::Response {
            node,
            certificate: fields[7].bytes().unwrap(),
            result: fields[8].bytes().unwrap(),
            ancestry: &ancestry,
        },
        |_, result, _| read::result_versions(result),
    )
    .unwrap();
    assert_eq!(
        verified.point().prefix(),
        &configuration.descriptor().genesis().unwrap()
    );
    assert_eq!(verified.statement.evaluated_at_ms, initial.evaluated_at_ms);
    if capacity {
        // A completed certificate must remain recoverable after a lost response.
        // Thirty-two real completed reads still occupy the finite collection budget.
        for mailbox in &mailboxes {
            while mailbox.try_pop().unwrap().is_some() {}
        }
        let mut issue = |nonce: u8| {
            let now = crate::consensus_clock::moment().unwrap();
            let signed = read::Request::sign(
                configuration.descriptor().scope(),
                &fixture.requester,
                requester,
                [nonce; 32],
                0,
                read::Query::PolicyContext,
            )
            .unwrap();
            let challenge = session
                .issue_read(
                    &signed,
                    &fixture.requester,
                    [nonce; 32],
                    5000,
                    None,
                    ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 1)
                        .unwrap()
                        .frozen(),
                )
                .unwrap();
            (signed, challenge)
        };
        let finish = |drivers: &mut Vec<Driver>, signed: &[u8], challenge: &[u8]| {
            let id = read::read_id(signed, challenge).unwrap();
            let submission = wire::encode(&V::Array(vec![
                V::Bytes(signed.to_vec()),
                V::Bytes(challenge.to_vec()),
            ]))
            .unwrap();
            let reply = drivers[0].read_start(&submission).unwrap();
            assert_eq!(
                wire::decode(&reply).unwrap().array(10).unwrap()[3]
                    .uint()
                    .unwrap(),
                0
            );
            for index in 1..4 {
                let bytes = mailboxes[index].try_pop().unwrap().expect("fresh probe");
                if index < 3 {
                    let message =
                        peer::decode(&configuration, configuration.voters[0], &bytes).unwrap();
                    drivers[index]
                        .receive(configuration.voters[0], message)
                        .unwrap();
                    let share = mailboxes[0].try_pop().unwrap().expect("fresh share");
                    let message =
                        peer::decode(&configuration, configuration.voters[index], &share).unwrap();
                    drivers[0]
                        .receive(configuration.voters[index], message)
                        .unwrap();
                }
            }
            let reply = drivers[0].read_poll(id).unwrap();
            assert_eq!(
                wire::decode(&reply).unwrap().array(10).unwrap()[3]
                    .uint()
                    .unwrap(),
                1
            );
            reply
        };
        for nonce in 100..100 + MAX_PENDING as u8 - 1 {
            let (signed, challenge) = issue(nonce);
            finish(&mut drivers, &signed, &challenge);
        }
        assert_eq!(drivers[0].reads.len(), MAX_PENDING);
        let (signed, original_challenge) = issue(200);
        let exact = wire::encode(&V::Array(vec![
            V::Bytes(signed.clone()),
            V::Bytes(original_challenge.clone()),
        ]))
        .unwrap();
        assert!(!drivers[0].diagnostics.has_read_capacity_report());
        let unavailable = drivers[0].read_start(&exact).unwrap();
        assert!(drivers[0].diagnostics.has_read_capacity_report());
        let unavailable = wire::decode(&unavailable).unwrap();
        let fields = unavailable.array(10).unwrap();
        assert_eq!(
            (fields[3].uint().unwrap(), fields[4].uint().unwrap()),
            (2, 2)
        );
        assert_eq!(drivers[0].reads.len(), MAX_PENDING);
        let acknowledged = if acknowledge {
            // Completion alone did not release the slot, including after a lost response.
            let recovered = drivers[0].read_poll(id).unwrap();
            assert_eq!(recovered, reply);
            let directory = Directory::new();
            let now = crate::consensus_clock::moment().unwrap();
            let health = ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 1)
                .unwrap()
                .frozen();
            let mut store = crate::authority_floor::Store::initialise(
                &directory.0,
                configuration.descriptor().clone(),
                requester,
                health,
            )
            .unwrap();
            // Negative vectors precede the bounded consume-and-acknowledge section.
            let signed = read::Acknowledgement::sign(
                &verified.statement,
                &fixture.requester,
                verified.statement.expires_at_ms,
            )
            .unwrap();
            let (payload, _) = wire::envelope(&signed, 1).unwrap();
            let fields = wire::decode(&payload).unwrap().array(7).unwrap().to_vec();
            let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
            assert!(
                drivers[0]
                    .read_acknowledge(&wire::sign_envelope(&payload, &wrong_key).unwrap())
                    .is_err()
            );
            for (field, value) in [
                (1, V::Uint(2)),
                (4, V::Bytes(vec![91; 32])),
                (5, V::Bytes(vec![92; 32])),
                (6, V::Uint(u64::MAX)),
            ] {
                let mut changed = fields.clone();
                changed[field] = value;
                let bad = wire::sign_envelope(
                    &wire::encode(&V::Array(changed)).unwrap(),
                    &fixture.requester,
                )
                .unwrap();
                assert!(drivers[0].read_acknowledge(&bad).is_err());
                assert_eq!(drivers[0].reads.len(), MAX_PENDING);
            }
            let mut changed = fields.clone();
            let mut scope = configuration.descriptor().scope().clone();
            scope.epoch += 1;
            changed[2] = scope.value();
            let bad = wire::sign_envelope(
                &wire::encode(&V::Array(changed)).unwrap(),
                &fixture.requester,
            )
            .unwrap();
            assert!(drivers[0].read_acknowledge(&bad).is_err());
            let mut expired = fields.clone();
            expired[6] = V::Uint(now.wall_ms);
            let expired = wire::sign_envelope(
                &wire::encode(&V::Array(expired)).unwrap(),
                &fixture.requester,
            )
            .unwrap();
            let reply = drivers[0].read_acknowledge(&expired).unwrap();
            assert!(
                !wire::decode(&reply).unwrap().array(7).unwrap()[6]
                    .boolean()
                    .unwrap()
            );
            assert_eq!(drivers[0].reads.len(), MAX_PENDING);
            let mut changed = fields;
            changed[3] = V::Bytes(vec![94; 32]);
            let absent = wire::sign_envelope(
                &wire::encode(&V::Array(changed)).unwrap(),
                &fixture.requester,
            )
            .unwrap();
            drivers[0].read_acknowledge(&absent).unwrap();
            assert_eq!(drivers[0].reads.len(), MAX_PENDING);
            let now = crate::consensus_clock::moment().unwrap();
            let health = ClockHealth::new(now.wall_ms, now.boot_ms, now.boot_ms + 1000, 1)
                .unwrap()
                .frozen();
            let (value, consumed) = store
                .accept_read_consumed(verified, &mut session, health, 0, |_, _| Ok(42))
                .unwrap();
            assert_eq!(value, 42);
            let signed = consumed
                .acknowledgement(&fixture.requester, now.boot_ms + 1000)
                .unwrap();
            let packet = control(&drivers[0], 8, &signed);
            let reply = drivers[0].local_checked(&packet).unwrap();
            let receipt = wire::decode(&reply).unwrap();
            let receipt = receipt.array(7).unwrap();
            assert_eq!(receipt[0].uint().unwrap(), 64);
            assert_eq!(receipt[1].uint().unwrap(), 1);
            assert_eq!(receipt[2], configuration.descriptor().scope().value());
            assert_eq!(receipt[3].fixed::<32>().unwrap(), id);
            assert!(receipt[6].boolean().unwrap());
            assert_eq!(drivers[0].reads.len(), MAX_PENDING - 1);
            assert!(!drivers[0].reads.contains_key(&id));
            Some(signed)
        } else {
            let expires = crate::authority_proof::Challenge::from_signed(&challenge)
                .unwrap()
                .expires_at_ms;
            let now = crate::consensus_clock::moment().unwrap().wall_ms;
            std::thread::sleep(Duration::from_millis(
                expires
                    .saturating_sub(crate::authority_challenge::DELTA_MS)
                    .saturating_add(1)
                    .saturating_sub(now),
            ));
            None
        };
        for directory in &directories {
            runtime_clock(&directory.0);
        }
        let reply = finish(&mut drivers, &signed, &original_challenge);
        let value = wire::decode(&reply).unwrap();
        let fields = value.array(10).unwrap();
        let node = fields[6].bytes().unwrap();
        let ancestry = vec![node.to_vec()];
        let verified = read::verify_response(
            configuration.descriptor(),
            &signed,
            &original_challenge,
            read::Response {
                node,
                certificate: fields[7].bytes().unwrap(),
                result: fields[8].bytes().unwrap(),
                ancestry: &ancestry,
            },
            |_, result, _| read::result_versions(result),
        )
        .unwrap();
        assert_eq!(
            verified.point().prefix(),
            &configuration.descriptor().genesis().unwrap()
        );
        assert!(
            verified.statement.expires_at_ms
                <= crate::authority_proof::Challenge::from_signed(&original_challenge)
                    .unwrap()
                    .expires_at_ms
        );
        assert_eq!(drivers[0].reads.len(), MAX_PENDING);
        if let Some(acknowledgement) = acknowledged {
            let duplicate = drivers[0].read_acknowledge(&acknowledgement).unwrap();
            assert!(
                !wire::decode(&duplicate).unwrap().array(7).unwrap()[6]
                    .boolean()
                    .unwrap()
            );
            assert_eq!(drivers[0].reads.len(), MAX_PENDING);
            assert!(
                drivers[0]
                    .reads
                    .contains_key(&read::read_id(&signed, &original_challenge).unwrap())
            );
        }
    }
    if delayed {
        // A forward wall correction must expire the old quorum even before its monotonic cap.
        let expired_wall = initial.expires_at_ms - crate::authority_challenge::DELTA_MS;
        let reply = drivers[0]
            .read_poll_at(id, started + Duration::from_millis(1500), Ok(expired_wall))
            .unwrap();
        assert_ne!(
            wire::decode(&reply).unwrap().array(10).unwrap()[3]
                .uint()
                .unwrap(),
            1
        );
        let reply = drivers[0]
            .read_poll_at(id, started + Duration::from_millis(5001), Ok(expired_wall))
            .unwrap();
        assert_eq!(
            wire::decode(&reply).unwrap().array(10).unwrap()[3]
                .uint()
                .unwrap(),
            2
        );
        assert!(!drivers[0].reads.contains_key(&id));
    }
    for (driver, (generation, state)) in drivers.iter().zip(before) {
        assert_eq!(driver.engine.generation(), generation);
        assert_eq!(driver.engine.application(), state);
        assert!(driver.requests.is_empty());
        assert!(driver.outbox.is_empty());
    }
    let mut wrong_challenge = wire::decode(&wire::envelope(&challenge, 1).unwrap().0)
        .unwrap()
        .array(12)
        .unwrap()
        .to_vec();
    wrong_challenge[8] = V::Bytes(vec![92; 32]);
    let wrong = wire::sign_envelope(
        &wire::encode(&V::Array(wrong_challenge)).unwrap(),
        &fixture.requester,
    )
    .unwrap();
    assert!(read::read_id(&request, &wrong).is_err());
}
