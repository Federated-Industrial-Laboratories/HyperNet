// SPDX-License-Identifier: MIT
// Real policy evaluation and signed peer records exercise the volatile collection path.
use super::*;
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_read as read,
};
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
    policy_quorum(false);
}
#[test]
fn fresh_read_delayed_shares_survive_retransmission_and_recollection_until_exact_expiry() {
    policy_quorum(true);
}
fn policy_quorum(delayed: bool) {
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
            5000,
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
