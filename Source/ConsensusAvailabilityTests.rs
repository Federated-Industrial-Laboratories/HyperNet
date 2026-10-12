// SPDX-License-Identifier: MIT
use super::super::super::{id, report_id, synchronizer};
use super::checkpoint_recovery::{apply, phase, prepare, reports, round, wishes};
use super::*;

#[test]
fn view_timer_is_common_one_shot_and_rederived_after_restart() {
    assert_eq!(view_timeout(0), Duration::ZERO);
    assert_eq!(view_timeout(1), Duration::from_millis(1000));
    assert_eq!(view_timeout(2), Duration::from_millis(1250));
    assert_eq!(view_timeout(320), Duration::from_millis(3000));
    assert_eq!(view_timeout(1024), Duration::from_millis(3500));
    assert_eq!(view_timeout(u64::MAX), Duration::from_millis(16750));
    for power in 1..64 {
        let v = 1u64 << power;
        assert!(view_timeout(v) > view_timeout(v - 1));
    }
    assert!(view_deadline(0, Instant::now()).unwrap().is_none());
    let (configuration, keys) = fixture();
    let directory = Directory::new();
    let mut engine = Engine::create(
        &directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    wishes(
        &configuration,
        &keys,
        std::slice::from_mut(&mut engine),
        1024,
    );
    let mailbox = ingress::Mailbox::new();
    let mut driver = repair_driver(
        engine,
        &directory.0,
        &keys,
        configuration.voters[1],
        mailbox,
    );
    driver.expires = Some(Instant::now() - Duration::from_millis(1));
    driver.tick().unwrap();
    driver.drain_local().unwrap();
    assert!(driver.expires.is_none());
    let generation = driver.engine.generation();
    for _ in 0..8 {
        driver.tick().unwrap();
        driver.drain_local().unwrap();
    }
    assert_eq!(driver.engine.generation(), generation);
    assert!(driver.expires.is_none());
    for key in &keys[..3] {
        driver
            .receive(
                key.verifying_key().to_bytes(),
                Message::Wish(synchronizer::sign(&configuration, 1025, key).unwrap()),
            )
            .unwrap();
    }
    assert_eq!(driver.engine.view(), 1025);
    assert!(driver.expires.is_some());
    let generation = driver.engine.generation();
    drop(driver);
    let engine = Engine::open(
        &directory.0,
        configuration.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    let before = Instant::now();
    let driver = repair_driver(
        engine,
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let after = Instant::now();
    let deadline = driver.expires.unwrap();
    assert!(deadline >= before + view_timeout(1025));
    assert!(deadline <= after + view_timeout(1025));
}

#[test]
fn empty_views_reclaim_reports_before_the_old_report_capacity() {
    let (configuration, keys) = fixture();
    let directory = Directory::new();
    let mut engine = Engine::create(
        &directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    for view in 1..=1030 {
        wishes(
            &configuration,
            &keys,
            std::slice::from_mut(&mut engine),
            view,
        );
        assert!(engine.snapshot.reports.len() <= 2);
        assert_eq!(engine.snapshot.nodes.len(), 1);
        assert!(engine.snapshot.checkpoint.is_none());
    }
    assert_eq!(engine.snapshot.retired_view, 1028);
    let generation = engine.generation();
    drop(engine);
    let engine = Engine::open(&directory.0, configuration, keys[0].clone(), generation).unwrap();
    assert_eq!(engine.view(), 1030);
    assert_eq!(engine.snapshot.retired_view, 1028);
}

#[test]
fn failed_views_reclaim_garbage_preserve_lock_and_accept_late_decide() {
    let (configuration, keys) = fixture();
    let (directories, mut replicas) = fixtures::engines(&configuration, &keys);
    replicas.pop();
    wishes(&configuration, &keys, &mut replicas, 1);
    reports(&configuration, &mut replicas, 0, &[0, 1, 2]);
    let command = fixtures::request(&configuration, 70);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let prepared = prepare(
        &configuration,
        &mut replicas,
        &[0, 1, 2],
        &proposal,
        &command,
    );
    let votes: Vec<_> = replicas
        .iter()
        .map(|r| {
            r.snapshot
                .own_votes
                .values()
                .find(|bytes| {
                    SignedVote::parse(&configuration, bytes).unwrap().vote.phase == Phase::Prepare
                })
                .unwrap()
                .clone()
        })
        .collect();
    for vote in votes {
        replicas[0].receive_vote(&vote).unwrap();
    }
    assert_eq!(replicas[0].snapshot.highest_prepare, prepared.digest());
    let precommitted = phase(&configuration, &mut replicas, &[0, 1, 2], &prepared);
    let committed = phase(&configuration, &mut replicas, &[0, 1, 2], &precommitted);
    let lock = replicas[0].snapshot.locked;
    let high = replicas[0].snapshot.highest_prepare;
    let stale_vote = replicas[0]
        .snapshot
        .own_votes
        .values()
        .next()
        .unwrap()
        .clone();
    let mut failed = 0;
    for view in 2..=362 {
        wishes(&configuration, &keys, &mut replicas, view);
        let leader = configuration
            .member(&configuration.leader(view).unwrap())
            .unwrap();
        if leader < 3 {
            reports(&configuration, &mut replicas, leader, &[0, 1, 2]);
            let command = fixtures::request(&configuration, (view % 200 + 1) as u8);
            let proposal = replicas[leader].propose(&command, 10000).unwrap();
            for replica in &mut replicas {
                replica
                    .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                    .unwrap();
            }
            // The votes are withheld in transit; no later PrepareQC is delivered.
            failed += 1;
        }
        for replica in &replicas {
            assert!(replica.snapshot.nodes.len() <= 4);
            assert!(replica.snapshot.commands.len() <= 3);
            assert!(replica.snapshot.reports.len() <= 6);
            assert_eq!(replica.snapshot.locked, lock);
            assert_eq!(replica.snapshot.highest_prepare, high);
            assert_eq!(replica.applied().unwrap().height, 0);
        }
    }
    assert!(failed > 256);
    let mut replica = replicas.remove(0);
    let floor = replica.snapshot.retired_view;
    assert_eq!(floor, 360);
    let generation = replica.generation();
    assert!(replica.receive_vote(&stale_vote).is_err());
    assert!(
        replica
            .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
    assert!(replica.advance_phase(&precommitted.bytes).is_err());
    assert_eq!(replica.generation(), generation);
    drop(replica);
    let mut replica = Engine::open(
        &directories[0].0,
        configuration.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    assert_eq!(replica.snapshot.locked, lock);
    assert_eq!(replica.snapshot.retired_view, floor);
    replica.decide(&committed.bytes).unwrap();
    replica
        .apply_committed(|_, p| Ok(fixtures::execution(&configuration, p)))
        .unwrap();
    assert_eq!(replica.applied().unwrap().height, 1);
    assert_eq!(replica.snapshot.locked, lock);
    assert_eq!(replica.snapshot.retired_view, floor);
    assert!(
        replica
            .snapshot
            .own_votes
            .values()
            .all(|bytes| SignedVote::parse(&configuration, bytes).unwrap().vote.view > floor)
    );
    let generation = replica.generation();
    drop(replica);
    let replica = Engine::open(
        &directories[0].0,
        configuration,
        keys[0].clone(),
        generation,
    )
    .unwrap();
    assert_eq!(replica.applied().unwrap().height, 1);
}

#[test]
fn requested_repair_pivots_across_twenty_positions_without_a_checkpoint() {
    let (configuration, keys) = fixture();
    let (directories, mut replicas) = fixtures::engines(&configuration, &keys);
    let mut lag = replicas.pop().unwrap();
    let mut committed = None;
    for height in 1..=20 {
        committed = Some(round(&configuration, &keys, &mut replicas, height).2);
    }
    let committed = committed.unwrap();
    let view = replicas[0].view();
    assert!(replicas[0].checkpoint_proof().is_none());
    // Voter2 participated previously, then withholds all further messages.
    replicas.pop();
    for index in [0, 1, 3] {
        lag.receive_wish(&synchronizer::sign(&configuration, view, &keys[index]).unwrap())
            .unwrap();
    }
    let source_key = configuration.voters[0];
    let target_key = configuration.voters[3];
    let requests = ingress::Mailbox::new();
    let responses = ingress::Mailbox::new();
    let mut source = repair_driver(
        replicas.remove(0),
        &directories[0].0,
        &keys,
        target_key,
        responses.clone(),
    );
    let mut target = repair_driver(lag, &directories[3].0, &keys, source_key, requests.clone());
    target
        .receive(source_key, Message::Certificate(committed.bytes.clone()))
        .unwrap();
    let mut pivoted = false;
    let mut partial_import = false;
    let mut responses_seen = 0;
    for _ in 0..400 {
        while let Some(bytes) = requests.try_pop().unwrap() {
            let request = peer::decode(&configuration, target_key, &bytes).unwrap();
            if let Message::RepairRequest(_, refs) = &request {
                assert!(refs.len() <= peer::MAX_REPAIR_RECORDS);
                source.receive(target_key, request).unwrap();
            }
        }
        while let Some(bytes) = responses.try_pop().unwrap() {
            let response = peer::decode(&configuration, source_key, &bytes).unwrap();
            if let Message::RepairResponse(_, items) = &response {
                if responses_seen == 0 {
                    let generation = target.engine.generation();
                    assert!(
                        target
                            .receive(source_key, Message::RepairResponse([99; 32], items.clone()))
                            .is_err()
                    );
                    assert_eq!(target.engine.generation(), generation);
                }
                target.receive(source_key, response).unwrap();
                responses_seen += 1;
                for repair in target.repairs.values() {
                    let (wanted, staged, goals, pivots) = repair.retained_counts();
                    assert!(wanted <= 32 && staged <= 32 && goals <= 8);
                    pivoted |= pivots > 0;
                }
                let height = target.engine.applied().unwrap().height;
                assert!(height <= 20);
                partial_import |= height == 0 && target.engine.snapshot.nodes.len() > 1;
            }
        }
        target.apply().unwrap();
        if target.engine.applied().unwrap().height == 20 {
            break;
        }
    }
    assert!(pivoted && partial_import);
    assert!(responses_seen > 10);
    assert!(target.repairs.is_empty());
    assert_eq!(target.engine.snapshot.applied, committed.node);
    assert!(target.engine.checkpoint_proof().is_none());
    let prepare = source
        .engine
        .known_certificate(&source.engine.snapshot.highest_prepare)
        .unwrap();
    target
        .receive(source_key, Message::Certificate(prepare.bytes))
        .unwrap();
    let Driver { engine: source, .. } = source;
    let Driver { engine: target, .. } = target;
    replicas.insert(0, source);
    replicas.push(target);
    let mut next_view = view + 1;
    while configuration.leader(next_view).unwrap() != source_key {
        next_view += 1;
    }
    for replica in &mut replicas {
        for index in [0, 1, 3] {
            replica
                .receive_wish(&synchronizer::sign(&configuration, next_view, &keys[index]).unwrap())
                .unwrap();
        }
    }
    reports(&configuration, &mut replicas, 0, &[0, 1, 2]);
    let command = fixtures::request(&configuration, 91);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let prepared = super::checkpoint_recovery::prepare(
        &configuration,
        &mut replicas,
        &[0, 1, 2],
        &proposal,
        &command,
    );
    let precommitted = phase(&configuration, &mut replicas, &[0, 1, 2], &prepared);
    let committed = phase(&configuration, &mut replicas, &[0, 1, 2], &precommitted);
    apply(&configuration, &mut replicas, &committed);
    assert!(replicas.iter().all(|r| r.applied().unwrap().height == 21));
    let target = replicas.pop().unwrap();
    assert_eq!(target.signer(), target_key);
    let generation = target.generation();
    drop(target);
    let target = Engine::open(
        &directories[3].0,
        configuration.clone(),
        keys[3].clone(),
        generation,
    )
    .unwrap();
    assert_eq!(target.applied().unwrap().height, 21);
    assert!(
        target
            .snapshot
            .reports
            .contains_key(&report_id(next_view, &target_key))
    );
    assert!(target.snapshot.nodes.contains_key(&id(&committed.node)));
}
