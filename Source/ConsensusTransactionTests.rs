// SPDX-License-Identifier: MIT
use super::*;
use journal::tests::Directory;
use records::tests::fixture;

pub(super) fn prepared() -> (
    Configuration,
    [SigningKey; 4],
    Vec<Directory>,
    Vec<Engine>,
    Vec<SignedVote>,
) {
    let (config, keys) = fixture();
    let (directories, mut replicas) = tests::engines(&config, &keys);
    tests::enter(&config, &keys, &mut replicas, 1);
    let command = tests::request(&config, 75);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let votes = replicas
        .iter_mut()
        .map(|r| {
            SignedVote::parse(
                &config,
                &r.prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    (config, keys, directories, replicas, votes)
}

fn reopen(engine: Engine, directory: &Path, key: &SigningKey) -> Engine {
    let config = engine.configuration.clone();
    let generation = engine.generation();
    drop(engine);
    Engine::open(directory, config, key.clone(), generation).unwrap()
}

fn commit_votes(
    config: &Configuration,
    replicas: &mut [Engine],
    mut votes: Vec<SignedVote>,
) -> Vec<SignedVote> {
    for _ in 0..2 {
        let qc = Certificate::collect(config, &votes[..3]).unwrap();
        votes = replicas
            .iter_mut()
            .map(|replica| {
                SignedVote::parse(config, &replica.advance_phase(&qc.bytes).unwrap()).unwrap()
            })
            .collect();
    }
    votes
}

#[test]
fn advance_retains_own_wish_and_entry_before_lost_broadcast() {
    for peers in [0, 2] {
        let (config, keys) = fixture();
        let directory = Directory::new();
        let mut target = Engine::create(
            &directory.0,
            config.clone(),
            keys[3].clone(),
            records::tests::initial(),
        )
        .unwrap();
        for key in &keys[..peers] {
            target
                .receive_wish(&synchronizer::sign(&config, 1, key).unwrap())
                .unwrap();
        }
        let generation = target.generation();
        let output = target.advance_view().unwrap();
        assert_eq!(target.generation(), generation + 1);
        let wish = output.wish.unwrap();
        assert_eq!(
            synchronizer::verify(&config, &wish).unwrap(),
            (config.voters[3], 1)
        );
        // Lose all outputs. Restart must retain the own WISH and any entry
        // caused by it before a duplicate loopback can arrive.
        target = reopen(target, &directory.0, &keys[3]);
        assert_eq!(target.snapshot.wishes[3].as_ref(), Some(&wish));
        assert_eq!(target.snapshot.sync.maxima[3], 1);
        assert_eq!(target.view(), if peers == 2 { 1 } else { 0 });
        assert_eq!(target.snapshot.sync.advanced, peers == 0);
        if peers == 2 {
            assert_eq!(
                target.snapshot.reports[&report_id(1, &config.voters[3])],
                output.new_view.unwrap(),
            );
        } else {
            assert!(output.new_view.is_none());
        }
        let duplicate = target.receive_wish(&wish).unwrap();
        assert!(duplicate.wish.is_none() && duplicate.new_view.is_none());
        assert_eq!(target.generation(), generation + 1);
    }
}

#[test]
fn failed_advance_publication_exposes_no_wish_and_requires_reopen() {
    let (config, keys) = fixture();
    let directory = Directory::new();
    let mut target = Engine::create(
        &directory.0,
        config.clone(),
        keys[3].clone(),
        records::tests::initial(),
    )
    .unwrap();
    let generation = target.generation();
    let pending = directory.0.join("SignerPending.bin");
    std::os::unix::fs::symlink("Signer.bin", &pending).unwrap();
    assert!(target.advance_view().is_err());
    assert_eq!(target.generation(), generation);
    assert!(target.snapshot.wishes[3].is_none());
    assert!(!target.snapshot.sync.advanced);
    std::fs::remove_file(pending).unwrap();
    assert!(target.advance_view().is_err());
    assert!(target.retransmit_wish().is_err());
    target = reopen(target, &directory.0, &keys[3]);
    assert_eq!(target.snapshot.sync.maxima, [0; 4]);
    assert!(target.advance_view().unwrap().wish.is_some());
    assert_eq!(target.generation(), generation + 1);
}

#[test]
fn collected_quorums_publish_next_vote_lock_and_decision_before_lost_reply() {
    let (config, keys, directories, mut replicas, mut votes) = prepared();
    let mut target = replicas.pop().unwrap();
    for phase in [Phase::Prepare, Phase::PreCommit, Phase::Commit] {
        let before = target.generation();
        assert!(target.receive_vote(&votes[0].envelope).unwrap().is_none());
        assert_eq!(target.generation(), before + 1);
        let bytes = target.receive_vote(&votes[1].envelope).unwrap().unwrap();
        assert_eq!(target.generation(), before + 2);
        let qc = Certificate::parse(&config, &bytes).unwrap();
        assert_eq!(qc.phase, phase);
        assert_eq!(
            target.snapshot.votes[&vote_id(1, phase, &config.voters[1])],
            votes[1].envelope
        );

        // Lose the returned QC before ordinary local delivery. Reopening must
        // retain both the received evidence and the complete local transition.
        target = reopen(target, &directories[3].0, &keys[3]);
        let generation = target.generation();
        if phase == Phase::Commit {
            assert_eq!(target.committed().unwrap().digest().unwrap(), qc.node);
            assert_eq!(target.applied().unwrap().height, 0);
            assert!(target.execution(qc.node).unwrap().is_none());
            target.decide(&bytes).unwrap();
        } else {
            let following = if phase == Phase::Prepare {
                assert_eq!(target.snapshot.highest_prepare, qc.digest());
                Phase::PreCommit
            } else {
                assert_eq!(target.snapshot.locked, qc.digest());
                Phase::Commit
            };
            let retained =
                target.snapshot.own_votes[&vote_id(1, following, &config.voters[3])].clone();
            assert_eq!(target.advance_phase(&bytes).unwrap(), retained);
        }
        assert_eq!(target.generation(), generation);

        // The fourth signer's evidence is still durable, and equivalent quorum
        // proofs cannot replace the first retained certificate or issue a new vote.
        target.receive_vote(&votes[2].envelope).unwrap().unwrap();
        assert_eq!(target.generation(), generation + 1);
        assert_eq!(target.known_certificate(&qc.digest()).unwrap().bytes, bytes);
        assert_eq!(
            target.snapshot.votes[&vote_id(1, phase, &config.voters[2])],
            votes[2].envelope
        );
        target.receive_vote(&votes[2].envelope).unwrap().unwrap();
        assert_eq!(target.generation(), generation + 1);
        if phase != Phase::Commit {
            votes = replicas
                .iter_mut()
                .map(|r| SignedVote::parse(&config, &r.advance_phase(&bytes).unwrap()).unwrap())
                .collect();
        }
    }
    let generation = target.generation();
    let mut calls = 0;
    assert!(matches!(
        target
            .apply_turn(|_, position| {
                calls += 1;
                Ok(tests::execution(&config, position))
            })
            .unwrap(),
        application::Turn::Result(..)
    ));
    assert_eq!(calls, 1);
    assert_eq!(target.generation(), generation + 1);
    assert_eq!(target.applied().unwrap().height, 1);
}

#[test]
fn direct_child_commit_publishes_reopenable_cursor_before_first_apply() {
    for delivery in ["Decide", "Certificate", "Repair"] {
        let (config, keys, directories, mut replicas, votes) = prepared();
        let votes = commit_votes(&config, &mut replicas, votes);
        let qc = Certificate::collect(&config, &votes[..3]).unwrap();
        let mut target = replicas.pop().unwrap();
        let before = target.generation();
        match delivery {
            "Decide" => target.decide(&qc.bytes).unwrap(),
            "Certificate" => target.receive_certificate(&qc.bytes).unwrap(),
            "Repair" => {
                let reference = repair::Reference {
                    kind: 12,
                    digest: qc.digest(),
                    signer: None,
                };
                let item = repair::Item {
                    reference: reference.clone(),
                    bytes: qc.bytes.clone(),
                };
                assert!(
                    target
                        .repair_import(&[reference], &[item])
                        .unwrap()
                        .is_empty()
                );
            }
            _ => unreachable!(),
        }
        // Repair first installs its verified object closure; the deciding
        // publication itself also retains the ready application cursor.
        assert_eq!(
            target.generation(),
            before + if delivery == "Repair" { 2 } else { 1 }
        );
        assert_eq!(target.snapshot.committed, qc.node);
        assert_eq!(target.applied().unwrap().height, 0);
        assert_eq!(
            Engine::cursor_certificate(&target.snapshot),
            Some(qc.digest())
        );
        assert!(target.execution(qc.node).unwrap().is_none());
        target = reopen(target, &directories[3].0, &keys[3]);
        target.validate_application_cursor().unwrap();

        let generation = target.generation();
        let mut calls = 0;
        assert!(matches!(
            target
                .apply_turn(|_, position| {
                    calls += 1;
                    assert_eq!(position.node, qc.node);
                    Ok(tests::execution(&config, position))
                })
                .unwrap(),
            application::Turn::Result(..)
        ));
        assert_eq!(calls, 1);
        assert_eq!(target.generation(), generation + 1);
        target = reopen(target, &directories[3].0, &keys[3]);
        assert_eq!(target.snapshot.applied, qc.node);
        assert!(target.execution(qc.node).unwrap().is_some());
        assert!(matches!(
            target
                .apply_turn(|_, _| anyhow::bail!("Completed command executed twice"))
                .unwrap(),
            application::Turn::Idle
        ));
    }
}

#[test]
fn failed_direct_child_commit_exposes_no_cursor_or_application_callback() {
    for delivery in ["Votes", "Certificate", "Decide"] {
        let (config, keys, directories, mut replicas, votes) = prepared();
        let votes = commit_votes(&config, &mut replicas, votes);
        let qc = Certificate::collect(&config, &votes[..3]).unwrap();
        let mut target = replicas.pop().unwrap();
        if delivery == "Votes" {
            assert!(target.receive_vote(&votes[0].envelope).unwrap().is_none());
        }
        let deliver = |target: &mut Engine| match delivery {
            "Votes" => target.receive_vote(&votes[1].envelope).map(|_| ()),
            "Certificate" => target.receive_certificate(&qc.bytes),
            "Decide" => target.decide(&qc.bytes),
            _ => unreachable!(),
        };
        let generation = target.generation();
        let pending = directories[3].0.join("SignerPending.bin");
        std::os::unix::fs::symlink("Signer.bin", &pending).unwrap();
        assert!(deliver(&mut target).is_err());
        assert_eq!(target.generation(), generation);
        assert_eq!(target.committed().unwrap().height, 0);
        assert!(target.snapshot.apply_cursor.is_none());
        let mut calls = 0;
        assert!(
            target
                .apply_turn(|_, position| {
                    calls += 1;
                    Ok(tests::execution(&config, position))
                })
                .is_err()
        );
        assert_eq!(calls, 0);
        std::fs::remove_file(pending).unwrap();
        assert!(deliver(&mut target).is_err());
        target = reopen(target, &directories[3].0, &keys[3]);
        assert!(target.snapshot.apply_cursor.is_none());
        deliver(&mut target).unwrap();
        assert_eq!(target.generation(), generation + 1);
        assert!(matches!(
            target
                .apply_turn(|_, position| Ok(tests::execution(&config, position)))
                .unwrap(),
            application::Turn::Result(..)
        ));
    }
}

#[test]
fn later_commit_preserves_cursor_and_longer_suffix_uses_bounded_discovery() {
    let (config, keys, _directories, mut replicas, votes) = prepared();
    let votes = commit_votes(&config, &mut replicas, votes);
    let first = Certificate::collect(&config, &votes[..3]).unwrap();
    // One replica already owns pending application work; another has only
    // prepared the same ancestor when the later CommitQC arrives.
    replicas[0].decide(&first.bytes).unwrap();
    let cursor = serde_json::to_value(&replicas[0].snapshot.apply_cursor).unwrap();
    tests::enter(&config, &keys, &mut replicas, 2);
    let leader = config.member(&config.leader(2).unwrap()).unwrap();
    replicas.swap(0, leader);
    let second = tests::phases(&config, &mut replicas, &tests::request(&config, 76));
    replicas.swap(0, leader);
    for target in &mut replicas[..2] {
        target.decide(&second.bytes).unwrap();
        assert_eq!(target.committed().unwrap().height, 2);
    }
    assert_eq!(
        serde_json::to_value(&replicas[0].snapshot.apply_cursor).unwrap(),
        cursor
    );
    assert!(replicas[1].snapshot.apply_cursor.is_none());
    let generation = replicas[1].generation();
    let mut calls = 0;
    assert!(matches!(
        replicas[1]
            .apply_turn(|_, _| {
                calls += 1;
                anyhow::bail!("Longer suffix executed before durable discovery")
            })
            .unwrap(),
        application::Turn::Progress
    ));
    assert_eq!(calls, 0);
    assert_eq!(replicas[1].generation(), generation + 1);
    assert_eq!(
        Engine::cursor_certificate(&replicas[1].snapshot),
        Some(second.digest())
    );
    for expected in [first.node, second.node] {
        assert!(matches!(
            replicas[1]
                .apply_turn(|_, position| {
                    calls += 1;
                    assert_eq!(position.node, expected);
                    Ok(tests::execution(&config, position))
                })
                .unwrap(),
            application::Turn::Result(..)
        ));
    }
    assert_eq!(calls, 2);
    assert!(matches!(
        replicas[0]
            .apply_turn(|_, position| {
                assert_eq!(position.node, first.node);
                Ok(tests::execution(&config, position))
            })
            .unwrap(),
        application::Turn::Result(..)
    ));
    assert_eq!(replicas[0].applied().unwrap().height, 1);
    assert_eq!(replicas[0].committed().unwrap().height, 2);
}

#[test]
fn failed_collected_quorum_publication_emits_nothing_and_requires_reopen() {
    let (config, keys, directories, mut replicas, votes) = prepared();
    let mut target = replicas.pop().unwrap();
    target.receive_vote(&votes[0].envelope).unwrap();
    let generation = target.generation();
    let pending = directories[3].0.join("SignerPending.bin");
    std::os::unix::fs::symlink("Signer.bin", &pending).unwrap();
    assert!(target.receive_vote(&votes[1].envelope).is_err());
    assert_eq!(target.generation(), generation);
    assert!(!target.snapshot.own_votes.contains_key(&vote_id(
        1,
        Phase::PreCommit,
        &config.voters[3]
    )));
    std::fs::remove_file(pending).unwrap();
    assert!(target.receive_vote(&votes[1].envelope).is_err());
    target = reopen(target, &directories[3].0, &keys[3]);
    assert_eq!(target.generation(), generation);
    assert!(
        !target
            .snapshot
            .votes
            .contains_key(&vote_id(1, Phase::Prepare, &config.voters[1]))
    );
    let qc = target.receive_vote(&votes[1].envelope).unwrap().unwrap();
    assert_eq!(target.generation(), generation + 1);
    let retained =
        target.snapshot.own_votes[&vote_id(1, Phase::PreCommit, &config.voters[3])].clone();
    assert_eq!(target.advance_phase(&qc).unwrap(), retained);
    assert_eq!(target.generation(), generation + 1);
}

#[test]
fn vote_batch_retains_accepted_prefix_before_invalid_evidence() {
    let (config, keys, directories, mut replicas, votes) = prepared();
    let mut target = replicas.pop().unwrap();
    let mut invalid = votes[1].envelope.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let generation = target.generation();
    let outputs = target
        .receive_votes(&[votes[0].envelope.clone(), invalid.clone()])
        .unwrap();
    assert_eq!(outputs, vec![None]);
    assert_eq!(target.generation(), generation + 1);
    assert!(target.receive_vote(&invalid).is_err());
    assert_eq!(target.generation(), generation + 1);
    target = reopen(target, &directories[3].0, &keys[3]);
    assert_eq!(
        target.snapshot.votes[&vote_id(1, Phase::Prepare, &config.voters[0])],
        votes[0].envelope
    );
    assert!(
        !target
            .snapshot
            .votes
            .contains_key(&vote_id(1, Phase::Prepare, &config.voters[1]))
    );
}
