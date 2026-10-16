// SPDX-License-Identifier: MIT
use super::*;
use super::{
    journal::tests::Directory,
    records::tests::{fixture, initial},
    tests as fixtures,
};
use std::fs;

#[test]
fn prepared_branch_beyond_cache_applies_in_bounded_turns_and_restarts() {
    let (config, keys) = fixture();
    let (directories, mut replicas) = fixtures::engines(&config, &keys);
    let mut final_commit = None;
    for view in 1..=260 {
        fixtures::enter(&config, &keys, &mut replicas, view);
        let leader = config.member(&config.leader(view).unwrap()).unwrap();
        let command = if view == 1 {
            fixtures::request(&config, 59)
        } else {
            Command::inert(&config).unwrap()
        };
        let proposal = replicas[leader].propose(&command, 10000).unwrap();
        let votes: Vec<_> = replicas
            .iter_mut()
            .take(3)
            .map(|r| {
                SignedVote::parse(
                    &config,
                    &r.prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        let prepared = Certificate::collect(&config, &votes).unwrap();
        // The fourth replica also needs the certified node closure if it was not
        // this view's leader. Its normal Prepare handler installs the same body.
        replicas[3]
            .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
            .unwrap();
        let precommit_votes: Vec<_> = replicas
            .iter_mut()
            .map(|r| {
                SignedVote::parse(&config, &r.advance_phase(&prepared.bytes).unwrap()).unwrap()
            })
            .collect();
        if view == 260 {
            let precommitted = Certificate::collect(&config, &precommit_votes[..3]).unwrap();
            let commit_votes: Vec<_> = replicas
                .iter_mut()
                .take(3)
                .map(|r| {
                    SignedVote::parse(&config, &r.advance_phase(&precommitted.bytes).unwrap())
                        .unwrap()
                })
                .collect();
            final_commit = Some(Certificate::collect(&config, &commit_votes).unwrap());
        }
    }
    assert!(
        replicas
            .iter()
            .all(|r| r.applied().unwrap().height == 0 && r.checkpoint_proof().is_none())
    );
    assert!(replicas[0].snapshot.nodes.len() > 256);
    let commit = final_commit.unwrap();
    for r in &mut replicas {
        r.decide(&commit.bytes).unwrap();
    }
    // Cursor discovery spans five bounded turns. No application callback runs
    // until its complete exact path to the durable applied base is established.
    for r in &mut replicas {
        for _ in 0..5 {
            let mut calls = 0;
            let turn = r
                .apply_turn(|_, _| {
                    calls += 1;
                    anyhow::bail!("Discovery executed early")
                })
                .unwrap();
            assert!(matches!(turn, application::Turn::Progress));
            assert_eq!(calls, 0);
        }
        assert_eq!(r.applied().unwrap().height, 0);
    }
    // Apply two intervals without certification; the third interval must wait.
    for _ in 0..64 {
        for r in &mut replicas {
            let mut calls = 0;
            r.apply_turn(|_, p| {
                calls += 1;
                Ok(fixtures::execution(&config, p))
            })
            .unwrap();
            assert_eq!(calls, 1);
        }
    }
    for r in &mut replicas {
        assert_eq!(r.applied().unwrap().height, 64);
        assert!(matches!(
            r.apply_turn(|_, _| anyhow::bail!("Full candidates executed"))
                .unwrap(),
            application::Turn::Blocked(_)
        ));
        assert_eq!(r.snapshot.executed.len(), 1);
    }
    let generations: Vec<_> = replicas.iter().map(Engine::generation).collect();
    let locks: Vec<_> = replicas.iter().map(|r| r.snapshot.locked).collect();
    drop(replicas);
    let mut replicas: Vec<_> = (0..4)
        .map(|i| {
            Engine::open(
                &directories[i].0,
                config.clone(),
                keys[i].clone(),
                generations[i],
            )
            .unwrap()
        })
        .collect();
    for i in 0..4 {
        assert_eq!(replicas[i].snapshot.locked, locks[i]);
    }
    loop {
        let shares: Vec<_> = replicas
            .iter()
            .take(3)
            .map(|r| checkpoint::share(&config, r.checkpoint_shares().last().unwrap()).unwrap())
            .collect();
        assert!(shares.iter().all(|s| s.0 == shares[0].0));
        let sigs = shares.iter().map(|(_, key, sig)| (*key, *sig)).collect();
        let proof = replicas[0].combine_checkpoint(&shares[0].0, &sigs).unwrap();
        assert_eq!(wire::decode(&proof).unwrap().array(4).unwrap().len(), 4);
        for r in &mut replicas {
            r.accept_checkpoint(&proof, Some(20000)).unwrap();
        }
        let goal = (replicas[0].applied().unwrap().height + 32).min(260);
        while replicas[0].applied().unwrap().height < goal {
            for r in &mut replicas {
                let mut calls = 0;
                r.apply_turn(|_, p| {
                    calls += 1;
                    Ok(fixtures::execution(&config, p))
                })
                .unwrap();
                assert_eq!(calls, 1);
            }
        }
        if goal == 260 {
            break;
        }
    }
    for r in &mut replicas {
        assert_eq!(r.applied().unwrap().height, 260);
        assert!(r.snapshot.executed.is_empty());
        assert_eq!(r.archive.leaves().len(), 260);
        assert!(r.snapshot.nodes.len() <= 8);
        assert!(matches!(
            r.apply_turn(|_, _| anyhow::bail!("Idle executed")).unwrap(),
            application::Turn::Idle
        ));
    }
    let g = replicas[0].generation();
    let state = replicas[0].application().to_vec();
    drop(replicas);
    let reopened = Engine::open(&directories[0].0, config, keys[0].clone(), g).unwrap();
    assert_eq!(reopened.application(), state);
    assert_eq!(reopened.applied().unwrap().height, 260);
}

#[test]
fn immutable_objects_recover_unpublished_suffix_and_refuse_committed_corruption() {
    let (config, keys) = fixture();
    let d = Directory::new();
    let engine = Engine::create(&d.0, config.clone(), keys[0].clone(), initial()).unwrap();
    let store = objects(&engine.snapshot).unwrap();
    let orphan = store
        .staged(22, [90; 32], &wire::encode(&V::Bool(true)).unwrap())
        .unwrap();
    store.publish(&orphan).unwrap();
    store.sync().unwrap();
    let path = d.0.join("Objects").join(orphan.key());
    assert!(path.exists());
    let generation = engine.generation();
    drop(engine);
    let engine = Engine::open(&d.0, config.clone(), keys[0].clone(), generation).unwrap();
    assert!(!path.exists());
    let committed = engine.snapshot.nodes.values().next().unwrap().key();
    drop(engine);
    let path = d.0.join("Objects").join(committed);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(path, bytes).unwrap();
    assert!(Engine::open(&d.0, config, keys[0].clone(), generation).is_err());
}

#[test]
fn state_roots_refuse_corruption_invalid_descriptors_and_old_format_on_reopen() {
    for fault in ["Missing", "Corrupt", "Identity", "Kind", "Format"] {
        let (config, keys) = fixture();
        let directory = Directory::new();
        let mut engine =
            Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
        let object = engine.snapshot.application.object.clone();
        assert!(
            engine
                .repair_export(&[repair::Reference {
                    kind: storage::APPLICATION_STATE as u64,
                    digest: object.identity,
                    signer: None
                }])
                .is_err()
        );
        let path = directory.0.join("Objects").join(object.key());
        match fault {
            "Missing" => fs::remove_file(path).unwrap(),
            "Corrupt" => {
                let mut bytes = fs::read(&path).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(path, bytes).unwrap();
            }
            "Identity" => {
                let store = engine.snapshot.objects.as_ref().unwrap();
                let different = store
                    .staged(storage::APPLICATION_STATE, [91; 32], engine.application())
                    .unwrap();
                store.publish(&different).unwrap();
                store.sync().unwrap();
                engine.snapshot.application.object = different;
                engine.journal.commit(&engine.snapshot).unwrap();
            }
            "Kind" => {
                engine.snapshot.application.object.kind = storage::EXECUTION;
                engine.journal.commit(&engine.snapshot).unwrap();
            }
            "Format" => {
                engine.snapshot.version = 2;
                engine.journal.commit(&engine.snapshot).unwrap();
            }
            _ => unreachable!(),
        }
        let generation = engine.generation();
        drop(engine);
        assert!(
            Engine::open(&directory.0, config, keys[0].clone(), generation).is_err(),
            "{fault}"
        );
    }
}

#[test]
fn failed_state_or_journal_publication_reopens_old_application_before_retry() {
    for fault in ["State", "Journal"] {
        let (config, keys, directories, mut replicas, votes) = transaction_tests::prepared();
        let mut qc = Certificate::collect(&config, &votes[..3]).unwrap();
        for _ in 0..2 {
            let votes: Vec<_> = replicas
                .iter_mut()
                .map(|replica| {
                    SignedVote::parse(&config, &replica.advance_phase(&qc.bytes).unwrap()).unwrap()
                })
                .collect();
            qc = Certificate::collect(&config, &votes[..3]).unwrap();
        }
        let mut target = replicas.pop().unwrap();
        target.decide(&qc.bytes).unwrap();
        assert!(matches!(
            target
                .apply_turn(|_, _| anyhow::bail!("Discovery executed early"))
                .unwrap(),
            application::Turn::Progress
        ));
        let before = target.application().to_vec();
        let old_path = directories[3]
            .0
            .join("Objects")
            .join(target.snapshot.application.object.key());
        let state =
            wire::encode_state(&V::Array(vec![V::Uint(1), V::Bytes(vec![173; 128 * 1024])]))
                .unwrap();
        let store = target.snapshot.objects.as_ref().unwrap().clone();
        let staged = storage::StateObject::staged(&store, state.clone()).unwrap();
        let state_path = directories[3].0.join("Objects").join(staged.object.key());
        let obstruction = if fault == "State" {
            std::os::unix::fs::symlink(old_path.file_name().unwrap(), &state_path).unwrap();
            state_path.clone()
        } else {
            let path = directories[3].0.join("SignerPending.bin");
            std::os::unix::fs::symlink("Signer.bin", &path).unwrap();
            path
        };
        let execution = |_: &[u8], position: &Committed| -> Result<Execution> {
            let mut execution = fixtures::execution(&config, position);
            execution.state = state.clone();
            if let ExecutionOutput::Result { attestation, .. } = &mut execution.output {
                let mut fields = wire::decode(attestation)?.array(23)?.to_vec();
                fields[16] = V::Bytes(wire::digest(&state).to_vec());
                *attestation = wire::encode(&V::Array(fields))?;
            }
            Ok(execution)
        };
        let generation = target.generation();
        assert!(target.apply_turn(execution).is_err());
        assert_eq!(target.generation(), generation);
        assert_eq!(target.application(), before);
        assert!(target.execution(qc.node).unwrap().is_none());
        fs::remove_file(obstruction).unwrap();
        assert!(
            target
                .apply_turn(|_, _| anyhow::bail!("Poisoned signer executed"))
                .is_err()
        );
        drop(target);
        let mut target = Engine::open(
            &directories[3].0,
            config.clone(),
            keys[3].clone(),
            generation,
        )
        .unwrap();
        assert_eq!(target.application(), before);
        assert!(target.archive.leaves().is_empty());
        assert!(!state_path.exists());
        assert!(old_path.exists());
        assert!(matches!(
            target.apply_turn(execution).unwrap(),
            application::Turn::Result(..)
        ));
        assert_eq!(target.application(), state);
        assert_eq!(target.archive.leaves(), &[qc.node]);
        assert!(state_path.exists());
        assert!(!old_path.exists());
    }
}

#[test]
fn object_directory_flushes_follow_creations_and_removals() {
    let (config, keys) = fixture();
    let directory = Directory::new();
    let mut engine =
        Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
    let store = engine.snapshot.objects.as_ref().unwrap().clone();
    let initial_syncs = store.sync_counts();
    assert!(initial_syncs.0 > 0 && initial_syncs.1 > 0);
    Engine::publish_objects(&engine.snapshot).unwrap();
    assert_eq!(store.sync_counts(), initial_syncs);
    let before = engine.generation();
    engine.advance_view().unwrap();
    assert!(engine.generation() > before);
    assert_eq!(store.sync_counts(), initial_syncs);

    let command = fixtures::request(&config, 81);
    let digest = wire::digest(&command);
    let object = store.staged(22, digest, &command).unwrap();
    let path = directory.0.join("Objects").join(object.key());
    let mut staged = engine.snapshot.clone();
    staged.commands.insert(id(&digest), object);
    Engine::publish_objects(&staged).unwrap();
    assert!(path.exists());
    assert_eq!(
        store.sync_counts(),
        (initial_syncs.0 + 1, initial_syncs.1 + 1)
    );
    Engine::publish_objects(&staged).unwrap();
    assert_eq!(
        store.sync_counts(),
        (initial_syncs.0 + 1, initial_syncs.1 + 1)
    );
    drop(staged);

    engine.collect_objects().unwrap();
    assert!(!path.exists());
    assert_eq!(
        store.sync_counts(),
        (initial_syncs.0 + 1, initial_syncs.1 + 2)
    );
    engine.collect_objects().unwrap();
    assert_eq!(
        store.sync_counts(),
        (initial_syncs.0 + 1, initial_syncs.1 + 2)
    );
    let generation = engine.generation();
    drop(engine);
    let engine = Engine::open(&directory.0, config, keys[0].clone(), generation).unwrap();
    assert_eq!(objects(&engine.snapshot).unwrap().sync_counts(), (0, 0));
    assert_eq!(engine.generation(), generation);
}

#[test]
fn explicit_inert_command_rejects_tags_scope_and_result_outputs() {
    let (config, _) = fixture();
    let command = Command::inert(&config).unwrap();
    assert!(command.len() <= 256);
    assert!(matches!(
        Command::parse(&config, &command).unwrap(),
        Command::Inert
    ));
    let mut tagged = wire::decode(&command).unwrap().array(4).unwrap().to_vec();
    tagged[3] = V::Bytes([1; 32].to_vec());
    assert!(
        matches!(Command::parse(&config, &wire::encode(&V::Array(tagged)).unwrap()).unwrap(), Command::Noop(target) if target == [1; 32])
    );
    let position = Committed {
        node: [2; 32],
        height: 1,

        evaluated_at: 10000,
        command,
    };
    assert!(
        validate_execution(
            &config,
            &position,
            &Execution {
                state: initial(),
                output: ExecutionOutput::Result {
                    result: vec![],
                    attestation: vec![]
                }
            }
        )
        .is_err()
    );
}

#[test]
fn unexpired_results_pause_before_execution_until_conservative_expiry() {
    let (config, keys) = fixture();
    let directory = Directory::new();
    let mut engine =
        Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
    for height in 1..=64 {
        checkpoint::tests::step(&mut engine, &keys, height);
        if height % 32 == 0 {
            let statement = checkpoint::share(&config, engine.checkpoint_shares().last().unwrap())
                .unwrap()
                .0;
            let signatures = keys[..3]
                .iter()
                .map(|key| {
                    wire::envelope(&wire::sign_envelope(&statement, key).unwrap(), 1)
                        .unwrap()
                        .1[0]
                })
                .collect();
            let proof = engine.combine_checkpoint(&statement, &signatures).unwrap();
            // Certificate acceptance is not evidence that existing reply deadlines expired.
            engine.accept_checkpoint(&proof, None).unwrap();
        }
    }
    assert_eq!(engine.snapshot.executed.len(), 64);
    checkpoint::tests::step(&mut engine, &keys, 65);
    assert_eq!(engine.committed().unwrap().height, 65);
    assert_eq!(engine.applied().unwrap().height, 64);
    let mut calls = 0;
    assert!(matches!(
        engine
            .apply_turn(|_, p| {
                calls += 1;
                Ok(fixtures::execution(&config, p))
            })
            .unwrap(),
        application::Turn::Blocked(_)
    ));
    assert_eq!(calls, 0);
    let expires = engine
        .snapshot
        .executed
        .values()
        .map(|record| record.expires)
        .max()
        .unwrap();
    engine.compact(Some(expires - 1)).unwrap();
    assert_eq!(engine.snapshot.executed.len(), 64);
    assert!(matches!(
        engine
            .apply_turn(|_, _| anyhow::bail!("Early expiry executed"))
            .unwrap(),
        application::Turn::Blocked(_)
    ));
    engine.compact(Some(expires)).unwrap();
    assert!(engine.snapshot.executed.is_empty());
    engine
        .apply_turn(|_, p| {
            calls += 1;
            Ok(fixtures::execution(&config, p))
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(engine.applied().unwrap().height, 65);
    assert_eq!(engine.snapshot.executed.len(), 1);
}

#[test]
fn oversized_canonical_command_is_refused_before_proposal_or_vote_publication() {
    let (config, keys) = fixture();
    let (_directories, mut replicas) = fixtures::engines(&config, &keys);
    fixtures::enter(&config, &keys, &mut replicas, 1);
    let original = fixtures::request(&config, 71);
    let mut command = wire::decode(&original).unwrap().array(6).unwrap().to_vec();
    let (intent, _) = wire::envelope(command[3].bytes().unwrap(), 1).unwrap();
    let mut intent = wire::decode(&intent).unwrap().array(17).unwrap().to_vec();
    intent[16] = V::Bytes(wire::encode(&V::Bytes(vec![42; 98304])).unwrap());
    let intent = wire::encode(&V::Array(intent)).unwrap();
    let (challenge, _) = wire::envelope(command[4].bytes().unwrap(), 1).unwrap();
    let mut challenge = wire::decode(&challenge)
        .unwrap()
        .array(12)
        .unwrap()
        .to_vec();
    challenge[7] = V::Bytes(wire::digest(&intent).to_vec());
    command[3] =
        V::Bytes(wire::sign_envelope(&intent, &SigningKey::from_bytes(&[30; 32])).unwrap());
    command[4] = V::Bytes(
        wire::sign_envelope(
            &wire::encode(&V::Array(challenge)).unwrap(),
            &SigningKey::from_bytes(&[31; 32]),
        )
        .unwrap(),
    );
    let command = wire::encode(&V::Array(command)).unwrap();
    assert!(command.len() > storage::maximum(22).unwrap());
    assert!(Command::parse(&config, &command).is_ok());
    let generation = replicas[0].generation();
    assert!(replicas[0].propose(&command, 10000).is_err());
    assert_eq!(replicas[0].generation(), generation);
    assert!(replicas[0].current_proposal().is_none());
    assert!(replicas[0].snapshot.commands.is_empty());
    let n = Node {
        scope: config.scope.clone(),
        height: 1,
        view: 1,
        parent: Some(config.genesis().digest().unwrap()),
        command: Some(wire::digest(&command)),
        evaluated_at: 10000,
        justify: Some(config.genesis_qc().unwrap().digest()),
    };
    let proposal = wire::sign_envelope(&n.encode().unwrap(), &keys[0]).unwrap();
    let generation = replicas[1].generation();
    assert!(
        replicas[1]
            .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
    assert_eq!(replicas[1].generation(), generation);
    assert!(replicas[1].snapshot.own_votes.is_empty());
}

#[test]
fn excess_actual_file_allocation_refuses_signer_restart() {
    use std::os::fd::AsRawFd;
    let (config, keys) = fixture();
    let directory = Directory::new();
    let engine = Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
    let object = engine.snapshot.nodes.values().next().unwrap().clone();
    let generation = engine.generation();
    drop(engine);
    let file = fs::OpenOptions::new()
        .write(true)
        .open(directory.0.join("Objects").join(object.key()))
        .unwrap();
    let result = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_KEEP_SIZE,
            0,
            (object.charged() * 2) as i64,
        )
    };
    assert_eq!(
        result,
        0,
        "Owned filesystem cannot exercise allocation accounting: {}",
        std::io::Error::last_os_error()
    );
    file.sync_all().unwrap();
    drop(file);
    assert!(Engine::open(&directory.0, config, keys[0].clone(), generation).is_err());
}
