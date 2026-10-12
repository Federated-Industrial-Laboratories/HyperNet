// SPDX-License-Identifier: MIT
use super::super::{
    journal::tests::Directory,
    records::tests::{fixture, initial},
    tests as fixture_tests,
};
use super::*;
use crate::authority_history;
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
};

pub(crate) fn step(engine: &mut Engine, keys: &[SigningKey; 4], serial: u64) -> Vec<u8> {
    step_with_state(engine, keys, serial, None)
}
fn step_with_state(
    engine: &mut Engine,
    keys: &[SigningKey; 4],
    serial: u64,
    state: Option<&[u8]>,
) -> Vec<u8> {
    let config = engine.configuration().clone();
    let view = serial;
    for key in &keys[..3] {
        engine
            .receive_wish(&synchronizer::sign(&config, view, key).unwrap())
            .unwrap();
    }
    assert_eq!(engine.view(), view);
    let qc = engine
        .known_certificate(&engine.snapshot.highest_prepare)
        .unwrap();
    let parent = engine.known_node(&qc.node).unwrap();
    let command = fixture_tests::request(&config, (serial % 200 + 1) as u8);
    let n = Node {
        scope: config.scope.clone(),
        view,
        height: parent.height + 1,
        parent: Some(qc.node),
        command: Some(wire::digest(&command)),
        evaluated_at: 10000,
        justify: Some(qc.digest()),
    };
    let leader = &keys[config.member(&config.leader(view).unwrap()).unwrap()];
    let proposal = wire::sign_envelope(&n.encode().unwrap(), leader).unwrap();
    engine
        .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
    let mut commit = vec![];
    for phase in [Phase::Prepare, Phase::PreCommit, Phase::Commit] {
        let votes: Vec<_> = keys[..3]
            .iter()
            .map(|k| {
                SignedVote::sign(
                    &config,
                    Vote {
                        scope: config.scope.clone(),
                        view,
                        phase,
                        node: n.digest().unwrap(),
                    },
                    k,
                )
                .unwrap()
            })
            .collect();
        let qc = Certificate::collect(&config, &votes).unwrap();
        if phase == Phase::Commit {
            engine.decide(&qc.bytes).unwrap();
            commit = qc.bytes;
        } else {
            engine.advance_phase(&qc.bytes).unwrap();
        }
    }
    engine
        .apply_committed(|_, p| {
            let mut execution = fixture_tests::execution(&config, p);
            if let Some(state) = state {
                execution.state = state.to_vec();
                if let ExecutionOutput::Result { attestation, .. } = &mut execution.output {
                    let mut fields = wire::decode(attestation)?.array(23)?.to_vec();
                    fields[16] = V::Bytes(wire::digest(state).to_vec());
                    *attestation = wire::encode(&V::Array(fields))?;
                }
            }
            Ok(execution)
        })
        .unwrap();
    commit
}
pub(crate) fn certify(engine: &mut Engine, keys: &[SigningKey; 4]) -> Vec<u8> {
    let share_bytes = engine.checkpoint_shares().last().unwrap().clone();
    let statement = share(engine.configuration(), &share_bytes).unwrap().0;
    let signatures = keys[..3]
        .iter()
        .map(|key| {
            let (_, s) = wire::envelope(&wire::sign_envelope(&statement, key).unwrap(), 1).unwrap();
            s[0]
        })
        .collect();
    let proof = engine.combine_checkpoint(&statement, &signatures).unwrap();
    engine.accept_checkpoint(&proof, Some(20000)).unwrap();
    proof
}

#[test]
fn archive_crash_suffix_and_corruption_follow_journal_boundaries() {
    let d = Directory::new();
    let scope = [7; 32];
    let value = [8; 32];
    let mut a = archive::Archive::open(&d.0, scope, 0, archive::empty_root()).unwrap();
    a.append(0, archive::empty_root(), &[value]).unwrap();
    drop(a);
    let mut a = archive::Archive::open(&d.0, scope, 0, archive::empty_root()).unwrap();
    assert!(a.leaves().is_empty());
    a.append(0, archive::empty_root(), &[value]).unwrap();
    let root = a.tree_root();
    drop(a);
    let a = archive::Archive::open(&d.0, scope, 1, root).unwrap();
    assert_eq!(a.leaves(), &[value]);
    drop(a);
    let mut f = OpenOptions::new()
        .write(true)
        .open(d.0.join("History.bin"))
        .unwrap();
    f.seek(SeekFrom::Start(48)).unwrap();
    f.write_all(&[99]).unwrap();
    f.sync_all().unwrap();
    drop(f);
    assert!(archive::Archive::open(&d.0, scope, 1, root).is_err());
}

#[test]
fn generated_merkle_paths_match_independent_verifier() {
    let leaves: Vec<Digest> = (0..129u64)
        .map(|n| wire::digest(&n.to_be_bytes()))
        .collect();
    for size in [1usize, 2, 3, 7, 8, 9, 31, 32, 33, 64, 65, 128, 129] {
        let root = archive::root(&leaves[..size]);
        for index in [0, size / 2, size - 1] {
            let path = archive::inclusion(&leaves[..size], index).unwrap();
            authority_history::verify_inclusion(
                &leaves[index],
                index as u64,
                size as u64,
                &root,
                &path,
            )
            .unwrap();
            let mut extra = path;
            extra.push([0; 32]);
            assert!(
                authority_history::verify_inclusion(
                    &leaves[index],
                    index as u64,
                    size as u64,
                    &root,
                    &extra
                )
                .is_err()
            );
        }
        for old in [1usize, size / 2 + 1, size] {
            let proof = archive::consistency(&leaves[..size], old).unwrap();
            authority_history::verify_consistency(
                old as u64,
                &archive::root(&leaves[..old]),
                size as u64,
                &root,
                &proof,
            )
            .unwrap();
        }
    }
}

#[test]
fn compaction_progresses_beyond_memory_bound_and_preserves_restart_history() {
    let (config, keys) = fixture();
    let d = Directory::new();
    let lag_dir = Directory::new();
    let mut engine = Engine::create(&d.0, config.clone(), keys[0].clone(), initial()).unwrap();
    let mut lag = Engine::create(&lag_dir.0, config.clone(), keys[1].clone(), initial()).unwrap();
    let mut first = None;
    let mut proof = vec![];
    let mut prior_root = None;
    for height in 1..=288 {
        let commit = step(&mut engine, &keys, height);
        if height == 1 {
            first = Some(engine.snapshot.applied);
            for key in &keys[..3] {
                lag.receive_wish(&synchronizer::sign(&config, 1, key).unwrap())
                    .unwrap();
            }
            let n = engine.applied().unwrap();
            let command = engine.command(&n.command.unwrap()).unwrap();
            lag.prepare(
                &wire::sign_envelope(&n.encode().unwrap(), &keys[0]).unwrap(),
                &command,
                |_| Ok(()),
                |_, _| Ok(()),
            )
            .unwrap();
            lag.decide(&commit).unwrap();
            lag.apply_committed(|_, p| Ok(fixture_tests::execution(&config, p)))
                .unwrap();
        }
        if height % 32 == 0 {
            proof = certify(&mut engine, &keys);
            if height == 32 {
                prior_root = Some(engine.snapshot.archive_root);
            }
        }
        if height == 140 {
            let generation = engine.generation();
            let votes = engine.snapshot.own_votes.clone();
            let locked = engine.snapshot.locked;
            drop(engine);
            engine = Engine::open(&d.0, config.clone(), keys[0].clone(), generation).unwrap();
            assert_eq!(engine.snapshot.own_votes, votes);
            assert_eq!(engine.snapshot.locked, locked);
        }
        assert!(engine.snapshot.nodes.len() <= 70);
        assert!(engine.snapshot.votes.len() <= 110);
    }
    assert_eq!(engine.archive.leaves().len(), 288);
    assert_eq!(engine.applied().unwrap().height, 288);
    let reply = engine
        .history_reply(1, first.unwrap(), engine.snapshot.applied, 0, None)
        .unwrap();
    let reply = wire::decode(&reply).unwrap();
    let a = record(&reply, 54, 7).unwrap();
    let c = verified(&config, a[4].bytes().unwrap()).unwrap();
    let history = wire::decode(a[5].bytes().unwrap()).unwrap();
    let h = record(&history, 47, 10).unwrap();
    let inclusion: Vec<_> = h[6]
        .list(64)
        .unwrap()
        .iter()
        .map(V::fixed)
        .collect::<Result<Vec<Digest>>>()
        .unwrap();
    authority_history::verify_inclusion(&first.unwrap(), 0, 288, c.head().root(), &inclusion)
        .unwrap();
    let from32 = engine.archive.leaves()[31];
    let reply = engine
        .history_reply(32, from32, engine.snapshot.applied, 32, prior_root)
        .unwrap();
    let r = wire::decode(&reply).unwrap();
    let h = wire::decode(r.array(7).unwrap()[5].bytes().unwrap()).unwrap();
    let hashes = h.array(10).unwrap()[9]
        .list(64)
        .unwrap()
        .iter()
        .map(V::fixed)
        .collect::<Result<Vec<Digest>>>()
        .unwrap();
    authority_history::verify_consistency(32, &prior_root.unwrap(), 288, c.head().root(), &hashes)
        .unwrap();
    assert!(
        engine
            .history_reply(1, [77; 32], engine.snapshot.applied, 0, None)
            .is_err()
    );
    let old_votes = lag.snapshot.own_votes.clone();
    let old_view = lag.view();
    let old_lock = lag.snapshot.locked;
    let state = engine.checkpoint_state(*c.digest()).unwrap().to_vec();
    let leaves = engine.archive.leaves().to_vec();
    let mut corrupt = leaves.clone();
    corrupt[0] = [42; 32];
    let generation = lag.generation();
    assert!(
        lag.install_checkpoint(&proof, &state, &corrupt, |_, _| Ok(()), Some(20000))
            .is_err()
    );
    assert_eq!(lag.generation(), generation);
    lag.install_checkpoint(
        &proof,
        &state,
        &leaves,
        |state, height| {
            ensure!(
                wire::decode(state)?.array(1)?[0].uint()? == height,
                "Application height differs"
            );
            Ok(())
        },
        Some(20000),
    )
    .unwrap();
    assert_eq!(lag.snapshot.own_votes, old_votes);
    assert_eq!(lag.view(), old_view);
    assert_eq!(lag.snapshot.locked, old_lock);
    let generation = lag.generation();
    drop(lag);
    let mut lag = Engine::open(&lag_dir.0, config.clone(), keys[1].clone(), generation).unwrap();
    assert_eq!(lag.applied().unwrap().height, 288);
    let high = engine
        .known_certificate(&engine.snapshot.highest_prepare)
        .unwrap();
    let item = repair::Item {
        reference: repair::Reference {
            kind: 12,
            digest: high.digest(),
            signer: None,
        },
        bytes: high.bytes,
    };
    lag.repair_import(
        std::slice::from_ref(&item.reference),
        std::slice::from_ref(&item),
    )
    .unwrap();
    step(&mut lag, &keys, 289);
    assert_eq!(lag.applied().unwrap().height, 289);
}

#[test]
fn uncertified_candidates_pause_application_without_blocking_phase_progress() {
    let (config, keys) = fixture();
    let d = Directory::new();
    let mut engine = Engine::create(&d.0, config, keys[0].clone(), initial()).unwrap();
    let mut retired = Vec::new();
    for height in 1..=64 {
        let commit = step(&mut engine, &keys, height);
        if height == 1 {
            let n = engine.applied().unwrap();
            let qc = Certificate::parse(engine.configuration(), &commit).unwrap();
            let references: Vec<_> = [
                (14, n.digest().unwrap()),
                (22, n.command.unwrap()),
                (12, qc.digest()),
            ]
            .into_iter()
            .map(|(kind, digest)| repair::Reference {
                kind,
                digest,
                signer: None,
            })
            .collect();
            retired = engine.repair_export(&references).unwrap();
            assert_eq!(retired.len(), 3);
        }
    }
    assert_eq!(engine.snapshot.candidates.len(), 2);
    assert_eq!(engine.snapshot.retired_view, 62);
    assert_eq!(engine.snapshot.nodes.len(), 65);
    assert!(engine.checkpoint_admission(65).is_ok());
    step(&mut engine, &keys, 65);
    assert_eq!(engine.committed().unwrap().height, 65);
    assert_eq!(engine.applied().unwrap().height, 64);
    certify(&mut engine, &keys);
    let generation = engine.generation();
    let references: Vec<_> = retired.iter().map(|item| item.reference.clone()).collect();
    assert!(engine.repair_import(&references, &retired).is_err());
    assert_eq!(engine.generation(), generation);
    assert!(engine.checkpoint_admission(65).is_ok());
    let config = engine.configuration.clone();
    engine
        .apply_committed(|_, p| Ok(fixture_tests::execution(&config, p)))
        .unwrap();
    assert_eq!(engine.applied().unwrap().height, 65);
    let prior = engine.archive.leaves()[63];
    assert!(
        !extends(
            &engine.configuration,
            &engine.snapshot,
            prior,
            engine.snapshot.applied
        )
        .unwrap()
    );
    assert!(
        extends(
            &engine.configuration,
            &engine.snapshot,
            engine.snapshot.applied,
            prior
        )
        .unwrap()
    );
}

#[test]
fn expanded_state_crosses_wire_bound_through_journal_checkpoint_and_restart() {
    let (config, keys) = fixture();
    let directory = Directory::new();
    let mut engine =
        Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
    for height in 1..32 {
        step(&mut engine, &keys, height);
    }
    let state = wire::encode_state(&V::Array(vec![
        V::Uint(32),
        V::Bytes(vec![255; 1024 * 1024]),
    ]))
    .unwrap();
    assert!(wire::decode(&state).is_err());
    step_with_state(&mut engine, &keys, 32, Some(&state));
    let proof = certify(&mut engine, &keys);
    let leaves = engine.archive.leaves().to_vec();
    let verified = verified(&config, &proof).unwrap();
    let mut chunks = Vec::new();
    for (index, data) in state.chunks(CHUNK).enumerate() {
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(48),
            V::Uint(1),
            V::Bytes(verified.digest().to_vec()),
            V::Uint(state.len() as u64),
            V::Uint(index as u64),
            V::Bytes(data.to_vec()),
        ]))
        .unwrap();
        chunks.extend(chunk(&bytes).unwrap().3);
    }
    assert_eq!(chunks, state);
    let generation = engine.generation();
    drop(engine);
    let resumed = Engine::open(&directory.0, config.clone(), keys[0].clone(), generation).unwrap();
    assert_eq!(resumed.snapshot.application, state);
    let target = Directory::new();
    let mut lag = Engine::create(&target.0, config.clone(), keys[1].clone(), initial()).unwrap();
    lag.install_checkpoint(
        &proof,
        &chunks,
        &leaves,
        |value, height| {
            ensure!(
                wire::decode_state(value)?.array(2)?[0].uint()? == height,
                "checkpoint height differs"
            );
            Ok(())
        },
        Some(20000),
    )
    .unwrap();
    assert_eq!(lag.snapshot.application, state);
    let floor = lag.generation();
    drop(lag);
    let restored = Engine::open(&target.0, config, keys[1].clone(), floor).unwrap();
    assert_eq!(restored.snapshot.application, state);
}
