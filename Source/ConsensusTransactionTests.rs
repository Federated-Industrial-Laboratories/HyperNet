// SPDX-License-Identifier: MIT
use super::*;
use journal::tests::Directory;
use records::tests::fixture;

fn prepared() -> (
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
