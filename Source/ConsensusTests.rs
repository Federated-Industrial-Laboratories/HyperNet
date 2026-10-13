// SPDX-License-Identifier: MIT
use super::*;
use journal::tests::Directory;
use records::{
    bytes,
    tests::{fixture, initial},
};

pub(super) fn request(config: &Configuration, serial: u8) -> Vec<u8> {
    let requester = SigningKey::from_bytes(&[30; 32]);
    let recipient = SigningKey::from_bytes(&[31; 32]);
    let intent = wire::encode(&V::Array(vec![
        V::Uint(20),
        V::Uint(1),
        bytes(&config.scope.network),
        bytes(&config.scope.incarnation),
        V::Uint(1),
        bytes(&wire::digest(
            &wire::encode(&V::Array(vec![
                V::Text("HyperNet/StreamInitial".into()),
                V::Uint(1),
                bytes(&config.scope.network),
                bytes(&config.scope.incarnation),
                bytes(requester.verifying_key().as_bytes()),
            ]))
            .unwrap(),
        )),
        V::Uint(u64::from(serial) + 1),
        V::Uint(u64::from(serial)),
        bytes(requester.verifying_key().as_bytes()),
        V::Text("Status".into()),
        bytes(&[40; 32]),
        V::Uint(1),
        V::Uint(1),
        V::Uint(config.scope.epoch),
        V::Uint(0),
        V::Array(vec![]),
        bytes(&wire::encode(&V::Array(vec![])).unwrap()),
    ]))
    .unwrap();
    let challenge = wire::encode(&V::Array(vec![
        V::Uint(21),
        V::Uint(1),
        bytes(&config.scope.network),
        bytes(&config.scope.incarnation),
        bytes(recipient.verifying_key().as_bytes()),
        bytes(&[41; 32]),
        bytes(&[serial; 32]),
        bytes(&wire::digest(&intent)),
        bytes(&[42; 32]),
        V::Uint(10000),
        V::Uint(15000),
        V::Uint(5000),
    ]))
    .unwrap();
    wire::encode(&V::Array(vec![
        V::Uint(22),
        V::Uint(1),
        config.scope.value(),
        bytes(&wire::sign_envelope(&intent, &requester).unwrap()),
        bytes(&wire::sign_envelope(&challenge, &recipient).unwrap()),
        V::Uint(15000),
    ]))
    .unwrap()
}
pub(super) fn engines(
    config: &Configuration,
    keys: &[SigningKey; 4],
) -> (Vec<Directory>, Vec<Engine>) {
    let directories: Vec<_> = (0..4).map(|_| Directory::new()).collect();
    let engines = directories
        .iter()
        .zip(keys)
        .map(|(directory, key)| {
            Engine::create(&directory.0, config.clone(), key.clone(), initial()).unwrap()
        })
        .collect();
    (directories, engines)
}
pub(crate) fn enter(
    config: &Configuration,
    keys: &[SigningKey; 4],
    engines: &mut [Engine],
    view: u64,
) {
    for engine in engines.iter_mut() {
        for key in &keys[..3] {
            engine
                .receive_wish(&synchronizer::sign(config, view, key).unwrap())
                .unwrap();
        }
        assert_eq!(engine.view(), view);
    }
    let reports: Vec<_> = engines
        .iter()
        .map(|engine| engine.snapshot.reports[&report_id(view, &engine.snapshot.signer)].clone())
        .collect();
    for engine in engines {
        for report in &reports {
            engine.receive_new_view(report).unwrap();
        }
    }
}
pub(super) fn execution(config: &Configuration, position: &Committed) -> Execution {
    let state = wire::encode(&V::Array(vec![V::Uint(position.height)])).unwrap();
    let r = match Command::parse(config, &position.command).unwrap() {
        Command::Inert | Command::Noop(_) => {
            return Execution {
                state,
                output: ExecutionOutput::Inert,
            };
        }
        Command::Ordered(request) => request,
    };
    let result = wire::encode(&V::Array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(r.action.clone()),
        V::Uint(0),
        V::Uint(0),
        bytes(&state),
    ]))
    .unwrap();
    let attestation = wire::encode(&V::Array(vec![
        V::Uint(23),
        V::Uint(1),
        config.scope.value(),
        V::Uint(position.height),
        bytes(&position.node),
        bytes(&wire::digest(&position.command)),
        bytes(&r.intent),
        bytes(&r.challenge),
        bytes(&r.requester),
        bytes(&r.recipient),
        V::Text(r.action),
        bytes(&r.resource),
        V::Uint(r.revision),
        V::Uint(r.profile_generation),
        V::Uint(1),
        bytes(&wire::digest(&result)),
        bytes(&wire::digest(&state)),
        V::Uint(r.minimum_height),
        V::Uint(position.evaluated_at),
        V::Uint(r.expires),
        V::Null,
        V::Null,
        V::Null,
    ]))
    .unwrap();
    Execution {
        state,
        output: ExecutionOutput::Result {
            result,
            attestation,
        },
    }
}
pub(super) fn phases(
    config: &Configuration,
    engines: &mut [Engine],
    command: &[u8],
) -> Certificate {
    let proposal = engines[0].propose(command, 10000).unwrap();
    let votes: Vec<_> = engines
        .iter_mut()
        .map(|e| {
            SignedVote::parse(
                config,
                &e.prepare(&proposal, command, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let prepare = Certificate::collect(config, &votes[..3]).unwrap();
    let votes: Vec<_> = engines
        .iter_mut()
        .map(|e| SignedVote::parse(config, &e.advance_phase(&prepare.bytes).unwrap()).unwrap())
        .collect();
    let precommit = Certificate::collect(config, &votes[..3]).unwrap();
    let votes: Vec<_> = engines
        .iter_mut()
        .map(|e| SignedVote::parse(config, &e.advance_phase(&precommit.bytes).unwrap()).unwrap())
        .collect();
    Certificate::collect(config, &votes[..3]).unwrap()
}

#[test]
fn durable_votes_locks_and_results_survive_lost_replies() {
    let (config, keys) = fixture();
    let (directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let command = request(&config, 50);
    let commit = phases(&config, &mut replicas, &command);
    let last =
        replicas[0].snapshot.own_votes[&vote_id(1, Phase::Commit, &config.voters[0])].clone();
    let journal_generation = replicas[0].generation();
    let first = replicas.remove(0);
    drop(first);
    let mut resumed = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        journal_generation,
    )
    .unwrap();
    assert_eq!(
        resumed.snapshot.own_votes[&vote_id(1, Phase::Commit, &config.voters[0])],
        last
    );
    assert_eq!(
        certificate(&config, &resumed.snapshot, &resumed.snapshot.locked)
            .unwrap()
            .phase,
        Phase::PreCommit
    );
    assert!(
        resumed
            .apply_committed(|_, _| panic!("Uncommitted state executed"))
            .unwrap()
            .is_empty()
    );
    resumed.decide(&commit.bytes).unwrap();
    assert_eq!(resumed.committed().unwrap().height, 1);
    assert_eq!(resumed.applied().unwrap().height, 0);
    let discovery_generation = resumed.generation();
    assert!(matches!(
        resumed
            .apply_turn(|_, _| panic!("Discovery executed before durable publication"))
            .unwrap(),
        application::Turn::Progress
    ));
    assert_eq!(resumed.generation(), discovery_generation + 1);
    assert_eq!(resumed.applied().unwrap().height, 0);
    assert!(resumed.execution(commit.node).unwrap().is_none());
    drop(resumed);
    let mut resumed = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        discovery_generation + 1,
    )
    .unwrap();
    assert!(
        resumed
            .apply_committed(|_, _| anyhow::bail!("Interrupted executor"))
            .is_err()
    );
    let before_publication = resumed.generation();
    std::os::unix::fs::symlink("Signer.bin", directories[0].0.join("SignerPending.bin")).unwrap();
    assert!(
        resumed
            .apply_committed(|_, position| Ok(execution(&config, position)))
            .is_err()
    );
    assert_eq!(resumed.generation(), before_publication);
    assert_eq!(resumed.archive.leaves().len(), 1);
    assert_eq!(resumed.snapshot.archive_size, 0);
    assert!(resumed.active().is_err());
    drop(resumed);
    std::fs::remove_file(directories[0].0.join("SignerPending.bin")).unwrap();
    let mut resumed = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        before_publication,
    )
    .unwrap();
    assert_eq!(resumed.applied().unwrap().height, 0);
    assert!(resumed.archive.leaves().is_empty());
    assert!(resumed.execution(commit.node).unwrap().is_none());
    let result = resumed
        .apply_committed(|_, position| Ok(execution(&config, position)))
        .unwrap();
    assert_eq!(result.len(), 1);
    assert!(
        resumed
            .apply_committed(|_, _| panic!("Executed twice"))
            .unwrap()
            .is_empty()
    );
    drop(resumed);
    let resumed = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        journal_generation,
    )
    .unwrap();
    assert_eq!(
        resumed.execution(commit.node).unwrap().unwrap().attestation,
        result[0].attestation
    );
}
#[test]
fn equivocation_and_unsafe_branch_cannot_obtain_a_second_vote() {
    let (config, keys) = fixture();
    let (_directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let command = request(&config, 51);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let first = replicas[1]
        .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
    assert_eq!(
        replicas[1]
            .prepare(
                &proposal,
                &command,
                |_| anyhow::bail!("No new clock window"),
                |_, _| anyhow::bail!("No new effect")
            )
            .unwrap(),
        first
    );
    let other = request(&config, 52);
    assert!(replicas[0].propose(&other, 10000).is_err());
    let mut alternative = Node::parse(&config, &wire::envelope(&proposal, 1).unwrap().0).unwrap();
    alternative.command = Some(wire::digest(&other));
    let malicious = wire::sign_envelope(&alternative.encode().unwrap(), &keys[0]).unwrap();
    assert!(
        replicas[1]
            .prepare(&malicious, &other, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
    let commit = phases(&config, &mut replicas, &command);
    for replica in &mut replicas {
        replica.decide(&commit.bytes).unwrap();
    }
    enter(&config, &keys, &mut replicas, 2);
    let mut fork = config.genesis();
    fork.view = 2;
    fork.height = 1;
    fork.parent = Some(config.genesis().digest().unwrap());
    fork.command = Some(wire::digest(&other));
    fork.justify = Some(config.genesis_qc().unwrap().digest());
    let malicious = wire::sign_envelope(&fork.encode().unwrap(), &keys[1]).unwrap();
    assert!(
        replicas[2]
            .prepare(&malicious, &other, |_| Ok(()), |_, _| Ok(()))
            .is_err()
    );
}
#[test]
fn withheld_decide_is_reconstructed_without_the_leader() {
    let (config, keys) = fixture();
    let (_directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let command = request(&config, 53);
    phases(&config, &mut replicas, &command);
    let votes: Vec<_> = replicas[..3]
        .iter()
        .map(|r| r.snapshot.own_votes[&vote_id(1, Phase::Commit, &r.snapshot.signer)].clone())
        .collect();
    let mut reconstructed = None;
    for vote in votes {
        reconstructed = replicas[3].receive_vote(&vote).unwrap().or(reconstructed);
    }
    replicas[3].decide(&reconstructed.unwrap()).unwrap();
    assert_eq!(replicas[3].committed().unwrap().height, 1);
    assert_eq!(replicas[0].committed().unwrap().height, 0);
}
#[test]
fn duplicate_phase_lookups_verify_only_exact_quorums_with_retained_history() {
    let (config, keys) = fixture();
    let directory = Directory::new();
    let mut engine =
        Engine::create(&directory.0, config.clone(), keys[0].clone(), initial()).unwrap();
    for view in 1..=4 {
        checkpoint::tests::step(&mut engine, &keys, view);
    }
    for key in &keys[..3] {
        engine
            .receive_wish(&synchronizer::sign(&config, 5, key).unwrap())
            .unwrap();
    }
    let generation = engine.generation();
    let repeated = synchronizer::sign(&config, 5, &keys[0]).unwrap();
    let duplicate = engine.receive_wish(&repeated).unwrap();
    assert!(duplicate.wish.is_none() && duplicate.new_view.is_none());
    let mut invalid = repeated;
    *invalid.last_mut().unwrap() ^= 1;
    assert!(engine.receive_wish(&invalid).is_err());
    assert_eq!(engine.generation(), generation);
    let high = engine
        .known_certificate(&engine.snapshot.highest_prepare)
        .unwrap();
    let command = request(&config, 55);
    for key in &keys {
        let report = NewView::sign(&config, 5, high.digest(), key).unwrap();
        engine.receive_new_view(&report.envelope).unwrap();
    }
    let selected = report_id(5, &config.voters[0]);
    let original = engine.snapshot.reports[&selected].clone();
    let mut invalid = original.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let wrong_signer = NewView::sign(&config, 5, high.digest(), &keys[1]).unwrap();
    let wrong_view = NewView::sign(&config, 4, high.digest(), &keys[0]).unwrap();
    let wrong_phase = NewView::sign(&config, 5, engine.snapshot.locked, &keys[0]).unwrap();
    let generation = engine.generation();
    for replacement in [
        invalid,
        wrong_signer.envelope,
        wrong_view.envelope,
        wrong_phase.envelope,
    ] {
        engine
            .snapshot
            .reports
            .insert(selected.clone(), replacement);
        assert!(engine.propose(&command, 10000).is_err());
        assert_eq!(engine.generation(), generation);
    }
    engine.snapshot.reports.insert(selected, original);
    let previous_reports = engine.snapshot.reports.clone();
    for signer in &config.voters[2..] {
        engine.snapshot.reports.remove(&report_id(5, signer));
    }
    assert!(engine.propose(&command, 10000).is_err());
    assert_eq!(engine.generation(), generation);
    engine.snapshot.reports = previous_reports.clone();
    let node = Node {
        scope: config.scope.clone(),
        view: 5,
        height: engine.known_node(&high.node).unwrap().height + 1,
        parent: Some(high.node),
        command: Some(wire::digest(&command)),
        evaluated_at: 10000,
        justify: Some(high.digest()),
    };
    let proposal = engine.propose(&command, 10000).unwrap();
    assert_eq!(
        wire::envelope(&proposal, 1).unwrap().0,
        node.encode().unwrap()
    );
    assert_eq!(engine.snapshot.reports, previous_reports);
    engine
        .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
    let phase_votes = |phase| {
        keys.iter()
            .map(|key| {
                SignedVote::sign(
                    &config,
                    Vote {
                        scope: config.scope.clone(),
                        view: 5,
                        phase,
                        node: node.digest().unwrap(),
                    },
                    key,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let prepares = phase_votes(Phase::Prepare);
    let own_index = vote_id(5, Phase::Prepare, &config.voters[0]);
    let own = engine.snapshot.votes[&own_index].clone();
    let mut corrupt = own.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let wrong_phase = phase_votes(Phase::PreCommit)[0].envelope.clone();
    let generation = engine.generation();
    for replacement in [&corrupt, &prepares[2].envelope, &wrong_phase] {
        engine
            .snapshot
            .votes
            .insert(own_index.clone(), replacement.clone());
        assert!(engine.receive_vote(&prepares[1].envelope).is_err());
        assert_eq!(engine.generation(), generation);
        assert!(!engine.snapshot.votes.contains_key(&vote_id(
            5,
            Phase::Prepare,
            &config.voters[1]
        )));
    }
    engine.snapshot.votes.insert(own_index, own);
    let unrelated = engine
        .snapshot
        .votes
        .iter()
        .filter(|(_, bytes)| SignedVote::parse(&config, bytes).unwrap().vote.view != 5)
        .map(|(key, bytes)| (key.clone(), bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    assert!(!unrelated.is_empty());
    for vote in &prepares {
        engine.receive_vote(&vote.envelope).unwrap();
    }
    assert!(
        unrelated
            .iter()
            .all(|(key, bytes)| engine.snapshot.votes.get(key) == Some(bytes))
    );
    let selected = engine
        .known_certificate(&Certificate::vote_digest(&prepares[0].vote).unwrap())
        .unwrap();
    assert_eq!(selected.vote.as_ref(), Some(&prepares[0].vote));
    let prepare = Certificate::collect(&config, &prepares[..3]).unwrap();
    let extended = Certificate::collect(&config, &prepares).unwrap();
    let mut unsigned = wire::decode(&prepare.bytes)
        .unwrap()
        .array(5)
        .unwrap()
        .to_vec();
    unsigned[4] = V::Array(vec![]);
    assert_eq!(
        prepare.digest(),
        wire::digest(&wire::encode(&V::Array(unsigned)).unwrap())
    );
    assert_ne!(prepare.bytes, extended.bytes);
    assert_eq!(prepare.digest(), extended.digest());
    assert_eq!(
        prepare.digest(),
        Certificate::vote_digest(&prepares[0].vote).unwrap()
    );
    engine.advance_phase(&prepare.bytes).unwrap();
    let precommits = phase_votes(Phase::PreCommit);
    let precommit = Certificate::collect(&config, &precommits[..3]).unwrap();
    let commit_vote = engine.advance_phase(&precommit.bytes).unwrap();
    let prior_quorums = engine
        .snapshot
        .certificates
        .values()
        .filter(|object| {
            let bytes = body(&engine.snapshot, object).unwrap();
            let retained = Certificate::parse(&config, &bytes).unwrap();
            retained.view > 0 && retained.view < node.view
        })
        .count();
    assert!(prior_quorums >= 4);
    let generation = engine.generation();
    // A duplicate validates its selected quorum once, independent of unrelated history.
    for (vote, expected) in [(&prepares[0], &prepare), (&precommits[0], &precommit)] {
        let before = Certificate::parse_count();
        let reply = engine.receive_vote(&vote.envelope).unwrap().unwrap();
        assert_eq!(Certificate::parse_count() - before, 1);
        assert_eq!(reply, expected.bytes);
        assert_eq!(engine.generation(), generation);
    }
    let before = Certificate::parse_count();
    assert_eq!(engine.advance_phase(&precommit.bytes).unwrap(), commit_vote);
    assert_eq!(Certificate::parse_count() - before, 4);
    assert_eq!(engine.generation(), generation);

    // Index selection cannot replace signature validation or exact vote comparison.
    let index = id(&prepare.digest());
    let original = engine.snapshot.certificates[&index].clone();
    let mut invalid_signature = prepare.bytes.clone();
    *invalid_signature.last_mut().unwrap() ^= 1;
    assert!(wire::decode(&invalid_signature).is_ok());
    for substituted in [&invalid_signature, &precommit.bytes] {
        let object = objects(&engine.snapshot)
            .unwrap()
            .staged(12, prepare.digest(), substituted)
            .unwrap();
        engine.snapshot.certificates.insert(index.clone(), object);
        assert!(engine.receive_vote(&prepares[0].envelope).is_err());
        assert!(engine.advance_phase(&precommit.bytes).is_err());
        assert_eq!(engine.generation(), generation);
    }
    engine.snapshot.certificates.insert(index, original);
    let mut invalid_phase = precommit.bytes.clone();
    *invalid_phase.last_mut().unwrap() ^= 1;
    assert!(engine.advance_phase(&invalid_phase).is_err());
    assert_eq!(engine.generation(), generation);

    let commits = phase_votes(Phase::Commit);
    let commit = Certificate::collect(&config, &commits[..3]).unwrap();
    engine.decide(&commit.bytes).unwrap();
    let generation = engine.generation();
    engine.decide(&commit.bytes).unwrap();
    let mut invalid_commit = commit.bytes.clone();
    *invalid_commit.last_mut().unwrap() ^= 1;
    assert!(engine.decide(&invalid_commit).is_err());
    assert_eq!(engine.generation(), generation);
}
#[test]
fn result_forgery_cannot_acquire_an_executed_signature() {
    let (config, keys) = fixture();
    let (_directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let commit = phases(&config, &mut replicas, &request(&config, 54));
    replicas[0].decide(&commit.bytes).unwrap();
    assert!(
        replicas[0]
            .apply_committed(|_, position| {
                let mut fake = execution(&config, position);
                let ExecutionOutput::Result { result, .. } = &mut fake.output else {
                    panic!("Expected result")
                };
                *result = wire::encode(&V::Array(vec![
                    V::Uint(24),
                    V::Uint(1),
                    V::Text("Status".into()),
                    V::Uint(0),
                    V::Uint(0),
                    bytes(&wire::encode(&V::Bool(true))?),
                ]))?;
                Ok(fake)
            })
            .is_err()
    );
    assert_eq!(replicas[0].applied().unwrap().height, 0);
}
#[test]
fn repair_requires_an_exact_complete_quorum_certified_closure() {
    let (config, keys) = fixture();
    let (_directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let command = request(&config, 55);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let payload = wire::envelope(&proposal, 1).unwrap().0;
    let node = repair::Item {
        reference: repair::Reference {
            kind: 14,
            digest: wire::digest(&payload),
            signer: None,
        },
        bytes: payload,
    };
    assert!(
        replicas[1]
            .repair_import(
                std::slice::from_ref(&node.reference),
                std::slice::from_ref(&node)
            )
            .is_err()
    );
    let operation = repair::Item {
        reference: repair::Reference {
            kind: 22,
            digest: wire::digest(&command),
            signer: None,
        },
        bytes: command,
    };
    assert!(
        replicas[1]
            .repair_import(&[], &[node.clone(), operation.clone()])
            .is_err()
    );
    let generation = replicas[1].generation();
    let raw_refs = [node.reference.clone(), operation.reference.clone()];
    assert!(
        replicas[1]
            .repair_import(&raw_refs, &[node.clone(), operation.clone()])
            .is_err()
    );
    let votes: Vec<_> = [0, 2, 3]
        .into_iter()
        .map(|i| {
            SignedVote::parse(
                &config,
                &replicas[i]
                    .prepare(&proposal, &operation.bytes, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let certificate = Certificate::collect(&config, &votes).unwrap();
    let qc = repair::Item {
        reference: repair::Reference {
            kind: 12,
            digest: certificate.digest(),
            signer: None,
        },
        bytes: certificate.bytes,
    };
    let extra_command = request(&config, 56);
    let extra = repair::Item {
        reference: repair::Reference {
            kind: 22,
            digest: wire::digest(&extra_command),
            signer: None,
        },
        bytes: extra_command,
    };
    let items = vec![node.clone(), operation.clone(), qc.clone(), extra];
    let refs: Vec<_> = items.iter().map(|item| item.reference.clone()).collect();
    assert!(replicas[1].repair_import(&refs, &items).is_err());
    assert_eq!(replicas[1].generation(), generation);
    assert_eq!(replicas[1].snapshot.nodes.len(), 1);
    assert!(replicas[1].snapshot.commands.is_empty());
    let items = vec![node, operation, qc];
    let refs: Vec<_> = items.iter().map(|item| item.reference.clone()).collect();
    replicas[1].repair_import(&refs, &items).unwrap();

    assert!(replicas[1].snapshot.own_votes.is_empty());
}

#[test]
fn certificate_statement_identity_bounds_alternate_quorum_proofs() {
    let (config, keys) = fixture();
    let (directories, mut replicas) = engines(&config, &keys);
    enter(&config, &keys, &mut replicas, 1);
    let command = request(&config, 57);
    let proposal = replicas[0].propose(&command, 10000).unwrap();
    let votes: Vec<_> = replicas
        .iter_mut()
        .map(|replica| {
            SignedVote::parse(
                &config,
                &replica
                    .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let first = Certificate::collect(&config, &votes[..3]).unwrap();
    let other = Certificate::collect(&config, &votes[1..]).unwrap();
    let all = Certificate::collect(&config, &votes).unwrap();
    assert_ne!(first.bytes, other.bytes);
    assert_ne!(first.bytes, all.bytes);
    assert_eq!(first.digest(), other.digest());
    assert_eq!(first.digest(), all.digest());
    assert_ne!(first.digest(), wire::digest(&first.bytes));
    let genesis = config.genesis_qc().unwrap();
    assert_eq!(genesis.digest(), wire::digest(&genesis.bytes));

    let reference = repair::Reference {
        kind: 12,
        digest: first.digest(),
        signer: None,
    };
    let initial_count = replicas[0].snapshot.certificates.len();
    let mut expected_generation = None;
    for proof in [&first, &other, &all, &other] {
        let item = repair::Item {
            reference: reference.clone(),
            bytes: proof.bytes.clone(),
        };
        peer::validate_item(&config, &item).unwrap();
        replicas[0]
            .repair_import(std::slice::from_ref(&reference), &[item])
            .unwrap();
        assert_eq!(replicas[0].snapshot.certificates.len(), initial_count + 1);
        assert_eq!(
            replicas[0]
                .repair_export(std::slice::from_ref(&reference))
                .unwrap()[0]
                .bytes,
            first.bytes
        );
        assert_eq!(
            replicas[0].generation(),
            *expected_generation.get_or_insert(replicas[0].generation())
        );
    }
    let raw_reference = repair::Reference {
        digest: wire::digest(&first.bytes),
        ..reference.clone()
    };
    assert!(
        replicas[0]
            .repair_export(std::slice::from_ref(&raw_reference))
            .unwrap()
            .is_empty()
    );
    assert!(
        peer::validate_item(
            &config,
            &repair::Item {
                reference: raw_reference,
                bytes: first.bytes.clone(),
            }
        )
        .is_err()
    );

    let mut projection = wire::decode(&first.bytes)
        .unwrap()
        .array(5)
        .unwrap()
        .to_vec();
    projection[4] = V::Array(vec![]);
    let projection = wire::encode(&V::Array(projection)).unwrap();
    assert_eq!(first.digest(), wire::digest(&projection));
    assert!(Certificate::parse(&config, &projection).is_err());
    for changed in 0..3 {
        let mut modified_config = config.clone();
        let mut vote = votes[0].vote.clone();
        match changed {
            0 => vote.phase = Phase::PreCommit,
            1 => vote.node = [99; 32],
            2 => {
                modified_config.scope.incarnation = [98; 32];
                vote.scope = modified_config.scope.clone();
            }
            _ => unreachable!(),
        }
        let changed_votes: Vec<_> = keys[..3]
            .iter()
            .map(|key| SignedVote::sign(&modified_config, vote.clone(), key).unwrap())
            .collect();
        assert_ne!(
            first.digest(),
            Certificate::collect(&modified_config, &changed_votes)
                .unwrap()
                .digest()
        );
    }
    let generation = replicas[0].generation();
    drop(replicas.remove(0));
    let reopened = Engine::open(&directories[0].0, config, keys[0].clone(), generation).unwrap();
    assert_eq!(
        reopened.known_certificate(&first.digest()).unwrap().bytes,
        first.bytes
    );
}

#[test]
fn future_causal_floor_cannot_be_proposed_or_prepared() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = engines(&configuration, &keys);
    enter(&configuration, &keys, &mut engines, 1);
    let command = wire::decode(&request(&configuration, 89)).unwrap();
    let mut fields = command.array(6).unwrap().to_vec();
    let (intent, _) = wire::envelope(fields[3].bytes().unwrap(), 1).unwrap();
    let intent = wire::decode(&intent).unwrap();
    let mut intent = intent.array(17).unwrap().to_vec();
    intent[14] = V::Uint(99);
    let intent = wire::encode(&V::Array(intent)).unwrap();
    fields[3] = bytes(&wire::sign_envelope(&intent, &SigningKey::from_bytes(&[30; 32])).unwrap());
    let (challenge, _) = wire::envelope(fields[4].bytes().unwrap(), 1).unwrap();
    let challenge = wire::decode(&challenge).unwrap();
    let mut challenge = challenge.array(12).unwrap().to_vec();
    challenge[7] = bytes(&wire::digest(&intent));
    fields[4] = bytes(
        &wire::sign_envelope(
            &wire::encode(&V::Array(challenge)).unwrap(),
            &SigningKey::from_bytes(&[31; 32]),
        )
        .unwrap(),
    );
    let command = wire::encode(&V::Array(fields)).unwrap();
    let generation = engines[0].generation();
    assert!(engines[0].propose(&command, 10000).is_err());
    assert_eq!(engines[0].generation(), generation);
    let node = Node {
        scope: configuration.scope.clone(),
        view: 1,
        height: 1,
        parent: Some(configuration.genesis().digest().unwrap()),
        command: Some(wire::digest(&command)),
        evaluated_at: 10000,
        justify: Some(configuration.genesis_qc().unwrap().digest()),
    };
    let proposal = wire::sign_envelope(&node.encode().unwrap(), &keys[0]).unwrap();
    for replica in &mut engines {
        let generation = replica.generation();
        assert!(
            replica
                .prepare(&proposal, &command, |_| Ok(()), |_, _| Ok(()))
                .is_err()
        );
        assert_eq!(replica.generation(), generation);
    }
}
