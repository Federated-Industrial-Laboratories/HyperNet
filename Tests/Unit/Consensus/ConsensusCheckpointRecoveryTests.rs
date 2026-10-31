// SPDX-License-Identifier: MIT
use super::super::super::{checkpoint, id, synchronizer};
use super::*;

pub(super) fn wishes(
    config: &Configuration,
    keys: &[SigningKey; 4],
    replicas: &mut [Engine],
    view: u64,
) {
    for replica in replicas {
        for key in &keys[..3] {
            replica
                .receive_wish(&synchronizer::sign(config, view, key).unwrap())
                .unwrap();
        }
        assert_eq!(replica.view(), view);
    }
}
pub(super) fn reports(
    config: &Configuration,
    replicas: &mut [Engine],
    leader: usize,
    voters: &[usize],
) {
    let messages: Vec<_> = voters
        .iter()
        .map(|i| {
            let r = &replicas[*i];
            r.snapshot.reports[&super::super::super::report_id(r.view(), &r.signer())].clone()
        })
        .collect();
    for message in messages {
        replicas[leader].receive_new_view(&message).unwrap();
    }
    assert_eq!(
        config.leader(replicas[leader].view()).unwrap(),
        replicas[leader].signer()
    );
}
pub(super) fn prepare(
    config: &Configuration,
    replicas: &mut [Engine],
    voters: &[usize],
    proposal: &[u8],
    command: &[u8],
) -> Certificate {
    let votes: Vec<_> = voters
        .iter()
        .map(|i| {
            SignedVote::parse(
                config,
                &replicas[*i]
                    .prepare(proposal, command, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    Certificate::collect(config, &votes).unwrap()
}
pub(super) fn phase(
    config: &Configuration,
    replicas: &mut [Engine],
    voters: &[usize],
    qc: &Certificate,
) -> Certificate {
    let votes: Vec<_> = voters
        .iter()
        .map(|i| {
            SignedVote::parse(config, &replicas[*i].advance_phase(&qc.bytes).unwrap()).unwrap()
        })
        .collect();
    Certificate::collect(config, &votes).unwrap()
}
pub(super) fn apply(config: &Configuration, replicas: &mut [Engine], qc: &Certificate) {
    for r in replicas {
        r.decide(&qc.bytes).unwrap();
        r.apply_committed(|_, p| Ok(fixtures::execution(config, p)))
            .unwrap();
    }
}
fn certify(replicas: &mut [Engine]) -> Vec<u8> {
    let shares: Vec<_> = replicas
        .iter()
        .map(|r| checkpoint::share(r.configuration(), &r.checkpoint_shares()[0]).unwrap())
        .collect();
    assert!(shares.iter().all(|s| s.0 == shares[0].0));
    let signatures = shares.iter().map(|(_, key, sig)| (*key, *sig)).collect();
    let proof = replicas[0]
        .combine_checkpoint(&shares[0].0, &signatures)
        .unwrap();
    for r in replicas {
        r.accept_checkpoint(&proof, Some(20000)).unwrap();
    }
    proof
}
pub(super) fn round(
    config: &Configuration,
    keys: &[SigningKey; 4],
    replicas: &mut [Engine],
    height: u64,
) -> (Certificate, Certificate, Certificate) {
    let mut view = replicas[0].view() + 1;
    while config.leader(view).unwrap() == keys[3].verifying_key().to_bytes() {
        view += 1;
    }
    wishes(config, keys, replicas, view);
    let leader = config.member(&config.leader(view).unwrap()).unwrap();
    reports(config, replicas, leader, &[0, 1, 2]);
    let command = fixtures::request(config, (height % 200 + 1) as u8);
    let proposal = replicas[leader].propose(&command, 10000).unwrap();
    let prepared = prepare(config, replicas, &[0, 1, 2], &proposal, &command);
    let precommitted = phase(config, replicas, &[0, 1, 2], &prepared);
    let committed = phase(config, replicas, &[0, 1, 2], &precommitted);
    apply(config, replicas, &committed);
    assert!(
        replicas
            .iter()
            .all(|r| r.applied().unwrap().height == height)
    );
    (prepared, precommitted, committed)
}
fn exchange(
    source: &mut Driver,
    target: &mut Driver,
    requests: &ingress::Mailbox,
    responses: &ingress::Mailbox,
) {
    // Deliver exact requested repair/transfer records; other gossip can be lost.
    for _ in 0..64 {
        let mut delivered = false;
        while let Some(bytes) = requests.try_pop().unwrap() {
            let message = peer::decode(target.config(), target.engine.signer(), &bytes).unwrap();
            if matches!(
                message,
                Message::StateRequest(..)
                    | Message::ArchiveRequest(..)
                    | Message::RepairRequest(..)
            ) {
                source.receive(target.engine.signer(), message).unwrap();
                delivered = true;
            }
        }
        while let Some(bytes) = responses.try_pop().unwrap() {
            let message = peer::decode(source.config(), source.engine.signer(), &bytes).unwrap();
            if matches!(
                message,
                Message::StateResponse(..)
                    | Message::ArchiveResponse(..)
                    | Message::RepairResponse(..)
            ) {
                let duplicate = message.clone();
                let is_transfer = matches!(
                    message,
                    Message::StateResponse(..) | Message::ArchiveResponse(..)
                );
                target.receive(source.engine.signer(), message).unwrap();
                if is_transfer {
                    let generation = target.engine.generation();
                    assert!(target.receive(source.engine.signer(), duplicate).is_err());
                    assert_eq!(target.engine.generation(), generation);
                }
                delivered = true;
            }
        }
        target.apply().unwrap();
        if !delivered
            && target.engine.applied().unwrap().height == target.engine.committed().unwrap().height
        {
            return;
        }
    }
    panic!("Requested repair did not converge within its bound");
}

fn transferred_message(
    mailbox: &ingress::Mailbox,
    config: &Configuration,
    sender: Key,
    kind: u64,
) -> Message {
    while let Some(bytes) = mailbox.try_pop().unwrap() {
        let message = peer::decode(config, sender, &bytes).unwrap();
        if message.number() == kind {
            return message;
        }
    }
    panic!("Expected transfer message {kind} was not queued");
}

#[test]
fn checkpoint_turnover_pins_progress_and_correlates_restart_supersession() {
    let (config, keys) = fixture();
    let (directories, mut replicas) = fixtures::engines(&config, &keys);
    let lag = replicas.pop().unwrap();
    for height in 1..=32 {
        round(&config, &keys, &mut replicas, height);
    }
    let proof32 = certify(&mut replicas);
    let digest32 = *checkpoint::verified(&config, &proof32).unwrap().digest();
    let source_key = keys[0].verifying_key().to_bytes();
    let target_key = keys[3].verifying_key().to_bytes();
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
        .receive(source_key, Message::CheckpointProof(proof32))
        .unwrap();
    let request32 = transferred_message(&requests, &config, target_key, 13);
    let Message::StateRequest(id32, _, _) = request32 else {
        unreachable!()
    };
    let receiver_deadline = target.transfers[&source_key].expires_at();
    source.receive(target_key, request32.clone()).unwrap();
    let served_deadline = source.served_checkpoints[&target_key].expires_at();
    let delayed32 = transferred_message(&responses, &config, source_key, 14);

    // Ordinary phase handlers advance the donor while the first state reply is lost.
    replicas.insert(0, source.engine);
    for height in 33..=64 {
        round(&config, &keys, &mut replicas, height);
    }
    let proof64 = certify(&mut replicas);
    source.engine = replicas.remove(0);
    assert!(source.engine.checkpoint_state(digest32).is_err());
    assert!(source.engine.checkpoint_leaves(digest32).is_err());
    // A generic newer announcement cannot discard a working pinned transfer.
    target
        .receive(source_key, Message::CheckpointProof(proof64.clone()))
        .unwrap();
    assert_eq!(
        target.transfers[&source_key].expires_at(),
        receiver_deadline
    );
    assert!(
        matches!(target.transfers[&source_key].pending_message(), Message::StateRequest(id, digest, 0) if *id == id32 && *digest == digest32)
    );
    source.receive(target_key, request32).unwrap();
    assert_eq!(
        source.served_checkpoints[&target_key].expires_at(),
        served_deadline
    );
    target
        .receive(
            source_key,
            transferred_message(&responses, &config, source_key, 14),
        )
        .unwrap();
    assert!(target.receive(source_key, delayed32).is_err());
    let archive32 = transferred_message(&requests, &config, target_key, 15);
    assert!(
        source
            .receive(target_key, Message::ArchiveRequest(id32, digest32, 32, 1))
            .is_err()
    );
    source.receive(target_key, archive32).unwrap();
    target
        .receive(
            source_key,
            transferred_message(&responses, &config, source_key, 16),
        )
        .unwrap();
    assert_eq!(target.engine.applied().unwrap().height, 32);
    assert!(target.transfers.is_empty());

    // The next first request is delayed until its advertised checkpoint has gone.
    target
        .receive(source_key, Message::CheckpointProof(proof64.clone()))
        .unwrap();
    let request64 = transferred_message(&requests, &config, target_key, 13);
    let Message::StateRequest(id64, digest64, _) = request64 else {
        unreachable!()
    };
    let deadline64 = target.transfers[&source_key].expires_at();
    assert!(
        target
            .receive(
                source_key,
                Message::CheckpointSuperseded(id64, digest64, proof64)
            )
            .is_err()
    );
    assert_eq!(target.transfers[&source_key].expires_at(), deadline64);
    replicas.insert(0, source.engine);
    for height in 65..=96 {
        round(&config, &keys, &mut replicas, height);
    }
    let proof96 = certify(&mut replicas);
    source.engine = replicas.remove(0);
    let generation = source.engine.generation();
    drop(source);
    let reopened = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    let mut source = repair_driver(
        reopened,
        &directories[0].0,
        &keys,
        target_key,
        responses.clone(),
    );
    assert!(source.served_checkpoints.is_empty());
    source.receive(target_key, request64).unwrap();
    let superseded = transferred_message(&responses, &config, source_key, 17);
    let before = target.engine.generation();
    assert!(
        target
            .receive(
                source_key,
                Message::CheckpointSuperseded([99; 32], digest64, proof96.clone())
            )
            .is_err()
    );
    assert!(
        target
            .receive(
                source_key,
                Message::CheckpointSuperseded(id64, digest32, proof96)
            )
            .is_err()
    );
    assert_eq!(target.engine.generation(), before);
    let duplicate = superseded.clone();
    target.receive(source_key, superseded).unwrap();
    assert_eq!(target.transfers[&source_key].expires_at(), deadline64);
    assert!(
        matches!(target.transfers[&source_key].pending_message(), Message::StateRequest(id, digest, 0) if *id != id64 && *digest != digest64)
    );
    assert!(target.receive(source_key, duplicate).is_err());
    exchange(&mut source, &mut target, &requests, &responses);
    assert_eq!(target.engine.applied().unwrap().height, 96);
    assert!(target.transfers.is_empty());
    assert_eq!(source.served_checkpoints.len(), 1);
}

#[test]
fn divergent_precommit_lock_survives_pruned_checkpoint_until_normal_phase_progress() {
    let (config, keys) = fixture();
    let (directories, mut replicas) = fixtures::engines(&config, &keys);
    wishes(&config, &keys, &mut replicas, 1);
    reports(&config, &mut replicas, 0, &[0, 1, 2]);
    let b_command = fixtures::request(&config, 51);
    let b_proposal = replicas[0].propose(&b_command, 10000).unwrap();
    let b_prepared = prepare(&config, &mut replicas, &[0, 1, 2], &b_proposal, &b_command);
    // Only replica0 learns B's PrepareQC. No PreCommitQC exists for B yet.
    replicas[0].advance_phase(&b_prepared.bytes).unwrap();
    wishes(&config, &keys, &mut replicas, 2);
    reports(&config, &mut replicas, 1, &[1, 2, 3]);
    let a_command = fixtures::request(&config, 52);
    let a_proposal = replicas[1].propose(&a_command, 10000).unwrap();
    let a_prepared = prepare(&config, &mut replicas, &[1, 2, 3], &a_proposal, &a_command);
    let a_precommitted = phase(&config, &mut replicas, &[1, 2, 3], &a_prepared);
    // Only replica3 receives the PreCommitQC and durably votes Commit on A.
    replicas[3].advance_phase(&a_precommitted.bytes).unwrap();
    let mut lag = replicas.pop().unwrap();
    assert_eq!(lag.committed().unwrap().height, 0);
    wishes(&config, &keys, &mut replicas, 3);
    // Replica0 retained B through its highest PrepareQC. Other replicas may
    // retire B's old unsigned proposal, so repair its exact certified closure.
    let b_items = replicas[0]
        .repair_export(&[
            reference(12, b_prepared.digest()),
            reference(14, b_prepared.node),
            reference(22, wire::digest(&b_command)),
        ])
        .unwrap();
    assert_eq!(b_items.len(), 3);
    for r in &mut replicas {
        let items = b_items
            .iter()
            .filter(|item| {
                item.reference.kind == 12
                    || r.repair_export(std::slice::from_ref(&item.reference))
                        .unwrap()
                        .is_empty()
            })
            .cloned()
            .collect::<Vec<_>>();
        let requested = items
            .iter()
            .map(|i| i.reference.clone())
            .collect::<Vec<_>>();
        r.repair_import(&requested, &items).unwrap();
    }
    // The single Byzantine leader2 ignores the highest NewView QC and proposes
    // B's branch. The other live replicas still have genesis locks, so their
    // ordinary safe-node checks legitimately permit this proposal.
    let command = fixtures::request(&config, 53);
    let n = Node {
        scope: config.scope.clone(),
        view: 3,
        height: 2,
        parent: Some(b_prepared.node),
        command: Some(wire::digest(&command)),
        evaluated_at: 10000,
        justify: Some(b_prepared.digest()),
    };
    let proposal = wire::sign_envelope(&n.encode().unwrap(), &keys[2]).unwrap();
    let prepared = prepare(&config, &mut replicas, &[0, 1, 2], &proposal, &command);
    let precommitted = phase(&config, &mut replicas, &[0, 1, 2], &prepared);
    let committed = phase(&config, &mut replicas, &[0, 1, 2], &precommitted);
    apply(&config, &mut replicas, &committed);
    let mut proof = Vec::new();
    for height in 3..=160 {
        round(&config, &keys, &mut replicas, height);
        if height % 32 == 0 {
            proof = certify(&mut replicas);
        }
    }
    assert!(replicas[0].known_node(&b_prepared.node).is_err());
    let canonical_prepare = replicas[0]
        .known_certificate(&replicas[0].snapshot.highest_prepare)
        .unwrap();
    // Repair may arrive long after the anchor and its deciding phase views.
    // These real WISH transitions retire old signatures without moving locks.
    wishes(&config, &keys, &mut replicas, 400);
    wishes(&config, &keys, std::slice::from_mut(&mut lag), 400);
    assert!(lag.snapshot.retired_view > canonical_prepare.view);
    let source_key = keys[0].verifying_key().to_bytes();
    let target_key = keys[3].verifying_key().to_bytes();
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
    let old_lock = target.engine.snapshot.locked;
    let old_high = target.engine.snapshot.highest_prepare;
    let old_votes = target.engine.snapshot.own_votes.clone();
    let old_floor = target.engine.snapshot.retired_view;
    let old_view = target.engine.view();
    target
        .receive(source_key, Message::CheckpointProof(proof))
        .unwrap();
    // Lose the first state request; the normal bounded transfer tick repeats it.
    while requests.try_pop().unwrap().is_some() {}
    target.checkpoint_tick().unwrap();
    exchange(&mut source, &mut target, &requests, &responses);
    assert!(target.transfers.is_empty());
    assert_eq!(target.engine.applied().unwrap().height, 160);
    assert_eq!(target.engine.snapshot.locked, old_lock);
    assert_eq!(target.engine.snapshot.highest_prepare, old_high);
    assert_eq!(target.engine.snapshot.own_votes, old_votes);
    assert_eq!(target.engine.snapshot.retired_view, old_floor);
    assert_eq!(target.engine.view(), old_view);
    assert!(
        !target
            .engine
            .snapshot
            .prefix_nodes
            .contains_key(&id(&a_precommitted.node))
    );
    let generation = target.engine.generation();
    drop(target);
    let reopened = Engine::open(
        &directories[3].0,
        config.clone(),
        keys[3].clone(),
        generation,
    )
    .unwrap();
    assert_eq!(reopened.snapshot.locked, old_lock);
    assert_eq!(reopened.snapshot.highest_prepare, old_high);
    assert_eq!(reopened.snapshot.own_votes, old_votes);
    assert_eq!(reopened.snapshot.retired_view, old_floor);
    assert!(
        !reopened
            .snapshot
            .prefix_nodes
            .contains_key(&id(&a_precommitted.node))
    );
    let mut target = repair_driver(
        reopened,
        &directories[3].0,
        &keys,
        source_key,
        requests.clone(),
    );
    let Driver { engine, .. } = source;
    replicas.insert(0, engine);
    let (prepared, precommitted, committed) = round(&config, &keys, &mut replicas, 161);
    let mut source = repair_driver(
        replicas.remove(0),
        &directories[0].0,
        &keys,
        target_key,
        responses.clone(),
    );
    for key in &keys[..3] {
        target
            .receive(
                key.verifying_key().to_bytes(),
                Message::Wish(synchronizer::sign(&config, prepared.view, key).unwrap()),
            )
            .unwrap();
    }
    target
        .receive(source_key, Message::Certificate(canonical_prepare.bytes))
        .unwrap();
    assert_eq!(target.engine.snapshot.locked, old_lock);
    target
        .receive(source_key, Message::Certificate(prepared.bytes))
        .unwrap();
    exchange(&mut source, &mut target, &requests, &responses);
    assert!(target.repairs.is_empty());
    assert_eq!(target.engine.snapshot.locked, old_lock);
    target
        .receive(source_key, Message::Certificate(precommitted.bytes.clone()))
        .unwrap();
    assert_eq!(target.engine.snapshot.locked, precommitted.digest());
    target
        .receive(source_key, Message::Certificate(committed.bytes))
        .unwrap();
    for _ in 0..4 {
        if target.engine.applied().unwrap().height == 161 {
            break;
        }
        target.apply().unwrap();
    }
    assert_eq!(target.engine.applied().unwrap().height, 161);
    assert_ne!(target.engine.snapshot.locked, old_lock);
    let vote_id = super::super::super::vote_id(precommitted.view, Phase::Commit, &target_key);
    let vote = target.engine.snapshot.own_votes[&vote_id].clone();
    let generation = target.engine.generation();
    drop(target);
    let reopened = Engine::open(&directories[3].0, config, keys[3].clone(), generation).unwrap();
    assert_eq!(reopened.snapshot.locked, precommitted.digest());
    assert_eq!(reopened.snapshot.own_votes[&vote_id], vote);
    assert_eq!(reopened.applied().unwrap().height, 161);
    // The imported canonical anchor does not relabel the old A lock as history.
    assert!(
        !reopened
            .snapshot
            .prefix_nodes
            .contains_key(&id(&a_precommitted.node))
    );
}
