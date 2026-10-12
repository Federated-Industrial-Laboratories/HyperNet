// SPDX-License-Identifier: MIT
//! Four admitted fresh deployments cross a real journalled terminal and readiness boundary.
use super::*;
use crate::{
    authority_epoch::{self as epoch, Declaration, Nomination},
    authority_governance::Requirement,
    authority_membership::Snapshot,
    consensus::{
        self, Engine,
        journal::tests::Directory,
        records::{Certificate, SignedVote},
    },
    runtime_manifest::{Endpoint, Manifest},
};
fn fixture() -> tests::Fixture {
    let f = vectors::Fixture::with_actions(vec![9, 13]);
    let verified = crate::trust_bootstrap::check(&f.bootstrap, true, 1000).unwrap();
    let config = Configuration::trusted(verified.descriptor().canonical()).unwrap();
    let initial = wire::decode(&f.bootstrap).unwrap().array(6).unwrap()[3]
        .bytes()
        .unwrap()
        .to_vec();
    let expected = Governance::parse(
        config.scope.network,
        config.scope.incarnation,
        &State::parse(&config, &initial).unwrap().records,
    )
    .unwrap()
    .versions();
    tests::Fixture {
        app: PolicyApplication::new(config),
        initial,
        bootstrap: f.bootstrap,
        requester: vectors::key(5),
        expected,
        grant: [23; 32],
    }
}
fn committee() -> Vec<u8> {
    let mut seeds = (121..=124).collect::<Vec<_>>();
    seeds.sort_by_key(|s| vectors::key(*s).verifying_key().to_bytes());
    seeds
}
fn offer(index: usize) -> crate::authority_deployments::Offer {
    use crate::authority_deployments::Offer;
    let seeds = committee();
    let public = |seed| vectors::key(seed).verifying_key().to_bytes();
    let mut manifest = vectors::manifest();
    manifest.deployment = [161 + index as u8; 32];
    manifest.host = [171 + index as u8; 32];
    manifest.roles.truncate(1);
    manifest.volumes.truncate(1);
    manifest.endpoints = seeds
        .iter()
        .enumerate()
        .map(|(i, seed)| Endpoint {
            endpoint_id: [210 + i as u8; 32],
            service_key: public(*seed),
            address: std::net::Ipv4Addr::new(192, 0, 2, 40 + i as u8).into(),
            port: 24000,
            transport_key: public(110 + i as u8),
            leaf_der: vectors::leaf(110 + i as u8),
        })
        .collect();
    manifest.roles[0].service_key = public(seeds[index]);
    manifest.roles[0].bind_endpoint_ids = vec![[210 + index as u8; 32]];
    manifest.roles[0].outbound_endpoint_ids =
        manifest.endpoints.iter().map(|e| e.endpoint_id).collect();
    manifest.placement.hosts = vec![manifest.host];
    manifest.placement.volumes = vec![manifest.volumes[0].volume_id];
    manifest.clock.monitor_key = public(151 + index as u8);
    manifest
        .authority_config
        .as_mut()
        .unwrap()
        .ordered_peer_endpoint_ids = manifest.roles[0].outbound_endpoint_ids.clone();
    Manifest::parse(&manifest.encode().unwrap()).unwrap();
    let consent =
        wire::sign_envelope(&manifest.unsigned_consent(0).unwrap(), &vectors::key(90)).unwrap();
    let mut signers = [
        (0, seeds[index]),
        (1, 110 + index as u8),
        (2, 151 + index as u8),
    ];
    signers.sort_by_key(|(class, seed)| (*class, public(*seed)));
    let possessions = signers
        .iter()
        .map(|(class, seed)| {
            wire::sign_envelope(
                &Offer::possession(
                    &manifest,
                    *class,
                    public(*seed),
                    [180 + index as u8; 32],
                    manifest.validity,
                )
                .unwrap(),
                &vectors::key(*seed),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    Offer::parse(
        &manifest.encode().unwrap(),
        &consent,
        &array(possessions.iter().map(|v| b(v)).collect()),
    )
    .unwrap()
}
fn register(f: &tests::Fixture, prior: &[u8], index: usize) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let offer = offer(index);
    let grant = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap()
    .versions()
    .into_iter()
    .find(|v| v.kind == 102 && v.id == f.grant)
    .unwrap();
    let parameters = |refs: &[VersionRef]| {
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentRegister".into()),
            reference(&grant),
            b(&offer.manifest_bytes),
            b(&offer.consent),
            offer.possessions_value(),
            vectors::snapshot(refs),
        ])
    };
    let preliminary = sign(
        f,
        &state,
        prior,
        &f.requester,
        "AuthorityDeploymentRegister",
        offer.manifest.deployment,
        1,
        parameters(&[]),
        vec![],
    );
    let intent = Intent::from_signed(&preliminary).unwrap();
    let decision = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &state.records,
            &state.reservations,
            &intent,
            10000,
            false,
            None,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    let refs = decision
        .dependencies
        .into_iter()
        .filter(|r| !matches!(r.kind, 105 | 117 | 129))
        .collect::<Vec<_>>();
    sign(
        f,
        &state,
        prior,
        &f.requester,
        "AuthorityDeploymentRegister",
        offer.manifest.deployment,
        1,
        parameters(&refs),
        refs,
    )
}
fn declaration(f: &tests::Fixture, prior: &[u8]) -> Declaration {
    let state = State::parse(&f.app.config, prior).unwrap();
    let scope = f.app.config.descriptor().scope();
    let governance = Governance::parse(scope.network, scope.incarnation, &state.records).unwrap();
    let requirement = |subject, action: &'static [u64], scope| Requirement {
        subject,
        actions: action,
        scope,
        namespace: None,
        usage: [0, 1, 0, 1],
        evaluated_at_ms: 10000,
        expected: &[],
    };
    let mut refs = governance
        .current_capability(
            f.grant,
            &requirement(
                f.requester.verifying_key().to_bytes(),
                &[9],
                (0, scope.network),
            ),
        )
        .unwrap()
        .dependencies;
    refs.extend(
        governance
            .versions()
            .into_iter()
            .filter(|v| matches!(v.kind, 100 | 114)),
    );
    let mut nominations = Vec::new();
    for registration in state.deployments().unwrap().deployments.values() {
        refs.extend(
            governance
                .current_capability(
                    registration.grant.id,
                    &requirement(registration.registrar, &[13], (5, registration.deployment)),
                )
                .unwrap()
                .dependencies,
        );
        refs.extend([
            registration.reference.clone(),
            registration.profile.clone(),
            registration.consent.clone(),
        ]);
        nominations.push(Nomination {
            voter: registration.services[&0],
            profile: registration.profile.clone(),
            consent: registration.consent.clone(),
        });
    }
    refs.sort_by_key(VersionRef::index);
    refs.dedup();
    nominations.sort_by_key(|n| n.voter);
    Declaration::create(
        scope.clone(),
        f.requester.verifying_key().to_bytes(),
        f.grant,
        Snapshot::parse(&array(vec![
            array(vec![
                V::Uint(scope.epoch),
                V::Uint(state.height),
                b(&wire::digest(prior)),
            ]),
            array(refs.iter().map(reference).collect()),
        ]))
        .unwrap(),
        nominations,
    )
    .unwrap()
}
fn reconfigure(f: &tests::Fixture, prior: &[u8], declaration: &Declaration) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    sign(
        f,
        &state,
        prior,
        &f.requester,
        "Reconfigure",
        f.app.config.scope.network,
        declaration.snapshot.height,
        wire::decode(&declaration.parameters().unwrap()).unwrap(),
        declaration.snapshot.references.clone(),
    )
}
fn phases(config: &Configuration, engines: &mut [Engine], command: &[u8]) -> Certificate {
    let leader = config.leader(engines[0].view()).unwrap();
    let leader = engines.iter().position(|e| e.signer() == leader).unwrap();
    let proposal = engines[leader].propose(command, 10000).unwrap();
    let votes = engines
        .iter_mut()
        .map(|e| {
            let app = PolicyApplication::new(config.clone());
            let state = e.application().to_vec();
            SignedVote::parse(
                config,
                &e.prepare(
                    &proposal,
                    command,
                    |_| Ok(()),
                    |bytes, at| {
                        app.validate(
                            &state,
                            bytes,
                            at,
                            &crate::authority_objects::Resolved::default(),
                        )
                    },
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let prepare = Certificate::collect(config, &votes[..3]).unwrap();
    let votes = engines
        .iter_mut()
        .map(|e| SignedVote::parse(config, &e.advance_phase(&prepare.bytes).unwrap()).unwrap())
        .collect::<Vec<_>>();
    let precommit = Certificate::collect(config, &votes[..3]).unwrap();
    let votes = engines
        .iter_mut()
        .map(|e| SignedVote::parse(config, &e.advance_phase(&precommit.bytes).unwrap()).unwrap())
        .collect::<Vec<_>>();
    Certificate::collect(config, &votes[..3]).unwrap()
}
#[test]
fn fresh_committee_preserves_policy_state_and_votes_only_after_durable_ready_quorum() {
    let f = fixture();
    let config = f.app.config.clone();
    let mut keys = (1..=4).map(vectors::key).collect::<Vec<_>>();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let keys: [SigningKey; 4] = keys.try_into().unwrap();
    let directories = (0..4).map(|_| Directory::new()).collect::<Vec<_>>();
    let mut engines = directories
        .iter()
        .zip(&keys)
        .map(|(d, k)| Engine::create(&d.0, config.clone(), k.clone(), f.initial.clone()).unwrap())
        .collect::<Vec<_>>();
    for i in 0..4 {
        let prior = engines[0].application().to_vec();
        let request = register(&f, &prior, i);
        let command = f.committed(&request, 8000, 10000, i as u64 + 1).command;
        consensus::tests::enter(&config, &keys, &mut engines, i as u64 + 1);
        let commit = phases(&config, &mut engines, &command);
        for engine in &mut engines {
            engine.decide(&commit.bytes).unwrap();
            engine
                .apply_committed(|prior, position| {
                    f.app.execute(
                        prior,
                        position,
                        &crate::authority_objects::Resolved::default(),
                    )
                })
                .unwrap();
            assert_eq!(engine.applied().unwrap().height, i as u64 + 1);
        }
    }
    let prior = engines[0].application().to_vec();
    let declaration = declaration(&f, &prior);
    let request = reconfigure(&f, &prior, &declaration);
    let committed = f.committed(&request, 8000, 10000, 5);
    let mut stale = declaration.clone();
    let mut value = wire::decode(&stale.bytes)
        .unwrap()
        .array(8)
        .unwrap()
        .to_vec();
    let mut snapshot = value[6].array(2).unwrap().to_vec();
    let mut point = snapshot[0].array(3).unwrap().to_vec();
    point[2] = b(&[199; 32]);
    snapshot[0] = array(point);
    value[6] = array(snapshot);
    stale = Declaration::parse(&wire::encode(&array(value)).unwrap()).unwrap();
    let stale_request = reconfigure(&f, &prior, &stale);
    assert_eq!(
        code(
            &f.app
                .execute(
                    &prior,
                    &f.committed(&stale_request, 8000, 10000, 5),
                    &crate::authority_objects::Resolved::default()
                )
                .unwrap()
        ),
        12
    );
    consensus::tests::enter(&config, &keys, &mut engines, 5);
    let terminal_commit = phases(&config, &mut engines, &committed.command);
    // A later no-op may decide the declaration, but it must not move the applied policy past it.
    consensus::tests::enter(&config, &keys, &mut engines, 6);
    let leader = config.leader(6).unwrap();
    let leader = engines.iter().position(|e| e.signer() == leader).unwrap();
    assert!(engines[leader].propose(&committed.command, 10000).is_err());
    let wrong = epoch::noop(config.descriptor().scope(), [197; 32]).unwrap();
    assert!(engines[leader].propose(&wrong, 10000).is_err());
    let noop = engines[leader].terminal_progress().unwrap().unwrap();
    assert_eq!(
        noop,
        epoch::noop(config.descriptor().scope(), terminal_commit.node).unwrap()
    );
    let commit = phases(&config, &mut engines, &noop);
    for engine in &mut engines {
        engine.decide(&commit.bytes).unwrap();
        let result = engine
            .apply_committed(|prior, position| {
                f.app.execute(
                    prior,
                    position,
                    &crate::authority_objects::Resolved::default(),
                )
            })
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            crate::authority_proof::OperationResult::parse(&result[0].result)
                .unwrap()
                .code,
            0
        );
        assert!(engine.halted());
        assert!(!engine.can_vote());
        assert!(engine.retransmit_wish().is_err());
        assert_eq!(engine.applied().unwrap().height, 5);
    }
    let shares = engines
        .iter()
        .take(3)
        .map(|e| e.terminal_share().unwrap())
        .collect::<Vec<_>>();
    assert!(epoch::assemble_checkpoint(config.descriptor(), &shares[..2]).is_err());
    let checkpoint = epoch::assemble_checkpoint(config.descriptor(), &shares).unwrap();
    let handoffs = engines
        .iter()
        .take(3)
        .map(|e| e.handoff_share(&checkpoint).unwrap())
        .collect::<Vec<_>>();
    let evidence = epoch::assemble_handoff(config.descriptor(), &handoffs).unwrap();
    let history = engines[0]
        .terminal_history(&checkpoint, &config.descriptor().genesis().unwrap(), None)
        .unwrap();
    let terminal = epoch::verify_terminal(
        config.descriptor(),
        &config.descriptor().genesis().unwrap(),
        None,
        &evidence,
        &history,
    )
    .unwrap();
    let terminal_state = engines[0].application().to_vec();
    let generation = engines[0].generation();
    drop(engines.remove(0));
    let old = Engine::open(
        &directories[0].0,
        config.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    assert!(old.halted());
    assert!(!old.can_vote());
    assert_eq!(old.terminal_share().unwrap(), shares[0]);
    let next_config = config.successor(&terminal).unwrap();
    let next_keys = committee()
        .into_iter()
        .map(vectors::key)
        .collect::<Vec<_>>();
    let next_directories = (0..4).map(|_| Directory::new()).collect::<Vec<_>>();
    let mut next = next_directories
        .iter()
        .zip(&next_keys)
        .map(|(d, k)| {
            Engine::prepare_epoch(&d.0, config.clone(), k.clone(), &terminal_state, &terminal)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let initial = next[0].application().to_vec();
    let before = wire::decode_state(&terminal_state).unwrap();
    let after = wire::decode_state(&initial).unwrap();
    assert_eq!(
        &before.array(13).unwrap()[6..11],
        &after.array(13).unwrap()[6..11]
    );
    PolicyApplication::new(next_config.clone())
        .validate_checkpoint(&initial, 0)
        .unwrap();
    for engine in &mut next {
        assert!(!engine.can_vote());
        assert!(engine.retransmit_wish().is_err());
    }
    let readiness = next
        .iter()
        .take(3)
        .map(|e| e.readiness_share().unwrap())
        .collect::<Vec<_>>();
    assert!(epoch::assemble_ready(terminal.clone(), &readiness[..2]).is_err());
    let activation = epoch::assemble_ready(terminal, &readiness).unwrap();
    let minimum = next[0].generation();
    drop(next.remove(0));
    let mut reopened = Engine::open(
        &next_directories[0].0,
        next_config.clone(),
        next_keys[0].clone(),
        minimum,
    )
    .unwrap();
    assert!(!reopened.can_vote());
    reopened.activate_epoch(&activation).unwrap();
    let minimum = reopened.generation();
    drop(reopened);
    let reopened = Engine::open(
        &next_directories[0].0,
        next_config.clone(),
        next_keys[0].clone(),
        minimum,
    )
    .unwrap();
    assert!(reopened.can_vote());
    next.insert(0, reopened);
    for engine in next.iter_mut().skip(1) {
        engine.activate_epoch(&activation).unwrap();
    }
    let new = tests::Fixture {
        app: PolicyApplication::new(next_config.clone()),
        initial,
        bootstrap: f.bootstrap,
        requester: f.requester,
        expected: f.expected,
        grant: f.grant,
    };
    let status = wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(55),
            V::Uint(1),
            b(&next_config.scope.network),
            b(&next_config.scope.incarnation),
            b(&new.requester.verifying_key().to_bytes()),
            b(&[198; 32]),
            V::Uint(1),
            V::Uint(0),
        ]))
        .unwrap(),
        &new.requester,
    )
    .unwrap();
    let command = new.committed(&status, 8000, 10000, 1).command;
    let next_keys: [SigningKey; 4] = next_keys.try_into().unwrap();
    consensus::tests::enter(&next_config, &next_keys, &mut next, 1);
    let commit = phases(&next_config, &mut next, &command);
    for engine in &mut next {
        engine.decide(&commit.bytes).unwrap();
        assert_eq!(
            engine
                .apply_committed(|prior, position| new.app.execute(
                    prior,
                    position,
                    &crate::authority_objects::Resolved::default()
                ))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(engine.applied().unwrap().height, 1);
    }
}
