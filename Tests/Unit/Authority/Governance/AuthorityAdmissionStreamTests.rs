// SPDX-License-Identifier: MIT
// Adoption transfers exact invitation streams without retaining retired assignment authority.
use super::{membership_tests as member, *};
use crate::{
    authority_admission::{self as admission, tests as native},
    authority_deployment_tests as vectors,
    authority_domains::{self as domains, routes},
    authority_membership::Snapshot,
};
use ed25519_dalek::SigningKey;

fn fixture() -> tests::Fixture {
    let source = vectors::Fixture::with_actions(vec![0, 6, 10, 11, 12, 13, 26, 30]);
    let verified = crate::trust_bootstrap::check(&source.bootstrap, true, 1000).unwrap();
    let config = Configuration::trusted(verified.descriptor().canonical()).unwrap();
    let initial = wire::decode(&source.bootstrap).unwrap().array(6).unwrap()[3]
        .bytes()
        .unwrap()
        .to_vec();
    let expected = Governance::record_versions(
        config.scope.network,
        config.scope.incarnation,
        &State::parse(&config, &initial).unwrap().records,
    )
    .unwrap();
    tests::Fixture {
        app: PolicyApplication::new(config),
        initial,
        bootstrap: source.bootstrap,
        requester: vectors::key(5),
        expected,
        grant: [23; 32],
    }
}

fn apply(f: &tests::Fixture, prior: &mut Vec<u8>, request: &[u8], signer: &SigningKey) {
    let result = member::execute(f, prior, request, signer, 5000);
    assert_eq!(member::code(&result), 0);
    *prior = result.state;
    let height = State::parse(&f.app.config, prior).unwrap().height;
    PolicyApplication::new(f.app.config.clone())
        .validate_checkpoint(prior, height)
        .unwrap();
}

fn reject_old_request(
    f: &tests::Fixture,
    prior: &mut Vec<u8>,
    request: &[u8],
    signer: &SigningKey,
) {
    let height = State::parse(&f.app.config, prior).unwrap().height + 1;
    let committed = f.with_recipient(request, 3500, 5000, height, signer);
    let inputs = crate::authority_objects::Resolved::default();
    assert!(
        f.app
            .validate(prior, &committed.command, 5000, &inputs)
            .is_err()
    );
    // A request already ordered before retirement must also produce no effect.
    let refused = f.app.execute(prior, &committed, &inputs).unwrap();
    assert_ne!(member::code(&refused), 0);
    PolicyApplication::new(f.app.config.clone())
        .validate_checkpoint(&refused.state, height)
        .unwrap();
    *prior = refused.state;
}

fn domain(
    f: &tests::Fixture,
    prior: &[u8],
    signer: &SigningKey,
    command: routes::Command,
    grant: bool,
) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let snapshot =
        |refs: &[VersionRef]| domains::snapshot(&member::snapshot(f, prior, refs)).unwrap();
    let mut operation = domains::Operation {
        grant: grant.then(|| {
            Governance::record_versions(
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
                &state.records,
            )
            .unwrap()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == f.grant)
            .unwrap()
        }),
        command: domains::Command::Route(command),
        snapshot: snapshot(&[]),
    };
    let sign = |operation: &domains::Operation, refs: Vec<VersionRef>| {
        let request = member::signed(
            f,
            prior,
            signer,
            "AuthorityDomain",
            operation.command.resource(),
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            refs,
        );
        let (payload, _) = wire::envelope(&request, 1).unwrap();
        let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
        fields[11] = V::Uint(u64::from(operation.mutation()));
        wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), signer).unwrap()
    };
    let provisional = sign(&operation, vec![]);
    let intent = Intent::from_signed(&provisional).unwrap();
    let decision = operation
        .prepare(
            &state.domains,
            &state.records,
            &state.reservations,
            &intent,
            5000,
            false,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    operation.snapshot = snapshot(&decision.dependencies);
    sign(&operation, decision.dependencies)
}

fn current_snapshot(f: &tests::Fixture, prior: &[u8], snapshot: &Snapshot) -> Snapshot {
    Snapshot::parse(&member::snapshot(f, prior, &snapshot.references)).unwrap()
}

fn update_snapshot(f: &tests::Fixture, prior: &[u8], op: &mut admission::Operation) {
    op.snapshot = current_snapshot(f, prior, &op.snapshot);
    let mut next = wire::decode(&op.next).unwrap().array(9).unwrap().to_vec();
    next[8] = op.snapshot.value.clone();
    op.next = wire::encode(&array(next)).unwrap();
    if op.transition == admission::Transition::Policy {
        op.policy = op.next.clone();
    }
}

fn native_request(
    f: &tests::Fixture,
    prior: &[u8],
    signer: &SigningKey,
    op: &admission::Operation,
) -> Vec<u8> {
    let reference = admission::record_reference(
        &op.next,
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
    )
    .unwrap();
    let request = member::signed(
        f,
        prior,
        signer,
        "AuthorityAdmission",
        reference.id,
        wire::decode(&op.parameters().unwrap()).unwrap(),
        op.snapshot.references.clone(),
    );
    let (payload, _) = wire::envelope(&request, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[11] = V::Uint(reference.generation);
    let signed = wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), signer).unwrap();
    let intent = Intent::from_signed(&signed).unwrap();
    let parsed = admission::Operation::parse(&intent).unwrap();
    let state = State::parse(&f.app.config, prior).unwrap();
    parsed
        .authorise(&state.records, &state.reservations, &intent, 5000, false)
        .unwrap();
    signed
}

fn register_routes(f: &tests::Fixture, prior: &mut Vec<u8>) -> [routes::RegisteredProfile; 3] {
    use crate::authority_deployments::{Offer, Operation};
    let profiles = routes::tests::admission_profiles();
    for (index, profile) in profiles.iter().enumerate() {
        let index = u8::try_from(index).unwrap();
        let manifest = &profile.manifest;
        let consent = wire::sign_envelope(
            &manifest.unsigned_consent(0).unwrap(),
            &vectors::key(90 + 2 * index),
        )
        .unwrap();
        let possessions = [(0, 160 + index), (1, 110 + index), (2, 91)].map(|(class, seed)| {
            b(&wire::sign_envelope(
                &Offer::possession(
                    manifest,
                    class,
                    member::public(&vectors::key(seed)),
                    [180 + index; 32],
                    manifest.validity,
                )
                .unwrap(),
                &vectors::key(seed),
            )
            .unwrap())
        });
        let offer = Offer::parse(
            &manifest.encode().unwrap(),
            &consent,
            &array(possessions.to_vec()),
        )
        .unwrap();
        let state = State::parse(&f.app.config, prior).unwrap();
        let grant = f
            .expected
            .iter()
            .find(|r| r.kind == 102 && r.id == f.grant)
            .unwrap();
        let request = |refs: &[VersionRef]| {
            member::signed(
                f,
                prior,
                &f.requester,
                "AuthorityDeploymentRegister",
                manifest.deployment,
                array(vec![
                    V::Uint(200),
                    V::Uint(1),
                    V::Text("AuthorityDeploymentRegister".into()),
                    reference(grant),
                    b(&offer.manifest_bytes),
                    b(&offer.consent),
                    offer.possessions_value(),
                    member::snapshot(f, prior, refs),
                    V::Bool(false),
                ]),
                refs.to_vec(),
            )
        };
        let provisional = request(&[]);
        let intent = Intent::from_signed(&provisional).unwrap();
        let decision = Operation::parse(&intent)
            .unwrap()
            .prepare(
                &state.records,
                &state.reservations,
                &intent,
                5000,
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
        let request = request(&refs);
        apply(f, prior, &request, &f.requester);
        let request = domain(
            f,
            prior,
            &f.requester,
            routes::Command::Register {
                profile: Box::new(profile.clone()),
            },
            true,
        );
        apply(f, prior, &request, &f.requester);
    }
    profiles
}

#[test]
fn adopted_invitation_streams_retire_reopen_and_reassign_without_replay() {
    let f = fixture();
    let mut prior = f.initial.clone();
    let profiles = register_routes(&f, &mut prior);
    let keys = [
        (native::signer(800), native::signer(801)),
        (native::signer(802), native::signer(803)),
    ];
    let unrelated = native::signer(804);
    let mut acceptances = Vec::new();
    for (index, key) in keys
        .iter()
        .map(|(key, _)| key)
        .chain([&unrelated])
        .enumerate()
    {
        let id = 70 + u8::try_from(index).unwrap() * 2;
        let request =
            member::delegate(&f, &prior, member::child(&f, member::public(key), id), 5000);
        apply(&f, &mut prior, &request, &f.requester);
        let accepted = member::accepted(&f, key, member::reader(&f, &prior, id), id + 1, 20000);
        let offer =
            wire::sign_envelope(&wire::envelope(&accepted, 2).unwrap().0, &f.requester).unwrap();
        let request = domain(
            &f,
            &prior,
            &f.requester,
            routes::Command::Invite { offer },
            true,
        );
        apply(&f, &mut prior, &request, &f.requester);
        let request = member::admit(&f, &prior, &accepted, 5000);
        apply(&f, &mut prior, &request, &f.requester);
        acceptances.push(accepted);
    }
    let request = domain(
        &f,
        &prior,
        &keys[0].0,
        routes::Command::CandidateContext {
            accepted: acceptances[0].clone(),
        },
        false,
    );
    apply(&f, &mut prior, &request, &keys[0].0);
    let old_request = request;
    let original = State::parse(&f.app.config, &prior)
        .unwrap()
        .streams
        .metadata(&member::public(&keys[0].0))
        .unwrap()
        .unwrap();
    let (_, _, mut policy) = native::fixture();
    policy.parent = f
        .expected
        .iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
        .unwrap()
        .clone();
    policy.relay = profiles[0].identity.service;
    policy.authority = profiles[1].identity.service;
    for template in &mut policy.templates {
        template.destination = profiles[2].identity.service;
    }
    let state = State::parse(&f.app.config, &prior).unwrap();
    let manual = state
        .records
        .iter()
        .filter(|bytes| wire::decode(bytes).unwrap().list(32).unwrap()[0] == V::Uint(125))
        .cloned()
        .collect::<Vec<_>>();
    // Eligibility alone does not transfer the unrelated invitation's stream.
    policy.legacy = Governance::record_versions(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &manual,
    )
    .unwrap();
    let snapshot = current_snapshot(&f, &prior, &native::snapshot(&state.records, None));
    policy.bytes = native::record(180, policy.reference.id, policy.payload(), &snapshot, None);
    policy = admission::Policy::parse(
        &policy.bytes,
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
    )
    .unwrap();
    let op = admission::Operation {
        transition: admission::Transition::Policy,
        policy: policy.bytes.clone(),
        previous: None,
        next: policy.bytes.clone(),
        acceptance: vec![],
        legacy: vec![],
        snapshot,
    };
    let request = native_request(&f, &prior, &f.requester, &op);
    apply(&f, &mut prior, &request, &f.requester);
    let registrar = native::signer(100);
    let mut old = None;
    for ordinal in 1..=2 {
        let state = State::parse(&f.app.config, &prior).unwrap();
        let mut op = native::reserve(&state.records, &policy, 0, ordinal, old.as_ref(), &keys);
        update_snapshot(&f, &prior, &mut op);
        let request = native_request(&f, &prior, &registrar, &op);
        apply(&f, &mut prior, &request, &registrar);
        let pending = admission::Slot::parse(
            &op.next,
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
        )
        .unwrap();
        let state = State::parse(&f.app.config, &prior).unwrap();
        let snapshot = current_snapshot(
            &f,
            &prior,
            &native::snapshot(&state.records, Some(&pending)),
        );
        let mut op =
            native::enrol_with_snapshot(&state.records, &policy, &pending, &keys, snapshot);
        if ordinal == 1 {
            op.transition = admission::Transition::Adopt;
            op.legacy = manual
                .iter()
                .filter(|bytes| {
                    keys.iter().any(|(key, _)| {
                        wire::decode(bytes).unwrap().array(12).unwrap()[7]
                            == b(&member::public(key))
                    })
                })
                .cloned()
                .collect();
            op.snapshot.references.extend(
                Governance::record_versions(
                    f.app.config.scope.network,
                    f.app.config.scope.incarnation,
                    &op.legacy,
                )
                .unwrap(),
            );
            op.snapshot.references.sort_by_key(VersionRef::index);
            op.snapshot.references.dedup();
            op.snapshot = current_snapshot(&f, &prior, &op.snapshot);
            let mut active = admission::Slot::parse(
                &op.next,
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
            )
            .unwrap();
            active.legacy_streams = keys.iter().map(|(key, _)| member::public(key)).collect();
            active.legacy_streams.sort();
            let parent = wire::decode(
                Governance::parse(
                    f.app.config.scope.network,
                    f.app.config.scope.incarnation,
                    &state.records,
                )
                .unwrap()
                .record_bytes(102, policy.parent.id)
                .unwrap(),
            )
            .unwrap();
            let tier = crate::authority_membership::version(&parent.array(17).unwrap()[9]).unwrap();
            active.material = admission::enrol_material(
                &policy,
                &pending,
                &tier,
                &op.snapshot,
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
            )
            .unwrap();
            op.next = native::record(
                181,
                pending.reference.id,
                active.payload(),
                &op.snapshot,
                Some(&pending.bytes),
            );
        }
        let request = native_request(&f, &prior, &registrar, &op);
        apply(&f, &mut prior, &request, &registrar);
        let active = admission::Slot::parse(
            &op.next,
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
        )
        .unwrap();
        let state = State::parse(&f.app.config, &prior).unwrap();
        let metadata = state
            .streams
            .metadata(&member::public(&keys[0].0))
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata.generation_id == original.generation_id,
            ordinal == 1
        );
        if ordinal == 1 {
            assert_eq!(metadata.generation, original.generation);
            assert_eq!(metadata.retired_through, original.retired_through);
            assert_eq!(
                metadata.completion.as_ref().unwrap().sequence,
                original.completion.as_ref().unwrap().sequence
            );
        }
        assert_eq!(
            state.streams.origin(&member::public(&keys[0].0)).is_none(),
            ordinal == 1
        );
        let transferred = state.evidence.transferred_manual_streams().unwrap();
        assert_eq!(transferred.len(), 2);
        assert!(!transferred.contains(&member::public(&unrelated)));
        if ordinal == 2 {
            reject_old_request(&f, &mut prior, &old_request, &keys[0].0);
        }
        let state = State::parse(&f.app.config, &prior).unwrap();
        let mut op = native::retire(&state.records, &policy, &active);
        update_snapshot(&f, &prior, &mut op);
        let request = native_request(&f, &prior, &registrar, &op);
        apply(&f, &mut prior, &request, &registrar);
        let state = State::parse(&f.app.config, &prior).unwrap();
        for (key, _) in &keys {
            assert!(
                state
                    .streams
                    .metadata(&member::public(key))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            state
                .streams
                .metadata(&member::public(&unrelated))
                .unwrap()
                .is_some()
        );
        reject_old_request(&f, &mut prior, &old_request, &keys[0].0);
        old = Some(
            admission::Slot::parse(
                &op.next,
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
            )
            .unwrap(),
        );
    }
    // An ordinary manual grant revocation does not transfer or erase requester history.
    let state = State::parse(&f.app.config, &prior).unwrap();
    let meta = state
        .streams
        .metadata(&member::public(&f.requester))
        .unwrap()
        .unwrap();
    let sequence = meta.completion.unwrap().sequence + 1;
    let revoke = transaction_tests::revoke(&f, &prior, [74; 32], u8::try_from(sequence).unwrap());
    apply(&f, &mut prior, &revoke, &f.requester);
    let mut state = State::parse(&f.app.config, &prior).unwrap();
    assert!(
        state
            .streams
            .metadata(&member::public(&unrelated))
            .unwrap()
            .is_some()
    );
    assert!(
        !state
            .evidence
            .transferred_manual_streams()
            .unwrap()
            .contains(&member::public(&unrelated))
    );
    state.streams.retire_owned(&member::public(&unrelated));
    assert!(State::parse(&f.app.config, &state.encode(&f.app.config).unwrap()).is_err());
}
