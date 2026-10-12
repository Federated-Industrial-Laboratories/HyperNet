// SPDX-License-Identifier: MIT
use super::{
    tests::{Fixture, result_bytes},
    *,
};
use crate::authority_membership::{Acceptance, Mutation};
use ed25519_dalek::SigningKey;

pub(super) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub(super) fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}
pub(super) fn code(execution: &Execution) -> u64 {
    wire::decode(result_bytes(execution))
        .unwrap()
        .array(6)
        .unwrap()[4]
        .uint()
        .unwrap()
}
pub(super) fn snapshot(f: &Fixture, prior: &[u8], refs: &[VersionRef]) -> V {
    array(vec![
        array(vec![
            V::Uint(f.app.config.scope.epoch),
            V::Uint(State::parse(&f.app.config, prior).unwrap().height),
            b(&wire::digest(prior)),
        ]),
        array(refs.iter().map(reference).collect()),
    ])
}
pub(super) fn signed(
    f: &Fixture,
    prior: &[u8],
    signer: &SigningKey,
    action: &str,
    resource: [u8; 32],
    parameters: V,
    refs: Vec<VersionRef>,
) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let metadata = state.streams.metadata(&public(signer)).unwrap().unwrap();
    let sequence = metadata
        .completion
        .map_or(metadata.retired_through, |v| v.sequence)
        + 1;
    wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(20),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            V::Uint(metadata.generation),
            b(&metadata.generation_id),
            V::Uint(sequence),
            V::Uint(sequence - 1),
            b(&public(signer)),
            V::Text(action.into()),
            b(&resource),
            V::Uint(1),
            V::Uint(0),
            V::Uint(f.app.config.scope.epoch),
            V::Uint(state.height),
            array(refs.iter().map(reference).collect()),
            b(&wire::encode(&parameters).unwrap()),
        ]))
        .unwrap(),
        signer,
    )
    .unwrap()
}
fn prepare(
    f: &Fixture,
    prior: &[u8],
    action: &str,
    resource: [u8; 32],
    mut parameters: V,
    at: u64,
) -> Vec<u8> {
    let provisional = signed(
        f,
        prior,
        &f.requester,
        action,
        resource,
        parameters.clone(),
        vec![],
    );
    let intent = Intent::from_signed(&provisional).unwrap();
    let state = State::parse(&f.app.config, prior).unwrap();
    let mutation = Mutation::parse(&intent).unwrap();
    let decision = mutation
        .prepare(&state.records, &state.reservations, &intent, at, false)
        .unwrap();
    let V::Array(fields) = &mut parameters else {
        unreachable!()
    };
    fields[5] = snapshot(f, prior, &decision.dependencies);
    signed(
        f,
        prior,
        &f.requester,
        action,
        resource,
        parameters,
        decision.dependencies,
    )
}
pub(super) fn execute(
    f: &Fixture,
    prior: &[u8],
    request: &[u8],
    signer: &SigningKey,
    at: u64,
) -> Execution {
    let height = State::parse(&f.app.config, prior).unwrap().height + 1;
    let committed = f.with_recipient(request, at - 1500, at, height, signer);
    f.app
        .validate(
            prior,
            &committed.command,
            at,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    f.app
        .execute(
            prior,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap()
}
pub(super) fn child(f: &Fixture, subject: [u8; 32], id: u8) -> V {
    let tier = f.expected.iter().find(|v| v.kind == 101).unwrap();
    array(vec![
        b(&[id; 32]),
        b(&subject),
        reference(tier),
        array(vec![V::Uint(0)]),
        array(vec![array(vec![
            V::Uint(0),
            b(&f.app.config.scope.network),
        ])]),
        array(vec![V::Uint(1000), V::Uint(900000)]),
        V::Uint(0),
        array(vec![V::Uint(10), V::Uint(10), V::Uint(1), V::Uint(1)]),
    ])
}
pub(super) fn delegate(f: &Fixture, prior: &[u8], child: V, at: u64) -> Vec<u8> {
    let id = child.array(8).unwrap()[0].fixed().unwrap();
    prepare(
        f,
        prior,
        "AuthorityDelegateGrant",
        id,
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegateGrant".into()),
            reference(
                f.expected
                    .iter()
                    .find(|v| v.kind == 102 && v.id == f.grant)
                    .unwrap(),
            ),
            child,
            snapshot(f, prior, &[]),
        ]),
        at,
    )
}
pub(super) fn accepted(
    f: &Fixture,
    candidate: &SigningKey,
    reader: VersionRef,
    id: u8,
    end: u64,
) -> Vec<u8> {
    let payload = wire::encode(&array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityMemberAcceptance".into()),
        b(&f.app.config.scope.network),
        b(&f.app.config.scope.incarnation),
        b(&[id; 32]),
        b(&public(candidate)),
        array(vec![V::Uint(1000), V::Uint(900000)]),
        reference(&reader),
        b(&public(&f.requester)),
        b(&[id + 1; 32]),
        array(vec![V::Uint(1000), V::Uint(end)]),
    ]))
    .unwrap();
    let mut pairs = [&f.requester, candidate]
        .into_iter()
        .map(|key| {
            wire::envelope(&wire::sign_envelope(&payload, key).unwrap(), 1)
                .unwrap()
                .1
                .remove(0)
        })
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(key, _)| *key);
    wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(
            pairs
                .iter()
                .map(|(key, sig)| array(vec![b(key), b(sig)]))
                .collect(),
        ),
    ]))
    .unwrap()
}
pub(super) fn admit(f: &Fixture, prior: &[u8], accepted: &[u8], at: u64) -> Vec<u8> {
    let parsed = Acceptance::parse(
        accepted,
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        true,
    )
    .unwrap();
    prepare(
        f,
        prior,
        "AuthorityAdmitMember",
        parsed.member_id,
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityAdmitMember".into()),
            b(&f.grant),
            b(accepted),
            snapshot(f, prior, &[]),
        ]),
        at,
    )
}
pub(super) fn reader(f: &Fixture, prior: &[u8], id: u8) -> VersionRef {
    let state = State::parse(&f.app.config, prior).unwrap();
    Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap()
    .versions()
    .into_iter()
    .find(|r| r.kind == 102 && r.id == [id; 32])
    .unwrap()
}
fn setup(f: &Fixture, candidate: &SigningKey) -> (Vec<u8>, Vec<u8>) {
    let request = delegate(f, &f.initial, child(f, public(candidate), 70), 5000);
    let delegated = execute(f, &f.initial, &request, &f.requester, 5000);
    assert_eq!(code(&delegated), 0);
    let envelope = accepted(f, candidate, reader(f, &delegated.state, 70), 71, 20000);
    (delegated.state, envelope)
}
#[test]
fn admission_is_atomic_audited_and_replay_preserves_a_fenced_candidate() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let candidate = key(80);
    let (prior, envelope) = setup(&f, &candidate);
    assert_eq!(
        State::parse(&f.app.config, &prior).unwrap().streams.keys(),
        vec![public(&f.requester)]
    );
    // A fresh own-status advances the snapshot after the offline acceptance.
    let status = wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(55),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            b(&public(&f.requester)),
            b(&[88; 32]),
            V::Uint(0),
            V::Uint(1),
        ]))
        .unwrap(),
        &f.requester,
    )
    .unwrap();
    let advanced = execute(&f, &prior, &status, &f.requester, 7000);
    let request = admit(&f, &advanced.state, &envelope, 10000);
    let admitted = execute(&f, &advanced.state, &request, &f.requester, 10000);
    assert_eq!(code(&admitted), 0);
    let state = State::parse(&f.app.config, &admitted.state).unwrap();
    assert_eq!(state.evidence.value().list(512).unwrap().len(), 2);
    let metadata = state
        .streams
        .metadata(&public(&candidate))
        .unwrap()
        .unwrap();
    let scope = crate::authority_proof::Scope {
        network: f.app.config.scope.network,
        incarnation: f.app.config.scope.incarnation,
        configuration: f.app.config.scope.configuration,
        epoch: 0,
    };
    let fence = wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(57),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&public(&candidate)),
            b(&[89; 32]),
            V::Uint(0),
            V::Uint(state.height),
            V::Uint(metadata.generation),
            b(&metadata.generation_id),
            b(&wire::digest(
                &state
                    .streams
                    .metadata_bytes(&scope, &public(&candidate))
                    .unwrap(),
            )),
        ]))
        .unwrap(),
        &candidate,
    )
    .unwrap();
    let fenced = execute(&f, &admitted.state, &fence, &candidate, 12000);
    assert_eq!(code(&fenced), 0);
    let replay = execute(&f, &fenced.state, &request, &f.requester, 25000);
    assert_eq!(code(&replay), 0);
    assert_eq!(result_bytes(&admitted), result_bytes(&replay));
    let before = State::parse(&f.app.config, &fenced.state).unwrap();
    let after = State::parse(&f.app.config, &replay.state).unwrap();
    assert_eq!(before.streams.value(), after.streams.value());
    assert_eq!(before.evidence.value(), after.evidence.value());
    f.app.validate_checkpoint(&replay.state, 5).unwrap();
    // Default membership never supplies inspection authority.
    let gov = Governance::parse(scope.network, scope.incarnation, &after.records).unwrap();
    assert!(
        gov.current_capability(
            [70; 32],
            &crate::authority_governance::Requirement {
                subject: public(&candidate),
                actions: &[25],
                scope: (0, scope.network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 25000,
                expected: &[]
            }
        )
        .is_err()
    );
}
#[test]
fn checkpoint_rejects_missing_evidence_changed_roles_and_unadmitted_streams() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let candidate = key(80);
    let (prior, envelope) = setup(&f, &candidate);
    let request = admit(&f, &prior, &envelope, 10000);
    let applied = execute(&f, &prior, &request, &f.requester, 10000);
    f.app.validate_checkpoint(&applied.state, 2).unwrap();
    for index in [8, 9] {
        let mut fields = wire::decode(&applied.state)
            .unwrap()
            .array(13)
            .unwrap()
            .to_vec();
        fields[index] = array(vec![]);
        assert!(
            f.app
                .validate_checkpoint(&wire::encode(&array(fields)).unwrap(), 2)
                .is_err()
        );
    }
    let mut state = State::parse(&f.app.config, &applied.state).unwrap();
    state
        .streams
        .admit(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            public(&key(81)),
        )
        .unwrap();
    assert!(
        f.app
            .validate_checkpoint(&state.encode(&f.app.config).unwrap(), 2)
            .is_err()
    );
    let mut fields = wire::decode(&applied.state)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    let V::Array(evidence) = &mut fields[9] else {
        unreachable!()
    };
    let V::Array(entry) = &mut evidence[1] else {
        unreachable!()
    };
    entry[3] = V::Uint(25000);
    assert!(
        f.app
            .validate_checkpoint(&wire::encode(&array(fields)).unwrap(), 2)
            .is_err()
    );
}
#[test]
fn possession_is_structural_and_expired_or_duplicate_acceptance_has_no_effect() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let candidate = key(80);
    let (prior, envelope) = setup(&f, &candidate);
    let (mut payload, pairs) = wire::envelope(&envelope, 2).unwrap();
    let last = payload.len() - 1;
    payload[last] ^= 1;
    let tampered = wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(
            pairs
                .iter()
                .map(|(key, sig)| array(vec![b(key), b(sig)]))
                .collect(),
        ),
    ]))
    .unwrap();
    assert!(
        Acceptance::parse(
            &tampered,
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            true
        )
        .is_err()
    );
    let expired = admit(&f, &prior, &envelope, 25000);
    let refusal = execute(&f, &prior, &expired, &f.requester, 25000);
    assert_eq!(code(&refusal), 7);
    let before = State::parse(&f.app.config, &prior).unwrap();
    let after = State::parse(&f.app.config, &refusal.state).unwrap();
    assert_eq!(before.records, after.records);
    assert_eq!(before.evidence.value(), after.evidence.value());
    let request = admit(&f, &prior, &envelope, 10000);
    let applied = execute(&f, &prior, &request, &f.requester, 10000);
    let duplicate = admit(&f, &applied.state, &envelope, 12000);
    let refused = execute(&f, &applied.state, &duplicate, &f.requester, 12000);
    assert_eq!(code(&refused), 28);
    assert_eq!(
        State::parse(&f.app.config, &applied.state).unwrap().records,
        State::parse(&f.app.config, &refused.state).unwrap().records
    );
}
#[test]
fn mutation_authorities_are_separate_and_dedicated_keys_cannot_be_subjects() {
    let f = Fixture::with_actions(1000, vec![0, 10, 25]);
    let request = delegate(&f, &f.initial, child(&f, public(&key(80)), 70), 5000);
    assert_eq!(
        code(&execute(&f, &f.initial, &request, &f.requester, 5000)),
        3
    );
    let f = Fixture::with_actions(1000, vec![0, 11, 25]);
    let candidate = key(80);
    let (prior, envelope) = setup(&f, &candidate);
    let request = admit(&f, &prior, &envelope, 10000);
    assert_eq!(code(&execute(&f, &prior, &request, &f.requester, 10000)), 3);
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let state = State::parse(&f.app.config, &f.initial).unwrap();
    for (_, reserved) in &state.reservations.0 {
        let request = delegate(&f, &f.initial, child(&f, *reserved, 70), 5000);
        let result = execute(&f, &f.initial, &request, &f.requester, 5000);
        assert_eq!(code(&result), 38);
    }
}
#[test]
fn child_attenuation_and_stale_snapshot_refuse_before_mutation() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    for (index, value, expected) in [
        (3, array(vec![V::Uint(31)]), 4),
        (5, array(vec![V::Uint(0), V::Uint(900000)]), 4),
        (6, V::Uint(8), 4),
        (
            7,
            array(vec![V::Uint(101), V::Uint(1), V::Uint(1), V::Uint(1)]),
            4,
        ),
    ] {
        let mut c = child(&f, public(&key(80)), 70).array(8).unwrap().to_vec();
        c[index] = value;
        let request = delegate(&f, &f.initial, array(c), 5000);
        let result = execute(&f, &f.initial, &request, &f.requester, 5000);
        assert_eq!(code(&result), expected);
        assert_eq!(
            State::parse(&f.app.config, &result.state).unwrap().records,
            State::parse(&f.app.config, &f.initial).unwrap().records
        );
    }
    let request = delegate(&f, &f.initial, child(&f, public(&key(80)), 70), 5000);
    let status = wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(55),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            b(&public(&f.requester)),
            b(&[87; 32]),
            V::Uint(0),
            V::Uint(0),
        ]))
        .unwrap(),
        &f.requester,
    )
    .unwrap();
    let advanced = execute(&f, &f.initial, &status, &f.requester, 5000);
    assert_eq!(
        code(&execute(&f, &advanced.state, &request, &f.requester, 6000)),
        12
    );
}
#[test]
fn finite_audit_capacity_refuses_atomically_without_orphan_grants() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let request = delegate(&f, &f.initial, child(&f, public(&key(80)), 100), 5000);
    let intent = Intent::from_signed(&request).unwrap();
    let committed = f.committed(&request, 3500, 5000, 1);
    let ordered = OrderedRequest::parse(&f.app.config, &committed.command).unwrap();
    let mut state = State::parse(&f.app.config, &f.initial).unwrap();
    let mut available = state.clone();
    let (_, accepted, _, _) = f
        .app
        .ordinary(
            &f.initial,
            &mut available,
            &intent,
            &ordered,
            &committed,
            0,
            ordered.recipient,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(accepted, 0);

    // Synthetic charged evidence exercises the real preflight boundary without
    // thousands of signed mutations. It is not an installable checkpoint.
    state.evidence = mutation_evidence::Evidence::at_capacity();
    state.capacity().unwrap();
    let before_records = state.records.clone();
    let before_evidence = state.evidence.value();
    let before_keys = state.streams.keys();
    let (_, code, _, _) = f
        .app
        .ordinary(
            &f.initial,
            &mut state,
            &intent,
            &ordered,
            &committed,
            0,
            ordered.recipient,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code, 2);
    assert_eq!(state.records, before_records);
    assert_eq!(state.evidence.value(), before_evidence);
    assert_eq!(state.streams.keys(), before_keys);
}

#[test]
fn reader_revocation_is_permanent_without_rewriting_membership_or_stream() {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let candidate = key(80);
    let (prior, envelope) = setup(&f, &candidate);
    let request = admit(&f, &prior, &envelope, 10000);
    let applied = execute(&f, &prior, &request, &f.requester, 10000);
    let before = State::parse(&f.app.config, &applied.state).unwrap();
    let revoke = super::transaction_tests::revoke(&f, &applied.state, [70; 32], 3);
    let revoked = execute(&f, &applied.state, &revoke, &f.requester, 12000);
    assert_eq!(code(&revoked), 0);
    let after = State::parse(&f.app.config, &revoked.state).unwrap();
    assert_eq!(
        before.streams.metadata(&public(&candidate)).unwrap(),
        after.streams.metadata(&public(&candidate)).unwrap()
    );
    let gov = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &after.records,
    )
    .unwrap();
    assert!(gov.revoked_chain([70; 32]).unwrap());
    assert_eq!(
        wire::decode(gov.record_bytes(125, [71; 32]).unwrap())
            .unwrap()
            .array(12)
            .unwrap()[9],
        V::Bool(false)
    );
    assert_eq!(after.evidence.value().list(512).unwrap().len(), 3);
    f.app.validate_checkpoint(&revoked.state, 3).unwrap();
    let reuse = delegate(&f, &revoked.state, child(&f, public(&candidate), 70), 15000);
    assert_eq!(
        code(&execute(&f, &revoked.state, &reuse, &f.requester, 15000)),
        6
    );
    // Even a valid acceptance cannot admit a new member using a revoked reader.
    let mut accepted_payload = wire::decode(&wire::envelope(&envelope, 2).unwrap().0)
        .unwrap()
        .array(12)
        .unwrap()
        .to_vec();
    accepted_payload[5] = b(&[90; 32]);
    let payload = wire::encode(&array(accepted_payload)).unwrap();
    let mut signatures = [&candidate, &f.requester]
        .into_iter()
        .map(|key| {
            wire::envelope(&wire::sign_envelope(&payload, key).unwrap(), 1)
                .unwrap()
                .1
                .remove(0)
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|(key, _)| *key);
    let envelope = wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(
            signatures
                .iter()
                .map(|(key, sig)| array(vec![b(key), b(sig)]))
                .collect(),
        ),
    ]))
    .unwrap();
    let fresh = admit(&f, &revoked.state, &envelope, 15000);
    assert_eq!(
        code(&execute(&f, &revoked.state, &fresh, &f.requester, 15000)),
        6
    );
}
