// SPDX-License-Identifier: MIT
use super::{
    membership_tests as m,
    tests::{Fixture, result_bytes},
    *,
};
use crate::authority_applications::{self as applications, Operation};
use crate::authority_governance::Requirement;
use crate::authority_membership::Mutation;
use ed25519_dalek::SigningKey;

fn record(f: &Fixture, prior: &[u8], kind: u64, id: [u8; 32]) -> VersionRef {
    Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &State::parse(&f.app.config, prior).unwrap().records,
    )
    .unwrap()
    .versions()
    .into_iter()
    .find(|v| v.kind == kind && v.id == id)
    .unwrap()
}
fn body(output: &Execution) -> V {
    let value = wire::decode(result_bytes(output)).unwrap();
    wire::decode(value.array(6).unwrap()[5].bytes().unwrap()).unwrap()
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn signed(
    f: &Fixture,
    prior: &[u8],
    key: &SigningKey,
    action: &str,
    resource: [u8; 32],
    parameters: V,
    expected: Vec<VersionRef>,
    mutation: bool,
) -> Vec<u8> {
    let original = m::signed(f, prior, key, action, resource, parameters, expected);
    if mutation {
        return original;
    }
    let mut fields = wire::decode(&wire::envelope(&original, 1).unwrap().0)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    fields[11] = V::Uint(0);
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), key).unwrap()
}
fn mutation(
    f: &Fixture,
    prior: &[u8],
    key: &SigningKey,
    action: &str,
    resource: [u8; 32],
    mut parameters: V,
    at: u64,
) -> Vec<u8> {
    let provisional = signed(
        f,
        prior,
        key,
        action,
        resource,
        parameters.clone(),
        vec![],
        true,
    );
    let intent = Intent::from_signed(&provisional).unwrap();
    let state = State::parse(&f.app.config, prior).unwrap();
    let dependencies = if action == "AuthorityDelegateGrant" {
        Mutation::parse(&intent)
            .unwrap()
            .prepare(&state.records, &state.reservations, &intent, at, false)
            .unwrap()
            .dependencies
    } else {
        let d = Operation::parse(&intent)
            .unwrap()
            .prepare(&state.records, &state.reservations, &intent, at, false)
            .unwrap();
        d.dependencies
            .into_iter()
            .filter(|v| Some(v) != d.created.as_ref())
            .collect()
    };
    let V::Array(fields) = &mut parameters else {
        unreachable!()
    };
    fields[if action == "AuthorityApplicationWithdraw" {
        4
    } else {
        5
    }] = m::snapshot(f, prior, &dependencies);
    signed(
        f,
        prior,
        key,
        action,
        resource,
        parameters,
        dependencies,
        true,
    )
}
fn delegate(
    f: &Fixture,
    prior: &[u8],
    owner: &SigningKey,
    parent: VersionRef,
    target: [u8; 32],
    id: u8,
    at: u64,
) -> Vec<u8> {
    mutation(
        f,
        prior,
        owner,
        "AuthorityDelegateGrant",
        [id; 32],
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegateGrant".into()),
            reference(&parent),
            m::child(f, target, id),
            m::snapshot(f, prior, &[]),
        ]),
        at,
    )
}
fn setup() -> (Fixture, SigningKey, Vec<u8>) {
    let f = Fixture::with_actions(1000, vec![0, 10, 11, 12, 25]);
    let owner = m::key(80);
    let mut child = m::child(&f, m::public(&owner), 70)
        .array(8)
        .unwrap()
        .to_vec();
    child[3] = array(vec![V::Uint(0), V::Uint(11)]);
    child[6] = V::Uint(1);
    let request = m::delegate(&f, &f.initial, array(child), 5000);
    let delegated = m::execute(&f, &f.initial, &request, &f.requester, 5000);
    assert_eq!(m::code(&delegated), 0);
    let acceptance = m::accepted(&f, &owner, m::reader(&f, &delegated.state, 70), 71, 20000);
    let request = m::admit(&f, &delegated.state, &acceptance, 5000);
    let admitted = m::execute(&f, &delegated.state, &request, &f.requester, 5000);
    assert_eq!(m::code(&admitted), 0);
    (f, owner, admitted.state)
}
fn acceptance(
    f: &Fixture,
    owner: &SigningKey,
    app: &SigningKey,
    grant: &VersionRef,
    expires: u64,
) -> Vec<u8> {
    let payload = wire::encode(&array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityApplicationAcceptance".into()),
        b(&f.app.config.scope.network),
        b(&f.app.config.scope.incarnation),
        b(&m::public(app)),
        b(&m::public(owner)),
        reference(grant),
        array(vec![V::Uint(2000), V::Uint(800000)]),
        b(&[90; 32]),
        array(vec![V::Uint(2000), V::Uint(expires)]),
    ]))
    .unwrap();
    let mut pairs = [owner, app]
        .iter()
        .map(|k| {
            wire::envelope(&wire::sign_envelope(&payload, k).unwrap(), 1)
                .unwrap()
                .1
                .remove(0)
        })
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(k, _)| *k);
    wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(pairs.iter().map(|(k, s)| array(vec![b(k), b(s)])).collect()),
    ]))
    .unwrap()
}
fn register(
    f: &Fixture,
    prior: &[u8],
    owner: &SigningKey,
    app: &SigningKey,
    grant_id: u8,
    at: u64,
) -> Vec<u8> {
    let parent = record(f, prior, 102, [70; 32]);
    let grant = record(f, prior, 102, [grant_id; 32]);
    mutation(
        f,
        prior,
        owner,
        "AuthorityApplicationRegister",
        m::public(app),
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationRegister".into()),
            reference(&parent),
            b(&acceptance(f, owner, app, &grant, 30000)),
            m::snapshot(f, prior, &[]),
        ]),
        at,
    )
}
fn app_setup(
    f: &Fixture,
    prior: &[u8],
    owner: &SigningKey,
    app: &SigningKey,
    grant_id: u8,
) -> (Vec<u8>, Vec<u8>, Execution) {
    let request = delegate(
        f,
        prior,
        owner,
        record(f, prior, 102, [70; 32]),
        m::public(app),
        grant_id,
        5000,
    );
    let delegated = m::execute(f, prior, &request, owner, 5000);
    assert_eq!(m::code(&delegated), 0);
    let request = register(f, &delegated.state, owner, app, grant_id, 5000);
    let registered = m::execute(f, &delegated.state, &request, owner, 5000);
    assert_eq!(m::code(&registered), 0);
    (delegated.state, request, registered)
}
fn get(f: &Fixture, prior: &[u8], requester: &SigningKey, application: [u8; 32]) -> Vec<u8> {
    signed(
        f,
        prior,
        requester,
        "AuthorityApplicationGet",
        application,
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationGet".into()),
            b(&application),
            array(vec![]),
        ]),
        vec![],
        false,
    )
}
fn withdraw(
    f: &Fixture,
    prior: &[u8],
    signer: &SigningKey,
    application: [u8; 32],
    at: u64,
) -> Vec<u8> {
    mutation(
        f,
        prior,
        signer,
        "AuthorityApplicationWithdraw",
        application,
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationWithdraw".into()),
            reference(&record(f, prior, 127, application)),
            m::snapshot(f, prior, &[]),
        ]),
        at,
    )
}
fn capability(f: &Fixture, prior: &[u8], app: [u8; 32], grant: u8, at: u64, action: u64) -> bool {
    let state = State::parse(&f.app.config, prior).unwrap();
    Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap()
    .current_capability(
        [grant; 32],
        &Requirement {
            subject: app,
            actions: &[action],
            scope: (0, f.app.config.scope.network),
            namespace: None,
            usage: [0, 1, 0, 1],
            evaluated_at_ms: at,
            expected: &[],
        },
    )
    .is_ok()
}

#[test]
fn non_auditor_owner_context_is_scoped_and_registration_accepts_only_exact_rights() {
    let (f, owner, prior) = setup();
    assert!(!capability(&f, &prior, m::public(&owner), 70, 5000, 25));
    let app = m::key(81);
    let (delegated, _, registered) = app_setup(&f, &prior, &owner, &app, 72);
    assert!(!capability(&f, &delegated, m::public(&app), 72, 5000, 0));
    assert!(capability(
        &f,
        &registered.state,
        m::public(&app),
        72,
        5000,
        0
    ));
    let state = State::parse(&f.app.config, &registered.state).unwrap();
    let tier = f.expected.iter().find(|v| v.kind == 101).unwrap();
    let parameters = array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityDelegationContext".into()),
        b(&[70; 32]),
        b(&tier.id),
        b(&[72; 32]),
        m::snapshot(&f, &registered.state, &[]).array(2).unwrap()[0].clone(),
        array(vec![]),
    ]);
    let request = signed(
        &f,
        &registered.state,
        &owner,
        "AuthorityDelegationContext",
        [70; 32],
        parameters.clone(),
        vec![],
        false,
    );
    let output = m::execute(&f, &registered.state, &request, &owner, 5000);
    assert_eq!(m::code(&output), 0);
    let selected = body(&output).array(5).unwrap()[4]
        .list(64)
        .unwrap()
        .iter()
        .map(|v| v.bytes().unwrap().to_vec())
        .collect::<Vec<_>>();
    let selected_refs = selected
        .iter()
        .map(|v| applications::record_reference(v).unwrap())
        .collect::<Vec<_>>();
    assert!(selected_refs.iter().any(|v| v.kind == 114));
    assert!(
        selected_refs
            .iter()
            .any(|v| v.kind == 125 && v.id == [71; 32])
    );
    assert!(!selected_refs.iter().any(|v| v.kind == 127));
    assert!(selected.len() < state.records.len());
    // Missing and unrelated child IDs disclose the same refusal; a root is not a delegated child.
    for child in [[99; 32], f.grant] {
        let mut fields = parameters.array(8).unwrap().to_vec();
        fields[5] = b(&child);
        let request = signed(
            &f,
            &registered.state,
            &owner,
            "AuthorityDelegationContext",
            [70; 32],
            array(fields),
            vec![],
            false,
        );
        assert_eq!(
            m::code(&m::execute(&f, &registered.state, &request, &owner, 5000)),
            3
        );
    }
    // A second safe grant stays inert and cannot replace the consented grant.
    let request = delegate(
        &f,
        &registered.state,
        &owner,
        record(&f, &registered.state, 102, [70; 32]),
        m::public(&app),
        73,
        5000,
    );
    let second = m::execute(&f, &registered.state, &request, &owner, 5000);
    assert_eq!(m::code(&second), 0);
    assert!(!capability(&f, &second.state, m::public(&app), 73, 5000, 0));
    assert!(capability(&f, &second.state, m::public(&app), 72, 5000, 0));
    let mut child = m::child(&f, m::public(&app), 74).array(8).unwrap().to_vec();
    child[3] = array(vec![V::Uint(0), V::Uint(11)]);
    let request = mutation(
        &f,
        &second.state,
        &owner,
        "AuthorityDelegateGrant",
        [74; 32],
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegateGrant".into()),
            reference(&record(&f, &second.state, 102, [70; 32])),
            array(child),
            m::snapshot(&f, &second.state, &[]),
        ]),
        5000,
    );
    assert_eq!(
        m::code(&m::execute(&f, &second.state, &request, &owner, 5000)),
        4
    );
}

#[test]
fn owner_and_application_can_withdraw_after_parent_revocation_without_audit_authority() {
    let (f, owner, prior) = setup();
    let one = m::key(81);
    let two = m::key(82);
    let (_, _, registered) = app_setup(&f, &prior, &owner, &one, 72);
    let (_, _, registered) = app_setup(&f, &registered.state, &owner, &two, 73);
    let revoke = super::transaction_tests::revoke(&f, &registered.state, [70; 32], 3);
    let revoked = m::execute(&f, &registered.state, &revoke, &f.requester, 6000);
    assert_eq!(m::code(&revoked), 0);
    assert!(!capability(
        &f,
        &revoked.state,
        m::public(&one),
        72,
        6000,
        0
    ));
    let mut prior = revoked.state;
    for (signer, app) in [(&owner, &one), (&two, &two)] {
        let request = get(&f, &prior, signer, m::public(app));
        let output = m::execute(&f, &prior, &request, signer, 6000);
        assert_eq!(m::code(&output), 0);
        applications::validate_lifecycle_result(
            &Intent::from_signed(&request).unwrap(),
            &body(&output),
        )
        .unwrap();
        prior = output.state;
        let request = withdraw(&f, &prior, signer, m::public(app), 6000);
        let output = m::execute(&f, &prior, &request, signer, 6000);
        assert_eq!(m::code(&output), 0);
        prior = output.state;
    }
    let state = State::parse(&f.app.config, &prior).unwrap();
    assert_eq!(state.streams.keys().len(), 4);
    assert_eq!(
        state
            .records
            .iter()
            .filter(|v| applications::record_reference(v).unwrap().kind == 128)
            .count(),
        2
    );
    f.app.validate_checkpoint(&prior, state.height).unwrap();
    // Another admitted identity cannot read another owner's application.
    let request = get(&f, &prior, &f.requester, m::public(&one));
    assert_eq!(
        m::code(&m::execute(&f, &prior, &request, &f.requester, 6000)),
        3
    );
    let mut fields = wire::decode(&prior).unwrap().array(13).unwrap().to_vec();
    fields[9] = array(vec![]);
    assert!(
        f.app
            .validate_checkpoint(&wire::encode(&array(fields)).unwrap(), state.height)
            .is_err()
    );
}

#[test]
fn application_creation_and_withdrawal_allow_bookkeeping_but_keep_current_authority() {
    let (f, owner, prior) = setup();
    let app = m::key(81);
    let (prior, request, _) = app_setup(&f, &prior, &owner, &app, 72);
    let advanced = m::execute(
        &f,
        &prior,
        &m::status(&f, &f.requester, 94),
        &f.requester,
        5500,
    );
    let registered = m::execute(&f, &advanced.state, &request, &owner, 6000);
    assert_eq!(m::code(&registered), 0);
    assert_eq!(
        body(&registered).array(6).unwrap()[5].uint().unwrap(),
        State::parse(&f.app.config, &registered.state)
            .unwrap()
            .height
    );
    let replayed = m::execute(&f, &registered.state, &request, &owner, 40000);
    assert_eq!(m::code(&replayed), 0);
    assert_eq!(result_bytes(&registered), result_bytes(&replayed));
    let before = State::parse(&f.app.config, &registered.state).unwrap();
    let after = State::parse(&f.app.config, &replayed.state).unwrap();
    assert_eq!(before.streams.value(), after.streams.value());
    assert_eq!(before.evidence.value(), after.evidence.value());
    assert_eq!(before.records, after.records);
    f.app
        .validate_checkpoint(&replayed.state, after.height)
        .unwrap();

    let withdrawal = withdraw(&f, &replayed.state, &owner, m::public(&app), 41000);
    let advanced = m::execute(
        &f,
        &replayed.state,
        &m::status(&f, &f.requester, 95),
        &f.requester,
        42000,
    );
    let withdrawn = m::execute(&f, &advanced.state, &withdrawal, &owner, 43000);
    assert_eq!(m::code(&withdrawn), 0);
    let replayed = m::execute(&f, &withdrawn.state, &withdrawal, &owner, 44000);
    assert_eq!(m::code(&replayed), 0);
    assert_eq!(result_bytes(&withdrawn), result_bytes(&replayed));
    let state = State::parse(&f.app.config, &replayed.state).unwrap();
    f.app
        .validate_checkpoint(&replayed.state, state.height)
        .unwrap();

    // A changed authorisation is still decisive at the delayed creation order.
    let revoke = super::transaction_tests::revoke(&f, &prior, [70; 32], 3);
    let revoked = m::execute(&f, &prior, &revoke, &f.requester, 6000);
    assert_eq!(m::code(&revoked), 0);
    let refused = m::execute(&f, &revoked.state, &request, &owner, 7000);
    assert_ne!(m::code(&refused), 0);
    assert_eq!(
        State::parse(&f.app.config, &revoked.state).unwrap().records,
        State::parse(&f.app.config, &refused.state).unwrap().records
    );
}

#[test]
fn registration_replay_after_acceptance_expiry_preserves_fenced_application_stream() {
    let (f, owner, prior) = setup();
    let app = m::key(81);
    let (_, request, registered) = app_setup(&f, &prior, &owner, &app, 72);
    let state = State::parse(&f.app.config, &registered.state).unwrap();
    let metadata = state.streams.metadata(&m::public(&app)).unwrap().unwrap();
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
            b(&m::public(&app)),
            b(&[93; 32]),
            V::Uint(0),
            V::Uint(state.height),
            V::Uint(metadata.generation),
            b(&metadata.generation_id),
            b(&wire::digest(
                &state
                    .streams
                    .metadata_bytes(&scope, &m::public(&app))
                    .unwrap(),
            )),
        ]))
        .unwrap(),
        &app,
    )
    .unwrap();
    let fenced = m::execute(&f, &registered.state, &fence, &app, 6000);
    assert_eq!(m::code(&fenced), 0);
    let replay = m::execute(&f, &fenced.state, &request, &owner, 40000);
    assert_eq!(m::code(&replay), 0);
    assert_eq!(result_bytes(&replay), result_bytes(&registered));
    let before = State::parse(&f.app.config, &fenced.state).unwrap();
    let after = State::parse(&f.app.config, &replay.state).unwrap();
    assert_eq!(before.streams.value(), after.streams.value());
    assert_eq!(before.evidence.value(), after.evidence.value());
    assert_eq!(before.records, after.records);
    f.app
        .validate_checkpoint(&replay.state, after.height)
        .unwrap();
}

#[test]
fn consent_tampering_identity_reuse_and_expiry_never_publish_registration() {
    let (f, owner, prior) = setup();
    let app = m::key(81);
    let (delegated, request, _) = app_setup(&f, &prior, &owner, &app, 72);
    let intent = Intent::from_signed(&request).unwrap();
    let Operation::Register {
        acceptance: parsed_acceptance,
        ..
    } = Operation::parse(&intent).unwrap()
    else {
        unreachable!()
    };
    let (mut payload, pairs) = wire::envelope(&parsed_acceptance.envelope, 2).unwrap();
    let last = payload.len() - 1;
    payload[last] ^= 1;
    let tampered = wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(pairs.iter().map(|(k, s)| array(vec![b(k), b(s)])).collect()),
    ]))
    .unwrap();
    assert!(
        applications::Acceptance::parse(&tampered, intent.network, intent.incarnation, true)
            .is_err()
    );
    let expired = register(&f, &delegated, &owner, &app, 72, 40000);
    let refused = m::execute(&f, &delegated, &expired, &owner, 40000);
    assert_eq!(m::code(&refused), 7);
    let before = State::parse(&f.app.config, &delegated).unwrap();
    let after = State::parse(&f.app.config, &refused.state).unwrap();
    assert_eq!(before.records, after.records);
    assert_eq!(before.evidence.value(), after.evidence.value());
    assert_eq!(before.streams.keys(), after.streams.keys());
    // An existing member cannot change identity class under another consenting owner.
    let request = m::delegate(&f, &prior, m::child(&f, m::public(&owner), 73), 5000);
    let child = m::execute(&f, &prior, &request, &f.requester, 5000);
    assert_eq!(m::code(&child), 0);
    let consent = acceptance(
        &f,
        &f.requester,
        &owner,
        &record(&f, &child.state, 102, [73; 32]),
        30000,
    );
    let request = mutation(
        &f,
        &child.state,
        &f.requester,
        "AuthorityApplicationRegister",
        m::public(&owner),
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationRegister".into()),
            reference(&record(&f, &child.state, 102, f.grant)),
            b(&consent),
            m::snapshot(&f, &child.state, &[]),
        ]),
        5000,
    );
    let refused = m::execute(&f, &child.state, &request, &f.requester, 5000);
    assert_eq!(m::code(&refused), 38);
    assert_eq!(
        State::parse(&f.app.config, &child.state).unwrap().records,
        State::parse(&f.app.config, &refused.state).unwrap().records
    );
}

#[test]
fn application_rights_end_with_owner_admission_and_metadata_withdrawal_remains_available() {
    let (f, owner, prior) = setup();
    let app = m::key(81);
    // The member's own reader grant can outlive its separate membership admission.
    let state = State::parse(&f.app.config, &prior).unwrap();
    let mut admission = wire::decode(
        Governance::parse(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            &state.records,
        )
        .unwrap()
        .record_bytes(125, [71; 32])
        .unwrap(),
    )
    .unwrap()
    .array(12)
    .unwrap()
    .to_vec();
    admission[8] = array(vec![V::Uint(1000), V::Uint(10000)]);
    // Pure governance checks use the exact current admission; committed-state tests
    // below retain the original signed evidence rather than alter its provenance.
    let (_, _, registered) = app_setup(&f, &prior, &owner, &app, 72);
    let mut records = State::parse(&f.app.config, &registered.state)
        .unwrap()
        .records;
    let index = records
        .iter()
        .position(|v| applications::record_reference(v).unwrap().kind == 125)
        .unwrap();
    records[index] = wire::encode(&array(admission)).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &records,
    )
    .unwrap();
    let requirement = Requirement {
        subject: m::public(&app),
        actions: &[0],
        scope: (0, f.app.config.scope.network),
        namespace: None,
        usage: [0, 1, 0, 1],
        evaluated_at_ms: 7000,
        expected: &[],
    };
    assert_eq!(
        governance
            .current_capability([72; 32], &requirement)
            .unwrap()
            .expires_ms,
        10000
    );
    assert!(
        governance
            .current_capability(
                [72; 32],
                &Requirement {
                    evaluated_at_ms: 9000,
                    ..requirement
                }
            )
            .is_err()
    );
    let request = get(&f, &registered.state, &app, m::public(&app));
    let output = m::execute(&f, &registered.state, &request, &app, 950000);
    assert_eq!(m::code(&output), 0);
    let request = withdraw(&f, &output.state, &app, m::public(&app), 950000);
    let withdrawn = m::execute(&f, &output.state, &request, &app, 950000);
    assert_eq!(m::code(&withdrawn), 0);
    assert!(!capability(
        &f,
        &withdrawn.state,
        m::public(&app),
        72,
        5000,
        0
    ));
}

#[test]
fn application_list_has_a_dedicated_complete_metadata_bound_above_ordinary_versions() {
    let (f, owner, prior) = setup();
    let app = m::key(81);
    let (_, _, registered) = app_setup(&f, &prior, &owner, &app, 72);
    let request = withdraw(&f, &registered.state, &app, m::public(&app), 5000);
    let withdrawn = m::execute(&f, &registered.state, &request, &app, 5000);
    let state = State::parse(&f.app.config, &withdrawn.state).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    let template_grant = wire::decode(governance.record_bytes(102, [72; 32]).unwrap()).unwrap();
    let template_admission =
        wire::decode(governance.record_bytes(127, m::public(&app)).unwrap()).unwrap();
    let template_withdrawal =
        wire::decode(governance.record_bytes(128, m::public(&app)).unwrap()).unwrap();
    // This is a metadata schema fixture. It does not bypass the separately tested
    // signed-mutation provenance requirement for installing replicated state.
    let mut records = Vec::new();
    for seed in 100..123 {
        let application = m::public(&m::key(seed));
        let mut grant = template_grant.array(17).unwrap().to_vec();
        grant[6] = b(&[seed; 32]);
        grant[8] = b(&application);
        let grant = wire::encode(&array(grant)).unwrap();
        let grant_ref = applications::record_reference(&grant).unwrap();
        let mut admission = template_admission.array(11).unwrap().to_vec();
        admission[6] = b(&application);
        admission[8] = reference(&grant_ref);
        let admission = wire::encode(&array(admission)).unwrap();
        let admission_ref = applications::record_reference(&admission).unwrap();
        let mut withdrawal = template_withdrawal.array(9).unwrap().to_vec();
        withdrawal[6] = reference(&admission_ref);
        withdrawal[7] = b(&application);
        records.extend([grant, admission, wire::encode(&array(withdrawal)).unwrap()]);
    }
    crate::authority_membership::sort_records(&mut records).unwrap();
    let request = signed(
        &f,
        &withdrawn.state,
        &owner,
        "AuthorityApplicationList",
        m::public(&owner),
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityApplicationList".into()),
            b(&m::public(&owner)),
            array(vec![]),
        ]),
        vec![],
        false,
    );
    let intent = Intent::from_signed(&request).unwrap();
    let decision = Operation::parse(&intent)
        .unwrap()
        .authorise(&records, &state.reservations, &intent, 5000, false)
        .unwrap();
    assert_eq!(decision.code, 0);
    assert_eq!(decision.dependencies.len(), 69);
    let versions = applications::validate_lifecycle_result(&intent, &decision.value).unwrap();
    assert!(crate::authority_proof::ActionValidation::new(versions.clone()).is_err());
    crate::authority_proof::ActionValidation::application_list(versions).unwrap();
    let mut truncated = decision.value.array(5).unwrap().to_vec();
    let V::Array(rows) = &mut truncated[4] else {
        unreachable!()
    };
    rows.pop();
    assert!(applications::validate_lifecycle_result(&intent, &array(truncated)).is_err());
}

#[test]
fn registration_capacity_refusal_keeps_candidate_record_stream_and_audit_atomic() {
    let (f, owner, prior) = setup();
    let app = m::key(100);
    let request = delegate(
        &f,
        &prior,
        &owner,
        record(&f, &prior, 102, [70; 32]),
        m::public(&app),
        100,
        5000,
    );
    let delegated = m::execute(&f, &prior, &request, &owner, 5000);
    assert_eq!(m::code(&delegated), 0);
    let prior = &delegated.state;
    let request = register(&f, prior, &owner, &app, 100, 5000);
    let intent = Intent::from_signed(&request).unwrap();
    let mut state = State::parse(&f.app.config, prior).unwrap();
    let committed = f.with_recipient(&request, 3500, 5000, state.height + 1, &owner);
    let ordered = OrderedRequest::parse(&f.app.config, &committed.command).unwrap();
    let mut available = state.clone();
    let (_, accepted, _, _) = f
        .app
        .ordinary(
            prior,
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

    // Synthetic negative boundary: exercise admission preflight without creating
    // hundreds of unrelated grants or presenting this as an installable checkpoint.
    let mut seed = 0u64;
    while state.streams.keys().len() < crate::authority_capacity::MAX_STREAMS {
        let key = SigningKey::from_bytes(&wire::digest(&seed.to_be_bytes()))
            .verifying_key()
            .to_bytes();
        seed += 1;
        state
            .streams
            .admit(
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
                key,
            )
            .unwrap();
    }
    state.capacity().unwrap();
    let before_records = state.records.clone();
    let before_evidence = state.evidence.value();
    let before_keys = state.streams.keys();
    assert!(!before_keys.contains(&m::public(&app)));
    let (refused, code, _, _) = f
        .app
        .ordinary(
            prior,
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
    assert!(
        state.records.iter().all(|v| {
            applications::record_reference(v).unwrap().index() != (127, m::public(&app))
        })
    );
    let (replay, code, _, _) = f
        .app
        .ordinary(
            prior,
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
    assert_eq!(replay, refused);
    assert_eq!(state.records, before_records);
    assert_eq!(state.evidence.value(), before_evidence);
    assert_eq!(state.streams.keys(), before_keys);
}
