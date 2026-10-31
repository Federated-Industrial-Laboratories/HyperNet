// SPDX-License-Identifier: MIT
//! Admission publishes its audit set and ordinary identities in one committed state.
use super::*;
use crate::{authority_deployment_tests as vectors, authority_deployments::Operation};
use ed25519_dalek::SigningKey;
fn fixture() -> tests::Fixture {
    let f = vectors::Fixture::new();
    let verified = crate::trust_bootstrap::check(&f.bootstrap, true, 1000).unwrap();
    let config = Configuration::trusted(verified.descriptor().canonical()).unwrap();
    let value = wire::decode(&f.bootstrap).unwrap();
    let initial = value.array(6).unwrap()[3].bytes().unwrap().to_vec();
    let state = State::parse(&config, &initial).unwrap();
    let expected = Governance::parse(
        config.scope.network,
        config.scope.incarnation,
        &state.records,
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
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
fn sign(
    f: &tests::Fixture,
    state: &State,
    prior: &[u8],
    signer: &SigningKey,
    action: &str,
    resource: [u8; 32],
    revision: u64,
    parameters: V,
    expected: Vec<VersionRef>,
) -> Vec<u8> {
    let signed = vectors::signed(signer, action, resource, revision, parameters, expected);
    let (payload, _) = wire::envelope(&signed, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    let meta = state
        .streams
        .metadata(&signer.verifying_key().to_bytes())
        .unwrap()
        .unwrap();
    let through = meta
        .completion
        .as_ref()
        .map_or(meta.retired_through, |c| c.sequence);
    fields[4] = V::Uint(meta.generation);
    fields[5] = b(&meta.generation_id);
    fields[6] = V::Uint(through + 1);
    fields[7] = V::Uint(through);
    fields[14] = V::Uint(state.height);
    let (arity, snapshot) = match action {
        "AuthorityDeploymentRegister" => (9, Some(7)),
        "AuthorityDeploymentWithdraw" => (6, Some(5)),
        "Reconfigure" => (4, None),
        _ => panic!("Unsupported deployment fixture action"),
    };
    let mut parameters = wire::decode(fields[16].bytes().unwrap())
        .unwrap()
        .array(arity)
        .unwrap()
        .to_vec();
    if let Some(snapshot) = snapshot {
        assert_eq!(revision, 1);
        let refs = parameters[snapshot].array(2).unwrap()[1].clone();
        parameters[snapshot] = array(vec![
            array(vec![
                V::Uint(f.app.config.scope.epoch),
                V::Uint(state.height),
                b(&wire::digest(prior)),
            ]),
            refs,
        ]);
    }
    fields[16] = b(&wire::encode(&array(parameters)).unwrap());
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), signer).unwrap()
}
fn registration(f: &tests::Fixture, state: &State, prior: &[u8]) -> Vec<u8> {
    let offer = vectors::offer(vectors::manifest());
    let g = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    let grant = g
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
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
            V::Bool(false),
        ])
    };
    let preliminary = sign(
        f,
        state,
        prior,
        &f.requester,
        "AuthorityDeploymentRegister",
        offer.manifest.deployment,
        1,
        parameters(&[]),
        vec![],
    );
    let intent = Intent::from_signed(&preliminary).unwrap();
    let d = Operation::parse(&intent)
        .unwrap()
        .prepare(
            &state.records,
            &state.reservations,
            &intent,
            6000,
            false,
            None,
        )
        .unwrap();
    assert_eq!(d.code, 0);
    let refs = d
        .dependencies
        .into_iter()
        .filter(|r| !matches!(r.kind, 105 | 117 | 129))
        .collect::<Vec<_>>();
    sign(
        f,
        state,
        prior,
        &f.requester,
        &intent.action,
        intent.resource,
        1,
        parameters(&refs),
        refs,
    )
}
fn code(e: &Execution) -> u64 {
    crate::authority_proof::OperationResult::parse(tests::result_bytes(e))
        .unwrap()
        .code
}
#[test]
fn admission_audit_restart_replay_and_expired_operator_withdrawal_are_atomic() {
    let f = fixture();
    let before = State::parse(&f.app.config, &f.initial).unwrap();
    let request = registration(&f, &before, &f.initial);
    let advanced = membership_tests::execute(
        &f,
        &f.initial,
        &membership_tests::status(&f, &f.requester, 93),
        &f.requester,
        5500,
    );
    let committed = f.committed(&request, 4000, 6000, 2);
    f.app
        .validate(
            &advanced.state,
            &committed.command,
            6000,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let applied = f
        .app
        .execute(
            &advanced.state,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&applied), 0);
    let state = State::parse(&f.app.config, &applied.state).unwrap();
    assert_eq!(state.records.len(), before.records.len() + 3);
    assert_eq!(state.streams.keys().len(), before.streams.keys().len() + 9);
    assert_eq!(state.evidence.value().list(1).unwrap().len(), 1);
    f.app.validate_checkpoint(&applied.state, 2).unwrap();
    let replay = f
        .app
        .execute(
            &applied.state,
            &f.committed(&request, 5000, 6500, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(tests::result_bytes(&replay), tests::result_bytes(&applied));
    let state = State::parse(&f.app.config, &replay.state).unwrap();
    assert_eq!(state.streams.keys().len(), 10);
    // One retained audit entry must account for all three exact output records.
    let mut damaged = wire::decode_state(&applied.state)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    damaged[9] = array(vec![]);
    assert!(
        f.app
            .validate_checkpoint(&wire::encode_state(&array(damaged)).unwrap(), 2)
            .is_err()
    );
    let index = state.deployments().unwrap();
    let registration = index.deployments.values().next().unwrap();
    let refs = vec![registration.reference.clone()];
    let parameters = array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityDeploymentWithdraw".into()),
        reference(&registration.reference),
        V::Uint(1),
        vectors::snapshot(&refs),
    ]);
    let operator = vectors::key(90);
    let request = sign(
        &f,
        &state,
        &replay.state,
        &operator,
        "AuthorityDeploymentWithdraw",
        registration.deployment,
        1,
        parameters,
        refs,
    );
    let advanced = membership_tests::execute(
        &f,
        &replay.state,
        &membership_tests::status(&f, &f.requester, 94),
        &f.requester,
        26000,
    );
    let committed = f.with_recipient(&request, 25000, 27000, 5, &operator);
    let withdrawn = f
        .app
        .execute(
            &advanced.state,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&withdrawn), 0);
    let state = State::parse(&f.app.config, &withdrawn.state).unwrap();
    assert_eq!(state.deployments().unwrap().open_count(), 0);
    assert_eq!(state.streams.keys().len(), 10);
    f.app.validate_checkpoint(&withdrawn.state, 5).unwrap();
    let replayed = membership_tests::execute(&f, &withdrawn.state, &request, &operator, 28000);
    assert_eq!(code(&replayed), 0);
    assert_eq!(
        tests::result_bytes(&withdrawn),
        tests::result_bytes(&replayed)
    );
}
#[test]
fn capacity_refusal_does_not_publish_partial_multi_identity_admission() {
    let f = fixture();
    let mut state = State::parse(&f.app.config, &f.initial).unwrap();
    let request = registration(&f, &state, &f.initial);
    // Deliberate negative boundary: fill the permanent stream table before the candidate.
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
    let prior_records = state.records.clone();
    let prior_keys = state.streams.keys();
    let intent = Intent::from_signed(&request).unwrap();
    let committed = f.committed(&request, 4000, 6000, 1);
    let ordered = OrderedRequest::parse(&f.app.config, &committed.command).unwrap();
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
    assert_eq!(state.records, prior_records);
    assert_eq!(state.streams.keys(), prior_keys);
    assert!(state.evidence.value().array(0).is_ok());
}

#[path = "../Epochs/AuthorityEpochApplicationTests.rs"]
mod epochs;
