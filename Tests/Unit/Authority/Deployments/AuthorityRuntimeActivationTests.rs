// SPDX-License-Identifier: MIT
// Runtime starts require a current manager capability, exact registration and host consent.
use super::*;
use crate::{authority_deployment_tests as fixture, authority_governance::Governance};
fn public(seed: u8) -> Key {
    fixture::key(seed).verifying_key().to_bytes()
}
fn prepare(
    records: &[Vec<u8>],
    reserved: &Reservations,
    registration: VersionRef,
    grant: VersionRef,
    requester: Key,
) -> (Intent, Operation) {
    let snapshot = Snapshot::parse(&fixture::snapshot(&[])).unwrap();
    let mut operation = Operation {
        grant,
        admission: registration,
        role: 8,
        recipient: public(107),
        local_generation: 1,
        snapshot,
    };
    let mut intent = Intent {
        network: [20; 32],
        incarnation: [21; 32],
        generation: 1,
        generation_id: [190; 32],
        sequence: 1,
        acknowledged_through: 0,
        requester,
        action: ACTION.into(),
        resource: [60; 32],
        revision: 1,
        profile_generation: 1,
        minimum_policy_epoch: 0,
        minimum_policy_height: 0,
        expected: vec![],
        parameters: vec![],
        digest: [191; 32],
    };
    let d = operation
        .prepare(records, reserved, &intent, public(107), 5000, false)
        .unwrap();
    assert_eq!(d.code, 0);
    intent.expected = d.versions.clone();
    operation.snapshot.references = d.versions;
    intent.parameters = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(ACTION.into()),
        reference(&operation.grant),
        reference(&operation.admission),
        V::Uint(8),
        b(&public(107)),
        V::Uint(1),
        fixture::snapshot(&intent.expected),
    ]))
    .unwrap();
    (intent, operation)
}
#[test]
fn exact_manager_and_recipient_are_separate_and_withdrawal_is_terminal() {
    let f = fixture::Fixture::new();
    let offer = fixture::offer(fixture::manifest());
    let (mut records, registration, _, _) = fixture::admitted(&f, &offer);
    let grant = Governance::parse([20; 32], [21; 32], &records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    let (intent, operation) = prepare(
        &records,
        &f.reservations,
        registration.reference.clone(),
        grant,
        public(5),
    );
    let parsed = Operation::parse(&intent).unwrap();
    let d = parsed
        .authorise(&records, &f.reservations, &intent, public(107), 5000, false)
        .unwrap();
    assert_eq!(d.code, 0);
    assert_eq!(d.restrictions.consent, Some(registration.consent.digest));
    assert_ne!(intent.requester, operation.recipient);
    assert_ne!(
        parsed
            .authorise(&records, &f.reservations, &intent, public(106), 5000, false)
            .unwrap()
            .code,
        0
    );
    let mut service_caller = intent.clone();
    service_caller.requester = public(107);
    assert_ne!(
        parsed
            .authorise(
                &records,
                &f.reservations,
                &service_caller,
                public(107),
                5000,
                false
            )
            .unwrap()
            .code,
        0
    );
    assert_ne!(
        parsed
            .authorise(
                &records,
                &f.reservations,
                &intent,
                public(107),
                20000,
                false
            )
            .unwrap()
            .code,
        0
    );
    let mut stale = intent.clone();
    stale.expected.clear();
    assert_ne!(
        parsed
            .authorise(&records, &f.reservations, &stale, public(107), 5000, false)
            .unwrap()
            .code,
        0
    );
    let refs = vec![registration.reference.clone()];
    let withdrawal = Intent::from_signed(&fixture::signed(
        &fixture::key(90),
        "AuthorityDeploymentWithdraw",
        [60; 32],
        1,
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentWithdraw".into()),
            reference(&registration.reference),
            V::Uint(1),
            fixture::snapshot(&refs),
        ]),
        refs,
    ))
    .unwrap();
    let decision = crate::authority_deployments::Operation::parse(&withdrawal)
        .unwrap()
        .authorise(&records, &f.reservations, &withdrawal, 5000, false, None)
        .unwrap();
    assert_eq!(decision.code, 0);
    records.extend(decision.records);
    members::sort_records(&mut records).unwrap();
    assert_ne!(
        parsed
            .authorise(&records, &f.reservations, &intent, public(107), 5000, false)
            .unwrap()
            .code,
        0
    );
}

#[test]
fn persistent_activation_keeps_dedicated_authority_and_exact_consent_after_years() {
    let (f, mut records, registration, manager) = fixture::persistent_activation_manager();
    assert!(crate::trust_bootstrap::check(&f.bootstrap, true, 31_536_000_000).is_ok());
    let (intent, operation) = prepare(
        &records,
        &f.reservations,
        registration.reference.clone(),
        manager,
        public(80),
    );
    let signed = fixture::signed(
        &fixture::key(80),
        ACTION,
        [60; 32],
        1,
        wire::decode(&intent.parameters).unwrap(),
        intent.expected.clone(),
    );
    let (payload, _) = wire::envelope(&signed, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[12] = V::Uint(1);
    let signed = wire::sign_envelope(
        &wire::encode(&a(fields.clone())).unwrap(),
        &fixture::key(80),
    )
    .unwrap();
    let request = Request::new(signed, records.clone())
        .unwrap()
        .until_withdrawn()
        .unwrap();
    assert!(
        Request::parse(&request.encode().unwrap())
            .unwrap()
            .persistent()
    );
    for (at, replay) in [(5000, false), (31_536_000_000, true)] {
        let decision = operation
            .authorise(
                &records,
                &f.reservations,
                request.intent(),
                public(107),
                at,
                replay,
            )
            .unwrap();
        assert_eq!(decision.code, 0);
        assert_eq!(
            decision.restrictions.consent,
            Some(registration.consent.digest)
        );
    }
    for (generation, sequence) in [(1, 2), (1, 10), (2, 1), (3, 2)] {
        fields[4] = V::Uint(generation);
        fields[6] = V::Uint(sequence);
        fields[7] = V::Uint(sequence - 1);
        let signed = wire::sign_envelope(
            &wire::encode(&a(fields.clone())).unwrap(),
            &fixture::key(80),
        )
        .unwrap();
        let continued = Request::new(signed, records.clone())
            .unwrap()
            .until_withdrawn()
            .unwrap();
        let reopened = Request::parse(&continued.encode().unwrap()).unwrap();
        assert!(reopened.persistent());
        assert_eq!(reopened.intent().generation, generation);
        assert_eq!(reopened.intent().sequence, sequence);
        assert_eq!(reopened.intent().acknowledged_through, sequence - 1);
        assert_eq!(
            operation
                .authorise(
                    &records,
                    &f.reservations,
                    reopened.intent(),
                    public(107),
                    31_536_000_000,
                    true,
                )
                .unwrap()
                .code,
            0
        );
    }
    for (generation, sequence, acknowledged) in [
        (1, 0, 0),
        (1, 2, 0),
        (1, 3, 1),
        (1, 2, 2),
        (1, u64::MAX, u64::MAX),
        (0, 2, 1),
    ] {
        fields[4] = V::Uint(generation);
        fields[6] = V::Uint(sequence);
        fields[7] = V::Uint(acknowledged);
        let signed = wire::sign_envelope(
            &wire::encode(&a(fields.clone())).unwrap(),
            &fixture::key(80),
        )
        .unwrap();
        assert!(
            Request::new(signed, records.clone())
                .and_then(Request::until_withdrawn)
                .is_err(),
            "generation {generation}, sequence {sequence}, acknowledged {acknowledged}"
        );
    }
    let refs = vec![registration.reference.clone()];
    let withdrawal = Intent::from_signed(&fixture::signed(
        &fixture::key(90),
        "AuthorityDeploymentWithdraw",
        [60; 32],
        1,
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentWithdraw".into()),
            reference(&registration.reference),
            V::Uint(1),
            fixture::snapshot(&refs),
        ]),
        refs,
    ))
    .unwrap();
    let decision = crate::authority_deployments::Operation::parse(&withdrawal)
        .unwrap()
        .authorise(&records, &f.reservations, &withdrawal, 5000, false, None)
        .unwrap();
    assert_eq!(decision.code, 0);
    records.extend(decision.records);
    members::sort_records(&mut records).unwrap();
    assert_ne!(
        operation
            .authorise(
                &records,
                &f.reservations,
                request.intent(),
                public(107),
                31_536_000_000,
                true
            )
            .unwrap()
            .code,
        0
    );
}
