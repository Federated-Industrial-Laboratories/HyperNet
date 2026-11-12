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
    use crate::trust_validity::{End, Validity};
    let f = fixture::Fixture::persistent();
    assert!(crate::trust_bootstrap::check(&f.bootstrap, true, 31_536_000_000).is_ok());
    let mut manifest = fixture::manifest();
    manifest.validity.1 = End::UntilWithdrawn;
    let offer = fixture::offer(manifest);
    let (mut records, registration, _, _) = fixture::admitted(&f, &offer);
    let governance = Governance::parse([20; 32], [21; 32], &records).unwrap();
    let root = governance
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    let mut grant = wire::decode(governance.record_bytes(102, root.id).unwrap())
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    grant[6] = b(&[179; 32]);
    grant[8] = b(&public(80));
    grant[10] = a(vec![V::Uint(26)]);
    grant[11] = a(vec![a(vec![V::Uint(5), b(&[60; 32])])]);
    grant[12] = Validity(1000, End::UntilWithdrawn).value();
    grant[13] = reference(&root);
    grant[14] = V::Uint(0);
    grant[16] = fixture::snapshot(&[]);
    let grant_bytes = wire::encode(&a(grant)).unwrap();
    let manager = VersionRef {
        kind: 102,
        id: [179; 32],
        generation: 1,
        digest: wire::digest(&grant_bytes),
    };
    records.push(grant_bytes);
    records.push(
        wire::encode(&a(vec![
            V::Uint(127),
            V::Uint(1),
            b(&[20; 32]),
            b(&[21; 32]),
            V::Uint(1),
            V::Null,
            b(&public(80)),
            b(&public(5)),
            reference(&manager),
            Validity(1000, End::UntilWithdrawn).value(),
            fixture::snapshot(&[]),
        ]))
        .unwrap(),
    );
    members::sort_records(&mut records).unwrap();
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
    fields[6] = V::Uint(2);
    let advanced =
        wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), &fixture::key(80)).unwrap();
    assert!(
        Request::new(advanced, records.clone())
            .unwrap()
            .until_withdrawn()
            .is_err()
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
