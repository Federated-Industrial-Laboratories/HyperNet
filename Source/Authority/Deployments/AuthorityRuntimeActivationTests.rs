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
        requester: public(5),
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
