// SPDX-License-Identifier: MIT
// Longer maintenance challenges cannot change ordinary deadlines or inherited permission expiry.
use super::*;
use crate::{
    authority_domains::{self as domains, federation, page},
    authority_proof::{self as proof, Intent, VersionRef, tests::Fixture},
};

fn reference(kind: u64, seed: u8) -> VersionRef {
    VersionRef {
        kind,
        id: [seed; 32],
        generation: 1,
        digest: [seed + 1; 32],
    }
}
fn operation(f: &mut Fixture, command: federation::Command, grant: Option<VersionRef>) {
    let operation = domains::Operation {
        grant,
        command: command.into(),
        snapshot: domains::snapshot(&V::Array(vec![
            V::Array(vec![V::Uint(0), V::Uint(0), V::Bytes(vec![90; 32])]),
            V::Array(vec![]),
        ]))
        .unwrap(),
    };
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
        panic!("intent array")
    };
    fields[9] = V::Text("AuthorityDomain".into());
    fields[10] = V::Bytes(operation.command.resource().to_vec());
    fields[11] = V::Uint(u64::from(operation.command.mutation()));
    fields[12] = V::Uint(0);
    fields[16] = V::Bytes(operation.parameters().unwrap());
    f.intent = wire::sign_envelope(
        &wire::encode(&V::Array(fields)).unwrap(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    f.operation = wire::encode(&V::Array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        V::Uint(0),
        V::Uint(0),
        V::Bytes(operation.parameters().unwrap()),
    ]))
    .unwrap();
}
fn challenge(f: &mut Fixture, duration: u64) {
    let (payload, _) = wire::envelope(&f.challenge, 1).unwrap();
    let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
        panic!("challenge array")
    };
    fields[7] = V::Bytes(Intent::from_signed(&f.intent).unwrap().digest.to_vec());
    fields[10] = V::Uint(fields[9].uint().unwrap() + duration);
    fields[11] = V::Uint(duration);
    f.challenge =
        wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &f.recipient).unwrap();
}
pub(crate) fn fixture(duration: u64, maintenance: bool) -> Fixture {
    let mut f = Fixture::new(10000);
    if maintenance {
        operation(
            &mut f,
            federation::Command::Admission {
                agreement: reference(151, 61),
                bridge: reference(152, 63),
                page: None,
                exchange: [65; 32],
                revision: None,
                after: None,
            },
            None,
        );
    }
    challenge(&mut f, duration);
    f.rebuild();
    f
}
fn verify(f: &Fixture) -> Result<proof::VerifiedResult> {
    proof::verify_response(&f.descriptor, f.context(), f.response(), |i, r, _| {
        domains::Operation::parse(i)?;
        ensure!(r.value == i.parameters, "profile fixture result differs");
        proof::ActionValidation::new(vec![])
    })
}
fn media_fixture(grant: Option<VersionRef>) -> Fixture {
    let foreign = fixture(FEDERATION_DURATION_MS, true);
    let mut admission = federation::ForeignProof {
        trust: reference(150, 67),
        floor: reference(157, 67),
        anchor: vec![],
        ordered: foreign.ordered,
        result: foreign.operation,
        certificate: foreign.certificate,
        ancestry: foreign.ancestry,
        checkpoint: None,
        history: None,
        predecessors: vec![],
        bytes: vec![],
    };
    admission.bytes = admission.encode().unwrap();
    let mut f = Fixture::new(10000);
    operation(
        &mut f,
        federation::Command::MediaAuthorise {
            asset: reference(144, 71),
            host: reference(143, 73),
            effect: page::MediaEffect::Read,
            offset: 0,
            bytes: 1,
            digest: None,
            proof: admission,
        },
        grant,
    );
    challenge(&mut f, FEDERATION_DURATION_MS);
    f.rebuild();
    f
}

#[test]
fn federation_freshness_issuer_selects_exact_maintenance_and_preserves_ordinary_ceiling() {
    let health = ClockHealth::new(10000, 100, 20000, 0).unwrap().frozen();
    let mut context = Fixture::new(10000);
    operation(
        &mut context,
        federation::Command::SourceContext {
            agreement: [61; 32],
            page: None,
            after: None,
        },
        None,
    );
    for (f, ceiling) in [
        (fixture(5000, false), MAXIMUM_DURATION_MS),
        (context, MAXIMUM_DURATION_MS),
        (fixture(15000, true), FEDERATION_DURATION_MS),
        (media_fixture(None), FEDERATION_DURATION_MS),
        (media_fixture(Some(reference(102, 75))), MAXIMUM_DURATION_MS),
    ] {
        let request = SignedRequest::from_signed(&f.intent).unwrap();
        assert_eq!(maximum_duration_ms(&request), ceiling);
        let mut session = Session::new().unwrap();
        let bytes = session
            .issue(&f.intent, &f.recipient, [92; 32], ceiling, health)
            .unwrap();
        Challenge::from_signed(&bytes)
            .unwrap()
            .validate_request(&request)
            .unwrap();
        assert!(
            session
                .issue(&f.intent, &f.recipient, [93; 32], ceiling + 1, health)
                .is_err()
        );
    }
}

#[test]
fn federation_freshness_unknown_or_malformed_commands_keep_only_the_ordinary_refusal_profile() {
    let f = fixture(15000, true);
    let intent = Intent::from_signed(&f.intent).unwrap();
    let V::Array(mut unknown) = wire::decode(&intent.parameters).unwrap() else {
        panic!("domain array")
    };
    unknown[4] = V::Array(vec![V::Text("FederationUnknown".into())]);
    for parameters in [V::Array(unknown), V::Array(vec![V::Uint(200)])] {
        let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
        let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
            panic!("intent array")
        };
        fields[16] = V::Bytes(wire::encode(&parameters).unwrap());
        let signed = wire::sign_envelope(
            &wire::encode(&V::Array(fields)).unwrap(),
            &SigningKey::from_bytes(&[1; 32]),
        )
        .unwrap();
        let request = SignedRequest::from_signed(&signed).unwrap();
        assert_eq!(maximum_duration_ms(&request), MAXIMUM_DURATION_MS);
        let mut session = Session::new().unwrap();
        let health = ClockHealth::new(10000, 100, 20000, 0).unwrap().frozen();
        let ordinary = session
            .issue(&signed, &f.recipient, [95; 32], MAXIMUM_DURATION_MS, health)
            .unwrap();
        Challenge::from_signed(&ordinary)
            .unwrap()
            .validate_request(&request)
            .unwrap();
        assert!(
            session
                .issue(
                    &signed,
                    &f.recipient,
                    [96; 32],
                    FEDERATION_DURATION_MS,
                    health
                )
                .is_err()
        );
    }
}

#[test]
fn federation_freshness_independent_verifier_refuses_wrong_purpose_and_excess_duration() {
    let ordinary = fixture(5001, false);
    assert!(ordinary.verify().is_err());
    let mut maintenance = fixture(FEDERATION_DURATION_MS, true);
    verify(&maintenance).unwrap();
    assert!(verify(&media_fixture(Some(reference(102, 75)))).is_err());
    challenge(&mut maintenance, FEDERATION_DURATION_MS + 1);
    assert!(Challenge::from_signed(&maintenance.challenge).is_err());
}

#[test]
fn federation_freshness_keeps_original_boot_boundary_and_shorter_inherited_expiry() {
    let mut f = fixture(FEDERATION_DURATION_MS, true);
    let mut session = Session::new().unwrap();
    let issued = ClockHealth::new(10000, 100, 20000, 0).unwrap().frozen();
    f.challenge = session
        .issue(
            &f.intent,
            &f.recipient,
            [94; 32],
            FEDERATION_DURATION_MS,
            issued,
        )
        .unwrap();
    f.rebuild();
    let result = verify(&f).unwrap();
    let current = ClockHealth::new(16000, 6100, 20000, 0).unwrap().frozen();
    session.check(&result, 0, current).unwrap();
    let c = Challenge::from_signed(&f.challenge).unwrap();
    assert_eq!(c.evaluation_expiry(10000, 13000).unwrap(), 13000);
    assert!(c.completion_within_interval(12749, 13000));
    assert!(!c.completion_within_interval(12750, 13000));
    assert!(
        session
            .check_at(
                &c,
                13000,
                0,
                Observation {
                    wall_ms: 12750,
                    boot_ms: 2850
                }
            )
            .is_err()
    );
    assert!(
        session
            .check_at(
                &c,
                25000,
                0,
                Observation {
                    wall_ms: 20000,
                    boot_ms: 15100
                }
            )
            .is_err()
    );
    let old = fixture(MAXIMUM_DURATION_MS, true);
    let old = Challenge::from_signed(&old.challenge).unwrap();
    assert_eq!(old.maximum_duration_ms, MAXIMUM_DURATION_MS);
    assert_eq!(old.evaluation_expiry(10000, 15000).unwrap(), 13750);
    assert!(old.evaluation_expiry(10000, 25000).is_err());
}
