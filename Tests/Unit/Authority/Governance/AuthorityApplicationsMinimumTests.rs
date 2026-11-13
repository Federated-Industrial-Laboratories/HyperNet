// SPDX-License-Identifier: MIT
// Mixed read minima preserve exact signed requests without widening authority references.
use super::*;
use ed25519_dalek::SigningKey;
fn minimum(kind: u64, byte: u8) -> VersionRef {
    VersionRef {
        kind,
        id: [byte; 32],
        generation: 1,
        digest: [byte; 32],
    }
}
fn signed(action: &str, minimum: V) -> Vec<u8> {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let requester = signer.verifying_key().to_bytes();
    let resource = match action {
        "AuthorityDelegationContext" => [3; 32],
        "AuthorityApplicationGet" => SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
        _ => requester,
    };
    let mut parameters = vec![V::Uint(200), V::Uint(1), V::Text(action.into())];
    if action == "AuthorityDelegationContext" {
        parameters.extend([
            b(&resource),
            b(&[4; 32]),
            V::Null,
            a(vec![V::Uint(0), V::Uint(19), b(&[99; 32])]),
            minimum,
        ]);
    } else {
        parameters.extend([b(&resource), minimum]);
    }
    wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(20),
            V::Uint(1),
            b(&[1; 32]),
            b(&[2; 32]),
            V::Uint(1),
            b(
                &crate::authority_proof::initial_generation_id([1; 32], [2; 32], requester)
                    .unwrap(),
            ),
            V::Uint(19),
            V::Uint(18),
            b(&requester),
            V::Text(action.into()),
            b(&resource),
            V::Uint(0),
            V::Uint(0),
            V::Uint(0),
            V::Uint(19),
            a(vec![]),
            b(&wire::encode(&a(parameters)).unwrap()),
        ]))
        .unwrap(),
        &signer,
    )
    .unwrap()
}
#[test]
fn exact_signed_application_reads_accept_mixed_retained_floors() {
    let mixed = [minimum(102, 3), minimum(147, 6), minimum(165, 8)];
    for action in [
        "AuthorityDelegationContext",
        "AuthorityApplicationGet",
        "AuthorityApplicationList",
    ] {
        let bytes = signed(action, a(mixed.iter().map(reference).collect()));
        let intent = Intent::from_signed(&bytes).unwrap();
        let parsed = Operation::parse(&intent).unwrap();
        let retained = match parsed {
            Operation::Context { minimum, .. }
            | Operation::Get { minimum, .. }
            | Operation::List { minimum, .. } => minimum,
            _ => panic!("read changed its action"),
        };
        assert_eq!(
            retained.iter().map(|v| v.kind).collect::<Vec<_>>(),
            vec![102, 147, 165]
        );
        assert_eq!(retained[2].digest, mixed[2].digest);
    }
    // Authority-bearing/result references retain their governance-only codec.
    assert!(membership::version(&reference(&mixed[1])).is_err());
    assert!(refs(&a(mixed.iter().map(reference).collect()), 512).is_err());
    let mut stale = minimum(102, 3);
    stale.generation = 2;
    assert!(!relevant_minima(&[mixed[0].clone()], &[stale]));
    let mut changed = mixed[0].clone();
    changed.digest = [10; 32];
    assert!(!relevant_minima(&[mixed[0].clone()], &[changed]));
}
#[test]
fn mixed_minima_keep_structural_order_and_capacity_checks() {
    let base = minimum(147, 6);
    for mutation in 0..4 {
        let mut changed = base.clone();
        match mutation {
            0 => changed.kind = 0,
            1 => changed.id = [0; 32],
            2 => changed.generation = 0,
            _ => changed.digest = [0; 32],
        }
        let bytes = signed("AuthorityDelegationContext", a(vec![reference(&changed)]));
        assert!(
            Operation::parse(&Intent::from_signed(&bytes).unwrap()).is_err(),
            "mutation {mutation}"
        );
    }
    for values in [
        vec![base.clone(), base.clone()],
        vec![minimum(165, 8), base],
    ] {
        assert!(minimum_refs(&a(values.iter().map(reference).collect()), 512).is_err());
    }
    let oversized = (0..513)
        .map(|index| reference(&minimum(1000 + index, 1)))
        .collect();
    assert!(minimum_refs(&a(oversized), 512).is_err());
}
