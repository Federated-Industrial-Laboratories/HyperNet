// SPDX-License-Identifier: MIT
// Unit tests for AuthorityStreams.
use super::*;
#[test]
fn owner_offer_never_substitutes_for_operator_acceptance() {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let operator = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
    let mut r = Registration {
        id: [3; 32],
        route: VersionRef {
            kind: 165,
            id: [4; 32],
            generation: 1,
            digest: [5; 32],
        },
        owner: owner.verifying_key().to_bytes(),
        operator: operator.verifying_key().to_bytes(),
        protocol: "example/1".into(),
        binding: [6; 32],
        limits: Limits {
            bytes: 1048576,
            duration_ms: 60000,
            idle_ms: 10000,
        },
        validity: (1, 100000),
        envelope: vec![],
    };
    r.envelope = wire::sign_envelope(&r.payload([1; 32], [2; 32]).unwrap(), &owner).unwrap();
    assert!(Registration::parse_offer(&r.envelope, [1; 32], [2; 32]).is_ok());
    assert!(Registration::parse(&r.envelope, [1; 32], [2; 32]).is_err());
    r.envelope = wire::sign_envelope(&r.payload([1; 32], [2; 32]).unwrap(), &operator).unwrap();
    assert!(Registration::parse_offer(&r.envelope, [1; 32], [2; 32]).is_err());
}
