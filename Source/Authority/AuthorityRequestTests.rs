// SPDX-License-Identifier: MIT
use super::*;
use crate::trust_wire::Value as V;
use ed25519_dalek::SigningKey;

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[41; 32])
}
fn b(bytes: &[u8]) -> V {
    V::Bytes(bytes.to_vec())
}
fn fields(kind: u64) -> Vec<V> {
    let requester = signer().verifying_key().to_bytes();
    match kind {
        20 => vec![
            V::Uint(20),
            V::Uint(1),
            b(&[1; 32]),
            b(&[2; 32]),
            V::Uint(1),
            b(&[3; 32]),
            V::Uint(1),
            V::Uint(0),
            b(&requester),
            V::Text("AuthorityInspect".into()),
            b(&[4; 32]),
            V::Uint(2),
            V::Uint(0),
            V::Uint(3),
            V::Uint(100),
            V::Array(vec![]),
            b(&wire::encode(&V::Array(vec![])).unwrap()),
        ],
        55 => vec![
            V::Uint(55),
            V::Uint(1),
            b(&[1; 32]),
            b(&[2; 32]),
            b(&requester),
            b(&[5; 32]),
            V::Uint(3),
            V::Uint(100),
        ],
        57 => vec![
            V::Uint(57),
            V::Uint(1),
            b(&[1; 32]),
            b(&[2; 32]),
            b(&requester),
            b(&[5; 32]),
            V::Uint(3),
            V::Uint(100),
            V::Uint(7),
            b(&[6; 32]),
            b(&[7; 32]),
        ],
        _ => unreachable!(),
    }
}
fn signed(fields: Vec<V>) -> Vec<u8> {
    wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &signer()).unwrap()
}

#[test]
fn authenticated_variants_have_exact_distinct_authority() {
    for kind in [20, 55, 57] {
        let request = SignedRequest::from_signed(&signed(fields(kind))).unwrap();
        assert_eq!(request.network(), [1; 32]);
        assert_eq!(request.incarnation(), [2; 32]);
        assert_eq!(request.requester(), signer().verifying_key().to_bytes());
        assert_eq!(request.minimum_policy_epoch(), 3);
        assert_eq!(request.minimum_policy_height(), 100);
        if kind == 20 {
            let intent = request.ordinary().unwrap();
            assert_eq!(
                (
                    intent.generation,
                    intent.sequence,
                    intent.acknowledged_through
                ),
                (1, 1, 0)
            );
            assert_eq!(request.resource(), [4; 32]);
            assert_eq!(request.revision(), 2);
        } else {
            assert!(request.ordinary().is_err());
            assert!(Intent::from_signed(&signed(fields(kind))).is_err());
            assert_eq!(request.resource(), request.requester());
            assert_eq!(request.profile_generation(), 0);
            assert!(request.expected().is_empty());
            assert_eq!(request.revision(), if kind == 55 { 0 } else { 7 });
            assert_eq!(
                request.action(),
                if kind == 55 {
                    "AuthorityStreamStatus"
                } else {
                    "AuthorityStreamFence"
                }
            );
        }
    }
}

#[test]
fn altered_signers_extra_authority_and_old_shapes_are_rejected() {
    for kind in [20, 55, 57] {
        let mut changed = fields(kind);
        changed[if kind == 20 { 8 } else { 4 }] =
            b(&SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes());
        assert!(SignedRequest::from_signed(&signed(changed)).is_err());
        let mut extra = fields(kind);
        extra.push(V::Text("AuthorityRevokeGrant".into()));
        assert!(SignedRequest::from_signed(&signed(extra)).is_err());
        let mut version = fields(kind);
        version[1] = V::Uint(2);
        assert!(SignedRequest::from_signed(&signed(version)).is_err());
    }
    let mut old = fields(20);
    old.truncate(13);
    assert!(SignedRequest::from_signed(&signed(old)).is_err());
    for action in ["AuthorityStreamStatus", "AuthorityStreamFence"] {
        let mut alias = fields(20);
        alias[9] = V::Text(action.into());
        assert!(SignedRequest::from_signed(&signed(alias)).is_err());
    }
    let mut unknown = fields(55);
    unknown[0] = V::Uint(56);
    assert!(SignedRequest::from_signed(&signed(unknown)).is_err());
}

#[test]
fn generation_sequence_and_nonce_bounds_do_not_wrap() {
    for (index, value) in [
        (4, V::Uint(0)),
        (5, b(&[0; 32])),
        (6, V::Uint(0)),
        (7, V::Uint(1)),
    ] {
        let mut invalid = fields(20);
        invalid[index] = value;
        assert!(SignedRequest::from_signed(&signed(invalid)).is_err());
    }
    let mut last = fields(20);
    last[4] = V::Uint(u64::MAX);
    last[6] = V::Uint(u64::MAX);
    last[7] = V::Uint(u64::MAX - 1);
    assert_eq!(
        Intent::from_signed(&signed(last)).unwrap().sequence,
        u64::MAX
    );
    for kind in [55, 57] {
        let mut invalid = fields(kind);
        invalid[5] = b(&[0; 32]);
        assert!(SignedRequest::from_signed(&signed(invalid)).is_err());
    }
    for (index, value) in [(8, V::Uint(0)), (9, b(&[0; 32])), (10, b(&[0; 32]))] {
        let mut invalid = fields(57);
        invalid[index] = value;
        assert!(SignedRequest::from_signed(&signed(invalid)).is_err());
    }
}

#[test]
fn immutable_digest_covers_floors_and_fence_comparison() {
    let original = fields(57);
    let encoded = signed(original.clone());
    let first = SignedRequest::from_signed(&encoded).unwrap();
    assert_eq!(
        first.digest(),
        SignedRequest::from_signed(&encoded).unwrap().digest()
    );
    for (index, value) in [
        (5, b(&[8; 32])),
        (6, V::Uint(4)),
        (7, V::Uint(101)),
        (8, V::Uint(8)),
        (9, b(&[9; 32])),
        (10, b(&[10; 32])),
    ] {
        let mut changed = original.clone();
        changed[index] = value;
        let updated = signed(changed);
        assert_ne!(
            first.digest(),
            SignedRequest::from_signed(&updated).unwrap().digest()
        );
        let mut envelope = wire::decode(&encoded).unwrap().array(4).unwrap().to_vec();
        envelope[2] = wire::decode(&updated).unwrap().array(4).unwrap()[2].clone();
        assert!(SignedRequest::from_signed(&wire::encode(&V::Array(envelope)).unwrap()).is_err());
    }
}
