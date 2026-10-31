// SPDX-License-Identifier: MIT
// Applied-state checkpoints retain exact quorum, anchor and record-shape requirements.
use super::*;
use crate::authority_proof::tests::{Fixture, signers};
use ed25519_dalek::Signer;

fn bytes(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn encode(fields: Vec<V>) -> Vec<u8> {
    wire::encode(&V::Array(fields)).unwrap()
}
fn envelope(statement: &[u8], count: usize) -> Vec<u8> {
    encode(vec![
        V::Uint(0),
        V::Uint(1),
        bytes(statement),
        V::Array(
            signers()[..count]
                .iter()
                .map(|key| {
                    let public = key.verifying_key().to_bytes();
                    V::Array(vec![
                        bytes(&public),
                        bytes(
                            &key.sign(&wire::signature_message(statement, &public))
                                .to_bytes(),
                        ),
                    ])
                })
                .collect(),
        ),
    ])
}
fn checkpoint(fixture: &Fixture, count: usize) -> Vec<V> {
    let anchor = encode(vec![
        V::Uint(14),
        V::Uint(1),
        fixture.descriptor.scope().value(),
        V::Uint(40),
        V::Uint(32),
        bytes(&[72; 32]),
        bytes(&[73; 32]),
        V::Uint(10000),
        bytes(&[74; 32]),
    ]);
    let statement = encode(vec![
        V::Uint(45),
        V::Uint(1),
        fixture.descriptor.scope().value(),
        V::Uint(32),
        bytes(&wire::digest(&anchor)),
        V::Uint(10000),
        bytes(&[75; 32]),
        V::Uint(32),
        bytes(&[76; 32]),
        V::Bool(false),
    ]);
    vec![
        V::Uint(46),
        V::Uint(1),
        bytes(&envelope(&statement, count)),
        bytes(&anchor),
    ]
}
#[test]
fn checkpoint_requires_exact_applied_state_quorum_and_anchor_without_phase_qc() {
    let fixture = Fixture::new(10000);
    let canonical = encode(checkpoint(&fixture, 3));
    let verified = verify_checkpoint(&fixture.descriptor, &canonical).unwrap();
    assert_eq!(verified.height(), 32);
    assert_eq!(verified.canonical_proof(), canonical);
    assert!(!verified.terminal());
    let four = verify_checkpoint(&fixture.descriptor, &encode(checkpoint(&fixture, 4))).unwrap();
    assert_eq!(verified.digest(), four.digest());
    assert!(verify_checkpoint(&fixture.descriptor, &encode(checkpoint(&fixture, 2))).is_err());
    let mut wrong_anchor = checkpoint(&fixture, 3);
    wrong_anchor[3] = bytes(&fixture.ancestry[0]);
    assert!(verify_checkpoint(&fixture.descriptor, &encode(wrong_anchor)).is_err());
    let mut former_shape = checkpoint(&fixture, 3);
    former_shape.extend([bytes(&[]), V::Array(vec![])]);
    assert!(verify_checkpoint(&fixture.descriptor, &encode(former_shape)).is_err());
}
