// SPDX-License-Identifier: MIT
// Quorum evidence rejects forged context, stale prefixes and unvalidated action schemas.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn bytes(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn array(value: Vec<V>) -> Vec<u8> {
    wire::encode(&V::Array(value)).unwrap()
}
pub(crate) fn signers() -> Vec<SigningKey> {
    let mut keys: Vec<_> = (11..=14)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    keys
}
fn quorum(payload: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    array(vec![
        V::Uint(0),
        V::Uint(1),
        bytes(payload),
        V::Array(
            keys.iter()
                .map(|k| {
                    let public = k.verifying_key().to_bytes();
                    V::Array(vec![
                        bytes(&public),
                        bytes(
                            &k.sign(&wire::signature_message(payload, &public))
                                .to_bytes(),
                        ),
                    ])
                })
                .collect(),
        ),
    ])
}
pub(crate) struct Fixture {
    pub descriptor: TrustDescriptor,
    pub recipient: SigningKey,
    pub intent: Vec<u8>,
    pub challenge: Vec<u8>,
    pub ordered: Vec<u8>,
    pub operation: Vec<u8>,
    pub certificate: Vec<u8>,
    pub ancestry: Vec<Vec<u8>>,
    pub evaluated_at: u64,
    pub restrictions: Restrictions,
}
impl Fixture {
    pub fn new(time: u64) -> Self {
        let descriptor = TrustDescriptor::from_canonical(&array(vec![
            V::Uint(10),
            V::Uint(1),
            bytes(&[81; 32]),
            bytes(&[82; 32]),
            V::Uint(0),
            V::Array(
                signers()
                    .iter()
                    .map(|k| bytes(&k.verifying_key().to_bytes()))
                    .collect(),
            ),
            bytes(&[83; 32]),
            bytes(&[84; 32]),
            bytes(&[85; 32]),
            V::Uint(1),
            V::Text("BasicHotStuff".into()),
        ]))
        .unwrap();
        let requester = SigningKey::from_bytes(&[1; 32]);
        let recipient = SigningKey::from_bytes(&[2; 32]);
        let parameters = array(vec![V::Uint(200), V::Uint(1)]);
        let payload = array(vec![
            V::Uint(20),
            V::Uint(1),
            bytes(&[81; 32]),
            bytes(&[82; 32]),
            V::Uint(1),
            bytes(
                &initial_generation_id([81; 32], [82; 32], requester.verifying_key().to_bytes())
                    .unwrap(),
            ),
            V::Uint(1),
            V::Uint(0),
            bytes(&requester.verifying_key().to_bytes()),
            V::Text("ReadPage".into()),
            bytes(&[4; 32]),
            V::Uint(1),
            V::Uint(1),
            V::Uint(0),
            V::Uint(0),
            V::Array(Vec::new()),
            bytes(&parameters),
        ]);
        let intent = wire::sign_envelope(&payload, &requester).unwrap();
        let challenge = wire::sign_envelope(
            &array(vec![
                V::Uint(21),
                V::Uint(1),
                bytes(&[81; 32]),
                bytes(&[82; 32]),
                bytes(&recipient.verifying_key().to_bytes()),
                bytes(&[5; 32]),
                bytes(&[6; 32]),
                bytes(&wire::digest(&payload)),
                bytes(&[7; 32]),
                V::Uint(time),
                V::Uint(time + 5000),
                V::Uint(5000),
            ]),
            &recipient,
        )
        .unwrap();
        let operation = array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text("ReadPage".into()),
            V::Uint(0),
            V::Uint(0),
            bytes(&parameters),
        ]);
        let mut f = Self {
            descriptor,
            recipient,
            intent,
            challenge,
            ordered: Vec::new(),
            operation,
            certificate: Vec::new(),
            ancestry: Vec::new(),
            evaluated_at: time,
            restrictions: Restrictions {
                consent: Some([86; 32]),
                placement: None,
                route: Some([87; 32]),
            },
        };
        f.rebuild();
        f
    }
    pub fn rebuild(&mut self) {
        let intent = Intent::from_signed(&self.intent).unwrap();
        let challenge = Challenge::from_signed(&self.challenge).unwrap();
        self.ordered = array(vec![
            V::Uint(22),
            V::Uint(1),
            self.descriptor.scope().value(),
            bytes(&self.intent),
            bytes(&self.challenge),
            V::Uint(challenge.expires_at_ms),
        ]);
        let node = array(vec![
            V::Uint(14),
            V::Uint(1),
            self.descriptor.scope().value(),
            V::Uint(1),
            V::Uint(1),
            bytes(self.descriptor.genesis().unwrap().node()),
            bytes(&wire::digest(&self.ordered)),
            V::Uint(self.evaluated_at),
            bytes(&[88; 32]),
        ]);
        self.certificate = quorum(
            &array(vec![
                V::Uint(23),
                V::Uint(1),
                self.descriptor.scope().value(),
                V::Uint(1),
                bytes(&wire::digest(&node)),
                bytes(&wire::digest(&self.ordered)),
                bytes(&intent.digest),
                bytes(&challenge.digest),
                bytes(&intent.requester),
                bytes(&challenge.recipient),
                V::Text(intent.action),
                bytes(&intent.resource),
                V::Uint(intent.revision),
                V::Uint(intent.profile_generation),
                V::Uint(64),
                bytes(&wire::digest(&self.operation)),
                bytes(&[89; 32]),
                V::Uint(intent.minimum_policy_height),
                V::Uint(self.evaluated_at),
                V::Uint(
                    challenge.expires_at_ms.min(
                        self.evaluated_at
                            .saturating_sub(crate::authority_governance::UNCERTAINTY_MS)
                            .saturating_add(challenge.maximum_duration_ms),
                    ),
                ),
                bytes(&[86; 32]),
                V::Null,
                bytes(&[87; 32]),
            ]),
            &signers()[..3],
        );
        self.ancestry = vec![node];
    }
    pub fn context(&self) -> ProofContext<'_> {
        ProofContext {
            intent: &self.intent,
            challenge: &self.challenge,
            restrictions: self.restrictions.clone(),
            minimum_height: 0,
            maximum_effect: 64,
            expected_stream: None,
        }
    }
    pub fn response(&self) -> Response<'_> {
        Response {
            ordered_request: &self.ordered,
            operation_result: &self.operation,
            certificate: &self.certificate,
            ancestry: &self.ancestry,
        }
    }
    pub fn verify(&self) -> Result<VerifiedResult> {
        verify_response(
            &self.descriptor,
            self.context(),
            self.response(),
            |intent, result, _| {
                ensure!(
                    intent.action == "ReadPage"
                        && wire::decode(&intent.parameters)?
                            == V::Array(vec![V::Uint(200), V::Uint(1)])
                        && result.value == intent.parameters,
                    "test action schema mismatch"
                );
                ActionValidation::new(Vec::new())
            },
        )
    }
    fn edit_certificate(&mut self, index: usize, value: V) {
        let (payload, _) = wire::envelope(&self.certificate, 4).unwrap();
        let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
            panic!("array")
        };
        fields[index] = value;
        self.certificate = quorum(&array(fields), &signers()[..3]);
    }
}
#[test]
fn quorum_result_requires_exact_context_and_typed_action() {
    let f = Fixture::new(10000);
    let accepted = f.verify().unwrap();
    accepted.extends(&f.descriptor.genesis().unwrap()).unwrap();
    assert!(
        verify_response(
            &f.descriptor,
            f.context(),
            f.response(),
            |_, _, _| anyhow::bail!("unknown schema")
        )
        .is_err()
    );
    for index in [4, 5, 6, 7, 8, 9, 11, 15, 20, 22] {
        let mut changed = Fixture::new(10000);
        let value = if index == 8 || index == 9 {
            signers()[0].verifying_key().to_bytes()
        } else {
            [42; 32]
        };
        changed.edit_certificate(index, bytes(&value));
        assert!(changed.verify().is_err(), "field {index}");
    }
    for index in [12, 13, 14, 17, 19] {
        let mut changed = Fixture::new(10000);
        changed.edit_certificate(index, V::Uint(99999));
        assert!(changed.verify().is_err(), "field {index}");
    }
    let mut context = f.context();
    context.restrictions.route = None;
    assert!(
        verify_response(&f.descriptor, context, f.response(), |_, _, _| {
            ActionValidation::new(Vec::new())
        })
        .is_err()
    );
    let mut context = f.context();
    context.minimum_height = 2;
    assert!(
        verify_response(&f.descriptor, context, f.response(), |_, _, _| {
            ActionValidation::new(Vec::new())
        })
        .is_err()
    );
}
#[test]
fn one_server_duplicate_unknown_and_wrong_kind_cannot_certify() {
    let f = Fixture::new(10000);
    let (payload, _) = wire::envelope(&f.certificate, 4).unwrap();
    for count in 1..=2 {
        let mut bad = Fixture::new(10000);
        bad.certificate = quorum(&payload, &signers()[..count]);
        assert!(bad.verify().is_err());
    }
    let mut keys = signers();
    keys[0] = SigningKey::from_bytes(&[70; 32]);
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let mut bad = Fixture::new(10000);
    bad.certificate = quorum(&payload, &keys);
    assert!(bad.verify().is_err());
    let V::Array(mut outer) = wire::decode(&f.certificate).unwrap() else {
        panic!("array")
    };
    let V::Array(ref mut pairs) = outer[3] else {
        panic!("array")
    };
    pairs[1] = pairs[0].clone();
    bad.certificate = array(outer);
    assert!(bad.verify().is_err());
    bad.certificate = quorum(
        &array(vec![
            V::Uint(11),
            V::Uint(1),
            f.descriptor.scope().value(),
            V::Uint(1),
            V::Uint(2),
            bytes(&[10; 32]),
        ]),
        &signers()[..3],
    );
    assert!(bad.verify().is_err());
    bad.certificate = f.certificate.clone();
    let last = bad.certificate.len() - 1;
    bad.certificate[last] ^= 1;
    assert!(bad.verify().is_err());
}
#[test]
fn prefix_is_a_certified_hash_chain_not_a_height_counter() {
    let f = Fixture::new(10000);
    let accepted = f.verify().unwrap();
    let mut floor = f.descriptor.genesis().unwrap();
    floor.node = [40; 32];
    assert!(accepted.extends(&floor).is_err());
    let mut conflicting = accepted.point.prefix.clone();
    conflicting.policy_state = [41; 32];
    assert!(accepted.extends(&conflicting).is_err());
    let mut conflicting = accepted.point.prefix.clone();
    conflicting.node = [41; 32];
    assert!(accepted.extends(&conflicting).is_err());
    let mut later = accepted.point.prefix.clone();
    later.height = 2;
    assert!(accepted.extends(&later).is_err());
}
#[test]
fn altered_result_bytes_and_noncanonical_envelopes_are_refused() {
    let mut f = Fixture::new(10000);
    f.operation = array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("ReadPage".into()),
        V::Uint(0),
        V::Uint(0),
        bytes(&array(vec![V::Uint(201), V::Uint(1)])),
    ]);
    assert!(f.verify().is_err());
    let mut f = Fixture::new(10000);
    f.intent.push(0);
    assert!(f.verify().is_err());
    let mut f = Fixture::new(10000);
    f.challenge.push(0);
    assert!(f.verify().is_err());
}

#[test]
fn future_requested_floor_can_receive_a_certified_refusal_but_never_a_permit() {
    let mut f = Fixture::new(10000);
    let requester = SigningKey::from_bytes(&[1; 32]);
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[14] = V::Uint(100);
    let payload = array(fields);
    f.intent = wire::sign_envelope(&payload, &requester).unwrap();
    let (challenge, _) = wire::envelope(&f.challenge, 1).unwrap();
    let mut fields = wire::decode(&challenge)
        .unwrap()
        .array(12)
        .unwrap()
        .to_vec();
    fields[7] = bytes(&wire::digest(&payload));
    f.challenge = wire::sign_envelope(&array(fields), &f.recipient).unwrap();
    f.rebuild();
    assert!(f.verify().is_err());
    let mut result = wire::decode(&f.operation)
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    result[3] = V::Uint(1);
    result[4] = V::Uint(21);
    f.operation = array(result);
    f.rebuild();
    f.edit_certificate(14, V::Uint(0));
    let result = f.verify().unwrap();
    assert_eq!(result.disposition(), Disposition::Refuse);
    assert_eq!(result.code(), 21);
    let mut context = f.context();
    context.minimum_height = 2;
    assert!(
        verify_response(&f.descriptor, context, f.response(), |_, _, _| {
            ActionValidation::new(Vec::new())
        })
        .is_err()
    );
}

#[test]
fn challenge_creation_is_plausible_without_maturation_and_cannot_extend_freshness() {
    let f = Fixture::new(10000);
    let original = Challenge::from_signed(&f.challenge).unwrap();
    assert_eq!(original.evaluation_expiry(10000, 15000).unwrap(), 13750);
    let mut future = original.clone();
    future.created_at_ms = 11250;
    future.expires_at_ms = 16250;
    assert_eq!(future.evaluation_expiry(10000, 16250).unwrap(), 13750);
    future.created_at_ms += 1;
    assert!(future.evaluation_expiry(10000, 16250).is_err());
    let mut old = original.clone();
    old.created_at_ms = 8000;
    old.expires_at_ms = 13000;
    assert_eq!(old.evaluation_expiry(10000, 13000).unwrap(), 13000);
    assert!(old.evaluation_expiry(11750, 13000).is_err());
    assert!(original.evaluation_expiry(10000, 15001).is_err());
    assert!(original.evaluation_expiry(1249, 15000).is_err());
    assert!(original.evaluation_expiry(u64::MAX, u64::MAX).is_err());
    let mut short = original;
    short.maximum_duration_ms = 2500;
    short.expires_at_ms = 12500;
    assert!(short.evaluation_expiry(10000, 12500).is_err());
}
#[test]
fn every_permit_independently_enforces_the_execution_cap_and_strict_expiry() {
    let mut f = Fixture::new(10000);
    let verified = f.verify().unwrap();
    assert_eq!(verified.executed.expires_at_ms, 13750);
    f.edit_certificate(19, V::Uint(13751));
    assert!(f.verify().is_err());
    f.edit_certificate(19, V::Uint(11250));
    assert!(f.verify().is_err());
    f.edit_certificate(19, V::Uint(11251));
    assert!(f.verify().is_ok());
}

#[test]
fn immediate_completion_preserves_same_recipient_order_and_strict_expiry() {
    let f = Fixture::new(10000);
    let challenge = Challenge::from_signed(&f.challenge).unwrap();
    let created = challenge.created_at_ms;
    let expiry = challenge
        .evaluation_expiry(created, challenge.expires_at_ms)
        .unwrap();
    assert!(challenge.completion_within_interval(created, expiry));
    assert!(challenge.completion_within_interval(created + 100, expiry));
    assert!(!challenge.completion_within_interval(created - 1, expiry));
    let boundary = expiry - crate::authority_challenge::DELTA_MS;
    assert!(challenge.completion_within_interval(boundary - 1, expiry));
    assert!(!challenge.completion_within_interval(boundary, expiry));
    assert!(!challenge.completion_within_interval(u64::MAX, expiry));
    assert!(!challenge.completion_within_interval(challenge.expires_at_ms, u64::MAX));
}
