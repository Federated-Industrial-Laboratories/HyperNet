// SPDX-License-Identifier: MIT
use super::*;

fn signed(payload: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    let mut signatures: Vec<_> = keys
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            Value::Array(vec![
                Value::Bytes(public.to_vec()),
                Value::Bytes(
                    key.sign(&signature_message(payload, &public))
                        .to_bytes()
                        .to_vec(),
                ),
            ])
        })
        .collect();
    signatures.sort_by_key(|pair| pair.array(2).unwrap()[0].fixed::<32>().unwrap());
    encode(&Value::Array(vec![
        Value::Uint(0),
        Value::Uint(1),
        Value::Bytes(payload.to_vec()),
        Value::Array(signatures),
    ]))
    .unwrap()
}

#[test]
fn cached_strict_verification_binds_message_key_and_signature_and_never_caches_failures() {
    let cache = signature_cache::Cache::new();
    let key = SigningKey::from_bytes(&[57; 32]);
    let payload = encode(&Value::Array(vec![Value::Uint(71)])).unwrap();
    let bytes = signed(&payload, std::slice::from_ref(&key));
    signature_cache::take_signature_statistics();
    for _ in 0..2 {
        assert_eq!(envelope_with_cache(&bytes, 1, &cache).unwrap().0, payload);
    }
    let stats = signature_cache::take_signature_statistics();
    assert_eq!(
        (stats.lookups, stats.hits, stats.strict_verifications),
        (2, 1, 1)
    );

    let fields = decode(&bytes).unwrap().array(4).unwrap().to_vec();
    let mut changed_payload = fields.clone();
    changed_payload[2] = Value::Bytes(encode(&Value::Array(vec![Value::Uint(72)])).unwrap());
    let mut changed_key = fields.clone();
    let mut pair = fields[3].array(1).unwrap()[0].array(2).unwrap().to_vec();
    pair[0] = Value::Bytes(
        SigningKey::from_bytes(&[58; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    );
    changed_key[3] = Value::Array(vec![Value::Array(pair)]);
    let mut changed_signature = fields.clone();
    let mut pair = fields[3].array(1).unwrap()[0].array(2).unwrap().to_vec();
    let mut signature = pair[1].fixed::<64>().unwrap();
    signature[0] ^= 1;
    pair[1] = Value::Bytes(signature.to_vec());
    changed_signature[3] = Value::Array(vec![Value::Array(pair)]);
    for changed in [changed_payload, changed_key, changed_signature] {
        let changed = encode(&Value::Array(changed)).unwrap();
        for _ in 0..2 {
            assert!(envelope_with_cache(&changed, 1, &cache).is_err());
        }
    }
    let stats = signature_cache::take_signature_statistics();
    assert_eq!(
        (stats.lookups, stats.hits, stats.strict_verifications),
        (6, 0, 6)
    );
    assert_eq!(stats.evictions, 0);
    envelope_with_cache(&bytes, 1, &cache).unwrap();
    assert_eq!(signature_cache::take_signature_statistics().hits, 1);

    for weak in [[0; 32], {
        let mut identity = [0; 32];
        identity[0] = 1;
        identity
    }] {
        let mut changed = fields.clone();
        let mut pair = fields[3].array(1).unwrap()[0].array(2).unwrap().to_vec();
        pair[0] = Value::Bytes(weak.to_vec());
        changed[3] = Value::Array(vec![Value::Array(pair)]);
        assert!(envelope_with_cache(&encode(&Value::Array(changed)).unwrap(), 1, &cache).is_err());
    }
    assert_eq!(signature_cache::take_signature_statistics().lookups, 0);
}

#[test]
fn cached_envelopes_still_enforce_canonical_schema_size_and_signer_rules() {
    let cache = signature_cache::Cache::new();
    let keys = [
        SigningKey::from_bytes(&[59; 32]),
        SigningKey::from_bytes(&[60; 32]),
    ];
    let payload = encode(&Value::Array(vec![Value::Uint(73)])).unwrap();
    let bytes = signed(&payload, &keys);
    envelope_with_cache(&bytes, 2, &cache).unwrap();
    signature_cache::take_signature_statistics();
    assert!(envelope_with_cache(&bytes, 1, &cache).is_err());
    let fields = decode(&bytes).unwrap().array(4).unwrap().to_vec();
    let pairs = fields[3].array(2).unwrap();
    let first = pairs[0].array(2).unwrap();
    for (index, value) in [
        (0, Value::Uint(1)),
        (1, Value::Uint(2)),
        (2, Value::Null),
        (3, Value::Null),
        (3, Value::Array(vec![])),
        (3, Value::Array(vec![pairs[0].clone(), pairs[0].clone()])),
        (3, Value::Array(vec![pairs[1].clone(), pairs[0].clone()])),
        (3, Value::Array(vec![Value::Array(vec![first[0].clone()])])),
        (
            3,
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(vec![1; 31]),
                first[1].clone(),
            ])]),
        ),
        (
            3,
            Value::Array(vec![Value::Array(vec![
                first[0].clone(),
                Value::Bytes(vec![1; 63]),
            ])]),
        ),
    ] {
        let mut changed = fields.clone();
        changed[index] = value;
        assert!(envelope_with_cache(&encode(&Value::Array(changed)).unwrap(), 2, &cache).is_err());
    }
    assert!(
        envelope_with_cache(
            &encode(&Value::Array(fields[..3].to_vec())).unwrap(),
            2,
            &cache
        )
        .is_err()
    );
    let mut noncanonical = vec![0x98, 4];
    noncanonical.extend_from_slice(&bytes[1..]);
    assert!(envelope_with_cache(&noncanonical, 2, &cache).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(envelope_with_cache(&trailing, 2, &cache).is_err());
    trailing.resize(MAXIMUM + 1, 0);
    assert!(envelope_with_cache(&trailing, 2, &cache).is_err());
    let stats = signature_cache::take_signature_statistics();
    assert_eq!(
        stats.strict_verifications, 0,
        "Invalid surrounding records cannot bypass validation on a hit"
    );
    assert!(stats.hits > 0);

    // Even a genuine cached signature over noncanonical payload bytes cannot
    // replace the envelope parser's independent canonical-payload requirement.
    let malformed_payload = [0x18, 1];
    let public = keys[0].verifying_key();
    let message = signature_message(&malformed_payload, &public.to_bytes());
    cache
        .verify(
            &valid_key(&public.to_bytes()).unwrap(),
            &message,
            keys[0].sign(&message).to_bytes(),
        )
        .unwrap();
    let malformed = signed(&malformed_payload, &keys[..1]);
    signature_cache::take_signature_statistics();
    assert!(envelope_with_cache(&malformed, 1, &cache).is_err());
    assert_eq!(signature_cache::take_signature_statistics().lookups, 0);
}
