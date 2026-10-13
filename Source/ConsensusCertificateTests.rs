// SPDX-License-Identifier: MIT
use super::*;

fn proof(config: &Configuration, keys: &[SigningKey], vote: &Vote) -> Vec<u8> {
    let signatures = keys
        .iter()
        .map(|key| {
            let signed = SignedVote::sign(config, vote.clone(), key).unwrap();
            V::Array(vec![bytes(&signed.signer), bytes(&signed.signature)])
        })
        .collect();
    wire::encode(&V::Array(vec![
        V::Uint(12),
        V::Uint(1),
        config.scope.value(),
        bytes(&vote.encode().unwrap()),
        V::Array(signatures),
    ]))
    .unwrap()
}
fn statement(config: &Configuration) -> Vote {
    Vote {
        scope: config.scope.clone(),
        view: 7,
        phase: Phase::Prepare,
        node: [90; 32],
    }
}

#[test]
fn exact_certificate_reuse_preserves_distinct_quorum_proofs_and_thread_isolation() {
    let (config, keys) = tests::fixture();
    let vote = statement(&config);
    let three = proof(&config, &keys[..3], &vote);
    let four = proof(&config, &keys, &vote);
    signature_cache::clear();
    let before = Certificate::signature_check_count();
    let first = Certificate::parse(&config, &three).unwrap();
    assert_eq!(Certificate::signature_check_count() - before, 3);
    assert_eq!(Certificate::parse(&config, &three).unwrap().bytes, three);
    assert_eq!(Certificate::signature_check_count() - before, 3);
    let extended = Certificate::parse(&config, &four).unwrap();
    assert_eq!(first.digest(), extended.digest());
    assert_ne!(first.bytes, extended.bytes);
    assert_eq!(Certificate::signature_check_count() - before, 7);
    Certificate::parse(&config, &four).unwrap();
    assert_eq!(Certificate::signature_check_count() - before, 7);
    let genesis = config.genesis_qc().unwrap();
    assert!(!signature_cache::contains(&genesis.bytes));

    std::thread::spawn(move || {
        assert!(!signature_cache::contains(&three));
        let before = Certificate::signature_check_count();
        Certificate::parse(&config, &three).unwrap();
        assert_eq!(Certificate::signature_check_count() - before, 3);
    })
    .join()
    .unwrap();
}

#[test]
fn changed_certificate_payload_or_signature_is_never_reused_or_remembered() {
    let (config, keys) = tests::fixture();
    let vote = statement(&config);
    let original = proof(&config, &keys[..3], &vote);
    signature_cache::clear();
    Certificate::parse(&config, &original).unwrap();

    let mut payload = wire::decode(&original).unwrap().array(5).unwrap().to_vec();
    payload[3] = bytes(
        &Vote {
            node: [91; 32],
            ..vote
        }
        .encode()
        .unwrap(),
    );
    let payload = wire::encode(&V::Array(payload)).unwrap();
    let mut altered = wire::decode(&original).unwrap().array(5).unwrap().to_vec();
    let mut pairs = altered[4].list(4).unwrap().to_vec();
    let mut pair = pairs[0].array(2).unwrap().to_vec();
    let mut signature = pair[1].bytes().unwrap().to_vec();
    signature[0] ^= 1;
    pair[1] = bytes(&signature);
    pairs[0] = V::Array(pair);
    altered[4] = V::Array(pairs);
    let altered = wire::encode(&V::Array(altered)).unwrap();
    for candidate in [&payload, &altered] {
        let before = Certificate::signature_check_count();
        for _ in 0..2 {
            assert!(Certificate::parse(&config, candidate).is_err());
            assert!(!signature_cache::contains(candidate));
        }
        assert_eq!(Certificate::signature_check_count() - before, 2);
    }
    let before = Certificate::signature_check_count();
    Certificate::parse(&config, &original).unwrap();
    assert_eq!(Certificate::signature_check_count(), before);
}

#[test]
fn certificate_reuse_still_checks_current_scope_and_committee() {
    let (config, keys) = tests::fixture();
    let original = proof(&config, &keys[..3], &statement(&config));
    signature_cache::clear();
    Certificate::parse(&config, &original).unwrap();
    let before = Certificate::signature_check_count();

    let mut foreign = config.clone();
    foreign.scope.incarnation = [92; 32];
    assert!(Certificate::parse(&foreign, &original).is_err());
    let mut changed = config.clone();
    changed.voters[0] = SigningKey::from_bytes(&[93; 32]).verifying_key().to_bytes();
    changed.voters.sort();
    assert_eq!(changed.scope, config.scope);
    assert!(Certificate::parse(&changed, &original).is_err());
    assert_eq!(Certificate::signature_check_count(), before);

    Certificate::parse(&config, &original).unwrap();
    assert_eq!(Certificate::signature_check_count(), before);
}

#[test]
fn evicted_certificate_requires_signature_checks_again() {
    let (config, keys) = tests::fixture();
    let vote = statement(&config);
    let original = proof(&config, &keys[..3], &vote);
    signature_cache::clear();
    Certificate::parse(&config, &original).unwrap();
    for view in 8..264 {
        let next = proof(
            &config,
            &keys[..3],
            &Vote {
                view,
                ..vote.clone()
            },
        );
        Certificate::parse(&config, &next).unwrap();
    }
    assert!(!signature_cache::contains(&original));
    let before = Certificate::signature_check_count();
    Certificate::parse(&config, &original).unwrap();
    assert_eq!(Certificate::signature_check_count() - before, 3);
    Certificate::parse(&config, &original).unwrap();
    assert_eq!(Certificate::signature_check_count() - before, 3);
}
