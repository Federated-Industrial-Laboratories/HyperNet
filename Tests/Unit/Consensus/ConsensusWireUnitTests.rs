// SPDX-License-Identifier: MIT
// Unit tests for ConsensusWire.
use super::*;
#[test]
fn federation_freshness_ordered_parser_enforces_the_exact_request_profile() {
    for (duration, maintenance, accepted) in [
        (5000, false, true),
        (5001, false, false),
        (15000, true, true),
    ] {
        let f = crate::authority_challenge::profile_tests::fixture(duration, maintenance);
        let config = Configuration::trusted(f.descriptor.canonical()).unwrap();
        assert_eq!(OrderedRequest::parse(&config, &f.ordered).is_ok(), accepted);
    }
}
pub fn initial() -> Vec<u8> {
    wire::encode(&V::Array(vec![
        V::Uint(15),
        V::Uint(1),
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        V::Array(vec![]),
    ]))
    .unwrap()
}
pub fn fixture() -> (Configuration, [SigningKey; 4]) {
    let mut keys = [1, 2, 3, 4].map(|v| SigningKey::from_bytes(&[v; 32]));
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let descriptor = wire::encode(&V::Array(vec![
        V::Uint(10),
        V::Uint(1),
        bytes(&[7; 32]),
        bytes(&[8; 32]),
        V::Uint(0),
        V::Array(
            keys.iter()
                .map(|k| bytes(k.verifying_key().as_bytes()))
                .collect(),
        ),
        bytes(&[9; 32]),
        bytes(&[10; 32]),
        bytes(&wire::digest(&initial())),
        V::Uint(10000),
        V::Text("BasicHotStuff".into()),
    ]))
    .unwrap();
    (Configuration::trusted(&descriptor).unwrap(), keys)
}
#[test]
fn quorum_requires_exact_phase_node_scope_and_distinct_members() {
    let (config, keys) = fixture();
    let vote = Vote {
        scope: config.scope.clone(),
        view: 1,
        phase: Phase::Prepare,
        node: [12; 32],
    };
    let mut votes = keys[..3]
        .iter()
        .map(|key| SignedVote::sign(&config, vote.clone(), key).unwrap())
        .collect::<Vec<_>>();
    assert!(Certificate::collect(&config, &votes).is_ok());
    votes[2] = votes[1].clone();
    assert!(Certificate::collect(&config, &votes).is_err());
    votes[2] = SignedVote::sign(
        &config,
        Vote {
            phase: Phase::Commit,
            ..vote.clone()
        },
        &keys[2],
    )
    .unwrap();
    assert!(Certificate::collect(&config, &votes).is_err());
    assert!(SignedVote::sign(&config, vote, &SigningKey::from_bytes(&[22; 32])).is_err());
}
