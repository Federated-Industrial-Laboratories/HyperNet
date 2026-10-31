// SPDX-License-Identifier: MIT
// Unit tests for RuntimeBootstrapKeys.
use super::*;
use ed25519_dalek::SigningKey;
#[test]
fn immutable_reservations_bind_complete_committee_and_distinct_monitor() {
    let public = |seed| {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    };
    let mut voters = (1..=4).map(public).collect::<Vec<_>>();
    voters.sort();
    let keys = Keys {
        authority_transports: voters
            .iter()
            .enumerate()
            .map(|(i, voter)| (*voter, public(20 + i as u8)))
            .collect(),
        clock_monitors: [public(30)].into_iter().collect(),
        route_transports: [(2, ([70; 32], public(31))), (3, ([71; 32], public(32)))]
            .into_iter()
            .collect(),
    };
    let bytes = keys.encode([40; 32], [41; 32]).unwrap();
    let parsed = Keys::parse(&bytes, [40; 32], [41; 32]).unwrap();
    parsed.validate_voters(&voters).unwrap();
    assert_eq!(parsed.reservations().count(), 5);
    let mut wrong = voters.clone();
    wrong[0] = public(50);
    assert!(parsed.validate_voters(&wrong).is_err());
    let mut collision = keys.clone();
    collision.clock_monitors = [voters[0]].into_iter().collect();
    assert!(collision.encode([40; 32], [41; 32]).is_err());
    let mut value = wire::decode(&bytes).unwrap().array(9).unwrap().to_vec();
    value[4] = V::Uint(2);
    assert!(Keys::parse(&wire::encode(&V::Array(value)).unwrap(), [40; 32], [41; 32]).is_err());
}
