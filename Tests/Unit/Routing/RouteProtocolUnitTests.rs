// SPDX-License-Identifier: MIT
// Unit tests for RouteProtocol.
use super::*;
#[test]
fn endpoint_readiness_binds_exact_selected_service_and_protocol() {
    let bytes = endpoint_ready([1; 32], [2; 32], [3; 32], 1).unwrap();
    parse_endpoint_ready(&bytes, [1; 32], [2; 32], [3; 32], 1).unwrap();
    assert!(parse_endpoint_ready(&bytes, [4; 32], [2; 32], [3; 32], 1).is_err());
    assert!(parse_endpoint_ready(&bytes, [1; 32], [4; 32], [3; 32], 1).is_err());
    assert!(parse_endpoint_ready(&bytes, [1; 32], [2; 32], [4; 32], 1).is_err());
    assert!(parse_endpoint_ready(&bytes, [1; 32], [2; 32], [3; 32], 2).is_err());
    let mut extra = bytes;
    extra.push(0);
    assert!(parse_endpoint_ready(&extra, [1; 32], [2; 32], [3; 32], 1).is_err());
}
#[test]
fn route_possession_cannot_move_between_channels_or_destinations() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let open = Open {
        network: [1; 32],
        incarnation: [2; 32],
        relay: [3; 32],
        service: [4; 32],
        voucher: vec![5],
        nonce: [6; 32],
        attachment: false,
    };
    let proof = open.sign([7; 32], [8; 32], &key).unwrap();
    assert_eq!(
        open.verify([7; 32], [8; 32], &proof).unwrap(),
        key.verifying_key().to_bytes()
    );
    assert!(open.verify([10; 32], [8; 32], &proof).is_err());
    assert!(open.verify([7; 32], [10; 32], &proof).is_err());
    let mut changed = open.clone();
    changed.service = [11; 32];
    assert!(changed.verify([7; 32], [8; 32], &proof).is_err());
    changed = open;
    changed.attachment = true;
    changed.voucher.clear();
    assert!(changed.verify([7; 32], [8; 32], &proof).is_err());
}
