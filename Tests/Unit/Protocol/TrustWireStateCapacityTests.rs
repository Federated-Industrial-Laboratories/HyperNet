// SPDX-License-Identifier: MIT
// Unit tests for TrustWire.
use super::*;
#[test]
fn retained_state_bound_does_not_expand_wire_ingress() {
    let value = Value::Array(vec![Value::Bytes(vec![7; MAXIMUM + 1])]);
    assert!(encode(&value).is_err());
    let bytes = encode_state(&value).unwrap();
    assert!(decode(&bytes).is_err());
    assert_eq!(decode_state(&bytes).unwrap(), value);
    assert!(decode_state(&vec![0; crate::authority_capacity::MAX_STATE_BYTES + 1]).is_err());
    assert!(
        encode_state(&Value::Bytes(
            vec![0; crate::authority_capacity::MAX_STATE_BYTES]
        ))
        .is_err()
    );
}
