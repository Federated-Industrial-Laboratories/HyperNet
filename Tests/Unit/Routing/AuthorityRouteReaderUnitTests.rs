// SPDX-License-Identifier: MIT
// Unit tests for AuthorityRouteReader.
use super::*;
#[test]
fn signed_reader_route_never_accepts_operator_bridge_commands() {
    let signer = SigningKey::from_bytes(&[9; 32]);
    let grant = VersionRef {
        kind: 102,
        id: [8; 32],
        generation: 1,
        digest: [7; 32],
    };
    for name in ["BridgeSync", "BridgeActivate", "BridgeWithdraw"] {
        let packet = wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text(name.into()),
            V::Bytes(vec![1; 32]),
            V::Null,
        ]))
        .unwrap();
        assert!(
            sign(
                [1; 32], [2; 32], [3; 32], &grant, 0, 5000, [4; 32], &packet, &signer
            )
            .is_err()
        );
    }
}
