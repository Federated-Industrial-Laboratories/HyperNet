// SPDX-License-Identifier: MIT
// Bridge control mounts bind a selected local content/media role and exact network identity.
use super::*;
#[test]
fn bridge_store_routes_accept_role_one_without_weakening_identity_scope() {
    let base = crate::authority_deployment_tests::manifest();
    let mut bridge = base.clone();
    bridge.roles.retain(|role| role.role == 7);
    for role in [1, 2] {
        let mut store = base.clone();
        store.roles.retain(|value| value.role == role);
        let key = store.roles[0].service_key;
        store_route(&bridge, &store, key).unwrap();
        assert!(store_route(&bridge, &store, [7; 32]).is_err());
        store.network[0] ^= 1;
        assert!(store_route(&bridge, &store, key).is_err());
        store.network = base.network;
        store.incarnation[0] ^= 1;
        assert!(store_route(&bridge, &store, key).is_err());
    }
    let mut other = base;
    other.roles.retain(|role| role.role == 3);
    assert!(store_route(&bridge, &other, other.roles[0].service_key).is_err());
}
