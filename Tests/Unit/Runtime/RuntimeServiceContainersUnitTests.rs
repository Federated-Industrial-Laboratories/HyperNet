// SPDX-License-Identifier: MIT
// Unit tests for RuntimeServiceContainers.
use super::*;
#[test]
fn private_route_descriptor_budget_covers_all_pools_and_destinations() {
    for connections in [1, 8, 128, 4096] {
        let inbound = 3 * connections;
        let destinations = connections;
        assert_eq!(
            route_descriptors(connections).unwrap(),
            inbound + destinations + 64
        );
    }
    assert_eq!(route_descriptors(128).unwrap(), 576);
    assert!(route_descriptors(0).is_err());
    assert!(route_descriptors(4097).is_err());
    assert!(route_descriptors(u64::MAX).is_err());
}
