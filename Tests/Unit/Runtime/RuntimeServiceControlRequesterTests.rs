// SPDX-License-Identifier: MIT
// Unit tests for RuntimeServiceControl.
use super::*;
#[test]
fn requester_recovery_requires_initialised_stopped_bridge() {
    assert!(requester_scope(7, true, false).is_ok());
    for role in [1, 2, 3, 4, 8] {
        assert!(requester_scope(role, true, false).is_err());
    }
    assert!(requester_scope(7, false, false).is_err());
    assert!(requester_scope(7, true, true).is_err());
}
