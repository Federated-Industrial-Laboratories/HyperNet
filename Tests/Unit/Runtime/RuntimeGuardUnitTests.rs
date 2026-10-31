// SPDX-License-Identifier: MIT
// Unit tests for RuntimeGuard.
use super::*;
#[test]
fn suspend_and_clock_changes_do_not_extend_deadlines() {
    assert!(expired(100, 101, 200, 200, 200));
    assert!(expired(100, 200, 200, 10, 200));
    assert!(expired(100, 99, 200, 10, 200));
    assert!(!expired(100, 101, 200, 10, 200));
}
