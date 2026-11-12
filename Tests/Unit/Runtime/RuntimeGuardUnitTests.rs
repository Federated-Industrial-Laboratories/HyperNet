// SPDX-License-Identifier: MIT
// Unit tests for RuntimeGuard.
use super::*;
#[test]
fn suspend_and_clock_changes_do_not_extend_deadlines() {
    assert!(expired(100, 101, End::At(200), 200, Some(200)));
    assert!(expired(100, 200, End::At(200), 10, Some(200)));
    assert!(expired(100, 99, End::At(200), 10, Some(200)));
    assert!(!expired(100, 101, End::At(200), 10, Some(200)));
}

#[test]
fn until_withdrawn_has_no_runtime_deadline_but_rejects_clock_rollback() {
    assert!(!expired(
        100,
        10_000_000_000,
        End::UntilWithdrawn,
        10_000_000_000,
        None
    ));
    assert!(expired(100, 99, End::UntilWithdrawn, 10_000_000_000, None));
}
