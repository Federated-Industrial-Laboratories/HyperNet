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

#[test]
fn permanent_permission_keeps_a_finite_certificate_wall_and_boot_deadline() {
    let permission = End::UntilWithdrawn;
    let (end, deadline) = serving_lifetime(permission, Some(200), 100, 50).unwrap();
    assert_eq!(permission, End::UntilWithdrawn);
    assert_eq!(end, End::At(200));
    assert_eq!(deadline, Some(150));
    assert!(expired(100, 200, end, 51, deadline));
    assert!(expired(100, 101, end, 150, deadline));
    assert_eq!(
        serving_lifetime(permission, None, 100, 50).unwrap(),
        (permission, None)
    );
    assert_eq!(
        serving_lifetime(End::At(180), Some(200), 100, 50).unwrap(),
        (End::At(180), Some(130))
    );
    assert!(serving_lifetime(permission, Some(100), 100, 50).is_err());
}
