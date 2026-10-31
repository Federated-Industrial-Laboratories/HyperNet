// SPDX-License-Identifier: MIT
// Unit tests for SshService.
use super::*;
#[test]
fn deadline_subprocess() {
    if std::env::var_os("HYPERNET_SSH_DEADLINE_TEST").is_none() {
        return;
    }
    let timer = Deadline::new().unwrap();
    timer
        .arm(crate::authority_challenge::boot_time_ms().unwrap() + 150)
        .unwrap();
    // Simulate a blocked supervisor; no userspace polling enforces this deadline.
    std::thread::sleep(Duration::from_secs(2));
    panic!("kernel SSH deadline did not terminate the supervisor");
}
#[test]
fn kernel_deadline_stops_a_blocked_supervisor() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["ssh_service::tests::deadline_subprocess", "--exact"])
        .env("HYPERNET_SSH_DEADLINE_TEST", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(124));
    let timer = Deadline::new().unwrap();
    assert!(
        timer
            .arm(crate::authority_challenge::boot_time_ms().unwrap())
            .is_err()
    );
}
