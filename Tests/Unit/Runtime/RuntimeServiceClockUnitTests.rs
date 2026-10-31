// SPDX-License-Identifier: MIT
// Unit tests for RuntimeServiceClock.
use super::*;
use crate::consensus_clock::{Moment, Witness};
use std::{cell::Cell, io::Read, os::unix::net::UnixStream, time::Duration};

#[test]
fn expired_observation_suspends_until_fresh_health_and_unchanged_consent() {
    let boot = "12345678-1234-1234-1234-123456789abc";
    let witness = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    };
    let now = Moment {
        wall_ms: 11000,
        boot_ms: 3000,
    };
    let mut gate = Gate::default();
    let checks = Cell::new(0);
    let local = || {
        checks.set(checks.get() + 1);
        Ok(())
    };
    for _ in 0..2 {
        assert!(
            !gate
                .evaluate(witness.health(boot, now).map(|_| ()), local)
                .unwrap()
        );
    }
    assert_eq!(checks.get(), 2);
    let fresh = Witness {
        sample_wall_ms: 11000,
        sample_boot_ms: 3000,
        valid_until_boot_ms: 4000,
        ..witness
    };
    assert!(
        gate.evaluate(fresh.health(boot, now).map(|_| ()), local)
            .unwrap()
    );
    assert_eq!(checks.get(), 3);
    assert!(!gate.suspended);
}

#[test]
fn withdrawal_configuration_changes_and_other_clock_errors_never_resume() {
    for reason in [
        "consent withdrawn",
        "activation changed",
        "configuration changed",
        "local lifetime expired",
    ] {
        let mut gate = Gate::default();
        assert!(
            gate.evaluate(Err(ObservationExpired.into()), || anyhow::bail!("{reason}"))
                .is_err()
        );
        gate.suspended = true;
        assert!(gate.evaluate(Ok(()), || anyhow::bail!("{reason}")).is_err());
        assert!(gate.suspended);
    }
    for reason in [
        "clock regressed",
        "invalid witness signature",
        "wrong host boot",
    ] {
        let mut gate = Gate { suspended: true };
        assert!(
            gate.evaluate(Err(anyhow::anyhow!("{reason}")), || Ok(()))
                .is_err()
        );
        assert!(gate.suspended);
    }
}

#[test]
fn suspended_private_ingress_discards_queued_requests_without_reading_them() {
    let path = std::env::temp_dir().join(format!("Clock{}.sock", crate::random_hex::<8>()));
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut stream = UnixStream::connect(&path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    discard_waiting(&listener).unwrap();
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    discard_waiting(&listener).unwrap();
    std::fs::remove_file(path).unwrap();
}
