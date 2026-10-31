// SPDX-License-Identifier: MIT
// Unit tests for ConsensusClock.
use super::*;
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
#[test]
fn decimal_bounds_round_up_and_refuse_unknown_values() {
    assert_eq!(decimal_nanos("-0.0000000001", true).unwrap(), 1);
    assert_eq!(decimal_nanos("0.9999999999", false).unwrap(), 1_000_000_000);
    for value in ["NaN", "inf", "1e-9", "-0.1", "1..0", "18446744073709551615"] {
        assert!(decimal_nanos(value, false).is_err());
    }
}
fn reports() -> (String, String, String, String) {
    let tracking = "C0000201,192.0.2.1,2,1000.000000000,0.001000000,0.001,0.001,0.010,0.001,0.020,0.020,0.001,16.0,Normal\n".into();
    let sources = "^,*,192.0.2.1,1,4,377,0,0.001,0.001,0.001\n".into();
    let auth = "192.0.2.1,NTS,1,15,256,1,0,0,8,100\n".into();
    let mut ntp = vec!["0"; 38];
    ntp[0] = "192.0.2.1";
    ntp[1] = "C0000201";
    ntp[5] = "Normal";
    ntp[6] = "4";
    ntp[7] = "Server";
    ntp[27] = "Yes";
    ntp[33] = "8";
    (tracking, sources, auth, ntp.join(","))
}
#[test]
fn clock_probe_diagnostics_distinguish_duration_and_error_bound() {
    let (t, s, a, n) = reports();
    let before = Moment {
        wall_ms: 1000010,
        boot_ms: 100,
    };
    for (elapsed, code) in [
        (501, ProbeFailure::ProbeDuration),
        (250, ProbeFailure::ErrorBound),
    ] {
        let after = Moment {
            wall_ms: before.wall_ms + elapsed,
            boot_ms: before.boot_ms + elapsed,
        };
        let error = qualify(BOOT, before, after, &t, &t, &s, &s, &a, &n).unwrap_err();
        let diagnostic = error.downcast_ref::<ProbeDiagnostic>().unwrap();
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.elapsed_ms, Some(elapsed));
        assert_eq!(
            diagnostic.maximum_error_ms.is_some(),
            code == ProbeFailure::ErrorBound
        );
    }
}
#[test]
fn clock_probe_diagnostics_identify_query_phase_without_parsing_errors() {
    for (failed, phase) in [
        QueryPhase::FirstTracking,
        QueryPhase::FirstSources,
        QueryPhase::Authentication,
        QueryPhase::NtpData,
        QueryPhase::LastSources,
        QueryPhase::LastTracking,
    ]
    .into_iter()
    .enumerate()
    {
        let mut count = 0;
        let error = probe(|_| {
            if count == failed {
                anyhow::bail!("untrusted dependency output");
            }
            count += 1;
            Ok(String::new())
        })
        .unwrap_err();
        let diagnostic = error.downcast_ref::<ProbeDiagnostic>().unwrap();
        assert_eq!(diagnostic.code, ProbeFailure::ChronyQuery);
        assert_eq!(diagnostic.query_phase, Some(phase));
        assert_eq!(
            diagnostic.query_failure,
            Some(QueryFailureCode::UnknownQueryFailure)
        );
    }
    let error =
        probe(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "private detail").into()))
            .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<ProbeDiagnostic>()
            .unwrap()
            .query_failure,
        Some(QueryFailureCode::TimedOut)
    );
}
#[test]
fn health_requires_matching_authenticated_fresh_observations() {
    let (t, s, a, n) = reports();
    let before = Moment {
        wall_ms: 1000010,
        boot_ms: 100,
    };
    let after = Moment {
        wall_ms: 1000030,
        boot_ms: 120,
    };
    let w = qualify(BOOT, before, after, &t, &t, &s, &s, &a, &n).unwrap();
    assert!(w.maximum_error_ms >= 35);
    assert!(
        w.health(
            BOOT,
            Moment {
                wall_ms: 1001030,
                boot_ms: 1120
            }
        )
        .is_err()
    );
    assert!(
        w.health("22345678-1234-1234-1234-123456789abc", after)
            .is_err()
    );
    assert!(
        w.health(
            BOOT,
            Moment {
                wall_ms: 1001030,
                boot_ms: 121
            }
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s,
            &a,
            &n.replace("Yes", "No")
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s,
            &a.replace("NTS", "-"),
            &n
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t.replace("Normal", "Not synchronised"),
            &s,
            &s,
            &a,
            &n
        )
        .is_err()
    );
    assert!(
        qualify(
            BOOT,
            before,
            after,
            &t,
            &t,
            &s,
            &s.replace("192.0.2.1", "192.0.2.2"),
            &a,
            &n
        )
        .is_err()
    );
}
