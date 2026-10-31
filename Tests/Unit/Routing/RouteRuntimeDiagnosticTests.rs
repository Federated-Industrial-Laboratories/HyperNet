// SPDX-License-Identifier: MIT
// Unit tests for RouteRuntime.
use super::*;
#[test]
fn private_route_failure_codes_preserve_typed_causes_without_error_text() {
    for (kind, code) in [
        (
            std::io::ErrorKind::UnexpectedEof,
            FailureCode::UnexpectedEof,
        ),
        (std::io::ErrorKind::TimedOut, FailureCode::Timeout),
        (
            std::io::ErrorKind::ConnectionReset,
            FailureCode::ConnectionReset,
        ),
    ] {
        let error = anyhow::Error::new(std::io::Error::new(kind, "untrusted peer detail"))
            .context(Phase::AttachmentReady);
        assert_eq!(failure_code(&error), code);
        assert_eq!(
            format!("{:?}", error.downcast_ref::<Phase>().unwrap()),
            "AttachmentReady"
        );
        assert!(!format!("{:?}", failure_code(&error)).contains("untrusted"));
    }
    let error = anyhow::Error::new(crate::consensus_clock::ObservationExpired)
        .context(Phase::AdmissionClock);
    assert_eq!(failure_code(&error), FailureCode::ObservationExpired);
    assert_eq!(
        failure_code(&anyhow::anyhow!("private detail")),
        FailureCode::Other
    );
}
