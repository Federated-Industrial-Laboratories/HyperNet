// SPDX-License-Identifier: MIT
// Unit tests for AuthorityClockMonitor.
use super::*;
#[test]
fn clock_monitor_diagnostics_omit_dependency_error_details() {
    let error = anyhow::anyhow!("private dependency path and untrusted report")
        .context(MonitorFailure::PrivatePublish);
    let value = observation_status(&Err(error), Some(42));
    assert_eq!(value["reason"], "PrivatePublish");
    assert_eq!(value["bootMs"], 42);
    assert!(!value.to_string().contains("dependency"));
    let unknown = observation_status(&Err(anyhow::anyhow!("sensitive")), None);
    assert_eq!(unknown["reason"], "Unclassified");
    assert!(!unknown.to_string().contains("sensitive"));
}
