// SPDX-License-Identifier: MIT
// Unit tests for RuntimeControl.
use super::*;
#[test]
fn completed_receipts_compact_without_evicting_pending_operation() {
    let mut receipts = std::collections::BTreeMap::new();
    for generation in 1..=200u64 {
        receipts.insert(
            generation.to_string(),
            Receipt {
                request_digest: "digest".into(),
                result: json!({"generation":generation}),
            },
        );
        compact_receipts(&mut receipts, Some("1"));
    }
    assert_eq!(receipts.len(), 64);
    assert!(receipts.contains_key("1"));
    assert!(receipts.contains_key("200"));
    assert!(!receipts.contains_key("136"));
}
