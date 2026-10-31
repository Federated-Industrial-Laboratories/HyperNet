// SPDX-License-Identifier: MIT
// Unit tests for TrustSummary.
use super::*;

fn scope_value(kinds: &[u64]) -> Value {
    Value::Array(
        kinds
            .iter()
            .map(|kind| Value::Array(vec![Value::Uint(*kind), Value::Bytes(vec![1; 32])]))
            .collect(),
    )
}

#[test]
fn action_names_follow_the_terminal_scope_purpose() {
    let codes = Value::Array(vec![Value::Uint(29), Value::Uint(30)]);
    let service = actions(&codes, &scope_value(&[3])).unwrap();
    assert_eq!(service[0].name, "ManageApplicationService");
    assert_eq!(service[1].name, "ConnectApplicationService");
    assert!(
        service[0]
            .scope_requirement
            .unwrap()
            .contains("only Service")
    );
    let sealed = actions(&codes, &scope_value(&[1, 2])).unwrap();
    assert_eq!(sealed[0].name, "ReviewSealedPage");
    assert_eq!(sealed[1].name, "FinaliseSealedPage");
    assert!(
        sealed[0]
            .scope_requirement
            .unwrap()
            .contains("Object or Namespace")
    );
}

#[test]
fn broad_and_mixed_action_names_explain_both_uses_and_refusal() {
    let codes = Value::Array(vec![Value::Uint(29), Value::Uint(30)]);
    for kinds in [&[][..], &[0][..], &[0, 3][..], &[2, 3][..], &[4][..]] {
        let described = actions(&codes, &scope_value(kinds)).unwrap();
        assert_eq!(
            described[0].name,
            "ReviewSealedPageOrManageApplicationService"
        );
        assert_eq!(
            described[1].name,
            "FinaliseSealedPageOrConnectApplicationService"
        );
        for action in &described {
            assert!(
                action
                    .scope_requirement
                    .unwrap()
                    .contains("terminal scopes are refused")
            );
        }
    }
    let ordinary = actions(&Value::Array(vec![Value::Uint(9)]), &scope_value(&[0])).unwrap();
    assert_eq!(
        serde_json::to_value(&ordinary).unwrap(),
        serde_json::json!([{"code":9,"name":"AdministerPolicy"}])
    );
}
