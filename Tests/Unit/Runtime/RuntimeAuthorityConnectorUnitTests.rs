// SPDX-License-Identifier: MIT
// Unit tests for RuntimeAuthorityConnector.
use super::*;

#[test]
fn authority_connector_binding_pins_network_and_rejects_unknown_fields() {
    let mut manifest = crate::authority_deployment_tests::manifest();
    let value = json!({"format":"HyperNetAuthorityConnector/1",
        "network":hex::encode(manifest.network),
        "incarnation":hex::encode(manifest.incarnation),
        "bootstrapDigest":hex::encode(manifest.bootstrap_digest),
        "targetDigest":hex::encode([31;32])});
    let binding: Binding = serde_json::from_value(value.clone()).unwrap();
    binding.check(&manifest).unwrap();
    manifest.bootstrap_digest = [18; 32];
    assert!(binding.check(&manifest).is_err());
    let mut unknown = value.clone();
    unknown["profile"] = json!("/private/profile");
    assert!(serde_json::from_value::<Binding>(unknown).is_err());
    let mut zero = value;
    zero["targetDigest"] = json!(hex::encode([0; 32]));
    assert!(
        serde_json::from_value::<Binding>(zero)
            .unwrap()
            .validate()
            .is_err()
    );
}
