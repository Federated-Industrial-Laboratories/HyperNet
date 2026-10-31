// SPDX-License-Identifier: MIT
// Unit tests for AuthorityApplications.
use super::*;
#[test]
fn published_dual_consent_vector_binds_exact_predecessor_and_parties() {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Documentation/ApplicationRenewalVector.json"
    )))
    .unwrap();
    let bytes = |name: &str| hex::decode(value[name].as_str().unwrap()).unwrap();
    let network: Digest = bytes("network").try_into().unwrap();
    let incarnation: Digest = bytes("incarnation").try_into().unwrap();
    let previous = Registration::parse(&bytes("previousAdmission"), network, incarnation).unwrap();
    let envelope = bytes("renewalConsent");
    let renewal = Renewal::parse(&envelope, network, incarnation, true).unwrap();
    assert_eq!(renewal.admission, previous.reference);
    assert_eq!(renewal.owner, previous.owner);
    assert_eq!(renewal.grant, previous.grant);
    assert!(Renewal::parse(&envelope, network, incarnation, false).is_err());
    assert!(Renewal::parse(&envelope, [9; 32], incarnation, true).is_err());
    let mut changed = envelope;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(Renewal::parse(&changed, network, incarnation, true).is_err());
}
