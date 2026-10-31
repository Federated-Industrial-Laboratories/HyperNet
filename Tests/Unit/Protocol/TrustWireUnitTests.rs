// SPDX-License-Identifier: MIT
// Unit tests for TrustWire.
use super::*;
#[test]
fn normative_encoding_and_signatures() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Documentation/WireVectors.json"
    )))
    .unwrap();
    for case in vectors["canonical"].as_array().unwrap() {
        let bytes = hex::decode(case["wireHex"].as_str().unwrap()).unwrap();
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
    }
    for case in vectors["invalidEncoding"].as_array().unwrap() {
        let bytes = hex::decode(case["wireHex"].as_str().unwrap()).unwrap();
        assert!(decode(&bytes).is_err(), "{}", case["id"]);
    }
    let bytes = hex::decode(vectors["vote"]["wireHex"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(digest(&bytes)), vectors["vote"]["recordDigest"]);
    let key = SigningKey::from_bytes(&[7; 32]);
    let signed = sign_envelope(&bytes, &key).unwrap();
    assert_eq!(envelope(&signed, 1).unwrap().0, bytes);
    let mut altered = signed;
    let end = altered.len() - 1;
    altered[end] ^= 1;
    assert!(envelope(&altered, 1).is_err());
}
