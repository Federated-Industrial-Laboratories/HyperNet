// SPDX-License-Identifier: MIT
// Clock suspension preserves the original consent deadline and refuses changed local authorization.
use super::*;
use crate::consensus::journal::tests::Directory;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::PermissionsExt;

#[test]
fn service_clock_recovery_retains_deadline_and_rejects_changed_consent() {
    let directory = Directory::new();
    let key = SigningKey::from_bytes(&[73; 32]);
    let operator = key.verifying_key().to_bytes();
    let local = wire::encode(&V::Text("Exact local consent".into())).unwrap();
    let host = wire::encode(&V::Text("Exact host consent".into())).unwrap();
    let signed_local = wire::sign_envelope(&local, &key).unwrap();
    let signed_host = wire::sign_envelope(&host, &key).unwrap();
    for (name, bytes) in [
        ("Withdrawal.json", b"0".as_slice()),
        ("Generation.json", b"7".as_slice()),
        ("LocalConsent.cbor", signed_local.as_slice()),
        ("HostConsent.cbor", signed_host.as_slice()),
    ] {
        let path = directory.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let check = |now| {
        verify_local(
            &directory.0,
            operator,
            7,
            wire::digest(&local),
            wire::digest(&host),
            2000,
            now,
        )
    };
    check(1999).unwrap();
    assert!(check(2000).is_err());
    for (name, original, replacement) in [
        ("Withdrawal.json", b"0".to_vec(), b"1".to_vec()),
        ("Generation.json", b"7".to_vec(), b"8".to_vec()),
        (
            "LocalConsent.cbor",
            signed_local.clone(),
            signed_host.clone(),
        ),
        (
            "HostConsent.cbor",
            signed_host.clone(),
            signed_local.clone(),
        ),
    ] {
        std::fs::write(directory.0.join(name), replacement).unwrap();
        let error = check(1999).unwrap_err();
        assert!(!error.is::<crate::consensus_clock::ObservationExpired>());
        std::fs::write(directory.0.join(name), original).unwrap();
    }
    check(1999).unwrap();
}

#[test]
fn service_clock_recovery_refuses_changed_configuration() {
    let directory = Directory::new();
    let path = directory.0.join("ServiceConfig.json");
    std::fs::write(&path, b"Original").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let artifacts = BTreeMap::from([("ServiceConfig.json".into(), wire::digest(b"Original"))]);
    verify_artifacts(&directory.0, &artifacts).unwrap();
    std::fs::write(&path, b"Changed").unwrap();
    assert!(verify_artifacts(&directory.0, &artifacts).is_err());
    std::fs::write(&path, b"Original").unwrap();
    std::fs::write(directory.0.join("Unconsented.json"), b"Extra").unwrap();
    assert!(verify_artifacts(&directory.0, &artifacts).is_err());
}
