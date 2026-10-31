// SPDX-License-Identifier: MIT
// Clock suspension preserves the original consent deadline and refuses changed local authorization.
use super::*;
use crate::consensus::journal::tests::Directory;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::PermissionsExt;

#[test]
fn application_check_short_wait_and_clock_sample_preserve_fresh_challenge_geometry() {
    use crate::authority_challenge::{ClockHealth, Session};
    use crate::authority_proof::{Challenge, Scope};
    use crate::authority_read::{Query, Request};
    let signer = SigningKey::from_bytes(&[73; 32]);
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 1,
    };
    let request = Request::sign(
        &scope,
        &signer,
        signer.verifying_key().to_bytes(),
        [4; 32],
        1,
        Query::PolicyContext,
    )
    .unwrap();
    let clock = ApplicationClock {
        kernel_boot: "host".into(),
        consent_deadline: 20000,
        observation_deadline: 11000,
    };
    let sample = ClockHealth::new(1000000, 10000, 11000, 1).unwrap().frozen();
    for wait in [100, 1000, 5000] {
        let caller_deadline = 10000 + wait;
        let transport_deadline = clock.read_deadline(caller_deadline);
        assert_eq!(transport_deadline, caller_deadline);
        let signed = Session::new()
            .unwrap()
            .issue_read(&request, &signer, [4; 32], 5000, Some(15000), sample)
            .unwrap();
        let challenge = Challenge::from_signed(&signed).unwrap();
        assert_eq!(challenge.maximum_duration_ms, 5000);
        assert!(
            challenge
                .evaluation_expiry(1000010, challenge.expires_at_ms)
                .is_ok()
        );
        assert_eq!(
            clock.receipt_deadline(transport_deadline),
            caller_deadline.min(11000)
        );
    }
    // Capping the challenge to a one-second clock sample cannot satisfy the
    // existing +/-1250ms evaluation uncertainty, even with an instant network.
    let signed = Session::new()
        .unwrap()
        .issue_read(&request, &signer, [4; 32], 5000, Some(11000), sample)
        .unwrap();
    let clipped = Challenge::from_signed(&signed).unwrap();
    assert!(
        clipped
            .evaluation_expiry(1000010, clipped.expires_at_ms)
            .is_err()
    );
    // A later valid observation may replace the clock sample, never the caller
    // deadline, local consent lifetime, or original start+5000 challenge ceiling.
    let refreshed = ApplicationClock {
        kernel_boot: "host".into(),
        consent_deadline: 14000,
        observation_deadline: 13000,
    };
    assert_eq!(refreshed.read_deadline(15000), 14000);
    assert_eq!(refreshed.receipt_deadline(15000), 13000);
    assert_eq!(refreshed.receipt_deadline(11000), 11000);
    let later = ClockHealth::new(1000900, 10900, 11900, 1).unwrap().frozen();
    let signed = Session::new()
        .unwrap()
        .issue_read(&request, &signer, [4; 32], 5000, Some(15000), later)
        .unwrap();
    let queued = Challenge::from_signed(&signed).unwrap();
    assert_eq!(queued.maximum_duration_ms, 4100);
    assert_eq!(queued.expires_at_ms, 1005000);
    let expired = ClockHealth::new(1005000, 15000, 16000, 1).unwrap().frozen();
    assert!(
        Session::new()
            .unwrap()
            .issue_read(&request, &signer, [4; 32], 5000, Some(15000), expired)
            .unwrap_err()
            .is::<crate::authority_challenge::ChallengeExpired>()
    );
}

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
