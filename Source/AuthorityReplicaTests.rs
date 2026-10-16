// SPDX-License-Identifier: MIT
use super::*;
use crate::consensus::{journal::tests::Directory, runtime::tests as fixtures};
use std::{fs, os::unix::fs::PermissionsExt};

fn installed_manifest() -> Manifest {
    let mut canonical = crate::runtime_manifest::tests::fixture();
    let now = crate::store::now().unwrap();
    canonical.validity = (now * 1000, (now + 3600) * 1000);
    let volume = trust_wire::digest(
        format!("{}/ReplicaState", hex::encode(canonical.deployment)).as_bytes(),
    );
    canonical.volumes[0].volume_id = volume;
    canonical.roles[0].volume_ids = vec![volume];
    canonical.placement.volumes = vec![volume];
    for endpoint in &mut canonical.endpoints {
        endpoint.endpoint_id = trust_wire::digest(
            &trust_wire::encode(&trust_wire::Value::Array(vec![
                trust_wire::Value::Text("AuthorityEndpoint".into()),
                trust_wire::Value::Bytes(endpoint.service_key.to_vec()),
            ]))
            .unwrap(),
        );
    }
    canonical
        .authority_config
        .as_mut()
        .unwrap()
        .ordered_peer_endpoint_ids = canonical.endpoints.iter().map(|e| e.endpoint_id).collect();
    canonical.roles[0].bind_endpoint_ids = vec![canonical.endpoints[0].endpoint_id];
    canonical.endpoints.sort_by_key(|e| e.endpoint_id);
    canonical.roles[0].outbound_endpoint_ids =
        canonical.endpoints.iter().map(|e| e.endpoint_id).collect();
    Manifest::from_canonical(canonical).unwrap()
}
fn write_authorization(root: &Path, manifest: &Manifest) {
    if !root.exists() {
        files::create_directory(root).unwrap();
    }
    let directory = files::directory(root).unwrap();
    let operator = SigningKey::from_bytes(&[2; 32]);
    for (name, bytes) in [
        (
            "Manifest.cbor",
            manifest.canonical().unwrap().encode().unwrap(),
        ),
        ("DesiredProfile.cbor", manifest.desired().unwrap()),
        (
            "Consent.cbor",
            trust_wire::sign_envelope(&manifest.consent(0).unwrap(), &operator).unwrap(),
        ),
        ("Withdrawal.json", b"0".to_vec()),
    ] {
        files::atomic_at(&directory, std::ffi::OsStr::new(name), &bytes, true).unwrap();
    }
}
#[test]
fn installed_manifest_reconstructs_exact_config_and_refuses_unapproved_paths() {
    let manifest = installed_manifest();
    let restored = Manifest::from_canonical(manifest.canonical().unwrap()).unwrap();
    assert_eq!(
        manifest.config_digest().unwrap(),
        restored.config_digest().unwrap()
    );
    let mut altered = manifest.clone();
    altered.config.tls.private_key = "/Private/Other.key".into();
    assert!(altered.desired().is_err());
    altered = manifest.clone();
    altered.config.clock = Source::Private {
        path: "/Clock/Clock.json".into(),
    };
    assert!(altered.desired().is_err());
    altered = manifest;
    altered.config.peers.swap(0, 1);
    assert_ne!(altered.desired().unwrap(), restored.desired().unwrap());
}
#[test]
fn hosting_authorization_refuses_expiry_withdrawal_and_writable_artifacts() {
    let root = Directory::new();
    let directory = root.0.join("Authorization");
    let mut manifest = installed_manifest();
    write_authorization(&directory, &manifest);
    let verify = |manifest: &Manifest| {
        authorization::verify(
            &directory,
            &manifest.config_digest().unwrap(),
            &manifest.signer,
            &manifest.bootstrap_digest,
        )
    };
    verify(&manifest).unwrap();
    let path = directory.join("Withdrawal.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(verify(&manifest).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"1").unwrap();
    assert!(verify(&manifest).is_err());
    manifest.created -= 5;
    manifest.expires = crate::store::now().unwrap() - 1;
    write_authorization(&directory, &manifest);
    assert!(
        verify(&manifest)
            .err()
            .unwrap()
            .to_string()
            .contains("validity interval")
    );
}
#[test]
fn hosting_authorization_binds_exact_signer_bootstrap_and_signed_profile() {
    let root = Directory::new();
    let directory = root.0.join("Authorization");
    let manifest = installed_manifest();
    write_authorization(&directory, &manifest);
    assert!(
        authorization::verify(
            &directory,
            &manifest.config_digest().unwrap(),
            &"01".repeat(32),
            &manifest.bootstrap_digest
        )
        .is_err()
    );
    assert!(
        authorization::verify(
            &directory,
            &manifest.config_digest().unwrap(),
            &manifest.signer,
            &"02".repeat(32)
        )
        .is_err()
    );
    let mut changed = manifest.clone();
    changed.resources.memory_bytes += 1;
    fs::write(
        directory.join("Manifest.cbor"),
        changed.canonical().unwrap().encode().unwrap(),
    )
    .unwrap();
    assert!(
        authorization::verify(
            &directory,
            &manifest.config_digest().unwrap(),
            &manifest.signer,
            &manifest.bootstrap_digest
        )
        .is_err()
    );
}
#[test]
fn signed_clock_refresh_requires_new_exact_consent_without_other_semantic_changes() {
    let manifest = installed_manifest();
    let mut permitted = manifest.clone();
    let Source::Signed { kernel_boot, .. } = &mut permitted.config.clock else {
        unreachable!()
    };
    *kernel_boot = "NewHostBoot".into();
    assert_ne!(permitted.digest().unwrap(), manifest.digest().unwrap());
    let mut changed = permitted.clone();
    changed.resources.pids += 1;
    assert_ne!(changed.digest().unwrap(), permitted.digest().unwrap());
    let canonical = permitted.canonical().unwrap();
    assert_eq!(canonical.clock.kernel_boot, "NewHostBoot");
    assert_eq!(canonical.roles, manifest.canonical().unwrap().roles);
}
#[test]
fn confined_destinations_accept_public_ipv4_ipv6_but_no_dns() {
    let mut keys = [1, 2, 3, 4].map(|seed| SigningKey::from_bytes(&[seed; 32]));
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let mut config = fixtures::config(
        PathBuf::from("/Config/Clock/ClockHealth.cbor"),
        Path::new("/State/Replica"),
        &keys,
    );
    config.peers[0].origin = "https://203.0.113.9:443/".into();
    config.peers[1].origin = "https://[2001:db8::1]:5001/".into();
    let (reads, ports) = confined_inputs(&config).unwrap();
    assert!(ports.contains(&443) && ports.contains(&5001));
    assert!(reads.contains(&PathBuf::from("/Config/Clock")));
    config.peers[0].origin = "https://peer.example:443/".into();
    assert!(confined_inputs(&config).is_err());
}

// Reuse the real journalled committee fixture at its prepared, non-voting boundary.
pub(crate) fn activate_prepared_after_operational_successor(
    original: crate::runtime_manifest::Manifest,
    bootstrap: &[u8],
    evidence: &[u8],
    history: &[u8],
    ready: &[u8],
    engine: &mut Engine,
) {
    let mut successor = original.clone();
    successor.generation += 1;
    successor.previous_profile = Some(trust_wire::digest(&original.desired().unwrap()));
    successor.previous_consent = Some(trust_wire::digest(&original.unsigned_consent(0).unwrap()));
    successor.validity.1 += 10000;
    successor.clock.kernel_boot = "22345678-1234-1234-1234-123456789abc".into();
    successor.successor_of(&original).unwrap();
    let appointed = Manifest::from_canonical(original).unwrap();
    let current = Manifest::from_canonical(successor).unwrap();
    let config = serde_json::to_vec(&current.config).unwrap();
    let mut record = Record {
        format: "HyperNetAuthorityReplica/1".into(),
        bootstrap_digest: digest(bootstrap),
        signer: current.signer.clone(),
        config_generation: 2,
        config_digest: digest(&config),
        config: hex::encode(&config),
        minimum_generation: engine.generation(),
        consent_digest: digest(
            &trust_wire::sign_envelope(
                &current.consent(0).unwrap(),
                &crate::authority_deployment_tests::key(90),
            )
            .unwrap(),
        ),
        authorization: current.clone(),
        preparation: Some(epoch::Preparation {
            chain: vec![],
            evidence: hex::encode(evidence),
            history: hex::encode(history),
        }),
        appointment_authorization: Some(appointed.clone()),
    };
    let (_, terminal) = record
        .preparation
        .as_ref()
        .unwrap()
        .configuration(bootstrap, &record.bootstrap_digest)
        .unwrap();
    assert!(epoch::nomination(&current, &terminal).is_err());
    record.verify_appointment(&terminal).unwrap();
    let floor = engine.generation();
    let signer = engine.signer();
    assert_eq!(record.signer, hex::encode(signer));
    let application = engine.application().to_vec();
    assert!(!engine.can_vote());
    record.authorization.resources.memory_bytes += 1;
    assert!(epoch::activate_ready(&record, bootstrap, ready, engine).is_err());
    record.authorization = current.clone();
    record.appointment_authorization = Some(current.clone());
    assert!(epoch::activate_ready(&record, bootstrap, ready, engine).is_err());
    record.appointment_authorization = Some(appointed);
    assert!(epoch::activate_ready(&record, bootstrap, &ready[..ready.len() - 1], engine).is_err());
    assert!(!engine.can_vote());
    assert_eq!(engine.generation(), floor);
    assert_eq!(engine.application(), application);
    epoch::activate_ready(&record, bootstrap, ready, engine).unwrap();
    assert!(engine.can_vote());
    assert_eq!(engine.signer(), signer);
    assert_eq!(engine.application(), application);
    assert!(engine.generation() > floor);
    let committed = engine.generation();
    epoch::activate_ready(&record, bootstrap, ready, engine).unwrap();
    assert_eq!(engine.generation(), committed);
    assert_eq!(
        record.authorization.digest().unwrap(),
        current.digest().unwrap()
    );
    assert_eq!(record.config_generation, 2);
}
