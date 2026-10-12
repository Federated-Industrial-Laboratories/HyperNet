// SPDX-License-Identifier: MIT
//! Local lifecycle contracts without starting a container or contacting a peer.
use super::model::save;
use super::{control, files::*, model::*};
use crate::{authority_clock_handoff::Source, runtime_authorization::Manifest};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Fixture {
    root: PathBuf,
    profile: Profile,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("HyperNetLocalLifecycle{}", random_id()));
        directory(&root).unwrap();
        for name in ["Authorization", "Keys"] {
            directory(&root.join(name)).unwrap();
        }
        fs::set_permissions(
            root.join("Authorization"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let operator = SigningKey::from_bytes(&[2; 32]);
        create(&root.join("Keys/Operator.key"), &operator.to_bytes()).unwrap();
        let mut canonical = crate::runtime_manifest::tests::fixture();
        canonical.validity = (now().unwrap() * 1000, (now().unwrap() + 3600) * 1000);
        canonical.deployment = rand::random();
        canonical.host = canonical.deployment;
        canonical.placement.hosts = vec![canonical.host];
        let volume = crate::trust_wire::digest(
            format!("{}/ReplicaState", hex::encode(canonical.deployment)).as_bytes(),
        );
        canonical.volumes[0].volume_id = volume;
        canonical.roles[0].volume_ids = vec![volume];
        canonical.placement.volumes = vec![volume];
        for endpoint in &mut canonical.endpoints {
            endpoint.endpoint_id = crate::trust_wire::digest(
                &crate::trust_wire::encode(&crate::trust_wire::Value::Array(vec![
                    crate::trust_wire::Value::Text("AuthorityEndpoint".into()),
                    crate::trust_wire::Value::Bytes(endpoint.service_key.to_vec()),
                ]))
                .unwrap(),
            );
        }
        canonical
            .authority_config
            .as_mut()
            .unwrap()
            .ordered_peer_endpoint_ids =
            canonical.endpoints.iter().map(|e| e.endpoint_id).collect();
        canonical.roles[0].bind_endpoint_ids = vec![canonical.endpoints[0].endpoint_id];
        canonical.endpoints.sort_by_key(|e| e.endpoint_id);
        canonical.roles[0].outbound_endpoint_ids =
            canonical.endpoints.iter().map(|e| e.endpoint_id).collect();
        let manifest = Manifest::from_canonical(canonical).unwrap();
        let artifacts = [
            "Keys/Operator.key",
            "Seccomp.json",
            "Work/Config/Bootstrap.cbor",
            "Work/Config/Identity.json",
            "Work/Config/ReplicaConfig.json",
            "Work/Config/Tls/Authority.pem",
            "Work/Config/Tls/Certificate.pem",
            "Work/Config/Tls/PrivateKey.pem",
        ]
        .into_iter()
        .map(|name| (name.into(), hex::encode([26; 32])))
        .collect::<BTreeMap<_, _>>();
        let profile = Profile {
            version: 1,
            purpose: super::model::AuthorityPurpose::Appointed,
            manifest,
            root: root.clone(),
            selinux_relabel: false,
            clock_directory: root.join("Clock"),
            artifacts,
        };
        profile.validate(&root).unwrap();
        super::files::save(&root.join("Profile.json"), &profile).unwrap();
        publish_public(
            &root.join("Authorization/Manifest.cbor"),
            &profile.manifest.canonical().unwrap().encode().unwrap(),
        )
        .unwrap();
        publish_public(
            &root.join("Authorization/DesiredProfile.cbor"),
            &desired(&profile).unwrap(),
        )
        .unwrap();
        publish_public(&root.join("Authorization/Withdrawal.json"), b"0").unwrap();
        super::files::save(&root.join("Generation.json"), &1u64).unwrap();
        super::files::save(&root.join("SignerGeneration.json"), &1u64).unwrap();
        save(&root, &State::new(&profile).unwrap()).unwrap();
        Self { root, profile }
    }
    fn request(&self, operation: Operation) -> Request {
        let (_, state) = load(&self.root).unwrap();
        let floor = if matches!(operation, Operation::Start) {
            Some(1)
        } else {
            None
        };
        Request {
            operation,
            operation_id: Some(hex::encode(rand::random::<[u8; 16]>())),
            expected_generation: Some(state.generation),
            profile_digest: Some(state.profile_digest),
            minimum_signer_generation: floor,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn explicit_consent_binds_exact_appointment_and_offline_withdrawal_survives_stale_state() {
    let f = Fixture::new();
    let (_, state) = load(&f.root).unwrap();
    assert!(verify_consent(&f.root, &f.profile, &state).is_err());
    control::dispatch(&f.root, f.request(Operation::Consent)).unwrap();
    let (_, before) = load(&f.root).unwrap();
    verify_consent(&f.root, &f.profile, &before).unwrap();
    let mut veto = f.request(Operation::Withdraw);
    veto.expected_generation = Some(1);
    control::dispatch(&f.root, veto).unwrap();
    assert_eq!(withdrawal(&f.root).unwrap(), 1);
    // Restoring only the mutable lifecycle record cannot revoke the independent veto.
    super::files::save(&f.root.join("State.json"), &before).unwrap();
    let (_, after) = load(&f.root).unwrap();
    assert_eq!(after.status, "Withdrawn");
    assert_eq!(after.withdrawal_generation, 1);
    assert!(verify_consent(&f.root, &f.profile, &after).is_err());
}
#[test]
fn failed_start_binds_operation_identity_and_retained_signer_floor_never_decreases() {
    let f = Fixture::new();
    let request = f.request(Operation::Start);
    assert!(control::dispatch(&f.root, request.clone()).is_err());
    let retry = control::dispatch(&f.root, request.clone()).unwrap();
    assert_eq!(retry["ok"], false);
    let mut changed = request;
    changed.minimum_signer_generation = Some(2);
    assert!(control::dispatch(&f.root, changed).is_err());
    retain_signer_generation(&f.root, 9).unwrap();
    assert!(retain_signer_generation(&f.root, 8).is_err());
    assert_eq!(signer_generation(&f.root).unwrap(), 9);
}

#[test]
#[ignore = "Requires native rootless Podman; creates and removes one isolated empty network"]
fn withdrawal_retry_releases_exact_network_at_receipt_capacity() {
    struct Network(String);
    impl Drop for Network {
        fn drop(&mut self) {
            let _ = podman(&strings(&["network", "rm", &self.0]));
        }
    }
    let f = Fixture::new();
    control::dispatch(&f.root, f.request(Operation::Consent)).unwrap();
    let (_, mut state) = load(&f.root).unwrap();
    super::containers::network(&f.root, &f.profile, &mut state).unwrap();
    let _network = Network(state.resources[0].id.clone().unwrap());
    let exact_resource = state.resources[0].clone();
    // Retain prior operation identities and use the final reserved withdrawal slot.
    while state.receipts.len() < 121 {
        state.receipts.insert(
            hex::encode(rand::random::<[u8; 16]>()),
            Receipt {
                request_digest: hex::encode([31; 32]),
                result: serde_json::json!({"ok":true}),
            },
        );
    }
    state.resources[0].fingerprint = Some(hex::encode([32; 32]));
    save(&f.root, &state).unwrap();
    let request = f.request(Operation::Withdraw);
    assert!(control::dispatch(&f.root, request.clone()).is_err());
    let (_, failed) = load(&f.root).unwrap();
    assert_eq!(failed.withdrawal_generation, 1);
    assert_eq!(failed.receipts.len(), 122);
    assert_eq!(failed.resources.len(), 1);
    assert!(failed.accepted_consent.is_none());
    assert!(control::dispatch(&f.root, request.clone()).is_err());
    let mut changed = request.clone();
    changed.expected_generation = Some(failed.generation);
    assert!(control::dispatch(&f.root, changed).is_err());

    let (_, mut recovered) = load(&f.root).unwrap();
    recovered.resources[0] = exact_resource.clone();
    save(&f.root, &recovered).unwrap();
    let success = control::dispatch(&f.root, request.clone()).unwrap();
    assert_eq!(success["ok"], true);
    let (_, finished) = load(&f.root).unwrap();
    assert_eq!(finished.status, "Withdrawn");
    assert_eq!(finished.withdrawal_generation, 1);
    assert_eq!(withdrawal(&f.root).unwrap(), 1);
    assert_eq!(finished.receipts.len(), 122);
    assert!(finished.resources.is_empty());
    assert_eq!(signer_generation(&f.root).unwrap(), 1);
    assert!(verify_consent(&f.root, &f.profile, &finished).is_err());
    assert_eq!(
        control::dispatch(&f.root, request.clone()).unwrap(),
        success
    );
    assert!(control::dispatch(&f.root, f.request(Operation::Start)).is_err());

    // Recover a crash after network removal but before the final journal update.
    let mut interrupted = finished;
    interrupted.resources.push(exact_resource);
    interrupted.pending = request.operation_id.clone();
    interrupted
        .receipts
        .get_mut(request.operation_id.as_ref().unwrap())
        .unwrap()
        .result = serde_json::json!({"ok":false,"failureCode":"InterruptedOperation"});
    save(&f.root, &interrupted).unwrap();
    assert_eq!(control::dispatch(&f.root, request).unwrap()["ok"], true);
    let (_, final_state) = load(&f.root).unwrap();
    assert!(final_state.resources.is_empty());
    assert!(final_state.pending.is_none());
    assert_eq!(final_state.receipts.len(), 122);
    assert_eq!(final_state.withdrawal_generation, 1);
}
#[test]
fn installed_profile_refuses_hidden_mounts_unsigned_clock_and_non_ipv4_peers() {
    let f = Fixture::new();
    let mut altered = f.profile.clone();
    altered.manifest.config.tls.private_key = "/Private/Another.key".into();
    assert!(altered.validate(&f.root).is_err());
    altered = f.profile.clone();
    altered.manifest.config.clock = Source::Private {
        path: "/Clock/ClockHealth.json".into(),
    };
    assert!(altered.validate(&f.root).is_err());
    altered = f.profile.clone();
    altered.manifest.config.peers[0].origin = "https://[2001:db8::1]:24443".into();
    assert!(altered.validate(&f.root).is_err());
    altered = f.profile.clone();
    altered
        .artifacts
        .insert("Work/Config/Unexpected".into(), hex::encode([27; 32]));
    assert!(altered.validate(&f.root).is_err());
}
