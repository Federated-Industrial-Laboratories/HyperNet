// SPDX-License-Identifier: MIT
// Successor consent uses RecordDigest and historical repair accepts only exact staged inputs.
use super::*;
use crate::consensus::journal::tests::Directory;
use ed25519_dalek::SigningKey;

fn fixture() -> (Directory, Transaction) {
    let directory = Directory::new();
    let root = &directory.0;
    files::directory(&root.join("TransitionFiles")).unwrap();
    let key = SigningKey::from_bytes(&[2; 32]);
    files::create(&root.join("Operator.key"), &key.to_bytes()).unwrap();
    let mut previous = crate::runtime_manifest::tests::fixture();
    previous.roles[0].role = 1;
    previous.roles[0].bind_endpoint_ids.clear();
    previous.roles[0].outbound_endpoint_ids.clear();
    previous.endpoints.clear();
    previous.authority_config = None;
    previous.validate().unwrap();
    let mut successor = previous.clone();
    successor.generation = 2;
    successor.previous_profile = Some(wire::digest(&previous.desired().unwrap()));
    successor.previous_consent = Some(wire::digest(&previous.unsigned_consent(0).unwrap()));
    successor.successor_of(&previous).unwrap();
    let bytes = successor.encode().unwrap();
    let mut replacements = BTreeMap::new();
    stage(
        root,
        &mut replacements,
        "Config/Manifest.cbor",
        &bytes,
        false,
        Some("Config/Manifest.cbor"),
    )
    .unwrap();
    let mut artifacts = [
        "Bootstrap.cbor",
        "Manifest.cbor",
        "PageProfile.cbor",
        "Seccomp.json",
        "Service.key",
        "ServiceConfig.json",
    ]
    .into_iter()
    .map(|name| (name.to_string(), wire::digest(name.as_bytes())))
    .collect::<BTreeMap<_, _>>();
    artifacts.insert(
        "Manifest.cbor".into(),
        crate::trust_bootstrap::hex32(&files::hex_digest(&bytes)).unwrap(),
    );
    let profile: services::Profile = serde_json::from_value(json!({
        "version":1, "root":root, "manifest":successor, "artifacts":artifacts,
        "authorityControl":root.join("Authority/Launch/State/Control"),
        "clockDirectory":root.join("Clock"), "selinux":false, "mediaControls":{}, "routeTarget":null
    }))
    .unwrap();
    profile.validate().unwrap();
    let local =
        crate::runtime_service_authorization::local_consent(&successor, 1, 2, &artifacts).unwrap();
    stage(
        root,
        &mut replacements,
        "Authorization/LocalConsent.cbor",
        &wire::sign_envelope(&local, &key).unwrap(),
        true,
        None,
    )
    .unwrap();
    let proposal = Proposal {
        root: root.clone(),
        service: true,
        predecessor: hex::encode([13; 32]),
        previous,
        successor,
        executable: root.join("Bin/HyperNet"),
        package: None,
        bindings: None,
        transport: None,
    };
    let transaction = Transaction {
        operation: hex::encode([11; 16]),
        digest: files::hex_digest(&serde_json::to_vec(&proposal).unwrap()),
        proposal,
        replacements,
        authority: None,
        service: Some(profile),
        launch_identity: None,
        initialised: true,
        lifecycle_generation: 2,
        completed: false,
    };
    files::save(&root.join("Transition.json"), &transaction).unwrap();
    (directory, transaction)
}

#[test]
fn service_successor_uses_record_digest_of_verified_staged_configuration() {
    let directory = Directory::new();
    files::directory(&directory.0.join("TransitionFiles")).unwrap();
    let mut replacements = BTreeMap::new();
    for (name, bytes) in [
        ("Config/Manifest.cbor", b"Manifest".as_slice()),
        ("Config/Egress.json", b"Egress"),
    ] {
        stage(&directory.0, &mut replacements, name, bytes, false, None).unwrap();
    }
    let artifacts = configuration(&directory.0, &replacements).unwrap();
    assert_eq!(artifacts["Manifest.cbor"], wire::digest(b"Manifest"));
    assert_eq!(artifacts["Egress.json"], wire::digest(b"Egress"));
    let replacement = &replacements["Config/Manifest.cbor"];
    assert_ne!(hex::encode(artifacts["Manifest.cbor"]), replacement.digest);
    std::fs::write(
        directory
            .0
            .join("TransitionFiles")
            .join(&replacement.digest),
        b"Changed",
    )
    .unwrap();
    assert!(configuration(&directory.0, &replacements).is_err());
}

#[test]
fn historical_service_recovery_repairs_only_local_artifact_binding_and_is_repeatable() {
    let (directory, mut t) = fixture();
    let proposal = serde_json::to_vec(&t.proposal).unwrap();
    let operation = t.operation.clone();
    let prior = t.service.as_ref().unwrap().artifacts.clone();
    recover(&mut t).unwrap();
    let p = t.service.as_ref().unwrap();
    assert_eq!(serde_json::to_vec(&t.proposal).unwrap(), proposal);
    assert_eq!(t.operation, operation);
    assert_eq!(
        p.artifacts["Manifest.cbor"],
        wire::digest(&t.proposal.successor.encode().unwrap())
    );
    for (name, digest) in prior {
        if name != "Manifest.cbor" {
            assert_eq!(p.artifacts[&name], digest);
        }
    }
    let local = &t.replacements["Authorization/LocalConsent.cbor"];
    let (payload, signatures) = wire::envelope(&read(&directory.0, local).unwrap(), 1).unwrap();
    assert_eq!(signatures[0].0, t.proposal.successor.operator);
    assert_eq!(
        payload,
        crate::runtime_service_authorization::local_consent(&p.manifest, 1, 2, &p.artifacts)
            .unwrap()
    );
    let retained = files::read(&directory.0.join("Transition.json"), files::MAXIMUM).unwrap();
    let mut resumed: Transaction = serde_json::from_slice(&retained).unwrap();
    recover(&mut resumed).unwrap();
    assert_eq!(
        files::read(&directory.0.join("Transition.json"), files::MAXIMUM).unwrap(),
        retained
    );
}

#[test]
fn historical_service_recovery_rejects_changed_objects_bindings_and_consent() {
    for case in 0..3 {
        let (directory, mut t) = fixture();
        match case {
            0 => {
                let replacement = &t.replacements["Config/Manifest.cbor"];
                std::fs::write(
                    directory
                        .0
                        .join("TransitionFiles")
                        .join(&replacement.digest),
                    b"Changed",
                )
                .unwrap();
            }
            1 => {
                t.service
                    .as_mut()
                    .unwrap()
                    .artifacts
                    .insert("Manifest.cbor".into(), [99; 32]);
            }
            _ => {
                let replacement = &t.replacements["Authorization/LocalConsent.cbor"];
                let (payload, _) =
                    wire::envelope(&read(&directory.0, replacement).unwrap(), 1).unwrap();
                stage(
                    &directory.0,
                    &mut t.replacements,
                    "Authorization/LocalConsent.cbor",
                    &wire::sign_envelope(&payload, &SigningKey::from_bytes(&[7; 32])).unwrap(),
                    true,
                    None,
                )
                .unwrap();
            }
        }
        let before = files::read(&directory.0.join("Transition.json"), files::MAXIMUM).unwrap();
        assert!(recover(&mut t).is_err());
        assert_eq!(
            files::read(&directory.0.join("Transition.json"), files::MAXIMUM).unwrap(),
            before
        );
    }
}

#[test]
fn certificate_bundle_stages_only_exact_public_tls_files_and_rejects_mixed_identity() {
    use crate::runtime_manifest::certificates as tls;
    let crypto = tls::tests::fixture();
    let directory = Directory::new();
    let root = &directory.0;
    for relative in ["TransitionFiles", "Work", "Work/Config", "Work/Config/Tls"] {
        files::directory(&root.join(relative)).unwrap();
    }
    files::create(
        &root.join("Work/Config/Tls/Authority.pem"),
        crypto.issuer.as_bytes(),
    )
    .unwrap();
    let bundle = json!({"format":"HyperNetTransportCertificates/1", "issuerPem":crypto.next_issuer,
        "certificates":crypto.renewed.endpoints.iter().map(|e| json!({"endpoint":hex::encode(e.endpoint_id),
            "serviceKey":hex::encode(e.service_key), "transportKey":hex::encode(e.transport_key),
            "certificatePem":tls::pem(&e.leaf_der).unwrap()})).collect::<Vec<_>>()});
    let path = root.join("Bundle.json");
    files::save(&path, &bundle).unwrap();
    let mut successor = crypto.renewed.clone();
    let selection =
        certificates::prepare(root, false, &crypto.original, &mut successor, Some(&path))
            .unwrap()
            .unwrap();
    assert_eq!(successor, crypto.renewed);
    let mut proposal = Proposal {
        root: root.clone(),
        service: false,
        predecessor: hex::encode([12; 32]),
        previous: crypto.original.clone(),
        successor,
        executable: root.join("HyperNet"),
        package: None,
        bindings: None,
        transport: Some(selection),
    };
    let (_, deadline) = proposal.successor.transport_interval().unwrap().unwrap();
    assert!(certificates::historical_at(&proposal, deadline - 1).is_err());
    certificates::historical_at(&proposal, deadline).unwrap();
    let mut no_transport = proposal.clone();
    no_transport.transport = None;
    assert!(certificates::historical_at(&no_transport, deadline).is_err());
    let mut future = proposal.clone();
    future.successor.validity.0 = deadline + 1;
    assert!(certificates::historical_at(&future, deadline).is_err());
    let mut replacements = BTreeMap::new();
    certificates::stage_files(root, &proposal, &mut replacements, true).unwrap();
    assert_eq!(replacements.len(), 2);
    assert_eq!(
        read(root, &replacements["Work/Config/Tls/Authority.pem"]).unwrap(),
        crypto.next_issuer.as_bytes()
    );
    assert_eq!(
        read(root, &replacements["Work/Config/Tls/Certificate.pem"]).unwrap(),
        tls::pem(&crypto.renewed.endpoints[0].leaf_der)
            .unwrap()
            .as_bytes()
    );
    assert!(!replacements.keys().any(|name| name.contains("Private")));
    // Exact retained JSON can be resumed; later input-file edits cannot alter the reviewed proposal.
    let retained = serde_json::to_vec(&proposal).unwrap();
    let restored: Proposal = serde_json::from_slice(&retained).unwrap();
    certificates::validate(
        &restored.previous,
        &restored.successor,
        restored.transport.as_ref().unwrap(),
        false,
    )
    .unwrap();
    let mut mixed = bundle;
    mixed["certificates"][0]["transportKey"] = json!(hex::encode([222; 32]));
    files::save(&path, &mixed).unwrap();
    let mut changed = crypto.renewed.clone();
    assert!(
        certificates::prepare(root, false, &crypto.original, &mut changed, Some(&path)).is_err()
    );
    proposal.previous.endpoints[0].leaf_der = crypto.renewed.endpoints[0].leaf_der.clone();
    assert!(
        certificates::validate(
            &proposal.previous,
            &proposal.successor,
            proposal.transport.as_ref().unwrap(),
            false
        )
        .is_err()
    );
    let selected = &replacements["Work/Config/Tls/Certificate.pem"];
    std::fs::write(
        root.join("TransitionFiles").join(&selected.digest),
        b"mixed staged certificate",
    )
    .unwrap();
    assert!(read(root, selected).is_err());
}
