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
