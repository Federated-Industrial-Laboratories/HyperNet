// SPDX-License-Identifier: MIT
use super::*;
use ed25519_dalek::SigningKey;
use std::{fs, process::Command, sync::OnceLock};

pub(crate) fn fixture() -> Manifest {
    static FIXTURE: OnceLock<Manifest> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let public = |seed| {
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes()
            };
            let root = std::env::temp_dir().join(format!(
                "HyperNetManifest{}",
                hex::encode(rand::random::<[u8; 16]>())
            ));
            fs::create_dir(&root).unwrap();
            let mut endpoints = Vec::new();
            for i in 0..4 {
                let result = Command::new("openssl")
                    .args(["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout"])
                    .arg(root.join("Key.pem"))
                    .args(["-out"])
                    .arg(root.join("Leaf.der"))
                    .args([
                        "-outform",
                        "DER",
                        "-days",
                        "1",
                        "-subj",
                        "/CN=HyperNetManifestTest",
                    ])
                    .output()
                    .unwrap();
                assert!(result.status.success());
                let leaf_der = fs::read(root.join("Leaf.der")).unwrap();
                endpoints.push(Endpoint {
                    endpoint_id: [30 + i; 32],
                    service_key: public(3 + i),
                    address: Ipv4Addr::new(192, 0, 2, i + 1).into(),
                    port: 24443,
                    transport_key: leaf_key(&leaf_der).unwrap(),
                    leaf_der,
                });
            }
            fs::remove_dir_all(root).unwrap();
            let volume = [40; 32];
            Manifest {
                generation: 1,
                previous_profile: None,
                previous_consent: None,
                network: [20; 32],
                incarnation: [21; 32],
                deployment: [22; 32],
                host: [22; 32],
                operator: public(2),
                bootstrap_digest: [23; 32],
                software_digest: [24; 32],
                validity: (1000, 3601000),
                session_mode: 0,
                roles: vec![Role {
                    role: 0,
                    service_key: public(3),
                    image_digest: [25; 32],
                    memory_bytes: 536870912,
                    pids: 64,
                    cpu_quota: 100000,
                    cpu_period: 100000,
                    state_admission_bytes: 1073741824,
                    bind_endpoint_ids: vec![[30; 32]],
                    outbound_endpoint_ids: endpoints.iter().map(|e| e.endpoint_id).collect(),
                    volume_ids: vec![volume],
                }],
                volumes: vec![Volume {
                    volume_id: volume,
                    read_only: false,
                    storage_admission_bytes: 1073741824,
                }],
                authority_config: Some(AuthorityConfig {
                    listen_address: Ipv4Addr::UNSPECIFIED.into(),
                    listen_port: 24443,
                    ordered_peer_endpoint_ids: endpoints.iter().map(|e| e.endpoint_id).collect(),
                    tls_file_digests: [[26; 32], [27; 32], [28; 32]],
                    subnet_address: Ipv4Addr::new(10, 89, 132, 0).into(),
                    subnet_prefix: 24,
                }),
                endpoints,
                clock: Clock {
                    monitor_key: public(7),
                    kernel_boot: "12345678-1234-1234-1234-123456789abc".into(),
                    witness_file_name: "ClockHealth.cbor".into(),
                    maximum_error_ms: 250,
                    maximum_observation_age_ms: 1000,
                },
                placement: Placement {
                    hosts: vec![[22; 32]],
                    volumes: vec![volume],
                    backups: vec![],
                    copies: 1,
                },
                limits: [268435456, 20480, 16, 32],
                consent_policy: ConsentPolicy {
                    allow_opaque: false,
                    reviewer_roots: vec![],
                },
            }
        })
        .clone()
}
#[test]
fn canonical_consent_binds_owned_exposure_and_every_resource() {
    let manifest = fixture();
    let encoded = manifest.encode().unwrap();
    assert_eq!(Manifest::parse(&encoded).unwrap(), manifest);
    let desired = wire::decode(&manifest.desired().unwrap()).unwrap();
    let desired = desired.array(16).unwrap();
    assert_eq!(desired[14].fixed::<32>().unwrap(), wire::digest(&encoded));
    assert_eq!(
        desired[11],
        a([a([
            b(&manifest.roles[0].service_key),
            b(&manifest.endpoints[0].endpoint_id)
        ])])
    );
    let consent = wire::decode(&manifest.unsigned_consent(0).unwrap()).unwrap();
    assert_eq!(
        consent.array(19).unwrap()[17].fixed::<32>().unwrap(),
        wire::digest(&manifest.desired().unwrap())
    );
    let mut changed = manifest.clone();
    changed.clock.kernel_boot = "AnotherBoot".into();
    assert_ne!(changed.desired().unwrap(), manifest.desired().unwrap());
    changed = manifest.clone();
    changed
        .authority_config
        .as_mut()
        .unwrap()
        .ordered_peer_endpoint_ids
        .swap(1, 2);
    assert_ne!(changed.desired().unwrap(), manifest.desired().unwrap());
    changed = manifest;
    changed.roles[0].bind_endpoint_ids = vec![[31; 32]];
    assert!(changed.encode().is_err());
}
#[test]
fn certificate_identity_and_operator_monitor_separation_are_mandatory() {
    let manifest = fixture();
    let mut changed = manifest.clone();
    changed.endpoints[0].transport_key = manifest.endpoints[1].transport_key;
    assert!(changed.encode().is_err());
    changed = manifest.clone();
    changed.operator = changed.clock.monitor_key;
    assert!(changed.encode().is_err());
    changed = manifest.clone();
    changed.endpoints[0].leaf_der.truncate(40);
    assert!(changed.encode().is_err());
    changed = manifest;
    changed.roles[0].outbound_endpoint_ids.pop();
    assert!(changed.encode().is_err());
}
#[test]
fn manifest_rejects_unused_resources_ambiguous_sets_and_unbounded_input() {
    let manifest = fixture();
    let mut changed = manifest.clone();
    changed.volumes.push(Volume {
        volume_id: [99; 32],
        read_only: true,
        storage_admission_bytes: 1,
    });
    assert!(changed.encode().is_err());
    changed = manifest.clone();
    changed.endpoints.swap(0, 1);
    assert!(changed.encode().is_err());
    changed = manifest.clone();
    changed.roles[0].state_admission_bytes = 536870912;
    assert!(changed.encode().is_err());
    changed = manifest;
    changed.clock.witness_file_name = "../ClockHealth.cbor".into();
    assert!(changed.encode().is_err());
    assert!(Manifest::parse(&vec![0; MAXIMUM + 1]).is_err());
}

#[test]
fn operational_successor_requires_exact_predecessor_and_preserves_rights() {
    let original = fixture();
    let mut next = original.clone();
    next.generation = 2;
    next.previous_profile = Some(wire::digest(&original.desired().unwrap()));
    next.previous_consent = Some(wire::digest(&original.unsigned_consent(0).unwrap()));
    next.validity = (2000, 7200000);
    next.clock.kernel_boot = "22345678-1234-1234-1234-123456789abc".into();
    next.software_digest = [91; 32];
    next.roles[0].image_digest = [92; 32];
    next.successor_of(&original).unwrap();
    assert_eq!(Manifest::parse(&next.encode().unwrap()).unwrap(), next);
    assert!(next.permits_definition(&original).is_ok());
    let mut changed = next.clone();
    changed.previous_consent = Some([93; 32]);
    assert!(changed.successor_of(&original).is_err());
    let mut changed = next.clone();
    changed.roles[0].memory_bytes *= 2;
    assert!(changed.successor_of(&original).is_err());
    let mut changed = next.clone();
    changed.generation = 3;
    assert!(changed.successor_of(&original).is_err());
    next.session_mode = 1;
    assert!(next.validate().is_err());
    next.clock.kernel_boot = "CurrentHost".into();
    next.successor_of(&original).unwrap();
    next.session_mode = 0;
    assert!(next.validate().is_err());
}
