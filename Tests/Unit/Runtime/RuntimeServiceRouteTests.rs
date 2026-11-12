// SPDX-License-Identifier: MIT
// Bridge control mounts bind a selected local content/media role and exact network identity.
use super::*;
#[test]
fn bridge_store_routes_accept_role_one_without_weakening_identity_scope() {
    let base = crate::authority_deployment_tests::manifest();
    let mut bridge = base.clone();
    bridge.roles.retain(|role| role.role == 7);
    for role in [1, 2] {
        let mut store = base.clone();
        store.roles.retain(|value| value.role == role);
        let key = store.roles[0].service_key;
        store_route(&bridge, &store, key).unwrap();
        assert!(store_route(&bridge, &store, [7; 32]).is_err());
        store.network[0] ^= 1;
        assert!(store_route(&bridge, &store, key).is_err());
        store.network = base.network;
        store.incarnation[0] ^= 1;
        assert!(store_route(&bridge, &store, key).is_err());
    }
    let mut other = base;
    other.roles.retain(|role| role.role == 3);
    assert!(store_route(&bridge, &other, other.roles[0].service_key).is_err());
}

struct RetainedRoute {
    profile: Profile,
    successor: Manifest,
    data: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>,
}
impl RetainedRoute {
    fn new() -> Self {
        use crate::{
            authority_deployment_records, authority_deployment_tests as fixture,
            authority_domains::routes::RegisteredProfile,
            route_profile::{Assurance, Identity, Limits},
        };
        let root =
            std::env::temp_dir().join(format!("HyperNetRetainedRoute{}", files::random_id()));
        files::directory(&root).unwrap();
        files::directory(&root.join("Config")).unwrap();
        let mut manifest = fixture::manifest();
        manifest.roles.retain(|role| role.role == 5);
        manifest
            .volumes
            .retain(|volume| volume.volume_id == [105; 32]);
        manifest.placement.volumes = vec![[105; 32]];
        manifest
            .endpoints
            .retain(|endpoint| endpoint.endpoint_id == [85; 32]);
        manifest.authority_config = None;
        manifest.validate().unwrap();
        let mut successor = manifest.clone();
        successor.generation += 1;
        successor.previous_profile = Some(wire::digest(&manifest.desired().unwrap()));
        successor.previous_consent = Some(wire::digest(&manifest.unsigned_consent(0).unwrap()));
        successor.validity = (15000, 40000).into();
        successor.successor_of(&manifest).unwrap();
        let endpoint = &successor.endpoints[0];
        let certificate = pem("CERTIFICATE", &endpoint.leaf_der);
        let mut route = RegisteredProfile {
            deployment: successor.deployment,
            service: successor.roles[0].service_key,
            operator: successor.operator,
            deployment_profile: authority_deployment_records::reference(
                &successor.desired().unwrap(),
            )
            .unwrap(),
            consent: authority_deployment_records::reference(
                &successor.unsigned_consent(0).unwrap(),
            )
            .unwrap(),
            endpoint: endpoint.endpoint_id,
            identity: Identity {
                service: [171; 32],
                server_name: "192.0.2.10".into(),
                transport_key: endpoint.transport_key,
                leaf_der: endpoint.leaf_der.clone(),
                certificate_authority_pem: String::from_utf8(certificate.clone()).unwrap(),
            },
            address: Some(std::net::SocketAddr::new(endpoint.address, endpoint.port)),
            domain: hex::encode([172; 32]),
            protocol: 1,
            mode: 2,
            relay: None,
            limits: Limits {
                bytes: 1048576,
                duration_ms: 60000,
                idle_ms: 10000,
            },
            maximum_connections: 16,
            assurance: Assurance::Organisation,
            validity: successor.validity,
            manifest: successor.clone(),
            envelope: Vec::new(),
        };
        route.envelope = wire::sign_envelope(
            &route
                .payload(successor.network, successor.incarnation)
                .unwrap(),
            &fixture::key(90),
        )
        .unwrap();
        RegisteredProfile::parse(&route.envelope, successor.network, successor.incarnation)
            .unwrap();
        let configuration = crate::route_config::Configuration {
            version: 1,
            relay_identity: None,
            relay_address: None,
            application: None,
        };
        let data: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>> = [
            ("RouteProfile.cbor", route.envelope),
            (
                "ServiceConfig.json",
                serde_json::to_vec(&configuration).unwrap(),
            ),
            ("Certificate.pem", certificate.clone()),
            ("Transport.key", transport_key(114)),
            ("CertificateAuthority.pem", certificate),
        ]
        .into_iter()
        .map(|(name, bytes)| (name.into(), zeroize::Zeroizing::new(bytes)))
        .collect();
        let mut artifacts = [
            "Bootstrap.cbor",
            "Certificate.pem",
            "CertificateAuthority.pem",
            "Egress.json",
            "Manifest.cbor",
            "RouteBinding.json",
            "RouteProfile.cbor",
            "Seccomp.json",
            "Service.key",
            "ServiceConfig.json",
            "Transport.key",
        ]
        .into_iter()
        .map(|name| (name.into(), [0; 32]))
        .collect::<BTreeMap<_, _>>();
        for name in [
            "Certificate.pem",
            "Transport.key",
            "CertificateAuthority.pem",
        ] {
            files::create(&root.join("Config").join(name), &data[name]).unwrap();
            artifacts.insert(name.into(), wire::digest(&data[name]));
        }
        let profile = Profile {
            version: 1,
            root: root.clone(),
            manifest,
            artifacts,
            authority_control: root.join("Authority/Launch/State/Control"),
            authority_binding: None,
            clock_directory: root.join("Clock"),
            selinux: false,
            media_controls: BTreeMap::new(),
            route_target: None,
            application_target: None,
        };
        profile.validate().unwrap();
        Self {
            profile,
            successor,
            data,
        }
    }
    fn validate(&self) -> Result<()> {
        self.profile.validate_route_successor(
            &self.successor,
            &self.data["RouteProfile.cbor"],
            &self.data["ServiceConfig.json"],
        )
    }
}
impl Drop for RetainedRoute {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.profile.root);
    }
}
fn pem(label: &str, bytes: &[u8]) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(bytes)
    )
    .into_bytes()
}
fn transport_key(seed: u8) -> Vec<u8> {
    // The maintained deployment fixture uses this PKCS8 encoding for each fixed test seed.
    let mut bytes = zeroize::Zeroizing::new(vec![
        0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    bytes.extend([seed; 32]);
    pem("PRIVATE KEY", &bytes)
}

#[test]
fn route_successor_validates_retained_tls_against_signed_identity() {
    let mut fixture = RetainedRoute::new();
    fixture.validate().unwrap();
    for (name, replacement) in [
        (
            "Certificate.pem",
            pem("CERTIFICATE", &crate::authority_deployment_tests::leaf(113)),
        ),
        ("Transport.key", transport_key(113)),
        (
            "CertificateAuthority.pem",
            pem("CERTIFICATE", &crate::authority_deployment_tests::leaf(113)),
        ),
    ] {
        let replacement = zeroize::Zeroizing::new(replacement);
        let path = fixture.profile.root.join("Config").join(name);
        std::fs::write(&path, &replacement).unwrap();
        // Matching a local digest must not bypass leaf, key-pair or signed trust-root checks.
        fixture
            .profile
            .artifacts
            .insert(name.into(), wire::digest(&replacement));
        assert!(fixture.validate().is_err(), "{name}");
        std::fs::write(&path, &fixture.data[name]).unwrap();
        fixture
            .profile
            .artifacts
            .insert(name.into(), wire::digest(&fixture.data[name]));
    }
    fixture.validate().unwrap();
}

#[test]
fn route_successor_refuses_missing_or_changed_retained_tls_artifacts() {
    let mut fixture = RetainedRoute::new();
    for name in [
        "Certificate.pem",
        "Transport.key",
        "CertificateAuthority.pem",
    ] {
        let path = fixture.profile.root.join("Config").join(name);
        std::fs::remove_file(&path).unwrap();
        assert!(fixture.validate().is_err(), "missing {name}");
        files::create(&path, b"substituted").unwrap();
        assert!(
            fixture
                .validate()
                .unwrap_err()
                .to_string()
                .contains("differs from consent")
        );
        std::fs::write(&path, &fixture.data[name]).unwrap();
        let digest = fixture.profile.artifacts.remove(name).unwrap();
        assert!(
            fixture
                .validate()
                .unwrap_err()
                .to_string()
                .contains("artifact is absent")
        );
        fixture.profile.artifacts.insert(name.into(), digest);
    }
    fixture.validate().unwrap();
}

#[test]
fn route_import_returns_errors_for_every_missing_input() {
    let fixture = RetainedRoute::new();
    crate::route_config::validate_import(&fixture.successor, &fixture.data, None, None).unwrap();
    for name in fixture.data.keys() {
        let mut incomplete = fixture.data.clone();
        incomplete.remove(name);
        let error =
            crate::route_config::validate_import(&fixture.successor, &incomplete, None, None)
                .unwrap_err();
        assert!(error.to_string().contains(name), "{name}: {error}");
    }
}
