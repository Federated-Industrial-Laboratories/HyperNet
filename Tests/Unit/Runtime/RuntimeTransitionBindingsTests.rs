// SPDX-License-Identifier: MIT
// Binding successors preserve identity and deny unsigned, widened or substituted application consent.
use super::*;
use crate::{
    authority_deployment_records, authority_deployment_tests as fixture,
    authority_proof::VersionRef,
    route_profile::{Assurance, Identity, Limits},
    trust_wire as wire,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;

fn route() -> RegisteredProfile {
    let mut manifest = fixture::manifest();
    manifest.roles.retain(|r| r.role == 5);
    manifest.volumes.retain(|v| v.volume_id == [105; 32]);
    manifest.placement.volumes = vec![[105; 32]];
    manifest.endpoints.retain(|e| e.endpoint_id == [85; 32]);
    manifest.authority_config = None;
    manifest.validate().unwrap();
    let endpoint = &manifest.endpoints[0];
    let mut route = RegisteredProfile {
        deployment: manifest.deployment,
        service: manifest.roles[0].service_key,
        operator: manifest.operator,
        deployment_profile: authority_deployment_records::reference(&manifest.desired().unwrap())
            .unwrap(),
        consent: authority_deployment_records::reference(&manifest.unsigned_consent(0).unwrap())
            .unwrap(),
        endpoint: endpoint.endpoint_id,
        identity: Identity {
            service: [171; 32],
            server_name: "192.0.2.10".into(),
            transport_key: endpoint.transport_key,
            leaf_der: endpoint.leaf_der.clone(),
            certificate_authority_pem: format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                STANDARD.encode(&endpoint.leaf_der)
            ),
        },
        address: Some(std::net::SocketAddr::new(endpoint.address, endpoint.port)),
        domain: hex::encode([172; 32]),
        protocol: 7,
        mode: 2,
        relay: None,
        limits: Limits {
            bytes: 1048576,
            duration_ms: 60000,
            idle_ms: 10000,
        },
        maximum_connections: 16,
        assurance: Assurance::Organisation,
        validity: manifest.validity,
        manifest,
        envelope: vec![],
    };
    seal(&mut route);
    route
}
fn seal(route: &mut RegisteredProfile) {
    route.envelope = wire::sign_envelope(
        &route
            .payload(route.manifest.network, route.manifest.incarnation)
            .unwrap(),
        &fixture::key(90),
    )
    .unwrap();
    *route = RegisteredProfile::parse(
        &route.envelope,
        route.manifest.network,
        route.manifest.incarnation,
    )
    .unwrap();
}
fn successor(old: &Manifest) -> Manifest {
    let mut new = old.clone();
    new.generation += 1;
    new.previous_profile = Some(wire::digest(&old.desired().unwrap()));
    new.previous_consent = Some(wire::digest(&old.unsigned_consent(0).unwrap()));
    new.validity = (15000, 40000).into();
    new.successor_of(old).unwrap();
    new
}
fn renewed(old: &RegisteredProfile) -> (RegisteredProfile, Manifest) {
    let mut new = old.clone();
    new.manifest = successor(&old.manifest);
    new.validity = new.manifest.validity;
    new.deployment_profile =
        authority_deployment_records::reference(&new.manifest.desired().unwrap()).unwrap();
    new.consent =
        authority_deployment_records::reference(&new.manifest.unsigned_consent(0).unwrap())
            .unwrap();
    seal(&mut new);
    let mut host = successor(&new.manifest);
    host.validity = (16000, 40000).into();
    (new, host)
}
fn configuration(route: &RegisteredProfile, generation: u64) -> Configuration {
    let owner = fixture::key(71);
    let operator = fixture::key(90);
    let binding = streams::local::Binding {
        version: 1,
        id: [176; 32],
        network: route.manifest.network,
        incarnation: route.manifest.incarnation,
        service: [177; 32],
        owner: owner.verifying_key().to_bytes(),
        endpoint: route.service,
        protocol: "hrc/1".into(),
    };
    let mut registration = streams::Registration {
        id: binding.service,
        route: VersionRef {
            kind: 165,
            id: route.identity.service,
            generation,
            digest: [178; 32],
        },
        owner: binding.owner,
        operator: route.operator,
        protocol: binding.protocol.clone(),
        binding: binding.digest().unwrap(),
        limits: route.limits,
        validity: route.validity,
        envelope: vec![],
    };
    let payload = registration
        .payload(binding.network, binding.incarnation)
        .unwrap();
    let mut signatures = [
        (
            &owner,
            owner.sign(&wire::signature_message(
                &payload,
                &owner.verifying_key().to_bytes(),
            )),
        ),
        (
            &operator,
            operator.sign(&wire::signature_message(
                &payload,
                &operator.verifying_key().to_bytes(),
            )),
        ),
    ];
    signatures.sort_by_key(|(key, _)| key.verifying_key().to_bytes());
    use wire::Value as V;
    registration.envelope = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        V::Bytes(payload),
        V::Array(
            signatures
                .iter()
                .map(|(key, signature)| {
                    V::Array(vec![
                        V::Bytes(key.verifying_key().to_bytes().to_vec()),
                        V::Bytes(signature.to_bytes().to_vec()),
                    ])
                })
                .collect(),
        ),
    ]))
    .unwrap();
    streams::Registration::parse(&registration.envelope, binding.network, binding.incarnation)
        .unwrap();
    Configuration {
        version: 2,
        relay_identity: None,
        relay_address: None,
        application: Some(crate::route_config::Application {
            registration: registration.envelope,
            binding,
        }),
    }
}
#[test]
fn explicit_successor_accepts_fresh_dual_consent_with_unchanged_identity() {
    let old = route();
    let (new, host) = renewed(&old);
    same_route(&old, &new, &host).unwrap();
    same_configuration(
        &configuration(&old, 1),
        &configuration(&new, 2),
        &new,
        &host,
    )
    .unwrap();
    assert_eq!(old.identity, new.identity);
    assert_eq!(old.service, new.service);
}
#[test]
fn signed_route_changes_cannot_expand_exposure_privacy_or_budget() {
    let old = route();
    let (new, host) = renewed(&old);
    for case in 0..8 {
        let mut changed = new.clone();
        match case {
            0 => changed.identity.service[0] ^= 1,
            1 => changed.domain = hex::encode([199; 32]),
            2 => changed.assurance = Assurance::Independent,
            3 => changed.maximum_connections += 1,
            4 => changed.limits.bytes *= 2,
            5 => changed.protocol = 1,
            6 => changed.address = Some("192.0.2.11:24443".parse().unwrap()),
            _ => changed.identity.server_name = "elsewhere.example".into(),
        }
        assert!(same_route(&old, &changed, &host).is_err());
    }
}
#[test]
fn renewed_application_requires_same_binding_and_two_valid_signatures() {
    let old = route();
    let (new, host) = renewed(&old);
    let before = configuration(&old, 1);
    let after = configuration(&new, 2);
    for case in 0..4 {
        let mut changed = after.clone();
        match case {
            0 => changed.application.as_mut().unwrap().binding.id[0] ^= 1,
            1 => changed.relay_address = Some("192.0.2.12:24443".parse().unwrap()),
            2 => {
                let data = &mut changed.application.as_mut().unwrap().registration;
                let at = data.len() - 1;
                data[at] ^= 1;
            }
            _ => changed.application = None,
        }
        assert!(same_configuration(&before, &changed, &new, &host).is_err());
    }
}
#[test]
fn proposal_embeds_exact_bounded_artifacts_and_hashes_change_with_content() {
    let old = route();
    let (new, host) = renewed(&old);
    let config = serde_json::to_vec(&configuration(&new, 2)).unwrap();
    let value = Selection {
        route_profile: hex::encode(&new.envelope),
        application_configuration: Some(hex::encode(&config)),
    };
    assert_eq!(value.bytes().unwrap(), (new.envelope.clone(), Some(config)));
    let first = summary(&value, &host).unwrap();
    let mut changed = value.clone();
    changed
        .application_configuration
        .as_mut()
        .unwrap()
        .push_str("20");
    assert_ne!(summary(&changed, &host).unwrap(), first);
    changed.route_profile = "00".repeat(32769);
    assert!(changed.bytes().is_err());
}

#[test]
fn certificate_route_validation_overlays_reviewed_public_tls_and_retains_private_key_pin() {
    use crate::consensus::journal::tests::Directory;
    use crate::runtime_manifest::certificates as tls;
    let (before, after) = crate::authority_domains::routes::tests::certificate_profiles();
    let directory = Directory::new();
    let root = &directory.0;
    files::directory(&root.join("Config")).unwrap();
    let mut key = vec![
        0x30, 0x2e, 0x02, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    key.extend([110; 32]);
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(key)
    );
    let mut artifacts = std::collections::BTreeMap::new();
    for (name, bytes) in [
        (
            "Certificate.pem",
            tls::pem(&before.identity.leaf_der).unwrap(),
        ),
        (
            "CertificateAuthority.pem",
            before.identity.certificate_authority_pem.clone(),
        ),
        ("Transport.key", key_pem),
    ] {
        files::create(&root.join("Config").join(name), bytes.as_bytes()).unwrap();
        artifacts.insert(name.to_string(), wire::digest(bytes.as_bytes()));
    }
    let profile: services::Profile = serde_json::from_value(json!({"version":1, "root":root,
        "manifest":before.manifest,"artifacts":artifacts,"authorityControl":root.join("Authority/Control"),
        "clockDirectory":root.join("Clock"),"selinux":false,"mediaControls":{},"routeTarget":null})).unwrap();
    let configuration =
        serde_json::to_vec(&json!({"version":1,"relayIdentity":null,"relayAddress":null})).unwrap();
    profile
        .validate_route_successor(&after.manifest, &after.envelope, &configuration)
        .unwrap();
    let selection = Selection {
        route_profile: hex::encode(&after.envelope),
        application_configuration: Some(hex::encode(&configuration)),
    };
    let preview = summary(&selection, &after.manifest).unwrap();
    assert!(preview["application"].is_null());
    assert_eq!(
        preview["configurationSha256"],
        files::hex_digest(&configuration)
    );
    std::fs::write(
        root.join("Config/Transport.key"),
        b"substituted private key",
    )
    .unwrap();
    assert!(
        profile
            .validate_route_successor(&after.manifest, &after.envelope, &configuration)
            .is_err()
    );
}
