// SPDX-License-Identifier: MIT
use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("HyperNetPreparation{}", files::random_id()));
        files::directory(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn native_issuer_and_local_identity_produce_only_pinned_public_peer_material() {
    let directory = Directory::new();
    let ca = directory.0.join("Issuer");
    let operator = directory.0.join("Operator");
    let authority = issuer(&ca, 2).unwrap();
    let request = prepare_identity(&operator, Ipv4Addr::new(192, 0, 2, 10), 24443).unwrap();
    let output = directory.0.join("Peer.json");
    let issued = issue(
        &ca,
        authority["issuerDigest"].as_str().unwrap(),
        &operator.join("TransportRequest.json"),
        request["requestDigest"].as_str().unwrap(),
        1,
        &output,
    )
    .unwrap();
    let peer: Peer = serde_json::from_slice(
        &tls::read_pinned(&output, issued["peerDigest"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    peer.validate(&directory.0).unwrap();
    assert_eq!(peer.request.identity, request["identity"]);
    assert_eq!(peer.request.transport, request["transport"]);
    let raw = String::from_utf8(files::read(&output, 65536).unwrap()).unwrap();
    assert!(!raw.contains("PRIVATE KEY"));
    assert!(!raw.contains("secretKey"));
    assert!(
        issue(
            &ca,
            authority["issuerDigest"].as_str().unwrap(),
            &operator.join("TransportRequest.json"),
            &hex::encode([1; 32]),
            1,
            &directory.0.join("Wrong.json")
        )
        .is_err()
    );
    assert!(!directory.0.join("Wrong.json").exists());
    assert!(prepare_identity(&operator, Ipv4Addr::new(192, 0, 2, 10), 24443).is_err());
}
#[test]
fn unpublished_preparation_does_not_replace_an_existing_destination() {
    let directory = Directory::new();
    let destination = directory.0.join("Inputs");
    let pending = PreparedDirectory::new(&destination).unwrap();
    let scratch = pending.root.clone();
    files::create(&scratch.join("Incomplete.json"), b"{}").unwrap();
    files::directory(&destination).unwrap();
    files::create(&destination.join("Retained.json"), b"Retained").unwrap();
    assert!(pending.commit().is_err());
    assert!(!scratch.exists());
    assert_eq!(
        files::read(&destination.join("Retained.json"), 64).unwrap(),
        b"Retained"
    );
}

#[test]
fn renewed_issuer_and_leaf_keep_private_keys_and_exact_public_identity() {
    let directory = Directory::new();
    let ca = directory.0.join("Issuer");
    let operator = directory.0.join("Operator");
    let authority = issuer(&ca, 2).unwrap();
    let request = prepare_identity(&operator, Ipv4Addr::new(192, 0, 2, 10), 24443).unwrap();
    let issuer_key = files::read(&ca.join("Transport.key"), 8192).unwrap();
    let transport_key = files::read(&operator.join("Transport.key"), 8192).unwrap();
    let original = directory.0.join("OriginalPeer.json");
    issue(
        &ca,
        authority["issuerDigest"].as_str().unwrap(),
        &operator.join("TransportRequest.json"),
        request["requestDigest"].as_str().unwrap(),
        1,
        &original,
    )
    .unwrap();
    let renewed_ca = directory.0.join("RenewedIssuer.pem");
    let renewed = renew_issuer(
        &ca,
        None,
        authority["issuerDigest"].as_str().unwrap(),
        3,
        &renewed_ca,
    )
    .unwrap();
    let output = directory.0.join("RenewedPeer.json");
    issue_selected(
        &ca,
        renewed["issuerDigest"].as_str().unwrap(),
        Some(&renewed_ca),
        &operator.join("TransportRequest.json"),
        request["requestDigest"].as_str().unwrap(),
        2,
        &output,
    )
    .unwrap();
    let old: Peer = serde_json::from_slice(&files::read(&original, 65536).unwrap()).unwrap();
    let new: Peer = serde_json::from_slice(&files::read(&output, 65536).unwrap()).unwrap();
    crate::runtime_manifest::certificates::leaf_successor(
        &tls::certificate(old.certificate_pem.as_bytes()).unwrap(),
        &tls::certificate(new.certificate_pem.as_bytes()).unwrap(),
        &tls::certificate(old.authority_pem.as_bytes()).unwrap(),
        &tls::certificate(new.authority_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        old.request.signed_bytes().unwrap(),
        new.request.signed_bytes().unwrap()
    );
    assert_eq!(
        files::read(&ca.join("Transport.key"), 8192).unwrap(),
        issuer_key
    );
    assert_eq!(
        files::read(&operator.join("Transport.key"), 8192).unwrap(),
        transport_key
    );
    assert_eq!(
        files::hex_digest(&files::read(&ca.join("Authority.pem"), 8192).unwrap()),
        authority["issuerDigest"].as_str().unwrap()
    );
    assert!(
        renew_issuer(
            &ca,
            Some(&renewed_ca),
            authority["issuerDigest"].as_str().unwrap(),
            4,
            &directory.0.join("WrongIssuer.pem")
        )
        .is_err()
    );
    assert!(!directory.0.join("WrongIssuer.pem").exists());
}

#[test]
fn expired_issuer_and_leaf_recover_with_retained_keys_and_request_after_offline() {
    use crate::runtime_manifest::certificates::{self, tests::expired_certificate};
    let directory = Directory::new();
    let ca = directory.0.join("Issuer");
    let operator = directory.0.join("Operator");
    let authority = issuer(&ca, 2).unwrap();
    let request = prepare_identity(&operator, Ipv4Addr::new(192, 0, 2, 10), 24443).unwrap();
    let initial = directory.0.join("InitialPeer.json");
    issue(
        &ca,
        authority["issuerDigest"].as_str().unwrap(),
        &operator.join("TransportRequest.json"),
        request["requestDigest"].as_str().unwrap(),
        1,
        &initial,
    )
    .unwrap();
    let old: Peer = serde_json::from_slice(&files::read(&initial, 65536).unwrap()).unwrap();
    let expired_leaf = expired_certificate(
        &old.certificate_pem,
        &ca.join("Transport.key"),
        &directory.0,
    );
    let expired_issuer =
        expired_certificate(&old.authority_pem, &ca.join("Transport.key"), &directory.0);
    fs::write(ca.join("Authority.pem"), expired_issuer.as_bytes()).unwrap();
    let pin = files::hex_digest(expired_issuer.as_bytes());
    let output = directory.0.join("RecoveredIssuer.pem");
    let renewed = renew_issuer(&ca, None, &pin, 3, &output).unwrap();
    let recovered = directory.0.join("RecoveredPeer.json");
    issue_selected(
        &ca,
        renewed["issuerDigest"].as_str().unwrap(),
        Some(&output),
        &operator.join("TransportRequest.json"),
        request["requestDigest"].as_str().unwrap(),
        2,
        &recovered,
    )
    .unwrap();
    let new: Peer = serde_json::from_slice(&files::read(&recovered, 65536).unwrap()).unwrap();
    let now = files::now().unwrap() * 1000;
    assert!(
        certificates::current(
            &certificates::der(&expired_leaf).unwrap(),
            &certificates::der(&expired_issuer).unwrap(),
            Ipv4Addr::new(192, 0, 2, 10).into(),
            now
        )
        .is_err()
    );
    certificates::leaf_successor(
        &certificates::der(&expired_leaf).unwrap(),
        &certificates::der(&new.certificate_pem).unwrap(),
        &certificates::der(&expired_issuer).unwrap(),
        &certificates::der(&new.authority_pem).unwrap(),
    )
    .unwrap();
    new.validate(&directory.0).unwrap();
    assert_eq!(
        new.request.signed_bytes().unwrap(),
        old.request.signed_bytes().unwrap()
    );
}
