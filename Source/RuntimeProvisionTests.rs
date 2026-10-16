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
