// SPDX-License-Identifier: MIT
// Unit tests for Runtime.
use super::*;
#[test]
fn management_frames_are_bounded_and_unknown_operations_refused() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&16385u32.to_be_bytes()).unwrap();
    assert!(read_frame(&mut b).is_err());
    assert!(serde_json::from_str::<Request>(r#"{"operation":"Shell","operationId":null,"expectedGeneration":null,"profileDigest":null}"#).is_err());
}
#[test]
fn peer_credentials_match_the_actual_socket_owner() {
    let (a, _) = UnixStream::pair().unwrap();
    peer(&a).unwrap();
}
#[test]
fn setup_and_management_support_long_private_paths_and_retain_checks() {
    use std::os::unix::fs::PermissionsExt;
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "HyperNetManagement{}",
        hex::encode(rand::random::<[u8; 16]>())
    )));
    let root = temporary.0.join("a".repeat(64)).join("b".repeat(64));
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    std::fs::set_permissions(&temporary.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(root.join("Management.sock").as_os_str().len() > 108);
    let bootstrap = temporary.0.join("Bootstrap.cbor");
    files::create(&bootstrap, b"untrusted bootstrap").unwrap();
    let setup = |directory| {
        setup::setup(setup::Setup {
            directory,
            image: format!("sha256:{}", "01".repeat(32)),
            bootstrap: bootstrap.clone(),
            bootstrap_digest: "00".repeat(32),
            future_epoch: None,
            voter_key: temporary.0.join("Identity.json"),
            replica_config: temporary.0.join("ReplicaConfig.json"),
            peer_certificate: Vec::new(),
            bind: std::net::Ipv4Addr::LOCALHOST,
            private_peer_routing: false,
            port: 24443,
            subnet: std::net::Ipv4Addr::new(10, 89, 132, 0),
            memory_bytes: 536870912,
            pids: 64,
            cpu_quota: 100000,
            state_bytes: 1073741824,
            lifetime_seconds: Some(3600),
            until_withdrawn: false,
            session_policy: "Session".into(),
        })
        .unwrap_err()
        .to_string()
    };
    assert_eq!(
        setup(root.clone()),
        "Bootstrap differs from its independently authenticated digest"
    );
    assert!(!root.exists());
    assert_eq!(
        setup(PathBuf::from("RelativeRuntime")),
        "A new absolute runtime directory is required"
    );
    let alias = temporary.0.join("Alias");
    std::os::unix::fs::symlink(root.parent().unwrap(), &alias).unwrap();
    assert_eq!(
        setup(alias.join("Runtime")),
        "Private owner directory required"
    );
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(setup(root.clone()), "Private owner directory required");
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    files::directory(&root).unwrap();
    assert_eq!(
        setup(root.clone()),
        "A new absolute runtime directory is required"
    );
    let (_directory, address) = super::management_address(&root).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&address).unwrap();
    let client = std::os::unix::net::UnixStream::connect(&address).unwrap();
    let (server, _) = listener.accept().unwrap();
    super::peer(&client).unwrap();
    super::peer(&server).unwrap();
    assert!(std::fs::symlink_metadata(root.join("Management.sock")).is_ok());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(super::management_address(&root).is_err());
}
