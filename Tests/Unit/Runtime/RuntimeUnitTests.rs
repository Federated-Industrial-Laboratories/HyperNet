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
fn management_socket_supports_long_private_paths_and_retains_peer_check() {
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
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&temporary.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        root.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(root.join("Management.sock").as_os_str().len() > 108);
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
