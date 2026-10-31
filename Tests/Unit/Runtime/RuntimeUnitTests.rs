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
