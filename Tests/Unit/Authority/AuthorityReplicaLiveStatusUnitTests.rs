// SPDX-License-Identifier: MIT
// Unit tests for AuthorityReplicaLiveStatus.
use super::*;
use crate::consensus::{journal::tests::Directory, records::tests::fixture};
use std::{
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
};

#[test]
fn live_status_rejects_identity_generation_and_progress_mismatches() {
    let (configuration, _) = fixture();
    let signer = configuration.voters[0];
    let reply = vec![
        V::Uint(59),
        V::Uint(1),
        configuration.scope.value(),
        V::Bytes(signer.to_vec()),
        V::Uint(7),
        V::Uint(9),
        V::Uint(5),
        V::Uint(4),
        V::Bool(true),
    ];
    let accepted = parse(
        &wire::encode(&V::Array(reply.clone())).unwrap(),
        &configuration.scope,
        &signer,
        7,
    )
    .unwrap();
    assert_eq!(accepted["quorum"], "NotProbed");
    assert_eq!(accepted["clockReady"], true);
    for (index, value) in [
        (1, V::Uint(2)),
        (3, V::Bytes(configuration.voters[1].to_vec())),
        (4, V::Uint(6)),
        (7, V::Uint(6)),
        (8, V::Uint(1)),
    ] {
        let mut invalid = reply.clone();
        invalid[index] = value;
        assert!(
            parse(
                &wire::encode(&V::Array(invalid)).unwrap(),
                &configuration.scope,
                &signer,
                7
            )
            .is_err()
        );
    }
    let mut wrong_scope = configuration.scope.clone();
    wrong_scope.network[0] ^= 1;
    assert!(
        parse(
            &wire::encode(&V::Array(reply)).unwrap(),
            &wrong_scope,
            &signer,
            7
        )
        .is_err()
    );
}

#[test]
fn local_status_refuses_unsafe_socket_and_oversized_reply_before_body() {
    let directory = Directory::new();
    let path = directory.0.join("Control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(LocalControl::open(&directory.0).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let control = LocalControl::open(&directory.0).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut size = [0; 4];
        stream.read_exact(&mut size).unwrap();
        assert_eq!(u32::from_be_bytes(size), 1);
        let mut request = [0; 1];
        stream.read_exact(&mut request).unwrap();
        stream
            .write_all(&((MAX_RESPONSE + 1) as u32).to_be_bytes())
            .unwrap();
    });
    let error = control
        .exchange(&[0], boot_ms().unwrap() + TIMEOUT_MS)
        .unwrap_err();
    assert!(error.to_string().contains("response exceeds its bound"));
    server.join().unwrap();
    assert!(control.connect(boot_ms().unwrap()).is_err());
}
