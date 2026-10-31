// SPDX-License-Identifier: MIT
// Unit tests for AuthorityLocalTransport.
use super::*;
use std::time::Duration;
#[test]
fn closed_control_socket_preserves_typed_failure_without_replaying_io() {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    drop(server);
    let error = read_all(&mut client, &mut [0; 4], boot_time_ms().unwrap() + 1000).unwrap_err();
    assert_eq!(
        error.downcast_ref::<ControlClosed>(),
        Some(&ControlClosed::Read)
    );
    assert!(transport_closed(&error));
    assert!(transport_closed(
        &write_all(&mut client, b"request", boot_time_ms().unwrap() + 1000).unwrap_err()
    ));
    for error in [
        anyhow::anyhow!("private control read closed"),
        std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(),
        std::io::Error::from(std::io::ErrorKind::TimedOut).into(),
    ] {
        assert!(!transport_closed(&error));
    }
}
#[test]
fn fresh_read_capacity_reuses_exact_packet_and_original_deadline() {
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    for terminal in [true, false] {
        let fixture = crate::authority_proof::tests::Fixture::new(10000);
        let prefix = fixture.descriptor.genesis().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let boot = boot_time_ms().unwrap();
        let signed = crate::authority_read::Request::sign(
            fixture.descriptor.scope(),
            &key,
            key.verifying_key().to_bytes(),
            [77; 32],
            0,
            crate::authority_read::Query::PolicyContext,
        )
        .unwrap();
        let health = ClockHealth::new(wall, boot, boot + 1000, 1).unwrap();
        let challenge = crate::authority_challenge::Session::new()
            .unwrap()
            .issue_read(&signed, &key, [77; 32], 5000, None, health.frozen())
            .unwrap();
        let id = crate::authority_read::read_id(&signed, &challenge).unwrap();
        let expected = wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            prefix.scope().value(),
            V::Uint(6),
            b(&wire::encode(&a(vec![b(&signed), b(&challenge)])).unwrap()),
        ]))
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "FR{}",
            hex::encode(crate::route_protocol::random().unwrap())[..12].to_owned()
        ));
        files::create_directory(&path).unwrap();
        let socket = path.join("Control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let scope = prefix.scope().value();
        let done = Arc::new(AtomicBool::new(false));
        let stopped = done.clone();
        let server = std::thread::spawn(move || {
            let mut count = 0;
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut size = [0; 4];
                stream.read_exact(&mut size).unwrap();
                let size = u32::from_be_bytes(size) as usize;
                assert!(size <= wire::MAXIMUM);
                let mut received = vec![0; size];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(
                    received, expected,
                    "capacity must not mint another request or challenge"
                );
                count += 1;
                let code = if terminal && count == 3 { 1 } else { 2 };
                let reply = wire::encode(&a(vec![
                    V::Uint(62),
                    V::Uint(1),
                    scope.clone(),
                    V::Uint(2),
                    V::Uint(code),
                    b(&id),
                    V::Null,
                    V::Null,
                    V::Null,
                    a(vec![]),
                ]))
                .unwrap();
                if stream
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .and_then(|()| stream.write_all(&reply))
                    .is_err()
                {
                    break;
                }
            }
            count
        });
        let start = boot_time_ms().unwrap();
        let mut clock = || Ok(ClockHealth::new(wall, boot, boot + 1000, 1).unwrap());

        let error = exchange_read(
            &fixture.descriptor,
            &signed,
            &challenge,
            start + 120,
            &socket,
            &prefix,
            None,
            &mut clock,
        )
        .err()
        .expect("unavailability cannot become authority");
        let elapsed = boot_time_ms().unwrap() - start;
        done.store(true, Ordering::Relaxed);
        let count = server.join().unwrap();
        assert_eq!(
            error.downcast_ref::<FreshReadUnavailable>().unwrap().code,
            if terminal { 1 } else { 2 }
        );
        if terminal {
            assert_eq!(count, 3);
        } else {
            assert!(count >= 2);
            assert!((120..1000).contains(&elapsed));
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
#[test]
fn overtaken_history_requires_exact_unavailable_reply() {
    let fixture = crate::authority_proof::tests::Fixture::new(10000);
    let prefix = fixture.descriptor.genesis().unwrap();
    let fields = vec![
        V::Uint(42),
        V::Uint(1),
        prefix.scope().value(),
        V::Uint(2),
        V::Uint(5),
        V::Null,
        V::Null,
        V::Null,
        V::Null,
        a(vec![]),
    ];
    let classify = |fields: Vec<V>| {
        HistoryEvidence::checkpoint_reply(
            &prefix,
            &fixture.ancestry[0],
            &wire::encode(&a(fields)).unwrap(),
        )
        .err()
        .expect("unavailable history must never become proof")
    };
    assert!(classify(fields.clone()).is::<HistoryOvertaken>());
    for (index, value) in [
        (0, V::Uint(41)),
        (1, V::Uint(2)),
        (2, a(vec![])),
        (3, V::Uint(1)),
        (4, V::Uint(1)),
        (4, V::Uint(2)),
        (5, b(&[1; 32])),
        (6, b(&[])),
        (7, b(&[])),
        (8, b(&[])),
        (9, a(vec![V::Null])),
    ] {
        let mut changed = fields.clone();
        changed[index] = value;
        assert!(!classify(changed).is::<HistoryOvertaken>());
    }
    let mut extra = fields;
    extra.push(V::Null);
    assert!(!classify(extra).is::<HistoryOvertaken>());
}
#[test]
fn output_sidecars_are_finite_and_absent_from_nonpermits() {
    use crate::authority_objects::{Class, Object, Reference, Resolved};
    let body = b"approved source".to_vec();
    let reference = Reference::for_bytes(Class::PageSource, &body).unwrap();
    let objects = Resolved::exact(
        std::slice::from_ref(&reference),
        vec![Object::verify(reference.clone(), body).unwrap()],
    )
    .unwrap();
    let result = |disposition, code| {
        wire::encode(&a(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text("AuthorityDomain".into()),
            V::Uint(disposition),
            V::Uint(code),
            b(&wire::encode(&a(vec![])).unwrap()),
        ]))
        .unwrap()
    };
    assert_eq!(
        output_objects(&result(0, 0), &objects.value(), &mut |_| Ok(vec![
            reference.clone()
        ]))
        .unwrap()
        .references(),
        vec![reference]
    );
    assert!(output_objects(&result(0, 0), &objects.value(), &mut |_| Ok(vec![])).is_err());
    for (disposition, code) in [(1, 3), (2, 25)] {
        let mut called = false;
        let mut select = |_: &[u8]| {
            called = true;
            Ok(vec![])
        };
        assert!(output_objects(&result(disposition, code), &objects.value(), &mut select).is_err());
        assert!(
            output_objects(&result(disposition, code), &a(vec![]), &mut select)
                .unwrap()
                .is_empty()
        );
        assert!(!called);
    }
}
#[test]
fn drip_reads_do_not_extend_the_original_transport_deadline() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client.set_nonblocking(true).unwrap();
    let sender = std::thread::spawn(move || {
        for byte in 0..10 {
            if server.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let start = boot_time_ms().unwrap();
    let mut bytes = [0; 10];
    assert!(read_all(&mut client, &mut bytes, start + 55).is_err());
    assert!(boot_time_ms().unwrap() - start < 500);
    drop(client);
    sender.join().unwrap();
}
