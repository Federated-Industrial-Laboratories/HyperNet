// SPDX-License-Identifier: MIT
// Real nested TLS exchanges distinguish transport identity, cancellation and opaque forwarding.
use super::*;
use crate::{
    authority_domains::routes,
    route_connector,
    route_profile::{Assurance, Profile},
};
use std::{
    fs,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Certificate {
    identity: Identity,
    pem: Vec<u8>,
    key: Vec<u8>,
}
fn typed_voucher(
    relay: Digest,
    destination: Digest,
    possession: Digest,
) -> crate::authority_domains::Record {
    use crate::{
        authority_domains::{Record, State},
        authority_proof::VersionRef,
    };
    let reference = |kind, id, digest| VersionRef {
        kind,
        id,
        generation: 1,
        digest,
    };
    let voucher = routes::Voucher {
        relay: reference(165, relay, [81; 32]),
        destination: reference(165, destination, [82; 32]),
        sponsor: ed25519_dalek::SigningKey::from_bytes(&[83; 32])
            .verifying_key()
            .to_bytes(),
        grant: reference(102, [84; 32], [85; 32]),
        possession,
        action: 10,
        scope: (0, [1; 32]),
        connections: 2,
        bytes: 2 * 1024 * 1024,
        expires: u64::MAX,
        creation: [86; 32],
    };
    Record::next(
        &State::empty([1; 32], [2; 32]),
        166,
        [87; 32],
        voucher.value(),
    )
    .unwrap()
}

#[test]
fn private_route_refresh_schedule_predicts_full_action_cost() {
    let schedule = AdmissionSchedule::default();
    let reader = Some(([31; 32], false));
    assert_eq!(refresh_at(7600, 1800, None), 5700);
    assert_eq!(
        schedule.choose(5600, Some((7600, 0)), 1800, 1800, None),
        Work::Wait
    );
    assert_eq!(
        schedule.choose(5700, Some((7600, 0)), 1800, 1800, None),
        Work::Refresh
    );
    // A fresh job must not occupy the single requester across the latest renewal start.
    assert_eq!(
        schedule.choose(3800, Some((7600, 0)), 1800, 1800, reader),
        Work::Admit
    );
    assert_eq!(
        schedule.choose(3900, Some((7600, 0)), 1800, 1800, reader),
        Work::Refresh
    );
    // A slow admission reserves time only when admission work is actually queued.
    assert_eq!(
        schedule.choose(5100, Some((7600, 0)), 1800, 4500, None),
        Work::Wait
    );
    assert_eq!(
        schedule.choose(5100, Some((7600, 0)), 1800, 4500, reader),
        Work::Refresh
    );
    assert_eq!(refresh_at(100, u64::MAX, None), 0);
}

#[test]
fn private_route_reader_arriving_during_renewal_receives_one_admission_turn() {
    let mut schedule = AdmissionSchedule::default();
    let reader = Some(([31; 32], false));
    let replacement = Some(([32; 32], false));
    let attachment = Some(([33; 32], true));
    assert_eq!(
        schedule.choose(6000, Some((7500, 0)), 1800, 1800, None),
        Work::Refresh
    );
    schedule.refreshed();
    assert_eq!(
        schedule.choose(6800, Some((9300, 0)), 1800, 1800, None),
        Work::Wait
    );
    // A background attachment cannot spend the next reader's scheduling turn.
    schedule.admitted(attachment);
    assert_eq!(
        schedule.choose(6800, Some((9300, 0)), 1800, 1800, reader),
        Work::Admit
    );
    schedule.admitted(reader);
    assert_eq!(
        schedule.choose(6800, Some((9300, 0)), 1800, 1800, reader),
        Work::Refresh
    );
    schedule.refreshed();
    // A replacement required by a waiting reader is classified as eligible work.
    assert_eq!(
        schedule.choose(6800, Some((9300, 0)), 1800, 1800, replacement),
        Work::Admit
    );
    schedule.admitted(replacement);
    assert_eq!(
        schedule.choose(6800, Some((9300, 0)), 1800, 1800, replacement),
        Work::Refresh
    );
    schedule.refreshed();
    assert_eq!(
        schedule.choose(8600, Some((11100, 0)), 1800, 1800, attachment),
        Work::Refresh
    );
}

#[test]
fn private_route_fresh_permission_has_useful_time_without_extending_its_expiry() {
    let schedule = AdmissionSchedule::default();
    let reader = Some(([31; 32], false));
    let expires = 10000;
    let accepted_at = 8000;
    // Even a successful but slow renewal cannot immediately order another renewal.
    assert_eq!(
        schedule.choose(8000, Some((expires, accepted_at)), 4000, 4000, None),
        Work::Wait
    );
    assert_eq!(
        schedule.choose(8000, Some((expires, accepted_at)), 4000, 4000, reader),
        Work::Admit
    );
    assert_eq!(
        schedule.choose(9000, Some((expires, accepted_at)), 4000, 4000, None),
        Work::Refresh
    );
    assert_eq!(
        schedule.choose(expires, Some((expires, accepted_at)), 4000, 4000, None),
        Work::Refresh
    );
    // Keep a viable early renewal instead of delaying every proof until its midpoint.
    assert_eq!(refresh_at(10500, 2000, Some(8000)), 8400);
    assert!(useful_until(8000, expires) < expires);
    assert_eq!(refresh_at(expires, u64::MAX, Some(u64::MAX)), expires);
}

#[tokio::test]
async fn private_route_cold_admission_yields_with_original_binding_and_slot() {
    use crate::{authority_domains::State, route_authority::retained_voucher};
    let possession = ed25519_dalek::SigningKey::from_bytes(&[33; 32])
        .verifying_key()
        .to_bytes();
    let other_possession = ed25519_dalek::SigningKey::from_bytes(&[37; 32])
        .verifying_key()
        .to_bytes();
    let record = typed_voucher([31; 32], [32; 32], possession);
    let reference = record.reference.clone();
    let open = Open {
        network: [1; 32],
        incarnation: [2; 32],
        relay: [31; 32],
        service: [32; 32],
        voucher: wire::encode(&crate::authority_membership::reference(&reference)).unwrap(),
        nonce: [34; 32],
        attachment: false,
    };
    let slots = Arc::new(Semaphore::new(1));
    let queued = Queued {
        request: open,
        slot: slots.clone().acquire_owned().await.unwrap(),
        started: 1000,
        enqueued: 2000,
        deadline: 12000,
    };
    let binding = queued.request.binding([35; 32], [36; 32]).unwrap();
    let connection = wire::digest(&binding);
    let job = Some((connection, false));
    let mut state = State::empty([1; 32], [2; 32]);
    let mut schedule = AdmissionSchedule::default();
    assert_eq!(
        schedule.choose(3000, Some((8000, 0)), 1700, 1700, job),
        Work::Admit
    );
    schedule.admitted(job);
    assert!(
        retained_voucher(&state, &reference, &queued.request, possession)
            .unwrap()
            .is_none()
    );
    // Only the certified Context result is retained; no usage record or forwarding permission exists.
    state.records.insert((166, reference.id), record);
    assert_eq!(
        schedule.choose(4700, Some((8000, 0)), 1700, 1700, job),
        Work::Refresh
    );
    assert_eq!(slots.available_permits(), 0);
    schedule.refreshed();
    assert_eq!(
        schedule.choose(6400, Some((8900, 0)), 1700, 1700, job),
        Work::Admit
    );
    schedule.admitted(job);
    assert!(
        retained_voucher(&state, &reference, &queued.request, possession)
            .unwrap()
            .is_some()
    );
    assert!(state.records.keys().all(|(kind, _)| *kind != 167));
    assert_eq!(queued.request.binding([35; 32], [36; 32]).unwrap(), binding);
    assert_eq!(
        (queued.started, queued.enqueued, queued.deadline),
        (1000, 2000, 12000)
    );
    assert!(retained_voucher(&state, &reference, &queued.request, other_possession).is_err());
    let mut changed = queued.request.clone();
    changed.service = [38; 32];
    assert!(retained_voucher(&state, &reference, &changed, possession).is_err());
    let mut wrong = reference.clone();
    wrong.digest = [39; 32];
    assert!(retained_voucher(&state, &wrong, &queued.request, possession).is_err());
    // A suspended context cannot acquire a fresh admission deadline or retain a slot after expiry.
    let mut waiting = VecDeque::from([queued]);
    waiting.retain(|job| job.deadline > 12000);
    assert!(waiting.is_empty());
    assert_eq!(slots.available_permits(), 1);
}

fn certificates() -> (Certificate, Certificate) {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "HyperNetRouteTls{}",
        hex::encode(protocol::random().unwrap())
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new("openssl")
            .current_dir(&root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "test TLS fixture creation failed");
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ed25519",
        "-nodes",
        "-keyout",
        "Authority.key",
        "-out",
        "Authority.pem",
        "-days",
        "1",
        "-subj",
        "/CN=HyperNetRouteTestCA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
    ]);
    let authority = fs::read_to_string(root.join("Authority.pem")).unwrap();
    let build = |name: &str, service: Digest| {
        run(&[
            "req",
            "-new",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            "Service.key",
            "-out",
            "Service.csr",
            "-subj",
            &format!("/CN={name}"),
        ]);
        fs::write(root.join("Extensions.txt"),format!("subjectAltName=DNS:{name}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")).unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            "Service.csr",
            "-CA",
            "Authority.pem",
            "-CAkey",
            "Authority.key",
            "-CAcreateserial",
            "-out",
            "Service.pem",
            "-days",
            "1",
            "-extfile",
            "Extensions.txt",
        ]);
        let pem = fs::read(root.join("Service.pem")).unwrap();
        let key = fs::read(root.join("Service.key")).unwrap();
        let leaf = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap()
            .as_ref()
            .to_vec();
        Certificate {
            identity: Identity {
                service,
                server_name: name.into(),
                transport_key: crate::runtime_manifest::leaf_key(&leaf).unwrap(),
                leaf_der: leaf,
                certificate_authority_pem: authority.clone(),
            },
            pem,
            key,
        }
    };
    let relay = build("relay.hypernet.test", [31; 32]);
    let endpoint = build("endpoint.hypernet.test", [32; 32]);
    fs::remove_dir_all(root).unwrap();
    (relay, endpoint)
}
fn readiness_fixture(
    duration_ms: u64,
) -> (tokio::io::DuplexStream, Session, route_io::Gate, Vec<u8>) {
    let (peer, stream) = tokio::io::duplex(4096);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let deadline = start + duration_ms;
    let permission = route_io::Gate::new(start);
    let (stream, boundary) = route_io::Transport::new(stream, deadline);
    let session = Session {
        stream: Box::new(stream),
        boundary,
        deadline,
        idle_ms: duration_ms,
        bytes: 4096,
        slot: None,
        timing: Timing::begin(start, false),
        frames: 0,
    };
    let ready = protocol::endpoint_ready([1; 32], [2; 32], [4; 32], 1).unwrap();
    (peer, session, permission, ready)
}
async fn readiness_is_pending(
    mut pending: std::pin::Pin<&mut impl Future<Output = Result<Request>>>,
    peer: &mut tokio::io::DuplexStream,
) {
    std::future::poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        let mut bytes = [0; 1];
        let mut output = tokio::io::ReadBuf::new(&mut bytes);
        assert!(
            std::pin::Pin::new(&mut *peer)
                .poll_read(cx, &mut output)
                .is_pending()
        );
        assert!(output.filled().is_empty());
        std::task::Poll::Ready(())
    })
    .await;
}
#[tokio::test]
async fn private_route_endpoint_readiness_waits_for_current_renewal() {
    let (mut peer, session, permission, ready) = readiness_fixture(5000);
    let deadline = session.deadline;
    let remaining_bytes = session.bytes - (ready.len() + 4 + b"Request".len() + 4) as u64;
    let pending = ready_session(session, ready.clone(), permission.clone());
    tokio::pin!(pending);
    // Expiry precedes the task's first poll, reproducing the dispatch-to-ready race
    // without depending on a scheduler delay or a short sleep.
    readiness_is_pending(pending.as_mut(), &mut peer).await;
    permission.renew(deadline + 1000).unwrap();
    let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(pending, async {
            assert_eq!(route_io::receive(&mut peer, 256).await.unwrap(), ready);
            route_io::send(&mut peer, b"Request").await.unwrap();
        })
    })
    .await
    .unwrap();
    let request = result.unwrap();
    assert_eq!(request.packet, b"Request");
    assert_eq!(request.session.deadline, deadline);
    assert_eq!(request.session.bytes, remaining_bytes);
}
#[tokio::test]
async fn private_route_endpoint_readiness_refuses_closed_permission() {
    use tokio::io::AsyncReadExt;
    for close_before_binding in [false, true] {
        let (mut peer, session, permission, ready) = readiness_fixture(5000);
        if close_before_binding {
            permission.close();
        }
        let pending = ready_session(session, ready, permission.clone());
        tokio::pin!(pending);
        if !close_before_binding {
            readiness_is_pending(pending.as_mut(), &mut peer).await;
            permission.close();
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            permission
                .renew(crate::authority_challenge::boot_time_ms().unwrap() + 5000)
                .is_err()
        );
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
#[tokio::test]
async fn private_route_endpoint_prepares_near_expiry_permission_before_ready_and_reply() {
    let (mut peer, session, gate, ready) = readiness_fixture(10000);
    let deadline = session.deadline;
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let old_expiry = now + 3000;
    let budget = 1800;
    gate.renew(old_expiry).unwrap();
    // The proof is current, but an application action would cross the renewal's latest start.
    assert!(now < refresh_at(old_expiry, budget, None));
    let mut permission = EndpointPermission {
        gate: gate.clone(),
        accepted_at: None,
        renewals: 0,
    };
    let fresh_expiry = now + 5000;
    let mut renewed = false;
    permission
        .prepare(deadline, budget, |bound| {
            assert_eq!(bound, deadline);
            assert!(gate.expiry().unwrap() > crate::authority_challenge::boot_time_ms().unwrap());
            renewed = true;
            Ok(fresh_expiry)
        })
        .unwrap();
    assert!(renewed);
    assert_eq!(gate.expiry().unwrap(), fresh_expiry);
    permission
        .prepare(deadline, 10000, |_| {
            anyhow::bail!("fresh permission must be reused")
        })
        .unwrap();
    let expected_ready = ready.clone();
    let (request, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            async {
                let mut request = ready_session(session, ready, gate.clone()).await.unwrap();
                assert_eq!(request.packet, b"Request");
                assert_eq!(request.session.deadline, deadline);
                route_io::guarded_send(
                    &mut request.session.stream,
                    b"Reply",
                    &gate,
                    request.session.deadline,
                    request.session.idle_ms,
                )
                .await
                .unwrap();
                request
            },
            async {
                assert_eq!(
                    route_io::receive(&mut peer, 256).await.unwrap(),
                    expected_ready
                );
                route_io::send(&mut peer, b"Request").await.unwrap();
                assert_eq!(route_io::receive(&mut peer, 256).await.unwrap(), b"Reply");
            }
        )
    })
    .await
    .unwrap();
    assert_eq!(request.session.deadline, deadline);
    assert_eq!(permission.renewals, 1);
    drop(request);
    // This models a later point in the same proof after its useful interval has elapsed.
    permission.accepted_at = None;
    gate.renew(crate::authority_challenge::boot_time_ms().unwrap() + 1000)
        .unwrap();
    assert!(
        permission
            .prepare(deadline, budget, |_| anyhow::bail!(
                "current authority refused"
            ))
            .is_err()
    );
    assert_eq!(permission.renewals, 2);
    let retained_expiry = gate.expiry().unwrap();
    assert!(
        permission
            .renew(deadline, |_| Ok(
                crate::authority_challenge::boot_time_ms().unwrap()
            ))
            .is_err()
    );
    assert_eq!(gate.expiry().unwrap(), retained_expiry);
    assert_eq!(permission.renewals, 3);
    assert!(
        permission
            .prepare(
                crate::authority_challenge::boot_time_ms().unwrap(),
                budget,
                |_| anyhow::bail!("expired setup must not request renewal")
            )
            .is_err()
    );
    assert_eq!(permission.renewals, 3);
}
#[tokio::test]
async fn private_route_endpoint_readiness_retains_original_deadline() {
    let (mut peer, session, permission, ready) = readiness_fixture(200);
    let deadline = session.deadline;
    let pending = ready_session(session, ready.clone(), permission.clone());
    tokio::pin!(pending);
    readiness_is_pending(pending.as_mut(), &mut peer).await;
    permission.renew(deadline + 5000).unwrap();
    let (result, ()) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(pending, async {
            assert_eq!(route_io::receive(&mut peer, 256).await.unwrap(), ready);
            // No request follows. The renewed proof must not extend this session.
        })
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(crate::authority_challenge::boot_time_ms().unwrap() >= deadline);
    assert!(permission.expiry().unwrap() > deadline);
}
#[tokio::test]
async fn private_route_renewable_binding_blocks_other_expired_writes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (socket, mut peer) = tokio::io::duplex(128);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let deadline = start + 5000;
    let (mut socket, boundary) = route_io::Transport::new(socket, deadline);
    let permission = route_io::Gate::new(start);
    assert!(boundary.arm(permission.clone(), deadline).is_err());
    boundary
        .arm_renewable(permission.clone(), deadline)
        .unwrap();
    assert!(
        boundary
            .arm_renewable(permission.clone(), deadline + 5000)
            .is_err()
    );
    let pending = socket.write_all(b"Buffered TLS bytes");
    tokio::pin!(pending);
    std::future::poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        let mut bytes = [0; 1];
        let mut output = tokio::io::ReadBuf::new(&mut bytes);
        assert!(
            std::pin::Pin::new(&mut peer)
                .poll_read(cx, &mut output)
                .is_pending()
        );
        std::task::Poll::Ready(())
    })
    .await;
    permission.renew(deadline).unwrap();
    pending.await.unwrap();
    let mut bytes = [0; 18];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"Buffered TLS bytes");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_plain_session_progresses_while_authority_maintenance_is_delayed() {
    use crate::trust_wire::Value as V;
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
    let root = std::env::temp_dir().join(format!(
        "HyperNetRouteDriver{}",
        hex::encode(protocol::random().unwrap())
    ));
    files::create_directory(&root).unwrap();
    let path = root.join("Control.sock");
    let directory = files::private_directory(&root).unwrap();
    let bind = Path::new("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join("Control.sock");
    let application = tokio::net::UnixListener::bind(&bind).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let packet = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        crate::authority_proof::Scope {
            network: [1; 32],
            incarnation: [2; 32],
            configuration: [3; 32],
            epoch: 1,
        }
        .value(),
        V::Uint(2),
        V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
    ]))
    .unwrap();
    let expected = packet.clone();
    let application = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = application.accept().await.unwrap();
            assert_eq!(
                route_io::receive(&mut stream, wire::MAXIMUM).await.unwrap(),
                expected
            );
            route_io::send(&mut stream, b"Current local response")
                .await
                .unwrap();
        }
    });
    let (mut peer, stream) = tokio::io::duplex(16384);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let deadline = start + 5000;
    let permission = route_io::Gate::new(deadline);
    let (stream, boundary) = route_io::Transport::new(stream, deadline);
    let slots = Arc::new(Semaphore::new(1));
    let slot = slots.clone().acquire_owned().await.unwrap();
    let session = Session {
        stream: Box::new(stream),
        boundary,
        deadline,
        idle_ms: 5000,
        bytes: 16384,
        slot: Some(slot),
        timing: Timing::begin(start, false),
        frames: 0,
    };
    let driver = tokio::spawn(async move {
        let request = ready_session(
            session,
            protocol::endpoint_ready([1; 32], [2; 32], [4; 32], 1).unwrap(),
            permission.clone(),
        )
        .await?;
        ordinary_requests(request, (1, [1; 32], [2; 32]), permission, &path).await
    });
    let (completed, dispatcher) = std::sync::mpsc::sync_channel(1);
    let reader = tokio::spawn(async move {
        let ready = route_io::receive(&mut peer, 256).await.unwrap();
        protocol::parse_endpoint_ready(&ready, [1; 32], [2; 32], [4; 32], 1).unwrap();
        for _ in 0..3 {
            route_io::send(&mut peer, &packet).await.unwrap();
            assert_eq!(
                route_io::receive(&mut peer, 256).await.unwrap(),
                b"Current local response"
            );
        }
        completed.send(()).unwrap();
    });
    // The maintenance dispatcher is synchronously blocked until the socket tasks complete all exchanges.
    dispatcher.recv_timeout(Duration::from_secs(2)).unwrap();
    reader.await.unwrap();
    application.await.unwrap();
    assert!(driver.await.unwrap().is_err());
    assert_eq!(slots.available_permits(), 1);
    fs::remove_dir_all(root).unwrap();
}
#[derive(Default)]
struct BlockWrites {
    blocked: std::sync::atomic::AtomicBool,
    written: AtomicUsize,
    waiter: std::sync::Mutex<Option<std::task::Waker>>,
}
struct Backpressure {
    socket: tokio::io::DuplexStream,
    state: Arc<BlockWrites>,
}
impl AsyncRead for Backpressure {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_read(cx, bytes)
    }
}
impl AsyncWrite for Backpressure {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.state.blocked.load(Ordering::Acquire) {
            *self.state.waiter.lock().unwrap() = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }
        let result = std::pin::Pin::new(&mut self.socket).poll_write(cx, bytes);
        if let std::task::Poll::Ready(Ok(count)) = result {
            self.state.written.fetch_add(count, Ordering::AcqRel);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn private_route_tls_read_error_cannot_flush_ciphertext_after_permission_expiry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_, certificate) = certificates();
    let (client, server) = tokio::io::duplex(65536);
    let state = Arc::new(BlockWrites::default());
    let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 5000;
    let (server, boundary) = route_io::Transport::new(
        Backpressure {
            socket: server,
            state: state.clone(),
        },
        deadline,
    );
    let acceptor = TlsAcceptor::from(
        route_tls::server(&certificate.identity, &certificate.pem, &certificate.key).unwrap(),
    );
    let connector = TlsConnector::from(route_tls::client(&certificate.identity).unwrap());
    let (server, client) = tokio::join!(
        acceptor.accept(server),
        connector.connect(
            rustls::pki_types::ServerName::try_from(certificate.identity.server_name.clone())
                .unwrap(),
            client
        )
    );
    let mut server = server.unwrap();
    let mut client = client.unwrap();
    let expires = crate::authority_challenge::boot_time_ms().unwrap() + 100;
    let permission = route_io::Gate::new(expires);
    boundary.arm(permission, deadline).unwrap();
    state.blocked.store(true, Ordering::Release);
    server
        .write_all(b"Queued private application ciphertext")
        .await
        .unwrap();
    assert!(server.get_ref().1.wants_write());
    let before = state.written.load(Ordering::Acquire);
    tokio::time::sleep(Duration::from_millis(
        expires.saturating_sub(crate::authority_challenge::boot_time_ms().unwrap()) + 1,
    ))
    .await;
    state.blocked.store(false, Ordering::Release);
    if let Some(waker) = state.waiter.lock().unwrap().take() {
        waker.wake();
    }
    // A bad encrypted record invokes tokio-rustls' error-triggered write_tls from poll_read.
    let mut malformed = vec![23, 3, 3, 0, 17];
    malformed.extend_from_slice(&[0; 17]);
    client.get_mut().0.write_all(&malformed).await.unwrap();
    let error = tokio::time::timeout(Duration::from_millis(500), server.read(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(state.written.load(Ordering::Acquire), before);
    assert!(server.get_ref().1.wants_write());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_nested_tls_checks_final_identity_before_application_credentials() {
    let (relay_certificate, endpoint_certificate) = certificates();
    for (substitute, readiness_delay) in [(false, 0), (true, 0), (false, 1250), (true, 1250)] {
        let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = service.local_addr().unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let payloads = Arc::new(AtomicUsize::new(0));
        let observed = payloads.clone();
        let acceptor = TlsAcceptor::from(
            route_tls::server(
                &endpoint_certificate.identity,
                &endpoint_certificate.pem,
                &endpoint_certificate.key,
            )
            .unwrap(),
        );
        let limits = Limits {
            bytes: 1024 * 1024,
            duration_ms: 5000,
            idle_ms: 2000,
        };
        let endpoint_id = endpoint_certificate.identity.service;
        let service_task = tokio::spawn(async move {
            let (socket, _) = service.accept().await.unwrap();
            if let Ok(session) = endpoint_incoming(socket, acceptor, limits).await {
                let gate = route_io::Gate::new(session.deadline);
                let ready = protocol::endpoint_ready([1; 32], [2; 32], endpoint_id, 1).unwrap();
                let Ok(mut request) = ready_session(session, ready, gate.clone()).await else {
                    return;
                };
                for index in 0..3 {
                    observed.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(&request.packet, b"Private application credentials");
                    let session = &mut request.session;
                    session.charge(b"Exact application response".len()).unwrap();
                    route_io::guarded_send(
                        &mut session.stream,
                        b"Exact application response",
                        &gate,
                        session.deadline,
                        session.idle_ms,
                    )
                    .await
                    .unwrap();
                    if index < 2 {
                        request = next_packet(request.session, gate.clone()).await.unwrap();
                    }
                }
            }
        });
        let relay_acceptor = TlsAcceptor::from(
            route_tls::server(
                &relay_certificate.identity,
                &relay_certificate.pem,
                &relay_certificate.key,
            )
            .unwrap(),
        );
        let relay_id = relay_certificate.identity.service;
        let possession = ed25519_dalek::SigningKey::from_bytes(&[79; 32]);
        let expected_key = possession.verifying_key().to_bytes();
        let voucher = typed_voucher(
            relay_id,
            endpoint_certificate.identity.service,
            expected_key,
        );
        let expected_voucher = voucher.reference.clone();
        let admissions = Arc::new(AtomicUsize::new(0));
        let admitted = admissions.clone();
        let relay_task = tokio::spawn(async move {
            let (socket, _) = relay.accept().await.unwrap();
            admitted.fetch_add(1, Ordering::SeqCst);
            let opened = ingress(socket, relay_acceptor, [1; 32], [2; 32], relay_id, limits)
                .await
                .unwrap();
            assert_eq!(opened.signer, expected_key);
            let reference =
                crate::authority_domains::version(&wire::decode(&opened.open.voucher).unwrap())
                    .unwrap();
            assert_eq!(reference, expected_voucher);
            assert_eq!(
                opened.open.voucher,
                wire::encode(&crate::authority_membership::reference(&reference)).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(readiness_delay)).await;
            let remaining = if readiness_delay == 0 {
                limits
            } else {
                Limits {
                    duration_ms: 1000,
                    idle_ms: 1000,
                    ..limits
                }
            };
            // Setup has consumed more than the returned remaining lifetime, but the caller still has time.
            assert!(readiness_delay == 0 || readiness_delay > remaining.duration_ms);
            let destination = TcpStream::connect(destination).await.unwrap();
            let mut stream = opened.stream;
            route_io::send(
                &mut stream,
                &protocol::ready(opened.binding, remaining).unwrap(),
            )
            .await
            .unwrap();
            let _ = route_io::forward(stream, destination, remaining).await;
        });
        let mut final_identity = endpoint_certificate.identity.clone();
        if substitute {
            final_identity.server_name = "other.hypernet.test".into();
        }
        let profile = Profile {
            version: 1,
            network: [1; 32],
            incarnation: [2; 32],
            relay_address,
            relay: relay_certificate.identity.clone(),
            destination: final_identity,
            domain: "Destination".into(),
            relay_domain: "Relay".into(),
            protocol: 1,
            assurance: Assurance::Independent,
            minimum_assurance: Assurance::Independent,
            limits,
            voucher: voucher.bytes,
        };
        let no_credentials = payloads.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let start = crate::authority_challenge::boot_time_ms()?;
            let cancel = || false;
            let mut session =
                route_connector::Session::connect(&profile, &possession, start + 5000, &cancel)?;
            assert_eq!(no_credentials.load(Ordering::SeqCst), 0);
            // The application challenge begins only after final identity and current endpoint readiness.
            let challenge_start = crate::authority_challenge::boot_time_ms()?;
            assert!(challenge_start >= start + readiness_delay);
            let mut response = Vec::new();
            for _ in 0..3 {
                response = session.exchange(
                    b"Private application credentials",
                    challenge_start + 5000,
                    1024,
                )?;
                assert_eq!(response, b"Exact application response");
            }
            Ok(response)
        })
        .await
        .unwrap();
        if substitute {
            assert!(result.is_err());
            assert_eq!(payloads.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(result.unwrap(), b"Exact application response");
            assert_eq!(payloads.load(Ordering::SeqCst), 3);
            assert_eq!(admissions.load(Ordering::SeqCst), 1);
        }
        service_task.await.unwrap();
        relay_task.await.unwrap();
    }
}

#[test]
fn private_route_rejects_mismatched_voucher_before_network_connection() {
    use crate::authority_domains::{Record, State};
    let (relay, destination) = certificates();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let possession = ed25519_dalek::SigningKey::from_bytes(&[79; 32]);
    let voucher = typed_voucher(
        relay.identity.service,
        destination.identity.service,
        possession.verifying_key().to_bytes(),
    );
    let profile = Profile {
        version: 1,
        network: [1; 32],
        incarnation: [2; 32],
        relay_address: listener.local_addr().unwrap(),
        relay: relay.identity,
        destination: destination.identity,
        domain: "Destination".into(),
        relay_domain: "Relay".into(),
        protocol: 1,
        assurance: Assurance::Independent,
        minimum_assurance: Assurance::Independent,
        limits: Limits {
            bytes: 1024 * 1024,
            duration_ms: 5000,
            idle_ms: 2000,
        },
        voucher: voucher.bytes,
    };
    for case in 0..8 {
        let mut profile = profile.clone();
        let mut key = possession.clone();
        match case {
            0 => profile.voucher = vec![1],
            1 => {
                profile.voucher =
                    wire::encode(&crate::authority_membership::reference(&voucher.reference))
                        .unwrap()
            }
            2 => profile.network = [88; 32],
            3 => profile.incarnation = [89; 32],
            4 => {
                profile.voucher = Record::next(
                    &State::empty(profile.network, profile.incarnation),
                    167,
                    [87; 32],
                    routes::Usage {
                        connections: 1,
                        bytes: 65536,
                        connection: [90; 32],
                        transcript: [91; 32],
                        creation: [92; 32],
                    }
                    .value(),
                )
                .unwrap()
                .bytes
            }
            5 => profile.relay.service = [93; 32],
            6 => profile.destination.service = [94; 32],
            7 => key = ed25519_dalek::SigningKey::from_bytes(&[95; 32]),
            _ => unreachable!(),
        }
        let result = route_connector::exchange(
            &profile,
            &key,
            b"Private application credentials",
            crate::authority_challenge::boot_time_ms().unwrap() + 1000,
            1024,
            &|| false,
        );
        assert!(result.is_err(), "voucher case {case} was accepted");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "voucher case {case} contacted the relay"
        );
    }
}

async fn authenticated_ingress(
    address: SocketAddr,
    identity: Identity,
    attachment: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = TlsConnector::from(route_tls::client(&identity).unwrap());
    let mut stream = connector
        .connect(
            rustls::pki_types::ServerName::try_from(identity.server_name.clone()).unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .context("authenticate private relay")?;
    let exporter = stream
        .get_ref()
        .1
        .export_keying_material([0; 32], protocol::EXPORTER, None)
        .unwrap();
    let open = Open {
        network: [1; 32],
        incarnation: [2; 32],
        relay: identity.service,
        service: [32; 32],
        voucher: if attachment { vec![] } else { vec![1] },
        nonce: protocol::random().unwrap(),
        attachment,
    };
    route_io::send(&mut stream, &open.encode().unwrap())
        .await
        .unwrap();
    let challenge = protocol::parse_challenge(
        &route_io::receive(&mut stream, protocol::FRAME)
            .await
            .unwrap(),
    )
    .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[79; 32]);
    route_io::send(&mut stream, &open.sign(challenge, exporter, &key).unwrap())
        .await
        .unwrap();
    Ok(stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_blocked_admission_keeps_tls_responsive_and_capacity_bounded() {
    use tokio::io::AsyncReadExt;
    let (certificate, _) = certificates();
    let acceptor = TlsAcceptor::from(
        route_tls::server(&certificate.identity, &certificate.pem, &certificate.key).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = certificate.identity.clone();
    let limits = Limits {
        bytes: 1048576,
        duration_ms: 5000,
        idle_ms: 2000,
    };
    let relay = identity.service;
    let mut queue = listen(listener, 2, limits.idle_ms, None, move |socket| {
        ingress(socket, acceptor.clone(), [1; 32], [2; 32], relay, limits)
    });
    let first_client = tokio::spawn(authenticated_ingress(address, identity.clone(), false));
    let first = tokio::time::timeout(Duration::from_secs(2), queue.requests.recv())
        .await
        .unwrap()
        .unwrap();
    let mut first_client = first_client.await.unwrap().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let second_client = tokio::spawn(async move {
        let stream = authenticated_ingress(address, identity, false)
            .await
            .unwrap();
        sender.send(()).unwrap();
        stream
    });
    // Deliberately block the sole admission driver; accepting TLS runs independently.
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), queue.requests.recv())
        .await
        .unwrap()
        .unwrap();
    let mut second_client = second_client.await.unwrap();
    assert_eq!(first.deadline - first.started, limits.idle_ms);
    assert_eq!(second.deadline - second.started, limits.idle_ms);
    let mut excess = authenticated_ingress(address, certificate.identity.clone(), false)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    assert_eq!(
        queue.diagnostics.refused[Refusal::Capacity as usize].load(Ordering::Relaxed),
        1
    );
    drop(first);
    drop(second);
    drop(queue);
    for stream in [&mut first_client, &mut second_client] {
        let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0)) || closed.is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_queue_keeps_original_deadline_and_abort_closes_parsing() {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut queue = listen(listener, 1, 100, None, |socket| async { Ok(socket) });
    let mut client = TcpStream::connect(address).await.unwrap();
    let queued = queue.requests.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(110)).await;
    assert!(crate::authority_local_transport::remaining(queued.deadline).is_err());
    assert_eq!(queued.deadline - queued.started, 100);
    drop(queued);
    drop(queue);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, received) = tokio::sync::oneshot::channel();
    let sender = std::sync::Mutex::new(Some(sender));
    let queue = listen(listener, 1, 1000, None, move |socket| {
        sender.lock().unwrap().take().unwrap().send(()).unwrap();
        async move {
            std::future::pending::<()>().await;
            Ok(socket)
        }
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    received.await.unwrap();
    drop(queue);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_attachment_pool_cannot_starve_reader_tls_or_admission() {
    let (certificate, _) = certificates();
    let limits = Limits {
        bytes: 8388608,
        duration_ms: 120000,
        idle_ms: 30000,
    };
    for separate_pool in [false, true] {
        let acceptor = TlsAcceptor::from(
            route_tls::server(&certificate.identity, &certificate.pem, &certificate.key).unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = certificate.identity.service;
        let classify: Option<fn(&Opened) -> bool> =
            separate_pool.then_some(|opened: &Opened| opened.open.attachment);
        let mut queue = listen(listener, 8, limits.idle_ms, classify, move |socket| {
            ingress(socket, acceptor.clone(), [1; 32], [2; 32], relay, limits)
        });
        let mut sockets = Vec::new();
        for _ in 0..8 {
            sockets.push(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    authenticated_ingress(address, certificate.identity.clone(), true),
                )
                .await
                .unwrap()
                .unwrap(),
            );
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while if separate_pool {
                queue.attachments.len()
            } else {
                queue.requests.len()
            } != 8
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let reader = tokio::time::timeout(
            Duration::from_secs(2),
            authenticated_ingress(address, certificate.identity.clone(), false),
        )
        .await
        .unwrap();
        if !separate_pool {
            use tokio::io::AsyncReadExt;
            let mut reader = reader.unwrap();
            let closed = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut [0; 1]))
                .await
                .unwrap();
            assert!(matches!(closed, Ok(0)) || closed.is_err());
            assert_eq!(
                queue.diagnostics.refused[Refusal::Capacity as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(
                queue.diagnostics.refused[Refusal::Tls as usize].load(Ordering::Relaxed),
                0
            );
            continue;
        }
        sockets.push(reader.unwrap());
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.requests.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Reader admission takes priority over all eight queued pool warmers.
        let reader = next_admission(&mut queue.requests, &mut queue.attachments)
            .await
            .unwrap();
        assert!(!reader.request.open.attachment);
        assert_eq!(queue.attachments.len(), 8);
        assert_eq!(reader.deadline - reader.started, limits.idle_ms);
        let parked = next_admission(&mut queue.requests, &mut queue.attachments)
            .await
            .unwrap();
        assert!(parked.request.open.attachment);
        // Dequeuing a prospective parked socket does not release its pool reservation.
        sockets.push(
            tokio::time::timeout(
                Duration::from_secs(2),
                authenticated_ingress(address, certificate.identity.clone(), true),
            )
            .await
            .unwrap()
            .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.diagnostics.refused[Refusal::AttachmentCapacity as usize]
                .load(Ordering::Relaxed)
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(queue.attachments.len(), 7);
        assert_eq!(
            queue.diagnostics.refused[Refusal::Capacity as usize].load(Ordering::Relaxed),
            0
        );
        // Every reader slot may be occupied while the expired attachment needs replacing.
        let mut readers = vec![reader];
        for _ in 1..8 {
            sockets.push(
                authenticated_ingress(address, certificate.identity.clone(), false)
                    .await
                    .unwrap(),
            );
            readers.push(
                tokio::time::timeout(Duration::from_secs(2), queue.requests.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        drop(parked);
        sockets.push(
            tokio::time::timeout(
                Duration::from_secs(2),
                authenticated_ingress(address, certificate.identity.clone(), true),
            )
            .await
            .unwrap()
            .unwrap(),
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while queue.attachments.len() != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(readers.len(), 8);
        assert_eq!(
            queue.diagnostics.refused[Refusal::Capacity as usize].load(Ordering::Relaxed),
            0
        );
        drop(readers);
        drop(queue);
        drop(sockets);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_rendezvous_replaces_expired_attachment_without_second_reservation() {
    use tokio::io::AsyncReadExt;
    let (certificate, _) = certificates();
    let acceptor = TlsAcceptor::from(
        route_tls::server(&certificate.identity, &certificate.pem, &certificate.key).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let limits = Limits {
        bytes: 1048576,
        duration_ms: 10000,
        idle_ms: 5000,
    };
    let relay = certificate.identity.service;
    let mut queue = listen(
        listener,
        1,
        limits.idle_ms,
        Some(|opened: &Opened| opened.open.attachment),
        move |socket| ingress(socket, acceptor.clone(), [1; 32], [2; 32], relay, limits),
    );
    let mut reader_client = authenticated_ingress(address, certificate.identity.clone(), false)
        .await
        .unwrap();
    let reader = queue.requests.recv().await.unwrap();
    let mut old_client = authenticated_ingress(address, certificate.identity.clone(), true)
        .await
        .unwrap();
    let old = queue.attachments.recv().await.unwrap();
    let target = b"Exact approved target envelope".to_vec();
    let park = |queued: Queued<Opened>, deadline| Attached {
        stream: queued.request.stream,
        boundary: queued.request.boundary,
        service: [32; 32],
        envelope: target.clone(),
        binding: queued.request.binding,
        expires: 100000,
        deadline,
        total_deadline: queued.started + limits.duration_ms,
        slot: queued.slot,
    };
    let boot = crate::authority_challenge::boot_time_ms().unwrap();
    let connection = reader.request.connection;
    let voucher = typed_voucher(relay, [32; 32], reader.request.signer);
    let path = std::env::temp_dir().join(format!(
        "HyperNetRendezvous{}",
        hex::encode(protocol::random().unwrap())
    ));
    files::create_directory(&path).unwrap();
    let mut disk = crate::route_state::Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    // This is the single durable reservation performed by the successful initial Permit.
    disk.consume(connection, 1000, 11000).unwrap();
    let reservation = fs::read(path.join("RouteState.cbor")).unwrap();
    let deadline = reader.started + limits.duration_ms;
    let setup_deadline = reader.deadline;
    let mut waiting = VecDeque::from([Waiting {
        opened: reader.request,
        slot: reader.slot,
        setup_deadline,
        limits,
        target: [32; 32],
        envelope: target.clone(),
        live: Live {
            renewal: Renewal::fixture(voucher.reference, target.clone(), 11000),
            gate: route_io::Gate::new(boot),
            accepted_at: 0,
            deadline,
            timing: Timing::begin(boot, false),
            renewals: 0,
        },
    }]);
    let selected = crate::authority_challenge::boot_time_ms().unwrap();
    let mut parked = VecDeque::from([park(old, selected + 20)]);
    assert_eq!(
        waiting_pair(&waiting, &parked, 1000, selected),
        Some((0, 0))
    );
    let mut reader = waiting.pop_front().unwrap();
    let old = parked.pop_front().unwrap();
    let mut renewals = 0;
    reader
        .permission(old.total_deadline, |_, bound| {
            renewals += 1;
            assert_eq!(bound, setup_deadline.min(deadline).min(old.total_deadline));
            // The selected attachment expires during the fresh authority check.
            std::thread::sleep(Duration::from_millis(30));
            Ok(crate::authority_challenge::boot_time_ms().unwrap() + 5000)
        })
        .unwrap();
    assert!(!reader.matches(
        &old,
        1000,
        crate::authority_challenge::boot_time_ms().unwrap()
    ));
    drop(old);
    waiting.push_back(reader);
    assert_eq!(
        waiting_pair(
            &waiting,
            &parked,
            1000,
            crate::authority_challenge::boot_time_ms().unwrap()
        ),
        None
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), reader_client.read(&mut [0; 1]))
            .await
            .is_err()
    );
    let closed = tokio::time::timeout(Duration::from_secs(1), old_client.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());

    let mut endpoint = authenticated_ingress(address, certificate.identity.clone(), true)
        .await
        .unwrap();
    let replacement = queue.attachments.recv().await.unwrap();
    let mut pending = VecDeque::from([replacement]);
    assert_eq!(pending_admission(&pending, &waiting), Some((0, false)));
    let replacement = pending.pop_front().unwrap();
    let endpoint_binding = replacement.request.binding;
    let replacement = park(replacement, setup_deadline);
    parked.push_back(replacement);
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    assert_eq!(waiting_pair(&waiting, &parked, 1000, now), Some((0, 0)));
    parked[0].envelope.push(0);
    assert_eq!(waiting_pair(&waiting, &parked, 1000, now), None);
    parked[0].envelope.pop();
    parked[0].service = [99; 32];
    assert_eq!(waiting_pair(&waiting, &parked, 1000, now), None);
    parked[0].service = [32; 32];
    let mut reader = waiting.pop_front().unwrap();
    let replacement = parked.pop_front().unwrap();
    reader
        .permission(replacement.total_deadline, |_, _| {
            panic!("unexpired permission must not renew")
        })
        .unwrap();
    assert_eq!(renewals, 1);
    assert_eq!(reader.setup_deadline, setup_deadline);
    assert_eq!(reader.live.deadline, deadline);
    assert_eq!(reader.limits.bytes, limits.bytes);
    assert!(!reader.current(setup_deadline));
    let Waiting {
        opened, slot, live, ..
    } = reader;
    let reader_binding = opened.binding;
    let permission = live.gate.clone();
    let hard = deadline.min(replacement.total_deadline);
    let paired = tokio::spawn(async move {
        let _slot = slot;
        pair(
            opened,
            replacement,
            setup_deadline,
            limits,
            hard,
            permission,
        )
        .await
    });
    let ready = tokio::time::timeout(
        Duration::from_secs(2),
        route_io::receive(&mut reader_client, protocol::FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let admitted = protocol::parse_ready(&ready, reader_binding, limits).unwrap();
    assert!(admitted.duration_ms <= hard - now);
    assert_eq!(admitted.bytes, limits.bytes);
    protocol::parse_ready(
        &route_io::receive(&mut endpoint, protocol::FRAME)
            .await
            .unwrap(),
        endpoint_binding,
        limits,
    )
    .unwrap();
    route_io::send(&mut reader_client, b"Opaque inner TLS traffic")
        .await
        .unwrap();
    assert_eq!(
        route_io::receive(&mut endpoint, protocol::FRAME)
            .await
            .unwrap(),
        b"Opaque inner TLS traffic"
    );
    assert_eq!(fs::read(path.join("RouteState.cbor")).unwrap(), reservation);
    assert!(disk.consume(connection, 6000, 11000).is_err());
    live.gate.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), paired)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    drop(live);
    drop(queue);
    drop(disk);
    fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn private_route_rendezvous_refusal_and_setup_expiry_release_original_slot() {
    use tokio::io::AsyncReadExt;
    for expired_setup in [false, true] {
        let now = crate::authority_challenge::boot_time_ms().unwrap();
        let (stream, mut peer) = tokio::io::duplex(4096);
        let (stream, boundary) = route_io::Transport::new(stream, now + 10000);
        let slots = Arc::new(Semaphore::new(1));
        let possession = ed25519_dalek::SigningKey::from_bytes(&[79; 32])
            .verifying_key()
            .to_bytes();
        let voucher = typed_voucher([31; 32], [32; 32], possession);
        let gate = route_io::Gate::new(now);
        let setup = crate::authority_challenge::boot_time_ms().unwrap() + 20;
        let mut waiting = Waiting {
            opened: Opened {
                stream: Box::new(stream),
                boundary,
                open: Open {
                    network: [1; 32],
                    incarnation: [2; 32],
                    relay: [31; 32],
                    service: [32; 32],
                    voucher: vec![],
                    nonce: [1; 32],
                    attachment: false,
                },
                signer: possession,
                connection: [3; 32],
                binding: [4; 32],
                timing: None,
            },
            slot: slots.clone().try_acquire_owned().unwrap(),
            setup_deadline: setup,
            limits: Limits {
                bytes: 1048576,
                duration_ms: 10000,
                idle_ms: 5000,
            },
            target: [32; 32],
            envelope: b"Exact target".to_vec(),
            live: Live {
                renewal: Renewal::fixture(voucher.reference, b"Exact target".to_vec(), 11000),
                gate: gate.clone(),
                accepted_at: 0,
                deadline: now + 10000,
                timing: Timing::begin(now, false),
                renewals: 0,
            },
        };
        assert_eq!(slots.available_permits(), 0);
        let mut checked = false;
        assert!(
            waiting
                .permission(now + 5000, |_, bound| {
                    checked = true;
                    assert_eq!(bound, setup);
                    if expired_setup {
                        std::thread::sleep(Duration::from_millis(30));
                        Ok(crate::authority_challenge::boot_time_ms().unwrap() + 5000)
                    } else {
                        anyhow::bail!("current authority refused revoked sponsor")
                    }
                })
                .is_err()
        );
        assert!(checked);
        assert_eq!(waiting.setup_deadline, setup);
        assert_eq!(waiting.live.deadline, now + 10000);
        drop(waiting);
        assert!(gate.expiry().is_err());
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
    let diagnostics = IngressDiagnostics::default();
    for category in [
        Refusal::Admission,
        Refusal::AdmissionExpired,
        Refusal::AttachmentUnavailable,
        Refusal::Forwarding,
    ] {
        for _ in 0..5 {
            diagnostics.refuse(category);
        }
        assert_eq!(
            diagnostics.refused[category as usize].load(Ordering::Relaxed),
            5
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_route_ingress_diagnostics_distinguish_tls_from_deadline() {
    use tokio::io::AsyncWriteExt;
    let (certificate, _) = certificates();
    let acceptor = TlsAcceptor::from(
        route_tls::server(&certificate.identity, &certificate.pem, &certificate.key).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay = certificate.identity.service;
    let limits = Limits {
        bytes: 16384,
        duration_ms: 1000,
        idle_ms: 100,
    };
    let queue = listen(listener, 2, limits.idle_ms, None, move |socket| {
        ingress(socket, acceptor.clone(), [1; 32], [2; 32], relay, limits)
    });
    let mut malformed = TcpStream::connect(address).await.unwrap();
    malformed.write_all(b"Invalid TLS bytes").await.unwrap();
    malformed.shutdown().await.unwrap();
    let idle = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while queue.diagnostics.refused[Refusal::Tls as usize].load(Ordering::Relaxed) == 0
            || queue.diagnostics.refused[Refusal::Deadline as usize].load(Ordering::Relaxed) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        queue.diagnostics.refused[Refusal::Capacity as usize].load(Ordering::Relaxed),
        0
    );
    assert_eq!(queue.diagnostics.parsed.load(Ordering::Relaxed), 0);
    drop(idle);
    drop(queue);
}

#[test]
fn private_route_parked_identity_never_reuses_forwarding_permission() {
    let limits = Limits {
        bytes: 1048576,
        duration_ms: 120000,
        idle_ms: 30000,
    };
    let deadline = parking_deadline(30100, 100000, 1000, 100).unwrap();
    assert_eq!(deadline, 30100);
    // The inert socket can remain after its initial proof, but bytes need a new live proof.
    assert!(exact_attachment(
        b"Exact registered envelope",
        b"Exact registered envelope",
        (100000, deadline),
        (7000, 6100)
    ));
    let expired_permission = route_io::Gate::new(5000);
    assert!(expired_permission.expiry().unwrap() < 7000);
    assert!(!exact_attachment(
        b"Old key or generation",
        b"New key or generation",
        (100000, deadline),
        (7000, 6100)
    ));
    assert!(!exact_attachment(
        b"Same",
        b"Same",
        (100000, deadline),
        (100000, 6100)
    ));
    assert!(!exact_attachment(
        b"Same",
        b"Same",
        (100000, deadline),
        (7000, 30100)
    ));
    assert_eq!(parking_deadline(30100, 2000, 1000, 100).unwrap(), 1100);
    assert!(parking_deadline(100, 100000, 1000, 100).is_err());
    assert!(parking_deadline(30100, 1000, 1000, 100).is_err());
    let boot = crate::authority_challenge::boot_time_ms().unwrap();
    // Pairing near parking idle expiry retains only the original total lifetime, not a new total or an old idle ceiling.
    let total = total_deadline(boot - 500, limits, 200000, 1000, boot).unwrap();
    assert_eq!(total, boot + limits.duration_ms - 500);
    assert!(total > boot + limits.idle_ms);
    assert!(total_deadline(boot - limits.duration_ms, limits, 200000, 1000, boot).is_err());
    assert!(forwarding_limits(limits, boot).is_err());
    assert!(forwarding_limits(limits, boot + 2000).unwrap().duration_ms <= 2000);
}
