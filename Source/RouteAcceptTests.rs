// SPDX-License-Identifier: MIT
// Descriptor exhaustion is isolated to a child process and cannot change another test's limits.
use super::*;
use std::{
    fs::File,
    process::{Command, Stdio},
    time::Instant,
};
use tokio::io::AsyncReadExt;

#[test]
fn private_route_listener_recovers_from_descriptor_exhaustion() {
    const CHILD: &str = "HYPERNET_ROUTE_DESCRIPTOR_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exhaustion());
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "route_runtime::accept_tests::private_route_listener_recovers_from_descriptor_exhaustion",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "descriptor child failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("descriptor child exceeded its finite deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn fill_descriptors() -> Vec<File> {
    let mut retained = Vec::new();
    for _ in 0..=64 {
        match File::open("/dev/null") {
            Ok(file) => retained.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                return retained;
            }
        }
    }
    panic!("child descriptor limit was not applied");
}
async fn roundtrip(client: &mut TcpStream, message: &[u8]) {
    tokio::time::timeout(Duration::from_secs(1), async {
        route_io::send(client, message).await.unwrap();
        assert_eq!(route_io::receive(client, 128).await.unwrap(), message);
    })
    .await
    .unwrap();
}
async fn exhaustion() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut queue = listen(listener, 2, 10000, None, |socket| async { Ok(socket) });
    let mut client = TcpStream::connect(address).await.unwrap();
    let first = queue.requests.recv().await.unwrap();
    assert_eq!(first.deadline - first.started, 10000);
    let traffic = tokio::spawn(async move {
        let _slot = first.slot;
        let mut stream = first.request;
        for _ in 0..3 {
            let packet = route_io::receive(&mut stream, 128).await.unwrap();
            route_io::send(&mut stream, &packet).await.unwrap();
        }
    });
    // Reserve the client socket before exhaustion. Connecting it does not allocate another FD.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // This code runs only in the dedicated subprocess after its runtime descriptors exist.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    assert!(limit.rlim_cur >= 64);
    limit.rlim_cur = 64;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let handles = fill_descriptors();
    let exhausted_at = Instant::now();
    let mut pending = socket.connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while queue.diagnostics.refused[Refusal::Accept as usize].load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    roundtrip(&mut client, b"established traffic under exhaustion").await;
    tokio::time::sleep(Duration::from_millis(2 * DISPATCH_MS + 20)).await;
    let attempts = queue.diagnostics.refused[Refusal::Accept as usize].load(Ordering::Relaxed);
    assert!(attempts >= 1);
    assert!(attempts <= exhausted_at.elapsed().as_millis() as u64 / DISPATCH_MS + 2);
    assert!(queue.tasks.try_join_next().is_none());
    assert!(queue.requests.is_empty());

    drop(handles);
    let mut accepted = tokio::time::timeout(Duration::from_secs(1), queue.requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.deadline - accepted.started, 10000);
    route_io::send(&mut accepted.request, b"acceptance recovered")
        .await
        .unwrap();
    assert_eq!(
        route_io::receive(&mut pending, 128).await.unwrap(),
        b"acceptance recovered"
    );
    drop(accepted);
    drop(pending);
    roundtrip(&mut client, b"established traffic after recovery").await;

    // Shutdown remains selectable while a later resource failure is in its backoff interval.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    let handles = fill_descriptors();
    let before = queue.diagnostics.refused[Refusal::Accept as usize].load(Ordering::Relaxed);
    let mut pending = socket.connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while queue.diagnostics.refused[Refusal::Accept as usize].load(Ordering::Relaxed) == before
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(queue);
    let closed = tokio::time::timeout(Duration::from_secs(1), pending.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
    roundtrip(
        &mut client,
        b"independent existing task survives listener cancellation",
    )
    .await;
    traffic.await.unwrap();
    drop(handles);
}

#[test]
fn private_route_accept_retries_only_transient_failures() {
    for code in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOBUFS,
        libc::ENOMEM,
        libc::ECONNABORTED,
        libc::EINTR,
        libc::EAGAIN,
        libc::ENETUNREACH,
    ] {
        assert!(transient_accept(&std::io::Error::from_raw_os_error(code)));
    }
    for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EACCES] {
        assert!(!transient_accept(&std::io::Error::from_raw_os_error(code)));
    }
}
