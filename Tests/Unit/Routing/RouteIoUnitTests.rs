// SPDX-License-Identifier: MIT
// Unit tests for RouteIo.
use super::*;
#[tokio::test]
async fn private_route_raw_boundary_renews_both_pollers_and_cannot_rearm() {
    let (socket, mut peer) = tokio::io::duplex(128);
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let (socket, boundary) = Transport::new(socket, now + 2000);
    let gate = Gate::new(now + 50);
    boundary.arm(gate.clone(), now + 2000).unwrap();
    assert!(boundary.arm(Gate::new(now + 5000), now + 5000).is_err());
    tokio::time::sleep(Duration::from_millis(60)).await;
    let (mut reader, mut writer) = tokio::io::split(socket);
    let write = tokio::spawn(async move { writer.write_all(b"Renewed").await });
    let read = tokio::spawn(async move { reader.read_exact(&mut [0; 1]).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.read_exact(&mut [0; 1]))
            .await
            .is_err()
    );
    gate.renew(now + 2000).unwrap();
    tokio::time::timeout(Duration::from_millis(300), write)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    peer.read_exact(&mut [0; 7]).await.unwrap();
    gate.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), read)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}
#[tokio::test]
async fn private_route_raw_boundary_enforces_deadline_on_reads_flush_and_shutdown() {
    let (socket, _peer) = tokio::io::duplex(128);
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let (mut socket, boundary) = Transport::new(socket, now + 100);
    boundary.arm(Gate::new(now + 5000), now + 5000).unwrap();
    let error = tokio::time::timeout(Duration::from_millis(400), socket.read_exact(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(socket.flush().await.is_err());
    assert!(socket.shutdown().await.is_err());
    assert!(
        socket
            .write_vectored(&[std::io::IoSlice::new(b"Late")])
            .await
            .is_err()
    );
}
#[tokio::test]
async fn private_route_permission_pauses_then_renews_without_resetting_bytes() {
    let (mut reader, relay) = tokio::io::duplex(32768);
    let (service, mut destination) = tokio::io::duplex(32768);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let gate = Gate::new(start);
    let task = tokio::spawn(forward_guarded(
        relay,
        service,
        Limits {
            bytes: 16384,
            duration_ms: 2000,
            idle_ms: 1000,
        },
        gate.clone(),
        start + 2000,
    ));
    tokio::task::yield_now().await;
    assert!(
        !gate.demanded(),
        "idle reads must not renew an expired proof"
    );
    reader.write_all(&[1; 10000]).await.unwrap();
    let mut first = [0; 1];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(30),
            destination.read_exact(&mut first)
        )
        .await
        .is_err()
    );
    assert!(
        gate.demanded(),
        "buffered forwarding must request fresh permission"
    );
    gate.renew(start + 2000).unwrap();
    let mut received = [0; 10000];
    destination.read_exact(&mut received).await.unwrap();
    assert_eq!(received, [1; 10000]);
    tokio::task::yield_now().await;
    assert!(!gate.demanded(), "completed writes must return to idle");
    gate.renew(start + 3000).unwrap();
    destination.write_all(&[2; 10000]).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(!gate.demanded());
}
#[tokio::test]
async fn private_route_cancelled_raw_write_requests_only_one_renewal() {
    let (socket, _peer) = tokio::io::duplex(128);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let (mut socket, boundary) = Transport::new(socket, start + 2000);
    let gate = Gate::new(start);
    boundary.arm_renewable(gate.clone(), start + 2000).unwrap();
    let mut write = Box::pin(socket.write_all(b"Cancelled ciphertext"));
    std::future::poll_fn(|cx| {
        assert!(write.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(gate.demanded());
    // Demand predates the wait: Notify must retain the wake while the level remains set.
    tokio::time::timeout(Duration::from_millis(100), gate.signal().notified())
        .await
        .unwrap();
    drop(write);
    let expires = crate::authority_challenge::boot_time_ms().unwrap() + 50;
    gate.renew(expires).unwrap();
    assert!(!gate.demanded());
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        !gate.demanded(),
        "a cancelled TLS future must not retain activity"
    );
    for shutdown in [false, true] {
        let mut operation: std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<()>> + '_>,
        > = if shutdown {
            Box::pin(socket.shutdown())
        } else {
            Box::pin(socket.flush())
        };
        std::future::poll_fn(|cx| {
            assert!(operation.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(gate.demanded());
        drop(operation);
    }
    gate.close();
    assert!(!gate.demanded());
    assert!(socket.flush().await.is_err());
}
#[tokio::test]
async fn private_route_permission_renewal_never_extends_original_deadline() {
    let (mut reader, relay) = tokio::io::duplex(128);
    let (service, mut destination) = tokio::io::duplex(128);
    let start = crate::authority_challenge::boot_time_ms().unwrap();
    let gate = Gate::new(start);
    let task = tokio::spawn(forward_guarded(
        relay,
        service,
        Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 1000,
        },
        gate.clone(),
        start + 150,
    ));
    reader.write_all(b"Bounded").await.unwrap();
    gate.renew(start + 5000).unwrap();
    destination.read_exact(&mut [0; 7]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(600), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(destination.read(&mut [0; 1]).await.unwrap(), 0);
}
#[tokio::test]
async fn private_route_permission_close_cancels_backpressured_write() {
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 5000;
    let gate = Gate::new(deadline);
    let permission = gate.clone();
    let task = tokio::spawn(async move {
        guarded_send(
            &mut writer,
            b"Buffered sensitive reply",
            &permission,
            deadline,
            5000,
        )
        .await
    });
    // A one-byte buffer proves the frame is still backpressured after its first byte.
    reader.read_exact(&mut [0; 1]).await.unwrap();
    assert!(gate.demanded());
    gate.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(gate.renew(deadline).is_err());
    assert!(!gate.demanded());
}
#[tokio::test]
async fn closed_reader_rejects_response_and_ends_duplex() {
    let (mut reader, relay) = tokio::io::duplex(128);
    let (service, mut destination) = tokio::io::duplex(128);
    let task = tokio::spawn(forward(
        relay,
        service,
        Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 500,
        },
    ));
    reader.write_all(b"opaque").await.unwrap();
    let mut bytes = [0; 6];
    destination.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"opaque");
    drop(reader);
    // EOF alone can be a request half-close. A response to a fully closed
    // reader fails and terminates the remaining direction.
    assert_eq!(destination.read(&mut bytes).await.unwrap(), 0);
    destination.write_all(b"unread response").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(destination.read(&mut bytes).await.unwrap(), 0);
}
#[tokio::test]
async fn opaque_directions_share_one_byte_budget() {
    let (mut reader, relay) = tokio::io::duplex(32768);
    let (service, mut destination) = tokio::io::duplex(32768);
    let task = tokio::spawn(forward(
        relay,
        service,
        Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 500,
        },
    ));
    reader.write_all(&[1; 10000]).await.unwrap();
    destination.read_exact(&mut [0; 10000]).await.unwrap();
    destination.write_all(&[2; 10000]).await.unwrap();
    assert!(task.await.unwrap().is_err());
}
