// SPDX-License-Identifier: MIT
// Unit tests for RouteDuplex.
use super::*;
#[tokio::test]
async fn quiet_request_half_survives_response_activity_and_half_close() {
    let (mut caller, left) = tokio::io::duplex(128);
    let (right, mut service) = tokio::io::duplex(128);
    let limits = Limits {
        bytes: 16384,
        duration_ms: 3000,
        idle_ms: 200,
    };
    let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 3000;
    let task = tokio::spawn(forward(left, right, limits, Gate::new(deadline), deadline));
    caller.write_all(b"request").await.unwrap();
    let mut request = [0; 7];
    service.read_exact(&mut request).await.unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(80)).await;
        service.write_all(b"a").await.unwrap();
        let mut b = [0];
        caller.read_exact(&mut b).await.unwrap();
    }
    caller.shutdown().await.unwrap();
    let mut end = [0];
    assert_eq!(service.read(&mut end).await.unwrap(), 0);
    service.write_all(b"tail").await.unwrap();
    service.shutdown().await.unwrap();
    let mut tail = Vec::new();
    caller.read_to_end(&mut tail).await.unwrap();
    assert_eq!(tail, b"tail");
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn revoked_stream_ends_a_blocked_reader_and_writer() {
    let (mut caller, left) = tokio::io::duplex(16);
    let (right, _service) = tokio::io::duplex(16);
    let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 3000;
    let gate = Gate::new(deadline);
    let task = tokio::spawn(forward(
        left,
        right,
        Limits {
            bytes: 16384,
            duration_ms: 3000,
            idle_ms: 1000,
        },
        gate.clone(),
        deadline,
    ));
    let producer = tokio::spawn(async move { caller.write_all(&[1; 16384]).await });
    tokio::task::yield_now().await;
    gate.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(producer.await.unwrap().is_err());
}
