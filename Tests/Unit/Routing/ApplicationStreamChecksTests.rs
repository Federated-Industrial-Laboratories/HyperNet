// SPDX-License-Identifier: MIT
use super::*;
use crate::authority_domains::streams::control::{
    self, Cancel, Challenge, Disposition, IncomingPath, Privacy, Ready, Receipt, Request,
};

include!("../../Support/Routing/ApplicationStreamChecks.rs");

#[test]
fn completion_invalidates_stream_before_join_set_is_polled() {
    let (_, _, _, request) = fixture();
    let status = Arc::new(Forwarding {
        deadline: 5000,
        established: AtomicBool::new(false),
        finished: AtomicBool::new(false),
    });
    let stream = LiveStream {
        reference: request.session,
        gate: route_io::Gate::new(4000),
        accepted_at: 100,
        retry_after: 0,
        forwarding: status.clone(),
    };
    assert_eq!(stream.check_deadline(100), None);
    status.established.store(true, Ordering::Release);
    assert_eq!(stream.check_deadline(100), Some(4000));
    assert_eq!(stream.check_deadline(4000), None);
    drop(ForwardingCompletion(status));
    assert_eq!(stream.check_deadline(100), None);
}

#[tokio::test]
async fn check_exchange_correlates_receipts_and_rejects_second_pending_session() {
    let (binding, key, ready, request) = fixture();
    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let b = binding.clone();
    let privacy = ready.privacy.clone();
    let task = tokio::spawn(async move {
        checks::exchange(endpoint, Arc::new(ready), &b, &key, &sender).await
    });
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let check = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(check.request, request);
    let mut second = request.clone();
    second.nonce = [12; 32];
    route_io::send(&mut companion, &control::encode(&second).unwrap())
        .await
        .unwrap();
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        route_io::receive(&mut companion, control::MAXIMUM_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let receipt: Receipt = control::verify(&bytes, &binding).unwrap();
    assert_eq!(receipt.request, second);
    assert_eq!(receipt.disposition, Disposition::Unavailable);
    assert!(queue.try_recv().is_err());
    check
        .reply
        .send(checks::unavailable(
            request.clone(),
            privacy,
            Disposition::NotActive,
        ))
        .unwrap();
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        route_io::receive(&mut companion, control::MAXIMUM_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let receipt: Receipt = control::verify(&bytes, &binding).unwrap();
    assert_eq!(receipt.request, request);
    assert_eq!(receipt.disposition, Disposition::NotActive);
    drop(companion);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!check.connected.load(Ordering::Acquire));
}

#[tokio::test]
async fn cancellation_and_disconnect_invalidate_queued_and_executing_checks() {
    let (binding, key, ready, request) = fixture();
    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let task = tokio::spawn(async move {
        checks::exchange(endpoint, Arc::new(ready), &binding, &key, &sender).await
    });
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let check = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    route_io::send(
        &mut companion,
        &control::encode(&Cancel { request }).unwrap(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !check.cancelled.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(check.connected.load(Ordering::Acquire));
    drop(companion);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!check.connected.load(Ordering::Acquire));
}
