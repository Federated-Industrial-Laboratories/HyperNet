// SPDX-License-Identifier: MIT
// Application checks retain current stream identity and original authority deadlines.
use super::*;
use crate::authority_domains::streams::control::{
    self, Cancel, Challenge, Disposition, IncomingPath, Privacy, Ready, Receipt, Request,
};

include!("../../Support/Routing/ApplicationStreamChecks.rs");

fn prepared_stream(expiry: u64, deadline: u64) -> LiveStream {
    let (_, _, _, request) = fixture();
    LiveStream {
        reference: request.session,
        gate: route_io::Gate::new(expiry),
        accepted_at: crate::authority_challenge::boot_time_ms().unwrap(),
        retry_after: 0,
        forwarding: Arc::new(Forwarding {
            deadline,
            established: AtomicBool::new(true),
            finished: AtomicBool::new(false),
        }),
    }
}

#[test]
fn completed_stream_burst_yields_to_due_renewals_then_closes_without_starvation() {
    let now = crate::authority_challenge::boot_time_ms().unwrap() + 1000;
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 150),
        accepted_at: Some(now - 1000),
        renewals: 0,
    };
    let _activity = endpoint.gate.activity().unwrap();
    let mut live = BTreeMap::new();
    for n in 0..4 {
        let stream = prepared_stream(now + 10, now + 10_000);
        stream.forwarding.finished.store(true, Ordering::Release);
        live.insert([n; 32], stream);
    }
    live.insert([9; 32], prepared_stream(now + 150, now + 10_000));
    assert_eq!(
        maintenance(now, &endpoint, &live, None, 100, 100).unwrap(),
        Maintenance::Own,
        "completed forwarding cannot outrank an already due endpoint renewal"
    );
    endpoint.gate.renew(now + 5000).unwrap();
    endpoint.accepted_at = Some(now);
    assert_eq!(
        maintenance(now, &endpoint, &live, None, 100, 100).unwrap(),
        Maintenance::Stream([9; 32]),
        "finished streams must not consume renewal turns"
    );
    let stream = live.get_mut(&[9; 32]).unwrap();
    stream.gate.renew(now + 5000).unwrap();
    stream.accepted_at = now;
    for n in 0..4 {
        let close = PendingClose::completed(live.remove(&[n; 32]).unwrap(), now, 1000);
        assert_eq!(
            maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
            Maintenance::Close,
            "fresh headroom must release each bounded close turn"
        );
        assert_eq!(close.deadline, now + 1000);
        assert_eq!(endpoint.gate.expiry().unwrap(), now + 5000);
        assert_eq!(live[&[9; 32]].gate.expiry().unwrap(), now + 5000);
    }
}

#[test]
fn pending_close_reserves_one_action_before_each_renewal_latest_start() {
    let now = crate::authority_challenge::boot_time_ms().unwrap() + 1000;
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 250),
        accepted_at: Some(now - 1000),
        renewals: 0,
    };
    let _activity = endpoint.gate.activity().unwrap();
    let mut live = BTreeMap::from([([9; 32], prepared_stream(now + 250, now + 10_000))]);
    assert_eq!(
        maintenance(now, &endpoint, &live, None, 100, 100).unwrap(),
        Maintenance::Wait
    );
    let close = PendingClose::completed(prepared_stream(now + 100, now + 10_000), now, 1000);
    assert_eq!(
        maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
        Maintenance::Own
    );
    assert_eq!(endpoint.gate.expiry().unwrap(), now + 250);
    endpoint.gate.renew(now + 5000).unwrap();
    endpoint.accepted_at = Some(now);
    assert_eq!(
        maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
        Maintenance::Stream([9; 32])
    );
    assert_eq!(live[&[9; 32]].gate.expiry().unwrap(), now + 250);
    let stream = live.get_mut(&[9; 32]).unwrap();
    stream.gate.renew(now + 5000).unwrap();
    stream.accepted_at = now;
    assert_eq!(
        maintenance(close.deadline, &endpoint, &live, Some(&close), 100, 100).unwrap(),
        Maintenance::Close,
        "an expired close gets its original failing attempt, not a renewed window"
    );
    assert_eq!(close.deadline, now + 1000);
}

#[test]
fn held_completion_closes_local_gate_and_keeps_its_existing_capacity_slot() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut live = BTreeMap::from([([1; 32], prepared_stream(now + 5000, now + 10_000))]);
    let gate = live[&[1; 32]].gate.clone();
    let reference = live[&[1; 32]].reference.clone();
    assert_eq!(occupied(7, 8, &live, None), 16);
    let close = PendingClose::completed(live.remove(&[1; 32]).unwrap(), now, 1000);
    assert!(
        gate.expiry().is_err(),
        "completed local bytes are fenced immediately"
    );
    assert_eq!(close.reference, reference);
    assert_eq!(close.deadline, now + 1000);
    assert_eq!(occupied(7, 8, &live, Some(&close)), 16);
    assert_eq!(occupied(7, 8, &live, None), 15);
}

#[test]
fn queued_check_prepares_both_gates_before_the_normal_renewal_timer() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let caller_end = now + 2000;
    let route_end = now + 1500;
    let old_endpoint = now + 250;
    let old_stream = now + 300;
    let budget = 10;
    assert!(now < refresh_at(old_endpoint, budget, None));
    assert!(now < refresh_at(old_stream, budget, Some(now)));
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(old_endpoint),
        accepted_at: None,
        renewals: 0,
    };
    let mut stream = prepared_stream(old_stream, route_end);
    let mut stream_renewals = 0;
    endpoint
        .prepare_check(caller_end.min(route_end), budget, |bound| {
            assert_eq!(bound, route_end);
            Ok(now + 1400)
        })
        .unwrap();
    stream
        .prepare_check(
            caller_end,
            budget,
            || false,
            |bound| {
                assert_eq!(bound, route_end);
                stream_renewals += 1;
                Ok(now + 1800)
            },
        )
        .unwrap();
    // The bounded work crosses both old gates, but uses only the fresh certified tails.
    std::thread::sleep(Duration::from_millis(350));
    let completed = crate::authority_challenge::boot_time_ms().unwrap();
    assert!(completed >= old_endpoint && completed >= old_stream);
    let read_end = caller_end
        .min(endpoint.gate.expiry().unwrap())
        .min(stream.check_deadline(completed).unwrap());
    assert!(completed < read_end);
    assert_eq!(read_end, now + 1400);
    assert_eq!(stream.forwarding.deadline, route_end);
    assert_eq!(stream.gate.expiry().unwrap(), route_end);
    assert_eq!(endpoint.renewals, 1);
    assert_eq!(
        stream_renewals, 1,
        "a shorter fresh permit must not cause a renewal loop"
    );
}

#[test]
fn check_preparation_keeps_original_deadline_before_and_after_renewal() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 1000),
        accepted_at: None,
        renewals: 0,
    };
    assert!(
        endpoint
            .prepare_check(now, 100, |_| panic!("expired check renewed endpoint"))
            .is_err()
    );
    let mut stream = prepared_stream(now + 1000, now + 2000);
    assert!(
        stream
            .prepare_check(
                now,
                100,
                || false,
                |_| panic!("expired check renewed stream")
            )
            .is_err()
    );

    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let old = now + 60;
    stream.gate.renew(old).unwrap();
    assert!(
        stream
            .prepare_check(
                now + 100,
                10,
                || false,
                |bound| {
                    assert_eq!(bound, now + 100);
                    std::thread::sleep(Duration::from_millis(110));
                    Ok(now + 1000)
                }
            )
            .is_err()
    );
    assert_eq!(
        stream.gate.expiry().unwrap(),
        old,
        "late renewal changed the gate"
    );
}

#[test]
fn check_preparation_does_not_revive_cancelled_or_completed_streams() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut stream = prepared_stream(now + 1000, now + 5000);
    assert!(
        stream
            .prepare_check(
                now + 2000,
                100,
                || true,
                |_| panic!("cancelled check renewed stream")
            )
            .is_err()
    );
    let cancelled = AtomicBool::new(false);
    let old = stream.gate.expiry().unwrap();
    assert!(
        stream
            .prepare_check(
                now + 2000,
                100,
                || cancelled.load(Ordering::Acquire),
                |_| {
                    cancelled.store(true, Ordering::Release);
                    Ok(now + 3000)
                }
            )
            .is_err()
    );
    assert_eq!(stream.gate.expiry().unwrap(), old);
    let forwarding = stream.forwarding.clone();
    assert!(
        stream
            .prepare_check(
                now + 2000,
                100,
                || false,
                |_| {
                    forwarding.finished.store(true, Ordering::Release);
                    Ok(now + 3000)
                }
            )
            .is_err()
    );
    assert_eq!(stream.gate.expiry().unwrap(), old);
    assert_eq!(stream.check_deadline(now), None);
}

#[test]
fn check_preparation_reuses_sufficient_headroom_and_preserves_refusal() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 5000),
        accepted_at: Some(now),
        renewals: 0,
    };
    let mut stream = prepared_stream(now + 5000, now + 10000);
    endpoint
        .prepare_check(now + 1000, 10, |_| panic!("current endpoint renewed"))
        .unwrap();
    stream
        .prepare_check(
            now + 1000,
            10,
            || false,
            |_| panic!("current stream renewed"),
        )
        .unwrap();
    assert_eq!(endpoint.renewals, 0);
    assert!(
        endpoint
            .prepare_check(now + 6000, 10, |_| anyhow::bail!("authority refused"))
            .is_err()
    );
    assert!(
        stream
            .prepare_check(
                now + 6000,
                10,
                || false,
                |_| anyhow::bail!("authority refused")
            )
            .is_err()
    );
    assert_eq!(endpoint.gate.expiry().unwrap(), now + 5000);
    assert_eq!(stream.gate.expiry().unwrap(), now + 5000);
}

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
