// SPDX-License-Identifier: MIT
// Queued checks interleave with bounded, fair endpoint lifecycle work.
use super::*;
use std::task::Poll;

fn check(ready: &Ready, request: &Request) -> checks::Check {
    let (reply, _receipt) = tokio::sync::oneshot::channel();
    checks::Check {
        request: request.clone(),
        ready: Arc::new(ready.clone()),
        connected: Arc::new(AtomicBool::new(true)),
        cancelled: Arc::new(AtomicBool::new(false)),
        reply,
        timing: None,
    }
}

#[tokio::test]
async fn check_arriving_during_admission_runs_before_ready_cleanup() {
    let (_, _, ready, request) = fixture();
    let (sender, mut checks) = mpsc::channel(control::MAXIMUM_PENDING);
    let mut schedule = Schedule::default();
    assert_eq!(
        schedule.poll(|class| match class {
            Dispatch::Handshake => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Handshake)
    );
    // The selected admission runs synchronously. The original check arrives
    // before it returns, while the next independent cleanup is already ready.
    sender.try_send(check(&ready, &request)).unwrap();
    let selected = schedule
        .next(|class, cx| match class {
            Dispatch::Check => checks.poll_recv(cx).map(|value| {
                let original = value.unwrap();
                assert_eq!(original.request, request);
                assert!(!original.cancelled.load(Ordering::Acquire));
                class
            }),
            Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        })
        .await;
    assert_eq!(selected, Dispatch::Check);
    assert_eq!(sender.capacity(), control::MAXIMUM_PENDING);
    assert_eq!(
        schedule.poll(|class| match class {
            Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Close)
    );
}

#[tokio::test]
async fn sustained_checks_preserve_every_non_check_turn() {
    let (_, _, ready, request) = fixture();
    let (sender, mut checks) = mpsc::channel(control::MAXIMUM_PENDING);
    sender.try_send(check(&ready, &request)).unwrap();
    let mut admissions = JoinSet::new();
    for _ in 0..2 {
        let (completed, completion) = tokio::sync::oneshot::channel();
        admissions.spawn(async move {
            completed.send(()).unwrap();
            17
        });
        tokio::time::timeout(Duration::from_secs(1), completion)
            .await
            .unwrap()
            .unwrap();
    }
    let mut schedule = Schedule::default();
    // Exhaust the task budget: the finite selector must still see real queued
    // checks and completed admissions before an always-ready maintenance class.
    for _ in 0..128 {
        if !tokio::task::coop::has_budget_remaining() {
            break;
        }
        tokio::task::consume_budget().await;
    }
    assert!(!tokio::task::coop::has_budget_remaining());
    let mut turns = Vec::new();
    for _ in 0..4 * DISPATCH.len() {
        let selected = schedule
            .next(|class, cx| match class {
                Dispatch::Check => checks.poll_recv(cx).map(|value| {
                    assert_eq!(value.unwrap().request, request);
                    class
                }),
                Dispatch::Handshake => admissions.poll_join_next(cx).map(|value| {
                    assert_eq!(value.unwrap().unwrap(), 17);
                    class
                }),
                _ => Poll::Ready(class),
            })
            .await;
        if selected == Dispatch::Check {
            sender.try_send(check(&ready, &request)).unwrap();
        }
        turns.push(selected);
    }
    let expected: Vec<_> = DISPATCH
        .into_iter()
        .cycle()
        .take(2 * DISPATCH.len())
        .flat_map(|class| [class, Dispatch::Check])
        .collect();
    assert_eq!(turns, expected);
    assert_eq!(checks.try_recv().unwrap().request, request);
    assert_eq!(sender.capacity(), control::MAXIMUM_PENDING);
    assert!(admissions.is_empty());
}

#[tokio::test]
async fn check_only_work_preserves_expired_cancelled_and_disconnected_requests() {
    let (_, _, ready, request) = fixture();
    let (sender, mut checks) = mpsc::channel(control::MAXIMUM_PENDING);
    for index in 0..control::MAXIMUM_PENDING {
        let mut original = check(&ready, &request);
        match index {
            0 => original.request.caller_deadline_boot_ms = 0,
            1 => original.cancelled.store(true, Ordering::Release),
            2 => original.connected.store(false, Ordering::Release),
            _ => {}
        }
        sender.try_send(original).unwrap();
    }
    let mut schedule = Schedule::default();
    for index in 0..control::MAXIMUM_PENDING {
        let selected = tokio::time::timeout(
            Duration::from_secs(1),
            schedule.next(|class, cx| match class {
                Dispatch::Check => checks.poll_recv(cx).map(|value| value.unwrap()),
                _ => Poll::Pending,
            }),
        )
        .await
        .unwrap();
        let mut expected = request.clone();
        if index == 0 {
            expected.caller_deadline_boot_ms = 0;
        }
        assert_eq!(selected.request, expected);
        assert_eq!(selected.cancelled.load(Ordering::Acquire), index == 1);
        assert_eq!(selected.connected.load(Ordering::Acquire), index != 2);
    }
    assert_eq!(sender.capacity(), control::MAXIMUM_PENDING);
    assert!(schedule.poll::<()>(|_| Poll::Pending).is_pending());
}
