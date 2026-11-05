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
        _slot: Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING))
            .try_acquire_owned()
            .unwrap(),
    }
}

#[tokio::test]
async fn check_arriving_during_admission_runs_before_ready_cleanup() {
    let (_, _, ready, request) = fixture();
    let (sender, mut checks) = mpsc::channel(control::MAXIMUM_PENDING);
    let mut schedule = Schedule::default();
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Handshake => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Handshake)
    );
    // The selected admission runs synchronously. The original check arrives
    // before it returns, while the next independent cleanup is already ready.
    sender.try_send(check(&ready, &request)).unwrap();
    let selected = schedule
        .next(false, |class, cx| match class {
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
        schedule.poll(false, |class| match class {
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
            .next(false, |class, cx| match class {
                Dispatch::Check => checks.poll_recv(cx).map(|value| {
                    assert_eq!(value.unwrap().request, request);
                    class
                }),
                Dispatch::Handshake => admissions.poll_join_next(cx).map(|value| {
                    assert_eq!(value.unwrap().unwrap(), 17);
                    class
                }),
                Dispatch::Complete => Poll::Pending,
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
            schedule.next(false, |class, cx| match class {
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
    assert!(schedule.poll::<()>(false, |_| Poll::Pending).is_pending());
}

#[test]
fn read_round_prevents_lifecycle_floor_change_between_issue_and_completion() {
    use crate::authority_floor::tests::{certified, prepare, read::Read, setup};
    for protect_round in [false, true] {
        let (_directory, sample, mut session, mut store) = setup();
        let observed = sample.observe().unwrap();
        let sample = crate::authority_challenge::ClockHealth::new(
            observed.wall_ms + 500,
            observed.boot_ms + 500,
            observed.boot_ms + 30_500,
            100,
        )
        .unwrap()
        .frozen();
        let query = Read::new(&store, &mut session, sample);
        let issued_floor = store.prefix().clone();
        let mut schedule = Schedule::default();
        // This is the actor state immediately after dispatching a fresh-read issue.
        assert_eq!(
            schedule.poll(false, |class| match class {
                Dispatch::Check => Poll::Ready(class),
                _ => Poll::Pending,
            }),
            Poll::Ready(Dispatch::Check)
        );
        let selected = schedule.poll(protect_round, |class| match class {
            Dispatch::Close | Dispatch::Check => Poll::Ready(class),
            _ => Poll::Pending,
        });
        if !protect_round {
            // Reproduce the old interleaving with an actual certified lifecycle
            // effect: its new floor makes the earlier fresh request unusable.
            assert_eq!(selected, Poll::Ready(Dispatch::Close));
            let (pending, operation) = prepare(&mut store, sample);
            let verified = certified(
                &store,
                &mut session,
                sample,
                pending.signed(),
                &operation,
                None,
            );
            store
                .accept(verified, &mut session, sample, 0)
                .unwrap()
                .perform(
                    &mut store,
                    &mut session,
                    sample,
                    1,
                    |_| Ok(()),
                    |_, _| Ok(()),
                )
                .unwrap();
            assert!(store.prefix().height() > issued_floor.height());
            let error = store
                .accept_read(
                    query.verify(&store),
                    &mut session,
                    sample,
                    0,
                    |_, _| -> anyhow::Result<()> { panic!("interleaved stale read was accepted") },
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("below the accepted"),
                "{error:#}"
            );
            continue;
        }
        // An unfinished worker does not yield the authority actor to lifecycle
        // work or allow a later arrival to prepare another set of gates.
        assert!(selected.is_pending());
        assert_eq!(store.prefix(), &issued_floor);
        assert_eq!(
            schedule.poll(true, |class| match class {
                Dispatch::Complete | Dispatch::Close | Dispatch::Check => Poll::Ready(class),
                _ => Poll::Pending,
            }),
            Poll::Ready(Dispatch::Complete)
        );
        store
            .accept_read(query.verify(&store), &mut session, sample, 0, |_, _| Ok(()))
            .unwrap();
        // Once the fixed round drains, lifecycle wins over continuous new checks.
        assert_eq!(
            schedule.poll(false, |class| match class {
                Dispatch::Close | Dispatch::Check => Poll::Ready(class),
                _ => Poll::Pending,
            }),
            Poll::Ready(Dispatch::Close)
        );
    }
}

#[test]
fn captured_check_cohort_is_finite_and_preserves_original_control_and_ends() {
    let (_, _, ready, request) = fixture();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let first = check(&ready, &request);
    for index in 1..=control::MAXIMUM_PENDING {
        let mut next = check(&ready, &request);
        next.request.nonce = [index as u8; 32];
        sender.try_send(next).unwrap();
    }
    let cohort = checks::cohort(first, &mut queue);
    assert_eq!(cohort.len(), control::MAXIMUM_PENDING);
    for (index, member) in cohort.iter().enumerate() {
        assert_eq!(
            member.request.caller_started_boot_ms,
            request.caller_started_boot_ms
        );
        assert_eq!(
            member.request.caller_deadline_boot_ms,
            request.caller_deadline_boot_ms
        );
        assert_eq!(
            member.request.control_generation,
            request.control_generation
        );
        if index != 0 {
            assert_eq!(member.request.nonce, [index as u8; 32]);
        }
    }
    // Later work stays queued even when a current member is cancelled or disconnects.
    cohort[0].cancelled.store(true, Ordering::Release);
    cohort[1].connected.store(false, Ordering::Release);
    assert_eq!(
        queue.try_recv().unwrap().request.nonce,
        [control::MAXIMUM_PENDING as u8; 32]
    );
    assert!(queue.try_recv().is_err());
}

#[test]
fn pending_round_completion_precedes_a_long_lifecycle_turn_and_preserves_gate_tail() {
    let (_, _, ready, request) = fixture();
    let check = check(&ready, &request);
    let now = request.caller_started_boot_ms;
    let endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 500),
        accepted_at: Some(now),
        renewals: 0,
    };
    let live = BTreeMap::from([(
        request.session.id,
        LiveStream {
            reference: request.session.clone(),
            proof_digest: [91; 32],
            gate: route_io::Gate::new(now + 2000),
            accepted_at: now,
            retry_after: 0,
            renewal_turn: 0,
            forwarding: Arc::new(Forwarding {
                deadline: request.caller_deadline_boot_ms,
                established: AtomicBool::new(true),
                finished: AtomicBool::new(false),
            }),
        },
    )]);
    let mut schedule = Schedule::default();
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Check => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Check)
    );
    assert_eq!(
        schedule.poll(true, |class| match class {
            Dispatch::Complete | Dispatch::Handshake => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Complete)
    );
    assert!(check.completion_stream(&live, &endpoint, now + 200).is_ok());
    // A long intervening admission can consume a roughly 500 ms gate tail.
    // The gate still rejects at that time: scheduling never extends permission.
    assert!(
        check
            .completion_stream(&live, &endpoint, now + 980)
            .is_err()
    );
    assert_eq!(endpoint.gate.expiry().unwrap(), now + 500);
}

#[test]
fn unused_slots_issue_without_floor_mutation_then_completion_closes_admission() {
    use crate::authority_floor::tests::{read::Read, setup};
    let (_directory, sample, mut session, mut store) = setup();
    let first = Read::new(&store, &mut session, sample);
    let prefix = store.prefix().clone();
    let now = sample.observe().unwrap();
    let mut schedule = Schedule::default();
    schedule.begin_round(1);
    schedule.initial_issue(now.boot_ms + 1000);
    assert_eq!(
        schedule.poll(true, |class| match class {
            Dispatch::Fill | Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Fill)
    );
    assert_eq!(
        schedule.admit_fill(now.boot_ms + 10),
        Some(now.boot_ms + 1000)
    );
    let later = crate::authority_challenge::ClockHealth::new(
        now.wall_ms + 10,
        now.boot_ms + 10,
        now.boot_ms + 30_010,
        100,
    )
    .unwrap()
    .frozen();
    let second = Read::new(&store, &mut session, later);
    assert_eq!(
        store.prefix(),
        &prefix,
        "challenge issuance cannot publish authority"
    );
    assert!(store.resume_ordinary().unwrap().is_none());
    assert!(store.resume_fence().unwrap().is_none());
    assert_eq!(
        schedule.poll(true, |class| match class {
            Dispatch::Complete | Dispatch::Fill | Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Complete)
    );
    assert!(schedule.fill_end(now.boot_ms + 20).is_none());
    store
        .accept_read(first.verify(&store), &mut session, later, 0, |_, _| Ok(()))
        .unwrap();
    // A second already-issued read still validates against the actor's current
    // floor. Slot filling does not retain the old floor as an authority cache.
    store
        .accept_read(second.verify(&store), &mut session, later, 0, |_, _| Ok(()))
        .unwrap();
    assert_eq!(
        schedule.poll(true, |class| match class {
            Dispatch::Fill | Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Pending
    );
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Check | Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Close)
    );
}

#[test]
fn late_admissions_share_fixed_round_end_and_never_refill_finished_slots() {
    let mut schedule = Schedule::default();
    schedule.begin_round(1);
    schedule.initial_issue(500);
    for expected in 2..=control::MAXIMUM_PENDING {
        assert_eq!(schedule.admit_fill(100 + expected as u64), Some(500));
        assert_eq!(schedule.round_admissions, expected);
        assert_eq!(schedule.round_end, 500);
    }
    assert!(schedule.admit_fill(200).is_none());
    assert!(
        schedule
            .poll(true, |class| match class {
                Dispatch::Fill => Poll::Ready(class),
                _ => Poll::Pending,
            })
            .is_pending()
    );
    schedule.begin_round(1);
    schedule.initial_issue(500);
    assert!(schedule.admit_fill(500).is_none());
    assert_eq!(schedule.round_admissions, 1);
    assert_eq!(
        schedule.poll(true, |class| match class {
            Dispatch::Complete | Dispatch::Fill => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Complete)
    );
    assert!(
        schedule.admit_fill(400).is_none(),
        "completion closes even unused slots"
    );
}

#[tokio::test]
async fn deferred_head_keeps_original_permit_and_precedes_later_arrivals_after_lifecycle() {
    let (_, _, ready, request) = fixture();
    let slots = Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING));
    let mut held = check(&ready, &request);
    held._slot = slots.clone().try_acquire_owned().unwrap();
    let original = held.request.clone();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    for nonce in 1..control::MAXIMUM_PENDING {
        let mut next = check(&ready, &request);
        next.request.nonce = [nonce as u8; 32];
        next._slot = slots.clone().try_acquire_owned().unwrap();
        sender.try_send(next).unwrap();
    }
    assert!(slots.clone().try_acquire_owned().is_err());
    let mut schedule = Schedule::default();
    schedule.begin_round(1);
    schedule.initial_issue(request.caller_deadline_boot_ms);
    schedule.admit_fill(request.caller_started_boot_ms).unwrap();
    // Readiness is deferred until workers have drained, rather than repeatedly
    // dequeuing the head or letting later requests bypass its original permit.
    schedule.round_open = false;
    assert!(schedule.poll(true, |_| Poll::<()>::Pending).is_pending());
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Check | Dispatch::Own => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Own)
    );
    held.cancelled.store(true, Ordering::Release);
    let cohort = checks::cohort(held, &mut queue);
    assert_eq!(cohort[0].request, original);
    assert!(cohort[0].cancelled.load(Ordering::Acquire));
    assert_eq!(cohort.len(), control::MAXIMUM_PENDING);
    assert!(slots.clone().try_acquire_owned().is_err());
    drop(cohort);
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING);
}

#[test]
fn retained_close_recovers_before_original_fifo_head_enters_a_fresh_round() {
    let (_, _, ready, request) = fixture();
    let now = request.caller_started_boot_ms;
    let slots = Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING));
    let mut first = check(&ready, &request);
    first._slot = slots.clone().try_acquire_owned().unwrap();
    let mut held = HeldCheck::ready(first);
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    for nonce in 1..control::MAXIMUM_PENDING {
        let mut next = check(&ready, &request);
        next.request.nonce = [nonce as u8; 32];
        next._slot = slots.clone().try_acquire_owned().unwrap();
        sender.try_send(next).unwrap();
    }
    let mut close =
        PendingClose::completed(prepared_stream(now + 1000, now + 30_000), now, 10_000, 0, 0);
    let original_close = (close.reference.clone(), close.proof_digest, close.deadline);
    let original_ordinary = wire::digest(b"Exact retained signed close, including nonce");
    let mut diagnostics = 0;
    assert!(!close.attempt_with(
        || now,
        &mut diagnostics,
        |_, _, _| { anyhow::bail!("exact ordinary outcome remains unknown") }
    ));
    assert!(held.defer_close(now, Some(original_ordinary), close.deadline));
    assert_eq!(
        held.close,
        Some((original_ordinary, request.caller_deadline_boot_ms))
    );
    assert!(held.waiting(now, Some(original_ordinary)));
    assert_eq!(slots.available_permits(), 0);
    let mut schedule = Schedule {
        check_turn: true,
        ..Schedule::default()
    };
    // A held head is not repeatedly dispatched during cleanup backoff. Later
    // queue entries remain bounded behind it while lifecycle turns stay fair.
    for expected in DISPATCH {
        assert_eq!(
            schedule.poll(false, |class| match class {
                Dispatch::Check | Dispatch::Complete => Poll::Pending,
                _ => Poll::Ready(class),
            }),
            Poll::Ready(expected)
        );
    }
    assert_eq!(queue.len(), control::MAXIMUM_PENDING - 1);
    let retry_at = close.retry_after;
    assert!(close.attempt_with(
        || retry_at,
        &mut diagnostics,
        |reference, proof, end| {
            assert_eq!((reference.clone(), proof, end), original_close);
            Ok(())
        }
    ));
    assert!(!held.waiting(now + READ_RETRY_MS, None));
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Check | Dispatch::Close => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Check)
    );
    let cohort = checks::cohort(held.into_check(now + READ_RETRY_MS).unwrap(), &mut queue);
    assert_eq!(cohort[0].request, request);
    assert_eq!(cohort.len(), control::MAXIMUM_PENDING);
    assert!(queue.is_empty());
    // Recovery supplied no receipt or challenge. The original request still
    // requires preparation and the issue/finish ordinary/fence guards.
    schedule.begin_round(cohort.len());
    assert_eq!(schedule.round_admissions, control::MAXIMUM_PENDING);
    assert_eq!(
        schedule.poll(false, |class| match class {
            Dispatch::Own | Dispatch::Check => Poll::Ready(class),
            _ => Poll::Pending,
        }),
        Poll::Ready(Dispatch::Own)
    );
    drop(cohort);
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING);
}

#[test]
fn close_wait_preserves_cancellation_control_loss_exact_operation_and_original_ends() {
    let (_, _, ready, request) = fixture();
    let now = request.caller_started_boot_ms;
    for mode in 0..7 {
        let mut held = HeldCheck::ready(check(&ready, &request));
        let (reply, mut receiver) = tokio::sync::oneshot::channel();
        held.check.reply = reply;
        let end = now + 1000;
        assert!(held.defer_close(now, Some([31; 32]), end));
        let mut at = now + 1;
        let mut ordinary = Some([31; 32]);
        match mode {
            0 => held.check.cancelled.store(true, Ordering::Release),
            1 => held.check.connected.store(false, Ordering::Release),
            2 => at = end,
            3 => at = request.caller_deadline_boot_ms,
            4 => ordinary = Some([32; 32]),
            5 => ordinary = None,
            6 => held.check.request.control_generation += 1,
            _ => unreachable!(),
        }
        assert!(!held.waiting(at, ordinary));
        assert!(!held.defer_close(at, ordinary, end + 5000));
        assert_eq!(held.close, Some(([31; 32], end)));
        if mode == 2 || mode == 3 {
            assert!(held.into_check(at).is_none());
            let receipt = receiver.try_recv().unwrap();
            assert_eq!(receipt.request, request);
            assert_eq!(
                receipt.disposition,
                if mode == 3 {
                    Disposition::Expired
                } else {
                    Disposition::Unavailable
                }
            );
            assert!(receipt.authority.is_none());
        } else {
            let checked = held.into_check(at).unwrap();
            assert_eq!(checked.request.nonce, request.nonce);
            assert_eq!(checked.request.action_digest, request.action_digest);
            assert_eq!(
                checked.request.caller_deadline_boot_ms,
                request.caller_deadline_boot_ms
            );
        }
    }
}
