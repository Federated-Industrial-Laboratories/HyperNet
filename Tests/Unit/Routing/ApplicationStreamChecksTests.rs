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
        proof_digest: [91; 32],
        gate: route_io::Gate::new(expiry),
        accepted_at: crate::authority_challenge::boot_time_ms().unwrap(),
        retry_after: 0,
        renewal_turn: 0,
        forwarding: Arc::new(Forwarding {
            deadline,
            established: AtomicBool::new(true),
            finished: AtomicBool::new(false),
        }),
    }
}

#[test]
fn stalled_diagnostic_sink_does_not_hold_producers_or_retime_records() {
    use std::{
        io,
        sync::{Mutex, mpsc},
    };
    struct Stalled {
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
        records: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl io::Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
                self.release
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            }
            self.records.lock().unwrap().push(bytes.to_vec());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (entered, waiting) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let records = Arc::new(Mutex::new(Vec::new()));
    let (sender, writer) = diagnostic_writer(Stalled {
        entered: Some(entered),
        release: held,
        records: records.clone(),
    })
    .unwrap();
    let mut first = DiagnosticLine::new();
    std::fmt::write(&mut first, format_args!("sample=1 bootMs=100\n")).unwrap();
    queue_diagnostic(&sender, first);
    let stalled = waiting.recv_timeout(Duration::from_secs(1));
    let producer_sender = sender.clone();
    let (finished, completion) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        for sample in 2..=1025 {
            let mut line = DiagnosticLine::new();
            std::fmt::write(&mut line, format_args!("sample={sample} bootMs=200\n")).unwrap();
            queue_diagnostic(&producer_sender, line);
        }
        let mut oversized = DiagnosticLine::new();
        assert!(
            std::fmt::Write::write_str(&mut oversized, &"x".repeat(DIAGNOSTIC_BYTES + 1)).is_err()
        );
        queue_diagnostic(&producer_sender, oversized);
        let _ = finished.send(());
    });
    let produced_without_sink = completion.recv_timeout(Duration::from_millis(500));
    // Always release and join the finite test writer before checking producer progress.
    let _ = release.send(());
    producer.join().unwrap();
    drop(sender);
    writer.join().unwrap();
    assert!(stalled.is_ok());
    assert!(
        produced_without_sink.is_ok(),
        "diagnostic producer waited for the sink"
    );
    let records = records.lock().unwrap();
    assert_eq!(records.len(), DIAGNOSTIC_QUEUE + 1);
    assert_eq!(records[0], b"sample=1 bootMs=100\n");
    assert!(
        records
            .iter()
            .skip(1)
            .all(|line| line.ends_with(b"bootMs=200\n"))
    );
    assert!(records.iter().all(|line| line.len() <= DIAGNOSTIC_BYTES));
    let (closed, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    queue_diagnostic(&closed, DiagnosticLine::new());
}

#[test]
fn timing_caps_are_independent_and_do_not_reset_when_exhausted() {
    let checks = AtomicU64::new(0);
    let actor = AtomicU64::new(0);
    let session = AtomicU64::new(0);
    for expected in 1..=256 {
        assert_eq!(Timing::counted(7, &checks, 256).sample, Some(expected));
    }
    for _ in 0..4 {
        assert!(Timing::counted(7, &checks, 256).sample.is_none());
    }
    for expected in 1..=64 {
        assert_eq!(Timing::counted(7, &actor, 64).sample, Some(expected));
    }
    assert!(Timing::counted(7, &actor, 64).sample.is_none());
    assert_eq!(Timing::counted(7, &session, 64).sample, Some(1));
    assert_eq!(checks.load(Ordering::Relaxed), 256);
    assert_eq!(actor.load(Ordering::Relaxed), 64);
}

#[test]
fn actor_diagnostics_preserve_single_execution_and_typed_failure() {
    let mut effects = 0;
    let value = observed(Activity::StreamAdmission, 123, None, || {
        effects += 1;
        Ok(17)
    })
    .unwrap();
    assert_eq!((value, effects), (17, 1));
    let error = observed(Activity::Cleanup, 123, None, || -> Result<()> {
        effects += 1;
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
    })
    .unwrap_err();
    assert_eq!(effects, 2);
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn check_diagnostics_keep_early_outcomes_bounds_and_redaction_with_failed_sink() {
    struct Closed;
    impl std::fmt::Write for Closed {
        fn write_str(&mut self, _: &str) -> std::fmt::Result {
            Err(std::fmt::Error)
        }
    }
    let (_, _, ready, mut request) = fixture();
    request.local_connection_id = "private-connection-must-not-appear".into();
    request.caller_started_boot_ms = 100;
    request.caller_deadline_boot_ms = 200;
    let (reply, _) = tokio::sync::oneshot::channel();
    let check = checks::Check {
        request: request.clone(),
        ready: Arc::new(ready),
        connected: Arc::new(AtomicBool::new(true)),
        cancelled: Arc::new(AtomicBool::new(false)),
        reply,
        _slot: Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING))
            .try_acquire_owned()
            .unwrap(),
        timing: Some(Timing {
            started: 110,
            sample: Some(7),
        }),
    };
    let mut output = String::new();
    for stage in [checks::Stage::Enqueued, checks::Stage::Dequeued] {
        check.record_at(&mut output, 210, stage, None, None);
    }
    for disposition in [Disposition::Expired, Disposition::NotActive] {
        // These are successful evaluate returns, not errors: each still has an outcome record.
        let original =
            checks::unavailable(request.clone(), check.ready.privacy.clone(), disposition);
        let encoded = control::encode(&original).unwrap();
        check.record_at(
            &mut Closed,
            210,
            checks::Stage::Outcome,
            Some(&original.disposition),
            None,
        );
        let receipt = check.complete(Ok(original));
        assert_eq!(control::encode(&receipt).unwrap(), encoded);
        check.record_at(
            &mut output,
            210,
            checks::Stage::Outcome,
            Some(&receipt.disposition),
            None,
        );
    }
    let receipt = check.complete(Err(
        std::io::Error::from(std::io::ErrorKind::BrokenPipe).into()
    ));
    assert_eq!(receipt.request, request);
    assert_eq!(receipt.disposition, Disposition::Unavailable);
    assert!(receipt.authority.is_none());
    let text = output;
    assert_eq!(text.matches("sample=7 ").count(), 4);
    assert_eq!(text.matches("deadlineBootMs=200 ").count(), 4);
    assert!(text.contains("elapsedMs=100 "));
    assert!(text.contains("disposition=Some(Expired)"));
    assert!(text.contains("disposition=Some(NotActive)"));
    assert!(!text.contains(&request.local_connection_id));
    assert!(!text.contains("nonce") && !text.contains("session"));
    let mut maximum = check;
    maximum.request.caller_started_boot_ms = u64::MAX;
    maximum.request.caller_deadline_boot_ms = u64::MAX;
    maximum.timing = Some(Timing {
        started: 0,
        sample: Some(256),
    });
    let mut record = String::new();
    maximum.record_at(
        &mut record,
        u64::MAX,
        checks::Stage::EndpointPreparation,
        Some(&Disposition::Unavailable),
        Some((FailureCode::FreshQuorumUnavailable, Some(u64::MAX), None)),
    );
    assert!(record.len() < 384);
}

#[path = "ApplicationStreamScheduleTests.rs"]
mod schedule_tests;

#[test]
fn due_streams_are_serviced_before_renewed_low_ids_and_new_arrivals() {
    let now = crate::authority_challenge::boot_time_ms().unwrap() + 1000;
    let mut schedule = Schedule::default();
    let mut live = BTreeMap::new();
    for id in 1..=3 {
        let mut stream = prepared_stream(now + 50, now + 10_000);
        stream.accepted_at = now - 1000;
        stream.renewal_turn = schedule.renewed().unwrap();
        live.insert([id; 32], stream);
    }
    let expiry = live[&[1; 32]].gate.expiry().unwrap();
    for expected in 1..=3 {
        let id = due_stream(&live, now, 100, u64::MAX).unwrap();
        assert_eq!(id, [expected; 32]);
        live.get_mut(&id).unwrap().renewal_turn = schedule.renewed().unwrap();
        if expected == 1 {
            let mut arrival = prepared_stream(now + 50, now + 10_000);
            arrival.accepted_at = now - 1000;
            arrival.renewal_turn = schedule.renewed().unwrap();
            live.insert([0; 32], arrival);
        }
        // Every stream remains due, including the low ID just serviced.
        assert_eq!(live[&[1; 32]].gate.expiry().unwrap(), expiry);
    }
    live.get(&[1; 32])
        .unwrap()
        .forwarding
        .finished
        .store(true, Ordering::Release);
    assert_eq!(due_stream(&live, now, 100, u64::MAX), Some([0; 32]));
}

#[test]
fn close_preparation_has_one_finite_pass_despite_continuously_due_gates() {
    let now = crate::authority_challenge::boot_time_ms().unwrap() + 1000;
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 50),
        accepted_at: Some(now - 1000),
        renewals: 0,
    };
    let _activity = endpoint.gate.activity().unwrap();
    let mut schedule = Schedule::default();
    let mut live = BTreeMap::new();
    for id in 1..=3 {
        let mut stream = prepared_stream(now + 50, now + 10_000);
        stream.accepted_at = now - 1000;
        stream.renewal_turn = schedule.renewed().unwrap();
        live.insert([id; 32], stream);
    }
    let close = PendingClose::completed(
        prepared_stream(now + 50, now + 10_000),
        now,
        1000,
        endpoint.renewals,
        schedule.renewal_turn,
    );
    let reference = close.reference.clone();
    assert_eq!(
        maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
        Maintenance::Own
    );
    endpoint.renewals += 1;
    for expected in 1..=3 {
        assert_eq!(
            maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
            Maintenance::Stream([expected; 32])
        );
        live.get_mut(&[expected; 32]).unwrap().renewal_turn = schedule.renewed().unwrap();
    }
    assert_eq!(
        maintenance(now, &endpoint, &live, Some(&close), 100, 100).unwrap(),
        Maintenance::Close,
        "already visited gates cannot restart the preparation pass"
    );
    assert_eq!(close.reference, reference);
    assert_eq!(close.deadline, now + 1000);
    assert_eq!(endpoint.gate.expiry().unwrap(), now + 50);
    assert_eq!(occupied(0, 0, &live, Some(&close)), 4);
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
        let close = PendingClose::completed(
            live.remove(&[n; 32]).unwrap(),
            now,
            1000,
            endpoint.renewals,
            0,
        );
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
    let close = PendingClose::completed(
        prepared_stream(now + 100, now + 10_000),
        now,
        1000,
        endpoint.renewals,
        0,
    );
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
fn held_completion_closes_local_gate_and_keeps_its_relay_attachment_slot() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut live = BTreeMap::from([([1; 32], prepared_stream(now + 5000, now + 10_000))]);
    let gate = live[&[1; 32]].gate.clone();
    let reference = live[&[1; 32]].reference.clone();
    // This accounting limits relay replenishment; public admission has its own semaphore.
    assert_eq!(occupied(7, 8, &live, None), 16);
    let close = PendingClose::completed(live.remove(&[1; 32]).unwrap(), now, 1000, 0, 0);
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
fn failed_retirement_retains_one_target_and_original_deadline_across_backoff() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut close =
        PendingClose::completed(prepared_stream(now + 5000, now + 10_000), now, 4000, 0, 0);
    let original = close.reference.clone();
    let proof = close.proof_digest;
    let deadline = close.deadline;
    let clock = std::cell::Cell::new(now);
    let mut diagnostics = 0;
    assert!(!close.attempt_with(
        || clock.get(),
        &mut diagnostics,
        |reference, digest, end| {
            assert_eq!((reference, digest, end), (&original, proof, deadline));
            clock.set(now + 250);
            anyhow::bail!("original close outcome remains unknown")
        }
    ));
    assert_eq!(close.retry_after, now + 250 + READ_RETRY_MS);
    assert_eq!(occupied(7, 8, &BTreeMap::new(), Some(&close)), 16);
    assert!(!close.attempt_with(
        || now + 500,
        &mut diagnostics,
        |_, _, _| panic!("backoff dispatched cleanup")
    ));
    assert!(!close.attempt_with(
        || now + 1500,
        &mut diagnostics,
        |reference, digest, end| {
            assert_eq!((reference, digest, end), (&original, proof, deadline));
            anyhow::bail!("exact outcome still pending")
        }
    ));
    assert_eq!(close.deadline, deadline);
    assert!(close.attempt_with(
        || deadline,
        &mut diagnostics,
        |_, _, _| panic!("expired cleanup obtained another attempt")
    ));
    assert_eq!(diagnostics, 3);
}

#[test]
fn recovered_retirement_completes_without_replacing_its_target_or_deadline() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut close =
        PendingClose::completed(prepared_stream(now + 5000, now + 10_000), now, 4000, 0, 0);
    let original = close.reference.clone();
    let deadline = close.deadline;
    let mut diagnostics = 0;
    assert!(!close.attempt_with(
        || now,
        &mut diagnostics,
        |_, _, _| anyhow::bail!("refusal requires exact status")
    ));
    assert!(close.attempt_with(
        || now + READ_RETRY_MS,
        &mut diagnostics,
        |reference, _, end| {
            assert_eq!(reference, &original);
            assert_eq!(end, deadline);
            Ok(())
        }
    ));
    assert_eq!(diagnostics, 1);
}

#[test]
fn longer_caller_wait_does_not_renew_current_gates() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let caller_end = now + 5000;
    let route_end = now + 4000;
    let old_endpoint = now + 2000;
    let old_stream = now + 2500;
    let budget = 10;
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(old_endpoint),
        accepted_at: None,
        renewals: 0,
    };
    let mut stream = prepared_stream(old_stream, route_end);
    endpoint
        .prepare(caller_end.min(route_end), budget, |_| {
            panic!("caller wait renewed a current endpoint")
        })
        .unwrap();
    stream
        .prepare_check(
            caller_end,
            budget,
            || false,
            |_| panic!("caller wait renewed a current stream"),
        )
        .unwrap();
    let read_end = caller_end
        .min(endpoint.gate.expiry().unwrap())
        .min(stream.current_deadline(now).unwrap());
    assert_eq!(read_end, old_endpoint);
    assert!(read_end < caller_end);
    assert_eq!(stream.forwarding.deadline, route_end);
    assert_eq!(stream.gate.expiry().unwrap(), old_stream);
    assert_eq!(endpoint.renewals, 0);
}

#[test]
fn due_check_gates_renew_once_with_the_original_wait_bound() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let caller_end = now + 5000;
    let route_end = now + 4000;
    let budget = 700;
    let mut endpoint = EndpointPermission {
        gate: route_io::Gate::new(now + 1000),
        accepted_at: Some(now.saturating_sub(2000)),
        renewals: 0,
    };
    let mut stream = prepared_stream(now + 1200, route_end);
    stream.accepted_at = now.saturating_sub(2000);
    let mut stream_renewals = 0;
    endpoint
        .prepare(caller_end.min(route_end), budget, |bound| {
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
    let completed = crate::authority_challenge::boot_time_ms().unwrap();
    let read_end = caller_end
        .min(endpoint.gate.expiry().unwrap())
        .min(stream.current_deadline(completed).unwrap());
    assert!(completed < read_end);
    assert_eq!(read_end, now + 1400);
    assert_eq!(stream.forwarding.deadline, route_end);
    assert_eq!(stream.gate.expiry().unwrap(), now + 1800);
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
            .prepare(now, 100, |_| panic!("expired check renewed endpoint"))
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
    stream.accepted_at = now.saturating_sub(1000);
    assert!(
        stream
            .prepare_check(
                now + 100,
                100,
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
    stream.accepted_at = now.saturating_sub(2000);
    assert!(
        stream
            .prepare_check(
                now + 2000,
                600,
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
                600,
                || false,
                |_| {
                    forwarding.finished.store(true, Ordering::Release);
                    Ok(now + 3000)
                }
            )
            .is_err()
    );
    assert_eq!(stream.gate.expiry().unwrap(), old);
    assert_eq!(stream.current_deadline(now).ok(), None);
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
        .prepare(now + 1000, 10, |_| panic!("current endpoint renewed"))
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
    endpoint.accepted_at = Some(now.saturating_sub(10000));
    stream.accepted_at = now.saturating_sub(10000);
    assert!(
        endpoint
            .prepare(now + 6000, 3000, |_| anyhow::bail!("authority refused"))
            .is_err()
    );
    assert!(
        stream
            .prepare_check(
                now + 6000,
                3000,
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
        proof_digest: [91; 32],
        gate: route_io::Gate::new(4000),
        accepted_at: 100,
        retry_after: 0,
        renewal_turn: 0,
        forwarding: status.clone(),
    };
    assert_eq!(stream.current_deadline(100).ok(), None);
    status.established.store(true, Ordering::Release);
    assert_eq!(stream.current_deadline(100).ok(), Some(4000));
    assert_eq!(stream.current_deadline(4000).ok(), None);
    drop(ForwardingCompletion(status, Timing::begin(0, false)));
    assert_eq!(stream.current_deadline(100).ok(), None);
}

#[tokio::test]
async fn check_exchange_correlates_receipts_and_rejects_second_pending_session() {
    let (binding, key, ready, request) = fixture();
    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let b = binding.clone();
    let privacy = ready.privacy.clone();
    let task = tokio::spawn(async move {
        checks::exchange(
            endpoint,
            Arc::new(ready),
            &b,
            &key,
            &sender,
            &Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING)),
        )
        .await
    });
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let check = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(check.request, request);
    let queued_timing = check.timing.expect("clock available at verified enqueue");
    assert!(queued_timing.started >= request.caller_started_boot_ms);
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
        checks::exchange(
            endpoint,
            Arc::new(ready),
            &binding,
            &key,
            &sender,
            &Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING)),
        )
        .await
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

#[test]
fn completed_exchange_requires_current_control_stream_gates_and_original_deadline() {
    for fault in 0..10 {
        let (_, _, ready, request) = fixture();
        let now = request.caller_started_boot_ms;
        let (reply, _receiver) = tokio::sync::oneshot::channel();
        let mut check = checks::Check {
            request: request.clone(),
            ready: Arc::new(ready),
            connected: Arc::new(AtomicBool::new(true)),
            cancelled: Arc::new(AtomicBool::new(false)),
            reply,
            timing: None,
            _slot: Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING))
                .try_acquire_owned()
                .unwrap(),
        };
        let forwarding = Arc::new(Forwarding {
            deadline: request.caller_deadline_boot_ms,
            established: AtomicBool::new(true),
            finished: AtomicBool::new(false),
        });
        let stream = LiveStream {
            reference: request.session.clone(),
            proof_digest: [91; 32],
            gate: route_io::Gate::new(now + 4000),
            accepted_at: now,
            retry_after: 0,
            renewal_turn: 0,
            forwarding: forwarding.clone(),
        };
        let permission = EndpointPermission {
            gate: route_io::Gate::new(now + 3000),
            accepted_at: Some(now),
            renewals: 0,
        };
        let mut live = BTreeMap::from([(request.session.id, stream)]);
        assert!(check.completion_stream(&live, &permission, now).is_ok());
        let mut completed_at = now;
        match fault {
            0 => check.cancelled.store(true, Ordering::Release),
            1 => check.connected.store(false, Ordering::Release),
            2 => {
                Arc::get_mut(&mut check.ready)
                    .unwrap()
                    .challenge
                    .control_generation += 1
            }
            3 => {
                live.get_mut(&request.session.id)
                    .unwrap()
                    .reference
                    .generation += 1
            }
            4 => {
                live.remove(&request.session.id);
            }
            5 => forwarding.finished.store(true, Ordering::Release),
            6 => forwarding.established.store(false, Ordering::Release),
            7 => live[&request.session.id].gate.close(),
            8 => permission.gate.close(),
            9 => completed_at = request.caller_deadline_boot_ms,
            _ => unreachable!(),
        }
        let result = check.completion_stream(&live, &permission, completed_at);
        assert!(result.is_err(), "fault {fault}");
    }
}

#[tokio::test]
async fn checks_overlap_and_correlate_out_of_order_without_waiting_for_a_slow_check() {
    let (binding, key, ready, request) = fixture();
    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let slots = Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING));
    let worker_slots = slots.clone();
    let verify_binding = binding.clone();
    let task = tokio::spawn(async move {
        checks::exchange(
            endpoint,
            Arc::new(ready),
            &binding,
            &key,
            &sender,
            &worker_slots,
        )
        .await
    });
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let slow = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    let mut other = request.clone();
    other.nonce = [12; 32];
    other.local_connection_id = "incoming-2".into();
    other.session.id = [13; 32];
    route_io::send(&mut companion, &control::encode(&other).unwrap())
        .await
        .unwrap();
    let fast = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING - 2);
    let receipt = checks::unavailable(
        other.clone(),
        fast.ready.privacy.clone(),
        Disposition::NotActive,
    );
    fast.respond(receipt);
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        route_io::receive(&mut companion, control::MAXIMUM_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let receipt: Receipt = control::verify(&bytes, &verify_binding).unwrap();
    assert_eq!(receipt.request, other);
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING - 1);
    let receipt = checks::unavailable(
        request.clone(),
        slow.ready.privacy.clone(),
        Disposition::NotActive,
    );
    slow.respond(receipt);
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        route_io::receive(&mut companion, control::MAXIMUM_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let receipt: Receipt = control::verify(&bytes, &verify_binding).unwrap();
    assert_eq!(receipt.request, request);
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING);
    drop(companion);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn four_total_check_slots_include_work_draining_from_the_previous_control() {
    let (binding, key, ready, request) = fixture();
    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let (sender, mut queue) = mpsc::channel(control::MAXIMUM_PENDING);
    let slots = Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING));
    let worker_slots = slots.clone();
    let worker_binding = binding.clone();
    let worker_key = key.clone();
    let worker_ready = ready.clone();
    let worker_sender = sender.clone();
    let task = tokio::spawn(async move {
        checks::exchange(
            endpoint,
            Arc::new(worker_ready),
            &worker_binding,
            &worker_key,
            &worker_sender,
            &worker_slots,
        )
        .await
    });
    let mut executing = Vec::new();
    for index in 0..control::MAXIMUM_PENDING {
        let mut next = request.clone();
        next.nonce = [20 + index as u8; 32];
        next.session.id = [30 + index as u8; 32];
        next.local_connection_id = format!("incoming-{index}");
        route_io::send(&mut companion, &control::encode(&next).unwrap())
            .await
            .unwrap();
        executing.push(
            tokio::time::timeout(Duration::from_secs(1), queue.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(slots.available_permits(), 0);
    assert!(queue.try_recv().is_err());
    drop(companion);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(
        executing
            .iter()
            .all(|check| !check.connected.load(Ordering::Acquire))
    );

    let (endpoint, mut companion) = tokio::net::UnixStream::pair().unwrap();
    let mut ready = ready;
    ready.challenge.control_generation += 1;
    let mut request = request;
    request.control_generation += 1;
    let worker_slots = slots.clone();
    let verify_binding = binding.clone();
    let task = tokio::spawn(async move {
        checks::exchange(
            endpoint,
            Arc::new(ready),
            &binding,
            &key,
            &sender,
            &worker_slots,
        )
        .await
    });
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let bytes = tokio::time::timeout(
        Duration::from_secs(1),
        route_io::receive(&mut companion, control::MAXIMUM_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    let receipt: Receipt = control::verify(&bytes, &verify_binding).unwrap();
    assert_eq!(receipt.request, request);
    assert_eq!(receipt.disposition, Disposition::Unavailable);
    assert!(queue.try_recv().is_err());
    drop(executing.pop());
    assert_eq!(slots.available_permits(), 1);
    request.nonce = [99; 32];
    route_io::send(&mut companion, &control::encode(&request).unwrap())
        .await
        .unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(1), queue.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admitted.request, request);
    assert_eq!(slots.available_permits(), 0);
    drop(admitted);
    drop(executing);
    drop(companion);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(slots.available_permits(), control::MAXIMUM_PENDING);
}

#[test]
fn expired_open_stream_prepares_once_without_extending_original_wait_or_lifetime() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut stream = prepared_stream(now.saturating_sub(1), now + 4000);
    assert_eq!(
        stream.current_deadline(now),
        Err(InactiveStream::GateExpired)
    );
    assert_eq!(stream.preparation_deadline(now).unwrap(), now + 4000);
    let mut calls = 0;
    stream
        .prepare_check(
            now + 3000,
            10,
            || false,
            |end| {
                calls += 1;
                assert_eq!(end, now + 3000);
                Ok(now + 6000)
            },
        )
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(stream.gate.expiry().unwrap(), now + 4000);
    assert_eq!(stream.current_deadline(now).ok(), Some(now + 4000));

    for fault in 0..5 {
        let mut stream = prepared_stream(now.saturating_sub(1), now + 4000);
        match fault {
            0 => stream.gate.close(),
            1 => stream
                .forwarding
                .established
                .store(false, Ordering::Release),
            2 => stream.forwarding.finished.store(true, Ordering::Release),
            3 => Arc::get_mut(&mut stream.forwarding).unwrap().deadline = now,
            4 => (),
            _ => unreachable!(),
        }
        let end = if fault == 4 { now } else { now + 3000 };
        assert!(
            stream
                .prepare_check(end, 10, || false, |_| panic!("terminal stream renewed"))
                .is_err()
        );
    }
}

#[test]
fn certified_check_renews_exact_current_gate_but_receipt_keeps_old_clipping() {
    for fault in 0..10 {
        let (_, _, ready, request) = fixture();
        let now = request.caller_started_boot_ms;
        let (reply, _) = tokio::sync::oneshot::channel();
        let check = checks::Check {
            request: request.clone(),
            ready: Arc::new(ready),
            connected: Arc::new(AtomicBool::new(true)),
            cancelled: Arc::new(AtomicBool::new(false)),
            reply,
            timing: None,
            _slot: Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING))
                .try_acquire_owned()
                .unwrap(),
        };
        let mut stream = prepared_stream(now + 2500, now + 4500);
        stream.retry_after = now + 1000;
        let permission = EndpointPermission {
            gate: route_io::Gate::new(now + 4000),
            accepted_at: Some(now),
            renewals: 0,
        };
        let mut session = request.session.clone();
        let mut completed_at = now;
        let expiry = if fault == 1 { None } else { Some(now + 6000) };
        match fault {
            2 => session.generation += 1,
            3 => stream.gate.close(),
            4 => completed_at = now + 2500,
            5 => check.cancelled.store(true, Ordering::Release),
            6 => stream.forwarding.finished.store(true, Ordering::Release),
            7 => check.connected.store(false, Ordering::Release),
            8 => permission.gate.close(),
            9 => (),
            _ => (),
        }
        let mut live = BTreeMap::from([(request.session.id, stream)]);
        let observation = crate::route_authority::StreamCheck::fixture(session, now + 3500, expiry);
        let result = check.finish_observation(
            observation,
            now + 3000,
            &mut live,
            &permission,
            completed_at,
            |end| if fault == 9 { now } else { end },
        );
        let stream = &live[&request.session.id];
        if fault == 0 {
            let receipt = result.unwrap();
            assert_eq!(receipt.disposition, Disposition::Permitted);
            assert_eq!(receipt.not_after_boot_ms, now + 2500);
            assert_eq!(stream.gate.expiry().unwrap(), now + 4500);
            assert_eq!(stream.retry_after, 0);
            assert_eq!(permission.gate.expiry().unwrap(), now + 4000);
        } else {
            if fault == 1 {
                assert_eq!(result.unwrap().disposition, Disposition::Denied);
            } else if fault == 9 {
                assert_eq!(result.unwrap().disposition, Disposition::Expired);
            } else {
                assert!(result.is_err(), "fault {fault}");
            }
            if fault != 3 {
                assert_eq!(stream.gate.expiry().unwrap(), now + 2500);
            }
            assert_eq!(stream.retry_after, now + 1000);
        }
    }
}

#[test]
fn gate_installation_rechecks_the_clipped_receipt_end() {
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let mut stream = prepared_stream(now + 3000, now + 5000);
    let renewal = crate::route_authority::StreamCheck::fixture(
        stream.reference.clone(),
        now + 4000,
        Some(now + 5000),
    )
    .renewal
    .unwrap();
    // A live gate alone cannot extend a caller/read end exhausted after receipt calculation.
    assert!(stream.renew_checked(renewal, now).is_err());
    assert_eq!(stream.gate.expiry().unwrap(), now + 3000);
}

#[test]
fn inactive_reason_is_bounded_and_preserves_not_active_receipt() {
    let (_, _, ready, request) = fixture();
    let (reply, _) = tokio::sync::oneshot::channel();
    let check = checks::Check {
        request,
        ready: Arc::new(ready),
        connected: Arc::new(AtomicBool::new(true)),
        cancelled: Arc::new(AtomicBool::new(false)),
        reply,
        timing: Some(Timing {
            started: 0,
            sample: Some(256),
        }),
        _slot: Arc::new(tokio::sync::Semaphore::new(control::MAXIMUM_PENDING))
            .try_acquire_owned()
            .unwrap(),
    };
    let receipt = check.complete(Err(InactiveStream::GateExpired.into()));
    assert_eq!(receipt.disposition, Disposition::NotActive);
    assert!(receipt.authority.is_none());
    let mut text = String::new();
    check.record_at(
        &mut text,
        10,
        checks::Stage::Outcome,
        Some(&receipt.disposition),
        Some((FailureCode::Other, None, Some(InactiveStream::GateExpired))),
    );
    assert!(text.contains("inactive=Some(GateExpired)"));
    assert!(text.len() < 384);
    assert!(!text.contains(&check.request.local_connection_id));
}
