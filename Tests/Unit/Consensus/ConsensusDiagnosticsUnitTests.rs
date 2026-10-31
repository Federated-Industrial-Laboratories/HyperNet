// SPDX-License-Identifier: MIT
// Unit tests for ConsensusDiagnostics.
use super::*;
#[test]
fn view_timing_keeps_first_phases_and_serializes_only_numeric_progress() {
    let (configuration, _) = crate::consensus::records::tests::fixture();
    let mut node = configuration.genesis();
    node.view = 7;
    node.height = 1;
    node.command = Some([93; 32]);
    let now = Instant::now();
    let stamp = |ms| Stamp {
        at: now + Duration::from_millis(ms),
        boot_ms: Some(1000 + ms),
    };
    let mut phases = Phases::default();
    phases.accepted(node.command.unwrap(), stamp(0));
    phases.accepted(node.command.unwrap(), stamp(5));
    phases.proposed(&node, stamp(10));
    phases.proposed(&node, stamp(20));
    phases.mark(&node, Phase::PrepareVote, stamp(30).at);
    phases.mark(&node, Phase::PrepareVote, stamp(40).at);
    phases.mark(&node, Phase::Executed, stamp(100).at);
    phases.mark(&node, Phase::Quorum, stamp(110).at);
    phases.mark(&node, Phase::ReplyReady, stamp(120).at);
    let (records, overflow) = phases.records(stamp(130).at, false);
    assert_eq!(overflow, 0);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    let keys: std::collections::BTreeSet<_> = record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "acceptedNs",
            "elapsedNs",
            "height",
            "incomplete",
            "reason",
            "startedBootMs",
            "view"
        ])
    );
    assert_eq!(record["startedBootMs"], 1000);
    assert_eq!(record["acceptedNs"], 0);
    assert_eq!(record["elapsedNs"]["proposed"], 10_000_000);
    assert_eq!(record["elapsedNs"]["prepareVote"], 30_000_000);
    assert_eq!(record["elapsedNs"]["replyReady"], 120_000_000);
    assert!(record["elapsedNs"]["prepareQc"].is_null());
    assert_eq!(
        record["elapsedNs"].as_object().unwrap().len(),
        PHASE_NAMES.len()
    );
    assert_eq!(record["incomplete"], false);
    assert_eq!(record["reason"], "ReplyReady");
    phases.proposed(&node, stamp(200));
    phases.mark(&node, Phase::PrepareQc, stamp(210).at);
    assert!(phases.records(stamp(220).at, true).0.is_empty());
}
#[test]
fn view_timing_bounds_stalled_views_reports_loss_and_flushes_incomplete_progress() {
    let (configuration, _) = crate::consensus::records::tests::fixture();
    let mut node = configuration.genesis();
    node.height = 1;
    node.command = Some([94; 32]);
    let now = Instant::now();
    let stamp = Stamp {
        at: now,
        boot_ms: None,
    };
    let mut phases = Phases::default();
    for view in 1..=super::super::MAX_PENDING as u64 + 1 {
        node.view = view;
        phases.proposed(&node, stamp);
    }
    assert_eq!(phases.views.len(), super::super::MAX_PENDING);
    let (records, overflow) = phases.records(now + RATE, false);
    assert_eq!(overflow, 1);
    assert_eq!(records.len(), super::super::MAX_PENDING);
    assert!(records.iter().all(|record| record["incomplete"] == true
        && record["reason"] == "Inactive"
        && record["acceptedNs"].is_null()
        && record["startedBootMs"].is_null()
        && record["elapsedNs"]["executed"].is_null()));
    node.view += 1;
    phases.proposed(&node, stamp);
    assert_eq!(phases.views.len(), super::super::MAX_PENDING);
    let (records, overflow) = phases.records(now, true);
    assert_eq!(overflow, 0);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reason"], "Shutdown");
    assert_eq!(records[0]["view"], node.view);
    node.view = 1;
    phases.proposed(&node, stamp);
    assert!(phases.records(now, true).0.is_empty());
    for byte in 0..=super::super::MAX_PENDING as u8 {
        phases.accepted([byte; 32], stamp);
    }
    assert_eq!(phases.accepted.len(), super::super::MAX_PENDING);
    assert_eq!(phases.records(now, true).1, 1);
}
#[test]
fn activity_includes_short_turns_without_losing_suppressed_interval_work() {
    let start = Instant::now();
    let mut activity = Activity::new(start);
    let storage = timing::Summary {
        calls: 2,
        elapsed_ns: 20,
        max_ns: 15,
        file_calls: 1,
        directory_calls: 1,
        journal_commits: 1,
        certificate_signature_calls: 3,
        certificate_signature_ns: 30,
        certificate_cache_hits: 4,
        envelope_signature_calls: 1,
        envelope_signature_ns: 2,
        envelope_cache_lookups: 3,
        envelope_cache_hits: 4,
        envelope_cache_evictions: 5,
        state_parse_calls: 1,
        state_parse_ns: 2,
        state_cache_hits: 3,
        metadata_encoding_ns: 4,
        metadata_max_bytes: 5,
        expired_challenges: 6,
        expired_challenge_age_max_ms: 7,
    };
    for i in 0..100 {
        assert!(
            activity
                .add(start, 19, Duration::from_millis(2), storage)
                .is_none(),
            "turn {i}"
        );
    }
    let record = activity
        .add(start + RATE, 20, Duration::ZERO, timing::Summary::default())
        .unwrap();
    assert_eq!(record["firstView"], 19);
    assert_eq!(record["view"], 20);
    assert_eq!(record["turns"], 101);
    assert_eq!(record["busyElapsedNs"], 200_000_000);
    assert_eq!(record["storageCalls"], 200);
    assert_eq!(record["storageElapsedNs"], 2000);
    assert_eq!(record["storageMaxNs"], 15);
    assert_eq!(record["journalCommits"], 100);
    assert_eq!(record["fileSyncCalls"], 100);
    assert_eq!(record["directorySyncCalls"], 100);
    assert_eq!(record["certificateSignatureCalls"], 300);
    assert_eq!(record["certificateSignatureNs"], 3000);
    assert_eq!(record["certificateCacheHits"], 400);
    assert_eq!(record["envelopeSignatureCalls"], 100);
    assert_eq!(record["envelopeSignatureNs"], 200);
    assert_eq!(record["envelopeCacheLookups"], 300);
    assert_eq!(record["envelopeCacheHits"], 400);
    assert_eq!(record["envelopeCacheEvictions"], 500);
    assert_eq!(record["stateParseCalls"], 100);
    assert_eq!(record["stateParseNs"], 200);
    assert_eq!(record["stateCacheHits"], 300);
    assert_eq!(record["metadataEncodingNs"], 400);
    assert_eq!(record["metadataMaxBytes"], 5);
    assert_eq!(record["expiredChallenges"], 600);
    assert_eq!(record["expiredChallengeAgeMaxMs"], 7);
    let next = activity
        .add(
            start + RATE * 2,
            21,
            Duration::ZERO,
            timing::Summary::default(),
        )
        .unwrap();
    assert_eq!(next["firstView"], 21);
    assert_eq!(next["turns"], 1);
    assert_eq!(next["journalCommits"], 0);
    assert_eq!(next["storageElapsedNs"], 0);
    assert_eq!(next["certificateSignatureCalls"], 0);
    assert_eq!(next["envelopeSignatureCalls"], 0);
    assert_eq!(next["envelopeSignatureNs"], 0);
    assert_eq!(next["envelopeCacheLookups"], 0);
    assert_eq!(next["envelopeCacheHits"], 0);
    assert_eq!(next["envelopeCacheEvictions"], 0);
    assert_eq!(next["certificateSignatureNs"], 0);
    assert_eq!(next["certificateCacheHits"], 0);
    assert_eq!(next["stateParseCalls"], 0);
    assert_eq!(next["stateParseNs"], 0);
    assert_eq!(next["stateCacheHits"], 0);
    assert_eq!(next["metadataEncodingNs"], 0);
    assert_eq!(next["metadataMaxBytes"], 0);
    assert_eq!(next["expiredChallenges"], 0);
    assert_eq!(next["expiredChallengeAgeMaxMs"], 0);
}
#[test]
fn categories_limit_rate_independently_and_resume_with_suppressed_count() {
    let mut budget = Budget::default();
    let start = Instant::now();
    assert_eq!(budget.admit(Code::LocalTimeout, start), Some(0));
    for _ in 0..100 {
        assert_eq!(budget.admit(Code::LocalTimeout, start), None);
    }
    assert_eq!(budget.admit(Code::StalledTurn, start), Some(0));
    assert_eq!(budget.admit(Code::LocalTimeout, start + RATE), Some(100));
    assert_eq!(budget.admit(Code::LocalTimeout, start + RATE * 2), Some(0));
}
#[test]
fn work_marker_excludes_idle_wait_and_clears_on_early_exit() {
    let (diagnostics, monitor) = Diagnostics::new();
    assert!(monitor.receiver.borrow().is_none());
    timing::journal_commit();
    let mut turn = diagnostics.begin(Stage::Peer, 19, None);
    assert_eq!(timing::take(), timing::Summary::default());
    turn.message_kind(2);
    let work = monitor.receiver.borrow().unwrap();
    assert_eq!(work.view, 19);
    assert_eq!(work.message_kind, Some(2));
    timing::journal_commit();
    drop(turn);
    assert!(monitor.receiver.borrow().is_none());
    assert_eq!(timing::take(), timing::Summary::default());
}
#[test]
fn peer_queue_delay_waits_for_decoded_kind_and_retains_invalid_message_diagnostics() {
    let (diagnostics, _) = Diagnostics::new();
    let mut turn = diagnostics.begin(Stage::Peer, 19, Some(Instant::now() - SLOW * 2));
    assert!(turn.queue_delay.is_some());
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::QueueDelay as usize]
            .last
            .is_none()
    );
    turn.message_kind(4);
    assert_eq!(turn.work.message_kind, Some(4));
    assert!(turn.queue_delay.is_none());
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::QueueDelay as usize]
            .last
            .is_some()
    );
    drop(turn);
    assert_eq!(
        diagnostics.budget.lock().unwrap().0[Code::QueueDelay as usize].suppressed,
        0
    );

    let (diagnostics, _) = Diagnostics::new();
    let turn = diagnostics.begin(Stage::Peer, 19, Some(Instant::now() - SLOW * 2));
    drop(turn);
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::QueueDelay as usize]
            .last
            .is_some()
    );
}
#[tokio::test]
async fn monitor_reports_unfinished_work_before_its_completion() {
    let (diagnostics, monitor) = Diagnostics::new();
    let turn = diagnostics.begin(Stage::Tick, 7, None);
    let task = tokio::spawn(monitor.run());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if diagnostics.budget.lock().unwrap().0[Code::StalledTurn as usize]
                .last
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(diagnostics.work.borrow().is_some());
    drop(turn);
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::SlowTurn as usize]
            .last
            .is_some()
    );
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn local_eof_distinguishes_full_queue_from_closed_response() {
    use super::super::{Event, ingress};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{mpsc, oneshot},
    };
    let directory = crate::consensus::journal::tests::Directory::new();
    let path = directory.0.join("Control.sock");
    let (listener, _guard) = ingress::local_socket(&path).unwrap();
    let (events, mut receiver) = mpsc::channel(1);
    let (answer, _response) = oneshot::channel();
    assert!(
        events
            .try_send(Event::Local {
                body: vec![0],
                answer,
                queued: Instant::now()
            })
            .is_ok()
    );
    let (diagnostics, _monitor) = Diagnostics::new();
    let task = tokio::spawn(ingress::accept_local(listener, events, diagnostics.clone()));
    let request = async {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_u32(1).await.unwrap();
        stream.write_u8(0).await.unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    };
    tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap();
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::LocalQueueFull as usize]
            .last
            .is_some()
    );
    drop(receiver.recv().await.unwrap());
    let request = async {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream.write_u32(1).await.unwrap();
        stream.write_u8(0).await.unwrap();
        drop(receiver.recv().await.unwrap());
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    };
    tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap();
    assert!(
        diagnostics.budget.lock().unwrap().0[Code::LocalResponseClosed as usize]
            .last
            .is_some()
    );
    task.abort();
    let _ = task.await;
}
