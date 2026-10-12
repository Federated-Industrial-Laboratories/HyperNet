// SPDX-License-Identifier: MIT
//! Fixed diagnostic categories expose delays without publishing request contents.
use super::super::timing;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

const RATE: Duration = Duration::from_secs(5);
const SLOW: Duration = Duration::from_millis(250);
const STALLED: Duration = Duration::from_secs(1);
const COUNT: usize = 12;

#[derive(Clone, Copy)]
pub(super) enum Code {
    LocalCapacity,
    LocalQueueFull,
    LocalDriverClosed,
    LocalResponseClosed,
    LocalTimeout,
    LocalInvalid,
    LocalIo,
    QueueDelay,
    SlowTurn,
    StalledTurn,
    ShutdownObserved,
    ProposalClockAge,
}
impl Code {
    fn name(self) -> &'static str {
        match self {
            Self::LocalCapacity => "LocalCapacity",
            Self::LocalQueueFull => "LocalQueueFull",
            Self::LocalDriverClosed => "LocalDriverClosed",
            Self::LocalResponseClosed => "LocalResponseClosed",
            Self::LocalTimeout => "LocalTimeout",
            Self::LocalInvalid => "LocalInvalid",
            Self::LocalIo => "LocalIo",
            Self::QueueDelay => "QueueDelay",
            Self::SlowTurn => "SlowTurn",
            Self::StalledTurn => "StalledTurn",
            Self::ShutdownObserved => "ShutdownObserved",
            Self::ProposalClockAge => "ProposalClockAge",
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Stage {
    LocalIngress,
    Restore,
    Peer,
    Local,
    Tick,
    LocalDrain,
    Apply,
    Shutdown,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::LocalIngress => "LocalIngress",
            Self::Restore => "Restore",
            Self::Peer => "Peer",
            Self::Local => "Local",
            Self::Tick => "Tick",
            Self::LocalDrain => "LocalDrain",
            Self::Apply => "Apply",
            Self::Shutdown => "Shutdown",
        }
    }
}
#[derive(Clone, Copy, Default)]
struct Slot {
    last: Option<Instant>,
    suppressed: u64,
}
struct Budget([Slot; COUNT]);
impl Default for Budget {
    fn default() -> Self {
        Self([Slot::default(); COUNT])
    }
}
impl Budget {
    fn admit(&mut self, code: Code, now: Instant) -> Option<u64> {
        let slot = &mut self.0[code as usize];
        if slot
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < RATE)
        {
            slot.suppressed = slot.suppressed.saturating_add(1);
            return None;
        }
        slot.last = Some(now);
        Some(std::mem::take(&mut slot.suppressed))
    }
}
#[derive(Clone, Copy)]
struct Work {
    start: Instant,
    stage: Stage,
    view: u64,
    message_kind: Option<u64>,
}
#[derive(Clone)]
pub(super) struct Diagnostics {
    budget: Arc<Mutex<Budget>>,
    work: watch::Sender<Option<Work>>,
}
pub(super) struct Monitor {
    diagnostics: Diagnostics,
    receiver: watch::Receiver<Option<Work>>,
}
pub(super) struct Turn {
    diagnostics: Diagnostics,
    work: Work,
    queue_delay: Option<Duration>,
}
impl Diagnostics {
    pub(super) fn new() -> (Self, Monitor) {
        let (work, receiver) = watch::channel(None);
        let diagnostics = Self {
            budget: Arc::new(Mutex::new(Budget::default())),
            work,
        };
        (
            diagnostics.clone(),
            Monitor {
                diagnostics,
                receiver,
            },
        )
    }
    pub(super) fn emit(&self, code: Code, stage: Stage, elapsed: Duration, view: u64) {
        self.emit_detail(code, stage, elapsed, view, None, None);
    }
    fn emit_detail(
        &self,
        code: Code,
        stage: Stage,
        elapsed: Duration,
        view: u64,
        message_kind: Option<u64>,
        storage: Option<timing::Summary>,
    ) {
        let suppressed = self
            .budget
            .lock()
            .ok()
            .and_then(|mut b| b.admit(code, Instant::now()));
        if let Some(suppressed) = suppressed {
            let elapsed_ms = elapsed.as_millis().min(u64::MAX as u128) as u64;
            let mut record = serde_json::json!({"status":"ReplicaDiagnostic", "code":code.name(),
                "stage":stage.name(), "elapsedMs":elapsed_ms,
                "view":view, "suppressed":suppressed});
            if let Some(kind) = message_kind {
                record["messageKind"] = kind.into();
            }
            if matches!(code, Code::ProposalClockAge) {
                record["proposalAgeMs"] = elapsed_ms.into();
            }
            if let Some(storage) = storage {
                record["storageCalls"] = storage.calls.into();
                record["storageElapsedNs"] = storage.elapsed_ns.into();
                record["storageMaxNs"] = storage.max_ns.into();
                record["fileSyncCalls"] = storage.file_calls.into();
                record["directorySyncCalls"] = storage.directory_calls.into();
                record["journalCommits"] = storage.journal_commits.into();
            }
            let _ = writeln!(std::io::stderr().lock(), "{record}");
        }
    }
    pub(super) fn begin(&self, stage: Stage, view: u64, queued: Option<Instant>) -> Turn {
        timing::reset();
        let start = Instant::now();
        let mut queue_delay = queued
            .map(|queued| start.saturating_duration_since(queued))
            .filter(|delay| *delay >= SLOW);
        if !matches!(stage, Stage::Peer)
            && let Some(delay) = queue_delay.take()
        {
            self.emit(Code::QueueDelay, stage, delay, view);
        }
        let work = Work {
            start,
            stage,
            view,
            message_kind: None,
        };
        self.work.send_replace(Some(work));
        Turn {
            diagnostics: self.clone(),
            work,
            queue_delay,
        }
    }
}
impl Turn {
    fn emit_queue_delay(&mut self) {
        if let Some(delay) = self.queue_delay.take() {
            self.diagnostics.emit_detail(
                Code::QueueDelay,
                self.work.stage,
                delay,
                self.work.view,
                self.work.message_kind,
                None,
            );
        }
    }
    pub(super) fn message_kind(&mut self, kind: u64) {
        self.work.message_kind = Some(kind);
        self.diagnostics.work.send_replace(Some(self.work));
        self.emit_queue_delay();
    }
}
impl Drop for Turn {
    fn drop(&mut self) {
        self.emit_queue_delay();
        self.diagnostics.work.send_replace(None);
        let storage = timing::take();
        let elapsed = self.work.start.elapsed();
        if elapsed >= SLOW {
            self.diagnostics.emit_detail(
                Code::SlowTurn,
                self.work.stage,
                elapsed,
                self.work.view,
                self.work.message_kind,
                Some(storage),
            );
        }
    }
}
impl Monitor {
    pub(super) async fn run(self) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut reported = None;
        loop {
            interval.tick().await;
            let work = *self.receiver.borrow();
            if let Some(work) = work
                && work.start.elapsed() >= STALLED
                && reported != Some(work.start)
            {
                reported = Some(work.start);
                self.diagnostics.emit_detail(
                    Code::StalledTurn,
                    work.stage,
                    work.start.elapsed(),
                    work.view,
                    work.message_kind,
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
