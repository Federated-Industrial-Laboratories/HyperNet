// SPDX-License-Identifier: MIT
//! Fixed diagnostic categories expose delays without publishing request contents.
use super::super::timing;
use std::{
    collections::BTreeMap,
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
pub(super) struct Stamp {
    at: Instant,
    boot_ms: Option<u64>,
}
impl Stamp {
    pub(super) fn now() -> Self {
        Self {
            at: Instant::now(),
            boot_ms: crate::authority_challenge::boot_time_ms().ok(),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Phase {
    Proposed,
    PrepareVote,
    PrepareQc,
    PreCommitVote,
    PreCommitQc,
    CommitVote,
    CommitQc,
    Committed,
    Executed,
    Quorum,
    ReplyReady,
}
const PHASE_NAMES: [&str; 11] = [
    "proposed",
    "prepareVote",
    "prepareQc",
    "preCommitVote",
    "preCommitQc",
    "commitVote",
    "commitQc",
    "committed",
    "executed",
    "quorum",
    "replyReady",
];
struct ViewTiming {
    height: u64,
    // Correlation stays in memory; only explicit numeric fields are serialized.
    command: super::Digest,
    accepted: Option<Stamp>,
    start: Stamp,
    phases: [Option<Instant>; PHASE_NAMES.len()],
    last: Instant,
    reported: bool,
}
#[derive(Default)]
struct Phases {
    accepted: BTreeMap<super::Digest, Stamp>,
    views: BTreeMap<u64, ViewTiming>,
    retired: u64,
    overflow: u64,
}
impl Phases {
    fn accepted(&mut self, command: super::Digest, stamp: Stamp) {
        if self.accepted.contains_key(&command) {
            return;
        }
        if self.accepted.len() == super::MAX_PENDING {
            if let Some(old) = self
                .accepted
                .iter()
                .min_by_key(|(_, stamp)| stamp.at)
                .map(|(id, _)| *id)
            {
                self.accepted.remove(&old);
            }
            self.overflow = self.overflow.saturating_add(1);
        }
        self.accepted.insert(command, stamp);
    }
    fn proposed(&mut self, node: &super::Node, stamp: Stamp) {
        let Some(command) = node.command else { return };
        if self.views.contains_key(&node.view) || node.view <= self.retired {
            return;
        }
        if self.views.len() == super::MAX_PENDING {
            if let Some(view) = self
                .views
                .iter()
                .find(|(_, record)| record.reported)
                .map(|(view, _)| *view)
            {
                self.views.remove(&view);
                self.retired = self.retired.max(view);
            } else {
                // Saturation loses diagnostics only; it cannot delay authority work.
                self.retired = self.retired.max(node.view);
                self.overflow = self.overflow.saturating_add(1);
                return;
            }
        }
        let accepted = self.accepted.remove(&command);
        let mut phases = [None; PHASE_NAMES.len()];
        phases[Phase::Proposed as usize] = Some(stamp.at);
        self.views.insert(
            node.view,
            ViewTiming {
                height: node.height,
                command,
                accepted,
                start: accepted.unwrap_or(stamp),
                phases,
                last: stamp.at,
                reported: false,
            },
        );
    }
    fn mark(&mut self, node: &super::Node, phase: Phase, now: Instant) {
        let Some(record) = self.views.get_mut(&node.view) else {
            return;
        };
        if record.reported || record.height != node.height || Some(record.command) != node.command {
            return;
        }
        let slot = &mut record.phases[phase as usize];
        if slot.is_none() {
            *slot = Some(now);
            record.last = now;
        }
    }
    fn records(&mut self, now: Instant, final_flush: bool) -> (Vec<serde_json::Value>, u64) {
        let mut records = Vec::new();
        for (view, record) in &mut self.views {
            let replied = record.phases[Phase::ReplyReady as usize].is_some();
            if record.reported
                || (!replied && !final_flush && now.saturating_duration_since(record.last) < RATE)
            {
                continue;
            }
            let phases: serde_json::Map<_, _> = PHASE_NAMES
                .iter()
                .zip(record.phases)
                .map(|(name, at)| {
                    (
                        (*name).to_owned(),
                        serde_json::json!(
                            at.map(|at| nanos(at.saturating_duration_since(record.start.at)))
                        ),
                    )
                })
                .collect();
            records.push(serde_json::json!({
                "view": view, "height": record.height,
                "startedBootMs": record.start.boot_ms,
                "acceptedNs": record.accepted.map(|_| 0u64),
                "elapsedNs": phases,
                "incomplete": !replied,
                "reason": if replied { "ReplyReady" } else if final_flush { "Shutdown" } else { "Inactive" },
            }));
            record.reported = true;
        }
        (records, std::mem::take(&mut self.overflow))
    }
}

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
    Classification,
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
            Self::Classification => "Classification",
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
struct Activity {
    start: Instant,
    first_view: Option<u64>,
    turns: u64,
    busy_ns: u64,
    storage: timing::Summary,
}
impl Activity {
    fn new(start: Instant) -> Self {
        Self {
            start,
            first_view: None,
            turns: 0,
            busy_ns: 0,
            storage: timing::Summary::default(),
        }
    }
    fn add(
        &mut self,
        now: Instant,
        view: u64,
        elapsed: Duration,
        storage: timing::Summary,
    ) -> Option<serde_json::Value> {
        self.first_view.get_or_insert(view);
        self.turns = self.turns.saturating_add(1);
        self.busy_ns = self.busy_ns.saturating_add(nanos(elapsed));
        self.storage.calls = self.storage.calls.saturating_add(storage.calls);
        self.storage.elapsed_ns = self.storage.elapsed_ns.saturating_add(storage.elapsed_ns);
        self.storage.max_ns = self.storage.max_ns.max(storage.max_ns);
        self.storage.file_calls = self.storage.file_calls.saturating_add(storage.file_calls);
        self.storage.directory_calls = self
            .storage
            .directory_calls
            .saturating_add(storage.directory_calls);
        self.storage.journal_commits = self
            .storage
            .journal_commits
            .saturating_add(storage.journal_commits);
        self.storage.certificate_signature_calls = self
            .storage
            .certificate_signature_calls
            .saturating_add(storage.certificate_signature_calls);
        self.storage.certificate_signature_ns = self
            .storage
            .certificate_signature_ns
            .saturating_add(storage.certificate_signature_ns);
        self.storage.certificate_cache_hits = self
            .storage
            .certificate_cache_hits
            .saturating_add(storage.certificate_cache_hits);
        self.storage.envelope_signature_calls = self
            .storage
            .envelope_signature_calls
            .saturating_add(storage.envelope_signature_calls);
        self.storage.envelope_signature_ns = self
            .storage
            .envelope_signature_ns
            .saturating_add(storage.envelope_signature_ns);
        self.storage.envelope_cache_lookups = self
            .storage
            .envelope_cache_lookups
            .saturating_add(storage.envelope_cache_lookups);
        self.storage.envelope_cache_hits = self
            .storage
            .envelope_cache_hits
            .saturating_add(storage.envelope_cache_hits);
        self.storage.envelope_cache_evictions = self
            .storage
            .envelope_cache_evictions
            .saturating_add(storage.envelope_cache_evictions);
        self.storage.state_parse_calls = self
            .storage
            .state_parse_calls
            .saturating_add(storage.state_parse_calls);
        self.storage.state_parse_ns = self
            .storage
            .state_parse_ns
            .saturating_add(storage.state_parse_ns);
        self.storage.state_cache_hits = self
            .storage
            .state_cache_hits
            .saturating_add(storage.state_cache_hits);
        self.storage.metadata_encoding_ns = self
            .storage
            .metadata_encoding_ns
            .saturating_add(storage.metadata_encoding_ns);
        self.storage.expired_challenges = self
            .storage
            .expired_challenges
            .saturating_add(storage.expired_challenges);
        self.storage.metadata_max_bytes = self
            .storage
            .metadata_max_bytes
            .max(storage.metadata_max_bytes);
        self.storage.expired_challenge_age_max_ms = self
            .storage
            .expired_challenge_age_max_ms
            .max(storage.expired_challenge_age_max_ms);
        let interval = now.saturating_duration_since(self.start);
        if interval < RATE {
            return None;
        }
        Some(self.finish(now, view))
    }
    fn finish(&mut self, now: Instant, view: u64) -> serde_json::Value {
        let interval = now.saturating_duration_since(self.start);
        let record = serde_json::json!({
            "status": "ReplicaDiagnostic", "code": "ActivitySummary",
            "bootMs": crate::authority_challenge::boot_time_ms().ok(),
            "firstView": self.first_view, "view": view,
            "intervalNs": nanos(interval), "turns": self.turns,
            "busyElapsedNs": self.busy_ns,
            "storageCalls": self.storage.calls,
            "storageElapsedNs": self.storage.elapsed_ns,
            "storageMaxNs": self.storage.max_ns,
            "fileSyncCalls": self.storage.file_calls,
            "directorySyncCalls": self.storage.directory_calls,
            "journalCommits": self.storage.journal_commits,
            "certificateSignatureCalls": self.storage.certificate_signature_calls,
            "certificateSignatureNs": self.storage.certificate_signature_ns,
            "certificateCacheHits": self.storage.certificate_cache_hits,
            "envelopeSignatureCalls": self.storage.envelope_signature_calls,
            "envelopeSignatureNs": self.storage.envelope_signature_ns,
            "envelopeCacheLookups": self.storage.envelope_cache_lookups,
            "envelopeCacheHits": self.storage.envelope_cache_hits,
            "envelopeCacheEvictions": self.storage.envelope_cache_evictions,
            "stateParseCalls": self.storage.state_parse_calls,
            "stateParseNs": self.storage.state_parse_ns,
            "stateCacheHits": self.storage.state_cache_hits,
            "metadataEncodingNs": self.storage.metadata_encoding_ns,
            "metadataMaxBytes": self.storage.metadata_max_bytes,
            "expiredChallenges": self.storage.expired_challenges,
            "expiredChallengeAgeMaxMs": self.storage.expired_challenge_age_max_ms,
        });
        *self = Self::new(now);
        record
    }
}
fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}
#[derive(Clone)]
pub(super) struct Diagnostics {
    budget: Arc<Mutex<Budget>>,
    activity: Arc<Mutex<Activity>>,
    phases: Arc<Mutex<Phases>>,
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
            activity: Arc::new(Mutex::new(Activity::new(Instant::now()))),
            phases: Arc::new(Mutex::new(Phases::default())),
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
    pub(super) fn accepted(&self, command: super::Digest) {
        if let Ok(mut phases) = self.phases.lock() {
            phases.accepted(command, Stamp::now());
        }
    }
    pub(super) fn proposed(&self, node: &super::Node, stamp: Stamp) {
        if let Ok(mut phases) = self.phases.lock() {
            phases.proposed(node, stamp);
        }
    }
    pub(super) fn phase(&self, node: &super::Node, phase: Phase) {
        if let Ok(mut phases) = self.phases.lock() {
            phases.mark(node, phase, Instant::now());
        }
    }

    fn write_activity(&self, mut summary: serde_json::Value, final_flush: bool) {
        if let Ok(mut phases) = self.phases.lock() {
            let (records, overflow) = phases.records(Instant::now(), final_flush);
            summary["viewTimings"] = records.into();
            summary["viewTimingOverflow"] = overflow.into();
        }
        summary["final"] = final_flush.into();
        let _ = writeln!(std::io::stderr().lock(), "{summary}");
    }
    pub(super) fn finish(&self, view: u64) {
        let summary = self
            .activity
            .lock()
            .ok()
            .map(|mut activity| activity.finish(Instant::now(), view));
        if let Some(summary) = summary {
            self.write_activity(summary, true);
        }
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
                record["certificateSignatureCalls"] = storage.certificate_signature_calls.into();
                record["certificateSignatureNs"] = storage.certificate_signature_ns.into();
                record["certificateCacheHits"] = storage.certificate_cache_hits.into();
                record["envelopeSignatureCalls"] = storage.envelope_signature_calls.into();
                record["envelopeSignatureNs"] = storage.envelope_signature_ns.into();
                record["envelopeCacheLookups"] = storage.envelope_cache_lookups.into();
                record["envelopeCacheHits"] = storage.envelope_cache_hits.into();
                record["envelopeCacheEvictions"] = storage.envelope_cache_evictions.into();
                record["stateParseCalls"] = storage.state_parse_calls.into();
                record["stateParseNs"] = storage.state_parse_ns.into();
                record["stateCacheHits"] = storage.state_cache_hits.into();
                record["metadataEncodingNs"] = storage.metadata_encoding_ns.into();
                record["metadataMaxBytes"] = storage.metadata_max_bytes.into();
                record["expiredChallenges"] = storage.expired_challenges.into();
                record["expiredChallengeAgeMaxMs"] = storage.expired_challenge_age_max_ms.into();
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
        // Include ordinary turns: slow-turn sampling alone hides aggregate work.
        // The synchronous driver guards do not overlap or include idle awaits.
        let summary = self
            .diagnostics
            .activity
            .lock()
            .ok()
            .and_then(|mut activity| {
                activity.add(Instant::now(), self.work.view, elapsed, storage)
            });
        if let Some(summary) = summary {
            self.diagnostics.write_activity(summary, false);
        }
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
#[path = "../../Tests/Unit/Consensus/ConsensusDiagnosticsUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusDiagnostics.rs");
