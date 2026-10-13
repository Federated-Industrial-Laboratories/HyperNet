// SPDX-License-Identifier: MIT
//! Numeric storage and proof timings cover one synchronous turn without retaining paths or data.
use std::{
    cell::Cell,
    fs::File,
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    pub calls: u64,
    pub elapsed_ns: u64,
    pub max_ns: u64,
    pub file_calls: u64,
    pub directory_calls: u64,
    pub journal_commits: u64,
    pub certificate_signature_calls: u64,
    pub certificate_signature_ns: u64,
    pub certificate_cache_hits: u64,
    pub state_parse_calls: u64,
    pub state_parse_ns: u64,
    pub state_cache_hits: u64,
    pub metadata_encoding_ns: u64,
    pub metadata_max_bytes: u64,
    pub expired_challenges: u64,
    pub expired_challenge_age_max_ms: u64,
}

thread_local! {
    static COUNTERS: Cell<Summary> = Cell::new(Summary::default());
}

// Turn guards enclose synchronous work only. They must not cross an await or
// nest: a task can resume on another thread, and a nested guard would reset it.
pub(super) fn reset() {
    COUNTERS.set(Summary::default());
}

pub(super) fn take() -> Summary {
    COUNTERS.replace(Summary::default())
}

pub(super) fn journal_commit() {
    let mut value = COUNTERS.get();
    value.journal_commits = value.journal_commits.saturating_add(1);
    COUNTERS.set(value);
}

pub(super) fn certificate_signature(elapsed: Duration) {
    let mut value = COUNTERS.get();
    value.certificate_signature_calls = value.certificate_signature_calls.saturating_add(1);
    value.certificate_signature_ns = value
        .certificate_signature_ns
        .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    COUNTERS.set(value);
}

pub(super) fn certificate_cache_hit() {
    let mut value = COUNTERS.get();
    value.certificate_cache_hits = value.certificate_cache_hits.saturating_add(1);
    COUNTERS.set(value);
}

pub(crate) fn state_parse(elapsed: Duration) {
    let mut value = COUNTERS.get();
    value.state_parse_calls = value.state_parse_calls.saturating_add(1);
    value.state_parse_ns = value
        .state_parse_ns
        .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    COUNTERS.set(value);
}

pub(crate) fn state_cache_hit() {
    let mut value = COUNTERS.get();
    value.state_cache_hits = value.state_cache_hits.saturating_add(1);
    COUNTERS.set(value);
}

pub(super) fn metadata_encoding(elapsed: Duration, bytes: usize) {
    let mut value = COUNTERS.get();
    value.metadata_encoding_ns = value
        .metadata_encoding_ns
        .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    value.metadata_max_bytes = value.metadata_max_bytes.max(bytes as u64);
    COUNTERS.set(value);
}

pub(crate) fn expired_challenge(age_ms: u64) {
    let mut value = COUNTERS.get();
    value.expired_challenges = value.expired_challenges.saturating_add(1);
    value.expired_challenge_age_max_ms = value.expired_challenge_age_max_ms.max(age_ms);
    COUNTERS.set(value);
}

pub(super) fn sync(file: &File, directory: bool) -> io::Result<()> {
    let start = Instant::now();
    let result = file.sync_all();
    let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let mut value = COUNTERS.get();
    value.calls = value.calls.saturating_add(1);
    value.elapsed_ns = value.elapsed_ns.saturating_add(elapsed);
    value.max_ns = value.max_ns.max(elapsed);
    if directory {
        value.directory_calls = value.directory_calls.saturating_add(1);
    } else {
        value.file_calls = value.file_calls.saturating_add(1);
    }
    COUNTERS.set(value);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_sync_preserves_error_and_timing_is_thread_local() {
        reset();
        let file = File::open("/dev/null").unwrap();
        assert!(sync(&file, false).is_err());
        journal_commit();
        std::thread::spawn(|| {
            assert_eq!(take(), Summary::default());
            journal_commit();
            assert_eq!(take().journal_commits, 1);
        })
        .join()
        .unwrap();
        let summary = take();
        assert_eq!(summary.calls, 1);
        assert_eq!(summary.file_calls, 1);
        assert_eq!(summary.directory_calls, 0);
        assert_eq!(summary.journal_commits, 1);
        assert_eq!(summary.elapsed_ns, summary.max_ns);
        assert_eq!(take(), Summary::default());
    }
}
