// SPDX-License-Identifier: MIT
//! Numeric storage timings cover one synchronous replica turn without retaining paths or data.
use std::{cell::Cell, fs::File, io, time::Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Summary {
    pub calls: u64,
    pub elapsed_ns: u64,
    pub max_ns: u64,
    pub file_calls: u64,
    pub directory_calls: u64,
    pub journal_commits: u64,
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
