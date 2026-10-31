// SPDX-License-Identifier: MIT
// Unit tests for ConsensusStorageTiming.
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
