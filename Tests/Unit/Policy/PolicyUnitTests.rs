// SPDX-License-Identifier: MIT
// Unit tests for Policy.
use super::*;
#[test]
fn media_range_accepts_partial_chunks_and_rejects_overflow() {
    for (total, offset, count) in [
        (1, 0, 1),
        (786432, 0, 32768),
        (786432, 786431, 1),
        (11, 3, 5),
    ] {
        assert!(media_range(total, offset, count));
    }
    for (total, offset, count) in [
        (0, 0, 1),
        (786433, 0, 1),
        (11, 11, 1),
        (11, 0, 0),
        (786432, 0, 32769),
        (11, 10, 2),
        (786432, u64::MAX, 2),
        (786432, 1, u64::MAX),
    ] {
        assert!(!media_range(total, offset, count));
    }
}
