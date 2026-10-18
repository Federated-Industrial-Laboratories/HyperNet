// SPDX-License-Identifier: MIT
//! Pure extent checks complement signature, current permission and whole-asset validation.
unsafe extern "C" {
    fn HyperNetMediaRange(total: u64, offset: u64, count: u64) -> std::ffi::c_uint;
}

pub fn media_range(total: u64, offset: u64, count: u64) -> bool {
    // The C boundary has no pointers, allocation, callbacks or mutable state.
    unsafe { HyperNetMediaRange(total, offset, count) == 1 }
}

#[cfg(test)]
mod tests {
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
}
