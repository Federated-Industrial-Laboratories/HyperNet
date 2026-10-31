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
#[path = "../../Tests/Unit/Policy/PolicyUnitTests.rs"]
mod tests;
