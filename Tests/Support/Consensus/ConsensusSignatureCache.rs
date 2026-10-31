// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub(super) fn clear() {
    VERIFIED.with(|cache| *cache.borrow_mut() = Cache::default());
}
