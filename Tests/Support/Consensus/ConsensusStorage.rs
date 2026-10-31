// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Store {
    #[cfg(test)]
    pub(super) fn sync_counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.file_syncs.load(Ordering::Relaxed),
            self.directory_syncs.load(Ordering::Relaxed),
        )
    }
}
