// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Repair {
    #[cfg(test)]
    pub(super) fn retained_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.wanted.len(),
            self.staged.len(),
            self.goals.len(),
            self.pivots,
        )
    }
}
