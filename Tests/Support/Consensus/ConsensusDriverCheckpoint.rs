// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
impl ServedCheckpoint {
    pub(super) fn expires_at(&self) -> Instant {
        self.deadline
    }
}

impl Transfer {
    #[cfg(test)]
    pub(super) fn expires_at(&self) -> Instant {
        self.deadline
    }
}
