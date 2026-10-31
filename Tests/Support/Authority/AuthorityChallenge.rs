// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl ClockHealth {
    #[cfg(test)]
    pub(crate) fn frozen(mut self) -> Self {
        self.test_observation = Some(Observation {
            wall_ms: self.sample_wall_ms,
            boot_ms: self.sample_boot_ms,
        });
        self
    }
}
