// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Store {
    /// The lower bound is an independent credential start, or zero when none applies.
    /// The original live challenge already establishes causal issuance through BOOTTIME.
    #[cfg(test)]
    pub fn accept(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        health: ClockHealth,
        not_before_ms: u64,
    ) -> Result<Permit> {
        self.accept_with_clock(result, session, &mut || Ok(health), not_before_ms)
    }
}
