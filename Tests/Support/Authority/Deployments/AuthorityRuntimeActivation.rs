// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Operation {
    #[cfg(test)]
    pub fn prepare(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        recipient: Key,
        at: u64,
        replay: bool,
    ) -> Result<Decision> {
        self.evaluate(records, reservations, intent, recipient, at, replay, false)
    }
}
