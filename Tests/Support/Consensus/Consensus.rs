// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Engine {
    #[cfg(test)]
    pub fn prepare(
        &mut self,
        proposal: &[u8],
        command: &[u8],
        admit_time: impl FnOnce(u64) -> Result<()>,
        validate_intent: impl FnOnce(&[u8], u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.prepare_with_inputs(
            proposal,
            command,
            &crate::authority_objects::Resolved::default(),
            admit_time,
            validate_intent,
        )
    }
}
