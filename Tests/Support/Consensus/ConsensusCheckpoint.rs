// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Engine {
    #[cfg(test)]
    pub fn install_checkpoint(
        &mut self,
        proof: &[u8],
        state: &[u8],
        leaves: &(impl archive::History + ?Sized),
        validate: impl FnOnce(&[u8], u64) -> Result<()>,
        expired_before: Option<u64>,
    ) -> Result<()> {
        self.install_checkpoint_with_inputs(proof, state, leaves, &[], validate, expired_before)
    }
}
