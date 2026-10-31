// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Engine {
    #[cfg(test)]
    pub fn prepare_epoch(
        directory: &Path,
        predecessor: Configuration,
        key: SigningKey,
        terminal_state: &[u8],
        terminal: &crate::authority_epoch::ValidatedTerminal,
    ) -> Result<Self> {
        Self::prepare_epoch_with_objects(
            directory,
            predecessor,
            key,
            terminal_state,
            terminal,
            None,
        )
    }
}
