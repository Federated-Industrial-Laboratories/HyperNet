// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub use stream_proof::initial_generation_id;

impl TrustDescriptor {
    #[cfg(test)]
    pub fn voters(&self) -> &[Key; 4] {
        &self.voters
    }
}

impl ActionValidation {
    /// A complete owner application list carries only bounded lifecycle metadata.
    #[cfg(test)]
    pub fn application_list(generations: Vec<VersionRef>) -> Result<Self> {
        validate_versions(&generations, 192)?;
        ensure!(
            generations
                .iter()
                .all(|v| matches!(v.kind, 102 | 127 | 128)),
            "application list contains an unsupported record kind"
        );
        Ok(Self {
            generations,
            updates: Vec::new(),
        })
    }
}
