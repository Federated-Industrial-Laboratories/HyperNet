// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Reference {
    #[cfg(test)]
    pub fn for_bytes(class: Class, bytes: &[u8]) -> Result<Self> {
        ensure!(
            (1..=class.maximum()).contains(&bytes.len()),
            "immutable input exceeds its class bound"
        );
        Ok(Self {
            class,
            content: Sha256::digest(bytes).into(),
            length: bytes.len(),
        })
    }
}

impl EpochIndex {
    #[cfg(test)]
    pub fn verify(&self, terminal_state: &[u8], required: &[Reference]) -> Result<()> {
        validate_references(required)?;
        ensure!(
            self.state == wire::digest(terminal_state) && self.references == required,
            "epoch object index differs from the complete accepted terminal state"
        );
        Ok(())
    }
}

impl Resolved {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}
