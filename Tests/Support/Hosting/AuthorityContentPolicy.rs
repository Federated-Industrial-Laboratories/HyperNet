// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl ContentPolicy {
    #[cfg(test)]
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(self.metadata_bytes),
            V::Uint(self.data_bytes),
            V::Uint(self.staging_bytes),
            V::Uint(self.quarantine_bytes),
            V::Uint(self.maximum_objects),
            V::Bool(self.opaque),
            b(&self.failure_domain),
            a(self.reviewers.iter().map(|r| b(r)).collect()),
            V::Bool(self.search),
        ])
    }
}
