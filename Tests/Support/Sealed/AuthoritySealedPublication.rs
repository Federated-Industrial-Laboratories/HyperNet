// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Placement {
    #[cfg(test)]
    pub fn value(&self) -> V {
        a(vec![
            a(self.hosts.iter().map(|d| b(d)).collect()),
            a(self.volumes.iter().map(|d| b(d)).collect()),
            a(self.backups.iter().map(|d| b(d)).collect()),
            V::Uint(self.copies),
        ])
    }
}
