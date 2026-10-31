// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Engine {
    /// Only a complete quorum-certified dependency closure can publish repaired objects.
    #[cfg(test)]
    pub fn repair_import(
        &mut self,
        requested: &[Reference],
        items: &[Item],
    ) -> Result<Vec<Vec<u8>>> {
        self.repair_import_with_inputs(requested, items, |_| Ok(vec![]))
    }
}
