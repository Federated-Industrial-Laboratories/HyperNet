// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Streams {
    /// The containing application commits this receipt and its permitted effect in one state.
    /// Authority and exact-snapshot checks use the original state before this retirement.
    #[cfg(test)]
    pub fn record(
        &mut self,
        request: &Request,
        proposed_result: &[u8],
        capacity_refusal: &[u8],
    ) -> Result<Recorded> {
        self.record_reserved(request, proposed_result, capacity_refusal, &BTreeSet::new())
    }
}
