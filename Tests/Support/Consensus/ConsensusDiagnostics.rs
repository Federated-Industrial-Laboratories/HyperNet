// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Diagnostics {
    #[cfg(test)]
    pub(super) fn signature_lookups(&self) -> u64 {
        self.activity.lock().unwrap().storage.envelope_cache_lookups
    }

    #[cfg(test)]
    pub(super) fn has_phase(&self, node: &super::Node, phase: Phase) -> bool {
        self.phases
            .lock()
            .unwrap()
            .views
            .get(&node.view)
            .is_some_and(|record| record.phases[phase as usize].is_some())
    }
}
