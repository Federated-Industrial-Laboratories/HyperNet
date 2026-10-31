// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Evidence {
    #[cfg(test)]
    pub(super) fn at_capacity() -> Self {
        // Synthetic bytes are only for capacity preflight. Historical evidence
        // validation still requires a signed mutation and its exact derivation.
        let maximum = crate::authority_capacity::MAX_OTHER_EVIDENCE;
        let total = crate::authority_capacity::MAX_EVIDENCE_BYTES;
        let mut entries = Vec::new();
        for seed in 0..total.div_ceil(maximum) {
            let mut entry = Entry {
                created: VersionRef {
                    kind: 102,
                    id: wire::digest(&(seed as u64).to_be_bytes()),
                    generation: 1,
                    digest: [1; 32],
                },
                signed: vec![0; maximum],
                height: 1,
                at: 1000,
            };
            let excess = wire::encode(&entry.value()).unwrap().len() - maximum;
            entry.signed.truncate(entry.signed.len() - excess);
            assert_eq!(wire::encode(&entry.value()).unwrap().len(), maximum);
            entries.push(entry);
        }
        entries.sort_by_key(|entry| entry.created.index());
        let mut evidence = Self(entries);
        let excess = wire::encode_state(&evidence.value()).unwrap().len() - total;
        let last = evidence.0.last_mut().unwrap();
        last.signed.truncate(last.signed.len() - excess);
        assert_eq!(evidence.charge().unwrap(), total);
        evidence
    }
}
