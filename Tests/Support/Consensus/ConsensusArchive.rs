// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn inclusion(leaves: impl AsRef<[Digest]>, index: usize) -> Result<Vec<Digest>> {
    let l = leaves.as_ref();
    inclusion_at(l, l.len(), index)
}

#[cfg(test)]
pub fn consistency(leaves: impl AsRef<[Digest]>, old: usize) -> Result<Vec<Digest>> {
    let l = leaves.as_ref();
    consistency_at(l, l.len(), old)
}

impl Archive {
    #[cfg(test)]
    pub fn leaves(&self) -> Vec<Digest> {
        (0..self.size).map(|i| self.get(i).unwrap()).collect()
    }
}
