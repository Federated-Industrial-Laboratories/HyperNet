// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use serde::Serialize;

impl Journal {
    #[cfg(test)]
    pub fn create<T: Serialize>(directory: &Path, initial: &T) -> Result<Self> {
        let mut journal = Self::initialise(directory)?;
        journal.commit(initial)?;
        Ok(journal)
    }

    #[cfg(test)]
    pub fn commit<T: Serialize>(&mut self, state: &T) -> Result<()> {
        self.healthy()?;
        let bytes = serde_json::to_vec(state)?;
        self.commit_encoded(&bytes)
    }
}
