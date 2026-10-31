// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Mailbox {
    #[cfg(test)]
    pub(super) fn push(&self, body: Vec<u8>) -> Result<()> {
        self.push_class(body, Class::Transient)
    }

    #[cfg(test)]
    pub(super) fn try_pop(&self) -> Result<Option<Vec<u8>>> {
        let mut q = self
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("Peer mailbox failed"))?;
        let now = Instant::now();
        Ok(q.pop(Lane::Recovery, now)
            .or_else(|| q.pop(Lane::General, now)))
    }
}
