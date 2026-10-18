// SPDX-License-Identifier: MIT
// A fresh signer must be fully voting, caught up and locked on the applied prefix.
use super::*;
// The evaluator already accounts for proposal admission plus local clock uncertainty.
pub(super) const READ_ADMISSION_MS: u64 =
    crate::authority_governance::UNCERTAINTY_MS - crate::authority_challenge::DELTA_MS;
impl Engine {
    pub(super) fn read_anchor(&self) -> Result<Node> {
        self.voting()?;
        ensure!(
            self.snapshot.applied == self.snapshot.committed,
            "fresh read application is behind committed state"
        );
        let applied = self.applied()?;
        let locked = self.known_certificate(&self.snapshot.locked)?;
        ensure!(
            extends(
                &self.configuration,
                &self.snapshot,
                self.snapshot.applied,
                locked.node
            )?,
            "fresh read lock is not an ancestor of applied state"
        );
        Ok(applied)
    }
    pub(super) fn sign_read(
        &self,
        statement: &crate::authority_read::Statement,
        now: u64,
    ) -> Result<Vec<u8>> {
        let node = self.read_anchor()?;
        ensure!(
            statement.scope == *self.configuration.descriptor().scope()
                && statement.height == node.height
                && statement.node == node.digest()?
                && statement.state == wire::digest(self.application())
                && statement.evaluated_at_ms >= node.evaluated_at
                && statement.evaluated_at_ms.abs_diff(now) <= READ_ADMISSION_MS
                && now
                    .checked_add(crate::authority_challenge::DELTA_MS)
                    .is_some_and(|upper| upper < statement.expires_at_ms),
            "fresh signing state or clock differs"
        );
        wire::sign_envelope(&statement.encode()?, &self.key)
    }
}

#[cfg(test)]
#[path = "ConsensusReadTests.rs"]
mod tests;
