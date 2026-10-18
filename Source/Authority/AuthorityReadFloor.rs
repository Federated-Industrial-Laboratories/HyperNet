// SPDX-License-Identifier: MIT
// Fresh reads advance witnessed authority without changing the ordinary effect tracker.
use super::*;
use crate::authority_read::VerifiedRead;
impl Store {
    pub fn attach_read_history(
        &self,
        result: VerifiedRead,
        checkpoint: &[u8],
        history: &[u8],
    ) -> Result<VerifiedRead> {
        self.unchanged()?;
        let checkpoint = history::verify_checkpoint(&self.descriptor, checkpoint)?;
        result.attach_history(history::verify_history(
            &checkpoint,
            &self.floor,
            self.tree_head(),
            history,
        )?)
    }
    fn read_ready(&self, result: &VerifiedRead) -> Result<()> {
        self.unchanged()?;
        self.unsealed()?;
        self.require_requester(result.request.requester)?;
        ensure!(
            self.resume_ordinary()?.is_none() && self.resume_fence()?.is_none(),
            "fresh read cannot resolve an uncertain ordinary effect"
        );
        ensure!(
            result.request.scope == *self.descriptor.scope()
                && result.point().prefix().scope() == self.descriptor.scope()
                && result.request.minimum_height >= self.floor.height(),
            "fresh read context or causal floor differs"
        );
        if let Some(history) = result.history() {
            ensure!(
                history.from() == self.prefix() && history.prior() == self.tree_head(),
                "fresh read history differs from retained prefix"
            );
        }
        result.extends(&self.floor)
    }
    fn advance_read(&mut self, result: &VerifiedRead, wall: u64) -> Result<()> {
        let mut known: BTreeMap<_, _> = self
            .stored
            .generations
            .iter()
            .map(|r| (r.index(), r.clone()))
            .collect();
        for value in result
            .request
            .query
            .expected()
            .iter()
            .chain(result.generations())
        {
            if let Some(prior) = known.get(&value.index()) {
                ensure!(
                    value.generation >= prior.generation
                        && (value.generation != prior.generation || value.digest == prior.digest),
                    "fresh read is below a retained generation"
                );
            }
        }
        for value in result.generations() {
            known.insert(value.index(), value.clone());
        }
        ensure!(
            known.len() <= crate::authority_capacity::MAX_RECORDS,
            "fresh read floor capacity reached"
        );
        let mut next = self.next()?;
        next.generations = known.into_values().collect();
        next.certificate = Some(hex::encode(result.point().certificate()));
        next.node = Some(hex::encode(result.point().node()));
        next.checkpoint_proof = result
            .history()
            .map(|h| hex::encode(h.checkpoint().canonical_proof()))
            .or_else(|| self.stored.checkpoint_proof.clone());
        next.wall_floor_ms = wall;
        transaction::publish(
            self,
            next,
            transaction::Transition::LearnRead {
                result: hex::encode(result.operation_result_bytes()),
            },
            result.continuity(),
        )
    }
    pub fn observe_read(
        &mut self,
        result: VerifiedRead,
        session: &mut Session,
        health: ClockHealth,
        not_before: u64,
    ) -> Result<()> {
        self.read_ready(&result)?;
        ensure!(
            result.result.disposition == Disposition::Refuse,
            "fresh observation requires a refusal"
        );
        let now = session.check_read(&result, not_before, health)?;
        ensure!(
            now.wall_ms >= self.stored.wall_floor_ms,
            "fresh read wall clock below durable floor"
        );
        self.advance_read(&result, now.wall_ms)?;
        let consumed = session.consume_read(&result, not_before, health)?;
        session.finish_consumption(consumed, health)?;
        Ok(())
    }
    pub fn accept_read<T>(
        &mut self,
        result: VerifiedRead,
        session: &mut Session,
        health: ClockHealth,
        not_before: u64,
        publish: impl FnOnce(&OperationResult, &mut Store) -> Result<T>,
    ) -> Result<T> {
        self.read_ready(&result)?;
        ensure!(
            result.result.disposition == Disposition::Permit,
            "fresh read permit required"
        );
        let now = session.check_read(&result, not_before, health)?;
        ensure!(
            now.wall_ms >= self.stored.wall_floor_ms,
            "fresh read wall clock below durable floor"
        );
        self.advance_read(&result, now.wall_ms)?;
        let consumed = session.consume_read(&result, not_before, health)?;
        let output = publish(&result.result, self)?;
        self.unchanged()?;
        session.finish_consumption(consumed, health)?;
        Ok(output)
    }
}
