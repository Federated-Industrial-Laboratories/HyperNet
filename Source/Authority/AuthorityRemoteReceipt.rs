// SPDX-License-Identifier: MIT
// A signed remote effect report completes only its exact outgoing request and never releases a permit.
use super::*;
impl Store {
    /// Retain restrictive metadata from an exact already-known remote completion without releasing its effect.
    pub fn retain_media_context(
        &mut self,
        report: &crate::authority_domains::page::MediaReport,
    ) -> Result<()> {
        ensure!(
            self.remote_known(report.result(), "AuthorityDomain")?,
            "media context requires its established exact original completion"
        );
        crate::authority_domains::page::MediaRequest::parse(&hex::decode(
            &self
                .stored
                .tracker
                .ordinary
                .as_ref()
                .context("media request absent")?
                .signed,
        )?)?;
        let result = report.result();
        self.descriptor_for_scope(result.point().prefix().scope())?;
        let generations = self.next_generations(result)?;
        if generations == self.stored.generations {
            return Ok(());
        }
        let mut next = self.next()?;
        next.generations = generations;
        transaction::publish(
            self,
            next,
            transaction::Transition::RetainMediaContext {
                scope: hex::encode(wire::encode(&result.point().prefix().scope().value())?),
                certificate: hex::encode(result.point().certificate()),
                result: hex::encode(result.operation_result_bytes()),
            },
            proof::ContinuityEvidence {
                ancestry: vec![],
                history: None,
            },
        )
    }

    pub fn record_media(
        &mut self,
        report: crate::authority_domains::page::MediaReport,
    ) -> Result<Digest> {
        media_operation(report.request())?;
        let result = if self.remote_known(report.result(), "AuthorityDomain")? {
            report.into_verified()
        } else {
            report.into_result(self)?
        };
        self.record_remote(result, "AuthorityDomain")
    }

    // Only typed, verified service reports enter these private persistence helpers.
    fn remote_known(&self, result: &VerifiedResult, action: &str) -> Result<bool> {
        self.unchanged()?;
        let request = result.request().ordinary()?;
        let prior = self
            .stored
            .tracker
            .ordinary
            .as_ref()
            .context("remote report has no retained outgoing request")?;
        let intent = prior.request()?;
        ensure!(
            intent.digest == request.digest
                && intent.action == action
                && intent.requester == self.requester()
                && result.disposition() == Disposition::Permit
                && prior.effect != tracker::Effect::Claimed,
            "remote report differs from pending request or unresolved local effect"
        );
        Ok(prior.original.as_ref().is_some_and(|c| {
            c.disposition == 0
                && c.reason == 0
                && c.intent == request.digest
                && c.result_digest == result.executed.result
        }))
    }
    fn record_remote(&mut self, result: VerifiedResult, action: &str) -> Result<Digest> {
        let request = result.request().digest();
        if self.remote_known(&result, action)? {
            // Historical reporting preserves the current floor and cannot release the effect again.
            self.descriptor_for_scope(result.point().prefix().scope())?;
        } else {
            ensure!(
                result.point().prefix().scope() == self.descriptor.scope(),
                "remote report needs its original completion from current own-stream status"
            );
            self.check_history(&result)?;
            self.advance(&result, self.stored.wall_floor_ms)?;
        }
        let body = result.operation_result_bytes();
        let next = self
            .stored
            .tracker
            .body_saved(request, result.executed.result)?;
        if !self
            .stored
            .tracker
            .ordinary
            .as_ref()
            .context("outgoing tracker absent")?
            .body_saved
        {
            if transaction::exists(&self.directory, BODY)? {
                files::read_at(&self.directory, OsStr::new(BODY), wire::MAXIMUM, true)?;
            }
            files::atomic_at(&self.directory, OsStr::new(BODY), body, true)?;
            self.local(
                next,
                transaction::Transition::SaveBody {
                    request,
                    result: result.executed.result,
                },
                false,
            )?;
        } else {
            check_body(&self.directory, &self.stored)?;
        }
        if !self
            .stored
            .tracker
            .ordinary
            .as_ref()
            .context("outgoing tracker absent")?
            .complete
        {
            let next = self.stored.tracker.effect(request, false)?;
            self.local(next, transaction::Transition::Complete { request }, false)?;
        }
        self.unchanged()?;
        Ok(request)
    }
}

fn media_operation(intent: &crate::authority_proof::Intent) -> Result<()> {
    ensure!(
        matches!(
            crate::authority_domains::Operation::parse(intent)?.command,
            crate::authority_domains::Command::Page(
                crate::authority_domains::page::Command::MediaAuthorise { .. }
                    | crate::authority_domains::page::Command::Content(
                        crate::authority_domains::page::content::Command::Authorise { .. }
                    )
            ) | crate::authority_domains::Command::Federation(
                crate::authority_domains::federation::Command::MediaAuthorise { .. }
                    | crate::authority_domains::federation::Command::ContentAuthorise { .. }
            )
        ),
        "report is not a media effect"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityRemoteReceiptTests.rs"]
mod tests;
