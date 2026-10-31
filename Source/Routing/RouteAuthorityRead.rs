// SPDX-License-Identifier: MIT
// Fresh route contexts renew permission without consuming an ordinary request sequence.
use super::*;
use crate::authority_read::{self as fresh, Query};

pub(super) struct Observation {
    pub value: Option<V>,
    pub statement: fresh::Statement,
    pub disposition: Disposition,
    pub code: u64,
}

impl Client<'_> {
    pub(crate) fn retry_read(error: anyhow::Error) -> anyhow::Error {
        use crate::route_runtime::ReadRetry;
        if error.is::<ReadRetry>() {
            error
        } else if error.is::<transport::FreshReadUnavailable>() {
            error.context(ReadRetry::FreshQuorumUnavailable)
        } else if error.is::<transport::HistoryOvertaken>() {
            error.context(ReadRetry::HistoryOvertaken)
        } else if error.is::<authority_challenge::ChallengeExpired>() {
            error.context(ReadRetry::ChallengeExpired)
        } else if transport::transport_closed(&error) {
            error.context(ReadRetry::TransportClosed)
        } else {
            error
        }
    }

    pub(super) fn read_action(&mut self, command: DomainCommand) -> Result<V> {
        let observation = self.read_observation(command, None)?;
        ensure!(
            observation.disposition == Disposition::Permit,
            "Route maintenance refused with code {}",
            observation.code
        );
        observation
            .value
            .context("fresh Route permit omitted verified context")
    }

    pub(super) fn read_observation(
        &mut self,
        command: DomainCommand,
        challenge_ceiling: Option<u64>,
    ) -> Result<Observation> {
        ensure!(
            matches!(
                command,
                DomainCommand::Route(
                    routes::Command::Lookup { .. } | routes::Command::VoucherContext { .. }
                ) | DomainCommand::Stream(
                    streams::Command::Inspect { .. } | streams::Command::Permit { .. }
                )
            ),
            "fresh Route retry requires a read-only context operation"
        );
        let started = authority_challenge::boot_time_ms()?;
        self.permitted(&command)?;
        let descriptor = self.store.descriptor().clone();
        let operation = Operation {
            grant: None,
            command: command.clone(),
            snapshot: domains::snapshot(&a(vec![
                a(vec![
                    V::Uint(self.store.prefix().scope().epoch),
                    V::Uint(self.store.prefix().height()),
                    b(self.store.prefix().policy_state()),
                ]),
                a(vec![]),
            ]))?,
        };
        let nonce = random()?;
        let signed = fresh::Request::sign(
            descriptor.scope(),
            &self.config.key,
            self.store.requester(),
            nonce,
            self.store.prefix().height(),
            Query::Domain(operation),
        )?;
        let health = self.guard.health()?;
        let now = health.observe()?;
        let maximum_deadline = now
            .boot_ms
            .checked_add(authority_challenge::MAXIMUM_DURATION_MS)
            .context("Route read deadline overflow")?;
        let deadline = self
            .deadline
            .map_or(maximum_deadline, |original| original.min(maximum_deadline));
        transport::remaining(deadline)?;
        // The authority's uncertainty interval needs a full freshness window even
        // for short caller waits. Neither transport nor local effects acquire it.
        let challenge_ceiling = challenge_ceiling.unwrap_or(deadline);
        let challenge = self.session.issue_read(
            &signed,
            &self.config.key,
            nonce,
            authority_challenge::MAXIMUM_DURATION_MS,
            Some(challenge_ceiling),
            health,
        )?;
        let outcome = (|| {
            let (reply, history) = transport::exchange_read(
                &descriptor,
                &signed,
                &challenge,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
            )
            .map_err(Self::retry_read)
            .context("obtain fresh Route context and history")?;
            let mut candidate = None;
            let verified = fresh::verify_response(
                &descriptor,
                &signed,
                &challenge,
                fresh::Response {
                    node: &reply.node,
                    certificate: &reply.certificate,
                    result: &reply.result,
                    ancestry: &history.nodes,
                },
                |request, result, statement| {
                    let (state, records) = self.disk.context();
                    let selected = fresh::verify_domain(
                        &self.guard.bootstrap,
                        state,
                        records,
                        request,
                        result,
                        statement,
                        &[],
                    )?;
                    ensure!(
                        selected.updates.is_empty(),
                        "fresh Route context changes domain state"
                    );
                    result::minimum(&selected.versions, self.store.generations())?;
                    let versions = selected.versions.clone();
                    candidate = Some(selected);
                    Ok(versions)
                },
            )
            .context("verify fresh Route authority context")?;
            let verified = history.attach_read(&self.store, verified)?;
            let mut observation = Observation {
                value: None,
                statement: verified.statement.clone(),
                disposition: verified.result.disposition,
                code: verified.result.code,
            };
            if verified.result.disposition != Disposition::Permit {
                self.store
                    .observe_read(verified, &mut self.session, self.guard.health()?, 0)?;
                return Ok(observation);
            }
            let expiry = verified
                .statement
                .expires_at_ms
                .saturating_sub(authority_challenge::DELTA_MS);
            let candidate = candidate.context("fresh Route permit omitted verified context")?;
            transport::remaining(deadline)?;
            let value = self.store.accept_read(
                verified,
                &mut self.session,
                self.guard.health()?,
                0,
                |_, _| {
                    self.active.check(self.guard)?;
                    self.disk.publish(candidate.state, candidate.records)?;
                    self.active.check(self.guard)?;
                    transport::remaining(deadline)?;
                    Ok(candidate.value)
                },
            )?;
            self.last_expiry = expiry;
            observation.value = Some(value);
            Ok(observation)
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        } else {
            self.costs.observe(
                &command,
                self.config.profile.identity.service,
                authority_challenge::boot_time_ms()?.saturating_sub(started),
            );
        }
        outcome.map_err(Self::retry_read)
    }
}
