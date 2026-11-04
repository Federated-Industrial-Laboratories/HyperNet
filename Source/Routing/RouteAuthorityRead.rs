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

// The actor retains the challenge and all mutable authority state. A worker receives
// only this immutable, bounded exchange snapshot; it cannot accept an observation.
#[derive(Clone)]
pub(crate) struct ReadExchange {
    descriptor: proof::TrustDescriptor,
    signed: Vec<u8>,
    challenge: Vec<u8>,
    deadline: u64,
    prefix: proof::Prefix,
    head: Option<crate::authority_history::TreeHead>,
}
pub(crate) type ReadCompletion = (transport::CertifiedReply, transport::HistoryEvidence);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadStage {
    PublishStart,
    PublishComplete,
}

// This span includes durable floor acceptance, domain publication and final checks.
// Its observer cannot replace an outcome or turn a failed publication into success.
pub(super) fn observe_acceptance<T>(
    mut trace: impl FnMut(ReadStage),
    accept: impl FnOnce() -> Result<T>,
) -> Result<T> {
    trace(ReadStage::PublishStart);
    let result = accept();
    trace(ReadStage::PublishComplete);
    result
}
pub(crate) struct PreparedRead {
    exchange: ReadExchange,
    command: DomainCommand,
    started: u64,
}
impl PreparedRead {
    pub(super) fn permit_session(&self, expected: &VersionRef) -> Result<()> {
        ensure!(
            matches!(&self.command, DomainCommand::Stream(streams::Command::Permit { session }) if session == expected),
            "application check does not bind the exact stream permit"
        );
        Ok(())
    }

    pub(crate) fn exchange(&self) -> ReadExchange {
        self.exchange.clone()
    }
    pub(crate) fn deadline(&self) -> u64 {
        self.exchange.deadline
    }
}
impl ReadExchange {
    pub(crate) fn run(
        self,
        mut current: impl FnMut() -> Result<authority_challenge::ClockHealth>,
    ) -> Result<ReadCompletion> {
        transport::remaining(self.deadline)?;
        current()?.observe()?;
        transport::exchange_read(
            &self.descriptor,
            &self.signed,
            &self.challenge,
            self.deadline,
            Path::new("/Authority/Control.sock"),
            &self.prefix,
            self.head.as_ref(),
            &mut current,
        )
        .map_err(Client::retry_read)
        .context("obtain fresh Route context and history")
    }
}

pub(super) fn issue_challenge(
    session: &mut Session,
    request: &[u8],
    recipient: &ed25519_dalek::SigningKey,
    nonce: Digest,
    deadline: u64,
    challenge_ceiling: Option<u64>,
    health: authority_challenge::ClockHealth,
) -> Result<Vec<u8>> {
    // A short wait must not become an unusably short signed freshness window.
    // Only an existing check supplies a separate, already fixed original ceiling.
    session.issue_read(
        request,
        recipient,
        nonce,
        authority_challenge::MAXIMUM_DURATION_MS,
        Some(challenge_ceiling.unwrap_or(deadline)),
        health,
    )
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
        let prepared = self.prepare_read(command, challenge_ceiling)?;
        let completion = prepared.exchange().run(|| self.guard.health());
        self.finish_read(prepared, completion, |_| {})
    }

    pub(super) fn prepare_read(
        &mut self,
        command: DomainCommand,
        challenge_ceiling: Option<u64>,
    ) -> Result<PreparedRead> {
        ensure!(
            matches!(
                command,
                DomainCommand::Route(
                    routes::Command::Lookup { .. } | routes::Command::VoucherContext { .. }
                ) | DomainCommand::Stream(
                    streams::Command::Inspect { .. }
                        | streams::Command::Permit { .. }
                        | streams::Command::RetirementContext { .. }
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
        let challenge_ceiling = challenge_ceiling
            .into_iter()
            .chain(self.read_challenge_ceiling)
            .min();
        let challenge = issue_challenge(
            &mut self.session,
            &signed,
            &self.config.key,
            nonce,
            deadline,
            challenge_ceiling,
            health,
        )?;
        Ok(PreparedRead {
            exchange: ReadExchange {
                descriptor,
                signed,
                challenge,
                deadline,
                prefix: self.store.prefix().clone(),
                head: self.store.tree_head().cloned(),
            },
            command,
            started,
        })
    }

    pub(crate) fn discard_read(&mut self, prepared: PreparedRead) -> Result<()> {
        self.session.discard(&prepared.exchange.challenge)
    }

    pub(super) fn finish_read(
        &mut self,
        prepared: PreparedRead,
        completion: Result<ReadCompletion>,
        mut trace: impl FnMut(ReadStage),
    ) -> Result<Observation> {
        let PreparedRead {
            exchange,
            command,
            started,
        } = prepared;
        let ReadExchange {
            descriptor,
            signed,
            challenge,
            deadline,
            ..
        } = exchange;
        let outcome = (|| {
            self.active.check(self.guard)?;
            transport::remaining(deadline)?;
            ensure!(
                self.store.resume_ordinary()?.is_none() && self.store.resume_fence()?.is_none(),
                "fresh Route authority requester is busy"
            );
            let (reply, history) = completion?;
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
                let consumed = observe_acceptance(&mut trace, || {
                    self.store.observe_read_consumed(
                        verified,
                        &mut self.session,
                        self.guard.health()?,
                        0,
                    )
                })?;
                transport::acknowledge_read(
                    &consumed,
                    &self.config.key,
                    deadline,
                    Path::new("/Authority/Control.sock"),
                );
                return Ok(observation);
            }
            let expiry = verified
                .statement
                .expires_at_ms
                .saturating_sub(authority_challenge::DELTA_MS);
            let candidate = candidate.context("fresh Route permit omitted verified context")?;
            transport::remaining(deadline)?;
            let (value, consumed) = observe_acceptance(&mut trace, || {
                self.store.accept_read_consumed(
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
                )
            })?;
            transport::acknowledge_read(
                &consumed,
                &self.config.key,
                deadline,
                Path::new("/Authority/Control.sock"),
            );
            // Retirement metadata does not certify permission to forward bytes.
            if !matches!(
                command,
                DomainCommand::Stream(streams::Command::RetirementContext { .. })
            ) {
                self.last_expiry = expiry;
            }
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
