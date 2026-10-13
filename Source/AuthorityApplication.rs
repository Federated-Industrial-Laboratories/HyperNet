// SPDX-License-Identifier: MIT
// Deterministic governance commits exact changes, results and replay receipts together.
use crate::{
    authority_governance::Governance,
    authority_membership::Reservations,
    authority_proof::{Challenge, Intent, SignedRequest, VersionRef},
    consensus::{
        Committed, Execution, ExecutionOutput,
        records::{Configuration, OrderedRequest},
        runtime::Application,
    },
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::sync::{Arc, Mutex};

#[path = "AuthorityEpochEvaluation.rs"]
mod epoch_evaluation;
#[path = "AuthorityMutationEvidence.rs"]
mod mutation_evidence;
#[path = "AuthorityStreams.rs"]
mod streams;
#[path = "AuthorityTransactions.rs"]
mod transactions;

const MAX_GOVERNANCE_BYTES: usize = crate::authority_capacity::MAX_GOVERNANCE_BYTES;
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn array(values: Vec<V>) -> V {
    V::Array(values)
}
fn reference(value: &VersionRef) -> V {
    array(vec![
        V::Uint(value.kind),
        b(&value.id),
        V::Uint(value.generation),
        b(&value.digest),
    ])
}
#[derive(Clone)]
struct State {
    records: Vec<Vec<u8>>,
    streams: streams::Streams,
    height: u64,
    reservations: Reservations,
    evidence: mutation_evidence::Evidence,
    domains: crate::authority_domains::State,
    terminal: Option<crate::authority_epoch::Terminal>,
    origin: Option<crate::authority_epoch::Origin>,
}
impl State {
    fn parse(config: &Configuration, bytes: &[u8]) -> Result<Self> {
        let started = std::time::Instant::now();
        let parsed = Self::parse_complete(config, bytes);
        crate::consensus::timing::state_parse(started.elapsed());
        parsed
    }
    fn parse_complete(config: &Configuration, bytes: &[u8]) -> Result<Self> {
        let decoded = wire::decode_state(bytes)?;
        let list = decoded.list(13)?;
        ensure!(list.len() >= 2, "truncated application state");
        let genesis = list[0].uint()? == 15;
        let (records, height, stream_value, reservation_value, evidence_value) = if genesis {
            let f = decoded.array(6)?;
            ensure!(
                wire::digest(bytes) == config.genesis_governance
                    && f[1].uint()? == 1
                    && f[2].fixed::<32>()? == config.scope.network
                    && f[3].fixed::<32>()? == config.scope.incarnation,
                "genesis state differs from the pinned governance"
            );
            (f[4].list(35)?, 0, None, &f[5], None)
        } else {
            let f = decoded.array(13)?;
            ensure!(
                f[0].uint()? == 250
                    && f[1].uint()? == 1
                    && f[2].fixed::<32>()? == config.scope.network
                    && f[3].fixed::<32>()? == config.scope.incarnation
                    && f[4].uint()? == config.scope.epoch,
                "application state context differs"
            );
            (
                f[6].list(crate::authority_capacity::MAX_RECORDS)?,
                f[5].uint()?,
                Some(&f[7]),
                &f[8],
                Some(&f[9]),
            )
        };
        let records = records
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let reservations = Reservations::parse(reservation_value)?;
        let governance =
            Governance::parse(config.scope.network, config.scope.incarnation, &records)?;
        let versions = governance.versions();
        let mut initial = Vec::new();
        let mut created = Vec::new();
        let mut member_keys = std::collections::BTreeSet::new();
        for (bytes, version) in records.iter().zip(&versions) {
            let value = wire::decode(bytes)?;
            let fields = value.list(32)?;
            if version.kind == 131
                || fields.last() == Some(&V::Null) && matches!(version.kind, 100 | 101 | 102 | 114)
            {
                initial.push(b(bytes));
            } else {
                ensure!(
                    !genesis
                        && matches!(
                            version.kind,
                            102 | 105 | 117 | 125 | 126 | 127 | 128 | 129 | 130
                        ),
                    "unsupported post-genesis governance record"
                );
                if version.kind == 125 {
                    let key = fields[7].fixed()?;
                    ensure!(
                        !reservations.contains(&key) && !fields[9].boolean()?,
                        "reserved or unsupported membership identity"
                    );
                    member_keys.insert(key);
                } else if version.kind == 127 {
                    let key = fields[6].fixed()?;
                    ensure!(
                        !reservations.contains(&key),
                        "application reuses a dedicated role key"
                    );
                    member_keys.insert(key);
                } else if version.kind == 102 {
                    ensure!(
                        !reservations.contains(&fields[8].fixed()?),
                        "delegation reuses a dedicated role key"
                    );
                }
                created.push((version.clone(), bytes.clone()));
            }
        }
        // Reconstruct the immutable bootstrap subset, including its role keys. A
        // checkpoint cannot replace role reservations or add unaudited root grants.
        let initial = wire::encode(&array(vec![
            V::Uint(15),
            V::Uint(1),
            b(&config.scope.network),
            b(&config.scope.incarnation),
            array(initial),
            reservations.value(),
        ]))?;
        ensure!(
            wire::digest(&initial) == config.bootstrap_anchor,
            "retained genesis or role reservations changed"
        );
        let evidence = if let Some(value) = evidence_value {
            mutation_evidence::Evidence::parse(config, value, height, &created)?
        } else {
            mutation_evidence::Evidence::default()
        };
        let policy = wire::decode(governance.record_bytes(100, config.scope.network)?)?;
        for root in policy.array(17)?[15].list(16)? {
            let grant = wire::decode(governance.record_bytes(102, root.fixed()?)?)?;
            member_keys.insert(grant.array(17)?[8].fixed()?);
        }
        let deployments = crate::authority_deployment_records::Index::parse(
            &records,
            &reservations,
            config.scope.network,
            config.scope.incarnation,
        )?;
        member_keys.extend(deployments.streams());
        let domains = if genesis {
            crate::authority_domains::State::empty(config.scope.network, config.scope.incarnation)
        } else {
            crate::authority_domains::State::parse(
                &decoded.array(13)?[10],
                config.scope.network,
                config.scope.incarnation,
            )?
        };
        member_keys.extend(domains.requesters());
        let streams = if let Some(value) = stream_value {
            let streams =
                streams::Streams::parse(config.scope.network, config.scope.incarnation, value)?;
            ensure!(
                streams.keys() == member_keys.iter().copied().collect::<Vec<_>>(),
                "stream admissions differ from permanent identity classes"
            );
            streams
        } else {
            let mut streams = streams::Streams::default();
            for key in member_keys {
                streams.admit(config.scope.network, config.scope.incarnation, key)?;
            }
            streams
        };
        let scope = crate::authority_proof::Scope {
            network: config.scope.network,
            incarnation: config.scope.incarnation,
            configuration: config.scope.configuration,
            epoch: config.scope.epoch,
        };
        let (terminal, origin) = if genesis {
            (None, None)
        } else {
            let f = decoded.array(13)?;
            (
                crate::authority_epoch::Terminal::parse(&f[11], &scope)?,
                crate::authority_epoch::Origin::parse(&f[12], &scope)?,
            )
        };
        domains.validate_roles(&records, &reservations)?;
        let state = Self {
            domains,
            terminal,
            origin,
            records,
            streams,
            height,
            reservations,
            evidence,
        };
        state.capacity()?;
        Ok(state)
    }
    fn deployments(&self) -> Result<crate::authority_deployment_records::Index> {
        let value = wire::decode(&self.records[0])?;
        let f = value.list(32)?;
        crate::authority_deployment_records::Index::parse(
            &self.records,
            &self.reservations,
            f[2].fixed()?,
            f[3].fixed()?,
        )
    }
    fn capacity(&self) -> Result<()> {
        self.domains.charge()?;
        let index = self.deployments()?;
        let count = index.open_count();
        let evidence = self.evidence.charge()?;
        ensure!(
            self.records.len() + count <= crate::authority_capacity::MAX_RECORDS
                && evidence + count * crate::authority_capacity::MAX_OTHER_EVIDENCE
                    <= crate::authority_capacity::MAX_EVIDENCE_BYTES
                && self.records.iter().map(Vec::len).sum::<usize>()
                    + evidence
                    + count
                        * (crate::authority_capacity::MAX_OTHER_EVIDENCE
                            + crate::authority_capacity::WITHDRAWAL_RECORD_RESERVE)
                    <= MAX_GOVERNANCE_BYTES,
            "governance and terminal withdrawal reservation exceed capacity"
        );
        self.streams.validate_reserve(&index.open_operators())?;
        Ok(())
    }
    fn encode(&self, config: &Configuration) -> Result<Vec<u8>> {
        wire::encode_state(&array(vec![
            V::Uint(250),
            V::Uint(1),
            b(&config.scope.network),
            b(&config.scope.incarnation),
            V::Uint(config.scope.epoch),
            V::Uint(self.height),
            array(self.records.iter().map(|v| b(v)).collect()),
            self.streams.value(),
            self.reservations.value(),
            self.evidence.value(),
            self.domains.value(),
            self.terminal.as_ref().map_or(V::Null, |v| v.value()),
            self.origin.as_ref().map_or(V::Null, |v| v.value()),
        ]))
    }
}
fn stream_request(intent: &Intent) -> streams::Request {
    streams::Request {
        requester: intent.requester,
        generation: intent.generation,
        generation_id: intent.generation_id,
        sequence: intent.sequence,
        acknowledged_through: intent.acknowledged_through,
        intent: intent.digest,
    }
}
fn minimum_code(first: u64, second: u64) -> u64 {
    match (first, second) {
        (0, _) => second,
        (_, 0) => first,
        _ => first.min(second),
    }
}
fn result(action: &str, code: u64, value: &[u8]) -> Result<Vec<u8>> {
    wire::encode(&array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(action.into()),
        V::Uint(u64::from(code != 0)),
        V::Uint(code),
        b(value),
    ]))
}
struct VerifiedState {
    bytes: Vec<u8>,
    state: Arc<State>,
}
pub struct PolicyApplication {
    config: Configuration,
    verified: Mutex<Option<VerifiedState>>,
    #[cfg(test)]
    state_parses: std::sync::atomic::AtomicUsize,
}
impl PolicyApplication {
    /// The complete bootstrap, including genesis grants and custody acceptance, is verified before construction.
    pub fn new(config: Configuration) -> Self {
        Self {
            config,
            verified: Mutex::new(None),
            #[cfg(test)]
            state_parses: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    // Only immutable state validation is reused, under this fixed configuration.
    // Request authority and time-dependent decisions are evaluated separately.
    fn verified_state(&self, bytes: &[u8]) -> Result<Arc<State>> {
        ensure!(
            bytes.len() <= crate::authority_capacity::MAX_STATE_BYTES,
            "authority state exceeds its bound"
        );
        let mut retained = self
            .verified
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state validation is unavailable"))?;
        if let Some(entry) = retained.as_ref()
            && entry.bytes == bytes
        {
            crate::consensus::timing::state_cache_hit();
            return Ok(Arc::clone(&entry.state));
        }
        #[cfg(test)]
        self.state_parses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = Arc::new(State::parse(&self.config, bytes)?);
        *retained = Some(VerifiedState {
            bytes: bytes.to_vec(),
            state: Arc::clone(&state),
        });
        Ok(state)
    }

    fn inert(&self, command: &[u8]) -> Result<bool> {
        let value = wire::decode(command)?;
        let fields = value.list(6)?;
        if fields.first().context("empty authority command")?.uint()? != 53 {
            return Ok(false);
        }
        use crate::consensus::records::Command;
        Ok(matches!(
            Command::parse(&self.config, command)?,
            Command::Inert | Command::Noop(_)
        ))
    }
}
impl PolicyApplication {
    fn decode(&self, ordered: &[u8]) -> Result<(OrderedRequest, SignedRequest, Challenge)> {
        let request = OrderedRequest::parse(&self.config, ordered)?;
        let f = wire::decode(ordered)?;
        let f = f.array(6)?;
        let signed = SignedRequest::from_signed(f[3].bytes()?)?;
        let challenge = Challenge::from_signed(f[4].bytes()?)?;
        let expected = if let SignedRequest::Intent(intent) = &signed {
            match transactions::Operation::parse(intent, &self.config)? {
                transactions::Operation::Runtime(runtime) => runtime.recipient,
                transactions::Operation::Domain(domain) if domain.command.serving() => {
                    challenge.recipient
                }
                _ => signed.requester(),
            }
        } else {
            signed.requester()
        };
        ensure!(
            challenge.recipient == expected,
            "challenge recipient differs from the operation's exact recipient"
        );
        Ok((request, signed, challenge))
    }
    fn context_code(&self, request: &SignedRequest, state: &State) -> u64 {
        let epoch = request.minimum_policy_epoch();
        if epoch > self.config.scope.epoch
            || (epoch == self.config.scope.epoch && request.minimum_policy_height() > state.height)
        {
            21
        } else if epoch != self.config.scope.epoch {
            37
        } else {
            0
        }
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn ordinary(
        &self,
        prior: &[u8],
        state: &mut State,
        intent: &Intent,
        request: &OrderedRequest,
        committed: &Committed,
        context_code: u64,
        recipient: crate::authority_proof::Key,
        inputs: &crate::authority_objects::Resolved,
    ) -> Result<(Vec<u8>, u64, u64, crate::authority_proof::Restrictions)> {
        let at = committed.evaluated_at;
        let stream = stream_request(intent);
        let (fresh, replay, stream_code) = match state.streams.classify(&stream)? {
            streams::Classification::Fresh => (true, None, 0),
            streams::Classification::Replay(value) => (false, Some(value.to_vec()), 0),
            streams::Classification::Missing => (false, None, 3),
            streams::Classification::Retired => (false, None, 21),
            streams::Classification::Gap => (false, None, 12),
            streams::Classification::Conflict | streams::Classification::GenerationConflict => {
                (false, None, 28)
            }
        };
        let operation = transactions::Operation::parse(intent, &self.config)?;
        if context_code == 0
            && stream_code == 0
            && matches!(
                operation,
                transactions::Operation::Application(_) | transactions::Operation::Deployment(_)
            )
            && let Some(previous) = &replay
        {
            let code = crate::authority_proof::OperationResult::parse(previous)?.code;
            // A finite empty refusal is already complete; it has no created record
            // or protected body whose authority must be revalidated for disclosure.
            if code != 0 && *previous == refusal(&intent.action, code)? {
                return Ok((previous.clone(), code, request.expires, Default::default()));
            }
        }
        // Authority and exact snapshots refer to the state before acknowledgement.
        let decision = transactions::evaluate(
            &operation,
            state,
            &self.config,
            prior,
            intent,
            transactions::Evaluation {
                at,
                expires: request.expires,
                replay: replay.is_some(),
                recipient,
            },
            inputs,
        )?;
        let mut code = minimum_code(minimum_code(decision.code, context_code), stream_code);
        let mut output = if code == 0 {
            result(&intent.action, 0, &wire::encode(&decision.value)?)?
        } else {
            refusal(&intent.action, code)?
        };
        if output.len() > crate::consensus::MAX_RESULT_BYTES {
            code = minimum_code(code, 2);
            output = refusal(&intent.action, code)?;
        }
        if let Some(previous) = replay {
            if code == 0 {
                let old_code = crate::authority_proof::OperationResult::parse(&previous)?.code;
                if old_code != 0 || previous == output {
                    output = previous;
                    code = old_code;
                } else {
                    code = 12;
                    output = refusal(&intent.action, code)?;
                }
            }
            // A current disclosure refusal never overwrites the original completion.
        } else if fresh {
            let mut candidate = state.clone();
            if code == 0
                && let Some(records) = decision.records
            {
                candidate.records = records;
                let prepared = (|| -> Result<()> {
                    candidate.evidence.insert(
                        decision
                            .created
                            .context("mutation has no created reference")?,
                        wire::decode(&committed.command)?.array(6)?[3].bytes()?,
                        committed.height,
                        at,
                    )?;
                    for member in &decision.admissions {
                        ensure!(
                            !candidate.streams.keys().contains(member),
                            "new membership already has a stream"
                        );
                        candidate.streams.admit(
                            self.config.scope.network,
                            self.config.scope.incarnation,
                            *member,
                        )?;
                    }
                    candidate.capacity()?;
                    Ok(())
                })();
                if prepared.is_err() {
                    code = 2;
                    output = refusal(&intent.action, 2)?;
                    candidate = state.clone();
                }
            }
            if code == 0
                && let Some(domains) = decision.domains
            {
                candidate.domains = domains;
                let prepared = (|| -> Result<()> {
                    for member in &decision.admissions {
                        ensure!(
                            !candidate.streams.keys().contains(member),
                            "mail device already has a stream"
                        );
                        candidate.streams.admit(
                            self.config.scope.network,
                            self.config.scope.incarnation,
                            *member,
                        )?;
                    }
                    candidate.capacity()?;
                    Ok(())
                })();
                if prepared.is_err() {
                    code = 2;
                    output = refusal(&intent.action, 2)?;
                    candidate = state.clone();
                }
            }
            if code == 0
                && let Some(terminal) = decision.terminal
            {
                candidate.terminal = Some(terminal);
            }
            let operators = candidate.deployments()?.open_operators();
            let recorded = candidate.streams.record_reserved(
                &stream,
                &output,
                &refusal(&intent.action, 2)?,
                &operators,
            )?;
            output = recorded.result;
            code = crate::authority_proof::OperationResult::parse(&output)?.code;
            if recorded.proposed_result_retained
                && code == 0
                && candidate.capacity().is_ok()
                && candidate.encode(&self.config).is_ok()
            {
                *state = candidate;
            } else {
                // Rejected capacity cannot publish the candidate record, stream or evidence.
                if code == 0 {
                    output = refusal(&intent.action, 2)?;
                }
                let operators = state.deployments()?.open_operators();
                let recorded = state.streams.record_reserved(
                    &stream,
                    &output,
                    &refusal(&intent.action, 2)?,
                    &operators,
                )?;
                output = recorded.result;
                code = crate::authority_proof::OperationResult::parse(&output)?.code;
            }
        }
        Ok((output, code, decision.expires, decision.restrictions))
    }
}
impl Application for PolicyApplication {
    fn command_inputs(&self, ordered: &[u8]) -> Result<Vec<crate::authority_objects::Reference>> {
        if self.inert(ordered)? {
            return Ok(vec![]);
        }
        let (_, signed, _) = self.decode(ordered)?;
        match signed {
            SignedRequest::Intent(intent)
                if crate::authority_domains::Operation::handles(&intent.action) =>
            {
                Ok(crate::authority_domains::Operation::parse(&intent)?
                    .command
                    .command_inputs())
            }
            _ => Ok(vec![]),
        }
    }
    fn required_inputs(
        &self,
        prior: &[u8],
        ordered: &[u8],
    ) -> Result<Vec<crate::authority_objects::Reference>> {
        if self.inert(ordered)? {
            return Ok(vec![]);
        }
        let (_, signed, _) = self.decode(ordered)?;
        match signed {
            SignedRequest::Intent(intent)
                if crate::authority_domains::Operation::handles(&intent.action) =>
            {
                let state = self.verified_state(prior)?;
                crate::authority_domains::Operation::parse(&intent)?
                    .command
                    .required_inputs(&state.domains)
            }
            _ => Ok(vec![]),
        }
    }
    fn retained_inputs(&self, bytes: &[u8]) -> Result<Vec<crate::authority_objects::Reference>> {
        crate::authority_domains::retained_inputs(&self.verified_state(bytes)?.domains)
    }
    fn result_inputs(
        &self,
        ordered: &[u8],
        result: &[u8],
    ) -> Result<Vec<crate::authority_objects::Reference>> {
        if self.inert(ordered)? {
            return Ok(vec![]);
        }
        let (_, signed, _) = self.decode(ordered)?;
        let result = crate::authority_proof::OperationResult::parse(result)?;
        ensure!(
            result.action == signed.action(),
            "result input action differs from ordered request"
        );
        match signed {
            SignedRequest::Intent(intent)
                if result.disposition == crate::authority_proof::Disposition::Permit
                    && crate::authority_domains::Operation::handles(&intent.action) =>
            {
                crate::authority_domains::response_inputs(&intent, &wire::decode(&result.value)?)
            }
            _ => Ok(vec![]),
        }
    }
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()> {
        ensure!(
            self.verified_state(state)?.height == height,
            "checkpoint application height differs from its certified anchor"
        );
        Ok(())
    }
    fn validate(
        &self,
        prior: &[u8],
        ordered: &[u8],
        _evaluated_at: u64,
        inputs: &crate::authority_objects::Resolved,
    ) -> Result<()> {
        ensure!(
            inputs.references() == self.required_inputs(prior, ordered)?,
            "application validation input closure differs"
        );
        let state = self.verified_state(prior)?;
        ensure!(
            state.terminal.is_none(),
            "terminal old-epoch application cannot authorize further work"
        );
        if self.inert(ordered)? {
            return Ok(());
        }
        let (_, request, _) = self.decode(ordered)?;
        if let SignedRequest::Intent(intent) = request {
            ensure!(
                !matches!(
                    state.streams.classify(&stream_request(&intent))?,
                    streams::Classification::Missing | streams::Classification::GenerationConflict
                ),
                "ordinary request lacks its current admitted stream"
            );
        }
        Ok(())
    }
    fn execute(
        &self,
        prior: &[u8],
        committed: &Committed,
        inputs: &crate::authority_objects::Resolved,
    ) -> Result<Execution> {
        ensure!(
            inputs.references() == self.required_inputs(prior, &committed.command)?,
            "application execution input closure differs"
        );
        let mut state = self.verified_state(prior)?.as_ref().clone();
        ensure!(
            state.terminal.is_none(),
            "terminal old-epoch application cannot execute further work"
        );
        ensure!(
            committed.height
                == state
                    .height
                    .checked_add(1)
                    .context("application height overflow")?,
            "application state has a missing committed predecessor"
        );
        if self.inert(&committed.command)? {
            state.height = committed.height;
            return Ok(Execution {
                state: state.encode(&self.config)?,
                output: ExecutionOutput::Inert,
            });
        }
        // A request admitted before a fence still executes as a finite refusal afterward.
        let (ordered, request, challenge) = self.decode(&committed.command)?;
        let mut common_code = self.context_code(&request, &state);
        let challenge_expiry = challenge.evaluation_expiry(committed.evaluated_at, ordered.expires);
        if challenge_expiry.is_err() {
            crate::consensus::timing::expired_challenge(
                committed
                    .evaluated_at
                    .saturating_sub(challenge.created_at_ms),
            );
            common_code = minimum_code(common_code, 7);
        }
        let scope = crate::authority_proof::Scope {
            network: self.config.scope.network,
            incarnation: self.config.scope.incarnation,
            configuration: self.config.scope.configuration,
            epoch: self.config.scope.epoch,
        };
        let (output, code, expires, restrictions) = match &request {
            SignedRequest::Intent(intent) => self.ordinary(
                prior,
                &mut state,
                intent,
                &ordered,
                committed,
                common_code,
                challenge.recipient,
                inputs,
            )?,
            SignedRequest::StreamStatus(status) => {
                let metadata = state.streams.metadata_bytes(&scope, &status.requester)?;
                (
                    result(request.action(), common_code, &metadata)?,
                    common_code,
                    ordered.expires,
                    Default::default(),
                )
            }
            SignedRequest::StreamFence(fence) => {
                let refusal = match common_code {
                    0 => None,
                    7 => Some(streams::FenceRefusal::Expired),
                    21 => Some(streams::FenceRefusal::BelowPolicyFloor),
                    37 => Some(streams::FenceRefusal::WrongContext),
                    _ => anyhow::bail!("invalid fence context refusal"),
                };
                let value = state.streams.fence(
                    &scope,
                    &streams::FenceRequest {
                        requester: fence.requester,
                        digest: fence.digest,
                        expected_generation: fence.expected_generation,
                        expected_generation_id: fence.expected_generation_id,
                        expected_metadata_digest: fence.expected_metadata_digest,
                    },
                    refusal,
                )?;
                (
                    value.result()?,
                    value.code,
                    ordered.expires,
                    Default::default(),
                )
            }
        };
        // Preserve the signed ordered bytes; the derived bound limits every result.
        let expires = expires.min(challenge_expiry.unwrap_or(ordered.expires));
        state.height = committed.height;
        let state = state.encode(&self.config)?;
        let attestation = wire::encode(&array(vec![
            V::Uint(23),
            V::Uint(1),
            self.config.scope.value(),
            V::Uint(committed.height),
            b(&committed.node),
            b(&wire::digest(&committed.command)),
            b(&request.digest()),
            b(&challenge.digest),
            b(&request.requester()),
            b(&challenge.recipient),
            V::Text(request.action().into()),
            b(&request.resource()),
            V::Uint(request.revision()),
            V::Uint(request.profile_generation()),
            V::Uint(u64::from(code == 0)),
            b(&wire::digest(&output)),
            b(&wire::digest(&state)),
            V::Uint(request.minimum_policy_height()),
            V::Uint(committed.evaluated_at),
            V::Uint(expires),
            restrictions.consent.as_ref().map_or(V::Null, |v| b(v)),
            restrictions.placement.as_ref().map_or(V::Null, |v| b(v)),
            restrictions.route.as_ref().map_or(V::Null, |v| b(v)),
        ]))?;
        Ok(Execution {
            state,
            output: ExecutionOutput::Result {
                result: output,
                attestation,
            },
        })
    }
}

fn refusal(action: &str, code: u64) -> Result<Vec<u8>> {
    let value = wire::encode(&array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(action.into()),
        array(vec![]),
    ]))?;
    wire::encode(&array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(action.into()),
        V::Uint(1),
        V::Uint(code),
        b(&value),
    ]))
}

#[cfg(test)]
#[path = "AuthorityApplicationTests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "AuthorityTransactionTests.rs"]
mod transaction_tests;

#[cfg(test)]
#[path = "AuthorityApplicationStreamTests.rs"]
mod stream_tests;

#[cfg(test)]
#[path = "AuthorityApplicationStateTests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "AuthorityMembershipTests.rs"]
mod membership_tests;

#[cfg(test)]
#[path = "AuthorityApplicationsTests.rs"]
mod applications_tests;

#[cfg(test)]
#[path = "AuthorityDeploymentApplicationTests.rs"]
mod deployment_tests;

/// A terminal flag is meaningful only inside a fully validated authority state.
pub(crate) fn terminal(
    config: &Configuration,
    state: &[u8],
) -> Result<Option<crate::authority_epoch::Terminal>> {
    let decoded = wire::decode_state(state)?;
    if decoded.list(13)?.len() == 13
        && decoded
            .list(13)?
            .first()
            .is_some_and(|v| v.uint().ok() == Some(250))
    {
        Ok(State::parse(config, state)?.terminal)
    } else {
        Ok(None)
    }
}

/// Derive the unique successor application without altering retained governance or streams.
pub(crate) fn successor_state(
    config: &Configuration,
    prior: &[u8],
    checkpoint: &crate::authority_history::ValidatedCheckpoint,
) -> Result<Vec<u8>> {
    let mut state = State::parse(config, prior)?;
    let terminal = state
        .terminal
        .take()
        .context("Successor requires the exact terminal application")?;
    ensure!(
        checkpoint.terminal()
            && *checkpoint.state() == wire::digest(prior)
            && checkpoint.height() == state.height
            && *checkpoint.prefix().scope() == *config.descriptor().scope(),
        "Successor state differs from terminal checkpoint"
    );
    state.origin = Some(crate::authority_epoch::Origin {
        old_scope: terminal.declaration.old_scope.clone(),
        height: checkpoint.height(),
        node: *checkpoint.node(),
        state: *checkpoint.state(),
        checkpoint: *checkpoint.digest(),
        declaration: terminal.declaration.digest(),
    });
    state.height = 0;
    let mut next = config.clone();
    next.scope.epoch = next.scope.epoch.checked_add(1).context("Epoch overflow")?;
    state.encode(&next)
}

#[cfg(test)]
#[path = "AuthorityMailApplicationTests.rs"]
mod mail_application_tests;

#[cfg(test)]
#[path = "AuthorityPageApplicationTests.rs"]
mod page_application_tests;
