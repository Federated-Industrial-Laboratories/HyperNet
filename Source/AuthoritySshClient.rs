// SPDX-License-Identifier: MIT
// A registered SSH service requests only its own accepted session and consumes a durable lease.
use crate::{
    authority_challenge::{ClockHealth, MAXIMUM_DURATION_MS, Session},
    authority_domains::{self as domain, Record, State, ssh},
    authority_floor::Store,
    authority_governance::Governance,
    authority_local_transport::{self as transport, CertifiedReply, HistoryEvidence},
    authority_membership::Reservations,
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, ExecutedResult, Intent,
        OperationResult, Restrictions, VersionRef,
    },
    trust_bootstrap::Verified,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use std::{collections::BTreeMap, path::Path};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn random() -> Result<[u8; 32]> {
    let mut v = [0; 32];
    OsRng.try_fill_bytes(&mut v)?;
    ensure!(v != [0; 32], "zero request nonce");
    Ok(v)
}

pub struct Client {
    bootstrap: Verified,
    key: SigningKey,
    store: Store,
    session: Session,
    profile: ssh::Profile,
    grant: [u8; 32],
    native: [u8; 32],
}
impl Client {
    pub fn open(
        bootstrap: Verified,
        key: SigningKey,
        path: &Path,
        profile: ssh::Profile,
        grant: [u8; 32],
        native: [u8; 32],
    ) -> Result<Self> {
        let store = Store::open(path, bootstrap.descriptor().clone())?;
        store.require_requester(key.verifying_key().to_bytes())?;
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "SSH requester differs from service profile"
        );
        Ok(Self {
            bootstrap,
            key,
            store,
            session: Session::new()?,
            profile,
            grant,
            native,
        })
    }
    fn exchange(
        &mut self,
        request: &[u8],
        path: &Path,
        limit: Option<u64>,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<(Vec<u8>, Vec<u8>, CertifiedReply, HistoryEvidence)> {
        let health = clock()?;
        let now = health.observe()?;
        let duration = MAXIMUM_DURATION_MS;
        let deadline = limit
            .unwrap_or(now.boot_ms + duration)
            .min(now.boot_ms + duration);
        ensure!(deadline > now.boot_ms, "previous SSH lease expired");
        let challenge = self
            .session
            .issue(request, &self.key, random()?, duration, health)?;
        let c = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            self.store.descriptor().scope().value(),
            b(request),
            b(&challenge),
            V::Uint(c.expires_at_ms),
        ]))?;
        let reply = transport::exchange(
            self.store.descriptor(),
            &ordered,
            deadline,
            path,
            self.store.prefix(),
            self.store.tree_head(),
            clock,
        );
        match reply {
            Ok((reply, evidence)) => Ok((challenge, ordered, reply, evidence)),
            Err(error) => {
                self.session.discard(&challenge)?;
                Err(error)
            }
        }
    }
    fn status(
        &mut self,
        path: &Path,
        limit: Option<u64>,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
    ) -> Result<()> {
        let descriptor = self.store.descriptor().clone();
        let scope = descriptor.scope();
        let request = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(55),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                b(&self.store.requester()),
                b(&random()?),
                V::Uint(self.store.prefix().scope().epoch),
                V::Uint(self.store.prefix().height()),
            ]))?,
            &self.key,
        )?;
        let (challenge, ordered, reply, evidence) = self.exchange(&request, path, limit, clock)?;
        let result = (|| {
            let verified = proof::verify_response(
                &descriptor,
                proof::ProofContext {
                    intent: &request,
                    challenge: &challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: self.store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: None,
                },
                proof::Response {
                    ordered_request: &ordered,
                    operation_result: &reply.result,
                    certificate: &reply.certificate,
                    ancestry: &evidence.nodes,
                },
                |_, _, _| bail!("ordinary result on own-stream status path"),
            )?;
            let verified = evidence.attach(&self.store, verified)?;
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                self.store.observe(verified)?;
                bail!("SSH stream status refused with code {code}");
            }
            ensure!(
                matches!(
                    verified.stream_response(),
                    Some(proof::StreamResponse::Status(_))
                ),
                "incorrect SSH stream response"
            );
            self.store
                .accept(verified, &mut self.session, clock()?, 0)?
                .perform(
                    &mut self.store,
                    &mut self.session,
                    clock()?,
                    1,
                    |r| {
                        ensure!(
                            *r == Restrictions::default(),
                            "SSH stream restrictions changed"
                        );
                        Ok(())
                    },
                    |_, _| Ok(()),
                )
        })();
        if result.is_err() {
            self.session.discard(&challenge)?;
        }
        result
    }
    fn request(&mut self) -> Result<Vec<u8>> {
        let command = ssh::Command::Authorise {
            service: self.profile.service,
            id: self.grant,
        };
        if let Some(pending) = self.store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let operation = domain::Operation::parse(&intent)?;
            ensure!(
                operation.command.value() == command.value() && operation.grant.is_none(),
                "another SSH service request is pending"
            );
            return Ok(pending.signed().to_vec());
        }
        let prefix = self.store.prefix();
        let snapshot = domain::snapshot(&a(vec![
            a(vec![
                V::Uint(prefix.scope().epoch),
                V::Uint(prefix.height()),
                b(prefix.policy_state()),
            ]),
            a(vec![]),
        ]))?;
        let parameters = domain::Operation {
            grant: None,
            command: command.into(),
            snapshot,
        }
        .parameters()?;
        let slot = self.store.ordinary_slot()?;
        let scope = self.store.descriptor().scope();
        let request = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(20),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                V::Uint(slot.generation()),
                b(&slot.generation_id()),
                V::Uint(slot.sequence()),
                V::Uint(slot.acknowledged_through()),
                b(&self.store.requester()),
                V::Text("AuthorityDomain".into()),
                b(&self.grant),
                V::Uint(0),
                V::Uint(0),
                V::Uint(slot.minimum_policy_epoch()),
                V::Uint(slot.minimum_policy_height()),
                a(vec![]),
                b(&parameters),
            ]))?,
            &self.key,
        )?;
        Ok(self
            .store
            .prepare_ordinary(slot, &request)?
            .signed()
            .to_vec())
    }
    fn validate(
        &self,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
    ) -> Result<ActionValidation> {
        ensure!(
            executed.restrictions == Restrictions::default(),
            "unexpected SSH lease restriction dimension"
        );
        let value = wire::decode(&result.value)?;
        if result.disposition != Disposition::Permit {
            let f = value.array(4)?;
            ensure!(
                result.disposition == Disposition::Refuse
                    && f[0].uint()? == 201
                    && f[1].uint()? == 1
                    && f[2].text()? == "AuthorityDomain"
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0,
                "invalid SSH refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            executed.maximum_effect == 1 && intent.requester == self.profile.service,
            "SSH lease principal or effect differs"
        );
        let operation = domain::Operation::parse(intent)?;
        ensure!(
            operation.command.value()
                == ssh::Command::Authorise {
                    service: self.profile.service,
                    id: self.grant
                }
                .value()
                && operation.grant.is_none(),
            "SSH lease binds another operation"
        );
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
            "invalid SSH result envelope"
        );
        let versions = f[3]
            .list(64)?
            .iter()
            .map(domain::version)
            .collect::<Result<Vec<_>>>()?;
        proof::validate_versions(&versions, 64)?;
        let body = f[4].array(4)?;
        ensure!(
            body[0].text()? == "SshAuthorise" && body[3] == V::Null,
            "incorrect SSH result command"
        );
        let scope = self.store.descriptor().scope();
        let mut state = State::empty(scope.network, scope.incarnation);
        for bytes in body[1].array(2)? {
            let record = Record::parse(bytes.bytes()?, scope.network, scope.incarnation)?;
            ensure!(
                state
                    .records
                    .insert(record.reference.index(), record)
                    .is_none(),
                "duplicate SSH result record"
            );
        }
        let service = ssh::Service::parse(
            &state.record(132, self.profile.service)?.payload,
            scope.network,
            scope.incarnation,
        )?;
        let grant = ssh::Grant::parse(&state.record(133, self.grant)?.payload, scope.network)?;
        ensure!(
            service.profile.envelope == self.profile.envelope
                && grant.native == self.native
                && grant.accepted
                && !grant.revoked
                && !service.withdrawn,
            "SSH lease differs from locally accepted profile and native user"
        );
        state.reserve(0, service.profile.native, service.profile.service)?;
        state.reserve(1, grant.native, grant.member)?;
        ssh::validate_state(&state)?;
        let returned = body[2]
            .list(64)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let mut refs = Governance::record_versions(scope.network, scope.incarnation, &returned)?;
        refs.extend(state.records.values().map(|r| r.reference.clone()));
        refs.sort_by_key(VersionRef::index);
        ensure!(
            refs == versions,
            "SSH lease versions differ from enclosed records"
        );
        for old in self.store.generations() {
            if let Some(new) = versions.iter().find(|r| r.index() == old.index()) {
                ensure!(
                    new.generation >= old.generation
                        && (new.generation != old.generation || new.digest == old.digest),
                    "SSH lease rolls back retained authority"
                );
            }
            let target = match old.kind {
                126 => 102,
                128 => 127,
                130 => 129,
                _ => continue,
            };
            ensure!(
                !versions.iter().any(|v| v.kind == target && v.id == old.id)
                    || versions.contains(old),
                "SSH lease omits a retained restriction"
            );
        }
        let mut all = BTreeMap::new();
        for bytes in self.bootstrap.governance_records().iter().chain(&returned) {
            let reference = Governance::record_versions(
                scope.network,
                scope.incarnation,
                std::slice::from_ref(bytes),
            )?
            .remove(0);
            if let Some((old, _)) = all.get(&reference.index()) {
                let old: &VersionRef = old;
                ensure!(
                    reference.generation >= old.generation
                        && (reference.generation != old.generation
                            || reference.digest == old.digest),
                    "SSH lease conflicts with accepted bootstrap"
                );
            }
            all.insert(reference.index(), (reference, bytes.clone()));
        }
        let records = all
            .into_values()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let reserved = Reservations(self.bootstrap.reservations().to_vec());
        state.validate_roles(&records, &reserved)?;
        let decision = operation.prepare(
            &state,
            &records,
            &reserved,
            intent,
            executed.evaluated_at_ms,
            false,
            true,
        )?;
        ensure!(
            decision.code == 0
                && decision.value == value
                && executed.expires_at_ms <= decision.expires_ms,
            "SSH lease differs from independent current authorization"
        );
        ActionValidation::new(versions)
    }
    /// The handler receives a boot-clock deadline only after the exact lease effect has been claimed.
    pub fn lease<T>(
        &mut self,
        path: &Path,
        limit: Option<u64>,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
        mut guard: impl FnMut() -> Result<()>,
        effect: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        guard()?;
        ensure!(
            self.store.resume_fence()?.is_none(),
            "SSH requester has an unresolved explicit fence"
        );
        if self.store.needs_stream_status()? {
            self.status(path, limit, clock)?;
        }
        let request = self.request()?;
        let (challenge, ordered, reply, evidence) = self.exchange(&request, path, limit, clock)?;
        let result = (|| {
            let verified = proof::verify_response(
                self.store.descriptor(),
                proof::ProofContext {
                    intent: &request,
                    challenge: &challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: self.store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: None,
                },
                proof::Response {
                    ordered_request: &ordered,
                    operation_result: &reply.result,
                    certificate: &reply.certificate,
                    ancestry: &evidence.nodes,
                },
                |i, r, e| self.validate(i, r, e),
            )?;
            let verified = evidence.attach(&self.store, verified)?;
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                self.store.observe(verified)?;
                bail!("SSH lease refused with code {code}");
            }
            let expires = verified.executed.expires_at_ms;
            self.store
                .accept(verified, &mut self.session, clock()?, 0)?
                .perform_once(
                    &mut self.store,
                    &mut self.session,
                    clock()?,
                    1,
                    |r| {
                        ensure!(*r == Restrictions::default(), "SSH restrictions changed");
                        guard()
                    },
                    |_, _| {
                        let now = clock()?.observe()?;
                        let remaining = expires
                            .checked_sub(now.wall_ms)
                            .and_then(|v| v.checked_sub(crate::authority_challenge::DELTA_MS))
                            .context("SSH lease expired before effect")?;
                        let deadline = now
                            .boot_ms
                            .checked_add(remaining)
                            .context("SSH lease deadline overflow")?;
                        effect(deadline)
                    },
                )
        })();
        if result.is_err() {
            self.session.discard(&challenge)?;
        }
        result
    }
}
