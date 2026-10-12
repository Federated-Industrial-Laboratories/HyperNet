// SPDX-License-Identifier: MIT
// The registered Page host uses its own retained stream and independently checks every metadata change.
use super::*;
use crate::{
    authority_challenge::{MAXIMUM_DURATION_MS, Session},
    authority_domains::{self as domains, Command as DomainCommand, Operation, result},
    authority_floor::Store,
    authority_local_transport as transport,
    authority_membership::{Reservations, reference},
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, Intent, OperationResult,
        OwnStreamMetadata, Restrictions, Scope, VersionRef,
    },
};
use rand::{RngCore, rngs::OsRng};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn random() -> Result<[u8; 32]> {
    let mut v = [0; 32];
    OsRng.try_fill_bytes(&mut v)?;
    ensure!(v != [0; 32], "zero Page request nonce");
    Ok(v)
}
pub enum Outcome {
    Complete(V),
    RefusedDelivery,
    ExpiredUnsentDelivery,
}
enum PreparedAction {
    Signed(Vec<u8>),
    ExpiredUnsentDelivery,
}
impl Outcome {
    pub fn completed(self) -> Result<V> {
        match self {
            Self::Complete(value) => Ok(value),
            _ => anyhow::bail!("Page metadata operation returned a delivery outcome"),
        }
    }
}
// Metadata comes only from the requester's verified durable status, never a peer assertion.
fn original_delivery_refused(
    metadata: &OwnStreamMetadata,
    scope: &Scope,
    intent: &Intent,
) -> Result<bool> {
    Ok(matches!(
        Operation::parse(intent)?.command,
        DomainCommand::Page(page::Command::ReplicaDeliver { .. })
    ) && metadata.scope() == scope
        && metadata.requester() == intent.requester
        && scope.network == intent.network
        && scope.incarnation == intent.incarnation
        && metadata.state().is_some_and(|state| {
            state.generation == intent.generation
                && state.generation_id == intent.generation_id
                && state.completion.as_ref().is_some_and(|completion| {
                    completion.sequence == intent.sequence
                        && completion.intent == intent.digest
                        && completion.disposition == Disposition::Refuse
                })
        }))
}
pub struct Client<'a> {
    config: &'a Config,
    guard: &'a Guard,
    active: &'a Active,
    store: Store,
    session: Session,
    disk: disk::Disk,
}
impl<'a> Client<'a> {
    pub fn open(config: &'a Config, guard: &'a Guard, active: &'a Active) -> Result<Self> {
        active.check(guard)?;
        let store = Store::open(
            Path::new("/State/Requester"),
            guard.bootstrap.descriptor().clone(),
        )?;
        store.require_requester(config.profile.service)?;
        let disk = disk::Disk::open(
            Path::new("/State/PageState.bin"),
            &config.profile,
            guard.health()?.observe()?.wall_ms,
        )?;
        let out = Self {
            config,
            guard,
            active,
            store,
            session: Session::new()?,
            disk,
        };
        out.check_cache()?;
        Ok(out)
    }
    fn check_cache(&self) -> Result<()> {
        let (state, records) = self.disk.context();
        let scope = self.store.descriptor().scope();
        let mut refs = crate::authority_governance::Governance::record_versions(
            scope.network,
            scope.incarnation,
            records,
        )?;
        refs.extend(state.records.values().map(|r| r.reference.clone()));
        let pending = self
            .store
            .resume_ordinary()?
            .map(|r| Intent::from_signed(r.signed()))
            .transpose()?;
        for r in refs {
            ensure!(
                self.store.generations().contains(&r)
                    || pending
                        .as_ref()
                        .is_some_and(|p| p.action == "AuthorityDomain" && p.expected.contains(&r)),
                "Page cache lacks retained quorum authentication"
            );
        }
        if let Some(intent) = pending {
            let operation = Operation::parse(&intent)?;
            self.permitted(&operation.command)?;
            self.disk.objects(&operation.command.command_inputs())?;
        }
        Ok(())
    }
    fn permitted(&self, command: &DomainCommand) -> Result<()> {
        match command {
            DomainCommand::Page(
                page::Command::Sync {
                    host, namespace, ..
                }
                | page::Command::ReplicaQueue {
                    host, namespace, ..
                },
            ) => {
                ensure!(
                    *host == self.config.profile.service
                        && self.config.profile.namespaces.contains(namespace),
                    "Page maintenance leaves local host scope"
                );
            }
            DomainCommand::Page(page::Command::ReplicaDeliver { .. }) => {}
            _ => anyhow::bail!("Page service retained another kind of operation"),
        }
        Ok(())
    }
    fn envelope(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        let health = self.guard.health()?;
        let now = health.observe()?;
        let challenge = self.session.issue(
            request,
            &self.config.key,
            random()?,
            MAXIMUM_DURATION_MS,
            health,
        )?;
        let parsed = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            self.store.descriptor().scope().value(),
            b(request),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))?;
        Ok((
            challenge,
            ordered,
            now.boot_ms
                .checked_add(MAXIMUM_DURATION_MS)
                .context("Page deadline overflow")?,
        ))
    }
    fn status(&mut self) -> Result<()> {
        self.active.check(self.guard)?;
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
                V::Uint(scope.epoch),
                V::Uint(self.store.prefix().height()),
            ]))?,
            &self.config.key,
        )?;
        let (challenge, ordered, deadline) = self.envelope(&request)?;
        let outcome = (|| {
            let (reply, history) = transport::exchange(
                &descriptor,
                &ordered,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
            )?;
            let result = proof::verify_response(
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
                    ancestry: &history.nodes,
                },
                |_, _, _| anyhow::bail!("ordinary result on Page stream status path"),
            )?;
            let result = history.attach(&self.store, result)?;
            if result.disposition() != Disposition::Permit {
                let code = result.code();
                self.store.observe(result)?;
                anyhow::bail!("Page stream status refused with code {code}");
            }
            ensure!(
                matches!(
                    result.stream_response(),
                    Some(proof::StreamResponse::Status(_))
                ),
                "Page status returned another control response"
            );
            self.store
                .accept(result, &mut self.session, self.guard.health()?, 0)?
                .perform(
                    &mut self.store,
                    &mut self.session,
                    self.guard.health()?,
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Page status restrictions differ"
                        );
                        Ok(())
                    },
                    |_, _| Ok(()),
                )
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        }
        outcome
    }
    fn prepare(&mut self, command: DomainCommand) -> Result<PreparedAction> {
        self.permitted(&command)?;
        if let Some(pending) = self.store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let operation = Operation::parse(&intent)?;
            ensure!(
                operation.grant.is_none() && operation.command.value() == command.value(),
                "another exact Page operation is pending"
            );
            return Ok(PreparedAction::Signed(pending.signed().to_vec()));
        }
        let evaluated_at = self.guard.health()?.observe()?.wall_ms;
        if let DomainCommand::Page(page::Command::ReplicaDeliver { ticket, .. }) = &command {
            let record = self.disk.context().0.record(146, ticket.id)?;
            ensure!(
                record.reference == *ticket,
                "Page delivery ticket differs from cached context"
            );
            let value = page::Ticket::parse(&record.payload)?;
            if value.expires_ms <= evaluated_at.saturating_add(1250) {
                return Ok(PreparedAction::ExpiredUnsentDelivery);
            }
        }
        let snapshot = |expected: &[VersionRef]| {
            domains::snapshot(&a(vec![
                a(vec![
                    V::Uint(self.store.prefix().scope().epoch),
                    V::Uint(self.store.prefix().height()),
                    b(self.store.prefix().policy_state()),
                ]),
                a(expected.iter().map(reference).collect()),
            ]))
        };
        let mut operation = Operation {
            grant: None,
            command: command.clone(),
            snapshot: snapshot(&[])?,
        };
        let slot = self.store.ordinary_slot()?;
        let scope = self.store.descriptor().scope();
        let mut fields = vec![
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
            b(&command.resource()),
            V::Uint(u64::from(command.mutation())),
            V::Uint(0),
            V::Uint(slot.minimum_policy_epoch()),
            V::Uint(slot.minimum_policy_height()),
            a(vec![]),
            b(&operation.parameters()?),
        ];
        if command.mutation() {
            let probe = wire::sign_envelope(&wire::encode(&a(fields.clone()))?, &self.config.key)?;
            let intent = Intent::from_signed(&probe)?;
            let (state, records) = self.disk.context();
            let inputs = self.disk.objects(&command.required_inputs(state)?)?;
            let decision = operation.prepare_with_inputs(
                state,
                &result::merge(&self.guard.bootstrap, records)?,
                &Reservations(self.guard.bootstrap.reservations().to_vec()),
                &intent,
                evaluated_at,
                false,
                false,
                &inputs,
            )?;
            ensure!(
                decision.code == 0,
                "Page delivery preflight refused with code {}",
                decision.code
            );
            operation.snapshot = snapshot(&decision.dependencies)?;
            fields[15] = a(decision.dependencies.iter().map(reference).collect());
            fields[16] = b(&operation.parameters()?);
        }
        let signed = wire::sign_envelope(&wire::encode(&a(fields))?, &self.config.key)?;
        Ok(PreparedAction::Signed(
            self.store
                .prepare_ordinary(slot, &signed)?
                .signed()
                .to_vec(),
        ))
    }
    fn delivery_refused(&self, intent: &Intent) -> Result<bool> {
        let Some(metadata) = self.store.stream_metadata()? else {
            return Ok(false);
        };
        if !original_delivery_refused(&metadata, self.store.descriptor().scope(), intent)? {
            return Ok(false);
        }
        ensure!(
            self.store.resume_ordinary()?.is_none() && self.store.resume_fence()?.is_none(),
            "refused Page delivery still has unresolved local work"
        );
        let slot = self.store.ordinary_slot()?;
        ensure!(
            slot.generation() == intent.generation
                && slot.generation_id() == intent.generation_id
                && intent.sequence.checked_add(1) == Some(slot.sequence())
                && slot.acknowledged_through() == intent.sequence,
            "refused Page delivery did not release its exact next slot"
        );
        Ok(true)
    }
    pub fn pending(&mut self) -> Result<Option<page::Command>> {
        if self.store.refusal_needs_status()?
            && let Some(request) = self.store.resume_ordinary()?
        {
            let intent = Intent::from_signed(request.signed())?;
            if matches!(
                Operation::parse(&intent)?.command,
                DomainCommand::Page(page::Command::ReplicaDeliver { .. })
            ) {
                self.status()?;
                if self.delivery_refused(&intent)? {
                    return Ok(None);
                }
                ensure!(
                    self.store
                        .resume_ordinary()?
                        .is_some_and(|retained| retained.signed() == request.signed()),
                    "Page delivery status did not preserve its unresolved request"
                );
                anyhow::bail!("Page delivery outcome is unresolved; exact request remains pending");
            }
        }
        self.store
            .resume_ordinary()?
            .map(|request| {
                let operation = Operation::parse(&Intent::from_signed(request.signed())?)?;
                self.permitted(&operation.command)?;
                let DomainCommand::Page(command) = operation.command else {
                    unreachable!()
                };
                Ok(command)
            })
            .transpose()
    }
    pub fn action(&mut self, command: page::Command) -> Result<Outcome> {
        self.active.check(self.guard)?;
        ensure!(
            self.store.resume_fence()?.is_none(),
            "Page requester has an unresolved explicit fence"
        );
        let pending = self.store.resume_ordinary()?;
        if self.store.needs_stream_status()? {
            self.status()?;
        }
        if let Some(pending) = &pending
            && self.store.resume_ordinary()?.is_none()
        {
            let intent = Intent::from_signed(pending.signed())?;
            ensure!(
                Operation::parse(&intent)?.command.value()
                    == DomainCommand::Page(command.clone()).value()
                    && self.delivery_refused(&intent)?,
                "Page status did not retire the exact refused delivery"
            );
            return Ok(Outcome::RefusedDelivery);
        }
        let signed = match self.prepare(command.into())? {
            PreparedAction::Signed(signed) => signed,
            PreparedAction::ExpiredUnsentDelivery => return Ok(Outcome::ExpiredUnsentDelivery),
        };
        let intent = Intent::from_signed(&signed)?;
        let operation = Operation::parse(&intent)?;
        let input_refs = operation.command.command_inputs();
        let inputs = self.disk.objects(&input_refs)?;
        let (challenge, ordered, deadline) = self.envelope(&signed)?;
        let outcome = (|| {
            let descriptor = self.store.descriptor().clone();
            let (reply, history, outputs) = transport::exchange_objects(
                &descriptor,
                &ordered,
                &inputs,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
                &mut |bytes| {
                    domains::response_inputs(
                        &intent,
                        &wire::decode(&OperationResult::parse(bytes)?.value)?,
                    )
                },
            )?;
            let (state, records) = {
                let (s, r) = self.disk.context();
                (s.clone(), r.to_vec())
            };
            let mut objects = inputs.objects().cloned().collect::<Vec<_>>();
            for object in outputs.objects() {
                if let Some(old) = objects.iter().find(|v| v.reference() == object.reference()) {
                    ensure!(
                        old.bytes() == object.bytes(),
                        "Page output substituted retained bytes"
                    );
                } else {
                    objects.push(object.clone());
                }
            }
            let verified = proof::verify_response(
                &descriptor,
                proof::ProofContext {
                    intent: &signed,
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
                    ancestry: &history.nodes,
                },
                |i, r, e| {
                    ensure!(
                        e.restrictions == Restrictions::default(),
                        "Page maintenance restrictions differ"
                    );
                    if r.disposition == Disposition::Refuse {
                        let v = wire::decode(&r.value)?;
                        let f = v.array(4)?;
                        ensure!(
                            f[0].uint()? == 201
                                && f[1].uint()? == 1
                                && f[2].text()? == "AuthorityDomain"
                                && f[3].array(0)?.is_empty()
                                && e.maximum_effect == 0,
                            "invalid Page refusal"
                        );
                        return ActionValidation::new(vec![]);
                    }
                    let candidate =
                        result::verify(&self.guard.bootstrap, &state, &records, i, r, e, &objects)?;
                    ActionValidation::mutation(candidate.versions, candidate.updates)
                },
            )?;
            let verified = history.attach(&self.store, verified)?;
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                self.store.observe(verified)?;
                self.session.discard(&challenge)?;
                if code == 3
                    && matches!(
                        &operation.command,
                        DomainCommand::Page(page::Command::ReplicaDeliver { .. })
                    )
                {
                    self.status()?;
                    ensure!(
                        self.delivery_refused(&intent)?,
                        "Page delivery refusal did not establish an original refusal; exact request remains pending"
                    );
                    return Ok(Outcome::RefusedDelivery);
                }
                anyhow::bail!("Page maintenance refused with code {code}");
            }
            let candidate = result::verify(
                &self.guard.bootstrap,
                &state,
                &records,
                &intent,
                &verified.result,
                &verified.executed,
                &objects,
            )?;
            result::minimum(&candidate.versions, self.store.generations())?;
            let registered = page::Host::parse(
                &candidate
                    .state
                    .record(147, self.config.profile.service)?
                    .payload,
                descriptor.scope().network,
                descriptor.scope().incarnation,
            )?;
            ensure!(
                !registered.withdrawn
                    && registered.profile.envelope == self.config.profile.envelope,
                "Page quorum selected another local host profile"
            );
            transport::remaining(deadline)?;
            if let DomainCommand::Page(page::Command::ReplicaDeliver { bundle, .. }) =
                &operation.command
            {
                ensure!(
                    self.disk
                        .live(bundle, self.guard.health()?.observe()?.wall_ms),
                    "Page delivery exceeds retained host lifetime"
                );
            }
            self.store
                .accept(verified, &mut self.session, self.guard.health()?, 0)?
                .perform(
                    &mut self.store,
                    &mut self.session,
                    self.guard.health()?,
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Page maintenance restrictions changed"
                        );
                        Ok(())
                    },
                    |_, _| {
                        self.disk.publish(
                            candidate.state,
                            candidate.records,
                            &outputs,
                            &self.config.profile,
                            self.guard.health()?.observe()?.wall_ms,
                            &operation.command.command_inputs(),
                        )?;
                        transport::remaining(deadline)?;
                        Ok(Outcome::Complete(candidate.value))
                    },
                )
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        }
        outcome
    }
    pub fn cached(&self, reference: &crate::authority_objects::Reference) -> bool {
        self.guard
            .health()
            .and_then(|h| h.observe())
            .is_ok_and(|now| self.disk.live(reference, now.wall_ms))
    }
}

#[cfg(test)]
#[path = "AuthorityPageClientTests.rs"]
mod tests;
