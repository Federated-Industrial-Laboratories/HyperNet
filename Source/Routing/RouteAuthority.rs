// SPDX-License-Identifier: MIT
// A relay re-evaluates current certified permission and durably records connection admissions.
use crate::{
    authority_challenge::{self, Session},
    authority_domains::{
        self as domains, Command as DomainCommand, Operation, result, routes, streams,
    },
    authority_floor::Store,
    authority_local_transport as transport,
    authority_membership::{Reservations, reference},
    authority_objects::Resolved,
    authority_proof::{
        self as proof, ActionValidation, Challenge, Digest, Disposition, Intent, OperationResult,
        Restrictions, SignedRequest, VersionRef,
    },
    route_config::Config,
    route_runtime::{Phase, Timing},
    route_state as disk,
    runtime_service_activate::Active,
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::path::Path;
#[path = "RouteAuthorityRead.rs"]
mod read;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn random() -> Result<Digest> {
    crate::route_protocol::random()
}
pub(crate) fn registered(
    bootstrap: &crate::trust_bootstrap::Verified,
    state: &domains::State,
    records: &[Vec<u8>],
    service: Digest,
    now: u64,
) -> Result<routes::RegisteredProfile> {
    let selected = routes::Service::parse(
        &state.record(165, service)?.payload,
        state.network,
        state.incarnation,
    )?;
    ensure!(!selected.withdrawn, "route service has been withdrawn");
    let index = crate::authority_deployment_records::Index::parse(
        &result::merge(bootstrap, records)?,
        &Reservations(bootstrap.reservations().to_vec()),
        state.network,
        state.incarnation,
    )?;
    let deployment = index
        .deployments
        .get(&selected.profile.deployment)
        .context("Route deployment admission is absent")?;
    ensure!(
        !index.withdrawals.contains_key(&deployment.deployment),
        "Route deployment has been withdrawn"
    );
    let validity = crate::authority_operational_consent::validity(
        &deployment.manifest,
        &selected.profile.manifest,
        selected.profile.validity,
    )?;
    ensure!(
        validity.0 <= now && now < validity.1,
        "Route service is outside current operational consent"
    );
    Ok(selected.profile)
}
pub struct Client<'a> {
    config: &'a Config,
    guard: &'a Guard,
    active: &'a Active,
    store: Store,
    session: Session,
    disk: disk::Disk,
    last_expiry: u64,
    costs: OperationCosts,
    deadline: Option<u64>,
    read_challenge_ceiling: Option<u64>,
}
#[derive(Default)]
struct OperationCosts {
    action_ms: u64,
    own_ms: Option<u64>,
    voucher_ms: Option<u64>,
}
impl OperationCosts {
    fn observe(&mut self, command: &DomainCommand, own: Digest, elapsed: u64) {
        // These predict scheduling only; the certified expiry remains the I/O limit.
        self.action_ms = elapsed;
        match command {
            DomainCommand::Route(routes::Command::Lookup { service }) if *service == own => {
                self.own_ms = Some(elapsed);
            }
            DomainCommand::Route(routes::Command::VoucherContext { .. }) => {
                self.voucher_ms = Some(elapsed);
            }
            _ => {}
        }
    }
    fn voucher_ms(&self) -> u64 {
        // A retained voucher can admit before its first renewal in this process.
        self.voucher_ms.unwrap_or(self.action_ms)
    }
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
            Path::new("/State"),
            guard.manifest.network,
            guard.manifest.incarnation,
            config.metadata_bytes,
        )?;
        let mut out = Self {
            config,
            guard,
            active,
            store,
            session: Session::new()?,
            disk,
            last_expiry: 0,
            costs: OperationCosts::default(),
            deadline: None,
            read_challenge_ceiling: None,
        };
        out.check_cache()?;
        // Recover the exact retained request before any new connection can consume permission.
        out.recover()?;
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
        let historical = self.store.historical_cache_references()?;
        for r in refs {
            ensure!(
                self.store.generations().contains(&r)
                    || historical.contains(&r)
                    || pending
                        .as_ref()
                        .is_some_and(|p| p.action == "AuthorityDomain" && p.expected.contains(&r)),
                "Route cache lacks retained quorum authentication"
            );
        }
        if let Some(intent) = pending {
            let operation = Operation::parse(&intent)?;
            self.permitted(&operation.command)?;
            ensure!(
                operation.command.command_inputs().is_empty(),
                "route admission cannot retain content objects"
            );
        }
        Ok(())
    }
    fn permitted(&self, command: &DomainCommand) -> Result<()> {
        if matches!(
            command,
            DomainCommand::Stream(
                streams::Command::Inspect { .. }
                    | streams::Command::Admit { .. }
                    | streams::Command::Permit { .. }
                    | streams::Command::Close { .. }
            )
        ) {
            ensure!(
                self.config.profile.protocol == streams::PROTOCOL,
                "only application endpoints may admit streams"
            );
            return Ok(());
        }
        ensure!(
            matches!(
                command,
                DomainCommand::Route(
                    routes::Command::Lookup { .. }
                        | routes::Command::VoucherContext { .. }
                        | routes::Command::Permit { .. }
                        | routes::Command::Reader { .. }
                )
            ),
            "route requester has an operation outside finite admission"
        );
        Ok(())
    }
    fn envelope(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        let health = self.guard.health()?;
        let now = health.observe()?;
        let mut duration =
            authority_challenge::maximum_duration_ms(&SignedRequest::from_signed(request)?);
        if let Some(deadline) = self.deadline {
            duration = duration.min(transport::remaining(deadline)?);
        }
        let challenge =
            self.session
                .issue(request, &self.config.key, random()?, duration, health)?;
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
                .checked_add(duration)
                .context("Route deadline overflow")?,
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
                |_, _, _| anyhow::bail!("ordinary result on Route stream status path"),
            )?;
            let result = history.attach(&self.store, result)?;
            if result.disposition() != Disposition::Permit {
                let code = result.code();
                self.store.observe(result)?;
                anyhow::bail!("Route stream status refused with code {code}");
            }
            ensure!(
                matches!(
                    result.stream_response(),
                    Some(proof::StreamResponse::Status(_))
                ),
                "Route status returned another control response"
            );
            self.store
                .accept_with_clock(result, &mut self.session, &mut || self.guard.health(), 0)?
                .perform_with_clock(
                    &mut self.store,
                    &mut self.session,
                    &mut || self.guard.health(),
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Route status restrictions differ"
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
    fn prepare(&mut self, command: DomainCommand) -> Result<Vec<u8>> {
        self.permitted(&command)?;
        if let Some(pending) = self.store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let operation = Operation::parse(&intent)?;
            ensure!(
                operation.grant.is_none() && operation.command.value() == command.value(),
                "another exact Route operation is pending"
            );
            return Ok(pending.signed().to_vec());
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
            let inputs = Resolved::default();
            ensure!(
                command.required_inputs(state)?.is_empty(),
                "route preflight cannot require content objects"
            );
            let decision = operation.prepare_with_inputs(
                state,
                &result::merge(&self.guard.bootstrap, records)?,
                &Reservations(self.guard.bootstrap.reservations().to_vec()),
                &intent,
                self.guard.health()?.observe()?.wall_ms,
                false,
                false,
                &inputs,
            )?;
            ensure!(
                decision.code == 0,
                "Route delivery preflight refused with code {}",
                decision.code
            );
            operation.snapshot = snapshot(&decision.dependencies)?;
            fields[15] = a(decision.dependencies.iter().map(reference).collect());
            fields[16] = b(&operation.parameters()?);
        }
        let signed = wire::sign_envelope(&wire::encode(&a(fields))?, &self.config.key)?;
        Ok(self
            .store
            .prepare_ordinary(slot, &signed)?
            .signed()
            .to_vec())
    }
    pub fn pending(&self) -> Result<Option<DomainCommand>> {
        self.store
            .resume_ordinary()?
            .map(|request| {
                let operation = Operation::parse(&Intent::from_signed(request.signed())?)?;
                self.permitted(&operation.command)?;
                Ok(operation.command)
            })
            .transpose()
    }
    pub fn action(&mut self, command: routes::Command) -> Result<V> {
        self.domain_action(DomainCommand::Route(command))
    }
    fn domain_action(&mut self, command: DomainCommand) -> Result<V> {
        self.active.check(self.guard)?;
        if let Some(deadline) = self.deadline {
            transport::remaining(deadline)?;
        }
        ensure!(
            self.store.resume_fence()?.is_none(),
            "Route requester has an unresolved explicit fence"
        );
        if self.store.resume_ordinary()?.is_none()
            && matches!(
                command,
                DomainCommand::Route(
                    routes::Command::Lookup { .. } | routes::Command::VoucherContext { .. }
                ) | DomainCommand::Stream(
                    streams::Command::Inspect { .. } | streams::Command::Permit { .. }
                )
            )
        {
            return self.read_action(command);
        }
        if self.store.needs_stream_status()? {
            self.status()?;
        }
        let started = authority_challenge::boot_time_ms()?;
        let signed = self.prepare(command)?;
        let intent = Intent::from_signed(&signed)?;
        let operation = Operation::parse(&intent)?;
        let input_refs = operation.command.command_inputs();
        ensure!(
            input_refs.is_empty(),
            "route request cannot require content objects"
        );
        let inputs = Resolved::default();
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
            )
            .context("obtain Route authority response and history")?;
            let (state, records) = {
                let (s, r) = self.disk.context();
                (s.clone(), r.to_vec())
            };
            let mut objects = inputs.objects().cloned().collect::<Vec<_>>();
            for object in outputs.objects() {
                if let Some(old) = objects.iter().find(|v| v.reference() == object.reference()) {
                    ensure!(
                        old.bytes() == object.bytes(),
                        "Route output substituted retained bytes"
                    );
                } else {
                    objects.push(object.clone());
                }
            }
            let mut candidate = None;
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
                        "Route maintenance restrictions differ"
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
                            "invalid Route refusal"
                        );
                        return ActionValidation::new(vec![]);
                    }
                    let selected =
                        result::verify(&self.guard.bootstrap, &state, &records, i, r, e, &objects)
                            .context("independently evaluate Route domain response")?;
                    let validation = ActionValidation::mutation(
                        selected.versions.clone(),
                        selected.updates.clone(),
                    )?;
                    candidate = Some(selected);
                    Ok(validation)
                },
            )
            .context("verify Route authority response")?;
            let verified = history
                .attach(&self.store, verified)
                .context("attach Route requester history")?;
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                self.store.observe(verified)?;
                anyhow::bail!("Route maintenance refused with code {code}");
            }
            self.last_expiry = verified
                .executed
                .expires_at_ms
                .saturating_sub(authority_challenge::DELTA_MS);
            let candidate = candidate.context("Route permit omitted verified domain context")?;
            result::minimum(&candidate.versions, self.store.generations())?;
            transport::remaining(deadline)?;
            self.store
                .accept_with_clock(verified, &mut self.session, &mut || self.guard.health(), 0)?
                .perform_with_clock(
                    &mut self.store,
                    &mut self.session,
                    &mut || self.guard.health(),
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Route maintenance restrictions changed"
                        );
                        Ok(())
                    },
                    |_, _| {
                        ensure!(
                            outputs.references().is_empty(),
                            "route authority returned unexpected content objects"
                        );
                        self.disk.publish(candidate.state, candidate.records)?;
                        transport::remaining(deadline)?;
                        Ok(candidate.value)
                    },
                )
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        } else {
            self.costs.observe(
                &operation.command,
                self.config.profile.identity.service,
                authority_challenge::boot_time_ms()?.saturating_sub(started),
            );
        }
        outcome
    }
    pub fn operation_budget_ms(&self) -> u64 {
        self.costs.action_ms
    }
    pub fn voucher_renewal_budget_ms(&self) -> u64 {
        self.costs.voucher_ms()
    }
    pub fn own_renewal_budget_ms(&self) -> u64 {
        self.costs.own_ms.unwrap_or(0)
    }
    fn recover(&mut self) -> Result<()> {
        // A disclosure refusal is not an original outcome. Resolve it before
        // selecting a retained command so status cannot turn it into new work.
        if self.store.refusal_needs_status()? {
            self.status()?;
        }
        if let Some(pending) = self.pending()?
            && let Err(error) = self.domain_action(pending)
        {
            if self.store.refusal_needs_status()? {
                self.status()?;
                // Only authenticated terminal refusal releases this slot.
                // An unknown outcome or an unconsumed Permit stays pending.
                if self.pending()?.is_none() {
                    return Ok(());
                }
            }
            return Err(error);
        }
        Ok(())
    }
    pub fn now(&self) -> Result<u64> {
        Ok(self.guard.health()?.observe()?.wall_ms)
    }
    pub fn lookup(&mut self, service: Digest) -> Result<routes::RegisteredProfile> {
        self.recover()?;
        self.action(routes::Command::Lookup { service })?;
        self.registered(service)
    }
    fn registered(&self, service: Digest) -> Result<routes::RegisteredProfile> {
        let (state, records) = self.disk.context();
        registered(&self.guard.bootstrap, state, records, service, self.now()?)
    }
    pub fn own(&mut self) -> Result<()> {
        let own = self.lookup(self.config.profile.identity.service)?;
        ensure!(
            own.envelope == self.config.profile.envelope,
            "registered route profile differs from local consent"
        );
        Ok(())
    }
    pub fn admit(
        &mut self,
        open: &crate::route_protocol::Open,
        possession: Digest,
        connection: Digest,
        transcript: Digest,
        window: (u64, u64),
        timing: Timing,
    ) -> Result<Option<Admission>> {
        self.before(window.1, |client| {
            client.admit_current(open, possession, connection, transcript, window.0, timing)
        })
    }
    pub fn before<T>(
        &mut self,
        deadline: u64,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        transport::remaining(deadline)?;
        let previous = self.deadline;
        self.deadline = Some(previous.map_or(deadline, |old| old.min(deadline)));
        let result = operation(self);
        self.deadline = previous;
        result
    }
    pub fn before_check<T>(
        &mut self,
        deadline: u64,
        caller_started: u64,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            caller_started <= authority_challenge::boot_time_ms()?,
            "application check starts in the future"
        );
        let ceiling = caller_started
            .checked_add(authority_challenge::MAXIMUM_DURATION_MS)
            .context("application challenge ceiling overflow")?;
        transport::remaining(ceiling)?;
        let previous = self.read_challenge_ceiling;
        self.read_challenge_ceiling = Some(previous.map_or(ceiling, |old| old.min(ceiling)));
        // Readiness uses the final check's original freshness ceiling. The
        // synchronous wait and every accepted effect retain their shorter bounds.
        let result = self.before(deadline, operation);
        self.read_challenge_ceiling = previous;
        result
    }
    fn admit_current(
        &mut self,
        open: &crate::route_protocol::Open,
        possession: Digest,
        connection: Digest,
        transcript: Digest,
        started: u64,
        timing: Timing,
    ) -> Result<Option<Admission>> {
        if let Some(pending) = self.pending()? {
            self.domain_action(pending)?;
            return Ok(None);
        }
        ensure!(
            open.network == self.guard.manifest.network
                && open.incarnation == self.guard.manifest.incarnation
                && open.relay == self.config.profile.identity.service
                && self.config.profile.mode == 1,
            "route admission has another network or relay"
        );
        if open.attachment {
            let certified = self.action(routes::Command::Lookup {
                service: open.service,
            })?;
            let target = self.registered(open.service)?;
            let own = self.registered(open.relay)?;
            let own_reference = &self.disk.context().0.record(165, open.relay)?.reference;
            ensure!(
                certified.array(5)?[3].list(64)?.iter().any(|v| {
                    domains::version(v).is_ok_and(|version| &version == own_reference)
                }) && own.envelope == self.config.profile.envelope,
                "attachment lookup omits current relay consent or differs from local profile"
            );
            ensure!(
                target.mode == 3
                    && target.relay == Some(open.relay)
                    && possession == target.service,
                "outbound service attachment differs from its certified identity"
            );
            // The target lookup certifies both profiles and their current capability closures.
            let limits = intersect(self.config.profile.limits, target.limits);
            let total_expires = self.total_expiry(started, limits, target.validity.1)?;
            let expires = total_expires.min(self.last_expiry);
            let now = self.now()?;
            self.disk.consume(connection, now, total_expires)?;
            return Ok(Some(Admission {
                target,
                limits,
                expires,
                total_expires,
                renewal: None,
            }));
        }
        let voucher = domains::version(&wire::decode(&open.voucher)?)?;
        ensure!(
            voucher.kind == 166,
            "route admission does not contain a voucher reference"
        );
        let cached = retained_voucher(self.disk.context().0, &voucher, open, possession)?;
        if cached.is_none() {
            timing.mark(Phase::VoucherContextStart);
            self.action(routes::Command::VoucherContext {
                voucher: voucher.clone(),
            })?;
            timing.mark(Phase::VoucherContextComplete);
            retained_voucher(self.disk.context().0, &voucher, open, possession)?
                .context("certified route voucher absent")?;
            // A context proves the immutable PoP binding, never permission to forward or consume a stream.
            return Ok(None);
        }
        let admitted = cached.context("retained route voucher absent")?;
        timing.mark(Phase::PermitStart);
        self.action(routes::Command::Permit {
            voucher: voucher.clone(),
            connection,
            transcript,
        })?;
        timing.mark(Phase::PermitComplete);
        let own = self.registered(open.relay)?;
        ensure!(
            own.envelope == self.config.profile.envelope,
            "relay local consent differs from current registration"
        );
        let target = self.registered(open.service)?;
        ensure!(
            matches!(target.mode, 2 | 3),
            "route destination is not a final application endpoint"
        );
        let (state, _) = self.disk.context();
        let usage = routes::Usage::parse(&state.record(167, voucher.id)?.payload)?;
        ensure!(
            usage.connection == connection && usage.transcript == transcript,
            "certified usage differs from this exact stream"
        );
        let limits = intersect(own.limits, target.limits);
        let now = self.now()?;
        let total_expires =
            self.total_expiry(started, limits, admitted.expires.min(target.validity.1))?;
        let expires = total_expires.min(self.last_expiry);
        ensure!(now < expires, "route admission expired before forwarding");
        self.disk.consume(connection, now, total_expires)?;
        let renewal = Some(Renewal {
            voucher,
            target: target.envelope.clone(),
            relay: own.envelope,
            total_expires,
        });
        Ok(Some(Admission {
            target,
            limits,
            expires,
            total_expires,
            renewal,
        }))
    }
    fn total_expiry(
        &self,
        started: u64,
        limits: crate::route_profile::Limits,
        expires: u64,
    ) -> Result<u64> {
        let now = self.guard.health()?.observe()?;
        let remaining = started
            .checked_add(limits.duration_ms)
            .and_then(|deadline| deadline.checked_sub(now.boot_ms))
            .filter(|remaining| *remaining > 0)
            .context("original route lifetime expired")?;
        Ok(now.wall_ms.saturating_add(remaining).min(expires).min(
            crate::authority_operational_consent::validity(
                &self.config.manifest,
                &self.config.profile.manifest,
                self.config.profile.validity,
            )?
            .1,
        ))
    }
    pub fn refresh(&mut self, renewal: &Renewal, deadline: u64) -> Result<u64> {
        self.before(deadline, |client| {
            client.recover()?;
            ensure!(
                client.now()? < renewal.total_expires,
                "original route lifetime expired"
            );
            client.action(routes::Command::VoucherContext {
                voucher: renewal.voucher.clone(),
            })?;
            let (state, _) = client.disk.context();
            let record = state.record(166, renewal.voucher.id)?;
            ensure!(
                record.reference == renewal.voucher,
                "live route voucher changed"
            );
            let voucher = routes::Voucher::parse(&record.payload)?;
            let own = client.registered(voucher.relay.id)?;
            let target = client.registered(voucher.destination.id)?;
            ensure!(
                own.envelope == renewal.relay
                    && own.envelope == client.config.profile.envelope
                    && target.envelope == renewal.target
                    && client.now()? < renewal.total_expires,
                "live route identities or original lifetime changed"
            );
            client.effect_deadline()
        })
    }
    pub fn effect_deadline(&self) -> Result<u64> {
        let now = self.guard.health()?.observe()?;
        let remaining = self
            .last_expiry
            .checked_sub(now.wall_ms)
            .filter(|r| *r > 0)
            .context("certified route effect expired")?;
        now.boot_ms
            .checked_add(remaining)
            .context("route effect deadline overflow")
    }
    pub fn stream_admit(&mut self, proof: streams::Proof) -> Result<VersionRef> {
        self.recover()?;
        self.domain_action(DomainCommand::Stream(streams::Command::Inspect {
            proof: proof.clone(),
        }))?;
        let registered = streams::Service::parse(
            &self.disk.context().0.record(172, proof.service.id)?.payload,
            self.guard.manifest.network,
            self.guard.manifest.incarnation,
        )?;
        ensure!(
            registered.registration.envelope
                == self
                    .config
                    .application
                    .as_ref()
                    .context("local application binding absent")?
                    .registration,
            "registered stream service differs from exact local consent"
        );
        let id = proof.id()?;
        self.domain_action(DomainCommand::Stream(streams::Command::Admit { proof }))?;
        Ok(self.disk.context().0.record(173, id)?.reference.clone())
    }
    pub fn stream_permit(&mut self, session: &VersionRef) -> Result<u64> {
        self.recover()?;
        self.domain_action(DomainCommand::Stream(streams::Command::Permit {
            session: session.clone(),
        }))?;
        self.effect_deadline()
    }
    /// The fresh read never recovers or falls back to an ordinary request.
    pub fn check_stream(
        &mut self,
        session: &VersionRef,
        caller_started_boot_ms: u64,
    ) -> Result<(streams::control::Authority, bool, u64)> {
        self.active.check(self.guard)?;
        ensure!(
            self.store.resume_ordinary()?.is_none() && self.store.resume_fence()?.is_none(),
            "fresh application authority requester is busy"
        );
        let observation = self.read_observation(
            DomainCommand::Stream(streams::Command::Permit {
                session: session.clone(),
            }),
            Some(
                caller_started_boot_ms
                    .checked_add(authority_challenge::MAXIMUM_DURATION_MS)
                    .context("application challenge ceiling overflow")?,
            ),
        )?;
        ensure!(
            observation.disposition != Disposition::Pending,
            "fresh application authority is pending"
        );
        let statement = observation.statement;
        let health = self.guard.health()?;
        let now = health.observe()?;
        let remaining = statement
            .expires_at_ms
            .saturating_sub(authority_challenge::DELTA_MS)
            .checked_sub(now.wall_ms)
            .context("fresh application authority expired")?;
        let mut deadline = now
            .boot_ms
            .saturating_add(remaining)
            .min(health.valid_until_boot_ms());
        if let Some(caller) = self.deadline {
            deadline = deadline.min(caller);
        }
        let permitted = observation.disposition == Disposition::Permit;
        if permitted {
            deadline = deadline.min(self.effect_deadline()?);
        }
        let authority = streams::control::Authority {
            network: statement.scope.network,
            incarnation: statement.scope.incarnation,
            configuration: statement.scope.configuration,
            epoch: statement.scope.epoch,
            height: statement.height,
            state: statement.state,
            statement_digest: wire::digest(&statement.encode()?),
            evaluated_at_ms: statement.evaluated_at_ms,
            expires_at_ms: statement.expires_at_ms,
            code: observation.code,
        };
        Ok((authority, permitted, deadline))
    }
    pub fn stream_close(&mut self, session: &VersionRef) -> Result<()> {
        self.recover()?;
        let r = self.disk.context().0.record(173, session.id)?.clone();
        let current = streams::Session::parse(
            &r.payload,
            self.guard.manifest.network,
            self.guard.manifest.incarnation,
        )?;
        if !current.retired && current.proof.generation == session.generation {
            self.domain_action(DomainCommand::Stream(streams::Command::Close {
                session: r.reference,
            }))?;
        }
        Ok(())
    }
    pub fn reader(&mut self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.recover()?;
        let outer = wire::decode(envelope)?;
        let fields = outer.list(16)?;
        let search = if fields.first().is_some_and(|v| v.uint().ok() == Some(200)) {
            let f = outer.array(5)?;
            ensure!(
                f[1].uint()? == 1 && f[2].text()? == "RouteBridgeSearch",
                "unknown bridge reader frame"
            );
            let query = f[4].bytes()?;
            crate::search_text::Request::parse(query)?;
            Some((f[3].bytes()?, query))
        } else {
            None
        };
        // Only the query-free reader envelope enters ordered authority evidence.
        let envelope = search.map_or(envelope, |(reader, _)| reader);
        let reader = crate::authority_route_reader::Reader::parse(
            envelope,
            self.guard.manifest.network,
            self.guard.manifest.incarnation,
        )?;
        ensure!(
            self.config.profile.protocol == 6
                && reader.endpoint == self.config.profile.identity.service
                && self.now()? < reader.expires,
            "bridge read differs from its exact endpoint or lifetime"
        );
        self.action(routes::Command::Reader {
            envelope: envelope.to_vec(),
        })?;
        self.active.check(self.guard)?;
        ensure!(
            self.now()? < reader.expires,
            "bridge read expired before forwarding"
        );
        if let Some((_, query)) = search {
            ensure!(
                reader.action == 1 && reader.page.is_some() && reader.revision.is_some(),
                "search payload requires one exact search-authorised publication"
            );
            wire::encode(&V::Array(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("BridgeSearch".into()),
                V::Bytes(reader.packet),
                V::Bytes(query.to_vec()),
            ]))
        } else {
            Ok(reader.packet)
        }
    }
}
pub(crate) fn retained_voucher(
    state: &domains::State,
    voucher: &VersionRef,
    open: &crate::route_protocol::Open,
    possession: Digest,
) -> Result<Option<routes::Voucher>> {
    let Some(selected) = state.records.get(&(166, voucher.id)) else {
        return Ok(None);
    };
    ensure!(
        selected.reference == *voucher,
        "route voucher reference differs from certified admission"
    );
    let admitted = routes::Voucher::parse(&selected.payload)?;
    ensure!(
        admitted.possession == possession
            && admitted.relay.id == open.relay
            && admitted.destination.id == open.service,
        "route proof key or destination differs from its voucher"
    );
    Ok(Some(admitted))
}
pub struct Admission {
    pub target: routes::RegisteredProfile,
    pub limits: crate::route_profile::Limits,
    pub expires: u64,
    pub total_expires: u64,
    pub renewal: Option<Renewal>,
}
pub struct Renewal {
    voucher: VersionRef,
    target: Vec<u8>,
    relay: Vec<u8>,
    total_expires: u64,
}

fn intersect(
    left: crate::route_profile::Limits,
    right: crate::route_profile::Limits,
) -> crate::route_profile::Limits {
    crate::route_profile::Limits {
        bytes: left.bytes.min(right.bytes),
        duration_ms: left.duration_ms.min(right.duration_ms),
        idle_ms: left.idle_ms.min(right.idle_ms),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteAuthorityUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Routing/RouteAuthority.rs");
