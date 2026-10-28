// SPDX-License-Identifier: MIT
// Stream admission and renewal check the application capability independently of relay possession.
use super::*;
use crate::{
    authority_governance::{Governance, Requirement},
    authority_membership::current,
};
use anyhow::Context as _;
struct Context<'a> {
    state: &'a State,
    records: &'a [Vec<u8>],
    reserved: &'a Reservations,
    governance: Governance,
    intent: &'a Intent,
    operation: &'a Operation,
    at: u64,
    dependencies: Vec<VersionRef>,
    selected: BTreeMap<(u64, Digest), Record>,
    expires: u64,
}
impl Context<'_> {
    fn select(&mut self, kind: u64, id: Digest) -> Result<Record> {
        let r = self.state.record(kind, id)?.clone();
        self.dependencies.push(r.reference.clone());
        self.selected.insert(r.reference.index(), r.clone());
        Ok(r)
    }
    fn capability(
        &mut self,
        grant: &VersionRef,
        subject: Key,
        action: u64,
        service: Digest,
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "stream capability is stale"
        );
        let d = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions: &[action],
                scope: (3, service),
                namespace: None,
                usage: [0, 1, 1, 1],
                evaluated_at_ms: self.at,
                expected: &[],
            },
        )?;
        self.dependencies.extend(d.dependencies);
        self.expires = self.expires.min(d.expires_ms);
        Ok(())
    }
    fn route(&mut self, registration: &Registration) -> Result<routes::RegisteredProfile> {
        let record = self.select(165, registration.route.id)?;
        ensure!(
            record.reference == registration.route,
            "application route generation changed"
        );
        let service =
            routes::Service::parse(&record.payload, self.state.network, self.state.incarnation)?;
        let p = &service.profile;
        ensure!(
            p.protocol == PROTOCOL
                && p.mode != 1
                && p.operator == registration.operator
                && registration.limits.bytes <= p.limits.bytes
                && registration.limits.duration_ms <= p.limits.duration_ms
                && registration.limits.idle_ms <= p.limits.idle_ms
                && registration.validity.0 >= p.validity.0
                && registration.validity.1 <= p.validity.1
                && current(self.at, registration.validity),
            "application service differs from endpoint consent"
        );
        let command = routes::Command::Lookup {
            service: record.reference.id,
        };
        let op = Operation {
            grant: None,
            command: super::super::Command::Route(command.clone()),
            snapshot: self.operation.snapshot.clone(),
        };
        let mut intent = self.intent.clone();
        intent.requester = p.service;
        intent.expected.clear();
        let d = routes::evaluate(
            &op,
            &command,
            self.state,
            self.records,
            self.reserved,
            &intent,
            self.at,
            false,
            false,
        )?;
        ensure!(
            d.code == 0,
            "application endpoint has no current route authority"
        );
        let f = d.value.array(5)?;
        let body = f[4].array(4)?;
        for raw in body[1].list(64)? {
            let r = Record::parse(raw.bytes()?, self.state.network, self.state.incarnation)?;
            self.selected.insert(r.reference.index(), r);
        }
        self.dependencies.extend(d.dependencies);
        self.expires = self.expires.min(d.expires_ms).min(registration.validity.1);
        Ok(p.clone())
    }
    fn service(&mut self, id: Digest) -> Result<(Record, Service, routes::RegisteredProfile)> {
        let r = self.select(172, id)?;
        let s = Service::parse(&r.payload, self.state.network, self.state.incarnation)?;
        ensure!(!s.withdrawn, "application service is withdrawn");
        self.capability(&s.grant, s.registration.owner, MANAGE, id)?;
        let route = self.route(&s.registration)?;
        Ok((r, s, route))
    }
    fn proof(&mut self, p: &Proof) -> Result<routes::RegisteredProfile> {
        let (r, s, route) = self.service(p.service.id)?;
        ensure!(
            r.reference == p.service
                && p.protocol == s.registration.protocol
                && p.limits.bytes <= s.registration.limits.bytes
                && p.limits.duration_ms <= s.registration.limits.duration_ms
                && p.limits.idle_ms <= s.registration.limits.idle_ms
                && p.expires > self.at.saturating_add(1250),
            "stream proof has stale service or limits"
        );
        self.capability(&p.grant, p.principal, CONNECT, p.service.id)?;
        self.expires = self.expires.min(p.expires);
        Ok(route)
    }
}
fn grant(op: &Operation) -> Result<&VersionRef> {
    op.grant.as_ref().context("stream capability is absent")
}
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    op: &Operation,
    command: &Command,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
    exact: bool,
) -> Result<Decision> {
    ensure!(
        state.network == intent.network && state.incarnation == intent.incarnation,
        "stream request context differs"
    );
    let mut c = Context {
        state,
        records,
        reserved,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        intent,
        operation: op,
        at,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    let mut next = state.clone();
    let mut changed = None;
    let outcome = (|| -> Result<()> {
        match command {
            Command::Context { service, action } => {
                c.capability(grant(op)?, intent.requester, *action, *service)?;
                if state.records.contains_key(&(172, *service)) {
                    c.service(*service)?;
                }
            }
            Command::Register { registration: p } => {
                ensure!(
                    intent.requester == p.owner,
                    "only the consenting application owner can register"
                );
                c.capability(grant(op)?, intent.requester, MANAGE, p.id)?;
                c.route(p)?;
                if let Some(old) = state.records.get(&(172, p.id)) {
                    c.select(172, p.id)?;
                    let old = Service::parse(&old.payload, state.network, state.incarnation)?;
                    ensure!(
                        !old.withdrawn
                            && old.registration.owner == p.owner
                            && old.registration.operator == p.operator,
                        "stream service owner changed or was withdrawn"
                    );
                    if replay {
                        ensure!(
                            old.registration.envelope == p.envelope && old.grant == *grant(op)?,
                            "stream registration has another creation"
                        );
                    }
                } else {
                    ensure!(!replay, "replayed stream registration is absent");
                }
                if !replay {
                    changed = Some(Record::next(
                        state,
                        172,
                        p.id,
                        Service {
                            registration: p.clone(),
                            grant: grant(op)?.clone(),
                            withdrawn: false,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Lookup { service, slot } => {
                if op.grant.is_none() {
                    let r = c.select(172, *service)?;
                    let s = Service::parse(&r.payload, state.network, state.incarnation)?;
                    ensure!(
                        *slot == 0 && intent.requester == s.registration.owner,
                        "intrinsic stream context belongs to another owner"
                    );
                } else {
                    c.service(*service)?;
                    c.capability(grant(op)?, intent.requester, CONNECT, *service)?;
                    let id = slot_id(*service, intent.requester, *slot)?;
                    if state.records.contains_key(&(173, id)) {
                        c.select(173, id)?;
                    }
                }
            }
            Command::Inspect { proof: p } => {
                ensure!(
                    op.grant.is_none(),
                    "endpoint inspection uses the signed application capability"
                );
                let route = c.proof(p)?;
                ensure!(
                    intent.requester == route.service,
                    "stream inspection belongs to another endpoint"
                );
                let id = p.id()?;
                if state.records.contains_key(&(173, id)) {
                    c.select(173, id)?;
                }
            }
            Command::Admit { proof: p } => {
                ensure!(
                    op.grant.is_none(),
                    "endpoint admission uses the signed application capability"
                );
                let route = c.proof(p)?;
                ensure!(
                    intent.requester == route.service,
                    "stream admission belongs to another endpoint"
                );
                let id = p.id()?;
                if replay {
                    let r = c.select(173, id)?;
                    let s = Session::parse(&r.payload, state.network, state.incarnation)?;
                    ensure!(
                        r.reference.generation == p.generation
                            && !s.closed
                            && s.proof.envelope == p.envelope
                            && s.creation == intent.digest,
                        "stream admission has another creation"
                    );
                } else {
                    ensure!(
                        p.expires <= at.saturating_add(p.limits.duration_ms),
                        "stream expiry exceeds finite duration"
                    );
                    if let Some(old) = state.records.get(&(173, id)) {
                        c.select(173, id)?;
                        let s = Session::parse(&old.payload, state.network, state.incarnation)?;
                        // Closure consumes a generation. Reuse cannot restore the old quota or nonce.
                        ensure!(
                            (s.retired || at >= s.proof.expires)
                                && old.reference.generation.checked_add(1) == Some(p.generation)
                                && s.proof.nonce != p.nonce
                                && s.proof.challenge != p.challenge,
                            "stream slot remains live or generation is stale"
                        );
                    } else {
                        ensure!(p.generation == 1, "first stream slot generation differs");
                    }
                    // Preserve room for service withdrawal and slot closure at the metadata boundary.
                    ensure!(
                        state.records.len() < MAXIMUM_RECORDS - 32
                            || state.records.contains_key(&(173, id)),
                        "stream metadata admission reserve exhausted"
                    );
                    let r = Record::next(
                        state,
                        173,
                        id,
                        Session {
                            proof: p.clone(),
                            closed: false,
                            retired: false,
                            creation: intent.digest,
                        }
                        .value(),
                    )?;
                    let mut admission = state.clone();
                    admission.put(r.clone())?;
                    ensure!(
                        admission.charge()? <= MAXIMUM_BYTES - 32768,
                        "stream metadata byte reserve exhausted"
                    );
                    changed = Some(r);
                }
            }
            Command::Permit { session: r } => {
                ensure!(
                    op.grant.is_none(),
                    "stream renewal uses its existing application capability"
                );
                let current = c.select(173, r.id)?;
                ensure!(current.reference == *r, "stream slot generation changed");
                let s = Session::parse(&current.payload, state.network, state.incarnation)?;
                ensure!(!s.closed, "stream slot is closed");
                let route = c.proof(&s.proof)?;
                ensure!(
                    intent.requester == route.service,
                    "stream permission belongs to another endpoint"
                );
            }
            Command::Close { session: r } => {
                ensure!(
                    op.grant.is_none(),
                    "stream closure uses intrinsic ownership"
                );
                let current = c.select(173, r.id)?;
                let mut s = Session::parse(&current.payload, state.network, state.incarnation)?;
                let service = Service::parse(
                    &state.record(172, s.proof.service.id)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                let route = routes::Service::parse(
                    &state.record(165, service.registration.route.id)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                c.select(172, s.proof.service.id)?;
                c.select(165, service.registration.route.id)?;
                ensure!(
                    intent.requester == s.proof.principal
                        || intent.requester == route.profile.service,
                    "stream closure belongs to another principal"
                );
                if replay {
                    ensure!(
                        s.closed
                            && current.predecessor == Some(r.digest)
                            && current.reference.generation == r.generation.saturating_add(1),
                        "stream closure has another generation"
                    );
                } else {
                    ensure!(
                        current.reference == *r
                            && (!s.closed
                                || !s.retired && intent.requester == route.profile.service),
                        "stream slot is already retired or changed"
                    );
                    s.closed = true;
                    s.retired = intent.requester == route.profile.service;
                    changed = Some(Record::next(state, 173, r.id, s.value())?);
                }
            }
            Command::Withdraw { service: r } => {
                let current = c.select(172, r.id)?;
                let mut s = Service::parse(&current.payload, state.network, state.incarnation)?;
                ensure!(
                    op.grant.is_none() && intent.requester == s.registration.owner,
                    "stream withdrawal belongs to another owner"
                );
                if replay {
                    ensure!(
                        s.withdrawn && current.predecessor == Some(r.digest),
                        "stream withdrawal has another generation"
                    );
                } else {
                    ensure!(
                        current.reference == *r && !s.withdrawn,
                        "stream service changed or is withdrawn"
                    );
                    s.withdrawn = true;
                    changed = Some(Record::next(state, 172, r.id, s.value())?);
                }
            }
        };
        Ok(())
    })();
    if let Err(error) = outcome {
        #[cfg(test)]
        eprintln!("{} refused: {error:#}", command.name());
        let _ = error;
        return Ok(Decision::refused(3));
    }
    sorted(&mut c.dependencies)?;
    let dependencies = c.dependencies.clone();
    if exact
        && !replay
        && (command.mutation() && intent.expected != dependencies
            || !command.mutation() && intent.expected.iter().any(|r| !dependencies.contains(r)))
    {
        return Ok(Decision::refused(12));
    }
    if let Some(record) = changed {
        next.put(record.clone())?;
        c.selected.insert(record.reference.index(), record);
    }
    let mut versions = c
        .dependencies
        .iter()
        .map(|r| (r.index(), r.clone()))
        .collect::<BTreeMap<_, _>>();
    for r in c.selected.values() {
        versions.insert(r.reference.index(), r.reference.clone());
    }
    let versions = versions.into_values().collect::<Vec<_>>();
    validate_versions(&versions, 64)?;
    let governance = versions
        .iter()
        .filter(|r| r.kind < 132)
        .map(|r| Ok(b(c.governance.record_bytes(r.kind, r.id)?)))
        .collect::<Result<Vec<_>>>()?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(c.selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance),
            V::Null,
        ]),
    ]);
    Ok(Decision {
        state: (command.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
pub(crate) fn evaluate_read(
    op: &Operation,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    requester: Key,
    at: u64,
) -> Result<Decision> {
    let super::super::Command::Stream(command) = &op.command else {
        anyhow::bail!("stream read command differs")
    };
    ensure!(
        matches!(
            command,
            Command::Permit { .. } | Command::Lookup { .. } | Command::Inspect { .. }
        ),
        "operation is not a fresh stream read"
    );
    let intent = Intent {
        network: state.network,
        incarnation: state.incarnation,
        generation: 1,
        generation_id: [1; 32],
        sequence: 1,
        acknowledged_through: 0,
        requester,
        action: "AuthorityDomain".into(),
        resource: command.resource(),
        revision: 1,
        profile_generation: 0,
        minimum_policy_epoch: op.snapshot.epoch,
        minimum_policy_height: op.snapshot.height,
        expected: op.snapshot.references.clone(),
        parameters: op.parameters()?,
        digest: [1; 32],
    };
    evaluate(
        op, command, state, records, reserved, &intent, at, false, true,
    )
}
