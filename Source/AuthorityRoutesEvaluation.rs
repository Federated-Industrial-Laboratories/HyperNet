// SPDX-License-Identifier: MIT
// Every connection rechecks sponsor rights, exact deployment consent and reserved usage.
use super::*;
use crate::{
    authority_deployment_records::Index,
    authority_governance::{Governance, Requirement},
    authority_membership::{Mutation, current},
};
use anyhow::Context as _;

struct Context<'a> {
    state: &'a State,
    governance: Governance,
    index: Index,
    reserved: &'a Reservations,
    at: u64,
    dependencies: Vec<VersionRef>,
    expires: u64,
    selected: BTreeMap<(u64, Digest), Record>,
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
        scope: (u64, Digest),
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "route capability is stale"
        );
        let d = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions: &[action],
                scope,
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
    fn deployment(&mut self, p: &RegisteredProfile, live: bool) -> Result<()> {
        let r = self
            .index
            .deployments
            .get(&p.deployment)
            .context("route deployment is absent")?
            .clone();
        let roots = crate::runtime_bootstrap_keys::Keys::parse(
            self.governance.record_bytes(131, self.state.network)?,
            self.state.network,
            self.state.incarnation,
        )?;
        for (class, (id, key)) in &roots.route_transports {
            if *id == p.identity.service || *key == p.identity.transport_key {
                ensure!(
                    *id == p.identity.service
                        && *key == p.identity.transport_key
                        && if *class == 2 {
                            p.mode == 1
                        } else {
                            p.mode != 1 && p.protocol == 1
                        },
                    "route reuses another immutable bootstrap endpoint or transport"
                );
            }
        }

        ensure!(
            r.operator == p.operator
                && r.services.get(&5) == Some(&p.service)
                && r.transports.get(&p.service) == Some(&p.identity.transport_key)
                && r.profile == p.deployment_profile
                && r.consent == p.consent,
            "route differs from admitted service, transport or consent"
        );
        self.dependencies
            .extend([r.reference.clone(), r.profile.clone(), r.consent.clone()]);
        if let Some(w) = self.index.withdrawals.get(&r.deployment) {
            self.dependencies.push(w.reference.clone());
            ensure!(!live, "route deployment is withdrawn");
        }
        if live {
            let consent = wire::decode(self.governance.record_bytes(105, r.deployment)?)?;
            let f = consent.array(19)?;
            let span = f[16].array(2)?;
            let validity = (span[0].uint()?, span[1].uint()?);
            ensure!(
                current(self.at, p.validity)
                    && current(self.at, validity)
                    && p.validity.0 >= validity.0
                    && p.validity.1 <= validity.1
                    && f[11].list(16)?.iter().any(|v| v.array(2).is_ok_and(|f| f[0]
                        .fixed::<32>()
                        .ok()
                        == Some(p.service)
                        && f[1].fixed::<32>().ok() == Some(p.endpoint))),
                "route profile exceeds current local consent"
            );
            self.expires = self.expires.min(p.validity.1).min(validity.1);
            self.capability(&r.grant, r.registrar, 13, (5, r.deployment))?;
        }
        Ok(())
    }
    fn service(&mut self, id: Digest, live: bool) -> Result<(Record, Service)> {
        let r = self.select(165, id)?;
        let s = Service::parse(&r.payload, self.state.network, self.state.incarnation)?;
        self.deployment(&s.profile, live)?;
        if live {
            ensure!(!s.withdrawn, "route is withdrawn");
            self.capability(&s.grant, s.manager, 26, (5, s.profile.deployment))?;
            if s.profile.mode == 1 {
                self.capability(&s.grant, s.manager, 6, (3, s.profile.identity.service))?;
            }
        }
        Ok((r, s))
    }
    fn relay_caller(&mut self, requester: Key) -> Result<(Record, Service)> {
        let id = self
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 165)
            .find_map(|r| {
                Service::parse(&r.payload, self.state.network, self.state.incarnation)
                    .ok()
                    .filter(|s| s.profile.service == requester && s.profile.mode == 1)
                    .map(|_| r.reference.id)
            })
            .context("requester is not a registered relay")?;
        self.service(id, true)
    }
    fn pair(&mut self, relay: &RegisteredProfile, destination: &RegisteredProfile) -> Result<()> {
        let value = wire::decode(self.governance.record_bytes(100, self.state.network)?)?;
        let policy = value.array(17)?;
        let minimum = assurance(&policy[8])?;
        let domain = crate::trust_bootstrap::hex32(&relay.domain)?;
        ensure!(
            relay.assurance >= minimum
                && relay.assurance >= destination.assurance
                && policy[9]
                    .list(16)?
                    .iter()
                    .any(|v| v.fixed::<32>().ok() == Some(domain))
                && (relay.assurance != Assurance::Independent
                    || relay.domain != destination.domain
                        && relay.operator != destination.operator),
            "route violates approved domains, operator separation or minimum privacy"
        );
        Ok(())
    }
    fn voucher(
        &mut self,
        reference: &VersionRef,
        requester: Key,
    ) -> Result<(Voucher, Service, Service)> {
        let r = self.select(166, reference.id)?;
        ensure!(r.reference == *reference, "route voucher changed");
        let v = Voucher::parse(&r.payload)?;
        let (rr, relay) = self.service(v.relay.id, true)?;
        let (dr, destination) = self.service(v.destination.id, true)?;
        ensure!(
            rr.reference == v.relay
                && dr.reference == v.destination
                && relay.profile.mode == 1
                && relay.profile.service == requester
                && destination.profile.mode != 1
                && destination
                    .profile
                    .relay
                    .is_none_or(|id| id == rr.reference.id)
                && v.expires > self.at.saturating_add(1250),
            "route voucher, caller or destination is stale"
        );
        self.pair(&relay.profile, &destination.profile)?;
        self.capability(&v.grant, v.sponsor, v.action, v.scope)?;
        self.expires = self.expires.min(v.expires);
        Ok((v, relay, destination))
    }
    fn invitation(
        &mut self,
        offer: &[u8],
        grant: &VersionRef,
        snapshot: &Snapshot,
    ) -> Result<Acceptance> {
        let acceptance =
            Acceptance::parse(offer, self.state.network, self.state.incarnation, false)?;
        ensure!(
            !self.reserved.contains(&acceptance.candidate)
                && !self.index.reserved.contains(&acceptance.candidate)
                && !self.state.keys.contains_key(&acceptance.candidate),
            "invitation candidate owns a reserved identity"
        );
        self.capability(grant, acceptance.administrator, 10, (0, self.state.network))?;
        let mut records = self
            .governance
            .versions()
            .iter()
            .map(|r| Ok(self.governance.record_bytes(r.kind, r.id)?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        // A synthetic member permits evaluation of the offered reader chain without admission.
        // Only the current dependency closure is returned; the synthetic record is never committed.
        records.retain(|bytes| {
            wire::decode(bytes)
                .and_then(|v| {
                    Ok(v.list(32)?[0].uint()? != 125
                        || v.list(32)?[6].fixed::<32>()? != acceptance.member_id)
                })
                .unwrap_or(true)
        });
        let snapshot = Snapshot {
            epoch: snapshot.epoch,
            height: snapshot.height,
            state: snapshot.state,
            references: vec![],
            value: a(vec![
                a(vec![
                    V::Uint(snapshot.epoch),
                    V::Uint(snapshot.height),
                    b(&snapshot.state),
                ]),
                a(vec![]),
            ]),
        };
        let mutation = Mutation::Admit {
            grant: grant.id,
            acceptance: acceptance.clone(),
            snapshot,
        };
        let intent = Intent {
            network: self.state.network,
            incarnation: self.state.incarnation,
            generation: 1,
            generation_id: [1; 32],
            sequence: 1,
            acknowledged_through: 0,
            requester: acceptance.administrator,
            action: "AuthorityAdmitMember".into(),
            resource: acceptance.member_id,
            revision: 1,
            profile_generation: 0,
            minimum_policy_epoch: 0,
            minimum_policy_height: 0,
            expected: vec![],
            parameters: vec![],
            digest: [1; 32],
        };
        let decision = mutation.prepare(&records, self.reserved, &intent, self.at, false)?;
        ensure!(
            decision.code == 0,
            "invitation no longer has current admission and reader authority"
        );
        self.dependencies.extend(decision.dependencies);
        self.expires = self.expires.min(decision.expires_ms);
        Ok(acceptance)
    }
}
fn grant(operation: &Operation) -> Result<&VersionRef> {
    operation
        .grant
        .as_ref()
        .context("route capability is missing")
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    operation: &Operation,
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
        "route request context differs"
    );
    let mut c = Context {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        index: Index::parse(records, reserved, state.network, state.incarnation)?,
        reserved,
        at,
        dependencies: vec![],
        expires: u64::MAX,
        selected: BTreeMap::new(),
    };
    let mut next = state.clone();
    let mut changed = None;
    let outcome = (|| -> Result<()> {
        match command {
            Command::Context { action, scope } => {
                c.capability(grant(operation)?, intent.requester, *action, *scope)?;
                if *action == 26 && scope.0 == 5 {
                    let r = c
                        .index
                        .deployments
                        .get(&scope.1)
                        .context("route deployment is absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(&scope.1),
                        "route deployment is withdrawn"
                    );
                    c.dependencies.extend([r.reference, r.profile, r.consent]);
                    c.capability(&r.grant, r.registrar, 13, (5, scope.1))?;
                }
            }
            Command::Register { profile } => {
                let grant = grant(operation)?;
                c.capability(grant, intent.requester, 26, (5, profile.deployment))?;
                if profile.mode == 1 {
                    c.capability(grant, intent.requester, 6, (3, profile.identity.service))?;
                }
                c.deployment(profile, true)?;
                if replay {
                    let (_, old) = c.service(profile.identity.service, true)?;
                    ensure!(
                        old.profile.envelope == profile.envelope
                            && old.manager == intent.requester
                            && old.grant == *grant,
                        "route registration has another creation"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(165, profile.identity.service)),
                        "route identifier already exists"
                    );
                    // A service key identifies one independently certified route endpoint.
                    ensure!(
                        !state
                            .records
                            .values()
                            .filter(|r| r.reference.kind == 165)
                            .any(
                                |r| Service::parse(&r.payload, state.network, state.incarnation)
                                    .is_ok_and(|s| s.profile.service == profile.service)
                            ),
                        "route service key already has an endpoint"
                    );
                    changed = Some(Record::next(
                        state,
                        165,
                        profile.identity.service,
                        Service {
                            profile: profile.as_ref().clone(),
                            manager: intent.requester,
                            grant: grant.clone(),
                            withdrawn: false,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Lookup { service } => {
                let (_, target) = c.service(*service, true)?;
                if target.profile.service != intent.requester
                    && target.profile.operator != intent.requester
                {
                    if let Some(g) = &operation.grant {
                        let value = wire::decode(c.governance.record_bytes(102, g.id)?)?;
                        let f = value.array(17)?;
                        let actions = f[10].list(32)?;
                        let scopes = f[11].list(32)?;
                        let mut permitted = false;
                        for action in actions {
                            let action = action.uint()?;
                            if !matches!(action, 0 | 1 | 10 | 15 | 16 | 18 | 19) {
                                continue;
                            }
                            for scope in scopes {
                                let s = scope.array(2)?;
                                if c.capability(
                                    g,
                                    intent.requester,
                                    action,
                                    (s[0].uint()?, id(&s[1])?),
                                )
                                .is_ok()
                                {
                                    permitted = true;
                                    break;
                                }
                            }
                            if permitted {
                                break;
                            }
                        }
                        ensure!(
                            permitted,
                            "route lookup requires current membership capability"
                        );
                    } else {
                        let attached = state
                            .records
                            .values()
                            .filter(|r| r.reference.kind == 165)
                            .find_map(|r| {
                                Service::parse(&r.payload, state.network, state.incarnation)
                                    .ok()
                                    .filter(|s| {
                                        s.profile.mode == 3
                                            && s.profile.service == intent.requester
                                            && s.profile.relay == Some(*service)
                                    })
                                    .map(|_| r.reference.id)
                            });
                        if let Some(id) = attached {
                            c.service(id, true)?;
                            ensure!(target.profile.mode == 1, "attachment target is not a relay");
                        } else {
                            let (_, relay) = c.relay_caller(intent.requester)?;
                            ensure!(
                                target
                                    .profile
                                    .relay
                                    .is_none_or(|r| r == relay.profile.identity.service),
                                "attachment belongs to another relay"
                            );
                        }
                    }
                }
            }
            Command::Withdraw {
                service,
                generation,
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "route withdrawal is intrinsic operator consent"
                );
                let (r, mut s) = c.service(*service, false)?;
                ensure!(
                    intent.requester == s.profile.operator || intent.requester == s.profile.service,
                    "route withdrawal belongs to another operator"
                );
                if replay {
                    ensure!(
                        s.withdrawn && *generation == 1 && r.reference.generation == 2,
                        "withdrawal differs from retained state"
                    );
                } else {
                    ensure!(
                        !s.withdrawn && r.reference.generation == *generation,
                        "route withdrawal generation differs"
                    );
                    s.withdrawn = true;
                    changed = Some(Record::next(state, 165, *service, s.value())?);
                }
            }
            Command::Issue {
                id,
                relay,
                destination,
                possession,
                action,
                scope,
                connections,
                bytes,
                expires,
            } => {
                let grant = grant(operation)?;
                c.capability(grant, intent.requester, *action, *scope)?;
                let (rr, r) = c.service(*relay, true)?;
                let (dr, d) = c.service(*destination, true)?;
                c.pair(&r.profile, &d.profile)?;
                ensure!(
                    r.profile.mode == 1
                        && d.profile.mode != 1
                        && r.profile.service != d.profile.service
                        && d.profile.relay.is_none_or(|id| id == *relay)
                        && (*action != 10 || d.profile.protocol == 1)
                        && *possession != intent.requester
                        && !reserved.contains(possession)
                        && !c.index.reserved.contains(possession)
                        && !state.keys.contains_key(possession)
                        && *expires <= c.expires
                        && *expires > at.saturating_add(1250)
                        && *expires <= at.saturating_add(86400000),
                    "route issue exceeds current authority or separation"
                );
                for version in c.governance.versions() {
                    let value = wire::decode(c.governance.record_bytes(version.kind, version.id)?)?;
                    let f = value.list(32)?;
                    ensure!(
                        !(version.kind == 102 && f[8].fixed::<32>()? == *possession
                            || version.kind == 125 && f[7].fixed::<32>()? == *possession
                            || version.kind == 127 && f[6].fixed::<32>()? == *possession),
                        "relay possession key is an application identity"
                    );
                }
                let voucher = Voucher {
                    relay: rr.reference,
                    destination: dr.reference,
                    sponsor: intent.requester,
                    grant: grant.clone(),
                    possession: *possession,
                    action: *action,
                    scope: *scope,
                    connections: *connections,
                    bytes: *bytes,
                    expires: *expires,
                    creation: intent.digest,
                };
                Voucher::parse(&voucher.value())?;
                if replay {
                    let old = c.select(166, *id)?;
                    ensure!(
                        old.payload == voucher.value(),
                        "route voucher has another creation"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(166, *id)),
                        "route voucher already exists"
                    );
                    changed = Some(Record::next(state, 166, *id, voucher.value())?);
                }
            }
            Command::VoucherContext { voucher } | Command::Permit { voucher, .. } => {
                ensure!(
                    operation.grant.is_none(),
                    "relay admission uses intrinsic service authority"
                );
                let (v, r, d) = c.voucher(voucher, intent.requester)?;
                let old = if state.records.contains_key(&(167, voucher.id)) {
                    Some(c.select(167, voucher.id)?)
                } else {
                    None
                };
                if let Command::Permit {
                    connection,
                    transcript,
                    ..
                } = command
                {
                    let charge = r.profile.limits.bytes.min(d.profile.limits.bytes);
                    if replay {
                        let old = old.context("route consumption absent")?;
                        let usage = Usage::parse(&old.payload)?;
                        ensure!(
                            usage.creation == intent.digest
                                && usage.connection == *connection
                                && usage.transcript == *transcript,
                            "route consumption differs from retained request"
                        );
                    } else {
                        let prior = old.as_ref().map(|r| Usage::parse(&r.payload)).transpose()?;
                        let connections = prior
                            .as_ref()
                            .map_or(0, |u| u.connections)
                            .checked_add(1)
                            .context("route count exhausted")?;
                        let bytes = prior
                            .as_ref()
                            .map_or(0, |u| u.bytes)
                            .checked_add(charge)
                            .context("route budget overflow")?;
                        ensure!(
                            connections <= v.connections
                                && bytes <= v.bytes
                                && prior.as_ref().is_none_or(|u| u.connection != *connection),
                            "route budget exhausted or connection reused"
                        );
                        changed = Some(Record::next(
                            state,
                            167,
                            voucher.id,
                            Usage {
                                connections,
                                bytes,
                                connection: *connection,
                                transcript: *transcript,
                                creation: intent.digest,
                            }
                            .value(),
                        )?);
                    }
                }
            }
            Command::InviteContext { offer } => {
                let acceptance = c.invitation(offer, grant(operation)?, &operation.snapshot)?;
                ensure!(
                    intent.requester == acceptance.administrator,
                    "invitation belongs to another inviter"
                );
            }
            Command::Invite { offer } => {
                let grant = grant(operation)?;
                let accepted = c.invitation(offer, grant, &operation.snapshot)?;
                ensure!(
                    intent.requester == accepted.administrator,
                    "invitation belongs to another inviter"
                );
                if replay {
                    let r = c.select(168, accepted.member_id)?;
                    let old = Invitation::parse(&r.payload, state.network, state.incarnation)?;
                    ensure!(
                        old.offer == *offer && old.grant == *grant && old.creation == intent.digest,
                        "invitation has another creation"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(168, accepted.member_id))
                            && !c
                                .governance
                                .versions()
                                .iter()
                                .any(|r| r.kind == 125 && r.id == accepted.member_id)
                            && !requesters(state)?.contains(&accepted.candidate),
                        "candidate already has an invitation or membership"
                    );
                    changed = Some(Record::next(
                        state,
                        168,
                        accepted.member_id,
                        Invitation {
                            offer: offer.clone(),
                            grant: grant.clone(),
                            creation: intent.digest,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Reader { envelope } => {
                ensure!(
                    operation.grant.is_none(),
                    "bridge reader gate uses the signed reader capability"
                );
                let reader = crate::authority_route_reader::Reader::parse(
                    envelope,
                    state.network,
                    state.incarnation,
                )?;
                let (_, endpoint) = c.service(reader.endpoint, true)?;
                ensure!(
                    endpoint.profile.service == intent.requester
                        && endpoint.profile.protocol == 6
                        && endpoint.profile.mode != 1
                        && reader.expires > at.saturating_add(1250)
                        && reader.expires <= at.saturating_add(60000),
                    "bridge reader endpoint or expiry differs"
                );
                let command = reader.command();
                let mapped = Operation {
                    grant: Some(reader.grant.clone()),
                    command: super::super::Command::Federation(command.clone()),
                    snapshot: operation.snapshot.clone(),
                };
                let mut signed = intent.clone();
                signed.requester = reader.reader;
                signed.expected.clear();
                let d = federation::evaluate(
                    &mapped,
                    &command,
                    state,
                    records,
                    reserved,
                    &signed,
                    at,
                    false,
                    false,
                    &crate::authority_objects::Resolved::default(),
                )?;
                ensure!(
                    d.code == 0,
                    "bridge reader lacks current foreign publication authority"
                );
                let v = d.value.array(5)?;
                let body = v[4].array(4)?;
                for bytes in body[1].list(page::MAXIMUM_CONTEXT_RECORDS)? {
                    let r = Record::parse(bytes.bytes()?, state.network, state.incarnation)?;
                    c.selected.insert(r.reference.index(), r);
                }
                let agreement = federation::Agreement::parse(
                    &state.record(151, reader.agreement)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    state.record(150, agreement.foreign.id)?.bytes == reader.trust
                        && state.record(157, agreement.foreign.id)?.bytes == reader.floor,
                    "bridge reader substituted the accepted foreign trust or floor"
                );
                if let Some(raw) = reader.page {
                    let id = federation::qualified_page(
                        reader.agreement,
                        &agreement.treaty.source,
                        raw,
                    )?;
                    let head = federation::ForeignPage::parse(&state.record(154, id)?.payload)?;
                    let selected = if reader.action == 3 && head.pending.is_some() {
                        head.pending.clone().unwrap()
                    } else {
                        let review = head.published.context("foreign page has no publication")?;
                        federation::ForeignReview::parse(
                            &state.record(156, review.id)?.payload,
                            state.network,
                            state.incarnation,
                        )?
                        .revision
                    };
                    let revision = state.record(155, selected.id)?;
                    ensure!(
                        revision.reference == selected
                            && Some(federation::ForeignRevision::parse(&revision.payload)?.native)
                                == reader.revision,
                        "bridge reader requests another current publication revision"
                    );
                }
                c.dependencies.extend(d.dependencies);
                c.expires = c.expires.min(d.expires_ms).min(reader.expires);
            }
            Command::CandidateContext { accepted } => {
                ensure!(
                    operation.grant.is_none(),
                    "candidate context uses the signed invitation"
                );
                let acceptance =
                    Acceptance::parse(accepted, state.network, state.incarnation, true)?;
                ensure!(
                    intent.requester == acceptance.candidate,
                    "candidate context belongs to another identity"
                );
                let r = c.select(168, acceptance.member_id)?;
                let invitation = Invitation::parse(&r.payload, state.network, state.incarnation)?;
                ensure!(
                    wire::envelope(accepted, 2)?.0 == wire::envelope(&invitation.offer, 1)?.0,
                    "candidate acceptance differs from issued invitation"
                );
                c.invitation(&invitation.offer, &invitation.grant, &operation.snapshot)?;
                if let Some(member) = c
                    .governance
                    .versions()
                    .into_iter()
                    .find(|r| r.kind == 125 && r.id == acceptance.member_id)
                {
                    c.dependencies.push(member);
                }
            }
        }
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
    let mut versions: BTreeMap<_, _> = c
        .dependencies
        .iter()
        .map(|r| (r.index(), r.clone()))
        .collect();
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
