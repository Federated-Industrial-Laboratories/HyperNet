// SPDX-License-Identifier: MIT
// Each transfer effect rechecks both participants, exact selected storage and current deployment authority.
use super::*;
use crate::{
    authority_deployment_records::Index,
    authority_governance::{Governance, Requirement},
    authority_membership::current,
};
struct Evaluation<'a> {
    state: &'a State,
    governance: Governance,
    index: Index,
    at: u64,
    dependencies: Vec<VersionRef>,
    expires: u64,
    selected: BTreeMap<(u64, Digest), Record>,
}
impl Evaluation<'_> {
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
        bytes: u64,
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "transfer capability reference is stale"
        );
        let c = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions: &[action],
                scope,
                namespace: None,
                usage: [bytes, 1, 1, 1],
                evaluated_at_ms: self.at,
                expected: &[],
            },
        )?;
        self.dependencies.extend(c.dependencies);
        self.expires = self.expires.min(c.expires_ms);
        Ok(())
    }
    fn profile(&mut self, p: &Profile, live: bool) -> Result<()> {
        let m = &p.manifest;
        let r = self
            .index
            .deployments
            .get(&m.deployment)
            .context("transfer deployment absent")?
            .clone();
        r.manifest.permits_definition(m)?;
        let validity = r.manifest.validity;
        ensure!(
            r.operator == m.operator
                && r.services.get(&4) == Some(&p.service)
                && self.governance.record_bytes(117, m.deployment)? == r.manifest.desired()?
                && self.governance.record_bytes(105, m.deployment)?
                    == r.manifest.unsigned_consent(0)?,
            "transfer profile differs from admitted role or exact consent"
        );
        self.dependencies
            .extend([r.reference, r.profile, r.consent]);
        if let Some(w) = self.index.withdrawals.get(&m.deployment) {
            self.dependencies.push(w.reference.clone());
            ensure!(!live, "transfer deployment is withdrawn");
        }
        if live {
            ensure!(
                current(self.at, validity),
                "transfer deployment consent expired"
            );
            self.expires = self.expires.min(validity.1);
            self.capability(&r.grant, r.registrar, 13, (5, m.deployment), 0)?;
        }
        Ok(())
    }
    fn service(&mut self, id: Key, live: bool) -> Result<(Record, Service)> {
        let r = self.select(134, id)?;
        let s = Service::parse(&r.payload, self.state.network, self.state.incarnation)?;
        self.profile(&s.profile, live)?;
        if live {
            ensure!(!s.withdrawn, "transfer store withdrawn");
            self.capability(
                &s.grant,
                s.manager,
                26,
                (5, s.profile.manifest.deployment),
                0,
            )?;
        }
        Ok((r, s))
    }
    fn agreement(&mut self, id: Digest, live: bool) -> Result<(Record, Agreement)> {
        let r = self.select(135, id)?;
        let t = Agreement::parse(&r.payload, self.state.network, self.state.incarnation)?;
        if live {
            ensure!(
                !t.cancelled
                    && self
                        .at
                        .checked_add(1250)
                        .is_some_and(|v| v < t.offer.expires),
                "transfer cancelled or expired"
            );
            self.capability(
                &t.capability,
                t.offer.sender,
                18,
                (2, id),
                t.offer.payload_bytes,
            )?;
            self.expires = self.expires.min(t.offer.expires);
        }
        if let Some(a) = &t.acceptance {
            let (sr, s) = self.service(a.service.id, live)?;
            if live {
                ensure!(
                    sr.reference == a.service
                        && current(self.at, (0, a.expires))
                        && t.offer.payload_bytes <= s.profile.maximum_payload,
                    "transfer acceptance or selected store is stale"
                );
                self.capability(
                    &a.capability,
                    t.offer.recipient,
                    19,
                    (2, id),
                    t.offer.payload_bytes,
                )?;
                self.expires = self.expires.min(a.expires);
            }
        }
        Ok((r, t))
    }
    fn owner(&mut self, t: &Agreement, requester: Key) -> Result<()> {
        if requester == t.offer.sender || requester == t.offer.recipient {
            return Ok(());
        }
        if let Some(a) = &t.acceptance {
            let (_, s) = self.service(a.service.id, false)?;
            ensure!(
                requester == a.service.id || requester == s.profile.manifest.operator,
                "transfer belongs to other principals"
            );
            Ok(())
        } else {
            anyhow::bail!("transfer belongs to other principals")
        }
    }
}
pub fn expected_recipient(
    command: &Command,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
) -> Result<Key> {
    if let Command::Execute { id, .. } = command {
        let t = Agreement::parse(
            &state.record(135, *id)?.payload,
            state.network,
            state.incarnation,
        )?;
        let accepted = t.acceptance.context("transfer is not accepted")?;
        let r = state.record(134, accepted.service.id)?;
        let s = Service::parse(&r.payload, state.network, state.incarnation)?;
        let index = Index::parse(records, reserved, state.network, state.incarnation)?;
        let deployment = index
            .deployments
            .get(&s.profile.manifest.deployment)
            .context("transfer deployment absent")?;
        ensure!(
            r.reference == accepted.service
                && !s.withdrawn
                && !t.cancelled
                && deployment.services.get(&4) == Some(&s.profile.service)
                && deployment.operator == s.profile.manifest.operator,
            "transfer recipient is not the exact accepted registered service"
        );
        Ok(s.profile.service)
    } else {
        Ok(intent.requester)
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "The evaluator explicitly separates the command, prior state, policy, identity, time and replay mode."
)]
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
        "transfer request context differs"
    );
    let mut c = Evaluation {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        index: Index::parse(records, reserved, state.network, state.incarnation)?,
        at,
        dependencies: vec![],
        expires: u64::MAX,
        selected: BTreeMap::new(),
    };
    let mut next = state.clone();
    let mut changed = None;
    let mut continuation = None;
    let grant = || {
        operation
            .grant
            .as_ref()
            .context("transfer capability missing")
    };
    let result = (|| -> Result<()> {
        match command {
            Command::Context {
                action,
                scope_kind,
                resource,
            } => {
                c.capability(
                    grant()?,
                    intent.requester,
                    *action,
                    (*scope_kind, *resource),
                    0,
                )?;
                if *action == 26 {
                    let r = c
                        .index
                        .deployments
                        .get(resource)
                        .context("transfer deployment absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(resource),
                        "transfer deployment withdrawn"
                    );
                    c.dependencies.extend([r.reference, r.profile, r.consent]);
                    c.capability(&r.grant, r.registrar, 13, (5, *resource), 0)?;
                }
            }
            Command::Register { profile } => {
                let manager = grant()?;
                c.capability(
                    manager,
                    intent.requester,
                    26,
                    (5, profile.manifest.deployment),
                    0,
                )?;
                c.profile(profile, true)?;
                if replay {
                    let (_, s) = c.service(profile.service, true)?;
                    ensure!(
                        s.profile.envelope == profile.envelope
                            && s.manager == intent.requester
                            && s.grant == *manager,
                        "transfer registration differs from retained result"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(134, profile.service)),
                        "transfer service already registered"
                    );
                    changed = Some(Record::next(
                        state,
                        134,
                        profile.service,
                        Service {
                            profile: profile.clone(),
                            manager: intent.requester,
                            grant: manager.clone(),
                            withdrawn: false,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Withdraw {
                service,
                generation,
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "withdrawal is intrinsic local restriction"
                );
                let (r, mut s) = c.service(*service, false)?;
                ensure!(
                    intent.requester == *service || intent.requester == s.profile.manifest.operator,
                    "transfer withdrawal belongs to another operator"
                );
                if replay {
                    ensure!(
                        s.withdrawn && *generation == 1 && r.reference.generation == 2,
                        "transfer withdrawal differs"
                    );
                } else {
                    ensure!(
                        !s.withdrawn && r.reference.generation == *generation,
                        "transfer withdrawal generation differs"
                    );
                    s.withdrawn = true;
                    changed = Some(Record::next(state, 134, *service, s.value())?);
                }
            }
            Command::Service { service, action } => {
                if let Some(g) = &operation.grant {
                    c.capability(g, intent.requester, *action, (3, *service), 0)?;
                    c.service(*service, true)?;
                } else {
                    let (_, s) = c.service(*service, false)?;
                    ensure!(
                        intent.requester == *service
                            || intent.requester == s.profile.manifest.operator
                            || intent.requester == s.manager,
                        "transfer store belongs to another principal"
                    );
                    let _ = c.service(*service, true);
                }
            }
            Command::Services { action, after, .. } => {
                c.capability(grant()?, intent.requester, *action, (0, state.network), 0)?;
                let mut total = 0;
                let mut last = None;
                for r in state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == 134 && after.is_none_or(|a| r.reference.id > a))
                {
                    if c.selected.len() == 16 || total + r.bytes.len() > wire::MAXIMUM / 2 {
                        continuation = last;
                        break;
                    }
                    total += r.bytes.len();
                    last = Some(r.reference.id);
                    c.select(134, r.reference.id)?;
                }
            }
            Command::Offer { offer } => {
                let capability = grant()?;
                ensure!(
                    intent.requester == offer.sender
                        && at.checked_add(1250).is_some_and(|v| v < offer.expires)
                        && offer.expires <= at.saturating_add(MAXIMUM_LIFETIME_MS),
                    "transfer offer sender or expiry differs"
                );
                c.capability(
                    capability,
                    offer.sender,
                    18,
                    (2, offer.id),
                    offer.payload_bytes,
                )?;
                ensure!(
                    offer.expires <= c.expires,
                    "offer outlives sender permission"
                );
                if replay {
                    let (_, t) = c.agreement(offer.id, true)?;
                    ensure!(
                        t.creation == intent.digest
                            && t.offer.envelope == offer.envelope
                            && t.capability == *capability,
                        "transfer offer differs from retained result"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(135, offer.id)),
                        "transfer identifier already used"
                    );
                    changed = Some(Record::next(
                        state,
                        135,
                        offer.id,
                        Agreement {
                            offer: offer.clone(),
                            capability: capability.clone(),
                            acceptance: None,
                            cancelled: false,
                            creation: intent.digest,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Get { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "own transfer inspection is intrinsic"
                );
                let (_, t) = c.agreement(*id, false)?;
                c.owner(&t, intent.requester)?;
                let _ = c.agreement(*id, true);
            }
            Command::List { action, after, .. } => {
                c.capability(grant()?, intent.requester, *action, (0, state.network), 0)?;
                let mut list = state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == 135 && after.is_none_or(|a| r.reference.id > a))
                    .filter_map(|r| {
                        Agreement::parse(&r.payload, state.network, state.incarnation)
                            .ok()
                            .filter(|t| {
                                intent.requester == t.offer.sender
                                    || intent.requester == t.offer.recipient
                            })
                            .map(|_| r)
                    });
                let mut last = None;
                for _ in 0..4 {
                    let Some(r) = list.next() else { break };
                    c.agreement(r.reference.id, false)?;
                    last = Some(r.reference.id);
                }
                if list.next().is_some() {
                    continuation = last;
                }
            }
            Command::Accept {
                id,
                service,
                destination,
                expires,
            } => {
                let capability = grant()?;
                let (_, mut t) = c.agreement(*id, true)?;
                ensure!(
                    intent.requester == t.offer.recipient,
                    "transfer acceptance is not from named recipient"
                );
                c.capability(
                    capability,
                    intent.requester,
                    19,
                    (2, *id),
                    t.offer.payload_bytes,
                )?;
                let (sr, s) = c.service(*service, true)?;
                ensure!(
                    *expires <= t.offer.expires
                        && *expires <= c.expires
                        && at.checked_add(1250).is_some_and(|v| v < *expires)
                        && *expires <= at.saturating_add(s.profile.maximum_lifetime_ms)
                        && t.offer.payload_bytes <= s.profile.maximum_payload,
                    "acceptance exceeds exact participant or storage limits"
                );
                let accepted = Acceptance {
                    service: sr.reference,
                    capability: capability.clone(),
                    destination: destination.clone(),
                    expires: *expires,
                    intent: intent.digest,
                };
                if replay {
                    ensure!(
                        t.acceptance
                            .as_ref()
                            .is_some_and(|old| old.value() == accepted.value()),
                        "transfer acceptance differs from retained result"
                    );
                } else {
                    ensure!(t.acceptance.is_none(), "transfer is already accepted");
                    let mut reserved = reservation_bytes(t.offer.payload_bytes)?;
                    for other in state.records.values().filter(|r| r.reference.kind == 135) {
                        let other =
                            Agreement::parse(&other.payload, state.network, state.incarnation)?;
                        if !other.cancelled
                            && other
                                .acceptance
                                .as_ref()
                                .is_some_and(|a| a.service.id == *service && a.expires > at)
                        {
                            reserved = reserved
                                .checked_add(reservation_bytes(other.offer.payload_bytes)?)
                                .context("transfer reservation overflow")?;
                        }
                    }
                    ensure!(
                        reserved <= s.profile.state_bytes / 2 - BANK_HEADER - disk_header_bytes(),
                        "selected transfer store has insufficient unreserved capacity"
                    );
                    t.acceptance = Some(accepted);
                    changed = Some(Record::next(state, 135, *id, t.value())?);
                }
            }
            Command::Cancel { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "transfer cancellation is intrinsic restriction"
                );
                let (_, mut t) = c.agreement(*id, false)?;
                ensure!(
                    intent.requester == t.offer.sender || intent.requester == t.offer.recipient,
                    "transfer cancellation is not from a participant"
                );
                if replay {
                    ensure!(t.cancelled, "transfer cancellation absent");
                } else {
                    ensure!(!t.cancelled, "transfer already cancelled");
                    t.cancelled = true;
                    changed = Some(Record::next(state, 135, *id, t.value())?);
                }
            }
            Command::Execute {
                id,
                effect,
                offset,
                bytes,
                ..
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "transfer effect uses its accepted participant capabilities"
                );
                let (_, t) = c.agreement(*id, true)?;
                ensure!(
                    t.acceptance.is_some(),
                    "transfer requires recipient acceptance"
                );
                let permitted = match effect {
                    Effect::Put | Effect::Commit => intent.requester == t.offer.sender,
                    Effect::Fetch | Effect::Delete => intent.requester == t.offer.recipient,
                    Effect::Status => {
                        intent.requester == t.offer.sender || intent.requester == t.offer.recipient
                    }
                };
                ensure!(
                    permitted
                        && offset
                            .checked_add(*bytes)
                            .is_some_and(|end| end <= t.offer.payload_bytes),
                    "transfer effect principal or extent differs"
                );
                if *effect == Effect::Put {
                    ensure!(
                        *offset % CHUNK == 0
                            && *bytes == (t.offer.payload_bytes - *offset).min(CHUNK),
                        "transfer upload must use the exact aligned chunk or final extent"
                    );
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        #[cfg(test)]
        eprintln!("{} refused: {error:#}", command.name());
        let _ = error;
        return Ok(Decision::refused(3));
    }
    sorted(&mut c.dependencies)?;
    let dependencies = c.dependencies.clone();
    if exact
        && !replay
        && ((operation.mutation() && intent.expected != dependencies)
            || (!operation.mutation() && intent.expected.iter().any(|v| !dependencies.contains(v))))
    {
        return Ok(Decision::refused(12));
    }
    if let Some(r) = changed {
        next.put(r.clone())?;
        c.selected.insert(r.reference.index(), r);
    }
    let mut versions: BTreeMap<_, _> = c
        .dependencies
        .iter()
        .map(|v| (v.index(), v.clone()))
        .collect();
    for r in c.selected.values() {
        versions.insert(r.reference.index(), r.reference.clone());
    }
    let versions = versions.into_values().collect::<Vec<_>>();
    validate_versions(&versions, 64)?;
    let governance_records = versions
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
            a(governance_records),
            continuation.as_ref().map_or(V::Null, |v| b(v)),
        ]),
    ]);
    wire::encode(&value)?;
    Ok(Decision {
        state: (operation.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
