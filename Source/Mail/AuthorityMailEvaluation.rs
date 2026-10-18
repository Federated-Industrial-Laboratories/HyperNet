// SPDX-License-Identifier: MIT
// Claims consume exact MLS packages once; every storage effect rechecks current mailbox and host consent.
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
        actions: &[u64],
        scope: (u64, Digest),
        bytes: u64,
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "mail capability is stale"
        );
        let c = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions,
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
            .context("mail deployment absent")?
            .clone();
        r.manifest.permits_definition(m)?;
        let validity = r.manifest.validity;
        ensure!(
            r.operator == m.operator
                && r.services.get(&3) == Some(&p.service)
                && self.governance.record_bytes(117, m.deployment)? == r.manifest.desired()?
                && self.governance.record_bytes(105, m.deployment)?
                    == r.manifest.unsigned_consent(0)?,
            "mail profile differs from exact registered consent"
        );
        self.dependencies
            .extend([r.reference, r.profile, r.consent]);
        if let Some(w) = self.index.withdrawals.get(&m.deployment) {
            self.dependencies.push(w.reference.clone());
            ensure!(!live, "mail deployment withdrawn");
        }
        if live {
            ensure!(current(self.at, validity), "mail consent expired");
            self.expires = self.expires.min(validity.1);
            self.capability(&r.grant, r.registrar, &[13], (5, m.deployment), 0)?;
        }
        Ok(())
    }
    fn service(&mut self, id: Key, live: bool) -> Result<(Record, Service)> {
        let r = self.select(136, id)?;
        let s = Service::parse(&r.payload, self.state.network, self.state.incarnation)?;
        self.profile(&s.profile, live)?;
        if live {
            ensure!(!s.withdrawn, "mail store withdrawn");
            self.capability(
                &s.grant,
                s.manager,
                &[26],
                (5, s.profile.manifest.deployment),
                0,
            )?;
            self.capability(&s.grant, s.manager, &[14], (3, id), 0)?;
        }
        Ok((r, s))
    }
    fn mailbox(&mut self, id: Digest, action: Option<u64>) -> Result<(Record, Mailbox)> {
        let r = self.select(137, id)?;
        let m = Mailbox::parse(&r.payload, self.state.network)?;
        if let Some(action) = action {
            ensure!(
                !m.publication.manifest.deleted
                    && m.publication.manifest.expires.saturating_mul(1000) > self.at,
                "mailbox expired or deleted"
            );
            self.capability(&m.grant, m.manager, &[action], (2, id), 0)?;
            self.expires = self
                .expires
                .min(m.publication.manifest.expires.saturating_mul(1000));
        }
        for host in &m.publication.manifest.storage_hosts {
            self.service(objects::native(host)?, false)?;
        }
        Ok((r, m))
    }
    fn device(&mut self, m: &Mailbox, requester: Key, right: &str) -> Result<objects::Device> {
        let d = m.publication.device(requester, right, self.at)?.clone();
        self.expires = self.expires.min(d.expires.saturating_mul(1000));
        Ok(d)
    }
    fn owner(&self, m: &Mailbox, requester: Key) -> Result<()> {
        ensure!(
            m.manager == requester
                || m.publication
                    .manifest
                    .devices
                    .iter()
                    .any(|d| objects::native(&d.request_key).ok() == Some(requester)),
            "mailbox belongs to another principal"
        );
        Ok(())
    }
    fn claim(&mut self, id: Digest, live: bool) -> Result<(Record, Claim, Mailbox, Mailbox)> {
        let r = self.select(139, id)?;
        let c = Claim::parse(&r.payload)?;
        let (sr, s) = self.mailbox(c.sender.id, live.then_some(15))?;
        let (rr, t) = self.mailbox(c.recipient.id, live.then_some(16))?;
        for p in &c.packages {
            let r = self.select(138, p.id)?;
            ensure!(r.reference == *p, "claim package identity changed");
        }
        for host in &c.placement {
            self.service(host.id, false)?;
        }
        if live {
            for host in &c.placement {
                let (r, _) = self.service(host.id, true)?;
                ensure!(r.reference == *host, "claimed store changed");
            }
            ensure!(
                sr.reference == c.sender
                    && rr.reference == c.recipient
                    && self.at.checked_add(1250).is_some_and(|at| at < c.expires),
                "mail claim uses a changed mailbox or expired permission"
            );
            self.device(&s, c.device, "Send")?;
            self.expires = self.expires.min(c.expires);
        }
        Ok((r, c, s, t))
    }
    fn package(
        &mut self,
        reference: &VersionRef,
        mailbox: &Record,
        m: &Mailbox,
    ) -> Result<Inventory> {
        let r = self.select(138, reference.id)?;
        let p = Inventory::parse(&r.payload)?;
        ensure!(
            r.reference == *reference
                && p.mailbox == mailbox.reference
                && p.package.expires.saturating_mul(1000) > self.at,
            "mail package revision or expiry differs"
        );
        let d = m
            .publication
            .manifest
            .devices
            .iter()
            .find(|d| d.device_id == p.package.device_id)
            .context("package device removed")?;
        ensure!(
            d.permissions.iter().any(|p| p == "Read") && p.package.expires <= d.expires,
            "package exceeds device Read permission"
        );
        self.expires = self.expires.min(p.package.expires.saturating_mul(1000));
        Ok(p)
    }
}
pub fn expected_recipient(
    command: &Command,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
) -> Result<Key> {
    if let Command::Execute {
        address, service, ..
    } = command
    {
        let m = Mailbox::parse(&state.record(137, *address)?.payload, state.network)?;
        ensure!(
            !m.publication.manifest.deleted
                && m.publication
                    .manifest
                    .storage_hosts
                    .contains(&hex::encode(service)),
            "mail recipient is outside exact owner-selected placement"
        );
        let s = Service::parse(
            &state.record(136, *service)?.payload,
            state.network,
            state.incarnation,
        )?;
        let index = Index::parse(records, reserved, state.network, state.incarnation)?;
        let d = index
            .deployments
            .get(&s.profile.manifest.deployment)
            .context("mail deployment absent")?;
        ensure!(
            !s.withdrawn
                && d.operator == s.profile.manifest.operator
                && d.services.get(&3) == Some(service),
            "mail recipient is not its exact registered role"
        );
        Ok(*service)
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
        "mail context differs"
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
    let grant = || operation.grant.as_ref().context("mail capability missing");
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
                    &[*action],
                    (*scope_kind, *resource),
                    0,
                )?;
                if *action == 26 {
                    let r = c
                        .index
                        .deployments
                        .get(resource)
                        .context("mail deployment absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(resource),
                        "mail deployment withdrawn"
                    );
                    c.dependencies.extend([r.reference, r.profile, r.consent]);
                    c.capability(&r.grant, r.registrar, &[13], (5, *resource), 0)?;
                }
            }
            Command::Register { profile } => {
                let g = grant()?;
                c.capability(
                    g,
                    intent.requester,
                    &[26],
                    (5, profile.manifest.deployment),
                    0,
                )?;
                c.capability(g, intent.requester, &[14], (3, profile.service), 0)?;
                c.profile(profile, true)?;
                if replay {
                    let (_, s) = c.service(profile.service, true)?;
                    ensure!(
                        s.profile.envelope == profile.envelope
                            && s.manager == intent.requester
                            && s.grant == *g,
                        "mail registration differs from retained result"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(136, profile.service)),
                        "mail service already registered"
                    );
                    changed = Some(Record::next(
                        state,
                        136,
                        profile.service,
                        Service {
                            profile: profile.clone(),
                            manager: intent.requester,
                            grant: g.clone(),
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
                ensure!(operation.grant.is_none(), "mail withdrawal is intrinsic");
                let (r, mut s) = c.service(*service, false)?;
                ensure!(
                    intent.requester == *service || intent.requester == s.profile.manifest.operator,
                    "mail withdrawal belongs to another operator"
                );
                if replay {
                    ensure!(
                        s.withdrawn && *generation == 1 && r.reference.generation == 2,
                        "mail withdrawal differs"
                    );
                } else {
                    ensure!(
                        !s.withdrawn && r.reference.generation == *generation,
                        "mail withdrawal generation differs"
                    );
                    s.withdrawn = true;
                    changed = Some(Record::next(state, 136, *service, s.value())?);
                }
            }
            Command::Service { service } => {
                let (_, s) = c.service(*service, false)?;
                if let Some(g) = &operation.grant {
                    c.capability(g, intent.requester, &[16], (3, *service), 0)?;
                } else {
                    ensure!(
                        intent.requester == *service
                            || intent.requester == s.manager
                            || intent.requester == s.profile.manifest.operator,
                        "mail store belongs to another principal"
                    );
                }
                let _ = c.service(*service, true);
            }
            Command::Services { after, .. } => {
                c.capability(grant()?, intent.requester, &[16], (0, state.network), 0)?;
                let mut last = None;
                let mut total = 0;
                for r in state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == 136 && after.is_none_or(|a| r.reference.id > a))
                {
                    if c.selected.len() == 8 || total + r.bytes.len() > wire::MAXIMUM / 2 {
                        continuation = last;
                        break;
                    }
                    total += r.bytes.len();
                    last = Some(r.reference.id);
                    c.select(136, r.reference.id)?;
                }
            }
            Command::Publish {
                publication,
                private,
            } => {
                let address = publication.id()?;
                let g = grant()?;
                c.capability(g, intent.requester, &[15, 16], (2, address), 0)?;
                let m = Mailbox {
                    publication: publication.clone(),
                    manager: intent.requester,
                    grant: g.clone(),
                    private: *private,
                    creation: intent.digest,
                };
                ensure!(
                    publication.manifest.expires.saturating_mul(1000) > at,
                    "mail publication expired"
                );
                for host in &publication.manifest.storage_hosts {
                    let (_, s) = c.service(objects::native(host)?, true)?;
                    ensure!(
                        publication.manifest.retention_seconds.saturating_mul(1000)
                            <= s.profile.maximum_lifetime_ms,
                        "mail retention exceeds selected host consent"
                    );
                }
                if replay {
                    let (_, old) = c.mailbox(address, None)?;
                    ensure!(
                        old.value() == m.value(),
                        "mail publication differs from retained result"
                    );
                } else {
                    if let Some(old) = state.records.get(&(137, address)) {
                        let (_, old_m) = c.mailbox(address, None)?;
                        ensure!(
                            old_m.manager == m.manager
                                && old_m.publication.owner()? == publication.owner()?
                                && old_m.publication.manifest.generation.checked_add(1)
                                    == Some(publication.manifest.generation)
                                && publication.manifest.previous_digest.as_deref()
                                    == Some(hex::encode(old_m.publication.digest).as_str()),
                            "mailbox owner, manager or exact predecessor changed"
                        );
                        ensure!(
                            !old_m.publication.manifest.deleted,
                            "deleted mailbox identity cannot be reused"
                        );
                        let _ = old;
                    } else {
                        ensure!(
                            publication.manifest.generation == 1
                                && publication.manifest.previous_digest.is_none(),
                            "new mailbox has predecessor"
                        );
                    }
                    reserve(&mut next, &m)?;
                    next.validate_roles(records, reserved)?;
                    changed = Some(Record::next(state, 137, address, m.value())?);
                }
            }
            Command::Get { address, source } => {
                let (_, m) = c.mailbox(*address, None)?;
                if let Some(g) = &operation.grant {
                    c.capability(g, intent.requester, &[15], (2, *address), 0)?;
                } else if let Some(source) = source {
                    let (_, sender) = c.mailbox(*source, Some(15))?;
                    c.device(&sender, intent.requester, "Send")?;
                } else {
                    c.owner(&m, intent.requester)?;
                }
                // Device refresh carries the current manager and store capability closure.
                // Historical metadata remains readable when an effect is no longer permitted.
                let _ = c.mailbox(*address, Some(16));
                for host in &m.publication.manifest.storage_hosts {
                    let _ = c.service(objects::native(host)?, true);
                }
            }
            Command::Package { address, package } => {
                ensure!(
                    operation.grant.is_none(),
                    "mail package publication uses mailbox device authority"
                );
                let (r, m) = c.mailbox(*address, Some(16))?;
                let d = c.device(&m, intent.requester, "Read")?;
                ensure!(
                    package.device_id == d.device_id
                        && package.expires <= d.expires
                        && package.expires.saturating_mul(1000) > at,
                    "mail package device or expiry differs"
                );
                let lookup = package.id(state.network, state.incarnation, *address)?;
                let p = Inventory {
                    mailbox: r.reference,
                    package: package.clone(),
                    creation: intent.digest,
                };
                if replay {
                    ensure!(
                        Inventory::parse(&c.select(138, lookup)?.payload)?.value()? == p.value()?,
                        "mail inventory replay differs"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(138, lookup)),
                        "mail package reference already used"
                    );
                    changed = Some(Record::next(state, 138, lookup, p.value()?)?);
                }
            }
            Command::Inventory {
                address,
                source,
                after,
            } => {
                let (r, m) = c.mailbox(*address, Some(16))?;
                if let Some(g) = &operation.grant {
                    c.capability(g, intent.requester, &[15], (2, *address), 0)?;
                } else if let Some(source) = source {
                    let (_, sender) = c.mailbox(*source, Some(15))?;
                    c.device(&sender, intent.requester, "Send")?;
                } else {
                    c.owner(&m, intent.requester)?;
                }
                let mut last = None;
                let mut count = 0;
                for p in state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == 138 && after.is_none_or(|a| r.reference.id > a))
                {
                    let p2 = Inventory::parse(&p.payload)?;
                    if p2.mailbox == r.reference && p2.package.expires.saturating_mul(1000) > at {
                        let used = state
                            .records
                            .values()
                            .filter(|r| r.reference.kind == 139)
                            .map(|r| Claim::parse(&r.payload))
                            .collect::<Result<Vec<_>>>()?
                            .iter()
                            .any(|claim| claim.packages.contains(&p.reference));
                        if !used {
                            if count == 8 {
                                continuation = last;
                                break;
                            }
                            c.package(&p.reference, &r, &m)?;
                            count += 1;
                            last = Some(p.reference.id);
                        }
                    }
                }
            }
            Command::Claim {
                id,
                sender,
                recipient,
                packages,
                expires,
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "mail claim uses sender device authority"
                );
                let (sr, s) = c.mailbox(*sender, Some(15))?;
                c.device(&s, intent.requester, "Send")?;
                let (rr, r) = c.mailbox(*recipient, Some(16))?;
                let mut devices = std::collections::BTreeSet::new();
                for p in packages {
                    let p = c.package(p, &rr, &r)?;
                    ensure!(
                        devices.insert(p.package.device_id),
                        "duplicate package device in claim"
                    );
                }
                let expected = r
                    .publication
                    .manifest
                    .devices
                    .iter()
                    .filter(|d| {
                        d.expires.saturating_mul(1000) > at
                            && d.permissions.iter().any(|p| p == "Read")
                    })
                    .map(|d| d.device_id.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                ensure!(
                    !expected.is_empty()
                        && devices == expected
                        && at.checked_add(1250).is_some_and(|v| v < *expires)
                        && *expires <= c.expires
                        && *expires
                            <= at.saturating_add(
                                r.publication
                                    .manifest
                                    .retention_seconds
                                    .saturating_mul(1000)
                            ),
                    "claim recipient roster or expiry differs"
                );
                let mut placement = vec![];
                for host in &r.publication.manifest.storage_hosts {
                    let (sr, _) = c.service(objects::native(host)?, true)?;
                    placement.push(sr.reference);
                }
                sorted(&mut placement)?;
                ensure!(
                    *expires <= c.expires,
                    "mail claim outlives selected storage authority"
                );
                let claim = Claim {
                    sender: sr.reference,
                    recipient: rr.reference,
                    device: intent.requester,
                    packages: packages.clone(),
                    expires: *expires,
                    creation: intent.digest,
                    payload_digest: None,
                    payload_bytes: 0,
                    binding: None,
                    placement,
                    created_ms: if replay {
                        Claim::parse(&state.record(139, *id)?.payload)?.created_ms
                    } else {
                        at
                    },
                };
                if replay {
                    ensure!(
                        Claim::parse(&c.select(139, *id)?.payload)?.value() == claim.value(),
                        "mail claim replay differs"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(139, *id)),
                        "mail claim identity already used"
                    );
                    for other in state.records.values().filter(|r| r.reference.kind == 139) {
                        let old = Claim::parse(&other.payload)?;
                        ensure!(
                            !old.packages.iter().any(|p| packages.contains(p)),
                            "mail package has already been claimed"
                        );
                    }
                    changed = Some(Record::next(state, 139, *id, claim.value())?);
                }
            }
            Command::ClaimGet { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "mail claim inspection is intrinsic"
                );
                let (_, claim, s, r) = c.claim(*id, false)?;
                ensure!(intent.requester==claim.device||intent.requester==s.manager||intent.requester==r.manager||r.publication.manifest.devices.iter().any(|d|objects::native(&d.request_key).ok()==Some(intent.requester)),"mail claim belongs to other principals");
                for p in claim.packages {
                    c.select(138, p.id)?;
                }
            }
            Command::Bind { id, bytes, digest } => {
                ensure!(
                    operation.grant.is_none(),
                    "mail binding uses exact sender device authority"
                );
                let (_, mut claim, _, recipient) = c.claim(*id, true)?;
                ensure!(
                    intent.requester == claim.device,
                    "mail binding is not from claim sender"
                );
                for host in &claim.placement {
                    let (sr, s) = c.service(host.id, true)?;
                    ensure!(
                        sr.reference == *host
                            && *bytes <= s.profile.maximum_payload
                            && claim.expires <= at.saturating_add(s.profile.maximum_lifetime_ms),
                        "mail binding exceeds exact consenting store"
                    );
                }
                if replay {
                    ensure!(
                        claim.payload_digest == Some(*digest)
                            && claim.payload_bytes == *bytes
                            && claim.binding == Some(intent.digest),
                        "mail payload binding replay differs"
                    );
                } else {
                    ensure!(
                        claim.binding.is_none(),
                        "mail claim already bound to ciphertext"
                    );
                    for host in &recipient.publication.manifest.storage_hosts {
                        let (_, s) = c.service(objects::native(host)?, true)?;
                        ensure!(
                            *bytes <= s.profile.maximum_payload
                                && claim.expires
                                    <= at.saturating_add(s.profile.maximum_lifetime_ms),
                            "mail ciphertext exceeds selected host consent"
                        );
                        let mut used = reservation_bytes(*bytes)?;
                        for r in state.records.values().filter(|r| r.reference.kind == 139) {
                            let existing = Claim::parse(&r.payload)?;
                            if existing.binding.is_some()
                                && existing.expires > at
                                && existing
                                    .placement
                                    .iter()
                                    .any(|p| hex::encode(p.id) == *host)
                            {
                                used = used
                                    .checked_add(reservation_bytes(existing.payload_bytes)?)
                                    .context("mail store reservation overflow")?;
                            }
                        }
                        ensure!(
                            used <= s.profile.state_bytes / 2 - BANK_HEADER - disk_header_bytes(),
                            "mail store lacks unreserved capacity"
                        );
                    }
                    claim.payload_digest = Some(*digest);
                    claim.payload_bytes = *bytes;
                    claim.binding = Some(intent.digest);
                    changed = Some(Record::next(state, 139, *id, claim.value())?);
                }
            }
            Command::Execute {
                address,
                service,
                effect,
                message,
                claim,
                bytes,
                digest,
                ..
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "mail serving uses exact device authority"
                );
                let (r, m) = c.mailbox(*address, Some(16))?;
                ensure!(
                    m.publication
                        .manifest
                        .storage_hosts
                        .contains(&hex::encode(service)),
                    "mail effect is outside owner-selected placement"
                );
                let (_, s) = c.service(*service, true)?;
                match effect {
                    Effect::Put => {
                        let (_, c2, _, _) = c.claim(claim.context("mail claim missing")?, true)?;
                        ensure!(
                            c2.device == intent.requester
                                && c2.recipient == r.reference
                                && *message == *claim
                                && c2.payload_digest == *digest
                                && c2.payload_bytes == *bytes
                                && *bytes <= s.profile.maximum_payload
                                && c2.placement.iter().any(|p| p.id == *service
                                    && state
                                        .record(136, *service)
                                        .is_ok_and(|r| r.reference == *p)),
                            "mail Put differs from exact bound ciphertext"
                        );
                    }
                    Effect::List => {
                        c.device(&m, intent.requester, "Read")?;
                    }
                    Effect::Fetch | Effect::Delete => {
                        c.device(
                            &m,
                            intent.requester,
                            if *effect == Effect::Delete {
                                "Delete"
                            } else {
                                "Read"
                            },
                        )?;
                        let (_, old, _, _) =
                            c.claim(message.context("message identifier missing")?, false)?;
                        ensure!(
                            old.recipient.id == *address
                                && old.binding.is_some()
                                && old.expires > at
                                && old.placement.iter().any(|p| p.id == *service),
                            "message does not belong to this mailbox/store or has expired"
                        );
                        c.expires = c.expires.min(old.expires);
                    }
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
    if sorted(&mut c.dependencies).is_err() {
        return Ok(Decision::refused(2));
    }
    let dependencies = c.dependencies.clone();
    if exact
        && !replay
        && ((operation.mutation() && intent.expected != dependencies)
            || (!operation.mutation() && intent.expected.iter().any(|v| !dependencies.contains(v))))
    {
        return Ok(Decision::refused(12));
    }
    if let Some(r) = changed {
        if next.put(r.clone()).is_err() {
            return Ok(Decision::refused(2));
        }
        c.selected.insert(r.reference.index(), r);
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
    if validate_versions(&versions, 64).is_err() {
        return Ok(Decision::refused(2));
    }
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
            continuation.as_ref().map_or(V::Null, |v| b(v)),
        ]),
    ]);
    Ok(bounded_result(
        (operation.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies,
        c.expires,
    ))
}
fn bounded_result(
    state: Option<State>,
    value: V,
    versions: Vec<VersionRef>,
    dependencies: Vec<VersionRef>,
    expires_ms: u64,
) -> Decision {
    if wire::encode(&value).is_err() {
        return Decision::refused(2);
    }
    Decision {
        state,
        value,
        versions,
        dependencies,
        code: 0,
        expires_ms,
    }
}
pub fn reservation_bytes(payload: u64) -> Result<u64> {
    ensure!(
        (1..=MAXIMUM_PAYLOAD).contains(&payload),
        "mail reservation exceeds payload bound"
    );
    let empty = wire::encode(&a(vec![
        b(&[1; 32]),
        b(&[1; 32]),
        b(&[1; 32]),
        b(&[1; 32]),
        V::Uint(payload),
        V::Uint(u64::MAX),
        b(&[]),
        V::Bool(false),
    ]))?
    .len() as u64;
    let header = if payload < 24 {
        1
    } else if payload <= 255 {
        2
    } else if payload <= 65535 {
        3
    } else {
        5
    };
    empty
        .checked_add(payload)
        .and_then(|n| n.checked_add(header - 1))
        .context("mail storage reservation overflow")
}
pub fn disk_header_bytes() -> u64 {
    wire::encode(&a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityMailStorage".into()),
        b(&[1; 32]),
        b(&[1; 32]),
        b(&[1; 32]),
        V::Uint(u64::MAX),
        a(vec![]),
    ]))
    .expect("fixed mail storage header")
    .len() as u64
        + 2
}

#[cfg(test)]
#[test]
fn mail_oversized_response_closure_is_a_refusal_without_candidate_state() {
    let mut closure = State::empty([1; 32], [2; 32]);
    closure
        .reserve(
            3,
            crate::authority_deployment_tests::key(75)
                .verifying_key()
                .to_bytes(),
            crate::authority_deployment_tests::key(76)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(vec![]),
        a(vec![
            V::Text("MailClaim".into()),
            a(vec![b(&vec![17; wire::MAXIMUM])]),
            a(vec![]),
            V::Null,
        ]),
    ]);
    let refused = bounded_result(Some(closure), value, vec![], vec![], 10_000);
    assert_eq!(refused.code, 2);
    assert!(refused.state.is_none());
    assert_eq!(refused.value, a(vec![]));
}
