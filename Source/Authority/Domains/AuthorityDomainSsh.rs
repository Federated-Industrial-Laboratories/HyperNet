// SPDX-License-Identifier: MIT
// SSH sessions require a current member capability, operator acceptance and quorum freshness.
use super::*;
use crate::{
    authority_deployment_records::{Index, Registration},
    authority_governance::{Governance, Requirement},
    authority_membership::current,
};
use anyhow::Context as _;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Debug)]
pub struct Profile {
    pub manifest: crate::runtime_manifest::Manifest,
    #[cfg(test)]
    pub network: Digest,
    #[cfg(test)]
    pub incarnation: Digest,
    pub deployment: Digest,
    pub service: Key,
    pub operator: Key,
    pub native: Key,
    pub command_digest: Digest,
    pub endpoint: Digest,
    pub purpose: String,
    pub maximum_seconds: u64,
    pub validity: (u64, u64),
    pub deployment_profile: VersionRef,
    pub consent: VersionRef,
    pub envelope: Vec<u8>,
}
impl Profile {
    pub fn parse(envelope: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= crate::runtime_manifest::MAXIMUM + 4096,
            "SSH profile exceeds its bound"
        );
        let (payload, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&payload)?;
        let f = value.array(17)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthoritySshProfile"
                && id(&f[3])? == network
                && id(&f[4])? == incarnation,
            "SSH profile context differs"
        );
        let span = f[13].array(2)?;
        let profile = Self {
            manifest: crate::runtime_manifest::Manifest::parse(f[16].bytes()?)?,
            #[cfg(test)]
            network,
            #[cfg(test)]
            incarnation,
            deployment: id(&f[5])?,
            service: key(&f[6])?,
            operator: key(&f[7])?,
            native: key(&f[8])?,
            command_digest: id(&f[9])?,
            endpoint: id(&f[10])?,
            purpose: label(&f[11], 128)?,
            maximum_seconds: f[12].uint()?,
            validity: (span[0].uint()?, span[1].uint()?),
            deployment_profile: version(&f[14])?,
            consent: version(&f[15])?,
            envelope: envelope.to_vec(),
        };
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == profile.operator
                && profile.service != profile.operator
                && profile.native != profile.operator
                && profile.native != profile.service
                && (1..=300).contains(&profile.maximum_seconds)
                && profile.validity.0 < profile.validity.1
                && profile.deployment_profile.kind == 117
                && profile.consent.kind == 105
                && profile.deployment_profile.id == profile.deployment
                && profile.consent.id == profile.deployment,
            "SSH profile identity, signature or validity differs"
        );
        ensure!(
            profile.manifest.network == network
                && profile.manifest.incarnation == incarnation
                && profile.manifest.deployment == profile.deployment
                && profile.manifest.operator == profile.operator
                && profile.deployment_profile
                    == crate::authority_deployment_records::reference(
                        &profile.manifest.desired()?
                    )?
                && profile.consent
                    == crate::authority_deployment_records::reference(
                        &profile.manifest.unsigned_consent(0)?
                    )?
                && profile.manifest.roles.iter().any(|role| role.role == 8
                    && role.service_key == profile.service
                    && role.bind_endpoint_ids.contains(&profile.endpoint))
                && profile.validity.0 >= profile.manifest.validity.0
                && profile.validity.1 <= profile.manifest.validity.1,
            "SSH service definition differs from its exact original operator consent"
        );
        Ok(profile)
    }
}

#[derive(Clone, Debug)]
pub struct Service {
    pub profile: Profile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Service {
    pub fn parse(payload: &V, network: Digest, incarnation: Digest) -> Result<Self> {
        let f = payload.array(4)?;
        let result = Self {
            profile: Profile::parse(f[0].bytes()?, network, incarnation)?,
            manager: key(&f[1])?,
            grant: version(&f[2])?,
            withdrawn: f[3].boolean()?,
        };
        ensure!(
            result.grant.kind == 102,
            "SSH management reference is not a grant"
        );
        Ok(result)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.profile.envelope),
            b(&self.manager),
            reference(&self.grant),
            V::Bool(self.withdrawn),
        ])
    }
}
pub fn validate_service(
    payload: &V,
    network: Digest,
    incarnation: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    let service = Service::parse(payload, network, incarnation)?;
    ensure!(
        lookup == service.profile.service && generation == if service.withdrawn { 2 } else { 1 },
        "SSH service generation or lookup differs"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub service: Key,
    pub profile: VersionRef,
    pub member: Key,
    pub native: Key,
    pub capability: VersionRef,
    pub purpose: String,
    pub expires: u64,
    pub accepted: bool,
    pub revoked: bool,
    pub proof: String,
    pub creation: Digest,
}
impl Grant {
    pub fn parse(payload: &V, network: Digest) -> Result<Self> {
        let f = payload.array(11)?;
        let grant = Self {
            service: key(&f[0])?,
            profile: version(&f[1])?,
            member: key(&f[2])?,
            native: key(&f[3])?,
            capability: version(&f[4])?,
            purpose: label(&f[5], 128)?,
            expires: f[6].uint()?,
            accepted: f[7].boolean()?,
            revoked: f[8].boolean()?,
            proof: f[9].text()?.into(),
            creation: id(&f[10])?,
        };
        ensure!(
            grant.profile.kind == 132
                && grant.profile.id == grant.service
                && grant.profile.generation == 1
                && grant.capability.kind == 102
                && grant.service != grant.member
                && grant.native != grant.member
                && grant.native != grant.service
                && grant.expires > 0
                && grant.proof.len() <= 1024,
            "invalid SSH grant identities"
        );
        verify_native(&grant.proof, network, grant.member, grant.native)?;
        Ok(grant)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.service),
            reference(&self.profile),
            b(&self.member),
            b(&self.native),
            reference(&self.capability),
            V::Text(self.purpose.clone()),
            V::Uint(self.expires),
            V::Bool(self.accepted),
            V::Bool(self.revoked),
            V::Text(self.proof.clone()),
            b(&self.creation),
        ])
    }
}
pub fn validate_grant(
    payload: &V,
    network: Digest,
    _incarnation: Digest,
    _lookup: Digest,
    generation: u64,
) -> Result<()> {
    let grant = Grant::parse(payload, network)?;
    ensure!(
        generation == 1 + u64::from(grant.accepted) + u64::from(grant.revoked),
        "SSH grant generation differs from acceptance and revocation"
    );
    Ok(())
}
pub fn native_public(native: Key) -> String {
    let mut bytes = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    bytes.extend_from_slice(&native);
    format!("ssh-ed25519 {}", STANDARD.encode(bytes))
}
fn verify_native(proof: &str, network: Digest, member: Key, native: Key) -> Result<()> {
    crate::ssh_proof::verify(
        proof,
        &hex::encode(network),
        &hex::encode(member),
        &native_public(native),
    )
    .map_err(|error| anyhow::anyhow!("SSH native key possession failed: {error}"))
}
pub fn validate_state(state: &State) -> Result<()> {
    for record in state.records.values() {
        match record.reference.kind {
            132 => {
                let s = Service::parse(&record.payload, state.network, state.incarnation)?;
                ensure!(
                    state.keys.get(&s.profile.native) == Some(&(0, s.profile.service)),
                    "SSH host key reservation is absent"
                );
            }
            133 => {
                let g = Grant::parse(&record.payload, state.network)?;
                let s = state.record(132, g.service)?;
                ensure!(
                    s.reference.generation >= g.profile.generation
                        && (s.reference.generation != g.profile.generation
                            || s.reference == g.profile),
                    "SSH grant profile is absent or conflicts"
                );
                if g.accepted {
                    ensure!(
                        state.keys.get(&g.native) == Some(&(1, g.member)),
                        "accepted SSH key reservation is absent"
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub enum Command {
    Context {
        action: u64,
        scope_kind: u64,
        resource: Digest,
    },
    Register {
        profile: Box<Profile>,
    },
    Withdraw {
        service: Key,
        generation: u64,
    },
    Service {
        service: Key,
    },
    Services {
        network: Digest,
        after: Option<Key>,
    },
    Create {
        id: Digest,
        service: Key,
        native: Key,
        proof: String,
        purpose: String,
        expires: u64,
    },
    Accept {
        id: Digest,
    },
    Revoke {
        id: Digest,
    },
    Grant {
        id: Digest,
    },
    Authorise {
        service: Key,
        id: Digest,
    },
}
impl Command {
    pub fn parse(value: &V, network: Digest, incarnation: Digest) -> Result<Self> {
        let f = value.list(7)?;
        let name = f.first().context("empty domain command")?.text()?;
        Ok(match name {
            "SshContext" => {
                let f = value.array(4)?;
                let action = f[1].uint()?;
                let scope_kind = f[2].uint()?;
                ensure!(
                    matches!((action, scope_kind), (20, 0 | 3) | (26, 5)),
                    "unsupported SSH context capability"
                );
                let resource = id(&f[3])?;
                ensure!(
                    scope_kind != 0 || resource == network,
                    "SSH context network differs"
                );
                Self::Context {
                    action,
                    scope_kind,
                    resource,
                }
            }
            "SshServiceRegister" => {
                let f = value.array(2)?;
                Self::Register {
                    profile: Box::new(Profile::parse(f[1].bytes()?, network, incarnation)?),
                }
            }
            "SshServiceWithdraw" => {
                let f = value.array(3)?;
                Self::Withdraw {
                    service: key(&f[1])?,
                    generation: f[2].uint()?,
                }
            }
            "SshServiceGet" => {
                let f = value.array(2)?;
                Self::Service {
                    service: key(&f[1])?,
                }
            }
            "SshServices" => {
                let f = value.array(3)?;
                ensure!(id(&f[1])? == network, "SSH listing network differs");
                Self::Services {
                    network,
                    after: if f[2] == V::Null {
                        None
                    } else {
                        Some(key(&f[2])?)
                    },
                }
            }
            "SshGrantCreate" => {
                let f = value.array(7)?;
                ensure!(
                    f[4].text()?.len() <= 1024,
                    "SSH possession exceeds its bound"
                );
                Self::Create {
                    id: id(&f[1])?,
                    service: key(&f[2])?,
                    native: key(&f[3])?,
                    proof: f[4].text()?.into(),
                    purpose: label(&f[5], 128)?,
                    expires: f[6].uint()?,
                }
            }
            "SshGrantAccept" | "SshGrantRevoke" | "SshGrantGet" => {
                let f = value.array(2)?;
                let id = id(&f[1])?;
                match name {
                    "SshGrantAccept" => Self::Accept { id },
                    "SshGrantRevoke" => Self::Revoke { id },
                    _ => Self::Grant { id },
                }
            }
            "SshAuthorise" => {
                let f = value.array(3)?;
                Self::Authorise {
                    service: key(&f[1])?,
                    id: id(&f[2])?,
                }
            }
            _ => anyhow::bail!("unsupported domain command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "SshContext",
            Self::Register { .. } => "SshServiceRegister",
            Self::Withdraw { .. } => "SshServiceWithdraw",
            Self::Service { .. } => "SshServiceGet",
            Self::Services { .. } => "SshServices",
            Self::Create { .. } => "SshGrantCreate",
            Self::Accept { .. } => "SshGrantAccept",
            Self::Revoke { .. } => "SshGrantRevoke",
            Self::Grant { .. } => "SshGrantGet",
            Self::Authorise { .. } => "SshAuthorise",
        }
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Register { .. }
                | Self::Withdraw { .. }
                | Self::Create { .. }
                | Self::Accept { .. }
                | Self::Revoke { .. }
        )
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { resource, .. } => *resource,
            Self::Register { profile } => profile.service,
            Self::Withdraw { service, .. } | Self::Service { service } => *service,
            Self::Services { network, .. } => *network,
            Self::Create { id, .. }
            | Self::Accept { id }
            | Self::Revoke { id }
            | Self::Grant { id }
            | Self::Authorise { id, .. } => *id,
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        match self {
            Self::Context {
                action,
                scope_kind,
                resource,
            } => f.extend([V::Uint(*action), V::Uint(*scope_kind), b(resource)]),
            Self::Register { profile } => f.push(b(&profile.envelope)),
            Self::Withdraw {
                service,
                generation,
            } => f.extend([b(service), V::Uint(*generation)]),
            Self::Service { service } => f.push(b(service)),
            Self::Services { network, after } => {
                f.extend([b(network), after.as_ref().map_or(V::Null, |k| b(k))])
            }
            Self::Create {
                id,
                service,
                native,
                proof,
                purpose,
                expires,
            } => f.extend([
                b(id),
                b(service),
                b(native),
                V::Text(proof.clone()),
                V::Text(purpose.clone()),
                V::Uint(*expires),
            ]),
            Self::Accept { id } | Self::Revoke { id } | Self::Grant { id } => f.push(b(id)),
            Self::Authorise { service, id } => f.extend([b(service), b(id)]),
        }
        a(f)
    }
}

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
            "domain capability reference is stale"
        );
        let c = self.governance.current_capability(
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
        self.dependencies.extend(c.dependencies);
        self.expires = self.expires.min(c.expires_ms);
        Ok(())
    }
    fn deployment(&mut self, p: &Profile, live: bool) -> Result<Registration> {
        let r = self
            .index
            .deployments
            .get(&p.deployment)
            .context("SSH deployment absent")?
            .clone();
        ensure!(
            r.operator == p.operator
                && r.services.get(&8) == Some(&p.service)
                && p.deployment_profile.digest == wire::digest(&p.manifest.desired()?)
                && p.consent.digest == wire::digest(&p.manifest.unsigned_consent(0)?),
            "SSH profile differs from admitted role and local consent"
        );
        let effective =
            crate::authority_operational_consent::validity(&r.manifest, &p.manifest, p.validity)?;
        self.dependencies
            .extend([r.reference.clone(), r.profile.clone(), r.consent.clone()]);
        if let Some(w) = self.index.withdrawals.get(&r.deployment) {
            self.dependencies.push(w.reference.clone());
            ensure!(!live, "SSH deployment is withdrawn");
        }
        if live {
            let consent = wire::decode(self.governance.record_bytes(105, r.deployment)?)?;
            let f = consent.array(19)?;
            let span = f[16].array(2)?;
            let validity = (span[0].uint()?, span[1].uint()?);
            ensure!(
                current(self.at, effective)
                    && current(self.at, validity)
                    && effective.0 >= validity.0
                    && effective.1 <= validity.1
                    && f[11].list(16)?.iter().any(|v| v.array(2).is_ok_and(|f| f[0]
                        .fixed::<32>()
                        .ok()
                        == Some(p.service)
                        && f[1].fixed::<32>().ok() == Some(p.endpoint))),
                "SSH profile exceeds current deployment consent"
            );
            self.expires = self.expires.min(effective.1).min(validity.1);
            self.capability(&r.grant, r.registrar, 13, (5, r.deployment))?;
        }
        Ok(r)
    }
    fn service(&mut self, id: Key, live: bool) -> Result<(Record, Service)> {
        let record = self.select(132, id)?;
        let s = Service::parse(&record.payload, self.state.network, self.state.incarnation)?;
        self.deployment(&s.profile, live)?;
        if live {
            ensure!(!s.withdrawn, "SSH service is withdrawn");
            self.capability(&s.grant, s.manager, 26, (5, s.profile.deployment))?;
        }
        Ok((record, s))
    }
    fn grant(&mut self, id: Digest, live: bool) -> Result<(Record, Grant, Service)> {
        let record = self.select(133, id)?;
        let g = Grant::parse(&record.payload, self.state.network)?;
        let (sr, s) = self.service(g.service, live)?;
        if live {
            ensure!(
                !g.revoked
                    && g.profile == sr.reference
                    && g.purpose == s.profile.purpose
                    && self
                        .at
                        .checked_add(1250)
                        .is_some_and(|upper| upper < g.expires)
                    && g.expires <= s.profile.validity.1,
                "SSH session is stale, revoked or expired"
            );
            self.capability(&g.capability, g.member, 20, (3, g.service))?;
            self.expires = self.expires.min(g.expires);
        }
        Ok((record, g, s))
    }
    fn native(&self, native: Key, class: u64, owner: Key) -> Result<()> {
        ensure!(
            !self.reserved.contains(&native)
                && !self.index.reserved.contains(&native)
                && self
                    .state
                    .keys
                    .get(&native)
                    .is_none_or(|v| *v == (class, owner)),
            "SSH native key belongs to another identity class"
        );
        for v in self.governance.versions() {
            let r = wire::decode(self.governance.record_bytes(v.kind, v.id)?)?;
            let f = r.list(32)?;
            ensure!(
                !(v.kind == 102 && f[8].fixed::<32>()? == native
                    || v.kind == 125 && f[7].fixed::<32>()? == native
                    || v.kind == 127 && f[6].fixed::<32>()? == native),
                "SSH native key is an admitted principal"
            );
        }
        Ok(())
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
        "domain state differs from request context"
    );
    let governance = Governance::parse(intent.network, intent.incarnation, records)?;
    let index = Index::parse(records, reserved, intent.network, intent.incarnation)?;
    let mut c = Context {
        state,
        governance,
        index,
        reserved,
        at,
        dependencies: vec![],
        expires: u64::MAX,
        selected: BTreeMap::new(),
    };
    let mut next = state.clone();
    let mut changed = None;
    let mut continuation = None;
    let result = (|| -> Result<()> {
        match command {
            Command::Context {
                action,
                scope_kind,
                resource,
            } => {
                c.capability(
                    operation
                        .grant
                        .as_ref()
                        .context("SSH context capability missing")?,
                    intent.requester,
                    *action,
                    (*scope_kind, *resource),
                )?;
                if *action == 26 {
                    let r = c
                        .index
                        .deployments
                        .get(resource)
                        .context("SSH deployment absent")?
                        .clone();
                    ensure!(
                        !c.index.withdrawals.contains_key(resource),
                        "SSH deployment is withdrawn"
                    );
                    c.dependencies.extend([r.reference, r.profile, r.consent]);
                    c.capability(&r.grant, r.registrar, 13, (5, *resource))?;
                }
            }
            Command::Register { profile } => {
                let manager = operation
                    .grant
                    .as_ref()
                    .context("SSH management capability missing")?;
                c.capability(manager, intent.requester, 26, (5, profile.deployment))?;
                c.deployment(profile, true)?;
                c.native(profile.native, 0, profile.service)?;
                if replay {
                    let (_, old) = c.service(profile.service, true)?;
                    ensure!(
                        old.profile.envelope == profile.envelope
                            && old.manager == intent.requester
                            && old.grant == *manager,
                        "SSH registration differs from retained result"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(132, profile.service)),
                        "SSH service already configured"
                    );
                    let service = Service {
                        profile: profile.as_ref().clone(),
                        manager: intent.requester,
                        grant: manager.clone(),
                        withdrawn: false,
                    };
                    changed = Some(Record::next(state, 132, profile.service, service.value())?);
                    next.reserve(0, profile.native, profile.service)?;
                }
            }
            Command::Withdraw {
                service,
                generation,
            } => {
                ensure!(
                    operation.grant.is_none(),
                    "intrinsic withdrawal does not use a capability"
                );
                let (record, mut s) = c.service(*service, false)?;
                ensure!(
                    intent.requester == *service || intent.requester == s.profile.operator,
                    "SSH withdrawal is not from its operator or service"
                );
                if replay {
                    ensure!(
                        s.withdrawn && *generation == 1 && record.reference.generation == 2,
                        "SSH withdrawal differs from retained result"
                    );
                } else {
                    ensure!(
                        !s.withdrawn && record.reference.generation == *generation,
                        "SSH withdrawal generation differs"
                    );
                    s.withdrawn = true;
                    changed = Some(Record::next(state, 132, *service, s.value())?);
                }
            }
            Command::Service { service } => {
                if let Some(grant) = &operation.grant {
                    c.capability(grant, intent.requester, 20, (3, *service))?;
                    c.service(*service, true)?;
                } else {
                    let (_, s) = c.service(*service, false)?;
                    ensure!(
                        intent.requester == s.profile.operator
                            || intent.requester == *service
                            || intent.requester == s.manager,
                        "SSH service inspection belongs to another principal"
                    );
                    // Historical ownership permits inspection after expiry. When live,
                    // include the current permission context needed for a subsequent request.
                    let _ = c.service(*service, true);
                }
            }
            Command::Services { after, .. } => {
                c.capability(
                    operation
                        .grant
                        .as_ref()
                        .context("SSH list capability missing")?,
                    intent.requester,
                    20,
                    (0, state.network),
                )?;
                let mut services = state.records.values().filter(|r| {
                    r.reference.kind == 132 && after.is_none_or(|after| r.reference.id > after)
                });
                for _ in 0..16 {
                    let Some(record) = services.next() else { break };
                    c.select(132, record.reference.id)?;
                }
                if services.next().is_some() {
                    continuation = c.selected.keys().last().map(|(_, id)| *id);
                }
            }
            Command::Create {
                id,
                service,
                native,
                proof,
                purpose,
                expires,
            } => {
                let capability = operation
                    .grant
                    .as_ref()
                    .context("SSH session capability missing")?;
                c.capability(capability, intent.requester, 20, (3, *service))?;
                let (sr, s) = c.service(*service, true)?;
                c.native(*native, 1, intent.requester)?;
                verify_native(proof, state.network, intent.requester, *native)?;
                ensure!(
                    *purpose == s.profile.purpose
                        && *expires <= c.expires
                        && at.checked_add(1250).is_some_and(|upper| upper < *expires),
                    "SSH request exceeds current permission"
                );
                if replay {
                    let (_, g, _) = c.grant(*id, true)?;
                    ensure!(
                        g.creation == intent.digest,
                        "SSH grant has another creation intent"
                    );
                } else {
                    ensure!(
                        !state.records.contains_key(&(133, *id))
                            && at
                                .checked_add(s.profile.maximum_seconds * 1000)
                                .is_some_and(|end| *expires <= end),
                        "SSH grant already exists or exceeds the session limit"
                    );
                    changed = Some(Record::next(
                        state,
                        133,
                        *id,
                        Grant {
                            service: *service,
                            profile: sr.reference,
                            member: intent.requester,
                            native: *native,
                            capability: capability.clone(),
                            purpose: purpose.clone(),
                            expires: *expires,
                            accepted: false,
                            revoked: false,
                            proof: proof.clone(),
                            creation: intent.digest,
                        }
                        .value(),
                    )?);
                }
            }
            Command::Accept { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "SSH acceptance is intrinsic local consent"
                );
                let (_, mut g, s) = c.grant(*id, true)?;
                ensure!(
                    intent.requester == g.service || intent.requester == s.profile.operator,
                    "SSH acceptance is not from its operator or service"
                );
                c.native(g.native, 1, g.member)?;
                if replay {
                    ensure!(g.accepted, "SSH acceptance is absent");
                } else {
                    ensure!(!g.accepted, "SSH grant is already accepted");
                    for other in state
                        .records
                        .values()
                        .filter(|r| r.reference.kind == 133 && r.reference.id != *id)
                    {
                        let other = Grant::parse(&other.payload, state.network)?;
                        ensure!(
                            other.service != g.service
                                || !other.accepted
                                || other.revoked
                                || other.expires <= at,
                            "SSH service already has an accepted session"
                        );
                    }
                    next.reserve(1, g.native, g.member)?;
                    g.accepted = true;
                    changed = Some(Record::next(state, 133, *id, g.value())?);
                }
            }
            Command::Revoke { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "SSH revocation is an intrinsic restriction"
                );
                let (_, mut g, s) = c.grant(*id, false)?;
                ensure!(
                    intent.requester == g.member
                        || intent.requester == g.service
                        || intent.requester == s.profile.operator,
                    "SSH revocation is not from a session owner"
                );
                if replay {
                    ensure!(g.revoked, "SSH revocation is absent");
                } else {
                    ensure!(!g.revoked, "SSH grant is already revoked");
                    g.revoked = true;
                    changed = Some(Record::next(state, 133, *id, g.value())?);
                }
            }
            Command::Grant { id } => {
                ensure!(
                    operation.grant.is_none(),
                    "own SSH grant inspection is intrinsic"
                );
                let (_, g, s) = c.grant(*id, false)?;
                ensure!(
                    intent.requester == g.member
                        || intent.requester == g.service
                        || intent.requester == s.profile.operator,
                    "SSH grant belongs to another principal"
                );
                let _ = c.grant(*id, true);
            }
            Command::Authorise { service, id } => {
                ensure!(
                    operation.grant.is_none() && intent.requester == *service,
                    "SSH lease must be requested by its registered service"
                );
                let (_, g, _) = c.grant(*id, true)?;
                ensure!(
                    g.service == *service
                        && g.accepted
                        && state.keys.get(&g.native) == Some(&(1, g.member)),
                    "SSH session lacks exact operator acceptance"
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        #[cfg(test)]
        eprintln!("{} refused: {error:#}", operation.command.name());
        let _ = error;
        return Ok(Decision::refused(3));
    }
    sorted(&mut c.dependencies)?;
    let dependencies = c.dependencies.clone();
    if exact && !replay {
        if operation.mutation() && intent.expected != dependencies {
            return Ok(Decision::refused(12));
        }
        if !operation.mutation()
            && intent
                .expected
                .iter()
                .any(|expected| !dependencies.contains(expected))
        {
            return Ok(Decision::refused(12));
        }
    }
    if let Some(record) = changed {
        next.put(record.clone())?;
        c.selected.insert(record.reference.index(), record);
    }
    let mut versions: BTreeMap<_, _> = c
        .dependencies
        .iter()
        .map(|v| (v.index(), v.clone()))
        .collect();
    for record in c.selected.values() {
        versions.insert(record.reference.index(), record.reference.clone());
    }
    let versions = versions.into_values().collect::<Vec<_>>();
    validate_versions(&versions, 64)?;
    let bytes = c.selected.values().map(|r| b(&r.bytes)).collect();
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
            V::Text(operation.command.name().into()),
            a(bytes),
            a(governance_records),
            continuation.as_ref().map_or(V::Null, |k| b(k)),
        ]),
    ]);
    Ok(Decision {
        state: (operation.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}

#[cfg(test)]
include!("../../../Tests/Support/Authority/Domains/AuthorityDomainSsh.rs");
