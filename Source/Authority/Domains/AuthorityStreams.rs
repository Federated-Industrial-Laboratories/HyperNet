// SPDX-License-Identifier: MIT
// Application streams bind admitted principals to exact services and reusable finite session slots.
use super::*;
use crate::route_profile::Limits;
#[path = "AuthorityStreamsEvaluation.rs"]
mod evaluation;
pub use evaluation::evaluate;
pub(crate) use evaluation::evaluate_read;
#[path = "ApplicationStreamBinding.rs"]
pub mod local;
#[path = "ApplicationStreamProtocol.rs"]
pub mod protocol;
pub const MANAGE: u64 = 29;
pub const CONNECT: u64 = 30;
pub const PROTOCOL: u64 = 7;
pub const SLOTS: u64 = 16;

pub fn limits(v: &V) -> Result<Limits> {
    let f = v.array(3)?;
    let l = Limits {
        bytes: f[0].uint()?,
        duration_ms: f[1].uint()?,
        idle_ms: f[2].uint()?,
    };
    l.validate()?;
    Ok(l)
}
pub fn slot_id(service: Digest, principal: Key, slot: u64) -> Result<Digest> {
    ensure!(slot < SLOTS, "application stream slot exceeds its bound");
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Text("ApplicationStreamSlot".into()),
        b(&service),
        b(&principal),
        V::Uint(slot),
    ]))?))
}
#[derive(Clone, Debug)]
pub struct Registration {
    pub id: Digest,
    pub route: VersionRef,
    pub owner: Key,
    pub operator: Key,
    pub protocol: String,
    pub binding: Digest,
    pub limits: Limits,
    pub validity: (u64, u64),
    pub envelope: Vec<u8>,
}
impl Registration {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        Self::parse_inner(bytes, n, i, true)
    }

    fn parse_inner(bytes: &[u8], n: Digest, i: Digest, accepted: bool) -> Result<Self> {
        let (payload, signatures) = wire::envelope(bytes, 2)?;
        let value = wire::decode(&payload)?;
        let f = value.array(14)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "ApplicationStreamService"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "application service context differs"
        );
        let span = f[13].array(2)?;
        let out = Self {
            id: id(&f[5])?,
            route: version(&f[6])?,
            owner: key(&f[7])?,
            operator: key(&f[8])?,
            protocol: label(&f[9], 96)?,
            binding: id(&f[10])?,
            limits: limits(&f[11])?,
            validity: (span[0].uint()?, span[1].uint()?),
            envelope: bytes.to_vec(),
        };
        ensure!(
            f[12].uint()? == SLOTS
                && out.route.kind == 165
                && out.validity.0 < out.validity.1
                && out
                    .protocol
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b)),
            "invalid application stream service"
        );
        let mut signers = if accepted {
            vec![out.owner, out.operator]
        } else {
            vec![out.owner]
        };
        signers.sort();
        signers.dedup();
        ensure!(
            signatures.iter().map(|s| s.0).collect::<Vec<_>>() == signers,
            "application service requires exact owner and operator consent"
        );
        Ok(out)
    }
}
#[derive(Clone, Debug)]
pub struct Service {
    pub registration: Registration,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Service {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(3)?;
        let out = Self {
            registration: Registration::parse(f[0].bytes()?, n, i)?,
            grant: version(&f[1])?,
            withdrawn: f[2].boolean()?,
        };
        ensure!(
            out.grant.kind == 102,
            "application service requires a management capability"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.registration.envelope),
            reference(&self.grant),
            V::Bool(self.withdrawn),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Proof {
    pub service: VersionRef,
    pub principal: Key,
    pub grant: VersionRef,
    pub protocol: String,
    pub slot: u64,
    pub generation: u64,
    pub nonce: Digest,
    pub challenge: Digest,
    pub exporter: Digest,
    pub limits: Limits,
    pub expires: u64,
    pub envelope: Vec<u8>,
}
impl Proof {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        let value = wire::decode(&payload)?;
        let f = value.array(16)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "ApplicationStreamOpen"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "application stream proof context differs"
        );
        let out = Self {
            service: version(&f[5])?,
            principal: key(&f[6])?,
            grant: version(&f[7])?,
            protocol: label(&f[8], 96)?,
            slot: f[9].uint()?,
            generation: f[10].uint()?,
            nonce: id(&f[11])?,
            challenge: id(&f[12])?,
            exporter: id(&f[13])?,
            limits: limits(&f[14])?,
            expires: f[15].uint()?,
            envelope: bytes.to_vec(),
        };
        ensure!(
            out.service.kind == 172
                && out.grant.kind == 102
                && out.slot < SLOTS
                && out.generation > 0
                && out.expires > 0
                && signatures.len() == 1
                && signatures[0].0 == out.principal,
            "invalid application stream identity or slot"
        );
        Ok(out)
    }

    pub fn id(&self) -> Result<Digest> {
        slot_id(self.service.id, self.principal, self.slot)
    }
}
#[derive(Clone, Debug)]
pub struct Session {
    pub proof: Proof,
    pub closed: bool,
    pub retired: bool,
    pub creation: Digest,
}
impl Session {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(4)?;
        let out = Self {
            proof: Proof::parse(f[0].bytes()?, n, i)?,
            closed: f[1].boolean()?,
            retired: f[2].boolean()?,
            creation: id(&f[3])?,
        };
        ensure!(!out.retired || out.closed, "retired stream is not closed");
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.proof.envelope),
            V::Bool(self.closed),
            V::Bool(self.retired),
            b(&self.creation),
        ])
    }
}
pub fn validate_record(
    kind: u64,
    v: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    match kind {
        172 => ensure!(
            Service::parse(v, n, i)?.registration.id == lookup,
            "application service identifier differs"
        ),
        173 => {
            let s = Session::parse(v, n, i)?;
            ensure!(
                s.proof.id()? == lookup
                    && s.proof.generation <= generation
                    && generation
                        <= s.proof
                            .generation
                            .saturating_add(if s.retired { 2 } else { 1 })
                    && (generation == s.proof.generation) != s.closed,
                "application session generation differs"
            );
        }
        _ => anyhow::bail!("unsupported application stream record"),
    }
    Ok(())
}
pub fn validate_state(state: &State, partial: bool) -> Result<()> {
    for r in state.records.values().filter(|r| r.reference.kind == 172) {
        let s = Service::parse(&r.payload, state.network, state.incarnation)?;
        if let Some(route) = state.records.get(&(165, s.registration.route.id)) {
            ensure!(
                route.reference.generation >= s.registration.route.generation,
                "application route generation regressed"
            );
        } else {
            ensure!(partial, "application stream route is absent");
        }
    }
    for r in state.records.values().filter(|r| r.reference.kind == 173) {
        let s = Session::parse(&r.payload, state.network, state.incarnation)?;
        ensure!(
            partial || state.records.contains_key(&(172, s.proof.service.id)),
            "application stream service is absent"
        );
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub enum Command {
    Context { service: Digest, action: u64 },
    Register { registration: Registration },
    Lookup { service: Digest, slot: u64 },
    Admit { proof: Proof },
    Inspect { proof: Proof },
    Permit { session: VersionRef },
    Close { session: VersionRef },
    Withdraw { service: VersionRef },
}
impl Command {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.list(3)?;
        let c = match f.first().context("empty application command")?.text()? {
            "StreamContext" => {
                let f = v.array(3)?;
                let action = f[2].uint()?;
                ensure!(
                    matches!(action, MANAGE | CONNECT),
                    "invalid stream context action"
                );
                Self::Context {
                    service: id(&f[1])?,
                    action,
                }
            }
            "StreamRegister" => {
                let f = v.array(2)?;
                Self::Register {
                    registration: Registration::parse(f[1].bytes()?, n, i)?,
                }
            }
            "StreamLookup" => {
                let f = v.array(3)?;
                let slot = f[2].uint()?;
                ensure!(slot < SLOTS, "stream slot exceeds bound");
                Self::Lookup {
                    service: id(&f[1])?,
                    slot,
                }
            }
            name @ ("StreamAdmit" | "StreamInspect") => {
                let f = v.array(2)?;
                let proof = Proof::parse(f[1].bytes()?, n, i)?;
                if name == "StreamAdmit" {
                    Self::Admit { proof }
                } else {
                    Self::Inspect { proof }
                }
            }
            name @ ("StreamPermit" | "StreamClose" | "StreamWithdraw") => {
                let f = v.array(2)?;
                let r = version(&f[1])?;
                ensure!(
                    r.kind == if name == "StreamWithdraw" { 172 } else { 173 },
                    "stream reference kind differs"
                );
                match name {
                    "StreamPermit" => Self::Permit { session: r },
                    "StreamClose" => Self::Close { session: r },
                    _ => Self::Withdraw { service: r },
                }
            }
            _ => anyhow::bail!("unsupported application stream command"),
        };
        Ok(c)
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "StreamContext",
            Self::Register { .. } => "StreamRegister",
            Self::Lookup { .. } => "StreamLookup",
            Self::Admit { .. } => "StreamAdmit",
            Self::Inspect { .. } => "StreamInspect",
            Self::Permit { .. } => "StreamPermit",
            Self::Close { .. } => "StreamClose",
            Self::Withdraw { .. } => "StreamWithdraw",
        }
    }
    pub fn value(&self) -> V {
        let mut v = vec![V::Text(self.name().into())];
        match self {
            Self::Context { service, action } => v.extend([b(service), V::Uint(*action)]),
            Self::Register { registration } => v.push(b(&registration.envelope)),
            Self::Lookup { service, slot } => v.extend([b(service), V::Uint(*slot)]),
            Self::Admit { proof } | Self::Inspect { proof } => v.push(b(&proof.envelope)),
            Self::Permit { session } | Self::Close { session } => v.push(reference(session)),
            Self::Withdraw { service } => v.push(reference(service)),
        };
        a(v)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { service, .. } | Self::Lookup { service, .. } => *service,
            Self::Register { registration } => registration.id,
            Self::Admit { proof } | Self::Inspect { proof } => proof.service.id,
            Self::Permit { session } | Self::Close { session } => session.id,
            Self::Withdraw { service } => service.id,
        }
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Register { .. } | Self::Admit { .. } | Self::Close { .. } | Self::Withdraw { .. }
        )
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Register { .. } | Self::Withdraw { .. } => Some(172),
            Self::Admit { .. } | Self::Close { .. } => Some(173),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Domains/AuthorityStreamsOfferTests.rs"]
mod offer_tests;

#[cfg(test)]
include!("../../../Tests/Support/Authority/Domains/AuthorityStreams.rs");
