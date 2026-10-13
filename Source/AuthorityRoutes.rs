// SPDX-License-Identifier: MIT
// Certified routes bind exact consent, separate possession keys and finite connection budgets.
use super::*;
use crate::authority_membership::Acceptance;
use crate::route_profile::{Assurance, Identity, Limits};
use std::net::SocketAddr;

#[path = "AuthorityRoutesEvaluation.rs"]
mod evaluation;
pub use evaluation::evaluate;

#[cfg(test)]
#[path = "AuthorityRoutesTests.rs"]
mod tests;

#[derive(Clone, Debug)]
pub struct RegisteredProfile {
    pub manifest: crate::runtime_manifest::Manifest,
    pub deployment: Digest,
    pub service: Key,
    pub operator: Key,
    pub deployment_profile: VersionRef,
    pub consent: VersionRef,
    pub endpoint: Digest,
    pub identity: Identity,
    pub address: Option<SocketAddr>,
    pub domain: String,
    pub protocol: u64,
    pub mode: u64,
    pub relay: Option<Digest>,
    pub limits: Limits,
    pub maximum_connections: u64,
    pub assurance: Assurance,
    pub validity: (u64, u64),
    pub envelope: Vec<u8>,
}
fn identity(value: &V) -> Result<Identity> {
    let f = value.array(5)?;
    let identity = Identity {
        service: id(&f[0])?,
        server_name: label(&f[1], 253)?,
        transport_key: key(&f[2])?,
        leaf_der: f[3].bytes()?.to_vec(),
        certificate_authority_pem: f[4].text()?.into(),
    };
    identity.validate()?;
    Ok(identity)
}
#[cfg(test)]
fn identity_value(i: &Identity) -> V {
    a(vec![
        b(&i.service),
        V::Text(i.server_name.clone()),
        b(&i.transport_key),
        b(&i.leaf_der),
        V::Text(i.certificate_authority_pem.clone()),
    ])
}
fn limits(value: &V) -> Result<Limits> {
    let f = value.array(3)?;
    let limits = Limits {
        bytes: f[0].uint()?,
        duration_ms: f[1].uint()?,
        idle_ms: f[2].uint()?,
    };
    limits.validate()?;
    Ok(limits)
}
#[cfg(test)]
fn limits_value(l: Limits) -> V {
    a(vec![
        V::Uint(l.bytes),
        V::Uint(l.duration_ms),
        V::Uint(l.idle_ms),
    ])
}
fn assurance(value: &V) -> Result<Assurance> {
    Ok(match value.uint()? {
        0 => Assurance::Organisation,
        1 => Assurance::Independent,
        _ => anyhow::bail!("unsupported relay assurance"),
    })
}
impl RegisteredProfile {
    pub fn parse(envelope: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(envelope.len() <= 32768, "route profile exceeds its bound");
        let (payload, signatures) = wire::envelope(envelope, 1)?;
        let v = wire::decode(&payload)?;
        let f = v.array(22)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityRouteProfile"
                && id(&f[3])? == network
                && id(&f[4])? == incarnation,
            "route profile context differs"
        );
        let span = f[20].array(2)?;
        let p = Self {
            manifest: crate::runtime_manifest::Manifest::parse(f[21].bytes()?)?,
            deployment: id(&f[5])?,
            service: key(&f[6])?,
            operator: key(&f[7])?,
            deployment_profile: version(&f[8])?,
            consent: version(&f[9])?,
            endpoint: id(&f[10])?,
            identity: identity(&f[11])?,
            address: if f[12] == V::Null {
                None
            } else {
                Some(f[12].text()?.parse()?)
            },
            domain: label(&f[13], 255)?,
            protocol: f[14].uint()?,
            mode: f[15].uint()?,
            relay: if f[16] == V::Null {
                None
            } else {
                Some(id(&f[16])?)
            },
            limits: limits(&f[17])?,
            maximum_connections: f[18].uint()?,
            assurance: assurance(&f[19])?,
            validity: (span[0].uint()?, span[1].uint()?),
            envelope: envelope.to_vec(),
        };
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == p.operator
                && p.service != p.operator
                && p.identity.transport_key != p.service
                && p.identity.transport_key != p.operator
                && p.deployment_profile.kind == 117
                && p.consent.kind == 105
                && p.deployment_profile.id == p.deployment
                && p.consent.id == p.deployment
                && p.validity.0 < p.validity.1
                && (1..=4096).contains(&p.maximum_connections)
                && matches!((p.mode, p.protocol), (1, 0) | (2 | 3, 1..=6))
                && (p.mode == 3) == p.relay.is_some()
                && (p.mode != 3) == p.address.is_some()
                && p.relay != Some(p.identity.service),
            "route profile identities or bounds differ"
        );
        let own = p
            .manifest
            .endpoints
            .iter()
            .find(|e| e.endpoint_id == p.endpoint)
            .context("route endpoint absent from exact manifest")?;
        let role = p
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 5)
            .context("route manifest lacks its dedicated role")?;
        ensure!(
            p.manifest.network == network
                && p.manifest.incarnation == incarnation
                && p.manifest.deployment == p.deployment
                && p.manifest.operator == p.operator
                && role.service_key == p.service
                && role.bind_endpoint_ids == [p.endpoint]
                && own.service_key == p.service
                && own.transport_key == p.identity.transport_key
                && own.leaf_der == p.identity.leaf_der
                && (p.mode == 3 || p.address == Some(SocketAddr::new(own.address, own.port)))
                && p.deployment_profile.generation == 1
                && p.consent.generation == 1
                && p.deployment_profile.digest == wire::digest(&p.manifest.desired()?)
                && p.consent.digest == wire::digest(&p.manifest.unsigned_consent(0)?)
                && p.validity.0 >= p.manifest.validity.0
                && p.validity.1 <= p.manifest.validity.1,
            "route profile differs from the exact consented manifest endpoint"
        );
        crate::trust_bootstrap::hex32(&p.domain)?;
        if let Some(address) = p.address {
            ensure!(
                address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast()
                    && !matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast()),
                "route requires a fixed unicast address"
            );
        }
        Ok(p)
    }
    #[cfg(test)]
    pub fn payload(&self, network: Digest, incarnation: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityRouteProfile".into()),
            b(&network),
            b(&incarnation),
            b(&self.deployment),
            b(&self.service),
            b(&self.operator),
            reference(&self.deployment_profile),
            reference(&self.consent),
            b(&self.endpoint),
            identity_value(&self.identity),
            self.address.map_or(V::Null, |a| V::Text(a.to_string())),
            V::Text(self.domain.clone()),
            V::Uint(self.protocol),
            V::Uint(self.mode),
            self.relay.as_ref().map_or(V::Null, |r| b(r)),
            limits_value(self.limits),
            V::Uint(self.maximum_connections),
            V::Uint(u64::from(self.assurance == Assurance::Independent)),
            a(vec![V::Uint(self.validity.0), V::Uint(self.validity.1)]),
            b(&self.manifest.encode()?),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Service {
    pub profile: RegisteredProfile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Service {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(4)?;
        let s = Self {
            profile: RegisteredProfile::parse(f[0].bytes()?, n, i)?,
            manager: key(&f[1])?,
            grant: version(&f[2])?,
            withdrawn: f[3].boolean()?,
        };
        ensure!(
            s.grant.kind == 102,
            "route management reference is not a capability"
        );
        Ok(s)
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
#[derive(Clone, Debug)]
pub struct Voucher {
    pub relay: VersionRef,
    pub destination: VersionRef,
    pub sponsor: Key,
    pub grant: VersionRef,
    pub possession: Key,
    pub action: u64,
    pub scope: (u64, Digest),
    pub connections: u64,
    pub bytes: u64,
    pub expires: u64,
    pub creation: Digest,
}
impl Voucher {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(11)?;
        let scope = f[6].array(2)?;
        let v = Self {
            relay: version(&f[0])?,
            destination: version(&f[1])?,
            sponsor: key(&f[2])?,
            grant: version(&f[3])?,
            possession: key(&f[4])?,
            action: f[5].uint()?,
            scope: (scope[0].uint()?, id(&scope[1])?),
            connections: f[7].uint()?,
            bytes: f[8].uint()?,
            expires: f[9].uint()?,
            creation: id(&f[10])?,
        };
        ensure!(
            v.relay.kind == 165
                && v.destination.kind == 165
                && v.relay.id != v.destination.id
                && v.grant.kind == 102
                && v.possession != v.sponsor
                && matches!(v.action, 0 | 1 | 10 | 15 | 16 | 18 | 19)
                && v.scope.0 <= 5
                && (1..=4096).contains(&v.connections)
                && (16384..=1024 * 1024 * 1024 * 1024).contains(&v.bytes)
                && v.expires > 0,
            "invalid route voucher"
        );
        Ok(v)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.relay),
            reference(&self.destination),
            b(&self.sponsor),
            reference(&self.grant),
            b(&self.possession),
            V::Uint(self.action),
            a(vec![V::Uint(self.scope.0), b(&self.scope.1)]),
            V::Uint(self.connections),
            V::Uint(self.bytes),
            V::Uint(self.expires),
            b(&self.creation),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Usage {
    pub connections: u64,
    pub bytes: u64,
    pub connection: Digest,
    pub transcript: Digest,
    pub creation: Digest,
}
impl Usage {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(5)?;
        Ok(Self {
            connections: f[0].uint()?,
            bytes: f[1].uint()?,
            connection: id(&f[2])?,
            transcript: id(&f[3])?,
            creation: id(&f[4])?,
        })
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(self.connections),
            V::Uint(self.bytes),
            b(&self.connection),
            b(&self.transcript),
            b(&self.creation),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Invitation {
    pub offer: Vec<u8>,
    pub grant: VersionRef,
    pub creation: Digest,
}
impl Invitation {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(3)?;
        Acceptance::parse(f[0].bytes()?, n, i, false)?;
        let out = Self {
            offer: f[0].bytes()?.to_vec(),
            grant: version(&f[1])?,
            creation: id(&f[2])?,
        };
        ensure!(out.grant.kind == 102, "invitation authority is not a grant");
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.offer),
            reference(&self.grant),
            b(&self.creation),
        ])
    }
}
pub fn validate_record(
    kind: u64,
    payload: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    match kind {
        165 => {
            let s = Service::parse(payload, n, i)?;
            ensure!(
                lookup == s.profile.identity.service && generation == 1 + u64::from(s.withdrawn),
                "route service lookup or generation differs"
            );
        }
        166 => {
            Voucher::parse(payload)?;
            ensure!(generation == 1, "route voucher cannot be rewritten");
        }
        167 => {
            let u = Usage::parse(payload)?;
            ensure!(
                u.connections == generation && u.bytes > 0,
                "route usage differs from its generation"
            );
        }
        168 => {
            let invitation = Invitation::parse(payload, n, i)?;
            let offer = Acceptance::parse(&invitation.offer, n, i, false)?;
            ensure!(
                generation == 1 && lookup == offer.member_id,
                "invitation lookup or generation differs"
            );
        }
        _ => anyhow::bail!("unsupported route metadata"),
    }
    Ok(())
}
pub fn requesters(state: &State) -> Result<Vec<Key>> {
    let mut keys = vec![];
    for r in state.records.values().filter(|r| r.reference.kind == 168) {
        let i = Invitation::parse(&r.payload, state.network, state.incarnation)?;
        keys.push(Acceptance::parse(&i.offer, state.network, state.incarnation, false)?.candidate);
    }
    Ok(keys)
}
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Context {
        action: u64,
        scope: (u64, Digest),
    },
    Register {
        profile: Box<RegisteredProfile>,
    },
    Lookup {
        service: Digest,
    },
    Withdraw {
        service: Digest,
        generation: u64,
    },
    Issue {
        id: Digest,
        relay: Digest,
        destination: Digest,
        possession: Key,
        action: u64,
        scope: (u64, Digest),
        connections: u64,
        bytes: u64,
        expires: u64,
    },
    Permit {
        voucher: VersionRef,
        connection: Digest,
        transcript: Digest,
    },
    VoucherContext {
        voucher: VersionRef,
    },
    Reader {
        envelope: Vec<u8>,
    },
    Invite {
        offer: Vec<u8>,
    },
    InviteContext {
        offer: Vec<u8>,
    },
    CandidateContext {
        accepted: Vec<u8>,
    },
}
impl Command {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.list(10)?;
        let name = f.first().context("empty route command")?.text()?;
        Ok(match name {
            "RouteContext" => {
                let f = value.array(3)?;
                let s = f[2].array(2)?;
                let action = f[1].uint()?;
                ensure!(
                    matches!(action, 0 | 1 | 6 | 10 | 13 | 15 | 16 | 18 | 19 | 26)
                        && s[0].uint()? <= 5,
                    "unsupported route context"
                );
                Self::Context {
                    action,
                    scope: (s[0].uint()?, id(&s[1])?),
                }
            }
            "RouteRegister" => {
                let f = value.array(2)?;
                Self::Register {
                    profile: Box::new(RegisteredProfile::parse(f[1].bytes()?, n, i)?),
                }
            }
            "RouteLookup" => {
                let f = value.array(2)?;
                Self::Lookup {
                    service: id(&f[1])?,
                }
            }
            "RouteWithdraw" => {
                let f = value.array(3)?;
                Self::Withdraw {
                    service: id(&f[1])?,
                    generation: f[2].uint()?,
                }
            }
            "RouteIssue" => {
                let f = value.array(9)?;
                let s = f[6].array(2)?;
                let budget = f[7].array(2)?;
                ensure!(
                    matches!(f[5].uint()?, 0 | 1 | 10 | 15 | 16 | 18 | 19) && s[0].uint()? <= 5,
                    "unsupported route capability"
                );
                Self::Issue {
                    id: id(&f[1])?,
                    relay: id(&f[2])?,
                    destination: id(&f[3])?,
                    possession: key(&f[4])?,
                    action: f[5].uint()?,
                    scope: (s[0].uint()?, id(&s[1])?),
                    connections: budget[0].uint()?,
                    bytes: budget[1].uint()?,
                    expires: f[8].uint()?,
                }
            }
            "RouteReaderPermit" => {
                let f = value.array(2)?;
                crate::authority_route_reader::Reader::parse(f[1].bytes()?, n, i)?;
                Self::Reader {
                    envelope: f[1].bytes()?.to_vec(),
                }
            }
            "RouteVoucherContext" => {
                let f = value.array(2)?;
                let voucher = version(&f[1])?;
                ensure!(
                    voucher.kind == 166,
                    "route context requires a voucher reference"
                );
                Self::VoucherContext { voucher }
            }
            "RoutePermit" => {
                let f = value.array(4)?;
                let voucher = version(&f[1])?;
                ensure!(
                    voucher.kind == 166,
                    "route permit requires a voucher reference"
                );
                Self::Permit {
                    voucher,
                    connection: id(&f[2])?,
                    transcript: id(&f[3])?,
                }
            }
            "RouteInviteContext" => {
                let f = value.array(2)?;
                Acceptance::parse(f[1].bytes()?, n, i, false)?;
                Self::InviteContext {
                    offer: f[1].bytes()?.to_vec(),
                }
            }
            "RouteInvite" => {
                let f = value.array(2)?;
                Acceptance::parse(f[1].bytes()?, n, i, false)?;
                Self::Invite {
                    offer: f[1].bytes()?.to_vec(),
                }
            }
            "RouteCandidateContext" => {
                let f = value.array(2)?;
                Acceptance::parse(f[1].bytes()?, n, i, true)?;
                Self::CandidateContext {
                    accepted: f[1].bytes()?.to_vec(),
                }
            }
            _ => anyhow::bail!("unsupported route command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "RouteContext",
            Self::Register { .. } => "RouteRegister",
            Self::Lookup { .. } => "RouteLookup",
            Self::Withdraw { .. } => "RouteWithdraw",
            Self::Issue { .. } => "RouteIssue",
            Self::Permit { .. } => "RoutePermit",
            Self::Reader { .. } => "RouteReaderPermit",
            Self::VoucherContext { .. } => "RouteVoucherContext",
            Self::InviteContext { .. } => "RouteInviteContext",
            Self::Invite { .. } => "RouteInvite",
            Self::CandidateContext { .. } => "RouteCandidateContext",
        }
    }
    pub fn mutation(&self) -> bool {
        !matches!(
            self,
            Self::Context { .. }
                | Self::Lookup { .. }
                | Self::CandidateContext { .. }
                | Self::VoucherContext { .. }
                | Self::Reader { .. }
                | Self::InviteContext { .. }
        )
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { scope, .. } => scope.1,
            Self::Register { profile } => profile.identity.service,
            Self::Lookup { service } | Self::Withdraw { service, .. } => *service,
            Self::Issue { id, .. } => *id,
            Self::Permit { voucher, .. } | Self::VoucherContext { voucher } => voucher.id,
            Self::Reader { envelope } => {
                let (p, _) = wire::envelope(envelope, 1).expect("validated reader envelope");
                wire::decode(&p)
                    .expect("validated reader payload")
                    .array(12)
                    .expect("validated reader fields")[5]
                    .fixed()
                    .expect("validated endpoint")
            }
            Self::Invite { offer }
            | Self::InviteContext { offer }
            | Self::CandidateContext { accepted: offer } => {
                let (p, _) = wire::envelope(offer, 2).expect("validated membership envelope");
                wire::decode(&p)
                    .expect("validated membership payload")
                    .array(12)
                    .expect("validated membership fields")[5]
                    .fixed()
                    .expect("validated member identity")
            }
        }
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Register { .. } | Self::Withdraw { .. } => Some(165),
            Self::Issue { .. } => Some(166),
            Self::Permit { .. } => Some(167),
            Self::Invite { .. } => Some(168),
            _ => None,
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        match self {
            Self::Context { action, scope } => {
                f.extend([V::Uint(*action), a(vec![V::Uint(scope.0), b(&scope.1)])])
            }
            Self::Register { profile } => f.push(b(&profile.envelope)),
            Self::Lookup { service } => f.push(b(service)),
            Self::Withdraw {
                service,
                generation,
            } => f.extend([b(service), V::Uint(*generation)]),
            Self::Issue {
                id,
                relay,
                destination,
                possession,
                action,
                scope,
                connections,
                bytes,
                expires,
            } => f.extend([
                b(id),
                b(relay),
                b(destination),
                b(possession),
                V::Uint(*action),
                a(vec![V::Uint(scope.0), b(&scope.1)]),
                a(vec![V::Uint(*connections), V::Uint(*bytes)]),
                V::Uint(*expires),
            ]),
            Self::Reader { envelope } => f.push(b(envelope)),
            Self::VoucherContext { voucher } => f.push(reference(voucher)),
            Self::Permit {
                voucher,
                connection,
                transcript,
            } => f.extend([reference(voucher), b(connection), b(transcript)]),
            Self::Invite { offer }
            | Self::InviteContext { offer }
            | Self::CandidateContext { accepted: offer } => f.push(b(offer)),
        }
        a(f)
    }
}
