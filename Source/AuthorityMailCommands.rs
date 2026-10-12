// SPDX-License-Identifier: MIT
// Mail effects name a user-selected mailbox store, never an unconstrained destination.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Put,
    Fetch,
    List,
    Delete,
}
impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Self::Put => "Put",
            Self::Fetch => "Fetch",
            Self::List => "List",
            Self::Delete => "Delete",
        }
    }
    pub fn parse(v: &V) -> Result<Self> {
        Ok(match v.text()? {
            "Put" => Self::Put,
            "Fetch" => Self::Fetch,
            "List" => Self::List,
            "Delete" => Self::Delete,
            _ => anyhow::bail!("unsupported mail effect"),
        })
    }
}
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "One bounded decoded command owns its validated profile; variants are not retained in bulk."
)]
pub enum Command {
    Context {
        action: u64,
        scope_kind: u64,
        resource: Digest,
    },
    Register {
        profile: Profile,
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
        after: Option<Digest>,
    },
    Publish {
        publication: objects::Publication,
        private: bool,
    },
    Get {
        address: Digest,
        source: Option<Digest>,
    },
    Package {
        address: Digest,
        package: objects::Package,
    },
    Inventory {
        address: Digest,
        source: Option<Digest>,
        after: Option<Digest>,
    },
    Claim {
        id: Digest,
        sender: Digest,
        recipient: Digest,
        packages: Vec<VersionRef>,
        expires: u64,
    },
    ClaimGet {
        id: Digest,
    },
    Bind {
        id: Digest,
        bytes: u64,
        digest: Digest,
    },
    Execute {
        address: Digest,
        service: Key,
        effect: Effect,
        message: Option<Digest>,
        claim: Option<Digest>,
        bytes: u64,
        digest: Option<Digest>,
        after: Option<Digest>,
    },
}
fn optional(v: &V) -> Result<Option<Digest>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}
impl Command {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.list(10)?;
        let name = f.first().context("empty mail command")?.text()?;
        Ok(match name {
            "MailContext" => {
                let f = v.array(4)?;
                let action = f[1].uint()?;
                let scope_kind = f[2].uint()?;
                let resource = id(&f[3])?;
                ensure!(
                    matches!((action, scope_kind), (14..=16, 0 | 2 | 3) | (26, 5))
                        && (scope_kind != 0 || resource == n),
                    "invalid mail capability context"
                );
                Self::Context {
                    action,
                    scope_kind,
                    resource,
                }
            }
            "MailServiceRegister" => {
                let f = v.array(2)?;
                Self::Register {
                    profile: Profile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "MailServiceWithdraw" => {
                let f = v.array(3)?;
                Self::Withdraw {
                    service: key(&f[1])?,
                    generation: f[2].uint()?,
                }
            }
            "MailServiceGet" => {
                let f = v.array(2)?;
                Self::Service {
                    service: key(&f[1])?,
                }
            }
            "MailServices" => {
                let f = v.array(3)?;
                ensure!(id(&f[1])? == n, "mail network differs");
                Self::Services {
                    network: n,
                    after: optional(&f[2])?,
                }
            }
            "MailPublish" => {
                let f = v.array(3)?;
                Self::Publish {
                    publication: objects::Publication::parse(f[1].bytes()?, n)?,
                    private: f[2].boolean()?,
                }
            }
            "MailGet" => {
                let f = v.array(3)?;
                Self::Get {
                    address: id(&f[1])?,
                    source: optional(&f[2])?,
                }
            }
            "MailPackage" => {
                let f = v.array(3)?;
                Self::Package {
                    address: id(&f[1])?,
                    package: objects::Package::parse(f[2].bytes()?)?,
                }
            }
            "MailInventory" => {
                let f = v.array(4)?;
                Self::Inventory {
                    address: id(&f[1])?,
                    source: optional(&f[2])?,
                    after: optional(&f[3])?,
                }
            }
            "MailClaim" => {
                let f = v.array(6)?;
                let packages = f[4]
                    .list(8)?
                    .iter()
                    .map(version)
                    .collect::<Result<Vec<_>>>()?;
                validate_versions(&packages, 8)?;
                ensure!(
                    !packages.is_empty() && packages.iter().all(|p| p.kind == 138),
                    "invalid mail claim packages"
                );
                Self::Claim {
                    id: id(&f[1])?,
                    sender: id(&f[2])?,
                    recipient: id(&f[3])?,
                    packages,
                    expires: f[5].uint()?,
                }
            }
            "MailBind" => {
                let f = v.array(4)?;
                let bytes = f[2].uint()?;
                ensure!(
                    (1..=MAXIMUM_PAYLOAD).contains(&bytes),
                    "mail payload exceeds bound"
                );
                Self::Bind {
                    id: id(&f[1])?,
                    bytes,
                    digest: id(&f[3])?,
                }
            }
            "MailClaimGet" => {
                let f = v.array(2)?;
                Self::ClaimGet { id: id(&f[1])? }
            }
            "MailExecute" => {
                let f = v.array(9)?;
                let effect = Effect::parse(&f[3])?;
                let message = optional(&f[4])?;
                let claim = optional(&f[5])?;
                let bytes = f[6].uint()?;
                let digest = optional(&f[7])?;
                let after = optional(&f[8])?;
                ensure!(
                    match effect {
                        Effect::Put =>
                            message.is_some()
                                && claim.is_some()
                                && (1..=MAXIMUM_PAYLOAD).contains(&bytes)
                                && digest.is_some()
                                && after.is_none(),
                        Effect::List =>
                            message.is_none() && claim.is_none() && bytes == 0 && digest.is_none(),
                        _ =>
                            message.is_some()
                                && claim.is_none()
                                && bytes == 0
                                && digest.is_none()
                                && after.is_none(),
                    },
                    "invalid mail effect fields"
                );
                Self::Execute {
                    address: id(&f[1])?,
                    service: key(&f[2])?,
                    effect,
                    message,
                    claim,
                    bytes,
                    digest,
                    after,
                }
            }
            _ => anyhow::bail!("unsupported mail command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "MailContext",
            Self::Register { .. } => "MailServiceRegister",
            Self::Withdraw { .. } => "MailServiceWithdraw",
            Self::Service { .. } => "MailServiceGet",
            Self::Services { .. } => "MailServices",
            Self::Publish { .. } => "MailPublish",
            Self::Get { .. } => "MailGet",
            Self::Package { .. } => "MailPackage",
            Self::Inventory { .. } => "MailInventory",
            Self::Claim { .. } => "MailClaim",
            Self::ClaimGet { .. } => "MailClaimGet",
            Self::Bind { .. } => "MailBind",
            Self::Execute { .. } => "MailExecute",
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        let opt = |v: &Option<Digest>| v.as_ref().map_or(V::Null, |d| b(d));
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
            Self::Services { network, after } => f.extend([b(network), opt(after)]),
            Self::Publish {
                publication,
                private,
            } => f.extend([b(&publication.bytes), V::Bool(*private)]),
            Self::Get { address, source } => f.extend([b(address), opt(source)]),
            Self::Package { address, package } => f.extend([
                b(address),
                b(&serde_json::to_vec(package).expect("finite package")),
            ]),
            Self::Inventory {
                address,
                source,
                after,
            } => f.extend([b(address), opt(source), opt(after)]),
            Self::Claim {
                id,
                sender,
                recipient,
                packages,
                expires,
            } => f.extend([
                b(id),
                b(sender),
                b(recipient),
                a(packages.iter().map(reference).collect()),
                V::Uint(*expires),
            ]),
            Self::ClaimGet { id } => f.push(b(id)),
            Self::Bind { id, bytes, digest } => f.extend([b(id), V::Uint(*bytes), b(digest)]),
            Self::Execute {
                address,
                service,
                effect,
                message,
                claim,
                bytes,
                digest,
                after,
            } => f.extend([
                b(address),
                b(service),
                V::Text(effect.name().into()),
                opt(message),
                opt(claim),
                V::Uint(*bytes),
                opt(digest),
                opt(after),
            ]),
        }
        a(f)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { resource, .. } => *resource,
            Self::Register { profile } => profile.service,
            Self::Withdraw { service, .. } | Self::Service { service } => *service,
            Self::Services { network, .. } => *network,
            Self::Publish { publication, .. } => publication.id().expect("validated publication"),
            Self::Get { address, .. }
            | Self::Package { address, .. }
            | Self::Inventory { address, .. }
            | Self::Execute { address, .. } => *address,
            Self::Claim { id, .. } | Self::ClaimGet { id } | Self::Bind { id, .. } => *id,
        }
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Register { .. } | Self::Withdraw { .. } => Some(136),
            Self::Publish { .. } => Some(137),
            Self::Package { .. } => Some(138),
            Self::Claim { .. } | Self::Bind { .. } => Some(139),
            _ => None,
        }
    }
    pub fn mutation(&self) -> bool {
        self.mutation_kind().is_some()
    }
}
