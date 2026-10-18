// SPDX-License-Identifier: MIT
// Transfer control and serving commands have fixed fields and no caller-selected serving identity.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Put,
    Commit,
    Fetch,
    Status,
    Delete,
}
impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Self::Put => "Put",
            Self::Commit => "Commit",
            Self::Fetch => "Fetch",
            Self::Status => "Status",
            Self::Delete => "Delete",
        }
    }
    pub fn parse(value: &V) -> Result<Self> {
        Ok(match value.text()? {
            "Put" => Self::Put,
            "Commit" => Self::Commit,
            "Fetch" => Self::Fetch,
            "Status" => Self::Status,
            "Delete" => Self::Delete,
            _ => anyhow::bail!("unsupported transfer effect"),
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
        action: u64,
    },
    Services {
        network: Digest,
        action: u64,
        after: Option<Key>,
    },
    Offer {
        offer: Offer,
    },
    Get {
        id: Digest,
    },
    List {
        network: Digest,
        action: u64,
        after: Option<Digest>,
    },
    Accept {
        id: Digest,
        service: Key,
        destination: String,
        expires: u64,
    },
    Cancel {
        id: Digest,
    },
    Execute {
        id: Digest,
        effect: Effect,
        offset: u64,
        bytes: u64,
        digest: Option<Digest>,
    },
}
fn cursor(v: &V) -> Result<Option<Digest>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}
fn access(v: &V) -> Result<u64> {
    let action = v.uint()?;
    ensure!(
        matches!(action, 18 | 19),
        "invalid transfer capability action"
    );
    Ok(action)
}
impl Command {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let fields = v.list(7)?;
        let name = fields.first().context("empty transfer command")?.text()?;
        Ok(match name {
            "TransferContext" => {
                let f = v.array(4)?;
                let action = f[1].uint()?;
                let scope_kind = f[2].uint()?;
                let resource = id(&f[3])?;
                ensure!(
                    matches!((action, scope_kind), (18 | 19, 0 | 2 | 3) | (26, 5))
                        && (scope_kind != 0 || resource == n),
                    "invalid transfer context scope"
                );
                Self::Context {
                    action,
                    scope_kind,
                    resource,
                }
            }
            "TransferServiceRegister" => {
                let f = v.array(2)?;
                Self::Register {
                    profile: Profile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "TransferServiceWithdraw" => {
                let f = v.array(3)?;
                Self::Withdraw {
                    service: key(&f[1])?,
                    generation: f[2].uint()?,
                }
            }
            "TransferServiceGet" => {
                let f = v.array(3)?;
                Self::Service {
                    service: key(&f[1])?,
                    action: access(&f[2])?,
                }
            }
            "TransferServices" | "TransferList" => {
                let f = v.array(4)?;
                ensure!(id(&f[1])? == n, "transfer listing network differs");
                let action = access(&f[2])?;
                let after = cursor(&f[3])?;
                if name == "TransferServices" {
                    Self::Services {
                        network: n,
                        action,
                        after,
                    }
                } else {
                    Self::List {
                        network: n,
                        action,
                        after,
                    }
                }
            }
            "TransferOffer" => {
                let f = v.array(2)?;
                Self::Offer {
                    offer: Offer::parse(f[1].bytes()?, n, i)?,
                }
            }
            "TransferGet" | "TransferCancel" => {
                let f = v.array(2)?;
                let id = id(&f[1])?;
                if name == "TransferGet" {
                    Self::Get { id }
                } else {
                    Self::Cancel { id }
                }
            }
            "TransferAccept" => {
                let f = v.array(5)?;
                Self::Accept {
                    id: id(&f[1])?,
                    service: key(&f[2])?,
                    destination: label(&f[3], 64)?,
                    expires: f[4].uint()?,
                }
            }
            "TransferExecute" => {
                let f = v.array(6)?;
                let effect = Effect::parse(&f[2])?;
                let offset = f[3].uint()?;
                let bytes = f[4].uint()?;
                let digest = cursor(&f[5])?;
                ensure!(
                    match effect {
                        Effect::Put => (1..=CHUNK).contains(&bytes) && digest.is_some(),
                        Effect::Fetch => (1..=CHUNK).contains(&bytes) && digest.is_none(),
                        _ => offset == 0 && bytes == 0 && digest.is_none(),
                    },
                    "transfer effect range or digest differs"
                );
                Self::Execute {
                    id: id(&f[1])?,
                    effect,
                    offset,
                    bytes,
                    digest,
                }
            }
            _ => anyhow::bail!("unsupported transfer command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "TransferContext",
            Self::Register { .. } => "TransferServiceRegister",
            Self::Withdraw { .. } => "TransferServiceWithdraw",
            Self::Service { .. } => "TransferServiceGet",
            Self::Services { .. } => "TransferServices",
            Self::Offer { .. } => "TransferOffer",
            Self::Get { .. } => "TransferGet",
            Self::List { .. } => "TransferList",
            Self::Accept { .. } => "TransferAccept",
            Self::Cancel { .. } => "TransferCancel",
            Self::Execute { .. } => "TransferExecute",
        }
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Register { .. }
                | Self::Withdraw { .. }
                | Self::Offer { .. }
                | Self::Accept { .. }
                | Self::Cancel { .. }
        )
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Register { .. } | Self::Withdraw { .. } => Some(134),
            Self::Offer { .. } | Self::Accept { .. } | Self::Cancel { .. } => Some(135),
            _ => None,
        }
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { resource, .. } => *resource,
            Self::Register { profile } => profile.service,
            Self::Withdraw { service, .. } | Self::Service { service, .. } => *service,
            Self::Services { network, .. } | Self::List { network, .. } => *network,
            Self::Offer { offer } => offer.id,
            Self::Get { id }
            | Self::Accept { id, .. }
            | Self::Cancel { id }
            | Self::Execute { id, .. } => *id,
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
            Self::Service { service, action } => f.extend([b(service), V::Uint(*action)]),
            Self::Services {
                network,
                action,
                after,
            }
            | Self::List {
                network,
                action,
                after,
            } => f.extend([
                b(network),
                V::Uint(*action),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ]),
            Self::Offer { offer } => f.push(b(&offer.envelope)),
            Self::Get { id } | Self::Cancel { id } => f.push(b(id)),
            Self::Accept {
                id,
                service,
                destination,
                expires,
            } => f.extend([
                b(id),
                b(service),
                V::Text(destination.clone()),
                V::Uint(*expires),
            ]),
            Self::Execute {
                id,
                effect,
                offset,
                bytes,
                digest,
            } => f.extend([
                b(id),
                V::Text(effect.name().into()),
                V::Uint(*offset),
                V::Uint(*bytes),
                digest.as_ref().map_or(V::Null, |v| b(v)),
            ]),
        }
        a(f)
    }
}
