// SPDX-License-Identifier: MIT
// Finite recipient commands retain signed owner evidence before ordered admission.
use super::*;
#[derive(Clone, Debug)]
pub enum Command {
    Directory {
        member: Digest,
        view: Option<Digest>,
        after: Option<(u64, Digest)>,
    },
    Context {
        kind: u64,
        lookup: Digest,
    },
    Root {
        root: Record,
        acceptance: Vec<u8>,
        custody: Vec<u8>,
        recovery: Option<Vec<u8>>,
    },
    Device {
        binding: Record,
        admission: Box<Record>,
        challenge: Vec<u8>,
        possession: Vec<u8>,
        delegate: Option<VersionRef>,
    },
    Audience {
        audience: Record,
        acceptances: Vec<Vec<u8>>,
    },
    Freeze {
        roster: Record,
        scope: (u64, Digest),
    },
    Revoke {
        revocation: Record,
    },
}
impl Command {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let list = value.list(6)?;
        let name = list.first().context("empty recipient command")?.text()?;
        let rec = |v: &V, kind| -> Result<Record> {
            let r = signed_record(v.bytes()?, n, i)?;
            ensure!(r.reference.kind == kind, "recipient command record differs");
            Ok(r)
        };
        Ok(match name {
            "SealedIdentityDirectory" => {
                let f = value.array(4)?;
                let view = if f[2] == V::Null {
                    None
                } else {
                    Some(id(&f[2])?)
                };
                let after = if f[3] == V::Null {
                    None
                } else {
                    let p = f[3].array(2)?;
                    let kind = p[0].uint()?;
                    ensure!(
                        matches!(kind, 107..=109 | 158),
                        "invalid recipient directory cursor"
                    );
                    Some((kind, id(&p[1])?))
                };
                ensure!(
                    view.is_some() == after.is_some(),
                    "incomplete recipient directory cursor"
                );
                Self::Directory {
                    member: id(&f[1])?,
                    view,
                    after,
                }
            }
            "SealedIdentityContext" => {
                let f = value.array(3)?;
                let kind = f[1].uint()?;
                ensure!(persistent_kind(kind), "invalid recipient context kind");
                Self::Context {
                    kind,
                    lookup: id(&f[2])?,
                }
            }
            "SealedIdentityRoot" => {
                let f = value.array(5)?;
                Self::Root {
                    root: rec(&f[1], 107)?,
                    acceptance: f[2].bytes()?.to_vec(),
                    custody: f[3].bytes()?.to_vec(),
                    recovery: if f[4] == V::Null {
                        None
                    } else {
                        Some(f[4].bytes()?.to_vec())
                    },
                }
            }
            "SealedIdentityDevice" => {
                let f = value.array(6)?;
                Self::Device {
                    binding: rec(&f[1], 108)?,
                    admission: Box::new(rec(&f[2], 109)?),
                    challenge: f[3].bytes()?.to_vec(),
                    possession: f[4].bytes()?.to_vec(),
                    delegate: if f[5] == V::Null {
                        None
                    } else {
                        Some(typed_ref(&f[5], 108)?)
                    },
                }
            }
            "SealedIdentityAudience" => {
                let f = value.array(3)?;
                Self::Audience {
                    audience: rec(&f[1], 110)?,
                    acceptances: f[2]
                        .list(256)?
                        .iter()
                        .map(|v| Ok(v.bytes()?.to_vec()))
                        .collect::<Result<Vec<_>>>()?,
                }
            }
            "SealedIdentityFreeze" => {
                let f = value.array(4)?;
                let scope = (f[2].uint()?, id(&f[3])?);
                ensure!(
                    matches!(scope.0, 1 | 2),
                    "recipient roster requires namespace or object scope"
                );
                Self::Freeze {
                    roster: rec(&f[1], 111)?,
                    scope,
                }
            }
            "SealedIdentityRevoke" => {
                let f = value.array(2)?;
                Self::Revoke {
                    revocation: rec(&f[1], 158)?,
                }
            }
            _ => anyhow::bail!("unsupported recipient command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Directory { .. } => "SealedIdentityDirectory",
            Self::Context { .. } => "SealedIdentityContext",
            Self::Root { .. } => "SealedIdentityRoot",
            Self::Device { .. } => "SealedIdentityDevice",
            Self::Audience { .. } => "SealedIdentityAudience",
            Self::Freeze { .. } => "SealedIdentityFreeze",
            Self::Revoke { .. } => "SealedIdentityRevoke",
        }
    }
    pub fn value(&self) -> V {
        let mut v = vec![V::Text(self.name().into())];
        v.extend(match self {
            Self::Directory {
                member,
                view,
                after,
            } => vec![
                b(member),
                view.as_ref().map_or(V::Null, |v| b(v)),
                after
                    .as_ref()
                    .map_or(V::Null, |(k, id)| a(vec![V::Uint(*k), b(id)])),
            ],
            Self::Context { kind, lookup } => vec![V::Uint(*kind), b(lookup)],
            Self::Root {
                root,
                acceptance,
                custody,
                recovery,
            } => vec![
                b(&root.bytes),
                b(acceptance),
                b(custody),
                recovery.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::Device {
                binding,
                admission,
                challenge,
                possession,
                delegate,
            } => vec![
                b(&binding.bytes),
                b(&admission.bytes),
                b(challenge),
                b(possession),
                delegate.as_ref().map_or(V::Null, reference),
            ],
            Self::Audience {
                audience,
                acceptances,
            } => vec![
                b(&audience.bytes),
                a(acceptances.iter().map(|v| b(v)).collect()),
            ],
            Self::Freeze { roster, scope } => vec![b(&roster.bytes), V::Uint(scope.0), b(&scope.1)],
            Self::Revoke { revocation } => vec![b(&revocation.bytes)],
        });
        a(v)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Directory { member, .. } => *member,
            Self::Context { lookup, .. } => *lookup,
            Self::Root { root, .. } => root.reference.id,
            Self::Device { binding, .. } => binding.reference.id,
            Self::Audience { audience, .. } => audience.reference.id,
            Self::Freeze { roster, .. } => roster.reference.id,
            Self::Revoke { revocation } => revocation.reference.id,
        }
    }
    pub fn mutation(&self) -> bool {
        !matches!(self, Self::Context { .. } | Self::Directory { .. })
    }
    pub fn mutation_indices(&self) -> Vec<(u64, Digest)> {
        match self {
            Self::Directory { .. } => vec![],
            Self::Context { .. } => vec![],
            Self::Root { root, .. } => vec![root.reference.index()],
            Self::Device {
                binding, admission, ..
            } => vec![binding.reference.index(), admission.reference.index()],
            Self::Audience { audience, .. } => vec![audience.reference.index()],
            Self::Freeze { roster, .. } => vec![roster.reference.index()],
            Self::Revoke { revocation } => vec![revocation.reference.index()],
        }
    }
}
