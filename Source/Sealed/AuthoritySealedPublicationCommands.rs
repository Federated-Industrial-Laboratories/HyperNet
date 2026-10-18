// SPDX-License-Identifier: MIT
// Sealed commands carry signed policy and ciphertext metadata without private content.
use super::*;
use domains::{State, page::content};
#[derive(Clone, Debug)]
pub enum Command {
    Prepare {
        object: Digest,
        roster: VersionRef,
        author_grant: VersionRef,
        namespace: String,
    },
    Namespace {
        namespace: String,
        modes: Vec<u64>,
    },
    Policy {
        policy: Record,
    },
    Stage {
        outer: Record,
        policy: VersionRef,
        author_grant: VersionRef,
        namespace: String,
        failure_domains: u64,
        expires_ms: u64,
    },
    Commit {
        outer: VersionRef,
    },
    Read {
        outer: VersionRef,
        device: VersionRef,
    },
    Context {
        object: Digest,
    },
    ReaderContext {
        object: Digest,
        device: VersionRef,
    },
    Withdraw {
        outer: VersionRef,
    },
}
impl Command {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.list(7)?;
        Ok(match f.first().context("empty sealed command")?.text()? {
            "SealedPublicationNamespace" => {
                let f = value.array(3)?;
                let namespace = f[1].text()?.to_owned();
                ensure!(
                    crate::markup::namespace(&namespace),
                    "invalid publication namespace"
                );
                Self::Namespace {
                    namespace,
                    modes: domains::publication_modes::modes(&f[2])?,
                }
            }
            "SealedPublicationPrepare" => {
                let f = value.array(5)?;
                let namespace = f[4].text()?.to_owned();
                ensure!(
                    crate::markup::namespace(&namespace),
                    "invalid sealed namespace"
                );
                Self::Prepare {
                    object: id(&f[1])?,
                    roster: version(&f[2], 111)?,
                    author_grant: version(&f[3], 102)?,
                    namespace,
                }
            }
            "SealedPublicationPolicy" => {
                let f = value.array(2)?;
                let policy = signed_record(f[1].bytes()?, n, i)?;
                ensure!(policy.reference.kind == 104, "sealed policy kind differs");
                Self::Policy { policy }
            }
            "SealedPublicationStage" => {
                let f = value.array(7)?;
                let outer = signed_record(f[1].bytes()?, n, i)?;
                ensure!(outer.reference.kind == 113, "sealed outer kind differs");
                let namespace = f[4].text()?.to_owned();
                ensure!(
                    crate::markup::namespace(&namespace),
                    "sealed namespace differs"
                );
                Self::Stage {
                    outer,
                    policy: version(&f[2], 104)?,
                    author_grant: version(&f[3], 102)?,
                    namespace,
                    failure_domains: f[5].uint()?,
                    expires_ms: f[6].uint()?,
                }
            }
            "SealedPublicationCommit" => Self::Commit {
                outer: version(&value.array(2)?[1], 113)?,
            },
            "SealedPublicationRead" => {
                let f = value.array(3)?;
                Self::Read {
                    outer: version(&f[1], 113)?,
                    device: version(&f[2], 108)?,
                }
            }
            "SealedPublicationReaderContext" => {
                let f = value.array(3)?;
                Self::ReaderContext {
                    object: id(&f[1])?,
                    device: version(&f[2], 108)?,
                }
            }
            "SealedPublicationContext" => Self::Context {
                object: id(&value.array(2)?[1])?,
            },
            "SealedPublicationWithdraw" => Self::Withdraw {
                outer: version(&value.array(2)?[1], 113)?,
            },
            _ => anyhow::bail!("unknown sealed publication command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Prepare { .. } => "SealedPublicationPrepare",
            Self::Namespace { .. } => "SealedPublicationNamespace",
            Self::Policy { .. } => "SealedPublicationPolicy",
            Self::Stage { .. } => "SealedPublicationStage",
            Self::Commit { .. } => "SealedPublicationCommit",
            Self::Read { .. } => "SealedPublicationRead",
            Self::Context { .. } => "SealedPublicationContext",
            Self::ReaderContext { .. } => "SealedPublicationReaderContext",
            Self::Withdraw { .. } => "SealedPublicationWithdraw",
        }
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Namespace { namespace, .. } => {
                domains::page::namespace_id(namespace).unwrap_or([0; 32])
            }
            Self::Policy { policy } => policy.reference.id,
            Self::Stage { outer, .. } => outer.reference.id,
            Self::Commit { outer } | Self::Read { outer, .. } | Self::Withdraw { outer } => {
                outer.id
            }
            Self::Context { object }
            | Self::ReaderContext { object, .. }
            | Self::Prepare { object, .. } => *object,
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        f.extend(match self {
            Self::Namespace { namespace, modes } => vec![
                V::Text(namespace.clone()),
                a(modes.iter().map(|m| V::Uint(*m)).collect()),
            ],
            Self::Prepare {
                object,
                roster,
                author_grant,
                namespace,
            } => vec![
                b(object),
                reference(roster),
                reference(author_grant),
                V::Text(namespace.clone()),
            ],
            Self::Policy { policy } => vec![b(&policy.bytes)],
            Self::Stage {
                outer,
                policy,
                author_grant,
                namespace,
                failure_domains,
                expires_ms,
            } => vec![
                b(&outer.bytes),
                reference(policy),
                reference(author_grant),
                V::Text(namespace.clone()),
                V::Uint(*failure_domains),
                V::Uint(*expires_ms),
            ],
            Self::Commit { outer } | Self::Withdraw { outer } => vec![reference(outer)],
            Self::Read { outer, device } => vec![reference(outer), reference(device)],
            Self::Context { object } => vec![b(object)],
            Self::ReaderContext { object, device } => vec![b(object), reference(device)],
        });
        a(f)
    }
    pub fn mutation(&self) -> bool {
        !matches!(
            self,
            Self::Read { .. }
                | Self::Context { .. }
                | Self::ReaderContext { .. }
                | Self::Prepare { .. }
        )
    }
    pub fn mutation_indices(&self, state: &State) -> Result<Vec<(u64, Digest)>> {
        Ok(match self {
            Self::Namespace { namespace, .. } => {
                vec![(164, domains::page::namespace_id(namespace)?)]
            }
            Self::Policy { policy } => vec![policy.reference.index()],
            Self::Stage { outer, .. } => {
                let o = Outer::parse(&outer.bytes, state.network, state.incarnation)?;
                let p = placement_identity(&o)?;
                vec![
                    (113, o.publication),
                    (PUBLICATION_STATE, o.publication),
                    (OBJECT_HEAD, o.object),
                    (content::PLACEMENT_KIND, p),
                ]
            }
            Self::Commit { outer } | Self::Withdraw { outer } => {
                let r = state.record(113, outer.id)?;
                let o = Outer::parse(&r.bytes, state.network, state.incarnation)?;
                let mut indices = vec![(PUBLICATION_STATE, o.publication), (OBJECT_HEAD, o.object)];
                let target = if matches!(self, Self::Withdraw { .. }) {
                    Some(outer.clone())
                } else {
                    PublicationState::parse(
                        &state.record(PUBLICATION_STATE, o.publication)?.payload,
                    )?
                    .supersedes
                };
                if let Some(target) =
                    target.filter(|r| matches!(self, Self::Withdraw { .. }) || *r != *outer)
                {
                    let prior = PublicationState::parse(
                        &state.record(PUBLICATION_STATE, target.id)?.payload,
                    )?;
                    indices.push((PUBLICATION_STATE, target.id));
                    indices.push((content::TOMBSTONE_KIND, prior.placement.id));
                }
                indices.sort();
                indices.dedup();
                indices
            }
            _ => vec![],
        })
    }
}
pub fn placement_identity(o: &Outer) -> Result<Digest> {
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("PageContentPlacement".into()),
        reference(&o.reference),
        b(&o.ciphertext),
    ]))?))
}
