// SPDX-License-Identifier: MIT
// Tier changes are typed proposals with exact predecessor and reviewed dependency binding.
use crate::{
    authority_membership::{Snapshot, reference},
    authority_proof::{Digest, Intent, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
pub const IMPACT_PAGE: usize = 128;
pub const MAX_IMPACTS: usize = 65536;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let id = v.fixed()?;
    ensure!(id != [0; 32], "zero tier identifier");
    Ok(id)
}
#[derive(Clone, Debug)]
pub struct Spec {
    pub id: Digest,
    pub rank: u64,
    pub label: String,
    pub actions: Vec<u64>,
    pub scopes: Vec<(u64, Digest)>,
    pub depth: u64,
    pub limits: [u64; 4],
}
impl Spec {
    pub fn parse(v: &V, network: Digest) -> Result<Self> {
        let f = v.array(7)?;
        let actions = f[3]
            .list(32)?
            .iter()
            .map(V::uint)
            .collect::<Result<Vec<_>>>()?;
        let scopes = f[4]
            .list(64)?
            .iter()
            .map(|v| {
                let f = v.array(2)?;
                Ok((f[0].uint()?, id(&f[1])?))
            })
            .collect::<Result<Vec<_>>>()?;
        let l = f[6].array(4)?;
        let spec = Self {
            id: id(&f[0])?,
            rank: f[1].uint()?,
            label: f[2].text()?.into(),
            actions,
            scopes,
            depth: f[5].uint()?,
            limits: [l[0].uint()?, l[1].uint()?, l[2].uint()?, l[3].uint()?],
        };
        ensure!(
            spec.rank <= 65535
                && spec.depth <= 8
                && (1..=128).contains(&spec.label.len())
                && !spec
                    .label
                    .chars()
                    .any(|c| c.is_control() || matches!(c as u32,0x202a..=0x202e|0x2066..=0x2069)),
            "tier label, rank or depth differs"
        );
        ensure!(
            !spec.actions.is_empty()
                && spec.actions.iter().all(|v| *v < 32)
                && spec.actions.windows(2).all(|p| p[0] < p[1])
                && !spec.scopes.is_empty()
                && spec.scopes.windows(2).all(|p| p[0] < p[1])
                && spec
                    .scopes
                    .iter()
                    .all(|s| s.0 <= 5 && (s.0 != 0 || s.1 == network)),
            "invalid tier action or scope set"
        );
        Ok(spec)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.id),
            V::Uint(self.rank),
            V::Text(self.label.clone()),
            a(self.actions.iter().copied().map(V::Uint).collect()),
            a(self
                .scopes
                .iter()
                .map(|(k, id)| a(vec![V::Uint(*k), b(id)]))
                .collect()),
            V::Uint(self.depth),
            a(self.limits.iter().copied().map(V::Uint).collect()),
        ])
    }
    pub fn from_record(
        bytes: &[u8],
        network: Digest,
        incarnation: Digest,
    ) -> Result<(Self, VersionRef)> {
        let v = wire::decode(bytes)?;
        let f = v.array(14)?;
        ensure!(
            f[0].uint()? == 101
                && f[1].uint()? == 1
                && f[2].fixed::<32>()? == network
                && f[3].fixed::<32>()? == incarnation
                && f[4].uint()? > 0,
            "tier record context differs"
        );
        if f[4].uint()? == 1 {
            f[5].null()?;
        } else {
            id(&f[5])?;
        }
        let spec = Self::parse(&a(f[6..13].to_vec()), network)?;
        if f[13] != V::Null {
            Snapshot::parse(&f[13])?;
        }
        let r = VersionRef {
            kind: 101,
            id: spec.id,
            generation: f[4].uint()?,
            digest: wire::digest(bytes),
        };
        Ok((spec, r))
    }
}
#[derive(Clone, Debug)]
pub enum Operation {
    Context {
        grant: Digest,
        tier: Option<Digest>,
        point: Snapshot,
    },
    List {
        grant: Digest,
        after: Option<Digest>,
        point: Snapshot,
    },
    Change {
        grant: Digest,
        previous: Option<Vec<u8>>,
        spec: Spec,
        snapshot: Snapshot,
        token: Option<Digest>,
        apply: bool,
    },
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        matches!(
            action,
            "AuthorityTierContext"
                | "AuthorityTierList"
                | "AuthorityTierPreview"
                | "AuthorityTierApply"
        )
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        let v = wire::decode(&intent.parameters)?;
        let f = v.list(8)?;
        ensure!(
            f.len() >= 3
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == intent.action
                && intent.profile_generation == 0,
            "tier operation context differs"
        );
        let optional = |v: &V| {
            if *v == V::Null {
                Ok(None)
            } else {
                id(v).map(Some)
            }
        };
        let out = match intent.action.as_str() {
            "AuthorityTierContext" | "AuthorityTierList" => {
                let f = v.array(6)?;
                let point = Snapshot::parse(&a(vec![f[5].clone(), a(vec![])]))?;
                ensure!(
                    intent.expected.is_empty() && intent.revision == 0,
                    "tier discovery cannot claim mutable expectations"
                );
                if intent.action == "AuthorityTierContext" {
                    Self::Context {
                        grant: id(&f[3])?,
                        tier: optional(&f[4])?,
                        point,
                    }
                } else {
                    Self::List {
                        grant: id(&f[3])?,
                        after: optional(&f[4])?,
                        point,
                    }
                }
            }
            "AuthorityTierPreview" | "AuthorityTierApply" => {
                let f = v.array(8)?;
                let snapshot = Snapshot::parse(&f[6])?;
                let spec = Spec::parse(&f[5], intent.network)?;
                let previous = if f[4] == V::Null {
                    None
                } else {
                    Some(f[4].bytes()?.to_vec())
                };
                let old = previous
                    .as_ref()
                    .map(|v| Spec::from_record(v, intent.network, intent.incarnation))
                    .transpose()?;
                let generation = old
                    .as_ref()
                    .map_or(Some(1), |(_, r)| r.generation.checked_add(1))
                    .context("tier generation exhausted")?;
                ensure!(
                    intent.resource == spec.id
                        && intent.revision == generation
                        && intent.expected == snapshot.references
                        && old.as_ref().is_none_or(|(p, _)| p.id == spec.id),
                    "tier proposal differs from signed snapshot"
                );
                Self::Change {
                    grant: id(&f[3])?,
                    previous,
                    spec,
                    snapshot,
                    token: optional(&f[7])?,
                    apply: intent.action == "AuthorityTierApply",
                }
            }
            _ => anyhow::bail!("unsupported tier action"),
        };
        let point = out.snapshot();
        ensure!(
            point.epoch == intent.minimum_policy_epoch
                && point.height == intent.minimum_policy_height,
            "tier operation causal floor differs"
        );
        Ok(out)
    }
    pub fn grant(&self) -> Digest {
        match self {
            Self::Context { grant, .. } | Self::List { grant, .. } | Self::Change { grant, .. } => {
                *grant
            }
        }
    }
    pub fn snapshot(&self) -> &Snapshot {
        match self {
            Self::Context { point, .. } | Self::List { point, .. } => point,
            Self::Change { snapshot, .. } => snapshot,
        }
    }
    pub fn previous(&self) -> Option<&[u8]> {
        match self {
            Self::Change { previous, .. } => previous.as_deref(),
            _ => None,
        }
    }
    pub fn derive(&self, intent: &Intent) -> Result<Option<Vec<u8>>> {
        let Self::Change {
            previous,
            spec,
            snapshot,
            apply: true,
            ..
        } = self
        else {
            return Ok(None);
        };
        let old = previous
            .as_ref()
            .map(|v| Spec::from_record(v, intent.network, intent.incarnation))
            .transpose()?;
        let mut f = vec![
            V::Uint(101),
            V::Uint(1),
            b(&intent.network),
            b(&intent.incarnation),
            V::Uint(intent.revision),
            old.as_ref().map_or(V::Null, |(_, r)| b(&r.digest)),
        ];
        f.extend(spec.value().array(7)?.to_vec());
        f.push(snapshot.value.clone());
        Ok(Some(wire::encode(&a(f))?))
    }
    pub fn request_digest(&self, intent: &Intent) -> Result<Digest> {
        let Self::Change {
            previous,
            spec,
            snapshot,
            ..
        } = self
        else {
            anyhow::bail!("tier preview requires a proposal")
        };
        Ok(wire::digest(&wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("TierProposal".into()),
            b(&intent.network),
            b(&intent.incarnation),
            b(&intent.requester),
            b(&self.grant()),
            previous.as_ref().map_or(V::Null, |v| b(v)),
            spec.value(),
            a(snapshot.references.iter().map(reference).collect()),
        ]))?))
    }
}
// A certificate authenticates current policy. Historical references never widen its restrictions.
pub fn current_reference(current: &VersionRef, pinned: &VersionRef) -> Result<()> {
    ensure!(
        current.kind == 101
            && pinned.kind == 101
            && current.id == pinned.id
            && current.generation >= pinned.generation
            && (current.generation != pinned.generation || current.digest == pinned.digest),
        "current tier differs from retained grant policy"
    );
    Ok(())
}
#[allow(dead_code)]
pub fn record_reference(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<VersionRef> {
    Ok(Spec::from_record(bytes, network, incarnation)?.1)
}
