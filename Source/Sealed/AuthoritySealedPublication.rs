// SPDX-License-Identifier: MIT
// Sealed publication metadata binds exact audience, storage consent and reviewer-approved ciphertext.
use crate::{
    authority_domains::{self as domains, Record},
    authority_membership::{Snapshot, reference},
    authority_proof::{Digest, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
#[path = "AuthoritySealedPublicationCommands.rs"]
mod commands;
pub use commands::Command;
#[path = "AuthoritySealedPublicationEvaluation.rs"]
mod evaluation;
pub use evaluation::evaluate;
pub(crate) use evaluation::{content_access, live, local_search};
pub const PUBLICATION_STATE: u64 = 162;
pub const OBJECT_HEAD: u64 = 163;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let v = v.fixed()?;
    ensure!(v != [0; 32], "zero sealed publication identity");
    Ok(v)
}
fn key(v: &V) -> Result<Key> {
    let v = id(v)?;
    wire::valid_key(&v)?;
    Ok(v)
}
fn version(v: &V, kind: u64) -> Result<VersionRef> {
    let r = domains::version(v)?;
    ensure!(r.kind == kind, "sealed reference kind differs");
    Ok(r)
}
fn point(v: &V) -> Result<(u64, u64, Digest)> {
    let f = v.array(3)?;
    Ok((f[0].uint()?, f[1].uint()?, id(&f[2])?))
}
fn ids(v: &V, max: usize) -> Result<Vec<Digest>> {
    let v = v.list(max)?.iter().map(id).collect::<Result<Vec<_>>>()?;
    ensure!(
        v.windows(2).all(|w| w[0] < w[1]),
        "sealed identifiers repeat or reorder"
    );
    Ok(v)
}
fn prefix(payload: &[u8], n: Digest, i: Digest, kind: u64, arity: usize) -> Result<Vec<V>> {
    let value = wire::decode(payload)?;
    let f = value.array(arity)?;
    ensure!(
        f[0].uint()? == kind
            && f[1].uint()? == 1
            && id(&f[2])? == n
            && id(&f[3])? == i
            && f[4].uint()? > 0
            && (f[4].uint()? == 1) == (f[5] == V::Null),
        "sealed record context or predecessor differs"
    );
    if f[5] != V::Null {
        id(&f[5])?;
    }
    Ok(f.to_vec())
}
fn record_reference(f: &[V], lookup: Digest, payload: &[u8]) -> Result<VersionRef> {
    Ok(VersionRef {
        kind: f[0].uint()?,
        id: lookup,
        generation: f[4].uint()?,
        digest: wire::digest(payload),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub hosts: Vec<Digest>,
    pub volumes: Vec<Digest>,
    pub backups: Vec<Digest>,
    pub copies: u64,
}
impl Placement {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(4)?;
        let p = Self {
            hosts: ids(&f[0], 16)?,
            volumes: ids(&f[1], 16)?,
            backups: ids(&f[2], 16)?,
            copies: f[3].uint()?,
        };
        ensure!(
            !p.volumes.is_empty() && p.copies > 0 && p.copies <= p.hosts.len() as u64,
            "sealed placement lacks sufficient explicit locations"
        );
        Ok(p)
    }

    /// A user restriction can reduce destinations but cannot add an unconsented location.
    pub fn within(&self, parent: &Self) -> bool {
        self.hosts.iter().all(|d| parent.hosts.contains(d))
            && self.volumes.iter().all(|d| parent.volumes.contains(d))
            && self.backups.iter().all(|d| parent.backups.contains(d))
            && self.copies >= parent.copies
    }
}
#[derive(Clone, Debug)]
pub struct ObjectPolicy {
    pub reference: VersionRef,
    pub object: Digest,
    pub namespace: Digest,
    pub publisher: Key,
    pub audience: VersionRef,
    pub modes: Vec<u64>,
    pub public_audience: bool,
    pub placement: Placement,
    pub minimum_state: (u64, u64, Digest),
    pub disclosure: Option<Digest>,
    pub snapshot: Snapshot,
}
impl ObjectPolicy {
    pub fn parse(payload: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(payload, n, i, 104, 16)?;
        let object = id(&f[6])?;
        let modes = f[10]
            .list(2)?
            .iter()
            .map(V::uint)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !modes.is_empty()
                && modes.iter().all(|m| *m <= 1)
                && modes.windows(2).all(|w| w[0] < w[1]),
            "invalid object publication modes"
        );
        Ok(Self {
            reference: record_reference(&f, object, payload)?,
            object,
            namespace: id(&f[7])?,
            publisher: key(&f[8])?,
            audience: version(&f[9], 110)?,
            modes,
            public_audience: f[11].boolean()?,
            placement: Placement::parse(&f[12])?,
            minimum_state: point(&f[13])?,
            disclosure: if f[14] == V::Null {
                None
            } else {
                Some(id(&f[14])?)
            },
            snapshot: domains::snapshot(&f[15])?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Outer {
    pub reference: VersionRef,
    pub publication: Digest,
    pub object: Digest,
    pub revision: u64,
    pub encryption_generation: u64,
    pub audience: VersionRef,
    pub roster: Digest,
    pub ciphertext: Digest,
    pub bytes: u64,
    pub placement: Placement,
    pub opaque_consents: Vec<Digest>,
    pub minimum_state: (u64, u64, Digest),
    pub snapshot: Snapshot,
    pub reviewer: Key,
}
impl Outer {
    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let (payload, signers) = wire::envelope(envelope, 1)?;
        let f = prefix(&payload, n, i, 113, 19)?;
        id(&f[17])?;
        let publication = id(&f[6])?;
        let p = Self {
            reference: record_reference(&f, publication, &payload)?,
            publication,
            object: id(&f[7])?,
            revision: f[8].uint()?,
            encryption_generation: f[9].uint()?,
            audience: version(&f[10], 110)?,
            roster: id(&f[11])?,
            ciphertext: id(&f[12])?,
            bytes: f[13].uint()?,
            placement: Placement::parse(&f[14])?,
            opaque_consents: ids(&f[15], 16)?,
            minimum_state: point(&f[16])?,
            snapshot: domains::snapshot(&f[18])?,
            reviewer: signers[0].0,
        };
        ensure!(
            p.reference.generation == 1
                && p.revision > 0
                && p.encryption_generation > 0
                && p.bytes > 0
                && p.bytes <= 8 * 1024 * 1024
                && p.opaque_consents.len() == p.placement.hosts.len()
                && signers.len() == 1,
            "sealed outer extent, signer or opaque consent differs"
        );
        Ok(p)
    }
}

pub fn signed_record(envelope: &[u8], n: Digest, i: Digest) -> Result<Record> {
    let (payload, signers) = wire::envelope(envelope, 1)?;
    let v = wire::decode(&payload)?;
    let f = v.list(32)?;
    let reference = match f.first().context("empty sealed record")?.uint()? {
        104 => {
            let policy = ObjectPolicy::parse(&payload, n, i)?;
            ensure!(
                signers[0].0 == policy.publisher,
                "object policy lacks publisher signature"
            );
            policy.reference
        }
        113 => Outer::parse(envelope, n, i)?.reference,
        _ => anyhow::bail!("unsupported sealed publication record"),
    };
    Ok(Record {
        reference,
        predecessor: if f[5] == V::Null {
            None
        } else {
            Some(id(&f[5])?)
        },
        payload: a(f[6..].to_vec()),
        bytes: envelope.to_vec(),
    })
}
pub fn payload(record: &Record) -> Result<Vec<u8>> {
    Ok(wire::envelope(&record.bytes, 1)?.0)
}

#[derive(Clone, Debug)]
pub struct PublicationState {
    pub outer: VersionRef,
    pub policy: VersionRef,
    pub author_grant: VersionRef,
    pub reviewer_grant: VersionRef,
    pub namespace: String,
    pub placement: VersionRef,
    pub status: u64,
    pub supersedes: Option<VersionRef>,
}
impl PublicationState {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(8)?;
        let p = Self {
            outer: version(&f[0], 113)?,
            policy: version(&f[1], 104)?,
            author_grant: version(&f[2], 102)?,
            reviewer_grant: version(&f[3], 102)?,
            namespace: f[4].text()?.into(),
            placement: version(&f[5], 159)?,
            status: f[6].uint()?,
            supersedes: if f[7] == V::Null {
                None
            } else {
                Some(version(&f[7], 113)?)
            },
        };
        ensure!(
            crate::markup::namespace(&p.namespace)
                && p.status <= 2
                && p.supersedes.as_ref() != Some(&p.outer),
            "sealed publication status or namespace differs"
        );
        Ok(p)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.outer),
            reference(&self.policy),
            reference(&self.author_grant),
            reference(&self.reviewer_grant),
            V::Text(self.namespace.clone()),
            reference(&self.placement),
            V::Uint(self.status),
            self.supersedes.as_ref().map_or(V::Null, reference),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Head {
    pub object: Digest,
    pub revision: u64,
    pub encryption_generation: u64,
    pub pending: Option<VersionRef>,
    pub published: Option<VersionRef>,
}
impl Head {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(5)?;
        let p = Self {
            object: id(&f[0])?,
            revision: f[1].uint()?,
            encryption_generation: f[2].uint()?,
            pending: if f[3] == V::Null {
                None
            } else {
                Some(version(&f[3], 113)?)
            },
            published: if f[4] == V::Null {
                None
            } else {
                Some(version(&f[4], 113)?)
            },
        };
        ensure!(
            p.revision > 0 && p.encryption_generation > 0,
            "sealed generation floor absent"
        );
        Ok(p)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.object),
            V::Uint(self.revision),
            V::Uint(self.encryption_generation),
            self.pending.as_ref().map_or(V::Null, reference),
            self.published.as_ref().map_or(V::Null, reference),
        ])
    }
}
pub fn validate_record(kind: u64, value: &V, lookup: Digest) -> Result<()> {
    let expected = match kind {
        PUBLICATION_STATE => PublicationState::parse(value)?.outer.id,
        OBJECT_HEAD => Head::parse(value)?.object,
        _ => anyhow::bail!("unknown sealed state record"),
    };
    ensure!(expected == lookup, "sealed state lookup differs");
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/AuthoritySealedPublicationTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Sealed/AuthoritySealedPublication.rs");
