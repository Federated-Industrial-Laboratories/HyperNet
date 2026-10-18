// SPDX-License-Identifier: MIT
// Fixed recipient schemas retain exact root, device, audience and recovery bindings.
use super::*;

#[derive(Clone, Debug)]
pub struct Root {
    pub reference: VersionRef,
    pub member: Digest,
    pub key: Key,
    pub recovery_policy: Digest,
    pub valid_from: (u64, u64, Digest),
}
impl Root {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 107, 10)?;
        let member = id(&f[6])?;
        Ok(Self {
            reference: record_ref(&f, member, bytes)?,
            member,
            key: key(&f[7])?,
            recovery_policy: id(&f[8])?,
            valid_from: point(&f[9])?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Binding {
    pub reference: VersionRef,
    pub member: Digest,
    pub root: VersionRef,
    pub device: Digest,
    pub signing_key: Key,
    pub encryption_key: Digest,
    pub purposes: Vec<u64>,
    pub validity: (u64, u64),
}
impl Binding {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 108, 13)?;
        let device = id(&f[8])?;
        let purposes = f[11]
            .list(2)?
            .iter()
            .map(V::uint)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !purposes.is_empty()
                && purposes.iter().all(|v| *v <= 1)
                && purposes.windows(2).all(|w| w[0] < w[1]),
            "invalid recipient device purposes"
        );
        let result = Self {
            reference: record_ref(&f, device, bytes)?,
            member: id(&f[6])?,
            root: typed_ref(&f[7], 107)?,
            device,
            signing_key: key(&f[9])?,
            encryption_key: id(&f[10])?,
            purposes,
            validity: validity(&f[12])?,
        };
        validate_encryption_key(result.encryption_key)?;
        ensure!(
            result.member == result.root.id && result.signing_key != result.encryption_key,
            "recipient binding identity or keys differ"
        );
        Ok(result)
    }
}
#[derive(Clone, Debug)]
pub struct Admission {
    pub reference: VersionRef,
    pub member: Digest,
    pub binding: VersionRef,
    pub scopes: Vec<(u64, Digest)>,
    pub validity: (u64, u64),
    pub possession: Digest,
    pub snapshot: Snapshot,
}
impl Admission {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 109, 12)?;
        let binding = typed_ref(&f[7], 108)?;
        let scopes = f[8]
            .list(64)?
            .iter()
            .map(|v| {
                let p = v.array(2)?;
                let p = (p[0].uint()?, id(&p[1])?);
                ensure!(
                    p.0 <= 5 && (p.0 != 0 || p.1 == n),
                    "invalid recipient scope"
                );
                Ok(p)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !scopes.is_empty() && scopes.windows(2).all(|w| w[0] < w[1]),
            "invalid recipient scope set"
        );
        Ok(Self {
            reference: record_ref(&f, binding.digest, bytes)?,
            member: id(&f[6])?,
            binding,
            scopes,
            validity: validity(&f[9])?,
            possession: id(&f[10])?,
            snapshot: super::super::snapshot(&f[11])?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Audience {
    pub reference: VersionRef,
    pub publisher: Key,
    pub allowed_roots: Vec<VersionRef>,
    pub excluded_devices: Vec<Digest>,
    pub sharing_delegate: Option<VersionRef>,
    pub public_audience: bool,
    pub snapshot: Snapshot,
}
impl Audience {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 110, 13)?;
        let allowed_roots = f[8]
            .list(256)?
            .iter()
            .map(|r| typed_ref(r, 107))
            .collect::<Result<Vec<_>>>()?;
        validate_versions(&allowed_roots, 256)?;
        ensure!(
            !allowed_roots.is_empty(),
            "sealed audience has no accepted roots"
        );
        let result = Self {
            reference: record_ref(&f, id(&f[6])?, bytes)?,
            publisher: key(&f[7])?,
            allowed_roots,
            excluded_devices: ids(&f[9], 1024)?,
            sharing_delegate: if f[10] == V::Null {
                None
            } else {
                Some(typed_ref(&f[10], 102)?)
            },
            public_audience: f[11].boolean()?,
            snapshot: super::super::snapshot(&f[12])?,
        };
        ensure!(
            !result.public_audience,
            "public sealed audience is not supported"
        );
        Ok(result)
    }
}
pub type DeviceEvidence = (Digest, Digest, Digest);
#[derive(Clone, Debug)]
pub struct Roster {
    pub reference: VersionRef,
    pub publication: Digest,
    pub revision: u64,
    pub encryption_generation: u64,
    pub audience: VersionRef,
    pub roots: Vec<Digest>,
    pub devices: Vec<DeviceEvidence>,
    pub snapshot: Snapshot,
}
impl Roster {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 111, 13)?;
        let publication = id(&f[6])?;
        let devices = f[11]
            .list(1024)?
            .iter()
            .map(|v| {
                let p = v.array(3)?;
                Ok((id(&p[0])?, id(&p[1])?, id(&p[2])?))
            })
            .collect::<Result<Vec<_>>>()?;
        let result = Self {
            reference: record_ref(&f, publication, bytes)?,
            publication,
            revision: f[7].uint()?,
            encryption_generation: f[8].uint()?,
            audience: typed_ref(&f[9], 110)?,
            roots: ids(&f[10], 256)?,
            devices,
            snapshot: super::super::snapshot(&f[12])?,
        };
        ensure!(
            result.reference.generation == 1
                && result.revision > 0
                && result.encryption_generation > 0
                && !result.roots.is_empty()
                && !result.devices.is_empty()
                && result.devices.windows(2).all(|w| w[0] < w[1]),
            "invalid immutable recipient roster"
        );
        Ok(result)
    }
}
#[derive(Clone, Debug)]
pub struct Revocation {
    pub reference: VersionRef,
    pub target: VersionRef,
    pub signer: Key,
    pub snapshot: Snapshot,
}
impl Revocation {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 158, 9)?;
        let target = version(&f[6])?;
        ensure!(
            matches!(target.kind, 107..=109) && f[4].uint()? == 1,
            "invalid recipient revocation target"
        );
        Ok(Self {
            reference: record_ref(&f, target.digest, bytes)?,
            target,
            signer: key(&f[7])?,
            snapshot: super::super::snapshot(&f[8])?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Acceptance {
    pub operation: Digest,
    pub contact: Digest,
    pub previous_root: Option<VersionRef>,
    pub accepted_root: VersionRef,
    pub recovery_declaration: Option<Digest>,
}
impl Acceptance {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 121, 12)?;
        id(&f[11])?;
        let previous_root = if f[8] == V::Null {
            None
        } else {
            Some(typed_ref(&f[8], 107)?)
        };
        let recovery_declaration = if f[10] == V::Null {
            None
        } else {
            Some(id(&f[10])?)
        };
        ensure!(
            previous_root.is_some() || recovery_declaration.is_none(),
            "first contact has recovery declaration"
        );
        Ok(Self {
            operation: id(&f[6])?,
            contact: id(&f[7])?,
            previous_root,
            accepted_root: typed_ref(&f[9], 107)?,
            recovery_declaration,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Recovery {
    pub operation: Digest,
    pub member: Digest,
    pub prior_root: VersionRef,
    pub replacement_root: VersionRef,
    pub accepted_policy: Digest,
    pub snapshot: Snapshot,
}
impl Recovery {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 120, 12)?;
        let r = Self {
            operation: id(&f[6])?,
            member: id(&f[7])?,
            prior_root: typed_ref(&f[8], 107)?,
            replacement_root: typed_ref(&f[9], 107)?,
            accepted_policy: id(&f[10])?,
            snapshot: super::super::snapshot(&f[11])?,
        };
        ensure!(
            r.prior_root.id == r.member && r.replacement_root.id == r.member,
            "recipient recovery member differs"
        );
        Ok(r)
    }
}
#[derive(Clone, Debug)]
pub struct Custody {
    pub member: Digest,
    pub threshold: usize,
    pub keys: Vec<(Digest, Key)>,
    pub digest: Digest,
}
impl Custody {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let v = wire::decode(bytes)?;
        let f = v.array(8)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "RecipientCustody"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "recipient custody context differs"
        );
        let threshold = usize::try_from(f[6].uint()?)?;
        let keys = f[7]
            .list(3)?
            .iter()
            .map(|v| {
                let p = v.array(2)?;
                Ok((id(&p[0])?, key(&p[1])?))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            matches!((threshold, keys.len()), (1, 1) | (2, 3))
                && keys.windows(2).all(|w| w[0] < w[1])
                && keys.iter().map(|(_, k)| *k).collect::<BTreeSet<_>>().len() == keys.len(),
            "invalid recipient custody threshold or keys"
        );
        Ok(Self {
            member: id(&f[5])?,
            threshold,
            keys,
            digest: wire::digest(bytes),
        })
    }
}
#[derive(Clone, Debug)]
pub struct Possession {
    pub operation: Digest,
    pub binding: Digest,
    pub endpoint: Digest,
    pub challenge: Digest,
    pub expires_ms: u64,
}
impl Possession {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 122, 11)?;
        Ok(Self {
            operation: id(&f[6])?,
            binding: id(&f[7])?,
            endpoint: id(&f[8])?,
            challenge: id(&f[9])?,
            expires_ms: f[10].uint()?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Challenge {
    pub operation: Digest,
    pub binding: Digest,
    pub endpoint: Digest,
    pub expires_ms: u64,
}
impl Challenge {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let f = prefix(bytes, n, i, 123, 11)?;
        id(&f[9])?;
        Ok(Self {
            operation: id(&f[6])?,
            binding: id(&f[7])?,
            endpoint: id(&f[8])?,
            expires_ms: f[10].uint()?,
        })
    }
}
