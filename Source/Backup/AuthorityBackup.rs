// SPDX-License-Identifier: MIT
// Named cold archives carry explicit owner placement and independent storage consent.
use super::*;
use crate::runtime_manifest::Manifest;
#[path = "AuthorityBackupCommands.rs"]
mod commands;
pub use commands::Command;
#[path = "AuthorityBackupEvaluation.rs"]
mod evaluation;
#[path = "AuthorityBackupPackage.rs"]
pub mod package;
pub use evaluation::evaluate;
pub(crate) use evaluation::sealed_destination;
pub const DESTINATION: u64 = 169;
pub const ARCHIVE: u64 = 170;
pub const TOMBSTONE: u64 = 171;
pub const MAXIMUM_ARCHIVE: usize = 32 * 1024 * 1024;
pub const MAXIMUM_PROFILE: usize = crate::runtime_manifest::MAXIMUM + 8192;
pub const MAXIMUM_MANIFEST: usize = 16384;
fn keys(v: &V, maximum: usize) -> Result<Vec<Key>> {
    let result = v
        .list(maximum)?
        .iter()
        .map(key)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !result.is_empty() && result.windows(2).all(|w| w[0] < w[1]),
        "backup identities repeat or are absent"
    );
    Ok(result)
}
fn required(v: &V, kind: u64) -> Result<VersionRef> {
    let r = version(v)?;
    ensure!(r.kind == kind, "backup reference kind differs");
    Ok(r)
}
#[derive(Clone, Debug)]
pub struct Profile {
    pub manifest: Manifest,
    pub id: Digest,
    pub name: String,
    pub volume: Digest,
    pub bytes: u64,
    pub objects: u64,
    pub retention_ms: u64,
    pub recipients: Vec<Digest>,
    pub owners: Vec<Key>,
    pub opaque: bool,
    pub envelope: Vec<u8>,
}
impl Profile {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_PROFILE,
            "backup destination exceeds its bound"
        );
        let (payload, signers) = wire::envelope(bytes, 1)?;
        let v = wire::decode(&payload)?;
        let f = v.array(13)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "BackupDestination",
            "backup destination tag differs"
        );
        let p = Self {
            manifest: Manifest::parse(f[3].bytes()?)?,
            id: id(&f[4])?,
            name: label(&f[5], 64)?,
            volume: id(&f[6])?,
            bytes: f[7].uint()?,
            objects: f[8].uint()?,
            retention_ms: f[9].uint()?,
            recipients: f[10].list(16)?.iter().map(id).collect::<Result<_>>()?,
            owners: keys(&f[11], 16)?,
            opaque: f[12].boolean()?,
            envelope: bytes.to_vec(),
        };
        let volume = p
            .manifest
            .volumes
            .iter()
            .find(|v| v.volume_id == p.volume)
            .context("backup volume absent from consent")?;
        let allocated = p
            .manifest
            .roles
            .iter()
            .filter(|r| r.volume_ids.contains(&p.volume))
            .try_fold(0u64, |sum, r| {
                sum.checked_add(r.state_admission_bytes)
                    .context("backup volume admission overflow")
            })?;
        ensure!(
            p.manifest.network == n
                && p.manifest.incarnation == i
                && signers.len() == 1
                && signers[0].0 == p.manifest.operator
                && !volume.read_only
                && p.bytes > 0
                && allocated
                    .checked_add(p.bytes)
                    .is_some_and(|b| b <= volume.storage_admission_bytes)
                && (1..=2048).contains(&p.objects)
                && p.retention_ms > 0
                && !p.recipients.is_empty()
                && p.recipients.windows(2).all(|w| w[0] < w[1])
                && (!p.opaque || p.manifest.consent_policy.allow_opaque),
            "backup destination exceeds exact operator consent or spare volume allocation"
        );
        for r in &p.recipients {
            sealed_identity::validate_encryption_key(*r)?;
        }
        Ok(p)
    }
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("BackupDestination".into()),
            b(&self.manifest.encode()?),
            b(&self.id),
            V::Text(self.name.clone()),
            b(&self.volume),
            V::Uint(self.bytes),
            V::Uint(self.objects),
            V::Uint(self.retention_ms),
            a(self.recipients.iter().map(|k| b(k)).collect()),
            a(self.owners.iter().map(|k| b(k)).collect()),
            V::Bool(self.opaque),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Destination {
    pub profile: Profile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Destination {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(4)?;
        Ok(Self {
            profile: Profile::parse(f[0].bytes()?, n, i)?,
            manager: key(&f[1])?,
            grant: required(&f[2], 102)?,
            withdrawn: f[3].boolean()?,
        })
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
pub struct Archive {
    pub id: Digest,
    pub owner: Key,
    pub destination: VersionRef,
    pub placement: VersionRef,
    pub assets: Vec<VersionRef>,
    pub digest: Digest,
    pub bytes: u64,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub opaque: bool,
    pub envelope: Vec<u8>,
}
impl Archive {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_MANIFEST,
            "backup archive manifest exceeds its bound"
        );
        let (payload, signers) = wire::envelope(bytes, 1)?;
        let v = wire::decode(&payload)?;
        let f = v.array(15)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "BackupArchive"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "backup archive context differs"
        );
        let p = Self {
            id: id(&f[5])?,
            owner: key(&f[6])?,
            destination: required(&f[7], DESTINATION)?,
            placement: required(&f[8], 159)?,
            assets: f[9]
                .list(64)?
                .iter()
                .map(|v| required(v, 144))
                .collect::<Result<_>>()?,
            digest: id(&f[10])?,
            bytes: f[11].uint()?,
            created_ms: f[12].uint()?,
            expires_ms: f[13].uint()?,
            opaque: f[14].boolean()?,
            envelope: bytes.to_vec(),
        };
        validate_versions(&p.assets, 64)?;
        ensure!(
            signers.len() == 1
                && signers[0].0 == p.owner
                && p.created_ms > 0
                && p.expires_ms > p.created_ms
                && p.bytes > 0
                && p.bytes <= MAXIMUM_ARCHIVE as u64
                && (!p.opaque || p.assets.is_empty()),
            "backup archive signer, extent or retention differs"
        );
        Ok(p)
    }

    pub fn admitted(&self, p: &Profile, now: u64) -> Result<()> {
        ensure!(
            self.destination.id == p.id
                && p.owners.contains(&self.owner)
                && self.bytes <= p.bytes
                && self.created_ms <= now
                && self.expires_ms > now
                && self.expires_ms - self.created_ms <= p.retention_ms
                && (!self.opaque || p.opaque),
            "backup archive exceeds destination owner, byte or retention consent"
        );
        Ok(())
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
        DESTINATION => {
            let d = Destination::parse(v, n, i)?;
            ensure!(
                lookup == d.profile.id && generation == 1 + u64::from(d.withdrawn),
                "backup destination identity or generation differs"
            );
        }
        ARCHIVE => {
            let a = Archive::parse(v.bytes()?, n, i)?;
            ensure!(
                lookup == a.id && generation == 1,
                "backup archive is immutable"
            );
        }
        TOMBSTONE => {
            let f = v.array(2)?;
            let r = required(&f[0], ARCHIVE)?;
            ensure!(
                r.id == lookup && generation == 1 && f[1].uint()? > 0,
                "backup withdrawal differs"
            );
        }
        _ => anyhow::bail!("unknown backup record"),
    }
    Ok(())
}
pub fn validate_state(state: &State, partial: bool) -> Result<()> {
    for r in state
        .records
        .values()
        .filter(|r| r.reference.kind == ARCHIVE)
    {
        let archive = Archive::parse(r.payload.bytes()?, state.network, state.incarnation)?;
        if let Some(d) = state.records.get(&(DESTINATION, archive.destination.id)) {
            let d = Destination::parse(&d.payload, state.network, state.incarnation)?;
            ensure!(
                archive.destination.generation == 1
                    && archive.destination.digest
                        == wire::digest(
                            &Record::next(
                                &State::empty(state.network, state.incarnation),
                                DESTINATION,
                                d.profile.id,
                                Destination {
                                    withdrawn: false,
                                    ..d.clone()
                                }
                                .value()
                            )?
                            .bytes
                        ),
                "backup archive destination differs"
            );
        } else {
            ensure!(partial, "backup archive destination missing");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Backup/AuthorityBackupTests.rs"]
pub(crate) mod tests;

#[cfg(test)]
include!("../../Tests/Support/Backup/AuthorityBackup.rs");
