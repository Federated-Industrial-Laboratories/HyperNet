// SPDX-License-Identifier: MIT
// Exact immutable media bytes are validated before a complete-copy receipt is committed.
use crate::{
    authority_domains::{
        self as domains,
        page::{
            Asset, Command, CopyReceipt, HostProfile, MediaEffect, MediaRequest,
            STORAGE_BANK_HEADER_BYTES, media_storage_budget, serialized_bank_bytes,
        },
    },
    authority_proof::{Digest, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
const MAGIC: &[u8; 16] = b"HyperNetMedia2\0\0";
const HEADER: u64 = STORAGE_BANK_HEADER_BYTES;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn hash(v: &[u8]) -> Digest {
    Sha256::digest(v).into()
}
fn reference(v: &VersionRef) -> V {
    a(vec![
        V::Uint(v.kind),
        b(&v.id),
        V::Uint(v.generation),
        b(&v.digest),
    ])
}
#[derive(Clone)]
struct Entry {
    asset: VersionRef,
    metadata: Asset,
    host: VersionRef,
    expires: u64,
    payload: Vec<u8>,
    receipt: Option<CopyReceipt>,
}
impl Entry {
    fn value(&self) -> V {
        a(vec![
            reference(&self.asset),
            self.metadata.value(),
            reference(&self.host),
            V::Uint(self.expires),
            b(&self.payload),
            self.receipt.as_ref().map_or(V::Null, |r| b(&r.envelope)),
        ])
    }
    fn parse(v: &V, p: &HostProfile) -> Result<Self> {
        let f = v.array(6)?;
        let out = Self {
            asset: domains::version(&f[0])?,
            metadata: Asset::parse(&f[1])?,
            host: domains::version(&f[2])?,
            expires: f[3].uint()?,
            payload: f[4].bytes()?.to_vec(),
            receipt: if f[5] == V::Null {
                None
            } else {
                Some(CopyReceipt::parse(
                    f[5].bytes()?,
                    p.manifest.network,
                    p.manifest.incarnation,
                )?)
            },
        };
        ensure!(
            out.asset.kind == 144
                && out.asset.id == out.metadata.identity()?
                && out.host.kind == 143
                && out.host.id == p.service
                && out.metadata.hosts.contains(&out.host)
                && out.metadata.manifest.bytes <= p.maximum_asset_bytes
                && out.payload.len() as u64 <= out.metadata.manifest.bytes
                && out.expires > 0
                && out.expires <= out.metadata.expires_ms,
            "retained media extent or consent differs"
        );
        if let Some(r) = &out.receipt {
            ensure!(
                r.asset == out.asset
                    && r.host == out.host
                    && r.bytes == out.metadata.manifest.bytes
                    && hex::encode(r.digest) == out.metadata.manifest.digest
                    && out.payload.len() as u64 == r.bytes,
                "retained media receipt differs from complete bytes"
            );
            crate::markup::media::validate_asset_bytes(&out.metadata.manifest, &out.payload)
                .map_err(anyhow::Error::msg)?;
        } else {
            ensure!(
                (out.payload.len() as u64) < out.metadata.manifest.bytes,
                "complete media lacks validated receipt"
            );
        }
        Ok(out)
    }
}
#[derive(Clone)]
struct State {
    network: Digest,
    incarnation: Digest,
    service: Digest,
    profile: Digest,
    time: u64,
    records: BTreeMap<Digest, Entry>,
}
impl State {
    fn value(&self) -> V {
        a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityMediaStorage".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.service),
            b(&self.profile),
            V::Uint(self.time),
            a(self.records.values().map(Entry::value).collect()),
        ])
    }
    fn parse(bytes: &[u8], bound: usize, p: &HostProfile, now: u64) -> Result<Self> {
        let v = wire::decode_bounded(bytes, bound)?;
        let f = v.array(9)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityMediaStorage"
                && f[3].fixed::<32>()? == p.manifest.network
                && f[4].fixed::<32>()? == p.manifest.incarnation
                && f[5].fixed::<32>()? == p.service
                && f[6].fixed::<32>()? == wire::digest(&p.envelope)
                && f[7].uint()? <= now,
            "media storage identity or clock differs"
        );
        let mut records = BTreeMap::new();
        let mut previous = None;
        for value in f[8].list(domains::MAXIMUM_RECORDS)? {
            let entry = Entry::parse(value, p)?;
            let id = entry.asset.id;
            ensure!(
                previous.is_none_or(|old| old < id),
                "media entries repeat or reorder"
            );
            previous = Some(id);
            records.insert(id, entry);
        }
        Ok(Self {
            network: p.manifest.network,
            incarnation: p.manifest.incarnation,
            service: p.service,
            profile: wire::digest(&p.envelope),
            time: f[7].uint()?,
            records,
        })
    }
}
pub struct Disk {
    file: File,
    bank: u64,
    active: usize,
    generation: u64,
    active_bytes: u64,
    poisoned: bool,
    state: State,
}
fn zero(file: &File, offset: u64, length: u64) -> Result<()> {
    let block = [0u8; 65536];
    let mut done = 0;
    while done < length {
        let count = (length - done).min(block.len() as u64) as usize;
        file.write_all_at(&block[..count], offset + done)?;
        done += count as u64;
    }
    Ok(())
}
fn bank(
    file: &File,
    offset: u64,
    size: u64,
    p: &HostProfile,
    now: u64,
) -> Result<Option<(u64, State, u64)>> {
    let mut header = [0; 64];
    file.read_exact_at(&mut header, offset)?;
    if &header[..16] != MAGIC {
        return Ok(None);
    }
    let generation = u64::from_be_bytes(header[16..24].try_into()?);
    let length = u64::from_be_bytes(header[24..32].try_into()?);
    if generation == 0 || length == 0 || length > size - HEADER {
        return Ok(None);
    }
    let mut bytes = vec![0; usize::try_from(length)?];
    file.read_exact_at(&mut bytes, offset + HEADER)?;
    if wire::digest(&bytes) != header[32..64] {
        return Ok(None);
    }
    Ok(Some((
        generation,
        State::parse(&bytes, (size - HEADER) as usize, p, now)?,
        length,
    )))
}
impl Disk {
    pub fn initialise(path: &Path, profile: &HostProfile) -> Result<()> {
        media_storage_budget(profile.state_bytes)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let extent = i64::try_from(profile.state_bytes)
            .context("media storage admission exceeds filesystem extent")?;
        let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, extent) };
        ensure!(
            error == 0,
            "cannot reserve admitted media storage: {}",
            std::io::Error::from_raw_os_error(error)
        );
        file.sync_all()?;
        Ok(())
    }
    pub fn open(path: &Path, p: &HostProfile, now: u64) -> Result<Self> {
        media_storage_budget(p.state_bytes)?;
        let role = p
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 2)
            .context("media role absent")?;
        // Parsing and copy-on-write can hold an old state, decoded new state and encoded bank concurrently.
        ensure!(
            p.state_bytes
                .checked_mul(3)
                .is_some_and(|n| n <= role.memory_bytes),
            "media bank working set exceeds admitted memory"
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.mode() & 0o077 == 0
                && m.uid() == unsafe { libc::geteuid() }
                && m.nlink() == 1
                && m.len() == p.state_bytes,
            "media disk must be an owned private preallocated file of exact consented size"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "media disk is in use"
        );
        let size = serialized_bank_bytes(p.state_bytes)? + HEADER;
        let left = bank(&file, 0, size, p, now)?;
        let right = bank(&file, size, size, p, now)?;
        let chosen = match (left, right) {
            (Some(l), Some(r)) => {
                ensure!(
                    l.0 != r.0
                        || wire::encode_bounded(&l.1.value(), size as usize)?
                            == wire::encode_bounded(&r.1.value(), size as usize)?,
                    "media banks conflict at one generation"
                );
                if l.0 >= r.0 {
                    Some((0, l))
                } else {
                    Some((1, r))
                }
            }
            (Some(l), None) => Some((0, l)),
            (None, Some(r)) => Some((1, r)),
            _ => None,
        };
        let (active, (generation, state, active_bytes)) = if let Some(v) = chosen {
            v
        } else {
            let mut block = [0; 65536];
            let mut offset = 0;
            while offset < p.state_bytes {
                let n = (p.state_bytes - offset).min(block.len() as u64) as usize;
                file.read_exact_at(&mut block[..n], offset)?;
                ensure!(
                    block[..n].iter().all(|v| *v == 0),
                    "media disk has no recoverable committed bank"
                );
                offset += n as u64;
            }
            (
                0,
                (
                    0,
                    State {
                        network: p.manifest.network,
                        incarnation: p.manifest.incarnation,
                        service: p.service,
                        profile: wire::digest(&p.envelope),
                        time: now,
                        records: BTreeMap::new(),
                    },
                    0,
                ),
            )
        };
        let out = Self {
            file,
            bank: size,
            active,
            generation,
            active_bytes,
            poisoned: false,
            state,
        };
        zero(&out.file, (1 - active) as u64 * size, size)?;
        out.file.sync_all()?;
        Ok(out)
    }
    fn commit(&mut self, state: State) -> Result<()> {
        ensure!(
            !self.poisoned && state.time >= self.state.time,
            "media disk requires recovery or clock regressed"
        );
        let bytes = wire::encode_bounded(&state.value(), (self.bank - HEADER) as usize)?;
        let generation = self
            .generation
            .checked_add(1)
            .context("media disk generation exhausted")?;
        let target = 1 - self.active;
        let offset = target as u64 * self.bank;
        self.poisoned = true;
        self.file.write_all_at(&bytes, offset + HEADER)?;
        self.file.sync_data()?;
        let mut h = [0; 64];
        h[..16].copy_from_slice(MAGIC);
        h[16..24].copy_from_slice(&generation.to_be_bytes());
        h[24..32].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        h[32..].copy_from_slice(&wire::digest(&bytes));
        self.file.write_all_at(&h, offset)?;
        self.file.sync_all()?;
        let old_bytes = self.active_bytes;
        self.state = state;
        self.active = target;
        self.active_bytes = bytes.len() as u64;
        self.generation = generation;
        zero(
            &self.file,
            (1 - target) as u64 * self.bank,
            HEADER + old_bytes,
        )?;
        self.file.sync_all()?;
        self.poisoned = false;
        Ok(())
    }
    // Recipient claim reconciliation can repeat the exact write or read; stored bytes never change identity.
    pub fn execute(
        &mut self,
        request: &MediaRequest,
        asset: &Asset,
        profile: &HostProfile,
        payload: &[u8],
        key: &SigningKey,
        now: u64,
    ) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned
                && now >= self.state.time
                && self.state.profile == wire::digest(&profile.envelope)
                && key.verifying_key().to_bytes() == self.state.service,
            "media storage requires recovery or another identity"
        );
        let Command::MediaAuthorise {
            asset: reference_asset,
            host,
            effect,
            offset,
            bytes,
            digest,
        } = request.command()
        else {
            unreachable!()
        };
        ensure!(
            reference_asset.id == asset.identity()?
                && asset.hosts.contains(host)
                && host.id == self.state.service
                && crate::policy::media_range(asset.manifest.bytes, *offset, *bytes)
                && asset.manifest.bytes <= profile.maximum_asset_bytes
                && now < asset.expires_ms,
            "media effect exceeds current asset or host extent"
        );
        let mut state = self.state.clone();
        state.time = now;
        state.records.retain(|_, e| e.expires > now);
        let retained_count = state.records.len();
        if *effect == MediaEffect::Upload {
            ensure!(
                payload.len() as u64 == *bytes
                    && Some(hash(payload)) == *digest
                    && now < asset.upload_expires_ms,
                "media upload payload differs from signed range or digest"
            );
            state
                .records
                .entry(reference_asset.id)
                .or_insert_with(|| Entry {
                    asset: reference_asset.clone(),
                    metadata: asset.clone(),
                    host: host.clone(),
                    expires: asset
                        .expires_ms
                        .min(now.saturating_add(profile.retention_ms)),
                    payload: vec![],
                    receipt: None,
                });
        } else {
            ensure!(payload.is_empty(), "media read must not carry upload bytes");
        }
        let entry = state
            .records
            .get_mut(&reference_asset.id)
            .context("media asset unavailable at this host")?;
        ensure!(
            entry.asset == *reference_asset
                && entry.host == *host
                && entry.metadata.value() == asset.value(),
            "stored media differs from exact certified immutable asset"
        );
        let mut changed = retained_count != self.state.records.len();
        let output = match effect {
            MediaEffect::Upload => {
                let start = usize::try_from(*offset)?;
                let end = start
                    .checked_add(payload.len())
                    .context("media extent overflow")?;
                if start < entry.payload.len() {
                    ensure!(
                        end <= entry.payload.len() && entry.payload[start..end] == *payload,
                        "media replay changes existing bytes"
                    );
                } else {
                    ensure!(
                        start == entry.payload.len(),
                        "media upload has a missing predecessor range"
                    );
                    entry.payload.extend_from_slice(payload);
                    changed = true;
                }
                if entry.payload.len() as u64 == asset.manifest.bytes && entry.receipt.is_none() {
                    crate::markup::media::validate_asset_bytes(&asset.manifest, &entry.payload)
                        .map_err(anyhow::Error::msg)?;
                    let mut receipt = CopyReceipt {
                        asset: reference_asset.clone(),
                        host: host.clone(),
                        request: request.intent().digest,
                        digest: hash(&entry.payload),
                        bytes: asset.manifest.bytes,
                        recorded_ms: now,
                        envelope: vec![],
                    };
                    receipt.envelope = wire::sign_envelope(
                        &receipt.payload(state.network, state.incarnation)?,
                        key,
                    )?;
                    entry.receipt = Some(CopyReceipt::parse(
                        &receipt.envelope,
                        state.network,
                        state.incarnation,
                    )?);
                    changed = true;
                }
                vec![]
            }
            MediaEffect::Read | MediaEffect::Inspect => {
                ensure!(
                    entry.receipt.is_some(),
                    "media asset is not fully validated"
                );
                let start = usize::try_from(*offset)?;
                let end = usize::try_from(*offset + *bytes)?;
                entry.payload[start..end].to_vec()
            }
        };
        let response = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("PageMediaEffect".into()),
            reference(reference_asset),
            reference(host),
            V::Uint(effect.code()),
            V::Uint(*offset),
            V::Uint(*bytes),
            b(&if *effect == MediaEffect::Upload {
                (*digest).context("upload digest absent")?
            } else {
                hash(&output)
            }),
            b(&output),
            entry.receipt.as_ref().map_or(V::Null, |r| b(&r.envelope)),
        ]))?;
        if changed {
            self.commit(state)?;
        } else {
            self.state.time = now;
        }
        Ok(response)
    }
}

#[cfg(test)]
#[path = "AuthorityMediaDiskTests.rs"]
mod tests;
