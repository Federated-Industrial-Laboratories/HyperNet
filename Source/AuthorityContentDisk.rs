// SPDX-License-Identifier: MIT
// Reserved immutable objects become readable only after durable verification and current placement reconciliation.
use crate::{
    authority_files as files,
    authority_proof::Digest,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};

const MAGIC: &[u8; 16] = b"HyperNetContent1";
const HEADER: u64 = 64;
pub const CHUNK_BYTES: usize = 32768;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let d = v.fixed()?;
    ensure!(d != [0; 32], "zero content identity");
    Ok(d)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub network: Digest,
    pub incarnation: Digest,
    pub service: Digest,
    pub profile: Digest,
    /// Includes both preallocated metadata banks and their commit headers.
    pub metadata_bytes: u64,
    /// Covers every reserved payload, including incomplete and quarantined objects.
    pub data_bytes: u64,
    pub staging_bytes: u64,
    pub quarantine_bytes: u64,
    pub maximum_object_bytes: u64,
    pub maximum_objects: usize,
    pub opaque: bool,
}
impl Limits {
    pub fn from_profile(profile: &crate::authority_domains::page::HostProfile) -> Result<Self> {
        let consent = profile
            .content
            .as_ref()
            .context("host has no durable content storage consent")?;
        ensure!(profile.role == 1, "content storage requires a Page host");
        let limits = Self {
            network: profile.manifest.network,
            incarnation: profile.manifest.incarnation,
            service: profile.service,
            profile: wire::digest(&profile.envelope),
            metadata_bytes: consent.metadata_bytes,
            data_bytes: consent.data_bytes,
            staging_bytes: consent.staging_bytes,
            quarantine_bytes: consent.quarantine_bytes,
            maximum_object_bytes: profile.maximum_asset_bytes,
            maximum_objects: usize::try_from(consent.maximum_objects)?,
            opaque: consent.opaque,
        };
        limits.validate()?;
        let role = profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 1)
            .context("Page host role is absent")?;
        ensure!(
            profile
                .cache_bytes()?
                .checked_add(limits.metadata_bytes)
                .and_then(|n| n.checked_mul(3))
                .and_then(|n| n.checked_add(2 * CHUNK_BYTES as u64))
                .is_some_and(|n| n <= role.memory_bytes),
            "content metadata working set exceeds consented memory"
        );
        Ok(limits)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            [self.network, self.incarnation, self.service, self.profile]
                .iter()
                .all(|d| *d != [0; 32])
                && self.metadata_bytes >= 8192
                && self.metadata_bytes.is_multiple_of(2)
                && self.data_bytes > 0
                && self.staging_bytes > 0
                && self.staging_bytes <= self.data_bytes
                && self.quarantine_bytes <= self.data_bytes
                && self.maximum_object_bytes > 0
                && self.maximum_object_bytes <= self.staging_bytes
                && self.maximum_objects > 0
                && self.maximum_objects <= crate::authority_domains::MAXIMUM_RECORDS,
            "invalid content storage limits"
        );
        i64::try_from(self.metadata_bytes)?;
        i64::try_from(self.data_bytes)?;
        usize::try_from(self.metadata_bytes)?;
        Ok(())
    }
    fn value(&self) -> V {
        a(vec![
            b(&self.network),
            b(&self.incarnation),
            b(&self.service),
            b(&self.profile),
            V::Uint(self.metadata_bytes),
            V::Uint(self.data_bytes),
            V::Uint(self.staging_bytes),
            V::Uint(self.quarantine_bytes),
            V::Uint(self.maximum_object_bytes),
            V::Uint(self.maximum_objects as u64),
            V::Bool(self.opaque),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Digest of the immutable placement record, not a remotely selected path.
    pub placement: Digest,
    pub digest: Digest,
    pub bytes: u64,
    pub expires_ms: u64,
    pub opaque: bool,
}
impl Object {
    fn value(&self) -> V {
        a(vec![
            b(&self.placement),
            b(&self.digest),
            V::Uint(self.bytes),
            V::Uint(self.expires_ms),
            V::Bool(self.opaque),
        ])
    }
    fn parse(v: &V, limits: &Limits) -> Result<Self> {
        let f = v.array(5)?;
        let o = Self {
            placement: id(&f[0])?,
            digest: id(&f[1])?,
            bytes: f[2].uint()?,
            expires_ms: f[3].uint()?,
            opaque: f[4].boolean()?,
        };
        ensure!(
            o.bytes > 0
                && o.bytes <= limits.maximum_object_bytes
                && o.expires_ms > 0
                && (!o.opaque || limits.opaque),
            "content object exceeds consent"
        );
        Ok(o)
    }
    fn name(&self) -> String {
        format!("Content{}.bin", hex::encode_upper(self.placement))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Staging,
    Complete,
    Quarantined,
    Purging,
}
impl Status {
    fn code(self) -> u64 {
        match self {
            Self::Staging => 0,
            Self::Complete => 1,
            Self::Quarantined => 2,
            Self::Purging => 3,
        }
    }
    fn parse(v: &V) -> Result<Self> {
        Ok(match v.uint()? {
            0 => Self::Staging,
            1 => Self::Complete,
            2 => Self::Quarantined,
            3 => Self::Purging,
            _ => anyhow::bail!("unknown content state"),
        })
    }
}
#[derive(Clone)]
struct Entry {
    object: Object,
    status: Status,
    received: u64,
    receipt: Option<Vec<u8>>,
}
impl Entry {
    fn value(&self) -> V {
        a(vec![
            self.object.value(),
            V::Uint(self.status.code()),
            V::Uint(self.received),
            self.receipt.as_ref().map_or(V::Null, |v| b(v)),
        ])
    }
    fn parse(v: &V, limits: &Limits) -> Result<Self> {
        let f = v.array(4)?;
        let e = Self {
            object: Object::parse(&f[0], limits)?,
            status: Status::parse(&f[1])?,
            received: f[2].uint()?,
            receipt: if f[3] == V::Null {
                None
            } else {
                Some(f[3].bytes()?.to_vec())
            },
        };
        ensure!(
            e.received <= e.object.bytes
                && (e.status != Status::Complete || e.received == e.object.bytes),
            "content extent differs"
        );
        match &e.receipt {
            Some(bytes) => {
                ensure!(bytes.len() <= 2048, "content receipt exceeds bound");
                let (payload, signers) = wire::envelope(bytes, 1)?;
                let value = wire::decode(&payload)?;
                let f = value.array(8)?;
                ensure!(
                    f[0].text()? == "HyperNetDurableCopy"
                        && f[1].uint()? == 1
                        && f[2] == b(&limits.network)
                        && f[3] == b(&limits.incarnation)
                        && f[4] == b(&limits.profile)
                        && f[5] == e.object.value()
                        && id(&f[6]).is_ok()
                        && f[7].uint()? > 0
                        && signers[0].0 == limits.service
                        && e.received == e.object.bytes
                        && e.status != Status::Staging,
                    "content receipt differs from retained bytes"
                );
            }
            None => ensure!(
                e.status != Status::Complete,
                "complete content lacks a durable receipt"
            ),
        }
        Ok(e)
    }
}
#[derive(Clone)]
struct State {
    time: u64,
    entries: BTreeMap<Digest, Entry>,
}
impl State {
    fn value(&self, limits: &Limits) -> V {
        a(vec![
            V::Text("HyperNetContentStorage".into()),
            V::Uint(1),
            limits.value(),
            V::Uint(self.time),
            a(self.entries.values().map(Entry::value).collect()),
        ])
    }
    fn parse(bytes: &[u8], limits: &Limits, now: u64) -> Result<Self> {
        let value =
            wire::decode_bounded(bytes, usize::try_from(limits.metadata_bytes / 2 - HEADER)?)?;
        let f = value.array(5)?;
        ensure!(
            f[0].text()? == "HyperNetContentStorage"
                && f[1].uint()? == 1
                && f[2] == limits.value()
                && f[3].uint()? <= now,
            "content storage identity or clock differs"
        );
        let mut entries = BTreeMap::new();
        let mut previous = None;
        for v in f[4].list(limits.maximum_objects)? {
            let e = Entry::parse(v, limits)?;
            ensure!(
                previous.is_none_or(|d| d < e.object.placement),
                "content identities repeat or reorder"
            );
            previous = Some(e.object.placement);
            entries.insert(e.object.placement, e);
        }
        let state = Self {
            time: f[3].uint()?,
            entries,
        };
        state.charge(limits)?;
        Ok(state)
    }
    fn charge(&self, limits: &Limits) -> Result<()> {
        let mut data = 0u64;
        let mut staging = 0u64;
        let mut quarantine = 0u64;
        for e in self.entries.values() {
            data = data
                .checked_add(e.object.bytes)
                .context("content reservation overflow")?;
            if e.status == Status::Staging {
                staging = staging
                    .checked_add(e.object.bytes)
                    .context("staging reservation overflow")?;
            }
            if e.status == Status::Quarantined {
                quarantine = quarantine
                    .checked_add(e.object.bytes)
                    .context("quarantine reservation overflow")?;
            }
        }
        ensure!(
            data <= limits.data_bytes
                && staging <= limits.staging_bytes
                && quarantine <= limits.quarantine_bytes
                && self.entries.len() <= limits.maximum_objects,
            "content storage quota reached"
        );
        let encoded = wire::encode_bounded(
            &self.value(limits),
            usize::try_from(limits.metadata_bytes / 2 - HEADER)?,
        )?;
        // Reserve the largest bounded signature envelope before receiving the first payload byte.
        let future = self.entries.values().try_fold(64usize, |sum, e| {
            sum.checked_add(if e.receipt.is_none() { 2068 } else { 16 })
                .context("content metadata reservation overflow")
        })?;
        ensure!(
            encoded
                .len()
                .checked_add(future)
                .is_some_and(|n| n <= limits.metadata_bytes as usize / 2 - HEADER as usize),
            "content receipt metadata quota reached"
        );
        Ok(())
    }
}

pub struct Disk {
    directory: File,
    file: File,
    limits: Limits,
    state: State,
    active: usize,
    generation: u64,
    poisoned: bool,
    reconciled: BTreeSet<Digest>,
}
fn open_file(directory: &File, name: &str, create: bool) -> Result<File> {
    let name = CString::new(name)?;
    let flags = libc::O_RDWR
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if create {
            libc::O_CREAT | libc::O_EXCL
        } else {
            0
        };
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    ensure!(
        fd >= 0,
        "cannot open content file: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "content file must be private, owned and singly linked"
    );
    Ok(file)
}
fn allocate(file: &File, bytes: u64) -> Result<()> {
    let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, i64::try_from(bytes)?) };
    ensure!(
        result == 0,
        "cannot reserve content extent: {}",
        std::io::Error::from_raw_os_error(result)
    );
    file.sync_all()?;
    Ok(())
}
fn zero(file: &File, offset: u64, bytes: u64) -> Result<()> {
    let block = [0u8; 65536];
    let mut n = 0;
    while n < bytes {
        let count = (bytes - n).min(block.len() as u64) as usize;
        file.write_all_at(&block[..count], offset + n)?;
        n += count as u64;
    }
    Ok(())
}
fn bank(file: &File, offset: u64, limits: &Limits, now: u64) -> Result<Option<(u64, State)>> {
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, offset)?;
    if &header[..16] != MAGIC {
        return Ok(None);
    }
    let generation = u64::from_be_bytes(header[16..24].try_into()?);
    let length = u64::from_be_bytes(header[24..32].try_into()?);
    if generation == 0 || length == 0 || length > limits.metadata_bytes / 2 - HEADER {
        return Ok(None);
    }
    let mut bytes = vec![0u8; usize::try_from(length)?];
    file.read_exact_at(&mut bytes, offset + HEADER)?;
    if wire::digest(&bytes) != header[32..64] {
        return Ok(None);
    }
    Ok(Some((generation, State::parse(&bytes, limits, now)?)))
}
impl Disk {
    pub fn initialise(path: &Path, limits: &Limits) -> Result<()> {
        limits.validate()?;
        let directory = files::create_directory(path)?;
        let file = open_file(&directory, "Store.bin", true)?;
        allocate(&file, limits.metadata_bytes)?;
        directory.sync_all()?;
        Ok(())
    }
    pub fn open(path: &Path, limits: &Limits, now: u64) -> Result<Self> {
        limits.validate()?;
        let directory = files::private_directory(path)?;
        let file = open_file(&directory, "Store.bin", false)?;
        ensure!(
            file.metadata()?.len() == limits.metadata_bytes,
            "content metadata size differs from consent"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "content store is in use"
        );
        let size = limits.metadata_bytes / 2;
        let left = bank(&file, 0, limits, now)?;
        let right = bank(&file, size, limits, now)?;
        let selected = match (left, right) {
            (Some(l), Some(r)) => {
                ensure!(
                    l.0 != r.0 || l.1.value(limits) == r.1.value(limits),
                    "content banks conflict"
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
        let (active, generation, state) = if let Some((a, (g, s))) = selected {
            (a, g, s)
        } else {
            let mut block = [0u8; 65536];
            let mut offset = 0;
            while offset < limits.metadata_bytes {
                let n = (limits.metadata_bytes - offset).min(block.len() as u64) as usize;
                file.read_exact_at(&mut block[..n], offset)?;
                ensure!(
                    block[..n].iter().all(|v| *v == 0),
                    "content store has no recoverable bank"
                );
                offset += n as u64;
            }
            (
                0,
                0,
                State {
                    time: now,
                    entries: BTreeMap::new(),
                },
            )
        };
        let disk = Self {
            directory,
            file,
            limits: limits.clone(),
            state,
            active,
            generation,
            poisoned: false,
            reconciled: BTreeSet::new(),
        };
        disk.validate_directory()?;
        zero(&disk.file, (1 - active) as u64 * size, size)?;
        disk.file.sync_all()?;
        Ok(disk)
    }
    fn validate_directory(&self) -> Result<()> {
        // Enumeration is anchored to the already checked private directory descriptor.
        let descriptor = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        for entry in std::fs::read_dir(descriptor)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == OsStr::new("Store.bin") {
                continue;
            }
            let expected = self
                .state
                .entries
                .values()
                .find(|e| OsStr::new(&e.object.name()) == name);
            let e =
                expected.context("unaccounted content file requires operator reconciliation")?;
            let file = open_file(&self.directory, &e.object.name(), false)?;
            ensure!(
                file.metadata()?.len() <= e.object.bytes
                    && (e.status == Status::Staging
                        || e.status == Status::Purging
                        || file.metadata()?.len() == e.object.bytes),
                "content extent differs from reservation"
            );
        }
        Ok(())
    }
    fn commit(&mut self, state: State) -> Result<()> {
        ensure!(
            !self.poisoned && state.time >= self.state.time,
            "content store needs recovery or clock regressed"
        );
        state.charge(&self.limits)?;
        let size = self.limits.metadata_bytes / 2;
        let bytes =
            wire::encode_bounded(&state.value(&self.limits), usize::try_from(size - HEADER)?)?;
        let generation = self
            .generation
            .checked_add(1)
            .context("content generation exhausted")?;
        let target = 1 - self.active;
        let offset = target as u64 * size;
        self.poisoned = true;
        self.file.write_all_at(&bytes, offset + HEADER)?;
        self.file.sync_data()?;
        let mut header = [0u8; 64];
        header[..16].copy_from_slice(MAGIC);
        header[16..24].copy_from_slice(&generation.to_be_bytes());
        header[24..32].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        header[32..].copy_from_slice(&wire::digest(&bytes));
        self.file.write_all_at(&header, offset)?;
        self.file.sync_all()?;
        self.state = state;
        self.active = target;
        self.generation = generation;
        zero(&self.file, (1 - target) as u64 * size, size)?;
        self.file.sync_all()?;
        self.poisoned = false;
        Ok(())
    }
    pub fn reserve(&mut self, object: &Object, now: u64) -> Result<u64> {
        ensure!(
            !self.poisoned && now >= self.state.time && now < object.expires_ms,
            "content reservation expired or clock regressed"
        );
        Object::parse(&object.value(), &self.limits)?;
        if let Some(old) = self.state.entries.get(&object.placement) {
            ensure!(
                old.object == *object && matches!(old.status, Status::Staging | Status::Complete),
                "content reservation identity or state differs"
            );
        } else {
            let mut next = self.state.clone();
            next.time = now;
            next.entries.insert(
                object.placement,
                Entry {
                    object: object.clone(),
                    status: Status::Staging,
                    received: 0,
                    receipt: None,
                },
            );
            self.commit(next)?;
        }
        let entry = &self.state.entries[&object.placement];
        if entry.status == Status::Staging {
            let name = object.name();
            let file = match open_file(&self.directory, &name, false) {
                Ok(f) => f,
                Err(_) => open_file(&self.directory, &name, true)?,
            };
            ensure!(
                file.metadata()?.len() <= object.bytes,
                "reserved content extent grew"
            );
            allocate(&file, object.bytes)?;
            self.directory.sync_all()?;
        }
        Ok(entry.received)
    }
    /// A fresh repair permit can restore exact reserved bytes; it cannot revive a purging placement.
    pub fn repair(&mut self, object: &Object, now: u64) -> Result<u64> {
        ensure!(
            !self.poisoned && now >= self.state.time && now < object.expires_ms,
            "content repair requires current authority and storage"
        );
        let Some(old) = self.state.entries.get(&object.placement) else {
            return self.reserve(object, now);
        };
        ensure!(
            old.object == *object && old.status != Status::Purging,
            "content repair identity or withdrawal differs"
        );
        if old.status == Status::Staging {
            return self.reserve(object, now);
        }
        if old.status == Status::Complete && self.verify(object).is_ok() {
            return Ok(object.bytes);
        }
        let mut next = self.state.clone();
        next.time = now;
        let entry = next.entries.get_mut(&object.placement).unwrap();
        entry.status = Status::Staging;
        entry.received = 0;
        entry.receipt = None;
        self.commit(next)?;
        self.reconciled.remove(&object.placement);
        let file = match open_file(&self.directory, &object.name(), false) {
            Ok(file) => file,
            Err(_) => open_file(&self.directory, &object.name(), true)?,
        };
        file.set_len(0)?;
        allocate(&file, object.bytes)?;
        self.directory.sync_all()?;
        Ok(0)
    }
    pub fn write(&mut self, object: &Object, offset: u64, payload: &[u8], now: u64) -> Result<u64> {
        ensure!(
            !self.poisoned
                && now >= self.state.time
                && now < object.expires_ms
                && !payload.is_empty()
                && payload.len() <= CHUNK_BYTES,
            "content write exceeds validity or chunk bound"
        );
        let old = self
            .state
            .entries
            .get(&object.placement)
            .context("content reservation absent")?;
        ensure!(
            old.object == *object && old.status == Status::Staging,
            "content write has another placement or is immutable"
        );
        let end = offset
            .checked_add(payload.len() as u64)
            .context("content range overflow")?;
        ensure!(
            offset <= old.received
                && end <= object.bytes
                && (offset == old.received || end <= old.received),
            "content write is nonsequential or overlaps retained progress"
        );
        let file = open_file(&self.directory, &object.name(), false)?;
        ensure!(
            file.metadata()?.len() == object.bytes,
            "content extent was not reserved"
        );
        if offset < old.received {
            let mut prior = vec![0; payload.len()];
            file.read_exact_at(&mut prior, offset)?;
            ensure!(prior == payload, "content retry bytes differ");
            return Ok(old.received);
        }
        file.write_all_at(payload, offset)?;
        file.sync_data()?;
        let mut next = self.state.clone();
        next.time = now;
        next.entries.get_mut(&object.placement).unwrap().received = end;
        self.commit(next)?;
        Ok(end)
    }
    fn verify(&self, object: &Object) -> Result<File> {
        let file = open_file(&self.directory, &object.name(), false)?;
        ensure!(
            file.metadata()?.len() == object.bytes,
            "content length differs"
        );
        let mut hasher = Sha256::new();
        let mut block = [0u8; CHUNK_BYTES];
        let mut offset = 0;
        while offset < object.bytes {
            let count = (object.bytes - offset).min(block.len() as u64) as usize;
            file.read_exact_at(&mut block[..count], offset)?;
            hasher.update(&block[..count]);
            offset += count as u64;
        }
        ensure!(
            <Digest>::from(hasher.finalize()) == object.digest,
            "content digest differs"
        );
        Ok(file)
    }
    pub fn complete(
        &mut self,
        object: &Object,
        request: Digest,
        key: &SigningKey,
        now: u64,
        validate: impl FnOnce(&File) -> Result<()>,
    ) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned
                && key.verifying_key().to_bytes() == self.limits.service
                && request != [0; 32]
                && now >= self.state.time
                && now < object.expires_ms,
            "content completion authority differs"
        );
        let old = self
            .state
            .entries
            .get(&object.placement)
            .context("content reservation absent")?;
        ensure!(
            old.object == *object
                && old.received == object.bytes
                && matches!(old.status, Status::Staging | Status::Complete),
            "content completion is incomplete or has another placement"
        );
        let file = self.verify(object)?;
        validate(&file)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        if let Some(receipt) = &old.receipt {
            return Ok(receipt.clone());
        }
        let payload = wire::encode(&a(vec![
            V::Text("HyperNetDurableCopy".into()),
            V::Uint(1),
            b(&self.limits.network),
            b(&self.limits.incarnation),
            b(&self.limits.profile),
            object.value(),
            b(&request),
            V::Uint(now),
        ]))?;
        let receipt = wire::sign_envelope(&payload, key)?;
        let mut next = self.state.clone();
        next.time = now;
        let e = next.entries.get_mut(&object.placement).unwrap();
        e.status = Status::Complete;
        e.receipt = Some(receipt.clone());
        self.commit(next)?;
        Ok(receipt)
    }
    /// The caller supplies a current certified placement, after applying revocations and consent.
    pub fn reconcile(&mut self, object: &Object, now: u64) -> Result<()> {
        ensure!(
            !self.poisoned && now >= self.state.time && now < object.expires_ms,
            "content reconciliation expired or clock regressed"
        );
        let e = self
            .state
            .entries
            .get(&object.placement)
            .context("content copy unavailable")?;
        ensure!(
            e.object == *object && e.status == Status::Complete,
            "content copy is not complete under this placement"
        );
        if let Err(error) = self.verify(object) {
            self.quarantine(object.placement, now)?;
            return Err(error);
        }
        self.reconciled.insert(object.placement);
        Ok(())
    }
    pub fn read(&self, object: &Object, offset: u64, bytes: usize, now: u64) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned
                && self.reconciled.contains(&object.placement)
                && now >= self.state.time
                && now < object.expires_ms
                && bytes > 0
                && bytes <= CHUNK_BYTES,
            "content read needs current reconciliation or exceeds bounds"
        );
        let e = self
            .state
            .entries
            .get(&object.placement)
            .context("content copy unavailable")?;
        ensure!(
            e.object == *object
                && e.status == Status::Complete
                && offset
                    .checked_add(bytes as u64)
                    .is_some_and(|end| end <= object.bytes),
            "content read placement or range differs"
        );
        // Recheck the immutable object's full digest; a prior successful probe cannot authorise changed disk bytes.
        let file = self.verify(object)?;
        let mut payload = vec![0; bytes];
        file.read_exact_at(&mut payload, offset)?;
        Ok(payload)
    }
    pub fn quarantine(&mut self, placement: Digest, now: u64) -> Result<()> {
        ensure!(
            !self.poisoned && now >= self.state.time,
            "content quarantine requires recovered storage and a current clock"
        );
        self.reconciled.remove(&placement);
        let mut next = self.state.clone();
        next.time = now;
        let e = next
            .entries
            .get_mut(&placement)
            .context("content copy absent")?;
        ensure!(e.status != Status::Purging, "content is purging");
        e.status = Status::Quarantined;
        self.commit(next)
    }
    /// Persist non-serving state before unlinking. Interrupted deletion remains charged and retryable.
    pub fn purge(&mut self, placement: Digest, now: u64) -> Result<()> {
        ensure!(
            !self.poisoned && now >= self.state.time,
            "content purge requires recovered storage and a current clock"
        );
        self.reconciled.remove(&placement);
        let Some(e) = self.state.entries.get(&placement) else {
            return Ok(());
        };
        let name = e.object.name();
        let mut next = self.state.clone();
        next.time = now;
        next.entries.get_mut(&placement).unwrap().status = Status::Purging;
        self.commit(next)?;
        let name = CString::new(name)?;
        let result = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        ensure!(
            result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "cannot purge content copy: {}",
            std::io::Error::last_os_error()
        );
        self.directory.sync_all()?;
        let mut next = self.state.clone();
        next.entries.remove(&placement);
        self.commit(next)
    }
    pub fn inventory(&self) -> Vec<(Object, Status, u64)> {
        self.state
            .entries
            .values()
            .map(|e| (e.object.clone(), e.status, e.received))
            .collect()
    }
}

#[cfg(test)]
#[path = "AuthorityContentDiskTests.rs"]
mod tests;
