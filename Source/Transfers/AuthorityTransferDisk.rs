// SPDX-License-Identifier: MIT
// Two committed banks preserve bounded ciphertext and idempotent chunk identities across interruption.
use crate::{
    authority_domains::transfer::{self as transfer, Agreement, Command, Effect, Profile},
    authority_proof::Digest,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
const MAGIC: &[u8; 16] = b"HyperNetFile2\0\0\0";
const HEADER: u64 = transfer::BANK_HEADER;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
#[derive(Clone)]
struct Entry {
    id: Digest,
    offer: Digest,
    digest: Digest,
    length: u64,
    expires: u64,
    payload: Vec<u8>,
    chunks: Vec<Digest>,
    committed: bool,
    deleted: bool,
}
impl Entry {
    fn value(&self) -> V {
        a(vec![
            b(&self.id),
            b(&self.offer),
            b(&self.digest),
            V::Uint(self.length),
            V::Uint(self.expires),
            b(&self.payload),
            a(self.chunks.iter().map(|h| b(h)).collect()),
            V::Bool(self.committed),
            V::Bool(self.deleted),
        ])
    }
    fn parse(v: &V) -> Result<Self> {
        let f = v.array(9)?;
        let e = Self {
            id: f[0].fixed()?,
            offer: f[1].fixed()?,
            digest: f[2].fixed()?,
            length: f[3].uint()?,
            expires: f[4].uint()?,
            payload: f[5].bytes()?.to_vec(),
            chunks: f[6]
                .list((transfer::MAXIMUM_PAYLOAD / transfer::CHUNK) as usize)?
                .iter()
                .map(V::fixed)
                .collect::<Result<_>>()?,
            committed: f[7].boolean()?,
            deleted: f[8].boolean()?,
        };
        ensure!(
            (1..=transfer::MAXIMUM_PAYLOAD).contains(&e.length)
                && e.expires > 0
                && e.chunks.len() as u64 <= e.length.div_ceil(transfer::CHUNK)
                && (!e.committed || e.chunks.len() as u64 == e.length.div_ceil(transfer::CHUNK)),
            "invalid retained transfer extent"
        );
        if e.deleted {
            ensure!(e.payload.is_empty(), "deleted transfer retains ciphertext");
        } else {
            ensure!(
                e.payload.len() as u64 == (e.chunks.len() as u64 * transfer::CHUNK).min(e.length),
                "transfer chunk map differs from bytes"
            );
            for (chunk, hash) in e.payload.chunks(transfer::CHUNK as usize).zip(&e.chunks) {
                ensure!(
                    wire::digest(chunk) == *hash,
                    "retained transfer chunk damaged"
                );
            }
            if e.committed {
                ensure!(
                    wire::digest(&e.payload) == e.digest,
                    "committed transfer digest differs"
                );
            }
        }
        Ok(e)
    }
}
#[derive(Clone)]
struct State {
    network: Digest,
    incarnation: Digest,
    service: Digest,
    time: u64,
    records: BTreeMap<Digest, Entry>,
}
impl State {
    fn value(&self) -> V {
        a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityTransferStorage".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.service),
            V::Uint(self.time),
            a(self.records.values().map(Entry::value).collect()),
        ])
    }
    fn parse(bytes: &[u8], bound: usize, p: &Profile, now: u64) -> Result<Self> {
        let v = wire::decode_bounded(bytes, bound)?;
        let f = v.array(8)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityTransferStorage"
                && f[3].fixed::<32>()? == p.manifest.network
                && f[4].fixed::<32>()? == p.manifest.incarnation
                && f[5].fixed::<32>()? == p.service
                && f[6].uint()? <= now,
            "transfer disk identity or time differs"
        );
        let mut records = BTreeMap::new();
        let mut previous = None;
        for value in f[7].list(crate::authority_domains::MAXIMUM_RECORDS)? {
            let e = Entry::parse(value)?;
            ensure!(
                previous.is_none_or(|v| v < e.id),
                "transfer disk identifiers repeat or reorder"
            );
            previous = Some(e.id);
            records.insert(e.id, e);
        }
        Ok(Self {
            network: p.manifest.network,
            incarnation: p.manifest.incarnation,
            service: p.service,
            time: f[6].uint()?,
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
    p: &Profile,
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
    pub fn initialise(path: &Path, profile: &Profile) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let extent = i64::try_from(profile.state_bytes)
            .context("transfer storage admission exceeds filesystem extent")?;
        let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, extent) };
        ensure!(
            error == 0,
            "cannot reserve admitted transfer storage: {}",
            std::io::Error::from_raw_os_error(error)
        );
        file.sync_all()?;
        Ok(())
    }
    pub fn open(path: &Path, p: &Profile, now: u64) -> Result<Self> {
        let role = p
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 4)
            .context("transfer role absent")?;
        // Parsing and copy-on-write can hold an old state, decoded new state and encoded bank concurrently.
        ensure!(
            p.state_bytes
                .checked_mul(3)
                .is_some_and(|n| n <= role.memory_bytes),
            "transfer bank working set exceeds admitted memory"
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
            "transfer disk must be an owned private preallocated file of exact consented size"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "transfer disk is in use"
        );
        let size = p.state_bytes / 2;
        let left = bank(&file, 0, size, p, now)?;
        let right = bank(&file, size, size, p, now)?;
        let chosen = match (left, right) {
            (Some(l), Some(r)) => {
                ensure!(
                    l.0 != r.0
                        || wire::encode_bounded(&l.1.value(), size as usize)?
                            == wire::encode_bounded(&r.1.value(), size as usize)?,
                    "transfer banks conflict at one generation"
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
                    "transfer disk has no recoverable committed bank"
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
            "transfer disk requires recovery or clock regressed"
        );
        let bytes = wire::encode_bounded(&state.value(), (self.bank - HEADER) as usize)?;
        let generation = self
            .generation
            .checked_add(1)
            .context("transfer disk generation exhausted")?;
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
    /// Reconciliation is permitted only after the recipient journal identifies this exact prior claim.
    pub fn execute(
        &mut self,
        t: &Agreement,
        command: &Command,
        payload: &[u8],
        now: u64,
        reconcile: bool,
    ) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned && now >= self.state.time,
            "transfer disk requires recovery or clock regressed"
        );
        let Command::Execute {
            id,
            effect,
            offset,
            bytes,
            digest,
        } = command
        else {
            anyhow::bail!("not a serving transfer command")
        };
        let accepted = t.acceptance.as_ref().context("transfer unaccepted")?;
        ensure!(
            *id == t.offer.id
                && accepted.service.id == self.state.service
                && !t.cancelled
                && now < accepted.expires,
            "transfer no longer accepted at this store"
        );
        let mut state = self.state.clone();
        state.time = now;
        // Expired ciphertext and its bounded chunk receipts can no longer support a fresh effect.
        state.records.retain(|_, entry| entry.expires > now);
        let empty = Entry {
            id: *id,
            offer: wire::digest(&t.offer.envelope),
            digest: t.offer.payload_digest,
            length: t.offer.payload_bytes,
            expires: accepted.expires,
            payload: vec![],
            chunks: vec![],
            committed: false,
            deleted: false,
        };
        if *effect == Effect::Put {
            state.records.entry(*id).or_insert_with(|| empty.clone());
        }
        let mut output = vec![];
        let mut changed = false;
        let mut stored = 0;
        let mut committed = false;
        let mut deleted = false;
        if let Some(e) = state.records.get_mut(id) {
            ensure!(
                e.offer == empty.offer
                    && e.digest == empty.digest
                    && e.length == empty.length
                    && e.expires == empty.expires,
                "stored transfer differs from immutable acceptance"
            );
            match effect {
                Effect::Put => {
                    ensure!(
                        *offset <= e.length
                            && *offset % transfer::CHUNK == 0
                            && *bytes == (e.length - *offset).min(transfer::CHUNK)
                            && payload.len() as u64 == *bytes
                            && Some(wire::digest(payload)) == *digest,
                        "transfer chunk differs from exact signed position or digest"
                    );
                    let index = (*offset / transfer::CHUNK) as usize;
                    if let Some(old) = e.chunks.get(index) {
                        ensure!(
                            *old == digest.unwrap() && (!e.deleted || reconcile),
                            "chunk replay differs or transfer was deleted"
                        );
                    } else {
                        ensure!(
                            !e.deleted
                                && !e.committed
                                && index == e.chunks.len()
                                && e.payload.len() as u64 == *offset,
                            "transfer chunk has a gap or cannot reopen a closed transfer"
                        );
                        e.payload.extend(payload);
                        e.chunks.push(digest.unwrap());
                        changed = true;
                    }
                    stored = offset + bytes;
                }
                Effect::Commit => {
                    ensure!(
                        payload.is_empty()
                            && e.chunks.len() as u64 == e.length.div_ceil(transfer::CHUNK)
                            && (!e.deleted || reconcile && e.committed),
                        "transfer is incomplete or deleted"
                    );
                    if !e.committed {
                        ensure!(
                            wire::digest(&e.payload) == e.digest,
                            "complete ciphertext digest differs"
                        );
                        e.committed = true;
                        changed = true;
                    }
                    stored = e.length;
                    committed = true;
                }
                Effect::Fetch => {
                    ensure!(
                        payload.is_empty()
                            && e.committed
                            && !e.deleted
                            && offset
                                .checked_add(*bytes)
                                .is_some_and(|end| end <= e.length),
                        "transfer fetch is incomplete, deleted or outside its extent"
                    );
                    output = e.payload[*offset as usize..(*offset + *bytes) as usize].to_vec();
                    stored = e.length;
                    committed = true;
                }
                Effect::Status => {
                    ensure!(payload.is_empty(), "transfer status has unexpected payload");
                    stored = (e.chunks.len() as u64 * transfer::CHUNK).min(e.length);
                    committed = e.committed;
                    deleted = e.deleted;
                }
                Effect::Delete => {
                    ensure!(payload.is_empty(), "transfer delete has unexpected payload");
                    if !e.deleted {
                        e.payload.clear();
                        e.deleted = true;
                        changed = true;
                    }
                    deleted = true;
                }
            }
        } else {
            ensure!(
                *effect == Effect::Status || *effect == Effect::Delete,
                "transfer has no stored ciphertext"
            );
            ensure!(payload.is_empty(), "transfer has unexpected payload");
            if *effect == Effect::Delete {
                let mut e = empty;
                e.deleted = true;
                state.records.insert(*id, e);
                deleted = true;
                changed = true;
            }
        }
        let response = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("TransferEffect".into()),
            b(id),
            b(&wire::digest(&t.offer.envelope)),
            V::Text(effect.name().into()),
            V::Uint(*offset),
            V::Uint(*bytes),
            V::Uint(stored),
            V::Bool(committed),
            V::Bool(deleted),
            b(&output),
        ]))?;
        if changed || state.records.len() != self.state.records.len() {
            self.commit(state)?;
        } else {
            self.state.time = now;
        }
        Ok(response)
    }
}
#[cfg(test)]
#[path = "../../Tests/Unit/Transfers/AuthorityTransferDiskTests.rs"]
mod tests;
