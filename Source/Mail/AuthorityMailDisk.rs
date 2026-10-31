// SPDX-License-Identifier: MIT
// Two committed banks preserve bounded ciphertext and deletion tombstones across interruption.
use crate::{
    authority_domains::mail::{self as mail, Claim, Command, Effect, Mailbox, Profile},
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
const MAGIC: &[u8; 16] = b"HyperNetPost1\0\0\0";
const HEADER: u64 = mail::BANK_HEADER;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
#[derive(Clone)]
struct Entry {
    id: Digest,
    address: Digest,
    claim: Digest,
    digest: Digest,
    length: u64,
    expires: u64,
    payload: Vec<u8>,
    deleted: bool,
}
impl Entry {
    fn value(&self) -> V {
        a(vec![
            b(&self.id),
            b(&self.address),
            b(&self.claim),
            b(&self.digest),
            V::Uint(self.length),
            V::Uint(self.expires),
            b(&self.payload),
            V::Bool(self.deleted),
        ])
    }
    fn parse(v: &V) -> Result<Self> {
        let f = v.array(8)?;
        let e = Self {
            id: f[0].fixed()?,
            address: f[1].fixed()?,
            claim: f[2].fixed()?,
            digest: f[3].fixed()?,
            length: f[4].uint()?,
            expires: f[5].uint()?,
            payload: f[6].bytes()?.to_vec(),
            deleted: f[7].boolean()?,
        };
        ensure!(
            e.id != [0; 32]
                && e.address != [0; 32]
                && e.claim != [0; 32]
                && e.digest != [0; 32]
                && (1..=mail::MAXIMUM_PAYLOAD).contains(&e.length)
                && e.expires > 0
                && if e.deleted {
                    e.payload.is_empty()
                } else {
                    e.payload.len() as u64 == e.length && wire::digest(&e.payload) == e.digest
                },
            "invalid retained mail identity or ciphertext"
        );
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
            V::Text("AuthorityMailStorage".into()),
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
                && f[2].text()? == "AuthorityMailStorage"
                && f[3].fixed::<32>()? == p.manifest.network
                && f[4].fixed::<32>()? == p.manifest.incarnation
                && f[5].fixed::<32>()? == p.service
                && f[6].uint()? <= now,
            "mail disk identity or time differs"
        );
        let mut records = BTreeMap::new();
        let mut previous = None;
        for value in f[7].list(crate::authority_domains::MAXIMUM_RECORDS)? {
            let e = Entry::parse(value)?;
            ensure!(
                previous.is_none_or(|v| v < e.id),
                "mail disk identifiers repeat or reorder"
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
            .context("mail storage admission exceeds filesystem extent")?;
        let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, extent) };
        ensure!(
            error == 0,
            "cannot reserve admitted mail storage: {}",
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
            .find(|r| r.role == 3)
            .context("mail role absent")?;
        // Parsing and copy-on-write can hold an old state, decoded new state and encoded bank concurrently.
        ensure!(
            p.state_bytes
                .checked_mul(3)
                .is_some_and(|n| n <= role.memory_bytes),
            "mail bank working set exceeds admitted memory"
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
            "mail disk must be an owned private preallocated file of exact consented size"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "mail disk is in use"
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
                    "mail banks conflict at one generation"
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
                    "mail disk has no recoverable committed bank"
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
            "mail disk requires recovery or clock regressed"
        );
        let bytes = wire::encode_bounded(&state.value(), (self.bank - HEADER) as usize)?;
        let generation = self
            .generation
            .checked_add(1)
            .context("mail disk generation exhausted")?;
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
    /// Exact immutable ciphertext may be reconciled; deletion never allows it to reappear.
    pub fn execute(
        &mut self,
        mailbox: &Mailbox,
        claim: Option<&Claim>,
        command: &Command,
        payload: &[u8],
        now: u64,
        reconcile: bool,
    ) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned && now >= self.state.time,
            "mail disk requires recovery or clock regressed"
        );
        let Command::Execute {
            address,
            service,
            effect,
            message,
            after,
            ..
        } = command
        else {
            anyhow::bail!("not a serving mail command")
        };
        ensure!(
            *service == self.state.service
                && mailbox.publication.id()? == *address
                && !mailbox.publication.manifest.deleted
                && mailbox
                    .publication
                    .manifest
                    .storage_hosts
                    .contains(&hex::encode(service)),
            "mail is outside exact mailbox placement"
        );
        let mut state = self.state.clone();
        state.time = now;
        state.records.retain(|_, e| e.expires > now);
        let output;
        let status;
        if *effect == Effect::List {
            ensure!(
                payload.is_empty() && claim.is_none(),
                "mail list has unexpected ciphertext or claim"
            );
            output = a(state
                .records
                .values()
                .filter(|e| e.address == *address && !e.deleted && after.is_none_or(|a| e.id > a))
                .take(16)
                .map(|e| {
                    a(vec![
                        b(&e.id),
                        b(&e.digest),
                        V::Uint(e.length),
                        V::Uint(e.expires),
                    ])
                })
                .collect());
            status = "Listed";
        } else {
            let id = message.context("mail effect lacks message identifier")?;
            let claim = claim.context("mail effect lacks its exact certified claim")?;
            ensure!(
                claim.recipient.id == *address
                    && claim.binding.is_some()
                    && claim.expires > now
                    && claim.placement.iter().any(|p| p.id == *service),
                "mail claim expired or belongs to another store"
            );
            let empty = Entry {
                id,
                address: *address,
                claim: wire::digest(&wire::encode(&claim.value())?),
                digest: claim.payload_digest.context("unbound mail claim")?,
                length: claim.payload_bytes,
                expires: claim.expires,
                payload: vec![],
                deleted: false,
            };
            if let Some(old) = state.records.get(&id) {
                ensure!(
                    old.address == empty.address
                        && old.claim == empty.claim
                        && old.digest == empty.digest
                        && old.length == empty.length
                        && old.expires == empty.expires,
                    "mail ciphertext identity changed"
                );
            }
            match effect {
                Effect::Put => {
                    ensure!(
                        payload.len() as u64 == empty.length
                            && wire::digest(payload) == empty.digest,
                        "mail ciphertext differs from certified binding"
                    );
                    if let Some(old) = state.records.get(&id) {
                        ensure!(
                            !old.deleted && old.payload == payload,
                            "mail was deleted or ciphertext differs"
                        );
                    } else {
                        let mut entry = empty;
                        entry.payload = payload.to_vec();
                        state.records.insert(id, entry);
                    }
                    output = b(&[]);
                    status = "Stored";
                }
                Effect::Fetch => {
                    ensure!(payload.is_empty(), "mail fetch has payload");
                    let old = state
                        .records
                        .get(&id)
                        .context("mail has no stored ciphertext")?;
                    ensure!(!old.deleted, "mail has been deleted");
                    output = b(&old.payload);
                    status = "Fetched";
                }
                Effect::Delete => {
                    ensure!(payload.is_empty(), "mail delete has payload");
                    let e = state.records.entry(id).or_insert(empty);
                    e.deleted = true;
                    e.payload.clear();
                    output = b(&[]);
                    status = "Deleted";
                }
                Effect::List => unreachable!(),
            }
        }
        let _ = reconcile; // Recipient journals authorize reconciliation; immutable storage identities make it idempotent.
        let reply = wire::encode(&a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("MailEffect".into()),
            b(address),
            b(service),
            V::Text(effect.name().into()),
            message.as_ref().map_or(V::Null, |v| b(v)),
            V::Text(status.into()),
            output,
        ]))?;
        // Persist even reads' clock floor; otherwise restart could reopen expired mail after wall rollback.
        self.commit(state)?;
        Ok(reply)
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Mail/AuthorityMailDiskUnitTests.rs"]
mod tests;
