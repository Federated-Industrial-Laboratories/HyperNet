// SPDX-License-Identifier: MIT
// Exact approved bundles and their authenticated context survive interrupted requester completion.
use crate::{
    authority_domains::{
        self as domains,
        page::{HostProfile, objects::Bundle},
    },
    authority_objects::{Class, Object, Reference, Resolved},
    authority_proof::Digest,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
const MAGIC: &[u8; 16] = b"HyperNetPage1\0\0\0";
const BRIDGE_MAGIC: &[u8; 16] = b"HyperNetBridge1\0";
const HEADER: u64 = 64;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
#[derive(Clone, Copy)]
enum Profile<'a> {
    Page(&'a HostProfile),
    Bridge(&'a domains::federation::BridgeProfile),
}
impl<'a> Profile<'a> {
    fn manifest(self) -> &'a crate::runtime_manifest::Manifest {
        match self {
            Self::Page(p) => &p.manifest,
            Self::Bridge(p) => &p.manifest,
        }
    }
    fn service(self) -> Digest {
        match self {
            Self::Page(p) => p.service,
            Self::Bridge(p) => p.service,
        }
    }
    fn bytes(self) -> u64 {
        match self {
            Self::Page(p) => p.cache_bytes().expect("validated Page storage partition"),
            Self::Bridge(p) => p.state_bytes,
        }
    }
    fn role(self) -> u64 {
        match self {
            Self::Page(_) => 1,
            Self::Bridge(_) => 7,
        }
    }
    fn magic(self) -> &'static [u8; 16] {
        match self {
            Self::Page(_) => MAGIC,
            Self::Bridge(_) => BRIDGE_MAGIC,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Page(_) => "AuthorityPageStorage",
            Self::Bridge(_) => "AuthorityBridgeStorage",
        }
    }
    fn expiry(self, object: &Object, state: &domains::State, used: u64) -> Result<u64> {
        ensure!(
            object.reference().class() == Class::PageBundle,
            "bundle cache object class differs"
        );
        match self {
            Self::Page(p) => {
                let bundle =
                    Bundle::parse(object.bytes(), p.manifest.network, p.manifest.incarnation)?;
                ensure!(
                    object.reference().len() as u64 <= p.maximum_asset_bytes
                        && p.namespaces.contains(&bundle.author.namespace),
                    "Page bundle exceeds host scope"
                );
                Ok(bundle.author.expires_ms.min(p.manifest.validity.1).min(
                    used.checked_add(p.retention_ms)
                        .context("Page retention overflow")?,
                ))
            }
            Self::Bridge(p) => {
                let value = wire::decode(object.bytes())?;
                let author =
                    crate::authority_proof::Intent::from_signed(value.array(6)?[4].bytes()?)?;
                let bundle = Bundle::parse(object.bytes(), author.network, author.incarnation)?;
                let mut expiry = None;
                for (id, digest) in &p.agreements {
                    if let Ok(record) = state.record(151, *id) {
                        let agreement = domains::federation::Agreement::parse(
                            &record.payload,
                            state.network,
                            state.incarnation,
                        )?;
                        if agreement.treaty.digest()? == *digest
                            && agreement
                                .treaty
                                .source
                                .matches(author.network, author.incarnation)
                            && agreement.treaty.source_namespace == bundle.author.namespace
                        {
                            let limit = bundle
                                .author
                                .expires_ms
                                .min(p.manifest.validity.1)
                                .min(agreement.treaty.expires_ms);
                            expiry = Some(expiry.map_or(limit, |old: u64| old.max(limit)));
                        }
                    }
                }
                expiry.context("bridge cache bundle is outside its exact accepted treaty")
            }
        }
    }
}
#[derive(Clone)]
struct Entry {
    object: Object,
    expires: u64,
    used: u64,
}
impl Entry {
    fn value(&self) -> V {
        a(vec![
            self.object.reference().value(),
            b(self.object.bytes()),
            V::Uint(self.expires),
            V::Uint(self.used),
        ])
    }
    fn parse(v: &V, p: Profile<'_>, domain: &domains::State, time: u64) -> Result<Self> {
        let f = v.array(4)?;
        let object = Object::verify(Reference::parse(&f[0])?, f[1].bytes()?.to_vec())?;
        ensure!(
            object.reference().class() == Class::PageBundle,
            "Page cache cannot retain another object class"
        );
        let expires = f[2].uint()?;
        let used = f[3].uint()?;
        ensure!(
            expires > 0 && used <= time && expires <= p.expiry(&object, domain, used)?,
            "bundle cache exceeds exact consent or source validity"
        );
        Ok(Self {
            object,
            expires,
            used,
        })
    }
}
#[derive(Clone)]
struct State {
    label: String,
    network: Digest,
    incarnation: Digest,
    service: Digest,
    time: u64,
    domain: domains::State,
    governance: Vec<Vec<u8>>,
    records: BTreeMap<Digest, Entry>,
    payload: Vec<u8>,
}
impl State {
    fn value(&self) -> V {
        let mut fields = vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(self.label.clone()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.service),
            V::Uint(self.time),
            self.domain.value(),
            a(self.governance.iter().map(|v| b(v)).collect()),
            a(self.records.values().map(Entry::value).collect()),
        ];
        if self.label == "AuthorityBridgeStorage" {
            fields.push(b(&self.payload));
        }
        a(fields)
    }
    fn parse(bytes: &[u8], bound: usize, p: Profile<'_>, now: u64) -> Result<Self> {
        let v = wire::decode_bounded(bytes, bound)?;
        let f = v.array(if matches!(p, Profile::Bridge(_)) {
            11
        } else {
            10
        })?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == p.label()
                && f[3].fixed::<32>()? == p.manifest().network
                && f[4].fixed::<32>()? == p.manifest().incarnation
                && f[5].fixed::<32>()? == p.service()
                && f[6].uint()? <= now,
            "Page disk identity or time differs"
        );
        let time = f[6].uint()?;
        let domain =
            domains::State::parse_context(&f[7], p.manifest().network, p.manifest().incarnation)?;
        let governance = f[8]
            .list(crate::authority_capacity::MAX_RECORDS)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        crate::authority_governance::Governance::record_versions(
            p.manifest().network,
            p.manifest().incarnation,
            &governance,
        )?;
        let mut records = BTreeMap::new();
        let mut previous = None;
        for value in f[9].list(4096)? {
            let e = Entry::parse(value, p, &domain, time)?;
            let id = e.object.reference().identity();
            ensure!(
                previous.is_none_or(|v| v < id),
                "Page cache identities repeat or reorder"
            );
            previous = Some(id);
            records.insert(id, e);
        }
        let payload = if matches!(p, Profile::Bridge(_)) {
            let bytes = f[10].bytes()?;
            ensure!(
                bytes.len() <= 32768,
                "bridge retained extent exceeds its protocol bound"
            );
            bytes.to_vec()
        } else {
            vec![]
        };
        Ok(Self {
            payload,
            label: p.label().into(),
            network: p.manifest().network,
            incarnation: p.manifest().incarnation,
            service: p.service(),
            time,
            domain,
            governance,
            records,
        })
    }
}
pub struct Disk {
    magic: &'static [u8; 16],
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
    p: Profile<'_>,
    now: u64,
) -> Result<Option<(u64, State, u64)>> {
    let mut header = [0; 64];
    file.read_exact_at(&mut header, offset)?;
    if &header[..16] != p.magic() {
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
        Self::initialise_for(path, Profile::Page(profile))
    }
    pub fn initialise_bridge(
        path: &Path,
        profile: &domains::federation::BridgeProfile,
    ) -> Result<()> {
        Self::initialise_for(path, Profile::Bridge(profile))
    }
    fn initialise_for(path: &Path, profile: Profile<'_>) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let extent = i64::try_from(profile.bytes())
            .context("Page storage admission exceeds filesystem extent")?;
        let error = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, extent) };
        ensure!(
            error == 0,
            "cannot reserve admitted Page storage: {}",
            std::io::Error::from_raw_os_error(error)
        );
        file.sync_all()?;
        Ok(())
    }
    pub fn open(path: &Path, p: &HostProfile, now: u64) -> Result<Self> {
        Self::open_for(path, Profile::Page(p), now)
    }
    pub fn open_bridge(
        path: &Path,
        p: &domains::federation::BridgeProfile,
        now: u64,
    ) -> Result<Self> {
        Self::open_for(path, Profile::Bridge(p), now)
    }
    fn open_for(path: &Path, p: Profile<'_>, now: u64) -> Result<Self> {
        let role = p
            .manifest()
            .roles
            .iter()
            .find(|r| r.role == p.role())
            .context("Page role absent")?;
        // Parsing and copy-on-write can hold an old state, decoded new state and encoded bank concurrently.
        ensure!(
            p.bytes()
                .checked_mul(3)
                .is_some_and(|n| n <= role.memory_bytes),
            "Page bank working set exceeds admitted memory"
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
                && m.len() == p.bytes(),
            "Page disk must be an owned private preallocated file of exact consented size"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Page disk is in use"
        );
        crate::authority_domains::page::serialized_bank_bytes(p.bytes())?;
        let size = p.bytes() / 2;
        let left = bank(&file, 0, size, p, now)?;
        let right = bank(&file, size, size, p, now)?;
        let chosen = match (left, right) {
            (Some(l), Some(r)) => {
                ensure!(
                    l.0 != r.0
                        || wire::encode_bounded(&l.1.value(), size as usize)?
                            == wire::encode_bounded(&r.1.value(), size as usize)?,
                    "Page banks conflict at one generation"
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
            while offset < p.bytes() {
                let n = (p.bytes() - offset).min(block.len() as u64) as usize;
                file.read_exact_at(&mut block[..n], offset)?;
                ensure!(
                    block[..n].iter().all(|v| *v == 0),
                    "Page disk has no recoverable committed bank"
                );
                offset += n as u64;
            }
            (
                0,
                (
                    0,
                    State {
                        label: p.label().into(),
                        network: p.manifest().network,
                        incarnation: p.manifest().incarnation,
                        service: p.service(),
                        time: now,
                        domain: domains::State::empty(
                            p.manifest().network,
                            p.manifest().incarnation,
                        ),
                        governance: vec![],
                        records: BTreeMap::new(),
                        payload: vec![],
                    },
                    0,
                ),
            )
        };
        let out = Self {
            magic: p.magic(),
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
            "Page disk requires recovery or clock regressed"
        );
        let bytes = wire::encode_bounded(&state.value(), (self.bank - HEADER) as usize)?;
        let generation = self
            .generation
            .checked_add(1)
            .context("Page disk generation exhausted")?;
        let target = 1 - self.active;
        let offset = target as u64 * self.bank;
        self.poisoned = true;
        self.file.write_all_at(&bytes, offset + HEADER)?;
        self.file.sync_data()?;
        let mut h = [0; 64];
        h[..16].copy_from_slice(self.magic);
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
    pub fn bridge_payload(&self) -> Result<&[u8]> {
        ensure!(
            !self.poisoned && self.magic == BRIDGE_MAGIC,
            "bridge payload bank is unavailable"
        );
        Ok(&self.state.payload)
    }
    pub fn stage_bridge_payload(&mut self, payload: &[u8], now: u64) -> Result<()> {
        ensure!(
            self.magic == BRIDGE_MAGIC && payload.len() <= 32768,
            "bridge payload exceeds the exact storage role or extent"
        );
        let mut next = self.state.clone();
        next.time = now;
        next.payload = payload.to_vec();
        // Media authorisation has no Page bundle inputs. Optional cached bundles can be evicted.
        while wire::encode_bounded(&next.value(), (self.bank - HEADER) as usize).is_err() {
            let oldest = next
                .records
                .iter()
                .min_by_key(|(id, e)| (e.used, **id))
                .map(|(id, _)| *id)
                .context("bridge metadata and pending extent exceed consented storage")?;
            next.records.remove(&oldest);
        }
        self.commit(next)
    }
    pub fn context(&self) -> (&domains::State, &[Vec<u8>]) {
        (&self.state.domain, &self.state.governance)
    }
    #[cfg(test)]
    pub fn live(&self, reference: &Reference, now: u64) -> bool {
        !self.poisoned
            && self
                .state
                .records
                .get(&reference.identity())
                .is_some_and(|e| e.object.reference() == reference && e.expires > now)
    }
    pub fn objects(&self, references: &[Reference]) -> Result<Resolved> {
        Resolved::exact(
            references,
            references
                .iter()
                .map(|r| {
                    let entry = self
                        .state
                        .records
                        .get(&r.identity())
                        .context("pending Page bundle is absent from durable cache")?;
                    ensure!(
                        entry.object.reference() == r,
                        "retained Page reference differs"
                    );
                    Ok(entry.object.clone())
                })
                .collect::<Result<Vec<_>>>()?,
        )
    }
    /// Pinned inputs survive expiry and eviction until their exact requester journal is resolved.
    pub fn publish(
        &mut self,
        domain: domains::State,
        governance: Vec<Vec<u8>>,
        outputs: &Resolved,
        profile: &HostProfile,
        now: u64,
        pinned: &[Reference],
    ) -> Result<()> {
        self.publish_for(
            domain,
            governance,
            outputs,
            Profile::Page(profile),
            now,
            pinned,
        )
    }
    pub fn publish_bridge(
        &mut self,
        domain: domains::State,
        governance: Vec<Vec<u8>>,
        outputs: &Resolved,
        profile: &domains::federation::BridgeProfile,
        now: u64,
        pinned: &[Reference],
    ) -> Result<()> {
        self.publish_for(
            domain,
            governance,
            outputs,
            Profile::Bridge(profile),
            now,
            pinned,
        )
    }
    fn publish_for(
        &mut self,
        domain: domains::State,
        governance: Vec<Vec<u8>>,
        outputs: &Resolved,
        profile: Profile<'_>,
        now: u64,
        pinned: &[Reference],
    ) -> Result<()> {
        ensure!(
            !self.poisoned && now >= self.state.time,
            "Page disk requires recovery or clock regressed"
        );
        ensure!(
            domain.network == self.state.network && domain.incarnation == self.state.incarnation,
            "Page cache context belongs to another network"
        );
        let mut next = self.state.clone();
        next.time = now;
        next.domain = domain;
        next.governance = governance;
        let mut keep = pinned
            .iter()
            .map(Reference::identity)
            .collect::<BTreeSet<_>>();
        for object in outputs.objects() {
            ensure!(
                object.reference().class() == Class::PageBundle,
                "Page host accepts approved bundles only"
            );
            let expires = profile.expiry(object, &next.domain, now)?;
            ensure!(
                expires > now,
                "bundle exceeds its current consented lifetime"
            );
            let id = object.reference().identity();
            if let Some(old) = next.records.get(&id) {
                ensure!(
                    old.object.bytes() == object.bytes(),
                    "Page cache identity changed bytes"
                );
            }
            next.records.insert(
                id,
                Entry {
                    object: object.clone(),
                    expires,
                    used: now,
                },
            );
            keep.insert(id);
        }
        for id in &keep {
            ensure!(
                next.records.contains_key(id),
                "pinned Page input is missing"
            );
        }
        next.records
            .retain(|id, e| e.expires > now || keep.contains(id));
        loop {
            if wire::encode_bounded(&next.value(), (self.bank - HEADER) as usize).is_ok()
                && next.records.len() <= 4096
            {
                break;
            }
            let oldest = next
                .records
                .iter()
                .filter(|(id, _)| !keep.contains(*id))
                .min_by_key(|(id, e)| (e.used, **id))
                .map(|(id, _)| *id)
                .context("Page context and pending bundles exceed consented storage")?;
            next.records.remove(&oldest);
        }
        self.commit(next)
    }
}

#[cfg(test)]
#[path = "AuthorityPageDiskTests.rs"]
mod tests;
