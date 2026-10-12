// SPDX-License-Identifier: MIT
//! Immutable dependencies are published before the signer journal names them.
use super::records::Digest;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const MAX_NODES: usize = 4096;
pub const MAX_OBJECTS: usize = 20480;
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const ORDINARY_NODES: usize = 3584;
pub const ORDINARY_OBJECTS: usize = 17920;
pub const ORDINARY_BYTES: u64 = 224 * 1024 * 1024;
pub const MAX_RESULTS: usize = 64;
pub const EXECUTION: u16 = 4096;
const MAGIC: &[u8; 16] = b"HyperNetObject1\0";
const HEADER: usize = 64;
const INDEX: u64 = 256;
const CACHE_BYTES: usize = 8 * 1024 * 1024;
const CACHE_NODES: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "Descriptor", try_from = "Descriptor")]
pub struct Object {
    pub kind: u16,
    pub identity: Digest,
    hash: Digest,
    len: u32,
    charge: u64,
    raw: Option<Arc<Vec<u8>>>,
}
#[derive(Serialize, Deserialize)]
struct Descriptor(u16, String, String, u32, u64);
impl From<Object> for Descriptor {
    fn from(o: Object) -> Self {
        Self(
            o.kind,
            hex::encode(o.identity),
            hex::encode(o.hash),
            o.len,
            o.charge,
        )
    }
}
impl TryFrom<Descriptor> for Object {
    type Error = anyhow::Error;
    fn try_from(d: Descriptor) -> Result<Self> {
        let key = |s: String| -> Result<Digest> {
            let v: Digest = hex::decode(&s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid object digest"))?;
            ensure!(hex::encode(v) == s, "Object digest is not canonical");
            Ok(v)
        };
        ensure!(
            d.3 > 0 && d.3 as usize <= maximum(d.0)?,
            "Object length exceeds its kind"
        );
        Ok(Self {
            kind: d.0,
            identity: key(d.1)?,
            hash: key(d.2)?,
            len: d.3,
            charge: d.4,
            raw: None,
        })
    }
}
impl Object {
    pub fn len(&self) -> usize {
        self.len as usize
    }
    pub fn charged(&self) -> u64 {
        self.charge
    }
    pub fn key(&self) -> String {
        format!(
            "Object{:04X}{}.bin",
            self.kind,
            hex::encode_upper(self.identity)
        )
    }
    pub fn unstaged(&mut self) {
        self.raw = None;
    }
}
pub fn maximum(kind: u16) -> Result<usize> {
    Ok(match kind {
        14 => 1024,
        12 => 4096,
        22 => 98303,
        super::inputs::STORAGE_KIND => crate::authority_objects::PAGE_BUNDLE_BYTES,
        EXECUTION => super::peer::MAX_PAYLOAD,
        _ => anyhow::bail!("Unsupported stored object kind"),
    })
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "Object is not an exclusive private regular file"
    );
    Ok(())
}
#[derive(Default)]
struct Cache {
    entries: BTreeMap<String, Arc<Vec<u8>>>,
    order: std::collections::VecDeque<String>,
    bytes: usize,
    nodes: usize,
}
pub struct Store {
    directory: PathBuf,
    block: u64,
    cache: Mutex<Cache>,
    #[cfg(test)]
    file_syncs: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    directory_syncs: std::sync::atomic::AtomicUsize,
}
impl Store {
    pub fn open(parent: &Path, create: bool) -> Result<Arc<Self>> {
        let directory = parent.join("Objects");
        if create {
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let m = fs::symlink_metadata(&directory)?;
        ensure!(
            m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "Object directory is not private and owned"
        );
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&directory)?;
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut stats) } == 0,
            "Object filesystem accounting unavailable"
        );
        let block = (stats.f_frsize as u64).max(4096);
        ensure!(
            block.is_power_of_two() && block <= 65536,
            "Unsupported object allocation unit"
        );
        Ok(Arc::new(Self {
            directory,
            block,
            cache: Mutex::new(Cache::default()),
            #[cfg(test)]
            file_syncs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            directory_syncs: std::sync::atomic::AtomicUsize::new(0),
        }))
    }
    pub fn charge(&self, bytes: usize) -> Result<u64> {
        let size = (bytes as u64)
            .checked_add(HEADER as u64)
            .context("Object size overflow")?;
        size.div_ceil(self.block)
            .checked_mul(self.block)
            .and_then(|v| v.checked_add(INDEX))
            .context("Object charge overflow")
    }
    pub fn staged(&self, kind: u16, identity: Digest, bytes: &[u8]) -> Result<Object> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= maximum(kind)?,
            "Object exceeds its kind bound"
        );
        Ok(Object {
            kind,
            identity,
            hash: Sha256::digest(bytes).into(),
            len: bytes.len().try_into()?,
            charge: self.charge(bytes.len())?,
            raw: Some(Arc::new(bytes.to_vec())),
        })
    }
    fn validate_body(&self, object: &Object, raw: &[u8]) -> Result<()> {
        ensure!(
            raw.len() == object.len() && Sha256::digest(raw).as_slice() == object.hash,
            "Immutable object body differs from the journal"
        );
        ensure!(
            object.charge >= self.charge(raw.len())?,
            "Object charge is below its allocation profile"
        );
        Ok(())
    }
    pub fn read(&self, object: &Object) -> Result<Arc<Vec<u8>>> {
        if let Some(raw) = &object.raw {
            self.validate_body(object, raw)?;
            return Ok(raw.clone());
        }
        let key = object.key();
        if let Some(raw) = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Object cache unavailable"))?
            .entries
            .get(&key)
            .cloned()
        {
            self.validate_body(object, &raw)?;
            return Ok(raw);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.directory.join(&key))?;
        private(&file)?;
        let m = file.metadata()?;
        ensure!(
            m.len() == HEADER as u64 + object.len as u64
                && m.blocks()
                    .checked_mul(512)
                    .and_then(|n| n.checked_add(INDEX))
                    .is_some_and(|n| n <= object.charge),
            "Object allocation or length differs"
        );
        let mut bytes = Vec::with_capacity(HEADER + object.len());
        file.take((HEADER + object.len() + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == HEADER + object.len()
                && &bytes[..16] == MAGIC
                && u64::from_be_bytes(bytes[16..24].try_into()?) == object.kind as u64
                && u64::from_be_bytes(bytes[24..32].try_into()?) == object.len as u64
                && bytes[32..64] == object.hash,
            "Immutable object header differs"
        );
        let raw = Arc::new(bytes.split_off(HEADER));
        self.validate_body(object, &raw)?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Object cache unavailable"))?;
        while cache.bytes + raw.len() > CACHE_BYTES
            || object.kind == 14 && cache.nodes >= CACHE_NODES
        {
            let Some(old) = cache.order.pop_front() else {
                break;
            };
            if let Some(value) = cache.entries.remove(&old) {
                cache.bytes -= value.len();
                if old.starts_with("Object000E") {
                    cache.nodes -= 1;
                }
            }
        }
        if !cache.entries.contains_key(&key) {
            cache.bytes += raw.len();
            if object.kind == 14 {
                cache.nodes += 1;
            }
            cache.order.push_back(key.clone());
            cache.entries.insert(key, raw.clone());
        }
        Ok(raw)
    }
    /// A new durable file still requires its directory entry to be synchronized.
    pub fn publish(&self, object: &Object) -> Result<bool> {
        let Some(raw) = &object.raw else {
            return Ok(false);
        };
        self.validate_body(object, raw)?;
        let path = self.directory.join(object.key());
        if fs::symlink_metadata(&path).is_ok() {
            let mut durable = object.clone();
            durable.unstaged();
            self.read(&durable)?;
            return Ok(false);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        private(&file)?;
        file.write_all(MAGIC)?;
        file.write_all(&(object.kind as u64).to_be_bytes())?;
        file.write_all(&(object.len as u64).to_be_bytes())?;
        file.write_all(&object.hash)?;
        file.write_all(raw)?;
        super::timing::sync(&file, false)?;
        #[cfg(test)]
        self.file_syncs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ensure!(
            file.metadata()?
                .blocks()
                .checked_mul(512)
                .and_then(|v| v.checked_add(INDEX))
                .is_some_and(|v| v <= object.charge),
            "Actual object allocation exceeds reservation"
        );
        Ok(true)
    }
    pub fn sync(&self) -> Result<()> {
        super::timing::sync(&File::open(&self.directory)?, true)?;
        #[cfg(test)]
        self.directory_syncs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn sync_counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.file_syncs.load(Ordering::Relaxed),
            self.directory_syncs.load(Ordering::Relaxed),
        )
    }
    /// Call only after the current journal and every referenced object validate.
    pub fn collect(&self, retained: &BTreeSet<String>) -> Result<()> {
        let mut count = 0usize;
        let mut removed = false;
        for entry in fs::read_dir(&self.directory)? {
            count += 1;
            ensure!(
                count <= MAX_OBJECTS + MAX_RESULTS + super::repair::MAX_RECORDS + 2,
                "Object directory exceeds recovery bound"
            );
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Invalid object filename"))?;
            ensure!(
                name.len() == 78
                    && name.starts_with("Object")
                    && name.ends_with(".bin")
                    && name[6..74]
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c)),
                "Unexpected object directory entry"
            );
            if !retained.contains(&name) {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(entry.path())?;
                private(&file)?;
                fs::remove_file(entry.path())?;
                removed = true;
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Object cache unavailable"))?;
                if let Some(value) = cache.entries.remove(&name) {
                    cache.bytes -= value.len();
                    if name.starts_with("Object000E") {
                        cache.nodes -= 1;
                    }
                }
                cache.order.retain(|key| key != &name);
            }
        }
        if removed {
            self.sync()?;
        }
        Ok(())
    }
}
