// SPDX-License-Identifier: MIT
//! Segmented committed history and indexed RFC 9162 subtree hashes.
use super::records::Digest;
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

// This is an arithmetic/proof-format limit. Physical storage is governed by a byte quota.
pub const MAX_LEAVES: usize = (1usize << 63) - 1;
const SEGMENT: usize = 4096;
const HEADER: u64 = 64;
const MAGIC: &[u8; 16] = b"HyperNetHistory2";
const LEGACY: &[u8; 16] = b"HyperNetHistory1";
const DEFAULT_QUOTA: u64 = 1024 * 1024 * 1024;
pub fn empty_root() -> Digest {
    Sha256::digest([]).into()
}
fn leaf(value: &Digest) -> Digest {
    Sha256::digest([&[0][..], value].concat()).into()
}
fn branch(left: &Digest, right: &Digest) -> Digest {
    Sha256::digest([&[1][..], left, right].concat()).into()
}
fn split(n: usize) -> usize {
    1usize << (usize::BITS - (n - 1).leading_zeros() - 1)
}
pub fn root(leaves: impl AsRef<[Digest]>) -> Digest {
    fn sub(leaves: &[Digest]) -> Digest {
        match leaves.len() {
            0 => empty_root(),
            1 => leaf(&leaves[0]),
            n => {
                let k = split(n);
                branch(&sub(&leaves[..k]), &sub(&leaves[k..]))
            }
        }
    }
    sub(leaves.as_ref())
}
/// One accessor supports bounded on-disk history and small in-memory test fixtures.
pub trait History {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Result<Digest>;
    fn subtree(&self, start: usize, count: usize) -> Result<Digest>;
    fn root_at(&self, size: usize) -> Result<Digest> {
        ensure!(size <= self.len(), "History root position differs");
        if size == 0 {
            Ok(empty_root())
        } else {
            self.subtree(0, size)
        }
    }
    fn range(&self, start: usize, count: usize) -> Result<Vec<Digest>> {
        ensure!(
            count <= SEGMENT && start.checked_add(count).is_some_and(|n| n <= self.len()),
            "History range exceeds its bound"
        );
        (start..start + count).map(|i| self.get(i)).collect()
    }
}
impl History for [Digest] {
    fn len(&self) -> usize {
        <[Digest]>::len(self)
    }
    fn get(&self, index: usize) -> Result<Digest> {
        self.get(index).copied().context("History leaf is absent")
    }
    fn subtree(&self, start: usize, count: usize) -> Result<Digest> {
        Ok(root(
            self.get(start..start.checked_add(count).context("History range overflow")?)
                .context("History subtree is absent")?,
        ))
    }
}
impl History for Vec<Digest> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn get(&self, index: usize) -> Result<Digest> {
        History::get(self.as_slice(), index)
    }
    fn subtree(&self, start: usize, count: usize) -> Result<Digest> {
        History::subtree(self.as_slice(), start, count)
    }
}
impl<const N: usize> History for [Digest; N] {
    fn len(&self) -> usize {
        N
    }
    fn get(&self, index: usize) -> Result<Digest> {
        History::get(self.as_slice(), index)
    }
    fn subtree(&self, start: usize, count: usize) -> Result<Digest> {
        History::subtree(self.as_slice(), start, count)
    }
}
pub fn inclusion_at(
    history: &(impl History + ?Sized),
    size: usize,
    index: usize,
) -> Result<Vec<Digest>> {
    ensure!(
        index < size && size <= history.len(),
        "History inclusion position differs"
    );
    fn sub(
        h: &(impl History + ?Sized),
        start: usize,
        size: usize,
        index: usize,
        proof: &mut Vec<Digest>,
    ) -> Result<()> {
        if size == 1 {
            return Ok(());
        }
        let k = split(size);
        let sibling = if index < k {
            sub(h, start, k, index, proof)?;
            h.subtree(start + k, size - k)?
        } else {
            sub(h, start + k, size - k, index - k, proof)?;
            h.subtree(start, k)?
        };
        proof.push(sibling);
        Ok(())
    }
    let mut proof = Vec::new();
    sub(history, 0, size, index, &mut proof)?;
    Ok(proof)
}
pub fn consistency_at(
    history: &(impl History + ?Sized),
    size: usize,
    old: usize,
) -> Result<Vec<Digest>> {
    ensure!(
        old > 0 && old <= size && size <= history.len(),
        "History consistency size differs"
    );
    fn sub(
        h: &(impl History + ?Sized),
        start: usize,
        size: usize,
        old: usize,
        complete: bool,
        proof: &mut Vec<Digest>,
    ) -> Result<()> {
        if old == size {
            if !complete {
                proof.push(h.subtree(start, size)?);
            }
            return Ok(());
        }
        let k = split(size);
        let sibling = if old <= k {
            sub(h, start, k, old, complete, proof)?;
            h.subtree(start + k, size - k)?
        } else {
            sub(h, start + k, size - k, old - k, false, proof)?;
            h.subtree(start, k)?
        };
        proof.push(sibling);
        Ok(())
    }
    let mut proof = Vec::new();
    sub(history, 0, size, old, true, &mut proof)?;
    Ok(proof)
}

fn count(size: usize) -> Result<usize> {
    size.checked_mul(2)
        .and_then(|n| n.checked_sub(size.count_ones() as usize))
        .context("History index overflow")
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "History file is not an owned private regular file"
    );
    Ok(())
}
fn directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            if let Some(parent) = path.parent() {
                super::timing::sync(&File::open(parent)?, true)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "History directory is not owned and private"
    );
    Ok(())
}
fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    o
}
struct Segments {
    directory: PathBuf,
    configuration: Digest,
    kind: u64,
    tail: Option<(usize, File)>,
}
impl Segments {
    fn path(&self, number: usize) -> PathBuf {
        self.directory.join(format!(
            "{}{:016x}.bin",
            if self.kind == 0 { "Data" } else { "Nodes" },
            number
        ))
    }
    fn header(&self, number: usize) -> Vec<u8> {
        [
            MAGIC.as_slice(),
            &self.configuration,
            &(number as u64).to_be_bytes(),
            &self.kind.to_be_bytes(),
        ]
        .concat()
    }
    fn open(&self, number: usize, create: bool) -> Result<File> {
        let p = self.path(number);
        let file = match options().open(&p) {
            Ok(f) => f,
            Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                let f = options().create_new(true).mode(0o600).open(&p)?;
                f.write_all_at(&self.header(number), 0)?;
                f
            }
            Err(e) => return Err(e.into()),
        };
        private(&file)?;
        let m = file.metadata()?;
        ensure!(
            m.len() >= HEADER
                && m.len() <= HEADER + SEGMENT as u64 * 32
                && m.blocks() * 512 <= HEADER + SEGMENT as u64 * 32 + 8192,
            "History segment dimensions differ"
        );
        let mut header = [0; HEADER as usize];
        file.read_exact_at(&mut header, 0)?;
        ensure!(
            header.as_slice() == self.header(number),
            "History segment context differs"
        );
        Ok(file)
    }
    fn read(&self, index: usize) -> Result<Digest> {
        let file = self.open(index / SEGMENT, false)?;
        let mut value = [0; 32];
        file.read_exact_at(&mut value, HEADER + (index % SEGMENT) as u64 * 32)?;
        Ok(value)
    }
    fn range(&self, start: usize, size: usize) -> Result<Vec<Digest>> {
        ensure!(size <= SEGMENT, "History read exceeds one segment");
        let mut result = Vec::with_capacity(size);
        let mut index = start;
        while index < start + size {
            let n = (SEGMENT - index % SEGMENT).min(start + size - index);
            let f = self.open(index / SEGMENT, false)?;
            let mut bytes = vec![0; n * 32];
            f.read_exact_at(&mut bytes, HEADER + (index % SEGMENT) as u64 * 32)?;
            result.extend(bytes.chunks_exact(32).map(|b| Digest::try_from(b).unwrap()));
            index += n;
        }
        Ok(result)
    }
    fn write(&mut self, index: usize, value: &Digest) -> Result<()> {
        let number = index / SEGMENT;
        if self.tail.as_ref().is_none_or(|(n, _)| *n != number) {
            self.sync()?;
            self.tail = Some((number, self.open(number, true)?));
        }
        self.tail
            .as_ref()
            .unwrap()
            .1
            .write_all_at(value, HEADER + (index % SEGMENT) as u64 * 32)?;
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        if let Some((_, file)) = &self.tail {
            super::timing::sync(file, false)?;
        }
        Ok(())
    }
    fn truncate(&mut self, entries: usize) -> Result<()> {
        self.tail = None;
        let prefix = if self.kind == 0 { "Data" } else { "Nodes" };
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("Non-UTF8 history name")?;
            if !name.starts_with(prefix) {
                continue;
            }
            let number = usize::from_str_radix(
                name.strip_prefix(prefix)
                    .and_then(|v| v.strip_suffix(".bin"))
                    .context("Invalid history segment name")?,
                16,
            )?;
            let start = number
                .checked_mul(SEGMENT)
                .context("History segment index overflow")?;
            if start >= entries {
                let file = options().open(entry.path())?;
                private(&file)?;
                let mut header = vec![0; file.metadata()?.len().min(HEADER) as usize];
                file.read_exact_at(&mut header, 0)?;
                ensure!(
                    self.header(number).starts_with(&header),
                    "Uncommitted history segment belongs to another configuration"
                );
                drop(file);
                fs::remove_file(entry.path())?;
            } else {
                let file = self.open(number, false)?;
                let length = HEADER + (entries - start).min(SEGMENT) as u64 * 32;
                ensure!(
                    file.metadata()?.len() >= length,
                    "Committed history segment is incomplete"
                );
                if file.metadata()?.len() > length {
                    file.set_len(length)?;
                    super::timing::sync(&file, false)?;
                }
            }
        }
        Ok(())
    }
}
pub struct Archive {
    directory: PathBuf,
    configuration: Digest,
    data: Segments,
    nodes: Segments,
    size: usize,
    frontier: Vec<Option<Digest>>,
    quota: u64,
    poisoned: bool,
}
impl History for Archive {
    fn len(&self) -> usize {
        self.size
    }
    fn get(&self, index: usize) -> Result<Digest> {
        ensure!(index < self.size, "History leaf position differs");
        let value = self.data.read(index)?;
        ensure!(
            leaf(&value) == self.nodes.read(count(index)?)?,
            "History leaf index is corrupt"
        );
        Ok(value)
    }
    fn subtree(&self, start: usize, size: usize) -> Result<Digest> {
        ensure!(
            size > 0 && start.checked_add(size).is_some_and(|n| n <= self.size),
            "History subtree position differs"
        );
        if size.is_power_of_two() && start.is_multiple_of(size) {
            let end = start + size;
            let position = count(end - 1)? + size.trailing_zeros() as usize;
            self.nodes.read(position)
        } else {
            let k = split(size);
            Ok(branch(
                &self.subtree(start, k)?,
                &self.subtree(start + k, size - k)?,
            ))
        }
    }
    fn range(&self, start: usize, size: usize) -> Result<Vec<Digest>> {
        ensure!(
            size <= SEGMENT && start.checked_add(size).is_some_and(|n| n <= self.size),
            "History range differs"
        );
        self.data.range(start, size)
    }
}
impl Archive {
    pub fn open(
        directory_path: &Path,
        configuration: Digest,
        size: u64,
        expected: Digest,
    ) -> Result<Self> {
        let dir = directory_path.join("History");
        directory(&dir)?;
        let quota_path = dir.join("QuotaBytes");
        let quota = match options().open(&quota_path) {
            Ok(mut f) => {
                private(&f)?;
                ensure!(
                    f.metadata()?.len() <= 32,
                    "History quota file exceeds bound"
                );
                let mut text = String::new();
                f.read_to_string(&mut text)?;
                text.trim().parse::<u64>()?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut f = options().create_new(true).mode(0o600).open(&quota_path)?;
                writeln!(f, "{DEFAULT_QUOTA}")?;
                super::timing::sync(&f, false)?;
                DEFAULT_QUOTA
            }
            Err(e) => return Err(e.into()),
        };
        let mut result = Self::empty(dir, configuration, quota);
        ensure!(
            size <= MAX_LEAVES as u64,
            "History height exceeds proof arithmetic"
        );
        let size = size as usize;
        result.reserve(size)?;
        let marker = result.directory.join("Ready");
        if !marker.try_exists()? && directory_path.join("History.bin").try_exists()? {
            result.data.truncate(0)?;
            result.nodes.truncate(0)?;
            let mut old = options().open(directory_path.join("History.bin"))?;
            private(&old)?;
            let mut header = [0; 48];
            old.read_exact(&mut header)?;
            ensure!(
                &header[..16] == LEGACY
                    && header[16..] == configuration
                    && old.metadata()?.len() >= 48 + size as u64 * 32,
                "Legacy history context or prefix differs"
            );
            let mut remaining = size;
            while remaining > 0 {
                let n = remaining.min(SEGMENT);
                let mut bytes = vec![0; n * 32];
                old.read_exact(&mut bytes)?;
                let values = bytes
                    .chunks_exact(32)
                    .map(|v| v.try_into().unwrap())
                    .collect::<Vec<_>>();
                result.append(result.size as u64, result.tree_root(), &values)?;
                remaining -= n;
            }
            ensure!(
                result.tree_root() == expected,
                "Legacy committed history is corrupt"
            );
        } else {
            result.data.truncate(size)?;
            result.nodes.truncate(count(size)?)?;
            let total_nodes = count(size)?;
            let mut indexed = Vec::new();
            let mut indexed_start = 0;
            for start in (0..size).step_by(SEGMENT) {
                for value in result.data.range(start, (size - start).min(SEGMENT))? {
                    let hashes = result.advance(value);
                    let first = count(result.size - 1)?;
                    for (offset, hash) in hashes.iter().enumerate() {
                        let position = first + offset;
                        if indexed.is_empty() || position >= indexed_start + indexed.len() {
                            indexed_start = position;
                            indexed = result
                                .nodes
                                .range(position, (total_nodes - position).min(SEGMENT))?;
                        }
                        ensure!(
                            indexed[position - indexed_start] == *hash,
                            "Committed history index is corrupt"
                        );
                    }
                }
            }
            ensure!(
                result.tree_root() == expected,
                "Committed history archive is corrupt"
            );
        }
        if !marker.try_exists()? {
            let mut f = options().create_new(true).mode(0o600).open(&marker)?;
            f.write_all(&configuration)?;
            super::timing::sync(&f, false)?;
        } else {
            let f = options().open(&marker)?;
            private(&f)?;
            let mut stored = [0; 32];
            f.read_exact_at(&mut stored, 0)?;
            ensure!(
                f.metadata()?.len() == 32 && stored == configuration,
                "History configuration differs"
            );
        }
        for entry in fs::read_dir(&result.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_prefix("Transfer") {
                ensure!(
                    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Invalid history transfer directory"
                );
                let m = fs::symlink_metadata(entry.path())?;
                ensure!(
                    m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
                    "Unowned history transfer directory"
                );
                fs::remove_dir_all(entry.path())?;
            }
        }
        super::timing::sync(&File::open(&result.directory)?, true)?;
        Ok(result)
    }
    fn empty(directory: PathBuf, configuration: Digest, quota: u64) -> Self {
        Self {
            data: Segments {
                directory: directory.clone(),
                configuration,
                kind: 0,
                tail: None,
            },
            nodes: Segments {
                directory: directory.clone(),
                configuration,
                kind: 1,
                tail: None,
            },
            directory,
            configuration,
            size: 0,
            frontier: Vec::new(),
            quota,
            poisoned: false,
        }
    }
    pub fn healthy(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "History archive is quarantined after a write failure"
        );
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn tree_root(&self) -> Digest {
        let mut right = None;
        for value in self.frontier.iter().flatten() {
            right = Some(right.map_or(*value, |r| branch(value, &r)));
        }
        right.unwrap_or_else(empty_root)
    }
    pub fn next_root(&self, value: Digest) -> Digest {
        let mut frontier = self.frontier.clone();
        push(&mut frontier, value);
        let mut right = None;
        for value in frontier.iter().flatten() {
            right = Some(right.map_or(*value, |r| branch(value, &r)));
        }
        right.unwrap_or_else(empty_root)
    }
    fn advance(&mut self, value: Digest) -> Vec<Digest> {
        let hashes = push(&mut self.frontier, value);
        self.size += 1;
        hashes
    }
    pub fn capacity(&self) -> Result<(u64, u64)> {
        let mut bytes = 0u64;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("Data") || name.starts_with("Nodes") {
                bytes = bytes
                    .checked_add(
                        fs::symlink_metadata(entry.path())?
                            .blocks()
                            .checked_mul(512)
                            .context("History block count overflow")?,
                    )
                    .context("History allocation overflow")?;
            }
        }
        Ok((bytes, self.quota))
    }
    pub fn reserve(&self, size: usize) -> Result<()> {
        ensure!(
            size <= MAX_LEAVES,
            "History size overflows proof arithmetic"
        );
        let entries = (size as u64)
            .checked_add(count(size)? as u64)
            .context("History byte count overflow")?;
        let charged = entries
            .checked_mul(32)
            .and_then(|n| n.checked_add(entries.div_ceil(SEGMENT as u64) * 8192 + 16384))
            .context("History allocation overflow")?;
        ensure!(
            charged <= self.quota,
            "History byte quota exhausted; increase History/QuotaBytes while the replica is stopped"
        );
        Ok(())
    }
    pub fn append(&mut self, prior_size: u64, prior_root: Digest, values: &[Digest]) -> Result<()> {
        self.healthy()?;
        ensure!(
            prior_size == self.size as u64 && prior_root == self.tree_root(),
            "History append prefix differs"
        );
        self.reserve(
            self.size
                .checked_add(values.len())
                .context("History size overflow")?,
        )?;
        let result = (|| -> Result<()> {
            for value in values {
                let position = count(self.size)?;
                self.data.write(self.size, value)?;
                for (offset, hash) in self.advance(*value).iter().enumerate() {
                    self.nodes.write(position + offset, hash)?;
                }
            }
            self.data.sync()?;
            self.nodes.sync()?;
            super::timing::sync(&File::open(&self.directory)?, true)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn find(&self, value: Digest, size: usize) -> Result<Option<usize>> {
        ensure!(size <= self.size, "History search position differs");
        for start in (0..size).step_by(SEGMENT) {
            if let Some(i) = self
                .range(start, (size - start).min(SEGMENT))?
                .iter()
                .position(|v| *v == value)
            {
                return Ok(Some(start + i));
            }
        }
        Ok(None)
    }
    pub fn stage(&self) -> Result<Staged> {
        let path = self.directory.join(format!(
            "Transfer{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        directory(&path)?;
        let mut staged = Staged {
            archive: Self::empty(path, self.configuration, self.quota),
        };
        for start in (0..self.size).step_by(SEGMENT) {
            let values = self.range(start, (self.size - start).min(SEGMENT))?;
            staged.archive.append(
                staged.archive.size as u64,
                staged.archive.tree_root(),
                &values,
            )?;
        }
        Ok(staged)
    }
    pub fn append_history(&mut self, history: &(impl History + ?Sized)) -> Result<()> {
        ensure!(
            self.size <= history.len() && history.root_at(self.size)? == self.tree_root(),
            "Transferred history replaces committed prefix"
        );
        while self.size < history.len() {
            let values = history.range(self.size, (history.len() - self.size).min(SEGMENT))?;
            self.append(self.size as u64, self.tree_root(), &values)?;
        }
        Ok(())
    }
}
fn push(frontier: &mut Vec<Option<Digest>>, value: Digest) -> Vec<Digest> {
    let mut carry = leaf(&value);
    let mut hashes = vec![carry];
    let mut level = 0;
    loop {
        if level == frontier.len() {
            frontier.push(Some(carry));
            break;
        }
        match frontier[level].take() {
            Some(left) => {
                carry = branch(&left, &carry);
                hashes.push(carry);
                level += 1;
            }
            None => {
                frontier[level] = Some(carry);
                break;
            }
        }
    }
    hashes
}
pub struct Staged {
    pub archive: Archive,
}
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.archive.directory);
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Consensus/ConsensusArchiveUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusArchive.rs");
