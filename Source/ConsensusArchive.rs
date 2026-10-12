// SPDX-License-Identifier: MIT
//! Append-only committed Node digests; the signer journal binds the authoritative prefix.
use super::records::Digest;
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const MAX_LEAVES: usize = 131072;
const MAGIC: &[u8; 16] = b"HyperNetHistory1";
const HEADER: u64 = 48;
pub fn empty_root() -> Digest {
    Sha256::digest([]).into()
}
fn leaf(value: &Digest) -> Digest {
    Sha256::digest([&[0][..], value].concat()).into()
}
fn branch(left: &Digest, right: &Digest) -> Digest {
    Sha256::digest([&[1][..], left, right].concat()).into()
}
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => empty_root(),
        1 => leaf(&leaves[0]),
        n => {
            let k = split(n);
            branch(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}
fn split(n: usize) -> usize {
    1usize << (usize::BITS - (n - 1).leading_zeros() - 1)
}
pub fn inclusion(leaves: &[Digest], index: usize) -> Result<Vec<Digest>> {
    ensure!(
        index < leaves.len() && leaves.len() <= MAX_LEAVES,
        "History inclusion position differs"
    );
    if leaves.len() == 1 {
        return Ok(vec![]);
    }
    let k = split(leaves.len());
    let (mut path, sibling) = if index < k {
        (inclusion(&leaves[..k], index)?, root(&leaves[k..]))
    } else {
        (inclusion(&leaves[k..], index - k)?, root(&leaves[..k]))
    };
    path.push(sibling);
    Ok(path)
}
pub fn consistency(leaves: &[Digest], old: usize) -> Result<Vec<Digest>> {
    ensure!(
        old > 0 && old <= leaves.len() && leaves.len() <= MAX_LEAVES,
        "History consistency size differs"
    );
    fn sub(leaves: &[Digest], old: usize, complete: bool) -> Vec<Digest> {
        if old == leaves.len() {
            return if complete { vec![] } else { vec![root(leaves)] };
        }
        let k = split(leaves.len());
        let (mut proof, sibling) = if old <= k {
            (sub(&leaves[..k], old, complete), root(&leaves[k..]))
        } else {
            (sub(&leaves[k..], old - k, false), root(&leaves[..k]))
        };
        proof.push(sibling);
        proof
    }
    Ok(sub(leaves, old, true))
}
pub struct Archive {
    file: File,
    leaves: Vec<Digest>,
    frontier: Vec<Option<Digest>>,
    poisoned: bool,
}
impl Archive {
    pub fn open(
        directory: &Path,
        configuration: Digest,
        size: u64,
        expected: Digest,
    ) -> Result<Self> {
        ensure!(
            size <= MAX_LEAVES as u64,
            "History archive exceeds its bound"
        );
        let path = directory.join("History.bin");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && size == 0 => {
                let mut file = options.create_new(true).mode(0o600).open(&path)?;
                file.write_all(MAGIC)?;
                file.write_all(&configuration)?;
                super::timing::sync(&file, false)?;
                super::timing::sync(&File::open(directory)?, true)?;
                file
            }
            Err(e) => return Err(e.into()),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "History archive is not an owned private regular file"
        );
        ensure!(
            metadata
                .blocks()
                .checked_mul(512)
                .is_some_and(|n| n <= MAX_LEAVES as u64 * 32 + 65536),
            "Archive allocation exceeds partition"
        );
        file.seek(SeekFrom::Start(0))?;
        if size == 0 && metadata.len() < HEADER {
            let canonical = [MAGIC.as_slice(), &configuration].concat();
            let mut partial = vec![0; metadata.len() as usize];
            file.read_exact(&mut partial)?;
            ensure!(
                canonical.starts_with(&partial),
                "Interrupted archive header belongs to another configuration"
            );
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&canonical)?;
            super::timing::sync(&file, false)?;
        }
        let metadata = file.metadata()?;
        file.seek(SeekFrom::Start(0))?;
        let length = HEADER + size * 32;
        ensure!(
            metadata.len() >= length && metadata.len() <= HEADER + MAX_LEAVES as u64 * 32,
            "History archive is incomplete or exceeds its bound"
        );
        let mut header = [0; HEADER as usize];
        file.read_exact(&mut header)?;
        ensure!(
            &header[..16] == MAGIC && header[16..] == configuration,
            "History archive configuration differs"
        );
        let mut leaves = vec![[0; 32]; size as usize];
        for value in &mut leaves {
            file.read_exact(value)?;
        }
        ensure!(
            root(&leaves) == expected,
            "Committed history archive is corrupt"
        );
        if metadata.len() > length {
            file.set_len(length)?;
            super::timing::sync(&file, false)?;
        }
        file.seek(SeekFrom::Start(length))?;
        let mut result = Self {
            file,
            leaves: vec![],
            frontier: vec![],
            poisoned: false,
        };
        for value in leaves {
            result.push(value);
        }
        Ok(result)
    }
    pub fn healthy(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "History archive is quarantined after a write failure"
        );
        Ok(())
    }
    pub fn leaves(&self) -> &[Digest] {
        &self.leaves
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
        let mut carry = leaf(&value);
        let mut level = 0;
        loop {
            if level == frontier.len() {
                frontier.push(Some(carry));
                break;
            }
            match frontier[level].take() {
                Some(left) => {
                    carry = branch(&left, &carry);
                    level += 1;
                }
                None => {
                    frontier[level] = Some(carry);
                    break;
                }
            }
        }
        let mut right = None;
        for value in frontier.iter().flatten() {
            right = Some(right.map_or(*value, |r| branch(value, &r)));
        }
        right.unwrap_or_else(empty_root)
    }
    fn push(&mut self, value: Digest) {
        let mut carry = leaf(&value);
        let mut level = 0;
        loop {
            if level == self.frontier.len() {
                self.frontier.push(Some(carry));
                break;
            }
            match self.frontier[level].take() {
                Some(left) => {
                    carry = branch(&left, &carry);
                    level += 1;
                }
                None => {
                    self.frontier[level] = Some(carry);
                    break;
                }
            }
        }
        self.leaves.push(value);
    }
    /// A caller publishes the resulting size/root in its journal only after this sync succeeds.
    pub fn append(&mut self, prior_size: u64, prior_root: Digest, values: &[Digest]) -> Result<()> {
        self.healthy()?;
        ensure!(
            prior_size as usize == self.leaves.len() && prior_root == self.tree_root(),
            "History append prefix differs"
        );
        ensure!(
            self.leaves
                .len()
                .checked_add(values.len())
                .context("History size overflow")?
                <= MAX_LEAVES,
            "History archive capacity exhausted"
        );
        let result = (|| -> Result<()> {
            for value in values {
                self.file.write_all(value)?;
            }
            super::timing::sync(&self.file, false)?;
            ensure!(
                self.file
                    .metadata()?
                    .blocks()
                    .checked_mul(512)
                    .is_some_and(|n| n <= MAX_LEAVES as u64 * 32 + 65536),
                "Archive allocation exceeds partition"
            );
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        for value in values {
            self.push(*value);
        }
        Ok(())
    }
}
