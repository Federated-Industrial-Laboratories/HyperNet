// SPDX-License-Identifier: MIT
// Fixed-size two-bank persistence; no directory writes or auxiliary payload files.
use crate::{mail_authority::hash, media_types::*};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const MAGIC: &[u8; 16] = b"HyperNetMedia1\0\0";
const HEADER: u64 = 64;
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub source_digest: String,
    pub digest: String,
    pub bytes: u64,
    pub payload: String,
    pub stored_bytes: u64,
    pub status: String,
    pub receipt: crate::types::Envelope,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub authority_signer: String,
    pub host_generation: u64,
    pub authority_revision: i64,
    pub authority_epoch: u64,
    pub time: u64,
    pub records: BTreeMap<String, Record>,
}
pub struct Disk {
    file: File,
    bank_size: u64,
    active: usize,
    generation: u64,
    active_bytes: u64,
    poisoned: bool,
    pub state: State,
}
fn read_bank(file: &File, offset: u64, bank_size: u64) -> Result<Option<(u64, State)>> {
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, offset)?;
    if &header[..16] != MAGIC {
        return Ok(None);
    }
    let generation = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let length = u64::from_le_bytes(header[24..32].try_into().unwrap());
    if generation == 0 || length == 0 || length > bank_size - HEADER {
        return Ok(None);
    }
    let mut bytes = vec![0; length as usize];
    file.read_exact_at(&mut bytes, offset + HEADER)?;
    if hash(&bytes) != hex::encode(&header[32..]) {
        return Ok(None);
    }
    Ok(Some((
        generation,
        serde_json::from_slice(&bytes).context("Invalid media state")?,
    )))
}
fn zero(file: &File, offset: u64, length: u64) -> Result<()> {
    let block = [0u8; 65536];
    let mut written = 0;
    while written < length {
        let count = (length - written).min(block.len() as u64) as usize;
        file.write_all_at(&block[..count], offset + written)?;
        written += count as u64;
    }
    Ok(())
}
impl Disk {
    pub fn open(path: &Path, consent: &HostConsent, now: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.len() == consent.state_bytes,
            "media state must be an owned private preallocated file of its exact consented size"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "media state is already in use"
        );
        let bank_size = consent.state_bytes / 2;
        let a = read_bank(&file, 0, bank_size)?;
        let b = read_bank(&file, bank_size, bank_size)?;
        let selected = match (a, b) {
            (Some(a), Some(b)) => {
                if a.0 >= b.0 {
                    Some((0, a))
                } else {
                    Some((1, b))
                }
            }
            (Some(a), None) => Some((0, a)),
            (None, Some(b)) => Some((1, b)),
            (None, None) => None,
        };
        let (active, generation, state) = if let Some((active, (generation, state))) = selected {
            (active, generation, state)
        } else {
            // An established but damaged file cannot silently become a new empty mediabox.
            let mut block = vec![0u8; 65536];
            let mut offset = 0;
            while offset < consent.state_bytes {
                let count = (consent.state_bytes - offset).min(block.len() as u64) as usize;
                file.read_exact_at(&mut block[..count], offset)?;
                ensure!(
                    block[..count].iter().all(|b| *b == 0),
                    "media state has no recoverable committed bank"
                );
                offset += count as u64;
            }
            (
                0,
                0,
                State {
                    version: 1,
                    network: consent.network.clone(),
                    host_key: consent.host_key.clone(),
                    authority_signer: consent.authority_signer.clone(),
                    host_generation: consent.generation,
                    authority_revision: 0,
                    authority_epoch: 0,
                    time: now,
                    records: BTreeMap::new(),
                },
            )
        };
        ensure!(
            state.version == 1
                && state.network == consent.network
                && state.host_key == consent.host_key
                && state.authority_signer == consent.authority_signer
                && state.host_generation <= consent.generation
                && state.time <= now,
            "media state identity or monotonic floor mismatch"
        );
        let disk = Self {
            file,
            bank_size,
            active,
            generation,
            active_bytes: serde_json::to_vec(&state)?.len() as u64,
            poisoned: false,
            state,
        };
        zero(&disk.file, (1 - active) as u64 * bank_size, bank_size)?;
        disk.file.sync_all()?;
        Ok(disk)
    }
    pub fn commit(&mut self, mut state: State) -> Result<()> {
        ensure!(
            !self.poisoned,
            "media state requires recovery after a failed write"
        );
        ensure!(state.time >= self.state.time, "MediaRollback");
        let observed_time = state.time;
        state.time = self.state.time;
        let unchanged = state == self.state;
        state.time = observed_time;
        if unchanged {
            // Fresh leases remain mandatory; an unchanged floor does not rewrite ciphertext.
            self.state.time = observed_time;
            return Ok(());
        }
        let bytes = serde_json::to_vec(&state)?;
        ensure!(
            bytes.len() as u64 <= self.bank_size - HEADER,
            "MediaQuotaExceeded"
        );
        let next = self
            .generation
            .checked_add(1)
            .context("media generation exhausted")?;
        let target = 1 - self.active;
        let offset = target as u64 * self.bank_size;
        self.poisoned = true;
        self.file.write_all_at(&bytes, offset + HEADER)?;
        self.file.sync_data()?;
        let mut header = [0u8; 64];
        header[..16].copy_from_slice(MAGIC);
        header[16..24].copy_from_slice(&next.to_le_bytes());
        header[24..32].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        header[32..].copy_from_slice(&hex::decode(hash(&bytes))?);
        self.file.write_all_at(&header, offset)?;
        self.file.sync_all()?;
        self.state = state;
        self.active = target;
        self.generation = next;
        zero(
            &self.file,
            (1 - target) as u64 * self.bank_size,
            HEADER + self.active_bytes,
        )?;
        self.file.sync_all()?;
        self.active_bytes = bytes.len() as u64;
        self.poisoned = false;
        Ok(())
    }
    pub fn floor(&self, revision: i64, epoch: u64, host_generation: u64, now: u64) -> Result<()> {
        ensure!(
            revision > 0
                && revision >= self.state.authority_revision
                && epoch >= self.state.authority_epoch
                && host_generation >= self.state.host_generation
                && now >= self.state.time,
            "MediaRollback"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn committed_bank_survives_partial_next_write_and_old_bytes_are_cleared() {
        let path = std::env::temp_dir().join(format!("HyperNetMediaDisk{}", std::process::id()));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(8 * 1024 * 1024).unwrap();
        let consent = HostConsent {
            version: 1,
            network: "11".repeat(32),
            host_key: "22".repeat(32),
            generation: 1,
            services: vec!["PageMedia".into()],
            namespaces: vec!["Public".into()],
            retention_seconds: 86400,
            endpoint: "https://example.test:8443".into(),
            address: "127.0.0.1:8443".parse().unwrap(),
            ca_digest: "33".repeat(32),
            certificate_digest: "44".repeat(32),
            authority_endpoint: "https://authority.test:8443".into(),
            authority_address: "127.0.0.1:8443".parse().unwrap(),
            authority_signer: "55".repeat(32),
            memory_bytes: 512 * 1024 * 1024,
            pids: 64,
            cpu_quota: 100000,
            cpu_period: 100000,
            state_bytes: 8 * 1024 * 1024,
            expires: 1000,
        };
        {
            let mut disk = Disk::open(&path, &consent, 100).unwrap();
            let mut state = disk.state.clone();
            state.authority_revision = 7;
            disk.commit(state).unwrap();
            let committed = disk.generation;
            let mut same = disk.state.clone();
            same.time = 101;
            disk.commit(same).unwrap();
            assert_eq!(disk.generation, committed);
            assert_eq!(disk.state.time, 101);
            assert!(disk.floor(6, 0, 1, 101).is_err());
            assert!(Disk::open(&path, &consent, 100).is_err());
            file.write_all_at(
                b"partial uncommitted bytes",
                (1 - disk.active) as u64 * disk.bank_size + HEADER,
            )
            .unwrap();
            file.sync_all().unwrap();
        }
        let mut disk = Disk::open(&path, &consent, 100).unwrap();
        assert_eq!(disk.state.authority_revision, 7);
        let mut bytes = vec![0; consent.state_bytes as usize];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert!(!bytes.windows(7).any(|b| b == b"partial"));
        let mut state = disk.state.clone();
        state.authority_revision = 8;
        disk.commit(state).unwrap();
        assert!(disk.floor(7, 1, 1, 100).is_err());
        drop(disk);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Disk::open(&path, &consent, 100).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
