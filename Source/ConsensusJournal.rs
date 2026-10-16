// SPDX-License-Identifier: MIT
//! Exclusive, bounded, synchronised signer state. Checksums do not prove rollback resistance.
use anyhow::{Context, Result, ensure};
#[cfg(test)]
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 16] = b"HyperNetSigner1\0";
pub const MAXIMUM: usize = crate::authority_capacity::MAX_JOURNAL_BYTES;
const HEADER: usize = 64;

pub struct Journal {
    directory: PathBuf,
    _lock: File,
    owner_pid: libc::pid_t,
    generation: u64,
    poisoned: bool,
}
impl Drop for Journal {
    fn drop(&mut self) {
        if self.owner_pid == unsafe { libc::getpid() } {
            // A forked helper can retain this open description until exec. End
            // ownership explicitly when its creating process drops the journal.
            unsafe {
                libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "Signer journal is not an owned private regular file"
    );
    Ok(())
}
fn reader(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    private(&file)?;
    Ok(file)
}
impl Journal {
    fn lock(directory: &Path) -> Result<Self> {
        ensure!(
            directory.is_absolute() && directory.canonicalize()? == directory,
            "Signer directory must be canonical and absolute"
        );
        let m = fs::symlink_metadata(directory)?;
        ensure!(
            m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "Signer directory is not private and owned"
        );
        for ancestor in directory.ancestors().skip(1) {
            let m = fs::symlink_metadata(ancestor)?;
            ensure!(
                m.is_dir() && (m.mode() & 0o022 == 0 || m.uid() == 0 && m.mode() & 0o1000 != 0),
                "Signer ancestor permits replacement"
            );
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("Signer.lock"))?;
        private(&lock)?;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Signer journal is already owned by another process"
        );
        Ok(Self {
            directory: directory.to_path_buf(),
            _lock: lock,
            owner_pid: unsafe { libc::getpid() },
            generation: 0,
            poisoned: false,
        })
    }
    pub fn initialise(directory: &Path) -> Result<Self> {
        let journal = Self::lock(directory)?;
        for entry in fs::read_dir(directory)? {
            ensure!(
                entry?.file_name() == "Signer.lock",
                "Signer initialisation requires an empty directory"
            );
        }
        Ok(journal)
    }
    #[cfg(test)]
    pub fn create<T: Serialize>(directory: &Path, initial: &T) -> Result<Self> {
        let mut journal = Self::initialise(directory)?;
        journal.commit(initial)?;
        Ok(journal)
    }
    /// The minimum comes from independently retained state, not the snapshot being loaded.
    pub fn open<T: DeserializeOwned>(directory: &Path, minimum: u64) -> Result<(Self, T)> {
        let mut journal = Self::lock(directory)?;
        let file = reader(&directory.join("Signer.bin"))?;
        ensure!(
            (HEADER as u64..=(HEADER + MAXIMUM) as u64).contains(&file.metadata()?.len()),
            "Invalid signer snapshot size"
        );
        ensure!(
            file.metadata()?
                .blocks()
                .checked_mul(512)
                .is_some_and(|n| n <= crate::authority_capacity::MAX_JOURNAL_ALLOCATION),
            "Signer allocation exceeds metadata partition"
        );
        let mut bytes = Vec::new();
        file.take((HEADER + MAXIMUM + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= HEADER + MAXIMUM,
            "Signer snapshot exceeds its bound"
        );
        ensure!(
            bytes.len() >= HEADER && &bytes[..16] == MAGIC,
            "Invalid signer snapshot header"
        );
        let generation = u64::from_be_bytes(bytes[16..24].try_into()?);
        let length = u64::from_be_bytes(bytes[24..32].try_into()?);
        ensure!(
            generation > 0 && generation >= minimum && length == (bytes.len() - HEADER) as u64,
            "Signer snapshot is incomplete or below its retained floor"
        );
        ensure!(
            Sha256::digest(&bytes[HEADER..]).as_slice() == &bytes[32..HEADER],
            "Signer snapshot integrity failure"
        );
        let state =
            serde_json::from_slice(&bytes[HEADER..]).context("Invalid signer snapshot state")?;
        journal.generation = generation;
        Ok((journal, state))
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn healthy(&self) -> Result<()> {
        ensure!(
            self.owner_pid == unsafe { libc::getpid() },
            "Signer journal belongs to another process"
        );
        ensure!(
            !self.poisoned,
            "Signer journal is quarantined after a persistence failure"
        );
        Ok(())
    }
    #[cfg(test)]
    pub fn commit<T: Serialize>(&mut self, state: &T) -> Result<()> {
        self.healthy()?;
        let bytes = serde_json::to_vec(state)?;
        self.commit_encoded(&bytes)
    }
    pub(super) fn commit_encoded(&mut self, bytes: &[u8]) -> Result<()> {
        self.healthy()?;
        ensure!(bytes.len() <= MAXIMUM, "Signer journal capacity exhausted");
        let next = self
            .generation
            .checked_add(1)
            .context("Signer journal generation overflow")?;
        let operation = (|| -> Result<()> {
            let temporary = self.directory.join("SignerPending.bin");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&temporary)?;
            private(&file)?;
            file.set_len(0)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(MAGIC)?;
            file.write_all(&next.to_be_bytes())?;
            file.write_all(&(bytes.len() as u64).to_be_bytes())?;
            file.write_all(&Sha256::digest(bytes))?;
            file.write_all(bytes)?;
            super::timing::sync(&file, false)?;
            ensure!(
                file.metadata()?
                    .blocks()
                    .checked_mul(512)
                    .is_some_and(|n| n <= crate::authority_capacity::MAX_JOURNAL_ALLOCATION),
                "Signer allocation exceeds metadata partition"
            );
            fs::rename(temporary, self.directory.join("Signer.bin"))?;
            super::timing::sync(&File::open(&self.directory)?, true)?;
            Ok(())
        })();
        if operation.is_err() {
            self.poisoned = true;
        }
        operation?;
        self.generation = next;
        super::timing::journal_commit();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub struct Directory(pub PathBuf);
    impl Directory {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!("S{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn exclusive_restart_torn_state_and_retained_floor() {
        let path = Directory::new();
        let mut writer = Journal::create(&path.0, &vec![1u64]).unwrap();
        assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
        writer.commit(&vec![2u64]).unwrap();
        drop(writer);
        assert!(Journal::open::<Vec<u64>>(&path.0, 3).is_err());
        let (writer, value) = Journal::open::<Vec<u64>>(&path.0, 2).unwrap();
        assert_eq!(value, vec![2]);
        drop(writer);
        OpenOptions::new()
            .write(true)
            .open(path.0.join("Signer.bin"))
            .unwrap()
            .set_len(70)
            .unwrap();
        assert!(Journal::open::<Vec<u64>>(&path.0, 0).is_err());
    }
    #[test]
    fn owner_drop_releases_inherited_description_without_weakening_exclusion() {
        let path = Directory::new();
        let writer = Journal::create(&path.0, &vec![1u64]).unwrap();
        let inherited = writer._lock.try_clone().unwrap();
        assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
        drop(writer);
        let (mut resumed, value) = Journal::open::<Vec<u64>>(&path.0, 1).unwrap();
        assert_eq!(value, vec![1]);
        drop(inherited);
        assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
        let child_description = resumed._lock.try_clone().unwrap();
        resumed.owner_pid = 0;
        assert!(resumed.commit(&vec![2u64]).is_err());
        drop(resumed);
        assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
        drop(child_description);
        assert_eq!(Journal::open::<Vec<u64>>(&path.0, 1).unwrap().1, vec![1]);
    }
    #[test]
    fn failed_sync_path_poisoning_prevents_later_signer_progress() {
        let path = Directory::new();
        let mut writer = Journal::create(&path.0, &vec![1u64]).unwrap();
        std::os::unix::fs::symlink("Signer.bin", path.0.join("SignerPending.bin")).unwrap();
        assert!(writer.commit(&vec![2u64]).is_err());
        fs::remove_file(path.0.join("SignerPending.bin")).unwrap();
        assert!(writer.commit(&vec![3u64]).is_err());
    }
}
