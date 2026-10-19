// SPDX-License-Identifier: MIT
// Native cold custody binds one installed volume and never creates a serving content catalogue.
use super::*;
use backup::package::{PACKAGE_LIMIT, Package};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, os::unix::fs::MetadataExt};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Entry {
    manifest: Vec<u8>,
    stored_bytes: u64,
    complete: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Catalogue {
    profile: Vec<u8>,
    device: u64,
    inode: u64,
    time_ms: u64,
    entries: BTreeMap<String, Entry>,
}
pub(super) struct Disk {
    directory: File,
    _lock: files::ProfileLock,
    path: PathBuf,
    catalogue: Catalogue,
    pub(super) profile: backup::Profile,
}
fn filename(id: &str) -> Result<String> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid archive filename"
    );
    Ok(format!("Archive{id}.cbor"))
}
fn read_at(directory: &File, name: &OsStr, maximum: usize, private: bool) -> Result<Vec<u8>> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };
    let name_c = CString::new(name.as_bytes())?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name_c.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("cannot inspect backup entry");
    }
    files::read_at(directory, name, maximum, private)
}
impl Disk {
    pub(super) fn initialise(root: &Path, p: &backup::Profile, surplus: u64) -> Result<PathBuf> {
        let directory = files::private_directory(root)?;
        let _lock = files::profile_lock(&directory, OsStr::new("BackupVolume"))?;
        let mut total = p.bytes;
        for item in std::fs::read_dir(root)? {
            let item = item?;
            if !item
                .file_name()
                .to_string_lossy()
                .starts_with("Destination")
            {
                continue;
            }
            let d = files::private_directory(&item.path())?;
            let bytes = match read_at(&d, OsStr::new("Catalogue.json"), 1024 * 1024, true) {
                Ok(bytes) => bytes,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                        && item.file_name()
                            == format!("Destination{}", hex::encode_upper(p.id)).as_str()
                        && std::fs::read_dir(item.path())?.next().is_none() =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let c: Catalogue = serde_json::from_slice(&bytes)?;
            let old =
                backup::Profile::parse(&c.profile, p.manifest.network, p.manifest.incarnation)?;
            ensure!(
                old.volume == p.volume && old.manifest.host == p.manifest.host,
                "backup volume contains another binding"
            );
            if old.id == p.id {
                ensure!(
                    old.envelope == p.envelope,
                    "backup destination already has different consent"
                );
                return Ok(item.path());
            }
            total = total
                .checked_add(old.bytes)
                .context("backup volume quota overflow")?;
        }
        ensure!(
            total <= surplus,
            "backup destination quotas exceed consented spare volume capacity"
        );
        let path = root.join(format!("Destination{}", hex::encode_upper(p.id)));
        let d = if path.try_exists()? {
            files::private_directory(&path)?
        } else {
            files::create_directory(&path)?
        };
        ensure!(
            std::fs::read_dir(&path)?.next().is_none(),
            "uninitialised backup destination is not empty"
        );
        let m = d.metadata()?;
        let catalogue = Catalogue {
            profile: p.envelope.clone(),
            device: m.dev(),
            inode: m.ino(),
            time_ms: 0,
            entries: BTreeMap::new(),
        };
        files::atomic_at(
            &d,
            OsStr::new("Catalogue.json"),
            &serde_json::to_vec(&catalogue)?,
            false,
        )?;
        Ok(path)
    }
    pub(super) fn open(
        root: &Path,
        id: [u8; 32],
        manifest: &crate::runtime_manifest::Manifest,
        now: u64,
    ) -> Result<Self> {
        let path = root.join(format!("Destination{}", hex::encode_upper(id)));
        let directory = files::private_directory(&path)?;
        let lock = files::profile_lock(&directory, OsStr::new("BackupDestination"))?;
        let catalogue: Catalogue = serde_json::from_slice(&read_at(
            &directory,
            OsStr::new("Catalogue.json"),
            1024 * 1024,
            true,
        )?)?;
        let profile =
            backup::Profile::parse(&catalogue.profile, manifest.network, manifest.incarnation)?;
        manifest.permits_definition(&profile.manifest)?;
        let m = directory.metadata()?;
        ensure!(
            profile.id == id
                && profile.manifest.host == manifest.host
                && catalogue.device == m.dev()
                && catalogue.inode == m.ino()
                && now >= catalogue.time_ms
                && catalogue.entries.len() <= profile.objects as usize,
            "backup destination binding or monotonic time differs"
        );
        let disk = Self {
            directory,
            _lock: lock,
            path,
            catalogue,
            profile,
        };
        disk.charge()?;
        disk.reconcile_files()?;
        Ok(disk)
    }
    fn reconcile_files(&self) -> Result<()> {
        use sha2::{Digest as _, Sha256};
        let lock_name = format!(
            "Network{}.lock",
            hex::encode(Sha256::digest(b"BackupDestination"))
        );
        for item in std::fs::read_dir(&self.path)? {
            let item = item?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid backup filename"))?;
            if name == "Catalogue.json" || name == lock_name {
                continue;
            }
            if name
                .strip_prefix("Archive")
                .and_then(|v| v.strip_suffix(".cbor"))
                .is_some_and(|id| self.catalogue.entries.contains_key(id))
            {
                continue;
            }
            if name
                .strip_prefix("Pending")
                .and_then(|v| v.strip_suffix(".bin"))
                .is_some_and(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                read_at(&self.directory, OsStr::new(&name), PACKAGE_LIMIT, true)?;
                files::remove_private_at(&self.directory, OsStr::new(&name))?;
            } else {
                anyhow::bail!("backup destination contains untracked data");
            }
        }
        Ok(())
    }
    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.catalogue)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "backup catalogue exceeds metadata bound"
        );
        files::atomic_at(&self.directory, OsStr::new("Catalogue.json"), &bytes, true)
    }
    fn charge(&self) -> Result<u64> {
        let mut total = serde_json::to_vec(&self.catalogue)?.len() as u64 * 2;
        for (id, e) in &self.catalogue.entries {
            let a = backup::Archive::parse(
                &e.manifest,
                self.profile.manifest.network,
                self.profile.manifest.incarnation,
            )?;
            ensure!(
                *id == hex::encode_upper(a.id)
                    && a.destination.id == self.profile.id
                    && e.stored_bytes <= PACKAGE_LIMIT as u64,
                "backup catalogue entry differs"
            );
            total = total
                .checked_add(e.stored_bytes)
                .context("backup physical extent overflow")?;
        }
        ensure!(
            total <= self.profile.bytes
                && self.catalogue.entries.len() <= self.profile.objects as usize,
            "backup physical or object quota exceeded"
        );
        Ok(total)
    }
    pub(super) fn purge(&mut self, now: u64, selected: Option<[u8; 32]>) -> Result<usize> {
        let mut remove = vec![];
        for (id, e) in &self.catalogue.entries {
            let a = backup::Archive::parse(
                &e.manifest,
                self.profile.manifest.network,
                self.profile.manifest.incarnation,
            )?;
            if a.expires_ms <= now || selected == Some(a.id) {
                remove.push(id.clone());
            }
        }
        for id in &remove {
            let name = filename(id)?;
            match read_at(&self.directory, OsStr::new(&name), PACKAGE_LIMIT, true) {
                Ok(_) => files::remove_private_at(&self.directory, OsStr::new(&name))?,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(e) => return Err(e),
            }
            self.catalogue.entries.remove(id);
        }
        self.catalogue.time_ms = now;
        self.save()?;
        Ok(remove.len())
    }
    pub(super) fn import(&mut self, bytes: &[u8], now: u64) -> Result<[u8; 32]> {
        self.purge(now, None)?;
        let p = Package::parse(
            bytes,
            self.profile.manifest.network,
            self.profile.manifest.incarnation,
        )?;
        ensure!(
            p.profile.envelope == self.profile.envelope,
            "archive names different destination consent"
        );
        p.archive.admitted(&self.profile, now)?;
        let id = hex::encode_upper(p.archive.id);
        let name = filename(&id)?;
        if let Some(old) = self.catalogue.entries.get(&id) {
            ensure!(
                old.manifest == p.archive.envelope && old.stored_bytes == bytes.len() as u64,
                "archive identifier already has different content"
            );
            if old.complete {
                ensure!(
                    read_at(&self.directory, OsStr::new(&name), PACKAGE_LIMIT, true)? == bytes,
                    "stored archive damaged"
                );
                return Ok(p.archive.id);
            }
        } else {
            self.catalogue.entries.insert(
                id.clone(),
                Entry {
                    manifest: p.archive.envelope.clone(),
                    stored_bytes: bytes.len() as u64,
                    complete: false,
                },
            );
            if let Err(e) = self.charge() {
                self.catalogue.entries.remove(&id);
                return Err(e);
            }
            self.save()?;
        }
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::fstatvfs(self.directory.as_raw_fd(), stat.as_mut_ptr()) } == 0,
            "cannot inspect backup free space"
        );
        let stat = unsafe { stat.assume_init() };
        ensure!(
            (stat.f_bavail as u128) * (stat.f_frsize as u128)
                >= (bytes.len() + 2 * serde_json::to_vec(&self.catalogue)?.len()) as u128,
            "backup physical storage is full"
        );
        match read_at(&self.directory, OsStr::new(&name), PACKAGE_LIMIT, true) {
            Ok(old) => ensure!(old == bytes, "incomplete archive contains different bytes"),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                files::atomic_at(&self.directory, OsStr::new(&name), bytes, false)?
            }
            Err(e) => return Err(e),
        }
        self.catalogue.entries.get_mut(&id).unwrap().complete = true;
        self.catalogue.time_ms = now;
        self.save()?;
        Ok(p.archive.id)
    }
    pub(super) fn export(&mut self, id: [u8; 32], now: u64) -> Result<Vec<u8>> {
        self.purge(now, None)?;
        let key = hex::encode_upper(id);
        let e = self
            .catalogue
            .entries
            .get(&key)
            .context("backup archive absent or expired")?;
        ensure!(e.complete, "backup import is incomplete");
        let bytes = read_at(
            &self.directory,
            OsStr::new(&filename(&key)?),
            PACKAGE_LIMIT,
            true,
        )?;
        let p = Package::parse(
            &bytes,
            self.profile.manifest.network,
            self.profile.manifest.incarnation,
        )?;
        ensure!(
            p.archive.envelope == e.manifest,
            "backup archive differs from catalogue"
        );
        Ok(bytes)
    }
    pub(super) fn list(&mut self, now: u64) -> Result<serde_json::Value> {
        self.purge(now, None)?;
        let mut entries = vec![];
        for e in self.catalogue.entries.values() {
            let a = backup::Archive::parse(
                &e.manifest,
                self.profile.manifest.network,
                self.profile.manifest.incarnation,
            )?;
            entries.push(serde_json::json!({"archive":hex::encode(a.id),"owner":hex::encode(a.owner),"bytes":e.stored_bytes,"expiresMs":a.expires_ms,"complete":e.complete}));
        }
        Ok(
            serde_json::json!({"status":"ColdBackupDestination","destination":hex::encode(self.profile.id),"name":self.profile.name,"directory":self.path,"chargedBytes":self.charge()?,"quotaBytes":self.profile.bytes,"archives":entries}),
        )
    }
}

#[cfg(test)]
#[path = "AuthorityBackupDiskTests.rs"]
mod tests;
