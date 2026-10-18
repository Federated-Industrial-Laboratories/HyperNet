// SPDX-License-Identifier: MIT
// Descriptor-relative file access rejects symlink traversal and publishes without replacement.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::{CString, OsStr},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};

fn name(value: &OsStr) -> Result<CString> {
    Ok(CString::new(value.as_bytes())?)
}
fn open_at(parent: &File, value: &OsStr, flags: i32, mode: u32) -> Result<File> {
    let value = name(value)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            value.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    ensure!(
        fd >= 0,
        "cannot open path safely: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory_handle(path: &Path) -> Result<File> {
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() { "/" } else { "." })?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => {
                current = open_at(&current, value, libc::O_PATH | libc::O_DIRECTORY, 0)?
            }
            _ => anyhow::bail!("parent traversal is not permitted"),
        }
    }
    ensure!(current.metadata()?.is_dir(), "expected a directory");
    Ok(current)
}
pub fn directory(path: &Path) -> Result<File> {
    let current = directory_handle(path)?;
    // Mutation callers need a readable final descriptor for directory fsync.
    open_at(
        &current,
        OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )
}
pub fn private_directory(path: &Path) -> Result<File> {
    let f = directory(path)?;
    let m = f.metadata()?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
        "directory must be owned by the current user and mode 0700"
    );
    Ok(f)
}
fn parent(path: &Path, readable: bool) -> Result<(File, &OsStr)> {
    let value = path.file_name().context("file name required")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((
        if readable {
            directory(parent)?
        } else {
            directory_handle(parent)?
        },
        value,
    ))
}
pub fn read(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let (parent, value) = parent(path, false)?;
    read_at(&parent, value, maximum, private)
}
pub fn read_single(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>> {
    let (parent, value) = parent(path, false)?;
    read_file(&parent, value, maximum, private, true)
}
pub fn read_at(parent: &File, value: &OsStr, maximum: usize, private: bool) -> Result<Vec<u8>> {
    read_file(parent, value, maximum, private, private)
}
fn read_file(
    parent: &File,
    value: &OsStr,
    maximum: usize,
    private: bool,
    single: bool,
) -> Result<Vec<u8>> {
    let f = open_at(parent, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let m = f.metadata()?;
    ensure!(!single || m.nlink() == 1, "input must have one hard link");
    ensure!(
        m.is_file() && m.len() <= maximum as u64,
        "input must be a bounded regular file"
    );
    if private {
        ensure!(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0 && m.nlink() == 1,
            "private file must be owned, mode 0600 and have one link"
        );
    }
    let mut bytes = Vec::new();
    f.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "input grew beyond its size limit");
    Ok(bytes)
}
pub fn create_directory(path: &Path) -> Result<File> {
    let (p, n) = parent(path, true)?;
    let n = name(n)?;
    ensure!(
        unsafe { libc::mkdirat(p.as_raw_fd(), n.as_ptr(), 0o700) } == 0,
        "cannot create private directory: {}",
        std::io::Error::last_os_error()
    );
    p.sync_all()?;
    private_directory(path)
}
pub fn atomic_at(parent: &File, destination: &OsStr, bytes: &[u8], replace: bool) -> Result<()> {
    let temporary = format!("Pending{}.bin", crate::random_hex::<16>());
    let temporary = CString::new(temporary)?;
    let destination = name(destination)?;
    let f = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(f >= 0, "cannot create private staging file");
    let mut f = unsafe { File::from_raw_fd(f) };
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?;
        let flags = if replace { 0 } else { libc::RENAME_NOREPLACE };
        ensure!(
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    parent.as_raw_fd(),
                    destination.as_ptr(),
                    flags,
                )
            } == 0,
            "cannot publish file without changing the destination policy: {}",
            std::io::Error::last_os_error()
        );
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, value) = parent(path, true)?;
    atomic_at(&parent, value, bytes, false)
}
pub fn remove_private_at(parent: &File, value: &OsStr) -> Result<()> {
    let file = open_at(parent, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "unsafe private removal target"
    );
    let value = name(value)?;
    ensure!(
        unsafe { libc::unlinkat(parent.as_raw_fd(), value.as_ptr(), 0) } == 0,
        "cannot remove private profile"
    );
    parent.sync_all()?;
    Ok(())
}
pub fn profile_lock(parent: &File, value: &OsStr) -> Result<File> {
    use sha2::{Digest, Sha256};
    let label = format!(
        "Network{}.lock",
        hex::encode(Sha256::digest(value.as_bytes()))
    );
    let file = open_at(
        parent,
        OsStr::new(&label),
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        0o600,
    )?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1,
        "unsafe profile lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another command owns this profile"
    );
    parent.sync_all()?;
    Ok(file)
}
#[cfg(test)]
pub struct Destination {
    parent: File,
    name: CString,
}
#[cfg(test)]
impl Destination {
    pub fn open(path: &Path) -> Result<Self> {
        let p = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = private_directory(p)?;
        let value = path.file_name().context("destination file name required")?;
        let value = name(value)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                value.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        ensure!(
            result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
            "destination must not already exist"
        );
        Ok(Self {
            parent,
            name: value,
        })
    }
    pub fn publish(self, bytes: &[u8]) -> Result<()> {
        atomic_at(
            &self.parent,
            OsStr::from_bytes(self.name.as_bytes()),
            bytes,
            false,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn publication_rejects_symlinks_traversal_and_destination_races() {
        let root = std::env::temp_dir().join(format!(
            "HyperNetTransferFiles{}",
            crate::random_hex::<16>()
        ));
        create_directory(&root).unwrap();
        let output = root.join("Output");
        let destination = Destination::open(&output).unwrap();
        write_new(&output, b"existing").unwrap();
        assert!(destination.publish(b"replacement").is_err());
        assert_eq!(read(&output, 64, true).unwrap(), b"existing");
        symlink(&root, root.join("Link")).unwrap();
        assert!(Destination::open(&root.join("Link/Bad")).is_err());
        assert!(read(&root.join("Link/Output"), 64, false).is_err());
        assert!(Destination::open(&root.join("../Escape")).is_err());
        assert!(read(Path::new("/dev/zero"), 64, false).is_err());
        Destination::open(&root.join("Good"))
            .unwrap()
            .publish(b"complete")
            .unwrap();
        assert_eq!(read(&root.join("Good"), 64, true).unwrap(), b"complete");
        std::fs::remove_dir_all(root).unwrap();
    }
}
