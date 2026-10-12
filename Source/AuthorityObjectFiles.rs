// SPDX-License-Identifier: MIT
// Epoch object directories contain only the exact indexed immutable Page bodies.
use crate::{
    authority_capacity, authority_files as files,
    authority_objects::{EpochIndex, Reference},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    ffi::{CStr, OsStr, OsString},
    fs::File,
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
    path::Path,
};

pub const INDEX: &str = "Objects.cbor";

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(directory: &File, maximum: usize) -> Result<BTreeSet<OsString>> {
    let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure!(
        descriptor >= 0,
        "cannot duplicate object directory descriptor"
    );
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe {
            libc::close(descriptor);
        }
        anyhow::bail!("cannot inspect object directory");
    }
    let stream = DirectoryStream(stream);
    let mut names = BTreeSet::new();
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            ensure!(
                std::io::Error::last_os_error().raw_os_error() == Some(0),
                "cannot finish object directory inspection"
            );
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        ensure!(
            names.len() < maximum,
            "object directory contains unlisted files"
        );
        ensure!(
            names.insert(OsString::from_vec(name.to_vec())),
            "repeated object directory entry"
        );
    }
    Ok(names)
}

pub struct Directory {
    directory: File,
    index: EpochIndex,
}
impl Directory {
    /// Expected comes from independently verified terminal state, not this directory's index.
    pub fn open(path: &Path, expected: &EpochIndex) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let bytes = files::read_at(
            &directory,
            OsStr::new(INDEX),
            authority_capacity::MAX_STATE_BYTES,
            true,
        )?;
        let index = EpochIndex::parse(&bytes)?;
        ensure!(
            index.canonical()? == expected.canonical()?,
            "object directory names another terminal closure"
        );
        let mut wanted = BTreeSet::from([OsString::from(INDEX)]);
        wanted.extend(
            index
                .references()
                .iter()
                .map(|reference| OsString::from(reference.file_name())),
        );
        ensure!(
            names(&directory, wanted.len())? == wanted,
            "object directory differs from its exact index membership"
        );
        Ok(Self { directory, index })
    }
    pub fn index(&self) -> &EpochIndex {
        &self.index
    }
    pub fn read(&self, reference: &Reference) -> Result<Vec<u8>> {
        ensure!(
            self.index.references().binary_search(reference).is_ok(),
            "unlisted epoch input requested"
        );
        let bytes = files::read_at(
            &self.directory,
            OsStr::new(&reference.file_name()),
            reference.len(),
            true,
        )?;
        reference.verify(&bytes)?;
        Ok(bytes)
    }
    pub fn validate(&self) -> Result<()> {
        for reference in self.index.references() {
            self.read(reference)?;
        }
        Ok(())
    }
    /// Each file is durable before the index publishes the complete directory.
    pub fn create(
        path: &Path,
        index: &EpochIndex,
        mut load: impl FnMut(&Reference) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let directory = files::create_directory(path)?;
        for reference in index.references() {
            let bytes = load(reference)
                .with_context(|| format!("cannot export input {}", reference.file_name()))?;
            reference.verify(&bytes)?;
            files::atomic_at(
                &directory,
                OsStr::new(&reference.file_name()),
                &bytes,
                false,
            )?;
        }
        files::atomic_at(&directory, OsStr::new(INDEX), &index.canonical()?, false)?;
        Self::open(path, index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authority_objects::Class,
        trust_wire::{self as wire, Value as V},
    };
    use std::os::unix::fs::symlink;

    #[test]
    fn epoch_directory_rejects_extra_files_symlinks_and_different_bytes() {
        let root = crate::consensus::journal::tests::Directory::new();
        let state = wire::encode(&V::Array(vec![V::Uint(1)])).unwrap();
        let reference = Reference::for_bytes(Class::PageSource, b"exact publication").unwrap();
        let index = EpochIndex::new(&state, std::slice::from_ref(&reference)).unwrap();
        let path = root.0.join("Export");
        let directory =
            Directory::create(&path, &index, |_| Ok(b"exact publication".to_vec())).unwrap();
        directory.validate().unwrap();
        files::write_new(&path.join("Unlisted.bin"), b"unlisted").unwrap();
        assert!(Directory::open(&path, &index).is_err());
        std::fs::remove_file(path.join("Unlisted.bin")).unwrap();
        let body = path.join(reference.file_name());
        std::fs::remove_file(&body).unwrap();
        symlink(path.join(INDEX), &body).unwrap();
        assert!(Directory::open(&path, &index).unwrap().validate().is_err());
        std::fs::remove_file(&body).unwrap();
        files::write_new(&body, b"other publication").unwrap();
        assert!(Directory::open(&path, &index).unwrap().validate().is_err());
    }
}
