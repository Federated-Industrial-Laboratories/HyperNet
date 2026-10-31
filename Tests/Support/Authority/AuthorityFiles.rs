// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
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
