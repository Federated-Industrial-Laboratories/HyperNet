// SPDX-License-Identifier: MIT
use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const MAXIMUM: usize = 262144;
pub fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn random_id() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
pub fn selinux_enabled() -> Result<bool> {
    match fs::read("/sys/fs/selinux/enforce") {
        Ok(value) => {
            ensure!(
                value == b"0" || value == b"1" || value == b"0\n" || value == b"1\n",
                "Invalid SELinux kernel state"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
pub fn now() -> Result<u64> {
    crate::store::now()
}
pub fn private_dir(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o077 == 0,
        "Private owner directory required"
    );
    Ok(())
}
pub fn root(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "Runtime directory must be absolute");
    private_dir(path)?;
    let resolved = path.canonicalize()?;
    ensure!(
        resolved == path,
        "Runtime directory cannot contain symbolic links or relative components"
    );
    ancestors(path)?;
    Ok(resolved)
}
pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o077 == 0,
        "Private regular owner file required"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "Runtime file exceeds its bound");
    Ok(bytes)
}
pub fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, MAXIMUM)?)?)
}
pub fn receipt(path: &Path) -> Result<Vec<u8>> {
    private_dir(path.parent().context("Receipt parent required")?)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.len() <= 128,
        "Invalid container receipt"
    );
    // Podman creates public CID metadata inside the private deployment directory.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 128, "Container receipt exceeds bound");
    Ok(bytes)
}
pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("Parent required")?)?.sync_all()?;
    Ok(())
}
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAXIMUM, "Runtime state exceeds its bound");
    let parent = path.parent().context("Parent required")?;
    private_dir(parent)?;
    let pending = parent.join(format!("Pending{}", random_id()));
    if let Err(error) = create(&pending, &bytes) {
        let full = error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| matches!(e.raw_os_error(), Some(libc::ENOSPC) | Some(libc::EDQUOT)));
        let reserve = parent.join("FailureReserve");
        if full && reserve.exists() {
            let m = fs::symlink_metadata(&reserve)?;
            ensure!(
                m.is_file()
                    && m.uid() == unsafe { libc::geteuid() }
                    && m.nlink() == 1
                    && m.mode() & 0o077 == 0
                    && m.len() == 1048576,
                "Invalid failure reserve"
            );
            fs::remove_file(&reserve)?;
            if pending.exists() {
                fs::remove_file(&pending)?;
            }
            create(&pending, &bytes)?;
        } else {
            return Err(error);
        }
    }
    fs::rename(pending, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn reserve(root: &Path) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("FailureReserve"))?;
    let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, 1048576) };
    ensure!(result == 0, "Cannot reserve failure-reporting storage");
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}
pub fn capacity(root: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(root.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } == 0,
        "Cannot inspect runtime storage capacity"
    );
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .context("Storage capacity overflow")
}
pub fn directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn ancestors(path: &Path) -> Result<()> {
    for parent in path.ancestors() {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir()
                && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
                && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0)),
            "Runtime ancestor is writable by another account"
        );
    }
    Ok(())
}
pub fn safe_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("UTF-8 path required")?;
    ensure!(
        text.len() <= 4096
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_. -".contains(&b)),
        "Path contains unsupported delimiters or controls"
    );
    Ok(())
}
pub fn lock(path: &Path) -> Result<File> {
    private_dir(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.join("Lock"))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o077 == 0,
        "Invalid lifecycle lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0,
        "Cannot lock runtime"
    );
    Ok(file)
}
pub fn manager_lock(path: &Path) -> Result<File> {
    private_dir(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.join("Lock"))?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o077 == 0,
        "Invalid manager lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Runtime manager already active"
    );
    Ok(file)
}
pub fn executable(path: &Path) -> Result<String> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "Executable must be an absolute canonical path"
    );
    let file = File::open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.mode() & 0o022 == 0
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() }),
        "Executable is writable by another account"
    );
    ensure!(
        m.len() <= 128 * 1024 * 1024,
        "Executable exceeds size bound"
    );
    let mut digest = Sha256::new();
    let mut reader = file;
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
pub fn run(program: &Path, arguments: &[String], timeout: u64) -> Result<Vec<u8>> {
    ensure!(program.is_absolute(), "Absolute executable required");
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    for name in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().context("Missing command output")?;
    let mut stderr = child.stderr.take().context("Missing command error")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
            "Cannot bound command output"
        );
    }
    let mut bytes = Vec::new();
    let mut errors = Vec::new();
    let mut out_closed = false;
    let mut err_closed = false;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let outcome = (|| -> Result<_> {
        loop {
            for (pipe, output, closed) in [
                (&mut stdout as &mut dyn Read, &mut bytes, &mut out_closed),
                (&mut stderr as &mut dyn Read, &mut errors, &mut err_closed),
            ] {
                let mut buffer = [0u8; 8192];
                loop {
                    match pipe.read(&mut buffer) {
                        Ok(0) => {
                            *closed = true;
                            break;
                        }
                        Ok(n) => {
                            ensure!(
                                output.len() + n <= MAXIMUM,
                                "Runtime dependency output exceeded its bound"
                            );
                            output.extend_from_slice(&buffer[..n]);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            if let Some(status) = child.try_wait()?
                && out_closed
                && err_closed
            {
                break Ok(status);
            }
            ensure!(Instant::now() < deadline, "Runtime dependency timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if outcome.is_err() {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
    }
    let status = outcome?;
    ensure!(
        status.success(),
        "{} {} refused operation ({})",
        program.file_name().unwrap_or_default().to_string_lossy(),
        arguments.first().map_or("", String::as_str),
        status
    );
    Ok(bytes)
}
pub fn podman(arguments: &[String]) -> Result<Vec<u8>> {
    run(Path::new("/usr/bin/podman"), arguments, 45)
}
pub fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|x| x.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_reads_refuse_links_and_special_files() {
        let root = std::env::temp_dir().join(format!("HyperNetRuntimeFiles{}", random_id()));
        directory(&root).unwrap();
        create(&root.join("Original"), b"private").unwrap();
        fs::hard_link(root.join("Original"), root.join("Linked")).unwrap();
        assert!(read(&root.join("Linked"), 64).is_err());
        std::os::unix::fs::symlink("Original", root.join("Symbolic")).unwrap();
        assert!(read(&root.join("Symbolic"), 64).is_err());
        use std::os::unix::ffi::OsStrExt;
        let fifo = std::ffi::CString::new(root.join("Fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read(&root.join("Fifo"), 64).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
