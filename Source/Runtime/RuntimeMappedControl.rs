// SPDX-License-Identifier: MIT
// Inspect exact private mapped control metadata without exposing a native application account.
use crate::authority_files as files;
use anyhow::{Context, Result, ensure};
use std::path::Path;
use std::{
    fs::OpenOptions,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub fn inspect_mapped(path: &Path) -> Result<serde_json::Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "mapped control inspection requires the rootless user namespace"
    );
    let mapping = std::fs::read_to_string("/proc/self/uid_map")?;
    let first = mapping
        .lines()
        .next()
        .context("user namespace mapping absent")?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        first.len() == 3 && first[0] == 0 && first[1] != 0 && first[2] == 1,
        "mapped control inspection requires Podman's rootless parent mapping"
    );
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "mapped control directory must be canonical"
    );
    let directory = files::directory(path)?;
    let info = directory.metadata()?;
    ensure!(
        info.uid() == 1001 && info.gid() == 1001 && info.mode() & 0o7777 == 0o700,
        "mapped control ingress requires mapped UID1001:GID1001 and mode0700"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(
            Path::new("/proc/self/fd")
                .join(directory.as_raw_fd().to_string())
                .join("Binding.json"),
        )?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 1001
            && metadata.gid() == 1001
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() <= 16384,
        "mapped control binding requires one private mapped regular file"
    );
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16384,
        "mapped control binding exceeds its bound"
    );
    let binding: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(
        binding.is_object(),
        "mapped control binding must be an object"
    );
    Ok(
        serde_json::json!({"binding":binding,"encoded":hex::encode(bytes),"device":info.dev(),"inode":info.ino()}),
    )
}

pub fn inspect_host(path: &Path) -> Result<serde_json::Value> {
    crate::runtime_management::files::safe_path(path)?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "mapped control directory must be canonical"
    );
    crate::runtime_management::files::ancestors(
        path.parent()
            .context("mapped control parent directory absent")?,
    )?;
    let before = std::fs::symlink_metadata(path)?;
    ensure!(
        before.is_dir() && before.mode() & 0o7777 == 0o700,
        "mapped control ingress must be a private directory"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let bytes =
        crate::runtime_management::files::podman(&crate::runtime_management::files::strings(&[
            "unshare",
            executable
                .to_str()
                .context("executable path is not UTF-8")?,
            "runtime",
            "services",
            "mapped-control-check",
            "--directory",
            path.to_str().context("mapped control path is not UTF-8")?,
        ]))?;
    let result: serde_json::Value = serde_json::from_slice(&bytes)?;
    let after = std::fs::symlink_metadata(path)?;
    ensure!(
        result["device"] == before.dev()
            && result["inode"] == before.ino()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid(),
        "mapped control ingress changed or differs from exact local consent"
    );
    Ok(result)
}
