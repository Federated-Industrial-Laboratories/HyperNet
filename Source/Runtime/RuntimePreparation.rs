// SPDX-License-Identifier: MIT
// Publish only a complete durable workload tree; retain all existing voter data.
use super::super::{files::*, model::Profile};
use anyhow::{Context, Result, ensure};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Preparation {
    configuration: String,
    device: Option<u64>,
    inode: Option<u64>,
}
fn ensure_directory(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        directory(path)?;
    }
    private_dir(path)
}
fn prepared_file(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure!(
            read(path, MAXIMUM)? == bytes,
            "Partial preparation content differs"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(path, bytes)?,
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn sync_preparation(
    path: &Path,
    files: &std::collections::BTreeSet<std::path::PathBuf>,
) -> Result<()> {
    private_dir(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            sync_preparation(&entry.path(), files)?;
        } else {
            ensure!(
                metadata.is_file() && files.contains(&entry.path()),
                "Unexpected preparation content; no data removed"
            );
        }
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
fn publish_preparation(root: &Path, preparation: &Preparation) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let launch = root.join("Launch");
    let pending = root.join("LaunchPending");
    let location = if launch.exists() { &launch } else { &pending };
    let metadata = fs::symlink_metadata(location)?;
    ensure!(
        metadata.is_dir()
            && Some(metadata.dev()) == preparation.device
            && Some(metadata.ino()) == preparation.inode,
        "Prepared directory identity differs; no data removed"
    );
    if location == &pending {
        let from = std::ffi::CString::new(pending.as_os_str().as_bytes())?;
        let to = std::ffi::CString::new(launch.as_os_str().as_bytes())?;
        ensure!(
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "Cannot publish the exact prepared directory: {}",
            std::io::Error::last_os_error()
        );
        fs::File::open(root)?.sync_all()?;
    }
    Ok(())
}
pub fn prepare(root: &Path, p: &Profile) -> Result<()> {
    let journal = root.join("Preparation.json");
    let pending = root.join("LaunchPending");
    let digest = p.configuration_digest()?;
    let mut preparation: Preparation = if journal.exists() {
        super::super::files::json(&journal)?
    } else {
        ensure!(
            !pending.exists() && !root.join("Launch").exists(),
            "Unrecorded preparation directory; no data removed"
        );
        let preparation = Preparation {
            configuration: digest.clone(),
            device: None,
            inode: None,
        };
        super::super::files::save(&journal, &preparation)?;
        preparation
    };
    ensure!(
        preparation.configuration == digest
            && preparation.device.is_some() == preparation.inode.is_some(),
        "Preparation intent differs from profile"
    );
    if preparation.inode.is_some() {
        let location = if root.join("Launch").exists() {
            root.join("Launch")
        } else {
            pending.clone()
        };
        for relative in ["State/Authority", "State/Control"] {
            podman(&strings(&[
                "unshare",
                "/usr/bin/test",
                "-d",
                location.join(relative).to_str().unwrap(),
            ]))
            .context("Prepared authority layout differs; explicit offline migration is required")?;
        }
        podman(&strings(&[
            "unshare",
            "/usr/bin/test",
            "!",
            "-e",
            location.join("State/Replica").to_str().unwrap(),
        ]))
        .context("Old prepared signer layout requires explicit offline migration")?;
        return publish_preparation(root, &preparation);
    }
    ensure!(
        !root.join("Launch").exists(),
        "Incomplete preparation cannot own a published directory"
    );
    if pending.exists() {
        ensure!(
            fs::symlink_metadata(&pending)?.is_dir(),
            "Preparation must be a directory"
        );
        // This tree has never been mounted by a workload. Resume a partial ownership change.
        podman(&strings(&[
            "unshare",
            "/usr/bin/chown",
            "-R",
            "-h",
            "0:0",
            pending.to_str().unwrap(),
        ]))?;
    }
    ensure_directory(&pending)?;
    let mut files = std::collections::BTreeSet::new();
    for (relative, digest) in &p.artifacts {
        if let Some(part) = relative.strip_prefix("Work/") {
            ensure!(
                Path::new(part)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
                "Invalid preparation destination"
            );
            let destination = pending.join(part);
            let mut ancestors = destination
                .parent()
                .unwrap()
                .ancestors()
                .take_while(|d| *d != pending)
                .collect::<Vec<_>>();
            ancestors.reverse();
            for directory in ancestors {
                ensure_directory(directory)?;
            }
            let bytes = read(&root.join(relative), MAXIMUM)?;
            ensure!(
                hex_digest(&bytes) == *digest,
                "Generated configuration changed"
            );
            prepared_file(&destination, &bytes)?;
            files.insert(destination);
        }
    }
    let state = pending.join("State");
    ensure_directory(&state)?;
    ensure!(
        fs::read_dir(&state)?
            .all(|entry| entry
                .is_ok_and(|e| e.file_name() == "Control" || e.file_name() == "Authority"))
            && !state.join("Replica").exists(),
        "Unpublished signer state requires explicit recovery; no data removed"
    );
    ensure_directory(&state.join("Authority"))?;
    ensure!(
        fs::read_dir(state.join("Authority"))?.next().is_none(),
        "Unpublished authority directory contains signer state"
    );
    ensure_directory(&state.join("Control"))?;
    ensure!(
        fs::read_dir(state.join("Control"))?.next().is_none(),
        "Unpublished control directory contains unowned data"
    );
    sync_preparation(&pending, &files)?;
    podman(&strings(&[
        "unshare",
        "/usr/bin/chown",
        "-R",
        "-h",
        "1001:1001",
        pending.to_str().unwrap(),
    ]))?;
    podman(&strings(&[
        "unshare",
        "/usr/bin/sync",
        "--file-system",
        pending.to_str().unwrap(),
    ]))?;
    let metadata = fs::symlink_metadata(&pending)?;
    preparation.device = Some(metadata.dev());
    preparation.inode = Some(metadata.ino());
    super::super::files::save(&journal, &preparation)?;
    publish_preparation(root, &preparation)
}

pub(in crate::runtime_management) fn successor(root: &Path, p: &Profile) -> Result<()> {
    let mut preparation: Preparation = super::super::files::json(&root.join("Preparation.json"))?;
    let metadata = fs::symlink_metadata(root.join("Launch"))?;
    ensure!(
        metadata.is_dir()
            && Some(metadata.dev()) == preparation.device
            && Some(metadata.ino()) == preparation.inode,
        "Stopped successor cannot replace the retained launch directory"
    );
    preparation.configuration = p.configuration_digest()?;
    super::super::files::save(&root.join("Preparation.json"), &preparation)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimePreparationUnitTests.rs"]
mod tests;
