// SPDX-License-Identifier: MIT
//! Stopped cutovers retain the installed package floor through activation.
use super::files;
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Args)]
pub struct Inputs {
    #[arg(long, requires = "installed_prefix")]
    trust_directory: Option<PathBuf>,
    #[arg(long, requires = "installed_prefix")]
    public_key: Option<PathBuf>,
    #[arg(long, requires = "installed_prefix")]
    policy: Option<PathBuf>,
    #[arg(long, requires = "installed_prefix")]
    policy_signature: Option<PathBuf>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    prefix: PathBuf,
    trust_directory: PathBuf,
    public_key: PathBuf,
    public_key_digest: String,
    policy: PathBuf,
    policy_signature: PathBuf,
    verifier: PathBuf,
    verifier_digest: String,
    module_digest: String,
    target_digest: String,
}
pub(super) struct Admission {
    _lock: File,
    trust: PathBuf,
    digest: String,
    not_before: u64,
    expires: u64,
}
impl Admission {
    pub(super) fn fresh(&self) -> Result<()> {
        let bytes = files::read(&self.trust.join("Trust.json"), files::MAXIMUM)?;
        ensure!(
            files::hex_digest(&bytes) == self.digest,
            "Package trust changed during stopped cutover"
        );
        let trust: Value = serde_json::from_slice(&bytes)?;
        let now = files::now()?;
        ensure!(
            now >= trust["lastTime"]
                .as_u64()
                .context("Invalid package clock floor")?
                && now >= self.not_before
                && now < self.expires,
            "Package authorization expired or clock moved backwards"
        );
        Ok(())
    }
}
fn argument(path: &Path) -> Result<String> {
    files::safe_path(path)?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "Canonical package path required"
    );
    Ok(path.to_str().context("Non-UTF8 package path")?.into())
}
fn verified(selection: &Selection, historical: bool) -> Result<Value> {
    ensure!(
        files::executable(&selection.verifier)? == selection.verifier_digest
            && files::executable(&selection.verifier.with_file_name("PackageTrust.py"))?
                == selection.module_digest,
        "Previously trusted package verifier changed"
    );
    ensure!(
        files::executable(&selection.public_key)? == selection.public_key_digest,
        "Reviewed release public key changed"
    );
    let mut arguments = vec![
        argument(&selection.verifier)?,
        if historical {
            "InspectInstalledTarget"
        } else {
            "AdmitInstalled"
        }
        .into(),
        "--prefix".into(),
        argument(&selection.prefix)?,
        "--public-key".into(),
        argument(&selection.public_key)?,
        "--policy".into(),
        argument(&selection.policy)?,
        "--policy-signature".into(),
        argument(&selection.policy_signature)?,
    ];
    if !historical {
        arguments.extend([
            "--trust-directory".into(),
            argument(&selection.trust_directory)?,
        ]);
    }
    let output = files::capture(
        Path::new("/usr/bin/python3"),
        &arguments,
        180,
        524288,
        16384,
    )?;
    Ok(serde_json::from_slice(&output.0)?)
}
fn bind(value: &Value, executable: &Path, image: &str) -> Result<()> {
    let manifest = &value["manifest"];
    ensure!(
        manifest["metadata"]["imageId"].as_str() == Some(image),
        "Image differs from the current authorized package target"
    );
    let entry = manifest["files"]
        .as_array()
        .context("Package file list absent")?
        .iter()
        .find(|entry| entry["path"].as_str() == Some("Bin/HyperNet"))
        .context("Installed executable absent from package")?;
    ensure!(
        entry["sha256"].as_str() == Some(files::executable(executable)?.as_str()),
        "Executable differs from installed package target"
    );
    Ok(())
}
pub(super) fn prepare(
    prefix: &Path,
    inputs: Inputs,
    executable: &Path,
    image: &str,
) -> Result<Selection> {
    ensure!(
        executable == prefix.join("Bin/HyperNet"),
        "Exact installed executable required"
    );
    let current = std::env::current_exe()?.canonicalize()?;
    let verifier = current
        .parent()
        .and_then(Path::parent)
        .context("Installed verifier prefix absent")?
        .join("Tools/Bundle.py");
    let public_key = inputs
        .public_key
        .context("--public-key is required for cutover")?;
    let public_key_digest = files::executable(&public_key)?;
    let mut selection = Selection {
        prefix: prefix.into(),
        trust_directory: inputs
            .trust_directory
            .context("--trust-directory is required for cutover")?,
        public_key,
        public_key_digest,
        policy: inputs.policy.context("--policy is required for cutover")?,
        policy_signature: inputs
            .policy_signature
            .context("--policy-signature is required for cutover")?,
        verifier_digest: files::executable(&verifier)?,
        module_digest: files::executable(&verifier.with_file_name("PackageTrust.py"))?,
        verifier,
        target_digest: String::new(),
    };
    let value = verified(&selection, false)?;
    bind(&value, executable, image)?;
    selection.target_digest = value["targetDigest"]
        .as_str()
        .context("Package target digest absent")?
        .into();
    crate::trust_bootstrap::hex32(&selection.target_digest)?;
    Ok(selection)
}
pub(super) fn admit(selection: &Selection, executable: &Path, image: &str) -> Result<Admission> {
    ensure!(
        executable == selection.prefix.join("Bin/HyperNet"),
        "Cutover executable differs from reviewed package prefix"
    );
    let value = verified(selection, false)?;
    bind(&value, executable, image)?;
    ensure!(
        value["targetDigest"].as_str() == Some(selection.target_digest.as_str()),
        "Retained package target changed; review a new stopped successor"
    );
    files::root(&selection.trust_directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(selection.trust_directory.join("Lock"))?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() == 0,
        "Invalid retained package lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Package trust is busy"
    );
    let admission = Admission {
        _lock: lock,
        trust: selection.trust_directory.clone(),
        digest: value["trustDigest"]
            .as_str()
            .context("Package trust digest absent")?
            .into(),
        not_before: value["notBefore"]
            .as_u64()
            .context("Package validity absent")?,
        expires: value["expires"].as_u64().context("Package expiry absent")?,
    };
    admission.fresh()?;
    Ok(admission)
}

pub(super) fn inspect(selection: &Selection, executable: &Path, image: &str) -> Result<()> {
    ensure!(
        executable == selection.prefix.join("Bin/HyperNet"),
        "Historical package prefix differs"
    );
    let value = verified(selection, true)?;
    ensure!(
        value["activationAllowed"] == false
            && value["targetDigest"].as_str() == Some(selection.target_digest.as_str()),
        "Historical installed target differs from reviewed package"
    );
    bind(&value, executable, image)
}
