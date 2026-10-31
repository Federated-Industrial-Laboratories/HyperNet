// SPDX-License-Identifier: MIT
// A pinned host monitor signs short-lived observations for a read-only container mount.
use crate::{
    authority_challenge::ClockHealth,
    consensus_clock::{self as clock, Witness},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Source {
    Private {
        path: PathBuf,
    },
    Signed {
        path: PathBuf,
        #[serde(rename = "publicKey")]
        public_key: String,
        #[serde(rename = "kernelBoot")]
        kernel_boot: String,
    },
}
impl Source {
    pub fn health(&self) -> Result<ClockHealth> {
        match self {
            Self::Private { path } => crate::authority_clock_monitor::health(path),
            Self::Signed {
                path,
                public_key,
                kernel_boot,
            } => {
                unshifted_clock()?;
                let key =
                    crate::protocol::fixed_hex::<32>(public_key).map_err(anyhow::Error::msg)?;
                let bytes = read_opened_observation(open_signed_observation(path)?, false)?;
                let boot = if kernel_boot == "CurrentHost" {
                    clock::kernel_boot()?
                } else {
                    kernel_boot.clone()
                };
                verify(&bytes, key, &boot, clock::moment()?)
            }
        }
    }
}

fn open_observation(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?)
}
fn open_signed_observation(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == *path,
        "signed clock observation requires a canonical absolute path"
    );
    open_observation(path)
}
fn read_opened_observation(file: File, private: bool) -> Result<Vec<u8>> {
    let meta = file.metadata()?;
    // Atomic replacement may unlink this already opened observation. Its
    // original signed/boot-clock validity still applies to the retained bytes.
    ensure!(
        meta.is_file() && meta.nlink() <= 1 && meta.len() <= 4096,
        "clock observation is not a bounded regular file"
    );
    if private {
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "private clock observation is not a private owner file"
        );
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "clock observation exceeds its bound");
    Ok(bytes)
}
pub(super) fn read_private_observation(path: &Path) -> Result<Vec<u8>> {
    read_opened_observation(open_observation(path)?, true)
}

fn unshifted_clock() -> Result<()> {
    let bytes = std::fs::read_to_string("/proc/self/timens_offsets")?;
    ensure!(
        bytes.len() <= 256,
        "time namespace report exceeds its bound"
    );
    let lines = bytes.lines().collect::<Vec<_>>();
    ensure!(lines.len() == 2, "unknown time namespace report");
    for (line, name) in lines.iter().zip(["monotonic", "boottime"]) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.as_slice() == [name, "0", "0"],
            "shifted time namespace is unsupported"
        );
    }
    Ok(())
}

fn payload(w: &Witness) -> Result<Vec<u8>> {
    wire::encode(&V::Array(vec![
        V::Uint(44),
        V::Uint(1),
        V::Text(w.kernel_boot.clone()),
        V::Uint(w.sample_wall_ms),
        V::Uint(w.sample_boot_ms),
        V::Uint(w.valid_until_boot_ms),
        V::Uint(w.maximum_error_ms),
        V::Text(w.source.to_string()),
    ]))
}
fn verify(bytes: &[u8], key: [u8; 32], boot: &str, now: clock::Moment) -> Result<ClockHealth> {
    let (bytes, signatures) = wire::envelope(bytes, 1)?;
    ensure!(
        signatures.len() == 1 && signatures[0].0 == key,
        "clock monitor signature differs from its pin"
    );
    let value = wire::decode(&bytes)?;
    let f = value.array(8)?;
    ensure!(
        f[0].uint()? == 44 && f[1].uint()? == 1,
        "unsupported signed clock observation"
    );
    let source = f[7].text()?.parse()?;
    let w = Witness {
        version: 1,
        kernel_boot: f[2].text()?.into(),
        sample_wall_ms: f[3].uint()?,
        sample_boot_ms: f[4].uint()?,
        valid_until_boot_ms: f[5].uint()?,
        maximum_error_ms: f[6].uint()?,
        source,
    };
    ensure!(
        w.source.to_string() == f[7].text()?
            && !w.source.is_unspecified()
            && !w.source.is_loopback(),
        "invalid signed clock source"
    );
    ensure!(
        payload(&w)? == bytes,
        "noncanonical signed clock observation"
    );
    Ok(w.health(boot, now)?.authenticated_observation())
}

pub fn publish(directory: &Path, key: &SigningKey, witness: &Witness) -> Result<()> {
    ensure!(
        directory.is_absolute() && directory.canonicalize()? == directory,
        "clock export requires a canonical absolute directory"
    );
    let meta = std::fs::symlink_metadata(directory)?;
    ensure!(
        meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "clock export directory permits replacement"
    );
    crate::runtime_management::files::ancestors(directory)?;
    witness.health(&clock::kernel_boot()?, clock::moment()?)?;
    let bytes = wire::sign_envelope(&payload(witness)?, key)?;
    replace_observation(directory, "ClockHealth.cbor", &bytes, 0o644)?;
    witness.health(&clock::kernel_boot()?, clock::moment()?)?;
    Ok(())
}

pub(super) fn publish_private(directory: &Path, witness: &Witness) -> Result<()> {
    crate::runtime_management::files::root(directory)?;
    witness.health(&clock::kernel_boot()?, clock::moment()?)?;
    replace_observation(
        directory,
        "ClockHealth.json",
        &serde_json::to_vec(witness)?,
        0o600,
    )?;
    witness.health(&clock::kernel_boot()?, clock::moment()?)?;
    Ok(())
}

fn replace_observation(directory: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    ensure!(bytes.len() <= 4096, "clock observation exceeds its bound");
    let temporary = directory.join(format!("ClockPending{}", crate::random_hex::<16>()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        // Observations expire against the original boot clock. Atomic replacement
        // is required; crash durability is not. A lost or stale file refuses.
        std::fs::rename(&temporary, directory.join(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.context("clock observation could not be published")
}

#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityClockHandoffUnitTests.rs"]
mod tests;
