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
mod tests {
    use super::*;
    #[test]
    fn signed_clock_expiry_only_recovers_otherwise_valid_observations() {
        let key = SigningKey::from_bytes(&[62; 32]);
        let boot = "12345678-1234-1234-1234-123456789abc";
        let old = Witness {
            version: 1,
            kernel_boot: boot.into(),
            sample_wall_ms: 10000,
            sample_boot_ms: 2000,
            valid_until_boot_ms: 3000,
            maximum_error_ms: 20,
            source: "162.159.200.1".parse().unwrap(),
        };
        let now = clock::Moment {
            wall_ms: 11000,
            boot_ms: 3000,
        };
        let check = |w: &Witness, signer: &SigningKey| {
            verify(
                &wire::sign_envelope(&payload(w)?, signer)?,
                key.verifying_key().to_bytes(),
                boot,
                now,
            )
        };
        assert!(
            check(&old, &key)
                .unwrap_err()
                .is::<clock::ObservationExpired>()
        );
        let fresh = Witness {
            sample_wall_ms: 11000,
            sample_boot_ms: 3000,
            valid_until_boot_ms: 4000,
            ..old.clone()
        };
        check(&fresh, &key).unwrap();
        for invalid in [
            Witness {
                maximum_error_ms: 251,
                ..old.clone()
            },
            Witness {
                source: "127.0.0.1".parse().unwrap(),
                ..old.clone()
            },
            Witness {
                kernel_boot: "22345678-1234-1234-1234-123456789abc".into(),
                ..old.clone()
            },
            Witness {
                valid_until_boot_ms: 2999,
                ..old.clone()
            },
            Witness {
                sample_wall_ms: 12000,
                ..old.clone()
            },
            Witness {
                sample_wall_ms: 11001,
                sample_boot_ms: 3001,
                valid_until_boot_ms: 4001,
                ..old.clone()
            },
        ] {
            assert!(
                !check(&invalid, &key)
                    .unwrap_err()
                    .is::<clock::ObservationExpired>()
            );
        }
        assert!(
            !check(&old, &SigningKey::from_bytes(&[63; 32]))
                .unwrap_err()
                .is::<clock::ObservationExpired>()
        );
    }
    #[test]
    fn atomically_replaced_observations_keep_their_original_validity() {
        let directory = crate::consensus::journal::tests::Directory::new();
        let key = SigningKey::from_bytes(&[61; 32]);
        let public = key.verifying_key().to_bytes();
        let boot = "12345678-1234-1234-1234-123456789abc";
        let old = Witness {
            version: 1,
            kernel_boot: boot.into(),
            sample_wall_ms: 10000,
            sample_boot_ms: 2000,
            valid_until_boot_ms: 3000,
            maximum_error_ms: 20,
            source: "162.159.200.1".parse().unwrap(),
        };
        let current = Witness {
            sample_wall_ms: 10100,
            sample_boot_ms: 2100,
            valid_until_boot_ms: 3100,
            ..old.clone()
        };
        let before_expiry = clock::Moment {
            wall_ms: 10100,
            boot_ms: 2100,
        };
        let at_old_expiry = clock::Moment {
            wall_ms: 11000,
            boot_ms: 3000,
        };
        let signed_path = directory.0.join("ClockHealth.cbor");
        let old_signed = wire::sign_envelope(&payload(&old).unwrap(), &key).unwrap();
        let current_signed = wire::sign_envelope(&payload(&current).unwrap(), &key).unwrap();
        replace_observation(&directory.0, "ClockHealth.cbor", &old_signed, 0o644).unwrap();
        let opened = open_signed_observation(&signed_path).unwrap();
        replace_observation(&directory.0, "ClockHealth.cbor", &current_signed, 0o644).unwrap();
        assert_eq!(opened.metadata().unwrap().nlink(), 0);
        let retained = read_opened_observation(opened, false).unwrap();
        assert_eq!(retained, old_signed);
        assert!(verify(&retained, public, boot, before_expiry).is_ok());
        assert!(verify(&retained, public, boot, at_old_expiry).is_err());
        assert!(
            verify(
                &retained,
                SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
                boot,
                before_expiry
            )
            .is_err()
        );
        assert!(
            verify(
                &retained,
                public,
                "22345678-1234-1234-1234-123456789abc",
                before_expiry
            )
            .is_err()
        );
        let fresh =
            read_opened_observation(open_signed_observation(&signed_path).unwrap(), false).unwrap();
        assert_eq!(fresh, current_signed);
        assert!(verify(&fresh, public, boot, at_old_expiry).is_ok());

        let private_path = directory.0.join("ClockHealth.json");
        replace_observation(
            &directory.0,
            "ClockHealth.json",
            &serde_json::to_vec(&old).unwrap(),
            0o600,
        )
        .unwrap();
        let opened = open_observation(&private_path).unwrap();
        replace_observation(
            &directory.0,
            "ClockHealth.json",
            &serde_json::to_vec(&current).unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(opened.metadata().unwrap().nlink(), 0);
        let retained: Witness =
            serde_json::from_slice(&read_opened_observation(opened, true).unwrap()).unwrap();
        assert!(retained.health(boot, before_expiry).is_ok());
        assert!(retained.health(boot, at_old_expiry).is_err());
        let fresh: Witness =
            serde_json::from_slice(&read_private_observation(&private_path).unwrap()).unwrap();
        assert!(fresh.health(boot, at_old_expiry).is_ok());
    }
    #[test]
    fn observation_readers_reject_links_symlinks_oversize_and_private_permission_changes() {
        let directory = crate::consensus::journal::tests::Directory::new();
        let path = directory.0.join("ClockHealth.json");
        replace_observation(&directory.0, "ClockHealth.json", b"observation", 0o600).unwrap();
        let linked = directory.0.join("Linked.json");
        std::fs::hard_link(&path, &linked).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
        assert!(read_opened_observation(open_signed_observation(&path).unwrap(), false).is_err());
        assert!(read_private_observation(&path).is_err());
        std::fs::remove_file(&linked).unwrap();
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert!(open_signed_observation(&linked).is_err());
        assert!(read_private_observation(&linked).is_err());
        assert!(open_signed_observation(Path::new("ClockHealth.json")).is_err());
        assert!(
            read_opened_observation(open_signed_observation(&directory.0).unwrap(), false).is_err()
        );
        assert!(read_private_observation(&directory.0).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_observation(&path).is_err());
        assert_eq!(
            read_opened_observation(open_signed_observation(&path).unwrap(), false).unwrap(),
            b"observation"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![0; 4096]).unwrap();
        assert_eq!(read_private_observation(&path).unwrap().len(), 4096);
        std::fs::write(&path, vec![0; 4097]).unwrap();
        assert!(read_opened_observation(open_signed_observation(&path).unwrap(), false).is_err());
        assert!(read_private_observation(&path).is_err());
    }
    #[test]
    fn transient_replacement_preserves_open_readers_and_cleans_failed_publication() {
        let directory = crate::consensus::journal::tests::Directory::new();
        let path = directory.0.join("ClockHealth.json");
        replace_observation(&directory.0, "ClockHealth.json", b"old", 0o600).unwrap();
        let mut old = OpenOptions::new().read(true).open(&path).unwrap();
        replace_observation(&directory.0, "ClockHealth.json", b"new", 0o600).unwrap();
        let mut retained = Vec::new();
        old.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, b"old");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

        let protected = directory.0.join("Protected.bin");
        std::fs::write(&protected, b"protected").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&protected, &path).unwrap();
        replace_observation(&directory.0, "ClockHealth.json", b"current", 0o600).unwrap();
        assert_eq!(std::fs::read(&protected).unwrap(), b"protected");
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(replace_observation(&directory.0, "ClockHealth.json", b"failed", 0o600).is_err());
        assert!(path.is_dir());
        assert!(std::fs::read_dir(&directory.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("ClockPending")
        }));
    }
    #[test]
    fn monitor_pin_boot_expiry_and_progression_are_all_required() {
        let key = SigningKey::from_bytes(&[61; 32]);
        let boot = "12345678-1234-1234-1234-123456789abc";
        let w = Witness {
            version: 1,
            kernel_boot: boot.into(),
            sample_wall_ms: 10000,
            sample_boot_ms: 2000,
            valid_until_boot_ms: 3000,
            maximum_error_ms: 20,
            source: "162.159.200.1".parse().unwrap(),
        };
        let encoded = wire::sign_envelope(&payload(&w).unwrap(), &key).unwrap();
        let public = key.verifying_key().to_bytes();
        let now = clock::Moment {
            wall_ms: 10100,
            boot_ms: 2100,
        };
        assert!(verify(&encoded, public, boot, now).is_ok());
        assert!(
            verify(
                &encoded,
                SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
                boot,
                now
            )
            .is_err()
        );
        assert!(
            verify(
                &encoded,
                public,
                "22345678-1234-1234-1234-123456789abc",
                now
            )
            .is_err()
        );
        assert!(
            verify(
                &encoded,
                public,
                boot,
                clock::Moment {
                    wall_ms: 11000,
                    boot_ms: 3000
                }
            )
            .is_err()
        );
        assert!(
            verify(
                &encoded,
                public,
                boot,
                clock::Moment {
                    wall_ms: 10500,
                    boot_ms: 2100
                }
            )
            .is_err()
        );
        assert!(
            verify(
                &encoded,
                public,
                boot,
                clock::Moment {
                    wall_ms: 9999,
                    boot_ms: 1999
                }
            )
            .is_err()
        );
        let mut changed = encoded.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify(&changed, public, boot, now).is_err());
    }
}
