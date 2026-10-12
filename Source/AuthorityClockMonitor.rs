// SPDX-License-Identifier: MIT
// The local monitor can observe chrony but never receives a clock-changing command.
use crate::{consensus_clock as clock, runtime_management::files};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Subcommand)]
pub enum Command {
    /// Create a private monitor signing identity and a separate public observation directory.
    InitialiseExport(Location),
    /// Verify a read-only observation using an independently pinned monitor and host boot.
    VerifyExport {
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        monitor_key: String,
        #[arg(long)]
        kernel_boot: String,
    },
    /// Write one bounded clock-health observation without changing the system clock.
    Observe(Location),
    /// Refresh the local observation until stopped; failed observations expire.
    Monitor(Location),
    /// Check the current observation and report only its readiness.
    Status(Location),
}
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    chronyc: PathBuf,
    socket: PathBuf,
    export_directory: Option<PathBuf>,
}
fn export_key(root: &Path) -> Result<SigningKey> {
    use zeroize::Zeroize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Identity {
        secret_key: String,
        public_key: String,
    }
    let bytes = zeroize::Zeroizing::new(files::read(&root.join("ClockSigner.json"), 4096)?);
    let mut identity: Identity = serde_json::from_slice(&bytes)?;
    let decoded = crate::protocol::fixed_hex::<32>(&identity.secret_key);
    identity.secret_key.zeroize();
    let secret = zeroize::Zeroizing::new(decoded.map_err(anyhow::Error::msg)?);
    let key = SigningKey::from_bytes(&secret);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
        "clock monitor identity differs"
    );
    Ok(key)
}
fn initialise_export(root: &Path, config: &Config) -> Result<()> {
    let directory = config
        .export_directory
        .as_ref()
        .context("exportDirectory is required")?;
    ensure!(
        directory.is_absolute() && !directory.exists() && !root.join("ClockSigner.json").exists(),
        "clock export identity or directory already exists"
    );
    let parent = directory.parent().context("clock export parent absent")?;
    ensure!(
        parent.canonicalize()? == parent,
        "clock export parent is not canonical"
    );
    files::ancestors(parent)?;
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Identity<'a> {
        secret_key: &'a str,
        public_key: String,
    }
    let secret = zeroize::Zeroizing::new(hex::encode(key.to_bytes()));
    let identity = zeroize::Zeroizing::new(serde_json::to_vec(&Identity {
        secret_key: &secret,
        public_key: hex::encode(key.verifying_key().to_bytes()),
    })?);
    files::create(&root.join("ClockSigner.json"), &identity)?;
    std::fs::create_dir(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"publicKey":hex::encode(key.verifying_key().to_bytes()),
        "kernelBoot":clock::kernel_boot()?,"observation":directory.join("ClockHealth.cbor")})
    );
    Ok(())
}
fn validate(config: &Config) -> Result<()> {
    ensure!(
        config.chronyc.is_absolute() && config.chronyc.canonicalize()? == config.chronyc,
        "chronyc requires an absolute canonical executable path"
    );
    let binary = std::fs::symlink_metadata(&config.chronyc)?;
    ensure!(
        binary.is_file()
            && binary.mode() & 0o022 == 0
            && binary.mode() & 0o111 != 0
            && (binary.uid() == 0 || binary.uid() == unsafe { libc::geteuid() }),
        "chronyc executable is not trusted"
    );
    files::ancestors(
        config
            .chronyc
            .parent()
            .context("chronyc parent is absent")?,
    )?;
    ensure!(
        config.socket.is_absolute() && config.socket.canonicalize()? == config.socket,
        "chrony socket requires an absolute canonical local path"
    );
    let text = config
        .socket
        .to_str()
        .context("invalid chrony socket path")?;
    ensure!(
        !text.contains(',') && !text.chars().any(char::is_control),
        "chrony fallback is prohibited"
    );
    let socket = std::fs::symlink_metadata(&config.socket)?;
    ensure!(
        socket.file_type().is_socket()
            && socket.mode() & 0o002 == 0
            && (socket.uid() == 0 || socket.uid() == unsafe { libc::geteuid() }),
        "chrony control socket is not trusted"
    );
    files::ancestors(
        config
            .socket
            .parent()
            .context("chrony socket parent is absent")?,
    )?;
    Ok(())
}
fn observe(root: &Path, config: &Config, key: Option<&SigningKey>) -> Result<()> {
    validate(config)?;
    let witness = clock::probe(|command| {
        ensure!(
            matches!(command, "tracking" | "sources" | "authdata" | "ntpdata"),
            "unknown observation command"
        );
        let output = files::run(
            &config.chronyc,
            &[
                "-n".into(),
                "-c".into(),
                "-h".into(),
                config
                    .socket
                    .to_str()
                    .context("invalid chrony socket path")?
                    .into(),
                command.into(),
            ],
            1,
        )?;
        ensure!(output.len() <= 16384, "chrony report exceeded its bound");
        Ok(String::from_utf8(output)?)
    })?;
    crate::authority_clock_handoff::publish_private(root, &witness)?;
    if let Some(directory) = &config.export_directory {
        crate::authority_clock_handoff::publish(
            directory,
            key.context("clock export signer is absent")?,
            &witness,
        )?;
    }
    Ok(())
}
pub fn health(path: &Path) -> Result<crate::authority_challenge::ClockHealth> {
    let witness: clock::Witness = serde_json::from_slice(
        &crate::authority_clock_handoff::read_private_observation(path)?,
    )?;
    witness.health(&clock::kernel_boot()?, clock::moment()?)
}
fn lock(root: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root.join("ClockMonitor.lock"))?;
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file()
            && meta.mode() & 0o077 == 0
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() },
        "unsafe clock monitor lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "clock monitor is already active"
    );
    Ok(lock)
}
pub fn run(command: Command) -> Result<()> {
    let location = match &command {
        Command::InitialiseExport(v)
        | Command::Observe(v)
        | Command::Monitor(v)
        | Command::Status(v) => v,
        Command::VerifyExport {
            observation,
            monitor_key,
            kernel_boot,
        } => {
            crate::authority_clock_handoff::Source::Signed {
                path: observation.clone(),
                public_key: monitor_key.clone(),
                kernel_boot: kernel_boot.clone(),
            }
            .health()?
            .observe()?;
            println!("ClockHealthy");
            return Ok(());
        }
    };
    let root = files::root(&location.directory)?;
    if matches!(command, Command::Status(_)) {
        health(&root.join("ClockHealth.json"))?.observe()?;
        println!("ClockHealthy");
        return Ok(());
    }
    let _lock = lock(&root)?;
    let config: Config = files::json(&root.join("ClockConfig.json"))?;
    if matches!(command, Command::InitialiseExport(_)) {
        return initialise_export(&root, &config);
    }
    let key = config
        .export_directory
        .as_ref()
        .map(|_| export_key(&root))
        .transpose()?;
    if matches!(command, Command::Observe(_)) {
        observe(&root, &config, key.as_ref())?;
        println!("ClockObservationRecorded");
        return Ok(());
    }
    let mut previous = None;
    loop {
        let current = observe(&root, &config, key.as_ref()).is_ok();
        if previous != Some(current) {
            // Errors may contain local dependency details; the monitor exposes only state.
            println!(
                "{}",
                if current {
                    "ClockHealthy"
                } else {
                    "ClockUnavailable"
                }
            );
            previous = Some(current);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
