// SPDX-License-Identifier: MIT
// Native backup custody uses explicit spare capacity on an installed consenting volume.
use crate::{authority_domains::backup, authority_files as files, trust_wire as wire};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
#[path = "AuthorityBackupDisk.rs"]
mod disk;
#[derive(Subcommand)]
pub enum Command {
    Destination {
        #[command(subcommand)]
        command: DestinationCommand,
    },
}
#[derive(Subcommand)]
pub enum DestinationCommand {
    /// Bind a signed cold archive destination to spare capacity of an installed volume.
    Initialise {
        #[arg(long)]
        runtime_directory: PathBuf,
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        operator_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import one owner-signed encrypted archive after capacity and retention checks.
    Import {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        input: PathBuf,
    },
    List(Location),
    Export {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        archive: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Remove expired archives, or one explicitly selected archive.
    Purge {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        archive: Option<String>,
    },
}
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    runtime_directory: PathBuf,
    #[arg(long)]
    host: String,
    #[arg(long)]
    volume: String,
    #[arg(long)]
    destination: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Spec {
    id: String,
    name: String,
    host: String,
    volume: String,
    bytes: u64,
    objects: u64,
    retention_ms: u64,
    recipients: Vec<String>,
    owners: Vec<String>,
    opaque: bool,
}
fn id(s: &str) -> Result<[u8; 32]> {
    crate::trust_bootstrap::hex32(s)
}
fn signer(path: &Path) -> Result<SigningKey> {
    let bytes = Zeroizing::new(files::read_single(path, 8192, true)?);
    if bytes.len() == 32 {
        return Ok(SigningKey::from_bytes(bytes.as_slice().try_into()?));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let seed = Zeroizing::new(id(value["secretKey"]
        .as_str()
        .or_else(|| value["secret_key"].as_str())
        .context("operator identity secret absent")?)?);
    let key = SigningKey::from_bytes(&seed);
    let public = value["publicKey"]
        .as_str()
        .or_else(|| value["public_key"].as_str())
        .context("operator identity public key absent")?;
    ensure!(
        id(public)? == key.verifying_key().to_bytes(),
        "operator identity differs"
    );
    Ok(key)
}
fn open(location: &Location, live: bool, now: u64) -> Result<disk::Disk> {
    let (manifest, root, _) = crate::runtime_management::approved_backup_volume(
        &location.runtime_directory,
        id(&location.host)?,
        id(&location.volume)?,
        live,
    )?;
    disk::Disk::open(&root, id(&location.destination)?, &manifest, now)
}
pub fn run(command: Command) -> Result<()> {
    let now = crate::store::now()?
        .checked_mul(1000)
        .context("backup clock overflow")?;
    let Command::Destination { command } = command;
    let result = match command {
        DestinationCommand::Initialise {
            runtime_directory,
            spec,
            operator_key,
            output,
        } => {
            let spec: Spec = serde_json::from_slice(&files::read_single(&spec, 65536, false)?)?;
            let (manifest, root, surplus) = crate::runtime_management::approved_backup_volume(
                &runtime_directory,
                id(&spec.host)?,
                id(&spec.volume)?,
                true,
            )?;
            let key = signer(&operator_key)?;
            ensure!(
                key.verifying_key().to_bytes() == manifest.operator,
                "backup consent requires the installed operator"
            );
            let mut recipients = spec
                .recipients
                .iter()
                .map(|v| id(v))
                .collect::<Result<Vec<_>>>()?;
            recipients.sort();
            let mut owners = spec
                .owners
                .iter()
                .map(|v| id(v))
                .collect::<Result<Vec<_>>>()?;
            owners.sort();
            let mut profile = backup::Profile {
                manifest,
                id: id(&spec.id)?,
                name: spec.name,
                volume: id(&spec.volume)?,
                bytes: spec.bytes,
                objects: spec.objects,
                retention_ms: spec.retention_ms,
                recipients,
                owners,
                opaque: spec.opaque,
                envelope: vec![],
            };
            profile.envelope = wire::sign_envelope(&profile.payload()?, &key)?;
            let profile = backup::Profile::parse(
                &profile.envelope,
                profile.manifest.network,
                profile.manifest.incarnation,
            )?;
            let directory = disk::Disk::initialise(&root, &profile, surplus)?;
            if output.try_exists()? {
                ensure!(
                    files::read_single(&output, backup::MAXIMUM_PROFILE, false)?
                        == profile.envelope,
                    "consent output already contains different bytes"
                );
            } else {
                files::write_new(&output, &profile.envelope)?;
            }
            serde_json::json!({"status":"BackupDestinationInitialised","destination":hex::encode(profile.id),"host":hex::encode(profile.manifest.host),"volume":hex::encode(profile.volume),"directory":directory,"profileDigest":hex::encode(wire::digest(&profile.envelope)),"bytes":profile.bytes})
        }
        DestinationCommand::Import { location, input } => {
            let mut disk = open(&location, true, now)?;
            let bytes = files::read_single(&input, backup::package::PACKAGE_LIMIT, true)?;
            let archive = disk.import(&bytes, now)?;
            serde_json::json!({"status":"BackupArchiveImported","archive":hex::encode(archive),"serving":false})
        }
        DestinationCommand::List(location) => open(&location, false, now)?.list(now)?,
        DestinationCommand::Export {
            location,
            archive,
            output,
        } => {
            let mut disk = open(&location, false, now)?;
            let bytes = disk.export(id(&archive)?, now)?;
            files::write_new(&output, &bytes)?;
            serde_json::json!({"status":"EncryptedBackupExported","archive":archive,"output":output})
        }
        DestinationCommand::Purge { location, archive } => {
            let count =
                open(&location, false, now)?.purge(now, archive.as_deref().map(id).transpose()?)?;
            serde_json::json!({"status":"BackupRetentionApplied","removed":count})
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
