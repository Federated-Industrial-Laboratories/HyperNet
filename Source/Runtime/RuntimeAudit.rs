// SPDX-License-Identifier: MIT
//! Bounded signed lifecycle events with explicitly pinned independent head witnesses.
#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeAuditTests.rs"]
mod tests;
#[path = "RuntimeAuditWitness.rs"]
mod witness;
use crate::{runtime_management::files, runtime_manifest::Manifest, trust_bootstrap::hex32};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const ENTRY_LIMIT: usize = 8192;
const EXPORT_LIMIT: usize = 1048576;
const MAXIMUM_BYTES: u64 = 16777216;
const RETENTION_SECONDS: u64 = 7776000;
const PURPOSE: &str = "HyperNetOperationalAudit1";

#[derive(Subcommand)]
pub enum Command {
    /// Set the private event byte budget and minimum local retention interval.
    Configure {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        maximum_bytes: u64,
        #[arg(long)]
        retention_seconds: u64,
    },
    /// Inspect the local signed head without exporting event metadata.
    Inspect {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Export a bounded contiguous batch for an independently operated witness.
    Export {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        after_sequence: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a witness that accepts only the independently authenticated emitter key.
    WitnessInit {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        emitter_key: String,
    },
    /// Retain a contiguous signed batch and produce a signed head receipt.
    WitnessAccept {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        batch: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Remove expired local events only through an independently witnessed head.
    Prune {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        witness_key: String,
    },
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scope {
    emitter: String,
    network: String,
    incarnation: String,
    deployment: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Head {
    purpose: String,
    scope: Scope,
    sequence: u64,
    event_digest: String,
    recorded_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Event {
    head: Head,
    previous: String,
    profile_digest: String,
    generation: u64,
    software_digest: String,
    operation: String,
    outcome: String,
    audit_maximum_bytes: u64,
    audit_retention_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    payload: T,
    signature: String,
}
impl<T: Serialize> Signed<T> {
    fn new(payload: T, key: &SigningKey) -> Result<Self> {
        let signature = hex::encode(key.sign(&serde_json::to_vec(&payload)?).to_bytes());
        Ok(Self { payload, signature })
    }
    fn verify(&self, key: &str) -> Result<()> {
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&hex32(key)?)?
            .verify_strict(&serde_json::to_vec(&self.payload)?, &signature)?;
        Ok(())
    }
    fn digest(&self) -> Result<String> {
        Ok(files::hex_digest(&serde_json::to_vec(self)?))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    scope: Scope,
    maximum_bytes: u64,
    retention_seconds: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    base: Signed<Head>,
    events: Vec<Signed<Event>>,
    head: Signed<Head>,
}

fn key(root: &Path) -> Result<SigningKey> {
    let seed = Zeroizing::new(files::read(&root.join("Key.bin"), 32)?);
    Ok(SigningKey::from_bytes(
        seed.as_slice()
            .try_into()
            .context("Audit key length differs")?,
    ))
}
fn create_key(root: &Path) -> Result<SigningKey> {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let seed = Zeroizing::new(key.to_bytes());
    files::create(&root.join("Key.bin"), seed.as_ref())?;
    Ok(key)
}
fn read<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&files::read(path, maximum)?)?)
}
fn audit_root(directory: &Path) -> Result<PathBuf> {
    files::root(directory)?;
    files::root(&directory.join("Audit"))
}
fn event_path(root: &Path, sequence: u64) -> PathBuf {
    root.join(format!("Event{sequence:020}.json"))
}
fn validate_head(head: &Signed<Head>) -> Result<()> {
    head.verify(&head.payload.scope.emitter)?;
    ensure!(
        head.payload.purpose == PURPOSE && head.payload.recorded_at > 0,
        "Audit head purpose or time differs"
    );
    for value in [
        &head.payload.scope.emitter,
        &head.payload.scope.network,
        &head.payload.scope.incarnation,
        &head.payload.scope.deployment,
        &head.payload.event_digest,
    ] {
        hex32(value)?;
    }
    ensure!(
        head.payload.sequence != 0 || head.payload.event_digest == hex::encode([0; 32]),
        "Audit genesis digest differs"
    );
    Ok(())
}
fn event_head(event: &Signed<Event>, previous: &Head) -> Result<Head> {
    event.verify(&previous.scope.emitter)?;
    let e = &event.payload;
    ensure!(
        e.head.purpose == PURPOSE
            && e.head.scope == previous.scope
            && e.head.sequence
                == previous
                    .sequence
                    .checked_add(1)
                    .context("Audit sequence exhausted")?
            && e.previous == previous.event_digest
            && e.head.recorded_at >= previous.recorded_at
            && e.head.event_digest == hex::encode([0; 32])
            && e.generation > 0,
        "Audit event continuity differs"
    );
    hex32(&e.profile_digest)?;
    hex32(&e.software_digest)?;
    validate_labels(&e.operation, &e.outcome)?;
    validate_budget(e.audit_maximum_bytes, e.audit_retention_seconds)?;
    let mut head = e.head.clone();
    head.event_digest = event.digest()?;
    Ok(head)
}
fn validate_labels(operation: &str, outcome: &str) -> Result<()> {
    ensure!(
        matches!(
            operation,
            "Setup"
                | "Consent"
                | "Start"
                | "Stop"
                | "Withdraw"
                | "Transition"
                | "ManagedEnable"
                | "ManagedDisable"
                | "EpochPrepare"
                | "EpochActivate"
                | "EpochAdvance"
                | "Recovery"
                | "AuditConfigure"
        ) && matches!(outcome, "Prepared" | "Committed" | "Failed"),
        "Unsupported audit event type"
    );
    Ok(())
}
fn validate_budget(bytes: u64, retention: u64) -> Result<()> {
    ensure!(
        (65536..=17179869184).contains(&bytes) && retention > 0,
        "Audit byte budget must be 64 KiB to 16 GiB and retention must be positive"
    );
    Ok(())
}
fn load(root: &Path) -> Result<(Policy, SigningKey, Signed<Head>)> {
    let policy: Policy = read(&root.join("Policy.json"), ENTRY_LIMIT)?;
    validate_budget(policy.maximum_bytes, policy.retention_seconds)?;
    let key = key(root)?;
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == policy.scope.emitter,
        "Audit identity differs"
    );
    let mut head: Signed<Head> = read(&root.join("Head.json"), ENTRY_LIMIT)?;
    validate_head(&head)?;
    ensure!(head.payload.scope == policy.scope, "Audit scope differs");
    let anchor: Signed<Head> = read(&root.join("Anchor.json"), ENTRY_LIMIT)?;
    validate_head(&anchor)?;
    ensure!(
        anchor.payload.scope == policy.scope && anchor.payload.sequence <= head.payload.sequence,
        "Audit retention anchor differs"
    );
    if head.payload.sequence > anchor.payload.sequence {
        let event: Signed<Event> = read(&event_path(root, head.payload.sequence), ENTRY_LIMIT)?;
        event.verify(&policy.scope.emitter)?;
        ensure!(
            event.digest()? == head.payload.event_digest
                && event.payload.head.scope == policy.scope
                && event.payload.head.sequence == head.payload.sequence,
            "Audit retained tail is missing or altered"
        );
    }
    // One durable event may precede its head after interruption. Complete that exact append.
    let next = event_path(
        root,
        head.payload
            .sequence
            .checked_add(1)
            .context("Audit sequence exhausted")?,
    );
    if next.try_exists()? {
        let event: Signed<Event> = read(&next, ENTRY_LIMIT)?;
        head = Signed::new(event_head(&event, &head.payload)?, &key)?;
        files::save(&root.join("Head.json"), &head)?;
    }
    Ok((policy, key, head))
}
pub fn initialise(directory: &Path, manifest: &Manifest) -> Result<()> {
    manifest.validate()?;
    let parent = files::root(directory)?;
    let root = parent.join("Audit");
    ensure!(
        !root.try_exists()?,
        "Audit identity already exists; retain its history"
    );
    files::directory(&root)?;
    let key = create_key(&root)?;
    let scope = Scope {
        emitter: hex::encode(key.verifying_key().to_bytes()),
        network: hex::encode(manifest.network),
        incarnation: hex::encode(manifest.incarnation),
        deployment: hex::encode(manifest.deployment),
    };
    let head = Signed::new(
        Head {
            purpose: PURPOSE.into(),
            scope: scope.clone(),
            sequence: 0,
            event_digest: hex::encode([0; 32]),
            recorded_at: files::now()?,
        },
        &key,
    )?;
    files::create(
        &root.join("Policy.json"),
        &serde_json::to_vec(&Policy {
            scope,
            maximum_bytes: MAXIMUM_BYTES,
            retention_seconds: RETENTION_SECONDS,
        })?,
    )?;
    files::create(&root.join("Anchor.json"), &serde_json::to_vec(&head)?)?;
    files::create(&root.join("Head.json"), &serde_json::to_vec(&head)?)?;
    files::reserve(&root)?;
    record(directory, manifest, "Setup", "Committed")
}
fn retained_bytes(root: &Path) -> Result<u64> {
    let mut used = 0u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("Event") && n.ends_with(".json"))
        {
            used = used
                .checked_add(files::read(&entry.path(), ENTRY_LIMIT)?.len() as u64)
                .context("Audit capacity overflow")?;
        }
    }
    Ok(used)
}
pub fn record(directory: &Path, manifest: &Manifest, operation: &str, outcome: &str) -> Result<()> {
    validate_labels(operation, outcome)?;
    let root = audit_root(directory)?;
    let _lock = files::lock(&root)?;
    let (policy, key, head) = load(&root)?;
    ensure!(
        policy.scope.network == hex::encode(manifest.network)
            && policy.scope.incarnation == hex::encode(manifest.incarnation)
            && policy.scope.deployment == hex::encode(manifest.deployment),
        "Audit manifest scope differs"
    );
    let now = files::now()?;
    ensure!(
        now >= head.payload.recorded_at,
        "Audit clock moved backwards"
    );
    let mut next = head.payload.clone();
    next.sequence = next
        .sequence
        .checked_add(1)
        .context("Audit sequence exhausted")?;
    next.event_digest = hex::encode([0; 32]);
    next.recorded_at = now;
    let event = Signed::new(
        Event {
            head: next,
            previous: head.payload.event_digest.clone(),
            profile_digest: files::hex_digest(&manifest.desired()?),
            generation: manifest.generation,
            software_digest: hex::encode(manifest.software_digest),
            operation: operation.into(),
            outcome: outcome.into(),
            audit_maximum_bytes: policy.maximum_bytes,
            audit_retention_seconds: policy.retention_seconds,
        },
        &key,
    )?;
    let bytes = serde_json::to_vec(&event)?;
    ensure!(bytes.len() <= ENTRY_LIMIT, "Audit event exceeds its bound");
    let used = retained_bytes(&root)?;
    let reserve = if matches!(operation, "Stop" | "Withdraw" | "AuditConfigure") {
        0
    } else {
        (4 * ENTRY_LIMIT) as u64
    };
    ensure!(
        used + bytes.len() as u64 + reserve
            <= policy.maximum_bytes
                + if operation == "AuditConfigure" {
                    (2 * ENTRY_LIMIT) as u64
                } else {
                    0
                },
        "Audit capacity reached; witness and prune expired events before another security mutation"
    );
    let next_head = Signed::new(event_head(&event, &head.payload)?, &key)?;
    let destination = event_path(&root, next_head.payload.sequence);
    ensure!(
        matches!(fs::symlink_metadata(&destination), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "An existing signed event cannot be replaced; recover the retained head first"
    );
    files::save(&destination, &event)?;
    files::save(&root.join("Head.json"), &next_head)
}
/// A failed diagnostic write must never keep an explicitly stopped or withdrawn workload alive.
pub fn restrictive(directory: &Path, manifest: &Manifest, operation: &str, outcome: &str) -> bool {
    let recorded = record(directory, manifest, operation, outcome).is_ok();
    if !recorded {
        eprintln!("Operational audit unavailable; restrictive cleanup is not blocked");
    }
    recorded
}
fn head_at(
    root: &Path,
    sequence: u64,
    key: &SigningKey,
    current: &Signed<Head>,
) -> Result<Signed<Head>> {
    if sequence == current.payload.sequence {
        return Ok(current.clone());
    }
    let anchor: Signed<Head> = read(&root.join("Anchor.json"), ENTRY_LIMIT)?;
    validate_head(&anchor)?;
    if sequence == anchor.payload.sequence {
        return Ok(anchor);
    }
    ensure!(
        sequence > anchor.payload.sequence && sequence < current.payload.sequence,
        "Requested audit history was pruned or is beyond the current head"
    );
    let event: Signed<Event> = read(&event_path(root, sequence), ENTRY_LIMIT)?;
    event.verify(&current.payload.scope.emitter)?;
    ensure!(
        event.payload.head.scope == current.payload.scope
            && event.payload.head.sequence == sequence,
        "Audit event scope differs"
    );
    let mut head = event.payload.head.clone();
    head.event_digest = event.digest()?;
    Signed::new(head, key)
}
fn export(directory: &Path, after: u64, output: &Path) -> Result<serde_json::Value> {
    let root = audit_root(directory)?;
    let _lock = files::lock(&root)?;
    let (_, key, head) = load(&root)?;
    let base = head_at(&root, after, &key, &head)?;
    let mut cursor = base.payload.clone();
    let mut events = vec![];
    let mut size = 2 * ENTRY_LIMIT;
    while cursor.sequence < head.payload.sequence {
        let bytes = files::read(&event_path(&root, cursor.sequence + 1), ENTRY_LIMIT)?;
        if size + bytes.len() > EXPORT_LIMIT {
            break;
        }
        let event: Signed<Event> = serde_json::from_slice(&bytes)?;
        cursor = event_head(&event, &cursor)?;
        size += bytes.len();
        events.push(event);
    }
    let batch = Batch {
        base,
        events,
        head: Signed::new(cursor.clone(), &key)?,
    };
    let bytes = serde_json::to_vec(&batch)?;
    ensure!(
        bytes.len() <= EXPORT_LIMIT,
        "Audit export exceeds its bound"
    );
    files::root(
        output
            .parent()
            .context("Private audit output parent required")?,
    )?;
    files::create(output, &bytes)?;
    Ok(
        json!({"status":"AuditExported","throughSequence":cursor.sequence,"currentSequence":head.payload.sequence,
        "emitterKey":cursor.scope.emitter,"headDigest":batch.head.digest()?,"output":output}),
    )
}
pub fn run(command: Command) -> Result<()> {
    let value = match command {
        Command::Configure {
            directory,
            maximum_bytes,
            retention_seconds,
        } => {
            validate_budget(maximum_bytes, retention_seconds)?;
            let directory = files::root(&directory)?;
            let _lifecycle = files::lock(&directory)?;
            let manifest = Manifest::parse(&files::public_read(
                &directory.join("Authorization/Manifest.cbor"),
                crate::trust_wire::MAXIMUM,
            )?)?;
            record(&directory, &manifest, "AuditConfigure", "Prepared")?;
            {
                let root = audit_root(&directory)?;
                let _lock = files::lock(&root)?;
                let (mut policy, _, _) = load(&root)?;
                ensure!(
                    retained_bytes(&root)?
                        .checked_add(ENTRY_LIMIT as u64)
                        .is_some_and(|required| required <= maximum_bytes),
                    "Audit budget cannot be below retained history and its configuration outcome"
                );
                policy.maximum_bytes = maximum_bytes;
                policy.retention_seconds = retention_seconds;
                files::save(&root.join("Policy.json"), &policy)?;
            }
            record(&directory, &manifest, "AuditConfigure", "Committed")?;
            json!({"status":"AuditConfigured","maximumBytes":maximum_bytes,"retentionSeconds":retention_seconds})
        }
        Command::Inspect { directory } => {
            let root = audit_root(&directory)?;
            let _lock = files::lock(&root)?;
            let (policy, _, head) = load(&root)?;
            json!({"status":"AuditInspected","emitterKey":policy.scope.emitter,"sequence":head.payload.sequence,
                "headDigest":head.digest()?,"maximumBytes":policy.maximum_bytes,"retentionSeconds":policy.retention_seconds})
        }
        Command::Export {
            directory,
            after_sequence,
            output,
        } => export(&directory, after_sequence, &output)?,
        Command::WitnessInit {
            directory,
            emitter_key,
        } => witness::initialise(&directory, &emitter_key)?,
        Command::WitnessAccept {
            directory,
            batch,
            output,
        } => witness::accept(&directory, &batch, &output)?,
        Command::Prune {
            directory,
            receipt,
            witness_key,
        } => witness::prune(&directory, &receipt, &witness_key)?,
    };
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
