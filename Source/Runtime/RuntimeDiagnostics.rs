// SPDX-License-Identifier: MIT
// Diagnostic output admits only fixed categories and bounded recorded counters.
use super::{files, model};
use anyhow::{Result, anyhow, ensure};
use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct Options {
    #[arg(long)]
    directory: PathBuf,
    /// New private file for the exact redacted snapshot accepted in the preview.
    #[arg(long, requires = "preview_digest")]
    output: Option<PathBuf>,
    /// SHA-256 printed by a prior diagnostic preview.
    #[arg(long, requires = "output")]
    preview_digest: Option<String>,
}
#[derive(Serialize)]
enum Component {
    AuthorityRuntime,
    ServiceRuntime,
}
#[derive(Serialize)]
enum Availability {
    Recorded,
    UnavailableOrInvalid,
}
#[derive(Serialize)]
enum Role {
    Authority,
    Page,
    Media,
    Mail,
    Transfer,
    PrivateRoute,
    Bridge,
    Ssh,
    Unknown,
}
#[derive(Serialize)]
enum RecordedState {
    AwaitingConsent,
    AwaitingLocalConsent,
    Consented,
    Starting,
    Running,
    ClockUnavailable,
    Degraded,
    Stopped,
    Withdrawn,
    Failed,
    Recovering,
    EpochPrepared,
    EpochActivated,
    Unknown,
}
impl RecordedState {
    fn authority(value: &str) -> Self {
        match value {
            "AwaitingConsent" => Self::AwaitingConsent,
            "Starting" => Self::Starting,
            "Running" => Self::Running,
            "ClockUnavailable" => Self::ClockUnavailable,
            "Degraded" => Self::Degraded,
            "Stopped" => Self::Stopped,
            "Withdrawn" => Self::Withdrawn,
            "Failed" => Self::Failed,
            "Recovering" => Self::Recovering,
            "EpochPrepared" => Self::EpochPrepared,
            "EpochActivated" => Self::EpochActivated,
            _ => Self::Unknown,
        }
    }
}
#[derive(Serialize)]
enum FailureCode {
    InterruptedOperation,
    StaleLifecycleState,
    OperationFailed,
    ResourceRecoveryRequired,
    Unknown,
}
impl FailureCode {
    fn parse(value: &str) -> Self {
        match value {
            "InterruptedOperation" => Self::InterruptedOperation,
            "StaleLifecycleState" => Self::StaleLifecycleState,
            "OperationFailed" => Self::OperationFailed,
            "ResourceRecoveryRequired" => Self::ResourceRecoveryRequired,
            _ => Self::Unknown,
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Recorded {
    role: Role,
    state: RecordedState,
    generation: u64,
    withdrawal_generation: u64,
    resource_count: usize,
    initialised: bool,
    consent_retained: bool,
    withdrawn: bool,
    pending_operation: Option<bool>,
    failure_code: Option<FailureCode>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Snapshot {
    format: &'static str,
    product: &'static str,
    software_version: &'static str,
    component: Component,
    scope: &'static str,
    network_used: bool,
    network_probed: bool,
    current_authority: bool,
    readiness_probed: bool,
    availability: Availability,
    recorded: Option<Recorded>,
}
pub(super) fn unavailable(authority: bool) -> Snapshot {
    Snapshot {
        format: "HyperNetDiagnostics/1",
        product: "HyperNet",
        software_version: env!("CARGO_PKG_VERSION"),
        component: if authority {
            Component::AuthorityRuntime
        } else {
            Component::ServiceRuntime
        },
        scope: "SelectedLocalRuntime",
        network_used: false,
        network_probed: false,
        current_authority: false,
        readiness_probed: false,
        availability: Availability::UnavailableOrInvalid,
        recorded: None,
    }
}
fn authority(state: &model::State) -> Snapshot {
    let mut snapshot = unavailable(true);
    snapshot.availability = Availability::Recorded;
    snapshot.recorded = Some(Recorded {
        role: Role::Authority,
        state: RecordedState::authority(&state.status),
        generation: state.generation,
        withdrawal_generation: state.withdrawal_generation,
        resource_count: state.resources.len(),
        initialised: state.initialised,
        consent_retained: state.accepted_consent.is_some(),
        withdrawn: state.withdrawal_generation != 0,
        pending_operation: Some(state.pending.is_some()),
        failure_code: state.failure_code.as_deref().map(FailureCode::parse),
    });
    snapshot
}
pub(super) fn service(
    role: u64,
    consented: bool,
    withdrawn: bool,
    initialised: bool,
    resources: usize,
) -> Snapshot {
    let mut snapshot = unavailable(false);
    snapshot.availability = Availability::Recorded;
    snapshot.recorded = Some(Recorded {
        role: match role {
            1 => Role::Page,
            2 => Role::Media,
            3 => Role::Mail,
            4 => Role::Transfer,
            5 => Role::PrivateRoute,
            7 => Role::Bridge,
            8 => Role::Ssh,
            _ => Role::Unknown,
        },
        state: if withdrawn {
            RecordedState::Withdrawn
        } else if consented {
            RecordedState::Consented
        } else {
            RecordedState::AwaitingLocalConsent
        },
        generation: 1,
        withdrawal_generation: u64::from(withdrawn),
        resource_count: resources,
        initialised,
        consent_retained: consented,
        withdrawn,
        pending_operation: None,
        failure_code: None,
    });
    snapshot
}
pub(super) fn collect_authority(path: &Path) -> Snapshot {
    let result = (|| -> Result<_> {
        let root = files::root(path)?;
        let _lock = files::try_lock(&root)?;
        let (_, state) = model::load(&root)?;
        Ok(authority(&state))
    })();
    result.unwrap_or_else(|_| unavailable(true))
}
fn encode(snapshot: &Snapshot) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec(snapshot).map_err(|_| anyhow!("DiagnosticEncodingFailed"))?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 4096, "DiagnosticSnapshotTooLarge");
    Ok(bytes)
}
pub(super) fn preview(snapshot: Snapshot) -> Result<Value> {
    let bytes = encode(&snapshot)?;
    Ok(
        json!({"status":"DiagnosticPreview", "previewDigest":files::hex_digest(&bytes), "snapshot":snapshot}),
    )
}
fn export(bytes: &[u8], expected: &str, path: &Path) -> Result<()> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "DiagnosticPreviewDigestInvalid"
    );
    ensure!(
        files::hex_digest(bytes) == expected,
        "DiagnosticSnapshotChanged"
    );
    let write = || -> Result<()> {
        let parent = crate::authority_files::private_directory(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("DiagnosticOutputUnavailable"))?;
        crate::authority_files::atomic_at(&parent, name, bytes, false)
    };
    write().map_err(|_| anyhow!("DiagnosticOutputUnavailable"))
}
pub(super) fn run(options: Options, collect: impl FnOnce(&Path) -> Snapshot) -> Result<Value> {
    let snapshot = collect(&options.directory);
    match (options.output, options.preview_digest) {
        (None, None) => preview(snapshot),
        (Some(output), Some(expected)) => {
            let bytes = encode(&snapshot)?;
            export(&bytes, &expected, &output)?;
            Ok(json!({"status":"DiagnosticExported", "previewDigest":files::hex_digest(&bytes)}))
        }
        _ => Err(anyhow!("DiagnosticExportArgumentsIncomplete")),
    }
}

#[cfg(test)]
#[path = "RuntimeDiagnosticsTests.rs"]
mod tests;
