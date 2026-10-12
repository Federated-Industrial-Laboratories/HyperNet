// SPDX-License-Identifier: MIT
//! Explicit offline service epoch commands retain both authority journals without running a listener.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt};
#[derive(Subcommand)]
pub enum Command {
    /// Export both exact retained floors for separate terminal history proofs.
    Retained {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        requester_output: PathBuf,
        #[arg(long)]
        recipient_output: PathBuf,
    },
    /// Durably stop old effects in both journals before committee activation.
    Seal {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        requester_history: PathBuf,
        #[arg(long)]
        recipient_history: PathBuf,
    },
    /// Accept one matching ready quorum in both journals; does not restart the service.
    Activate {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        requester_history: PathBuf,
        #[arg(long)]
        recipient_history: PathBuf,
        #[arg(long)]
        ready: PathBuf,
        /// Explicit local route to a running member of this exact activated committee.
        #[arg(long)]
        authority_directory: PathBuf,
    },
}
fn output(path: &Path, bytes: &[u8]) -> Result<()> {
    files::safe_path(path)?;
    ensure!(
        path.is_absolute(),
        "Service epoch output needs an absolute private path"
    );
    files::private_dir(path.parent().context("Output parent missing")?)?;
    if path.exists() {
        ensure!(
            files::read(path, bytes.len().max(1))? == bytes,
            "Existing output differs; no file replaced"
        );
    } else {
        files::create(path, bytes)?;
    }
    Ok(())
}
pub(super) fn run(command: Command) -> Result<Value> {
    let location = match &command {
        Command::Retained { location, .. }
        | Command::Seal { location, .. }
        | Command::Activate { location, .. } => location,
    };
    let root = files::root(&location.directory)?;
    let _lock = files::lock(&root)?;
    let (p, mut s) = load(&root)?;
    ensure!(
        s.container.is_none(),
        "Stop the service before offline epoch adoption"
    );
    p.check_artifacts()?;
    ensure!(
        s.consented && !s.withdrawn,
        "Current explicit local consent is required"
    );
    let route = if let Command::Activate {
        authority_directory,
        ..
    } = &command
    {
        let root = files::root(authority_directory)?;
        let (authority, state) = super::super::model::load(&root)?;
        let bootstrap_bytes = files::read(&root.join("Work/Config/Bootstrap.cbor"), wire::MAXIMUM)?;
        let bootstrap = crate::trust_bootstrap::inspect(&bootstrap_bytes, true)?;
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.file_digest() == p.manifest.bootstrap_digest
                && authority.network == hex::encode(p.manifest.network)
                && authority.incarnation == hex::encode(p.manifest.incarnation),
            "New control route has another independently accepted network"
        );
        super::super::control::check_artifacts(&root, &authority)?;
        let health = containers::live_status(
            &authority,
            &state,
            super::super::model::signer_generation(&root)?,
        )?;
        ensure!(
            health["network"] == hex::encode(p.manifest.network)
                && health["incarnation"] == hex::encode(p.manifest.incarnation),
            "New control route scope differs"
        );
        Some((
            root.join("Launch/State/Control"),
            health["authorityConfiguration"]
                .as_str()
                .context("New authority scope missing")?
                .to_string(),
        ))
    } else {
        None
    };
    let mut inputs = Vec::new();
    match &command {
        Command::Seal {
            transition,
            requester_history,
            recipient_history,
            ..
        }
        | Command::Activate {
            transition,
            requester_history,
            recipient_history,
            ..
        } => {
            inputs.push(("Transition.cbor", files::read(transition, 131072)?));
            inputs.push((
                "RequesterHistory.cbor",
                files::read(requester_history, wire::MAXIMUM)?,
            ));
            inputs.push((
                "RecipientHistory.cbor",
                files::read(recipient_history, wire::MAXIMUM)?,
            ));
        }
        Command::Retained { .. } => {}
    }
    if let Command::Activate { ready, .. } = &command {
        inputs.push(("Ready.cbor", files::read(ready, 2048)?));
    }
    let input = root.join(format!("EpochInput{}", files::random_id()));
    files::directory(&input)?;
    for (name, bytes) in &inputs {
        files::publish_public(&input.join(name), bytes)?;
    }
    fs::set_permissions(&input, fs::Permissions::from_mode(0o755))?;
    let action = match &command {
        Command::Retained { .. } => "retained",
        Command::Seal { .. } => "seal",
        Command::Activate { .. } => "activate",
    };
    let result = control::epoch(
        &p,
        &mut s,
        &input,
        &files::strings(&["runtime-service-epoch", action]),
    );
    // Only these freshly created public proof files belong to this operation.
    let cleanup = (|| -> Result<()> {
        for (name, _) in &inputs {
            fs::remove_file(input.join(name))?;
        }
        fs::remove_dir(&input)?;
        Ok(())
    })();
    let mut result = result?;
    cleanup?;
    if let Some((path, configuration)) = route {
        ensure!(
            result["authorityConfiguration"] == configuration
                && result["requesterEpoch"] == result["recipientEpoch"]
                && result["requesterSealed"] == false
                && result["recipientSealed"] == false,
            "Control route differs from the exact activated service journals"
        );
        s.authority_control = Some(path.clone());
        save(&p, &mut s)?;
        result["authorityControl"] = json!(path);
    }
    if let Command::Retained {
        requester_output,
        recipient_output,
        ..
    } = command
    {
        output(
            &requester_output,
            &serde_json::to_vec_pretty(
                result
                    .get("requesterRetained")
                    .context("Requester floor missing")?,
            )?,
        )?;
        output(
            &recipient_output,
            &serde_json::to_vec_pretty(
                result
                    .get("recipientRetained")
                    .context("Recipient floor missing")?,
            )?,
        )?;
    }
    let object = result
        .as_object_mut()
        .context("Service epoch result must be an object")?;
    object.remove("requesterRetained");
    object.remove("recipientRetained");
    Ok(result)
}
