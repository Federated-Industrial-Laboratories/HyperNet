// SPDX-License-Identifier: MIT
//! Offline epoch commands use the same confined image and retain independent restart floors.
use super::{bootstrap, containers, control, files::*, model::*};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
#[path = "RuntimeEpochObjects.rs"]
mod objects;
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
    /// Independently retained signer floor; required after preparation.
    #[arg(long,value_parser=clap::value_parser!(u64).range(1..))]
    minimum_signer_generation: Option<u64>,
}
#[derive(Subcommand)]
pub enum Command {
    Prepare {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        history: PathBuf,
        #[arg(long)]
        terminal_state: PathBuf,
        #[arg(long)]
        prior_epochs: Option<PathBuf>,
        /// Exact indexed Page bodies for the accepted terminal state.
        #[arg(long)]
        objects: Option<PathBuf>,
        #[arg(long)]
        ready_output: PathBuf,
    },
    Terminal {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        share_output: PathBuf,
        #[arg(long)]
        state_output: PathBuf,
        #[arg(long)]
        epochs_output: PathBuf,
        /// Export all immutable Page inputs retained by this terminal state.
        #[arg(long)]
        objects_output: Option<PathBuf>,
    },
    Handoff {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        retained: Option<PathBuf>,
        #[arg(long)]
        share_output: PathBuf,
        #[arg(long)]
        history_output: PathBuf,
    },
    Activate {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        ready: PathBuf,
    },
}
fn output(path: &Path, bytes: &[u8]) -> Result<()> {
    safe_path(path)?;
    ensure!(
        path.is_absolute(),
        "Epoch output must use an absolute private path"
    );
    private_dir(path.parent().context("Epoch output parent missing")?)?;
    if path.exists() {
        ensure!(
            read(path, bytes.len().max(1))? == bytes,
            "Existing epoch output differs; no file replaced"
        );
    } else {
        create(path, bytes)?;
    }
    Ok(())
}
fn bytes(value: &mut Value, name: &str) -> Result<Vec<u8>> {
    let value = value
        .as_object_mut()
        .context("Epoch command response is not an object")?
        .remove(name)
        .context("Epoch output field missing")?;
    Ok(hex::decode(
        value.as_str().context("Epoch output is not hexadecimal")?,
    )?)
}
pub fn run(command: Command) -> Result<Value> {
    let location = match &command {
        Command::Prepare { location, .. }
        | Command::Terminal { location, .. }
        | Command::Handoff { location, .. }
        | Command::Activate { location, .. } => location,
    };
    let root = root(&location.directory)?;
    if !root.join("Manager").exists() {
        directory(&root.join("Manager"))?;
    }
    let _lock = manager_lock(&root.join("Manager"))?;
    let (p, mut s) = super::model::load(&root)?;
    ensure!(
        !s.resources.iter().any(|r| r.kind == "container"),
        "Stop authority workloads and runtime manager before offline epoch work"
    );
    verify_consent(&root, &p, &s)?;
    control::check_artifacts(&root, &p)?;
    if let Some(minimum) = location.minimum_signer_generation {
        retain_signer_generation(&root, minimum)?;
    } else {
        ensure!(
            matches!(command, Command::Prepare { .. }) && !s.initialised,
            "An independent signer generation is required"
        );
    }
    let mut arguments = Vec::new();
    let mut inputs: Vec<(&str, Vec<u8>)> = vec![];
    let mut input_objects = None;
    match &command {
        Command::Prepare {
            transition,
            history,
            terminal_state,
            prior_epochs,
            objects,
            ..
        } => {
            let AuthorityPurpose::FutureAuthority { epoch, .. } = &p.purpose else {
                anyhow::bail!("Epoch preparation requires explicit FutureAuthority setup");
            };
            let evidence = read(transition, 131072)?;
            let value = crate::trust_wire::decode(&evidence)?;
            let f = value.array(8)?;
            let (handoff, _) = crate::trust_wire::envelope(f[4].bytes()?, 4)?;
            let handoff = crate::trust_wire::decode(&handoff)?;
            let descriptor = crate::trust_wire::decode(handoff.array(8)?[5].bytes()?)?;
            ensure!(
                descriptor.array(11)?[4].uint()? == *epoch,
                "Transition differs from the configured future epoch"
            );
            inputs.extend([
                ("Transition.cbor", evidence),
                ("History.cbor", read(history, crate::trust_wire::MAXIMUM)?),
                (
                    "TerminalState.cbor",
                    read(terminal_state, crate::authority_capacity::MAX_STATE_BYTES)?,
                ),
            ]);
            if let Some(path) = objects {
                input_objects = Some(self::objects::open(path, &inputs[2].1)?);
            }
            arguments.extend(strings(&[
                "prepare",
                "--directory",
                "/State/Replica",
                "--bootstrap",
                "/Config/Bootstrap.cbor",
                "--bootstrap-digest",
                &p.bootstrap_digest,
                "--key",
                "/Config/Identity.json",
                "--config",
                "/Config/ReplicaConfig.json",
                "--authorization",
                "/Authorization",
                "--transition",
                "/EpochInput/Transition.cbor",
                "--history",
                "/EpochInput/History.cbor",
                "--terminal-state",
                "/EpochInput/TerminalState.cbor",
            ]));
            if input_objects.is_some() {
                arguments.extend(strings(&["--objects", "/EpochInput/Objects"]));
            }
            if let Some(path) = prior_epochs {
                inputs.push((
                    "PriorEpochs.json",
                    read(path, crate::authority_epoch::archive::MAX_ARCHIVE_BYTES)?,
                ));
                arguments.extend(strings(&["--prior-epochs", "/EpochInput/PriorEpochs.json"]));
            }
            containers::verify_image(&root, &p, &mut s)?;
            containers::prepare(&root, &p)?;
        }
        Command::Terminal { objects_output, .. } => {
            arguments.push("terminal".into());
            if objects_output.is_some() {
                arguments.extend(strings(&["--objects-output", "/EpochOutput/Objects"]));
            }
        }
        Command::Handoff {
            checkpoint,
            retained,
            ..
        } => {
            arguments.extend(strings(&[
                "handoff",
                "--checkpoint",
                "/EpochInput/Checkpoint.cbor",
            ]));
            inputs.push(("Checkpoint.cbor", read(checkpoint, 131072)?));
            if let Some(path) = retained {
                inputs.push(("Retained.json", read(path, crate::trust_wire::MAXIMUM)?));
                arguments.extend(strings(&["--retained", "/EpochInput/Retained.json"]));
            }
        }
        Command::Activate { ready, .. } => {
            arguments.extend(strings(&[
                "activate",
                "--ready",
                "/EpochInput/Ready.cbor",
                "--authorization",
                "/Authorization",
            ]));
            inputs.push(("Ready.cbor", read(ready, 2048)?));
        }
    }
    if !matches!(command, Command::Prepare { .. }) {
        ensure!(s.initialised, "Epoch command requires an installed signer");
        arguments.extend(strings(&[
            "--directory",
            "/State/Replica",
            "--minimum-generation",
            &signer_generation(&root)?.to_string(),
        ]));
    }
    let audit_operation = match &command {
        Command::Prepare { .. } => "EpochPrepare",
        Command::Activate { .. } => "EpochActivate",
        Command::Terminal { .. } | Command::Handoff { .. } => "EpochAdvance",
    };
    crate::runtime_audit::record(&root, &p.manifest.canonical()?, audit_operation, "Prepared")?;
    let input = root.join(format!("EpochInput{}", random_id()));
    directory(&input)?;
    for (name, body) in &inputs {
        create(&input.join(name), body)?;
    }
    if let Some(source) = &input_objects {
        objects::copy(source, &input.join("Objects"))?;
    }
    let export = if matches!(
        command,
        Command::Terminal {
            objects_output: Some(_),
            ..
        }
    ) {
        let path = root.join(format!("EpochOutput{}", random_id()));
        directory(&path)?;
        podman(&strings(&[
            "unshare",
            "/usr/bin/chown",
            "-R",
            "-h",
            "1001:1001",
            path.to_str().context("Epoch output path is not UTF-8")?,
        ]))?;
        Some(path)
    } else {
        None
    };
    podman(&strings(&[
        "unshare",
        "/usr/bin/chown",
        "-R",
        "-h",
        "1001:1001",
        input.to_str().context("Epoch path is not UTF-8")?,
    ]))?;
    let result =
        containers::epoch_temporary(&root, &p, &mut s, &input, export.as_deref(), &arguments);
    let cleanup = (|| -> Result<()> {
        podman(&strings(&[
            "unshare",
            "/usr/bin/chown",
            "-R",
            "-h",
            "0:0",
            input.to_str().unwrap(),
        ]))?;
        for (name, _) in &inputs {
            fs::remove_file(input.join(name))?;
        }
        if input_objects.is_some() {
            fs::remove_dir_all(input.join("Objects"))?;
        }
        fs::remove_dir(&input)?;
        Ok(())
    })();
    let exported = (|| -> Result<()> {
        if let Some(path) = &export {
            podman(&strings(&[
                "unshare",
                "/usr/bin/chown",
                "-R",
                "-h",
                "0:0",
                path.to_str().unwrap(),
            ]))?;
        }
        Ok(())
    })();
    cleanup?;
    exported?;
    let finished = (|| -> Result<Value> {
        let mut result = result?;
        bootstrap::retain_status(&root, &p, &result)?;
        match command {
            Command::Prepare { ready_output, .. } => {
                output(&ready_output, &bytes(&mut result, "readyShare")?)?;
                s.initialised = true;
                s.status = "EpochPrepared".into();
                super::model::save(&root, &s)?;
            }
            Command::Terminal {
                share_output,
                state_output,
                epochs_output,
                objects_output,
                ..
            } => {
                output(&share_output, &bytes(&mut result, "terminalShare")?)?;
                let terminal_state = bytes(&mut result, "terminalState")?;
                output(&state_output, &terminal_state)?;
                let chain = result
                    .as_object_mut()
                    .unwrap()
                    .remove("priorEpochs")
                    .context("Epoch archive missing")?;
                output(&epochs_output, &serde_json::to_vec(&chain)?)?;
                if let Some(destination) = objects_output {
                    let temporary = export.as_ref().unwrap();
                    let source = objects::open(&temporary.join("Objects"), &terminal_state)?;
                    objects::copy(&source, &destination)?;
                    result["objectsOutput"] = json!({
                        "directory": destination,
                        "objects": source.index().references().len(),
                        "terminalStateDigest": hex::encode(source.index().terminal_state()),
                    });
                }
            }
            Command::Handoff {
                share_output,
                history_output,
                ..
            } => {
                output(&share_output, &bytes(&mut result, "handoffShare")?)?;
                output(&history_output, &bytes(&mut result, "history")?)?;
            }
            Command::Activate { .. } => {
                s.status = "EpochActivated".into();
                super::model::save(&root, &s)?;
            }
        }
        result["networkServing"] = json!(false);
        Ok(result)
    })();
    let audit = if finished.is_ok() {
        crate::runtime_audit::record(
            &root,
            &p.manifest.canonical()?,
            audit_operation,
            "Committed",
        )
    } else {
        crate::runtime_audit::restrictive(
            &root,
            &p.manifest.canonical()?,
            audit_operation,
            "Failed",
        );
        Ok(())
    };
    let removed = export.map_or(Ok(()), fs::remove_dir_all);
    audit?;
    match (finished, removed) {
        (Err(error), Err(cleanup)) => Err(error.context(format!(
            "Could not remove temporary epoch output: {cleanup}"
        ))),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Ok(value), Ok(())) => Ok(value),
    }
}
