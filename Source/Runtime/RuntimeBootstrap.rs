// SPDX-License-Identifier: MIT
//! Initialise or inspect the exact appointed signer without authority-network access.
use super::model::save;
use super::{containers, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

pub fn retain_status(root: &Path, profile: &Profile, value: &Value) -> Result<()> {
    ensure!(
        value["signer"] == profile.signer
            && value["network"] == profile.network
            && value["configDigest"] == profile.config_digest()?,
        "Signer status differs from the consented deployment"
    );
    retain_signer_generation(
        root,
        value["generation"]
            .as_u64()
            .context("Signer generation is absent")?,
    )
}
pub fn initialise(root: &Path, profile: &Profile, state: &mut State) -> Result<()> {
    ensure!(
        !state.resources.iter().any(|r| r.kind == "container"),
        "Signer initialisation requires stopped workloads"
    );
    // The normal initializer validates a completed exact deployment idempotently.
    // Neither a missing marker nor a changed pin permits a journal to be recreated.
    let value = containers::temporary(root, profile, state, true)?;
    retain_status(root, profile, &value)?;
    state.initialised = true;
    save(root, state)
}
pub fn stopped(root: &Path, profile: &Profile, state: &mut State) -> Result<Option<Value>> {
    if !state.initialised {
        return Ok(None);
    }
    ensure!(
        !state.resources.iter().any(|r| r.kind == "container"),
        "Offline signer inspection requires stopped workloads"
    );
    let value = containers::temporary(root, profile, state, false)?;
    retain_status(root, profile, &value)?;
    Ok(Some(value))
}
