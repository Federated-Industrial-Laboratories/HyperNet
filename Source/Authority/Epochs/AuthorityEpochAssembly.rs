// SPDX-License-Identifier: MIT
//! Offline collectors combine exact statements; they do not acquire signing authority.
use super::*;
use crate::{authority_history, authority_proof::TrustDescriptor};

pub fn terminal_checkpoint(
    old: &TrustDescriptor,
    input: &[u8],
) -> Result<(Vec<u8>, authority_history::ValidatedCheckpoint, Vec<u8>, V)> {
    ensure!(
        input.len() <= proof::MAX_ACTIVATION,
        "Terminal checkpoint package exceeds bound"
    );
    let v = wire::decode(input)?;
    let f = v.array(7)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "EpochTerminalCheckpoint",
        "Terminal checkpoint package kind differs"
    );
    let checkpoint = authority_history::verify_checkpoint(old, f[4].bytes()?)?;
    ensure!(checkpoint.terminal(), "Terminal checkpoint required");
    proof::command(old, f[3].bytes()?, &checkpoint)?;
    proof::decide(old, &checkpoint, f[5].bytes()?, &f[6])?;
    Ok((
        f[3].bytes()?.to_vec(),
        checkpoint,
        f[5].bytes()?.to_vec(),
        f[6].clone(),
    ))
}

#[cfg(test)]
include!("../../../Tests/Support/Authority/Epochs/AuthorityEpochAssembly.rs");
