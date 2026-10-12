// SPDX-License-Identifier: MIT
//! Offline collectors combine exact statements; they do not acquire signing authority.
use super::*;
use crate::{authority_history, authority_proof::TrustDescriptor};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
fn envelope(payload: &[u8], signatures: &BTreeMap<Key, [u8; 64]>) -> Result<Vec<u8>> {
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .iter()
            .map(|(key, signature)| a(vec![b(key), b(signature)]))
            .collect()),
    ]))
}
#[cfg(test)]
pub fn assemble_checkpoint(old: &TrustDescriptor, shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(
        (3..=4).contains(&shares.len()),
        "Three or four terminal shares required"
    );
    let mut signatures = BTreeMap::new();
    let mut expected = None;
    let mut statement = Vec::new();
    let mut decisions = Vec::new();
    for share in shares {
        ensure!(
            share.len() <= proof::MAX_ACTIVATION,
            "Terminal share exceeds bound"
        );
        let v = wire::decode(share)?;
        let f = v.array(8)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "EpochTerminalShare",
            "Terminal share kind differs"
        );
        let (payload, signed) = wire::envelope(f[4].bytes()?, 1)?;
        ensure!(
            signed.len() == 1
                && old.voters().contains(&signed[0].0)
                && signatures.insert(signed[0].0, signed[0].1).is_none(),
            "Repeated or foreign terminal signer"
        );
        let common = (f[3].clone(), f[5].clone());
        decisions.push((f[6].clone(), f[7].clone()));
        if let Some(prior) = &expected {
            ensure!(
                *prior == common && statement == payload,
                "Terminal shares differ"
            );
        } else {
            expected = Some(common);
            statement = payload;
        }
    }
    let (ordered, anchor) = expected.context("Terminal shares missing")?;
    let checkpoint = wire::encode(&a(vec![
        V::Uint(46),
        V::Uint(1),
        b(&envelope(&statement, &signatures)?),
        anchor,
    ]))?;
    let checked = authority_history::verify_checkpoint(old, &checkpoint)?;
    ensure!(
        checked.terminal(),
        "Ordinary checkpoint cannot terminate an epoch"
    );
    proof::command(old, ordered.bytes()?, &checked)?;
    // Honest replicas can retain different CommitQC subsets or deciding no-op descendants.
    // Every supplied decision must commit the same terminal prefix; none alters its state.
    for (deciding, suffix) in &decisions {
        proof::decide(old, &checked, deciding.bytes()?, suffix)?;
    }
    let (deciding, suffix) = decisions
        .into_iter()
        .next()
        .context("Terminal decision missing")?;
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("EpochTerminalCheckpoint".into()),
        ordered,
        b(&checkpoint),
        deciding,
        suffix,
    ]))
}
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
pub fn assemble_handoff(old: &TrustDescriptor, shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(
        (3..=4).contains(&shares.len()),
        "Three or four handoff shares required"
    );
    let mut signatures = BTreeMap::new();
    let mut expected = None;
    let mut statement = Vec::new();
    for share in shares {
        let v = wire::decode(share)?;
        let f = v.array(5)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "EpochHandoffShare",
            "Handoff share kind differs"
        );
        let (payload, signed) = wire::envelope(f[4].bytes()?, 1)?;
        ensure!(
            signed.len() == 1
                && old.voters().contains(&signed[0].0)
                && signatures.insert(signed[0].0, signed[0].1).is_none(),
            "Repeated or foreign handoff signer"
        );
        if let Some(prior) = &expected {
            ensure!(
                *prior == f[3] && statement == payload,
                "Handoff shares differ"
            );
        } else {
            expected = Some(f[3].clone());
            statement = payload;
        }
    }
    let package = expected.context("Handoff shares missing")?;
    let (ordered, checkpoint, deciding, suffix) = terminal_checkpoint(old, package.bytes()?)?;
    wire::encode(&a(vec![
        V::Uint(52),
        V::Uint(1),
        b(&ordered),
        b(checkpoint.canonical_proof()),
        b(&envelope(&statement, &signatures)?),
        V::Null,
        b(&deciding),
        suffix,
    ]))
}
#[cfg(test)]
pub fn assemble_ready(
    terminal: ValidatedTerminal,
    shares: &[Vec<u8>],
) -> Result<ValidatedActivation> {
    ensure!(
        (3..=4).contains(&shares.len()),
        "Three or four readiness shares required"
    );
    let mut signatures = BTreeMap::new();
    let expected = proof::ready_statement(&terminal)?;
    for share in shares {
        let (payload, signed) = wire::envelope(share, 1)?;
        ensure!(
            payload == expected
                && signed.len() == 1
                && signatures.insert(signed[0].0, signed[0].1).is_none(),
            "Readiness shares differ or repeat a signer"
        );
    }
    verify_activation(terminal, &envelope(&expected, &signatures)?)
}
