// SPDX-License-Identifier: MIT
//! A stopped service adopts one certified epoch in both private authority journals.
use crate::{
    authority_floor, authority_recipient, runtime_authorization::public_read,
    runtime_service_authorization::Guard, trust_wire,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Subcommand)]
pub enum Command {
    Retained,
    Seal,
    Activate,
}
struct Input {
    transition: Vec<u8>,
    requester: Vec<u8>,
    recipient: Vec<u8>,
    ready: Option<Vec<u8>>,
}
/// Inputs are bounded and read before confinement; no input-selected filesystem path is used.
pub fn run(command: Command) -> Result<Value> {
    let input = if matches!(command, Command::Retained) {
        None
    } else {
        Some(Input {
            transition: public_read(Path::new("/EpochInput/Transition.cbor"), 131072)?,
            requester: public_read(
                Path::new("/EpochInput/RequesterHistory.cbor"),
                trust_wire::MAXIMUM,
            )?,
            recipient: public_read(
                Path::new("/EpochInput/RecipientHistory.cbor"),
                trust_wire::MAXIMUM,
            )?,
            ready: if matches!(command, Command::Activate) {
                Some(public_read(Path::new("/EpochInput/Ready.cbor"), 2048)?)
            } else {
                None
            },
        })
    };
    let manifest = crate::runtime_manifest::Manifest::parse(&public_read(
        Path::new("/Authorization/Manifest.cbor"),
        crate::runtime_manifest::MAXIMUM,
    )?)?;
    ensure!(
        manifest.roles.len() == 1 && matches!(manifest.roles[0].role, 1..=4 | 7 | 8),
        "Unsupported installed service epoch role"
    );
    let role = manifest.roles[0].role;
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), role)?;
    if role == 8 {
        crate::confinement::enter_ssh_parent(Path::new("/State"), &[], &[])?;
    } else {
        crate::confinement::enter_authority(
            Path::new("/State"),
            &["/Config", "/Clock", "/Authorization", "/Authority"].map(std::path::PathBuf::from),
            &[],
            &[],
        )?;
    }
    guard.check()?;
    let mut requester = authority_floor::Store::open(
        Path::new("/State/Requester"),
        guard.bootstrap.descriptor().clone(),
    )?;
    requester.require_requester(guard.key())?;
    let mut recipient = authority_recipient::Store::open(
        Path::new("/State/Recipient"),
        guard.bootstrap.descriptor().clone(),
        guard.key(),
    )?;
    if let Some(input) = input {
        let rt = requester.verify_epoch_terminal(&input.transition, &input.requester)?;
        let st = recipient.verify_epoch_terminal(&input.transition, &input.recipient)?;
        ensure!(
            rt.handoff() == st.handoff(),
            "Service journals selected different successors"
        );
        // Validate both ready proofs before retaining either activation. A partial publication remains stopped.
        let ready = input
            .ready
            .as_ref()
            .map(|ready| -> Result<_> {
                Ok((
                    crate::authority_epoch::verify_activation(rt.clone(), ready)?,
                    crate::authority_epoch::verify_activation(st.clone(), ready)?,
                ))
            })
            .transpose()?;
        if recipient.descriptor().scope() == st.old_descriptor().scope() {
            recipient.seal_epoch(&st)?;
        }
        if requester.descriptor().scope() == rt.old_descriptor().scope() {
            requester.seal_epoch(&rt)?;
        }
        if matches!(command, Command::Activate) {
            let (requester_ready, recipient_ready) =
                ready.context("Matching ready quorum required")?;
            guard.check()?;
            recipient.activate_epoch(&recipient_ready)?;
            requester.activate_epoch(&requester_ready)?;
            ensure!(
                requester.descriptor().canonical() == recipient.descriptor().canonical()
                    && !requester.epoch_sealed()
                    && !recipient.epoch_sealed(),
                "Service epoch activation is incomplete"
            );
        }
    }
    guard.check()?;
    Ok(
        json!({"status": match command { Command::Retained=>"ServiceEpochRetained",Command::Seal=>"ServiceEpochSealed",Command::Activate=>"ServiceEpochActivated" },
        "requesterEpoch":requester.descriptor().scope().epoch,"recipientEpoch":recipient.descriptor().scope().epoch,
        "authorityConfiguration":hex::encode(recipient.descriptor().scope().configuration),
        "requesterSealed":requester.epoch_sealed(),"recipientSealed":recipient.epoch_sealed(),
        "requesterRetained":requester.epoch_retained()?,"recipientRetained":recipient.epoch_retained()?,
        "networkServing":false,"currentPermission":false}),
    )
}
