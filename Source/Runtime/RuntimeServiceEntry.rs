// SPDX-License-Identifier: MIT
// Dedicated finite service entry points apply fixed mounts and confinement before retained-state access.
use crate::{
    authority_bridge_service as bridge, authority_mail_service as mail_store,
    authority_media_service as media_store, authority_page_service as page_store,
    authority_transfer_service as transfer, confinement, runtime_service_activate as activation,
    runtime_service_authorization::Guard,
};
use anyhow::{Result, ensure};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub fn exchange(expected_role: u64) -> Result<()> {
    ensure!(
        matches!(expected_role, 1..=4 | 7) && role()? == expected_role,
        "packet exchange requires its own installed service role"
    );
    store_confinement()?;
    let mut input = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(crate::trust_wire::MAXIMUM as u64 + 1)
        .read_to_end(&mut input)?;
    ensure!(
        input.len() <= crate::trust_wire::MAXIMUM,
        "service packet exceeds its bound"
    );
    let reply = if expected_role == 7 {
        bridge::exchange_packet(&input)?
    } else if expected_role == 1 {
        crate::authority_content_service::exchange_packet(&input)?
    } else if expected_role == 2 {
        media_store::exchange_packet(&input)?
    } else if expected_role == 3 {
        mail_store::exchange_packet(&input)?
    } else {
        transfer::exchange_packet(&input)?
    };
    std::io::stdout().lock().write_all(&reply)?;
    Ok(())
}
fn role() -> Result<u64> {
    let m = crate::runtime_manifest::Manifest::parse(&crate::runtime_authorization::public_read(
        Path::new("/Authorization/Manifest.cbor"),
        crate::runtime_manifest::MAXIMUM,
    )?)?;
    ensure!(
        m.roles.len() == 1 && matches!(m.roles[0].role, 1..=5 | 7 | 8),
        "unsupported installed service role"
    );
    Ok(m.roles[0].role)
}
fn store_confinement() -> Result<confinement::Profile> {
    confinement::enter_authority(
        Path::new("/State"),
        &["/Config", "/Clock", "/Authorization", "/Authority"].map(PathBuf::from),
        &[],
        &[],
    )
}
pub fn initialise() -> Result<()> {
    prepare(false)
}
pub fn verify_existing() -> Result<()> {
    prepare(true)
}
fn retained(guard: &Guard, role: u64, verify_only: bool) -> Result<()> {
    if !verify_only {
        return Ok(());
    }
    let requester = crate::authority_floor::Store::open(
        Path::new("/State/Requester"),
        guard.bootstrap.descriptor().clone(),
    )?;
    requester.require_requester(guard.key())?;
    let recipient = crate::authority_recipient::Store::open(
        Path::new("/State/Recipient"),
        guard.bootstrap.descriptor().clone(),
        guard.key(),
    )?;
    ensure!(
        requester.descriptor().canonical() == recipient.descriptor().canonical(),
        "Retained requester and recipient authority epochs differ"
    );
    let path = match role {
        1 => {
            let config = page_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
            if config.profile.content.is_some() {
                "/State/Content"
            } else {
                "/State/PageState.bin"
            }
        }
        2 => "/State/MediaState.bin",
        3 => "/State/MailState.bin",
        4 => "/State/TransferState.bin",
        5 => "/State/RouteState.cbor",
        7 => "/State/BridgeState.bin",
        8 => return Ok(()),
        _ => unreachable!(),
    };
    ensure!(
        Path::new(path).try_exists()?,
        "Retained service data is absent; explicit data recovery is required"
    );
    guard.check()
}
fn prepare(verify_only: bool) -> Result<()> {
    let role = role()?;
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), role)?;
    if role == 5 {
        let config = crate::route_config::Config::load()?;
        let profile = store_confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        drop(crate::route_state::Disk::open(
            Path::new("/State"),
            config.manifest.network,
            config.manifest.incarnation,
            config.metadata_bytes,
        )?);
        activation::initialise(&guard)?;
    } else if role == 7 {
        let config = bridge::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        let profile = config.confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        bridge::initialise(&guard)?;
    } else if role == 8 {
        let config = crate::ssh_service::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        confinement::enter_ssh_parent(Path::new("/State"), &[config.listen.port()], &[])?;
        retained(&guard, role, verify_only)?;
        activation::initialise(&guard)?;
    } else if role == 1 {
        let config = page_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        let profile = store_confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        page_store::initialise(&guard)?;
    } else if role == 2 {
        let config = media_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        let profile = store_confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        media_store::initialise(&guard)?;
    } else if role == 3 {
        let config = mail_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        let profile = store_confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        mail_store::initialise(&guard)?;
    } else {
        let config = transfer::Config::load(Path::new("/Config/ServiceConfig.json"))?;
        let profile = store_confinement()?;
        config.resources(&profile)?;
        retained(&guard, role, verify_only)?;
        transfer::initialise(&guard)?;
    }
    println!(
        "{}",
        serde_json::json!({"status":"ServicePrepared","currentPermission":false})
    );
    Ok(())
}
pub fn bridge() -> Result<()> {
    ensure!(role()? == 7, "Bridge entry requires own role");
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 7)?;
    let config = bridge::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let profile = config.confinement()?;
    config.resources(&profile)?;
    let mut active = activation::activate(&guard)
        .map_err(|error| anyhow::anyhow!("Bridge startup activation failed: {error:#}"))?;
    crate::runtime()?
        .block_on(bridge::run(config, &guard, &mut active))
        .map_err(|error| anyhow::anyhow!("Bridge startup or serving failed: {error:#}"))
}
pub fn bridge_requester(fence: bool) -> Result<()> {
    ensure!(
        role()? == 7,
        "requester recovery requires its own Bridge role"
    );
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 7)?;
    let config = bridge::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let expected = if fence {
        Some(crate::runtime_authorization::public_read(
            Path::new("/EpochInput/Expected.cbor"),
            486,
        )?)
    } else {
        None
    };
    let profile = store_confinement()?;
    config.resources(&profile)?;
    let bytes = bridge::recovery::run(&config, &guard, expected.as_deref())?;
    guard.check()?;
    std::io::stdout().lock().write_all(&bytes)?;
    Ok(())
}
pub fn pages() -> Result<()> {
    ensure!(role()? == 1, "Page entry requires its own role");
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 1)?;
    let config = page_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let profile = store_confinement()?;
    config.resources(&profile)?;
    let mut active = activation::activate(&guard)?;
    crate::runtime()?.block_on(page_store::run(config, &guard, &mut active))
}
pub fn media() -> Result<()> {
    ensure!(role()? == 2, "Media entry requires its own role");
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 2)?;
    let config = media_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let profile = store_confinement()?;
    config.resources(&profile)?;
    let mut active = activation::activate(&guard)?;
    crate::runtime()?.block_on(media_store::run(config, &guard, &mut active))
}
pub fn transfers() -> Result<()> {
    ensure!(role()? == 4, "Transfer entry requires its own role");
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 4)?;
    let config = transfer::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let profile = store_confinement()?;
    config.resources(&profile)?;
    let mut active = activation::activate(&guard)?;
    crate::runtime()?.block_on(transfer::run(config, &guard, &mut active))
}
pub fn mail() -> Result<()> {
    ensure!(role()? == 3, "Mail entry requires its own role");
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 3)?;
    let config = mail_store::Config::load(Path::new("/Config/ServiceConfig.json"))?;
    let profile = store_confinement()?;
    config.resources(&profile)?;
    let mut active = activation::activate(&guard)?;
    crate::runtime()?.block_on(mail_store::run(config, &guard, &mut active))
}
pub fn receipt() -> Result<()> {
    // Export is historical reporting and remains available after consent expiry or withdrawal.
    // The private service files are never selected by an input path.
    if role()? == 8 {
        confinement::enter_ssh_parent(Path::new("/State"), &[], &[])?;
    } else {
        store_confinement()?;
    }
    let bytes = crate::authority_files::read(
        Path::new("/State/Recipient/ActivationReceipt.cbor"),
        4 * crate::trust_wire::MAXIMUM,
        true,
    )?;
    let receipt = crate::authority_runtime_activation::Receipt::parse(&bytes)?;
    std::io::stdout().lock().write_all(receipt.canonical())?;
    Ok(())
}

pub fn routes() -> Result<()> {
    ensure!(
        role()? == 5,
        "private route entry requires its own installed role"
    );
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 5)?;
    let config = crate::route_config::Config::load()?;
    let profile = config.confinement()?;
    config.resources(&profile)?;
    let active = activation::activate(&guard)?;
    crate::runtime()?.block_on(crate::route_runtime::run(config, &guard, &active))
}
