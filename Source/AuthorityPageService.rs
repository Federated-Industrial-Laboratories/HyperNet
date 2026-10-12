// SPDX-License-Identifier: MIT
// An activated Page host maintains approved local bundles and fulfils exact reader tickets through authority.
use crate::{
    authority_domains::{Record, page},
    authority_files as files, confinement,
    runtime_service_activate::{self, Active},
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "AuthorityPageClient.rs"]
mod client;
#[path = "AuthorityPageDisk.rs"]
pub(crate) mod disk;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    bootstrap_file: PathBuf,
    manifest_file: PathBuf,
    profile_file: PathBuf,
    identity_file: PathBuf,
    state_file: PathBuf,
    control_socket: PathBuf,
    clock_witness_file: PathBuf,
}
pub struct Config {
    pub profile: page::HostProfile,
    key: SigningKey,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "Page store must be PID1 under its dedicated service UID"
        );
        let raw: Configuration = serde_json::from_slice(&files::read(path, 16384, true)?)?;
        for (actual, expected) in [
            (&raw.bootstrap_file, "/Config/Bootstrap.cbor"),
            (&raw.manifest_file, "/Config/Manifest.cbor"),
            (&raw.profile_file, "/Config/PageProfile.cbor"),
            (&raw.identity_file, "/Config/Service.key"),
            (&raw.state_file, "/State/PageState.bin"),
            (&raw.control_socket, "/Authority/Control.sock"),
            (&raw.clock_witness_file, "/Clock/ClockHealth.cbor"),
        ] {
            ensure!(
                actual == Path::new(expected),
                "Page path differs from its confined profile"
            );
        }
        let manifest = crate::runtime_manifest::Manifest::parse(&files::read(
            &raw.manifest_file,
            crate::runtime_manifest::MAXIMUM,
            true,
        )?)?;
        let bootstrap = crate::trust_bootstrap::inspect(
            &files::read(&raw.bootstrap_file, wire::MAXIMUM, true)?,
            true,
        )?;
        ensure!(
            manifest.bootstrap_digest == bootstrap.file_digest()
                && bootstrap.descriptor().scope().network == manifest.network
                && bootstrap.descriptor().scope().incarnation == manifest.incarnation,
            "Page manifest differs from accepted bootstrap"
        );
        let profile = page::HostProfile::parse(
            &files::read(
                &raw.profile_file,
                crate::runtime_manifest::MAXIMUM + 2048,
                true,
            )?,
            manifest.network,
            manifest.incarnation,
        )?;
        let role = manifest
            .roles
            .iter()
            .find(|r| r.role == 1)
            .context("Page role absent")?;
        ensure!(
            profile.manifest == manifest
                && profile.role == 1
                && role.bind_endpoint_ids.is_empty()
                && role.outbound_endpoint_ids.is_empty(),
            "local Page profile must have no direct network route"
        );
        let seed = zeroize::Zeroizing::new(files::read(&raw.identity_file, 32, true)?);
        let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            seed.as_slice()
                .try_into()
                .context("Page service key must be a raw32-byte seed")?,
        );
        let key = SigningKey::from_bytes(&seed);
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "Page signing identity differs from consent"
        );
        Ok(Self { profile, key })
    }
    pub fn resources(&self, actual: &confinement::Profile) -> Result<()> {
        let role = self
            .profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 1)
            .context("Page role absent")?;
        let cpu = actual
            .cpu_max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            actual.memory_max <= role.memory_bytes
                && actual.pids_max <= role.pids
                && cpu.len() == 2
                && cpu[0] as u128 * role.cpu_period as u128
                    <= role.cpu_quota as u128 * cpu[1] as u128,
            "Page cgroup exceeds consent"
        );
        Ok(())
    }
}
pub fn initialise(guard: &Guard) -> Result<()> {
    guard.check()?;
    ensure!(guard.role == 1, "Page preparation has another role");
    let config = Config::load(Path::new("/Config/ServiceConfig.json"))?;
    ensure!(
        config.profile.manifest == guard.manifest,
        "Page profile differs from local authorization"
    );
    runtime_service_activate::initialise(guard)?;
    let path = Path::new("/State/PageState.bin");
    if !path.try_exists()? {
        disk::Disk::initialise(path, &config.profile)?;
    }
    disk::Disk::open(path, &config.profile, guard.health()?.observe()?.wall_ms)?;
    guard.check()
}
fn records(value: &V, profile: &page::HostProfile) -> Result<Vec<Record>> {
    let f = value.array(5)?;
    let body = f[4].array(4)?;
    body[1]
        .list(page::MAXIMUM_CONTEXT_RECORDS)?
        .iter()
        .map(|v| {
            Record::parse(
                v.bytes()?,
                profile.manifest.network,
                profile.manifest.incarnation,
            )
        })
        .collect()
}
fn continuation(value: &V) -> Result<Option<[u8; 32]>> {
    let body = value.array(5)?[4].array(4)?;
    if body[3] == V::Null {
        Ok(None)
    } else {
        Ok(Some(body[3].fixed()?))
    }
}
fn maintain(
    client: &mut client::Client<'_>,
    profile: &page::HostProfile,
    namespace: &str,
    after: &mut Option<[u8; 32]>,
) -> Result<()> {
    if let Some(command) = client.pending()? {
        client.action(command)?;
        return Ok(());
    }
    let value = client
        .action(page::Command::ReplicaQueue {
            host: profile.service,
            namespace: namespace.into(),
            after: None,
        })?
        .completed()?;
    let returned = records(&value, profile)?;
    if let Some(record) = returned.iter().find(|r| r.reference.kind == 146) {
        let ticket = page::Ticket::parse(&record.payload)?;
        let review = page::Review::parse(
            &returned
                .iter()
                .find(|r| r.reference == ticket.publication)
                .context("Page ticket review is absent")?
                .payload,
            profile.manifest.network,
            profile.manifest.incarnation,
        )?;
        let revision = page::Revision::parse(
            &returned
                .iter()
                .find(|r| r.reference == review.statement.revision)
                .context("Page ticket revision is absent")?
                .payload,
            profile.manifest.network,
            profile.manifest.incarnation,
        )?;
        let bundle = review
            .bundle
            .context("Page ticket has no approved bundle")?;
        if !client.cached(&bundle) {
            client.action(page::Command::Sync {
                host: profile.service,
                namespace: namespace.into(),
                after: None,
                fetch: Some(revision.author.raw_page),
            })?;
        }
        client.action(page::Command::ReplicaDeliver {
            ticket: record.reference.clone(),
            bundle,
        })?;
        return Ok(());
    }
    let value = client
        .action(page::Command::Sync {
            host: profile.service,
            namespace: namespace.into(),
            after: *after,
            fetch: None,
        })?
        .completed()?;
    let returned = records(&value, profile)?;
    for record in returned.iter().filter(|r| r.reference.kind == 140) {
        let ledger = page::Ledger::parse(&record.payload)?;
        let Some(published) = ledger.published else {
            continue;
        };
        let review = page::Review::parse(
            &returned
                .iter()
                .find(|r| r.reference == published)
                .context("Page inventory review is absent")?
                .payload,
            profile.manifest.network,
            profile.manifest.incarnation,
        )?;
        let bundle = review
            .bundle
            .context("Page inventory lacks approved bundle")?;
        if !client.cached(&bundle) {
            client.action(page::Command::Sync {
                host: profile.service,
                namespace: namespace.into(),
                after: None,
                fetch: Some(ledger.raw_page),
            })?;
        }
    }
    *after = continuation(&value)?;
    Ok(())
}
pub async fn run(config: Config, guard: &Guard, active: &mut Active) -> Result<()> {
    active.check(guard)?;
    ensure!(
        guard.role == 1 && config.profile.manifest == guard.manifest,
        "Page service differs from activated role"
    );
    let mut client = client::Client::open(&config, guard, active)?;
    let mut cursors = vec![None; config.profile.namespaces.len()];
    let mut next = 0usize;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=tick.tick()=> {
                active.check(guard)?;
                maintain(&mut client,&config.profile,&config.profile.namespaces[next],&mut cursors[next])?;
                next=(next+1)%config.profile.namespaces.len();
            }
        }
    }
    active.check(guard)
}
