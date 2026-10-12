// SPDX-License-Identifier: MIT
// Each installed bridge has one local authority identity and only operator-pinned counterpart routes.
use crate::{
    authority_domains::{self as domains, Record, federation, page},
    authority_files as files, authority_local_transport as transport,
    authority_objects::Resolved,
    authority_page_service::disk,
    authority_proof::{Digest, VersionRef},
    confinement,
    runtime_service_activate::{self, Active},
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "AuthorityBridgeClient.rs"]
mod client;
#[path = "AuthorityBridgeRecovery.rs"]
pub(crate) mod recovery;
#[path = "AuthorityBridgeTls.rs"]
mod tls;
#[path = "AuthorityBridgeWorkflow.rs"]
mod workflow;
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
    listen_socket: PathBuf,
    certificate_file: PathBuf,
    transport_key_file: PathBuf,
    certificate_authority_file: PathBuf,
    media_hosts: Vec<String>,
}
pub struct Config {
    pub profile: federation::BridgeProfile,
    key: SigningKey,
    media: BTreeMap<Digest, PathBuf>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "bridge must be PID1 under its dedicated service UID"
        );
        let raw: Configuration = serde_json::from_slice(&files::read(path, 16384, true)?)?;
        for (actual, expected) in [
            (&raw.bootstrap_file, "/Config/Bootstrap.cbor"),
            (&raw.manifest_file, "/Config/Manifest.cbor"),
            (&raw.profile_file, "/Config/BridgeProfile.cbor"),
            (&raw.identity_file, "/Config/Service.key"),
            (&raw.state_file, "/State/BridgeState.bin"),
            (&raw.control_socket, "/Authority/Control.sock"),
            (&raw.clock_witness_file, "/Clock/ClockHealth.cbor"),
            (&raw.listen_socket, "/State/Control/Control.sock"),
            (&raw.certificate_file, "/Config/Certificate.pem"),
            (&raw.transport_key_file, "/Config/Transport.key"),
            (
                &raw.certificate_authority_file,
                "/Config/CertificateAuthority.pem",
            ),
        ] {
            ensure!(
                actual == Path::new(expected),
                "bridge configuration path leaves its fixed template"
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
                && manifest.network == bootstrap.descriptor().scope().network
                && manifest.incarnation == bootstrap.descriptor().scope().incarnation,
            "bridge bootstrap pin differs"
        );
        let profile = federation::BridgeProfile::parse(
            &files::read(&raw.profile_file, wire::MAXIMUM, true)?,
            manifest.network,
            manifest.incarnation,
        )?;
        ensure!(
            profile.manifest == manifest,
            "bridge profile manifest differs"
        );
        let role = manifest
            .roles
            .iter()
            .find(|r| r.role == 7)
            .context("bridge role absent")?;
        ensure!(
            manifest.roles.len() == 1
                && role.bind_endpoint_ids.len() == 1
                && !role.outbound_endpoint_ids.is_empty(),
            "bridge requires one TLS listener and exact counterpart routes"
        );
        let seed = zeroize::Zeroizing::new(files::read(&raw.identity_file, 32, true)?);
        let key = SigningKey::from_bytes(
            seed.as_slice()
                .try_into()
                .context("bridge key must be a raw32-byte seed")?,
        );
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "bridge signing identity differs"
        );
        let mut media = BTreeMap::new();
        for host in raw.media_hosts {
            let id = crate::trust_bootstrap::hex32(&host)?;
            ensure!(
                host == hex::encode(id)
                    && media
                        .insert(
                            id,
                            PathBuf::from(format!("/Media/{host}/Control/Control.sock"))
                        )
                        .is_none(),
                "bridge local media hosts repeat or are not canonical"
            );
        }
        Ok(Self {
            profile,
            key,
            media,
        })
    }
    pub fn confinement(&self) -> Result<confinement::Profile> {
        let role = self
            .profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 7)
            .context("bridge role absent")?;
        let ports = |ids: &[Digest]| -> Result<Vec<u16>> {
            ids.iter()
                .map(|id| {
                    self.profile
                        .manifest
                        .endpoints
                        .iter()
                        .find(|e| e.endpoint_id == *id)
                        .map(|e| e.port)
                        .context("bridge endpoint absent")
                })
                .collect()
        };
        let mut read = vec!["/Config", "/Clock", "/Authorization", "/Authority"]
            .into_iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        read.extend(
            self.media
                .values()
                .map(|p| p.parent().expect("fixed media parent").to_path_buf()),
        );
        confinement::enter_bridge(
            Path::new("/State"),
            &read,
            &ports(&role.bind_endpoint_ids)?,
            &ports(&role.outbound_endpoint_ids)?,
        )
    }
    pub fn resources(&self, actual: &confinement::Profile) -> Result<()> {
        let role = self
            .profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 7)
            .context("bridge role absent")?;
        let cpu = actual
            .cpu_max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            actual.memory_max <= role.memory_bytes
                && actual.pids_max <= role.pids
                && cpu.len() == 2
                && cpu[0] <= role.cpu_quota
                && cpu[1] == role.cpu_period,
            "bridge resource confinement exceeds consent"
        );
        Ok(())
    }
}
pub fn initialise(guard: &Guard) -> Result<()> {
    ensure!(guard.role == 7, "bridge initialisation requires own role");
    let profile = federation::BridgeProfile::parse(
        &files::read(Path::new("/Config/BridgeProfile.cbor"), wire::MAXIMUM, true)?,
        guard.manifest.network,
        guard.manifest.incarnation,
    )?;
    let path = Path::new("/State/BridgeState.bin");
    if !path.try_exists()? {
        disk::Disk::initialise_bridge(path, &profile)?;
    }
    drop(disk::Disk::open_bridge(
        path,
        &profile,
        guard.health()?.observe()?.wall_ms,
    )?);
    runtime_service_activate::initialise(guard)
}
pub async fn run(config: Config, guard: &Guard, active: &mut Active) -> Result<()> {
    ensure!(
        guard.role == 7 && config.profile.manifest == guard.manifest,
        "bridge activation differs"
    );
    let network = tls::Transport::load(&config).context("load Bridge TLS transport")?;
    let client = client::Shared::new(
        client::Client::open(&config, guard, active).context("open retained Bridge client")?,
    );
    workflow::run(&config, guard, active, &network, &client).await
}
pub fn exchange_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let v = wire::decode(packet)?;
    let f = v.list(10)?;
    ensure!(
        f.len() >= 3
            && f[0].uint()? == 200
            && f[1].uint()? == 1
            && matches!(f[2].text()?, "BridgeLease" | "BridgeSync"),
        "unknown local bridge operation"
    );
    let guard = Guard::load(Path::new("/Authorization"), Path::new("/Config"), 7)?;
    let now = guard.health()?.observe()?;
    let remaining = guard
        .manifest
        .validity
        .1
        .checked_sub(now.wall_ms)
        .context("bridge consent expired")?;
    let result = transport::LocalControl::open(Path::new("/State/Control/Control.sock"))?
        .exchange_limit(
            packet,
            now.boot_ms
                .checked_add(remaining)
                .context("bridge exchange deadline overflow")?,
            tls::FRAME,
        )?;
    guard.check()?;
    Ok(result)
}
