// SPDX-License-Identifier: MIT
// Installed route services bind one signed profile, fixed application mount and isolated numeric egress.
use crate::{
    authority_domains::routes::RegisteredProfile, authority_files as files, confinement,
    route_profile::Identity, runtime_manifest::Manifest, trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u64,
    pub relay_identity: Option<Identity>,
    pub relay_address: Option<SocketAddr>,
}
pub struct Config {
    pub profile: RegisteredProfile,
    pub manifest: Manifest,
    pub key: SigningKey,
    pub relay: Option<(Identity, SocketAddr)>,
    pub metadata_bytes: usize,
}
fn parse(
    manifest: &Manifest,
    profile: &[u8],
    configuration: &[u8],
) -> Result<(RegisteredProfile, Configuration)> {
    ensure!(
        manifest.roles.len() == 1 && manifest.roles[0].role == 5,
        "private routes require their dedicated installed role"
    );
    let profile = RegisteredProfile::parse(profile, manifest.network, manifest.incarnation)?;
    let configuration: Configuration = serde_json::from_slice(configuration)?;
    ensure!(
        configuration.version == 1
            && profile.deployment == manifest.deployment
            && profile.service == manifest.roles[0].service_key
            && profile.operator == manifest.operator
            && manifest.permits_definition(&profile.manifest).is_ok(),
        "route profile differs from exact local deployment consent"
    );
    let own = manifest
        .endpoints
        .iter()
        .find(|e| e.endpoint_id == profile.endpoint)
        .context("route TLS identity endpoint absent")?;
    ensure!(
        manifest.roles[0].bind_endpoint_ids == [own.endpoint_id]
            && own.service_key == profile.service
            && own.transport_key == profile.identity.transport_key
            && own.leaf_der == profile.identity.leaf_der,
        "route TLS identity differs from exact consented leaf"
    );
    ensure!(
        profile.mode == 3 || profile.address == Some(SocketAddr::new(own.address, own.port)),
        "route listener differs from local consent"
    );
    ensure!(
        (profile.mode == 3) == configuration.relay_identity.is_some()
            && (profile.mode == 3) == configuration.relay_address.is_some(),
        "outbound attachment relay configuration differs"
    );
    if let Some(relay) = &configuration.relay_identity {
        relay.validate()?;
        ensure!(
            profile.relay == Some(relay.service),
            "attachment selects another relay identity"
        );
        let address = configuration
            .relay_address
            .context("attachment relay address absent")?;
        ensure!(
            manifest.endpoints.iter().any(|e| manifest.roles[0]
                .outbound_endpoint_ids
                .contains(&e.endpoint_id)
                && SocketAddr::new(e.address, e.port) == address
                && e.transport_key == relay.transport_key
                && e.leaf_der == relay.leaf_der),
            "attachment relay is outside the consented transport allowlist"
        );
    }
    ensure!(
        profile
            .maximum_connections
            .checked_mul(65536)
            .is_some_and(|n| n <= manifest.roles[0].memory_bytes / 2),
        "route stream buffers exceed the consented memory admission"
    );
    Ok((profile, configuration))
}
pub fn validate_import(
    manifest: &Manifest,
    data: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    target_directory: Option<&Path>,
) -> Result<()> {
    let (profile, _) = parse(
        manifest,
        &data["RouteProfile.cbor"],
        &data["ServiceConfig.json"],
    )?;
    ensure!(
        (profile.mode != 1 && profile.protocol != 1) == target_directory.is_some(),
        "route endpoint requires exactly its own application socket binding"
    );
    if let Some(path) = target_directory {
        let target = Manifest::parse(&files::read(
            &path.join("Config/Manifest.cbor"),
            wire::MAXIMUM,
            true,
        )?)?;
        let role = match profile.protocol {
            2 => 1,
            3 => 2,
            4 => 3,
            5 => 4,
            6 => 7,
            _ => anyhow::bail!("unsupported route application protocol"),
        };
        ensure!(
            target.network == manifest.network
                && target.incarnation == manifest.incarnation
                && target.roles.len() == 1
                && target.roles[0].role == role,
            "route protocol differs from the exact installed application role"
        );
    }
    let _ = crate::route_tls::server(
        &profile.identity,
        &data["Certificate.pem"],
        &data["Transport.key"],
    )?;
    ensure!(
        data["CertificateAuthority.pem"].as_slice()
            == profile.identity.certificate_authority_pem.as_bytes(),
        "route trust roots differ from signed profile"
    );
    Ok(())
}
impl Config {
    pub fn load() -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "route service must be PID1 under its dedicated UID"
        );
        let manifest = Manifest::parse(&files::read(
            Path::new("/Config/Manifest.cbor"),
            wire::MAXIMUM,
            true,
        )?)?;
        let (profile, configuration) = parse(
            &manifest,
            &files::read(Path::new("/Config/RouteProfile.cbor"), wire::MAXIMUM, true)?,
            &files::read(Path::new("/Config/ServiceConfig.json"), 16384, true)?,
        )?;
        let seed = Zeroizing::new(files::read(Path::new("/Config/Service.key"), 32, true)?);
        let key = SigningKey::from_bytes(
            seed.as_slice()
                .try_into()
                .context("route service key must be a32-byte seed")?,
        );
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "route service key differs from consent"
        );
        let metadata_bytes =
            usize::try_from(manifest.roles[0].state_admission_bytes.min(4 * 1024 * 1024))?;
        let relay = configuration
            .relay_identity
            .zip(configuration.relay_address);
        Ok(Self {
            profile,
            manifest,
            key,
            relay,
            metadata_bytes,
        })
    }
    pub fn confinement(&self) -> Result<confinement::Profile> {
        let mut read = [
            "/Config",
            "/Clock",
            "/Authorization",
            "/Authority",
            "/Egress",
        ]
        .map(PathBuf::from)
        .to_vec();
        if self.profile.mode != 1 && self.profile.protocol != 1 {
            read.push(PathBuf::from("/Application"));
        }
        let bind = if self.profile.mode == 3 {
            vec![]
        } else {
            vec![
                self.profile
                    .address
                    .context("route listener absent")?
                    .port(),
            ]
        };
        confinement::enter_route(Path::new("/State"), &read, &bind)
    }
    pub fn resources(&self, actual: &confinement::Profile) -> Result<()> {
        let role = &self.manifest.roles[0];
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
            "route resource confinement exceeds consent"
        );
        Ok(())
    }
    pub fn dial(
        &self,
        identity: &Identity,
        address: SocketAddr,
    ) -> Result<crate::authority_proof::Digest> {
        let endpoint = self
            .manifest
            .endpoints
            .iter()
            .find(|e| {
                self.manifest.roles[0]
                    .outbound_endpoint_ids
                    .contains(&e.endpoint_id)
                    && SocketAddr::new(e.address, e.port) == address
                    && e.transport_key == identity.transport_key
                    && e.leaf_der == identity.leaf_der
            })
            .context("destination has no exact locally consented egress route")?;
        Ok(endpoint.endpoint_id)
    }
}
