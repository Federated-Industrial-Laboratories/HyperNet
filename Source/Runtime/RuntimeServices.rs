// SPDX-License-Identifier: MIT
// Fixed service templates retain local consent independently of network management authority.
use super::{containers, files, model::Resource};
use crate::{
    runtime_manifest::{Manifest, Role},
    trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
#[path = "RuntimeAuthorityConnector.rs"]
mod authority_connector;
#[path = "RuntimeServiceControl.rs"]
pub(super) mod control;
#[path = "RuntimeServiceEgress.rs"]
pub(crate) mod egress;
#[path = "RuntimeServiceEpoch.rs"]
mod epoch;
#[path = "RuntimeMappedControl.rs"]
pub(crate) mod mapped;
#[path = "RuntimeServicePreparation.rs"]
pub(super) mod preparation;
#[path = "RuntimeServiceSetup.rs"]
pub(super) mod setup;
#[path = "RuntimeServiceContainers.rs"]
pub(super) mod workload;
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Verify private mapped control metadata inside the rootless parent namespace.
    #[command(hide = true)]
    MappedControlCheck(Location),
    Transition {
        #[command(subcommand)]
        command: super::transition::Command,
    },
    Managed {
        #[command(subcommand)]
        command: super::managed::Command,
    },
    /// Forward a signed Content, Media, Mail or Transfer packet through this service's private local socket.
    Exchange {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    Epoch {
        #[command(subcommand)]
        command: epoch::Command,
    },
    Setup(setup::Setup),
    Preview(Location),
    /// Preview or explicitly export recorded local state without probing services.
    Diagnose(super::diagnostics::Options),
    Consent {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        profile_digest: String,
    },
    /// Keep the owned service under foreground supervision until stopped or the session exits.
    Start {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        activation_request: PathBuf,
    },
    Status(Location),
    /// Export exact certified own-stream metadata from a stopped Bridge service.
    RequesterStatus {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        output: PathBuf,
    },
    /// Explicitly fence a stopped Bridge stream against exact inspected metadata.
    RequesterFence {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Stop(Location),
    Withdraw(Location),
    /// Export the latest signed activation report; this is not a readiness assertion.
    ActivationReceipt {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        output: PathBuf,
    },
    WithdrawalReceipt {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Profile {
    pub(super) version: u64,
    pub(super) root: PathBuf,
    pub(super) manifest: Manifest,
    pub(super) artifacts: BTreeMap<String, [u8; 32]>,
    pub(super) authority_control: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_binding: Option<authority_connector::Binding>,
    pub(super) clock_directory: PathBuf,
    pub(super) selinux: bool,
    media_controls: BTreeMap<String, MediaMount>,
    route_target: Option<MediaMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_target: Option<MediaMount>,
}
impl Profile {
    pub(super) fn role(&self) -> Result<&Role> {
        ensure!(
            self.manifest.roles.len() == 1 && matches!(self.manifest.roles[0].role, 1..=5 | 7 | 8),
            "installed service template requires one Page, Media, Mail, Transfer, Route or SSH role"
        );
        Ok(&self.manifest.roles[0])
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            (self.version == 1 && self.authority_binding.is_none())
                || (self.version == 2 && self.authority_binding.is_some()),
            "unsupported installed service profile"
        );
        self.manifest.validate()?;
        let role = self.role()?;
        ensure!(
            self.manifest.authority_config.is_none()
                && (matches!(role.role, 5 | 7) || role.outbound_endpoint_ids.is_empty())
                && role.volume_ids.len() == 1
                && self.manifest.volumes.len() == 1
                && !self.manifest.volumes[0].read_only,
            "service template requires one explicit state volume and only Route or Bridge TCP egress"
        );
        if role.role == 5 {
            ensure!(
                role.bind_endpoint_ids.len() <= 1,
                "route service has more than one listener"
            );
            for endpoint in &self.manifest.endpoints {
                ensure!(
                    endpoint.address.is_ipv4() && endpoint.port > 1024,
                    "installed route endpoints require literal IPv4 and unprivileged ports"
                );
            }
        } else if role.role == 7 {
            ensure!(
                role.bind_endpoint_ids.len() == 1 && !role.outbound_endpoint_ids.is_empty(),
                "bridge requires exact listener and counterpart routes"
            );
            for endpoint in &self.manifest.endpoints {
                ensure!(
                    endpoint.address.is_ipv4()
                        && endpoint.port > 1024
                        && !endpoint.address.is_unspecified()
                        && !endpoint.address.is_multicast(),
                    "installed bridge requires literal IPv4 endpoints and unprivileged ports"
                );
            }
        } else if role.role == 8 {
            let endpoint = self
                .manifest
                .endpoints
                .first()
                .context("SSH listener absent")?;
            ensure!(
                role.bind_endpoint_ids == [endpoint.endpoint_id]
                    && self.manifest.endpoints.len() == 1
                    && endpoint.address.is_ipv4()
                    && endpoint.port > 1024
                    && !endpoint.address.is_unspecified()
                    && !endpoint.address.is_multicast(),
                "installed SSH exposure requires one explicit IPv4 address and unprivileged port"
            );
        } else {
            ensure!(
                role.bind_endpoint_ids.is_empty() && self.manifest.endpoints.is_empty(),
                "local storage template cannot expose TCP endpoints"
            );
        }
        ensure!(
            self.manifest.clock.witness_file_name == "ClockHealth.cbor",
            "installed service clock filename differs"
        );
        for p in [&self.root, &self.authority_control, &self.clock_directory] {
            files::safe_path(p)?;
            ensure!(p.is_absolute(), "absolute service path required");
        }
        if let Some(binding) = &self.authority_binding {
            binding.check(&self.manifest)?;
            ensure!(
                self.authority_control.ends_with("Ingress"),
                "authority connector must expose only its mapped Ingress directory"
            );
        } else {
            ensure!(
                self.authority_control.ends_with("Launch/State/Control"),
                "authority control must use its isolated installed directory"
            );
        }
        let expected: &[&str] = match role.role {
            5 => &[
                "Bootstrap.cbor",
                "Certificate.pem",
                "CertificateAuthority.pem",
                "Egress.json",
                "Manifest.cbor",
                "RouteBinding.json",
                "RouteProfile.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
                "Transport.key",
            ],
            7 => &[
                "Bootstrap.cbor",
                "BridgeProfile.cbor",
                "Certificate.pem",
                "CertificateAuthority.pem",
                "Manifest.cbor",
                "MediaBindings.json",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
                "Transport.key",
            ],
            8 => &[
                "AuthorizedKeys",
                "Bootstrap.cbor",
                "Manifest.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
                "SshHostKey",
                "SshProfile.cbor",
                "SshdConfig",
            ],
            4 => &[
                "Bootstrap.cbor",
                "Manifest.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
                "TransferProfile.cbor",
            ],
            1 => &[
                "Bootstrap.cbor",
                "Manifest.cbor",
                "PageProfile.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
            ],
            2 => &[
                "Bootstrap.cbor",
                "Manifest.cbor",
                "MediaProfile.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
            ],
            3 => &[
                "Bootstrap.cbor",
                "MailProfile.cbor",
                "Manifest.cbor",
                "Seccomp.json",
                "Service.key",
                "ServiceConfig.json",
            ],
            _ => unreachable!(),
        };
        ensure!(
            role.role == 7 || self.media_controls.is_empty(),
            "only a bridge can hold local media controls"
        );
        ensure!(
            role.role == 5 || self.route_target.is_none() && self.application_target.is_none(),
            "only a route endpoint can mount an application socket"
        );
        ensure!(
            self.route_target.is_none() || self.application_target.is_none(),
            "route has two local application bindings"
        );
        if let Some(target) = self
            .route_target
            .as_ref()
            .or(self.application_target.as_ref())
        {
            files::safe_path(&target.directory)?;
            ensure!(
                target.directory.is_absolute(),
                "route target directory must be absolute"
            );
        }
        for (key, mount) in &self.media_controls {
            ensure!(
                hex::encode(crate::trust_bootstrap::hex32(key)?) == *key
                    && mount.directory.is_absolute(),
                "media mount identity or path differs"
            );
            files::safe_path(&mount.directory)?;
        }
        ensure!(
            self.artifacts
                .keys()
                .map(String::as_str)
                .eq(expected.iter().copied()),
            "service artifact membership differs from fixed template"
        );
        Ok(())
    }
    pub(super) fn digest(&self) -> Result<String> {
        Ok(files::hex_digest(&serde_json::to_vec(self)?))
    }
    fn binding_digest(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value["manifest"] = json!(hex::encode(self.manifest.operational_digest()?));
        value["artifacts"]["Manifest.cbor"] = Value::Null;
        Ok(files::hex_digest(&serde_json::to_vec(&value)?))
    }
    fn name(&self) -> String {
        format!("HyperNetService{}", hex::encode(self.manifest.deployment))
    }
    pub(super) fn image(&self) -> Result<String> {
        Ok(format!("sha256:{}", hex::encode(self.role()?.image_digest)))
    }
    pub(super) fn check_artifacts(&self) -> Result<()> {
        self.validate()?;
        if let Some(binding) = &self.authority_binding {
            ensure!(
                authority_connector::Binding::read(&self.authority_control, &self.manifest)?
                    == *binding,
                "authority connector changed from exact local consent"
            );
        }
        ensure!(
            files::root(&self.root)? == self.root
                && files::executable(&std::env::current_exe()?.canonicalize()?)?
                    == hex::encode(self.manifest.software_digest),
            "installed service software or directory changed"
        );
        for (name, digest) in &self.artifacts {
            ensure!(
                wire::digest(&files::read(
                    &self.root.join("Config").join(name),
                    wire::MAXIMUM
                )?) == *digest,
                "consented service artifact changed"
            );
        }
        if self.role()?.role == 7 {
            ensure!(
                files::read(&self.root.join("Config/MediaBindings.json"), wire::MAXIMUM)?
                    == serde_json::to_vec(&self.media_controls)?,
                "media control mount list differs from signed local acceptance"
            );
            for (key, mount) in &self.media_controls {
                let (media, _) = load(&mount.directory)?;
                store_route(
                    &self.manifest,
                    &media.manifest,
                    crate::trust_bootstrap::hex32(key)?,
                )?;
                ensure!(
                    media.binding_digest()? == mount.profile_digest,
                    "local media mount changed its installed identity"
                );
            }
        }
        if self.role()?.role == 5 {
            ensure!(
                files::read(&self.root.join("Config/RouteBinding.json"), wire::MAXIMUM)?
                    == serde_json::to_vec(
                        &self
                            .route_target
                            .as_ref()
                            .or(self.application_target.as_ref())
                    )?,
                "application socket binding differs from signed local consent"
            );
            if let Some(target) = &self.application_target {
                let configuration: crate::route_config::Configuration = serde_json::from_slice(
                    &files::read(&self.root.join("Config/ServiceConfig.json"), 16384)?,
                )?;
                let application = configuration
                    .application
                    .context("application stream configuration absent")?;
                crate::route_config::application_mount::validate_host(
                    &target.directory,
                    &application,
                )?;
                ensure!(
                    target.profile_digest == hex::encode(application.binding.digest()?),
                    "local application binding digest differs"
                );
            }
            if let Some(target) = &self.route_target {
                let (installed, _) = load(&target.directory)?;
                ensure!(
                    installed.binding_digest()? == target.profile_digest,
                    "route application installation changed"
                );
                route_target(&self.manifest, &installed.manifest)?;
            }
        }
        ensure!(
            files::selinux_enabled()? == self.selinux,
            "SELinux mode differs from local service profile"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MediaMount {
    directory: PathBuf,
    profile_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct State {
    pub(super) version: u64,
    pub(super) profile_digest: String,
    pub(super) consented: bool,
    pub(super) withdrawn: bool,
    pub(super) initialised: bool,
    pub(super) container: Option<Resource>,
    pub(super) network: Option<Resource>,
    pub(super) helper: Option<Resource>,
    #[serde(default)]
    pub(super) egress: Option<Resource>,
    pub(super) authority_control: Option<PathBuf>,
    pub(super) last_time: u64,
}
pub(super) fn load(root: &Path) -> Result<(Profile, State)> {
    let root = files::root(root)?;
    super::transition::require_idle(&root)?;
    let p: Profile = files::json(&root.join("ServiceProfile.json"))?;
    let mut s: State = files::json(&root.join("ServiceState.json"))?;
    p.validate()?;
    ensure!(
        p.root == root && s.version == 1 && s.profile_digest == p.digest()?,
        "service state differs from immutable local profile"
    );
    let withdrawal: u64 = serde_json::from_slice(&files::public_read(
        &root.join("Authorization/Withdrawal.json"),
        64,
    )?)?;
    ensure!(
        withdrawal <= 1 && (!s.withdrawn || withdrawal == 1),
        "local service withdrawal regressed"
    );
    s.withdrawn = withdrawal == 1;
    Ok((p, s))
}
pub(super) fn save(p: &Profile, s: &mut State) -> Result<()> {
    let now = files::now()?;
    ensure!(now >= s.last_time, "service manager clock moved backwards");
    s.last_time = now;
    files::save(&p.root.join("ServiceState.json"), s)
}
fn preview(p: &Profile, s: &State) -> Result<Value> {
    Ok(
        json!({"status":if s.withdrawn{"Withdrawn"}else if s.consented{"Consented"}else{"AwaitingLocalConsent"},
        "profileDigest":p.digest()?,"localGeneration":p.manifest.generation,"manifest":p.manifest,"artifacts":p.artifacts,
        "role":match p.role()?.role{1=>"Page",2=>"Media",3=>"Mail",4=>"Transfer",5=>"PrivateRoute",7=>"Bridge",8=>"Ssh",_=>unreachable!()},"authentication":if p.role()?.role==8{"Native OpenSSH host key from exact signed SshProfile; generic manifest TLS metadata does not authenticate this listener"}else if p.role()?.role==7{"Pinned TLS1.3 counterpart bridges plus private local operator control; no direct reader route"}else if p.role()?.role==5{"Pinned TLS1.3 relay transport; inner TLS terminates at the exact consented final service"}else{"Private local control only; no remote reader route"},
        "tcpEgress":p.role()?.role==7,"isolatedEgressHelper":p.role()?.role==5,"mediaControls":p.media_controls,"authorityAccess":"Private control socket only","session":if p.manifest.session_mode==1{"Managed"}else{"Session"},"managedBootPolicy":p.manifest.session_mode==1,
        "authorityControl":s.authority_control.as_ref().unwrap_or(&p.authority_control),"authorityConnector":p.authority_binding,"currentPermission":false,"initialised":s.initialised}),
    )
}
pub fn run(command: Command) -> Result<Value> {
    match command {
        Command::MappedControlCheck(location) => mapped::inspect_mapped(&location.directory),
        Command::Transition { command } => super::transition::run(command, true),
        Command::Managed { command } => super::managed::run(command, true),
        Command::Diagnose(options) => super::diagnostics::run(options, diagnostic_snapshot),
        Command::Epoch { command } => epoch::run(command),
        Command::Setup(args) => setup::run(args),
        Command::Start {
            location,
            activation_request,
        } => control::start(&location.directory, &activation_request),
        command => {
            let location = match &command {
                Command::Preview(l)
                | Command::Status(l)
                | Command::Stop(l)
                | Command::Withdraw(l) => l,
                Command::Exchange { location, .. }
                | Command::Consent { location, .. }
                | Command::RequesterStatus { location, .. }
                | Command::RequesterFence { location, .. }
                | Command::ActivationReceipt { location, .. }
                | Command::WithdrawalReceipt { location, .. } => location,
                _ => unreachable!(),
            };
            let root = files::root(&location.directory)?;
            let _lock = files::lock(&root)?;
            if root.join("Transition.json").try_exists()? {
                return match command {
                    Command::Stop(_) => super::transition::restrict(&root, true, false),
                    Command::Withdraw(_) => super::transition::restrict(&root, true, true),
                    Command::WithdrawalReceipt { output, .. } => {
                        super::transition::withdrawal_receipt(&root, true, Some(&output))
                    }
                    Command::Status(_) | Command::Preview(_) => {
                        super::transition::pending_status(&root)
                    }
                    _ => anyhow::bail!(
                        "Resume the exact stopped successor before another service operation"
                    ),
                };
            }
            let (p, mut s) = load(&root)?;
            match command {
                Command::Exchange {
                    packet, receipt, ..
                } => control::exchange(&p, &mut s, &packet, &receipt),
                Command::Preview(_) => preview(&p, &s),
                Command::Consent { profile_digest, .. } => {
                    setup::consent(&p, &mut s, &profile_digest)
                }
                Command::Status(_) => control::status(&p, &mut s),
                Command::RequesterStatus { output, .. } => {
                    control::requester(&p, &mut s, None, &output)
                }
                Command::RequesterFence {
                    expected, output, ..
                } => control::requester(&p, &mut s, Some(&expected), &output),
                Command::Stop(_) => {
                    control::stop(&p, &mut s)?;
                    Ok(json!({"status":"Stopped"}))
                }
                Command::Withdraw(_) => control::withdraw(&p, &mut s),
                Command::ActivationReceipt { output, .. } => {
                    control::activation_receipt(&p, &mut s, &output)
                }
                Command::WithdrawalReceipt { output, .. } => {
                    control::withdrawal_receipt(&p, &s, &output)
                }
                _ => unreachable!(),
            }
        }
    }
}

fn diagnostic_snapshot(path: &Path) -> super::diagnostics::Snapshot {
    let result = (|| -> Result<_> {
        let root = files::root(path)?;
        let _lock = files::try_lock(&root)?;
        let (profile, state) = load(&root)?;
        Ok(super::diagnostics::service(
            profile.role()?.role,
            state.consented,
            state.withdrawn,
            state.initialised,
            [
                &state.container,
                &state.network,
                &state.helper,
                &state.egress,
            ]
            .iter()
            .filter(|resource| resource.is_some())
            .count(),
        ))
    })();
    result.unwrap_or_else(|_| super::diagnostics::unavailable(false))
}

fn store_route(bridge: &Manifest, store: &Manifest, key: [u8; 32]) -> Result<()> {
    ensure!(
        bridge.roles.len() == 1
            && bridge.roles[0].role == 7
            && store.roles.len() == 1
            && matches!(store.roles[0].role, 1 | 2)
            && store.roles[0].service_key == key
            && store.network == bridge.network
            && store.incarnation == bridge.incarnation,
        "Bridge content/media mount differs from exact installed identity or own network"
    );
    Ok(())
}
#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeServiceRouteTests.rs"]
mod route_tests;

fn route_target(route: &Manifest, target: &Manifest) -> Result<()> {
    ensure!(
        route.network == target.network
            && route.incarnation == target.incarnation
            && route.deployment != target.deployment
            && target.roles.len() == 1
            && matches!(target.roles[0].role, 1..=4 | 7),
        "route application mount must be one separate consented service in the same network"
    );
    Ok(())
}

pub(crate) fn approved_backup_volume(
    root: &Path,
    host: [u8; 32],
    volume: [u8; 32],
    live: bool,
) -> Result<(Manifest, PathBuf, u64)> {
    use std::{fs, os::unix::fs::MetadataExt};
    let root = files::root(root)?;
    let _lock = files::lock(&root)?;
    let (profile, state) = load(&root)?;
    if live {
        profile.check_artifacts()?;
    }
    ensure!(
        profile.manifest.host == host
            && profile.manifest.volumes[0].volume_id == volume
            && state.initialised,
        "Backup allocation requires the exact initialized host volume"
    );
    if live {
        super::transition::require_servable(&root)?;
        ensure!(
            state.consented && !state.withdrawn,
            "Backup storage requires live local host consent"
        );
        let now = files::now()?
            .checked_mul(1000)
            .context("Backup time overflow")?;
        ensure!(
            now >= profile.manifest.validity.0 && now < profile.manifest.validity.1,
            "Backup storage consent is outside its lifetime"
        );
    }
    let (consent, signatures) = wire::envelope(
        &files::public_read(&root.join("Authorization/HostConsent.cbor"), wire::MAXIMUM)?,
        1,
    )?;
    ensure!(
        signatures.len() == 1
            && signatures[0].0 == profile.manifest.operator
            && consent == profile.manifest.unsigned_consent(0)?,
        "Backup host consent differs"
    );
    let preparation: Value = files::json(&root.join("Preparation.json"))?;
    let launch = fs::symlink_metadata(root.join("Launch"))?;
    ensure!(
        launch.is_dir()
            && preparation["profile"] == profile.digest()?
            && preparation["identity"][0].as_u64() == Some(launch.dev())
            && preparation["identity"][1].as_u64() == Some(launch.ino()),
        "Prepared host backing identity differs"
    );
    let allocation = profile.manifest.volumes[0]
        .storage_admission_bytes
        .checked_sub(profile.role()?.state_admission_bytes)
        .context("Backup has no separately consented surplus")?;
    ensure!(
        allocation > 0,
        "Backup requires explicit volume capacity above service state allocation"
    );
    let backing = files::podman(&files::strings(&[
        "unshare",
        "/usr/bin/stat",
        "--format=%d:%F",
        "--",
        root.join("Launch/State")
            .to_str()
            .context("Invalid backing path")?,
    ]))?;
    let backing = String::from_utf8(backing)?;
    let (device, kind) = backing
        .trim()
        .split_once(':')
        .context("Invalid backing metadata")?;
    ensure!(
        kind == "directory",
        "Prepared state backing is not a directory"
    );
    let backing_device = device.parse::<u64>()?;
    let directory = root.join("Backups");
    if !directory.try_exists()? {
        ensure!(live, "Backup allocation has not been initialized");
        files::directory(&directory)?;
    }
    files::private_dir(&directory)?;
    ensure!(
        fs::symlink_metadata(&directory)?.dev() == backing_device,
        "Backup directory is not on the consented backing volume"
    );
    Ok((profile.manifest, directory, allocation))
}
