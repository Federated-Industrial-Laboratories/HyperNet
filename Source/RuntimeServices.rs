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
#[path = "RuntimeServiceControl.rs"]
mod control;
#[path = "RuntimeServiceEpoch.rs"]
mod epoch;
#[path = "RuntimeServicePreparation.rs"]
mod preparation;
#[path = "RuntimeServiceSetup.rs"]
mod setup;
#[path = "RuntimeServiceContainers.rs"]
mod workload;
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Forward a signed Media, Mail or Transfer packet through this service's private local socket.
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
struct Profile {
    version: u64,
    root: PathBuf,
    manifest: Manifest,
    artifacts: BTreeMap<String, [u8; 32]>,
    authority_control: PathBuf,
    clock_directory: PathBuf,
    selinux: bool,
    media_controls: BTreeMap<String, MediaMount>,
}
impl Profile {
    fn role(&self) -> Result<&Role> {
        ensure!(
            self.manifest.roles.len() == 1 && matches!(self.manifest.roles[0].role, 1..=4 | 7 | 8),
            "installed service template requires one Page, Media, Mail, Transfer or SSH role"
        );
        Ok(&self.manifest.roles[0])
    }
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported installed service profile");
        self.manifest.validate()?;
        let role = self.role()?;
        ensure!(
            self.manifest.authority_config.is_none()
                && (role.role == 7 || role.outbound_endpoint_ids.is_empty())
                && role.volume_ids.len() == 1
                && self.manifest.volumes.len() == 1
                && !self.manifest.volumes[0].read_only,
            "service template requires one explicit state volume and only role7 TCP egress"
        );
        if role.role == 7 {
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
        ensure!(
            self.authority_control.ends_with("Launch/State/Control"),
            "authority control must use its isolated installed directory"
        );
        let expected: &[&str] = match role.role {
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
    fn digest(&self) -> Result<String> {
        Ok(files::hex_digest(&serde_json::to_vec(self)?))
    }
    fn name(&self) -> String {
        format!("HyperNetService{}", hex::encode(self.manifest.deployment))
    }
    fn image(&self) -> Result<String> {
        Ok(format!("sha256:{}", hex::encode(self.role()?.image_digest)))
    }
    fn check_artifacts(&self) -> Result<()> {
        self.validate()?;
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
                ensure!(
                    media.role()?.role == 2
                        && hex::encode(media.role()?.service_key) == *key
                        && media.manifest.network == self.manifest.network
                        && media.manifest.incarnation == self.manifest.incarnation
                        && media.digest()? == mount.profile_digest,
                    "local media mount changed its installed identity"
                );
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
struct State {
    version: u64,
    profile_digest: String,
    consented: bool,
    withdrawn: bool,
    initialised: bool,
    container: Option<Resource>,
    network: Option<Resource>,
    helper: Option<Resource>,
    authority_control: Option<PathBuf>,
    last_time: u64,
}
fn load(root: &Path) -> Result<(Profile, State)> {
    let root = files::root(root)?;
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
fn save(p: &Profile, s: &mut State) -> Result<()> {
    let now = files::now()?;
    ensure!(now >= s.last_time, "service manager clock moved backwards");
    s.last_time = now;
    files::save(&p.root.join("ServiceState.json"), s)
}
fn preview(p: &Profile, s: &State) -> Result<Value> {
    Ok(
        json!({"status":if s.withdrawn{"Withdrawn"}else if s.consented{"Consented"}else{"AwaitingLocalConsent"},
        "profileDigest":p.digest()?,"localGeneration":1,"manifest":p.manifest,"artifacts":p.artifacts,
        "role":match p.role()?.role{1=>"Page",2=>"Media",3=>"Mail",4=>"Transfer",7=>"Bridge",8=>"Ssh",_=>unreachable!()},"authentication":if p.role()?.role==8{"Native OpenSSH host key from exact signed SshProfile; generic manifest TLS metadata does not authenticate this listener"}else if p.role()?.role==7{"Pinned TLS1.3 counterpart bridges plus private local operator control; no direct reader route"}else{"Private local control only; no remote reader route"},
        "tcpEgress":p.role()?.role==7,"mediaControls":p.media_controls,"authorityAccess":"Private control socket only","session":"Foreground","automaticBoot":false,
        "authorityControl":s.authority_control.as_ref().unwrap_or(&p.authority_control),"currentPermission":false,"initialised":s.initialised}),
    )
}
pub fn run(command: Command) -> Result<Value> {
    match command {
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
