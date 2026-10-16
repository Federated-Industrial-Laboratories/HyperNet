#[path = "AuthorityContentDisk.rs"]
mod authority_content_disk;
#[path = "AuthorityContentService.rs"]
mod authority_content_service;
// SPDX-License-Identifier: MIT
#[path = "AuthorityApplication.rs"]
mod authority_application;
#[path = "AuthorityApplications.rs"]
mod authority_applications;
#[path = "AuthorityBackupCli.rs"]
mod authority_backup_cli;
#[path = "AuthorityBridgeService.rs"]
mod authority_bridge_service;
#[path = "AuthorityCapacity.rs"]
mod authority_capacity;
#[path = "AuthorityChallenge.rs"]
mod authority_challenge;
#[path = "AuthorityClockHandoff.rs"]
mod authority_clock_handoff;
#[path = "AuthorityClockMonitor.rs"]
mod authority_clock_monitor;
#[path = "AuthorityDeploymentRecords.rs"]
mod authority_deployment_records;
#[path = "AuthorityDeployments.rs"]
mod authority_deployments;
#[path = "AuthorityDomains.rs"]
mod authority_domains;
#[path = "AuthorityEpoch.rs"]
mod authority_epoch;
#[path = "AuthorityFiles.rs"]
mod authority_files;
#[path = "AuthorityFloor.rs"]
mod authority_floor;
#[path = "AuthorityGovernance.rs"]
mod authority_governance;
#[path = "AuthorityGrantReview.rs"]
mod authority_grant_review;
#[path = "AuthorityHistory.rs"]
mod authority_history;
#[path = "AuthorityLocalTransport.rs"]
mod authority_local_transport;
#[path = "AuthorityMailService.rs"]
mod authority_mail_service;
#[path = "AuthorityMediaService.rs"]
mod authority_media_service;
#[path = "AuthorityMembership.rs"]
mod authority_membership;
#[path = "AuthorityObjectFiles.rs"]
mod authority_object_files;
#[path = "AuthorityObjects.rs"]
mod authority_objects;
#[path = "AuthorityOperationalConsent.rs"]
mod authority_operational_consent;
#[path = "AuthorityPageService.rs"]
mod authority_page_service;
#[path = "AuthorityPolicies.rs"]
mod authority_policies;
#[path = "AuthorityProof.rs"]
mod authority_proof;
#[path = "AuthorityRecipient.rs"]
mod authority_recipient;
#[cfg(test)]
#[path = "AuthorityRecovery.rs"]
mod authority_recovery;
#[path = "AuthorityReplica.rs"]
mod authority_replica;
#[path = "AuthorityRouteReader.rs"]
mod authority_route_reader;
#[path = "AuthorityRuntimeActivation.rs"]
mod authority_runtime_activation;
#[path = "AuthorityTiers.rs"]
mod authority_tiers;
#[path = "AuthorityTransferService.rs"]
mod authority_transfer_service;
#[path = "Confinement.rs"]
mod confinement;
#[path = "Consensus.rs"]
mod consensus;
#[path = "ConsensusClock.rs"]
mod consensus_clock;
#[path = "Markup.rs"]
mod markup;
#[path = "Policy.rs"]
mod policy;
#[path = "Protocol.rs"]
mod protocol;
#[path = "RouteAuthority.rs"]
mod route_authority;
#[path = "RouteConfig.rs"]
mod route_config;
#[cfg(test)]
#[path = "RouteConnector.rs"]
mod route_connector;
#[path = "RouteEndpoint.rs"]
mod route_endpoint;
#[path = "RouteIo.rs"]
mod route_io;
#[path = "RouteProfile.rs"]
mod route_profile;
#[path = "RouteProtocol.rs"]
mod route_protocol;
#[path = "RouteRuntime.rs"]
mod route_runtime;
#[path = "RouteState.rs"]
mod route_state;
#[path = "RouteTls.rs"]
mod route_tls;
#[path = "RuntimeAudit.rs"]
mod runtime_audit;
#[path = "RuntimeAuthorization.rs"]
mod runtime_authorization;
#[path = "RuntimeBootstrapKeys.rs"]
mod runtime_bootstrap_keys;
#[path = "RuntimeGuard.rs"]
mod runtime_guard;
#[path = "Runtime.rs"]
mod runtime_management;
#[path = "RuntimeManifest.rs"]
mod runtime_manifest;
#[path = "RuntimeProvision.rs"]
mod runtime_provision;
#[path = "RuntimeServiceActivate.rs"]
mod runtime_service_activate;
#[path = "RuntimeServiceAuthorization.rs"]
mod runtime_service_authorization;
#[path = "RuntimeServiceEntry.rs"]
mod runtime_service_entry;
#[path = "RuntimeServiceEpochCommand.rs"]
mod runtime_service_epoch_command;
#[path = "SearchText.rs"]
mod search_text;
#[path = "SshProof.rs"]
mod ssh_proof;
#[path = "SshService.rs"]
mod ssh_service;
#[path = "Store.rs"]
mod store;
#[path = "Transport.rs"]
mod transport;
#[path = "TrustBootstrap.rs"]
mod trust_bootstrap;
#[path = "TrustWire.rs"]
#[allow(dead_code)]
mod trust_wire;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

fn random_hex<const N: usize>() -> String {
    use rand::RngCore;
    let mut value = [0; N];
    rand::rngs::OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

#[derive(Parser)]
#[command(
    name = "HyperNet",
    version,
    about = "Permissioned authority and confined hosting"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise or run one independently pinned authority replica.
    AuthorityReplica {
        #[command(subcommand)]
        command: authority_replica::Command,
    },
    /// Observe authenticated local time without changing the system clock.
    AuthorityClock {
        #[command(subcommand)]
        command: authority_clock_monitor::Command,
    },
    #[command(hide = true)]
    RuntimeGuard {
        #[arg(long, value_enum)]
        kind: runtime_guard::Kind,
        #[arg(long)]
        expires: u64,
        #[arg(last = true)]
        arguments: Vec<String>,
    },
    /// Manage explicitly consented encrypted content backup destinations.
    Backup {
        #[command(subcommand)]
        command: authority_backup_cli::Command,
    },
    /// Prepare and manage an explicitly consented local runtime.
    Runtime {
        #[command(subcommand)]
        command: runtime_management::Command,
    },
    /// Supervise a separately consented OpenSSH service.
    SshService {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(hide = true)]
    RuntimeServiceInitialise,
    #[command(hide = true)]
    RuntimeServiceVerify,
    /// Run the exact consented private relay or application endpoint.
    PrivateRouteService,
    #[command(hide = true)]
    PrivateRouteEgress,
    #[command(hide = true)]
    RuntimeServiceReceipt,
    #[command(hide = true)]
    RuntimeServiceRequesterStatus,
    #[command(hide = true)]
    RuntimeServiceRequesterFence,
    #[command(hide = true)]
    RuntimeServiceEpoch {
        #[command(subcommand)]
        command: runtime_service_epoch_command::Command,
    },
    /// Run a consented Page replica with no direct reader endpoint.
    AuthorityPageService,
    /// Run a consented immutable media store through its private control socket.
    AuthorityMediaService,
    #[command(hide = true)]
    AuthorityMediaExchange,
    #[command(hide = true)]
    AuthorityContentExchange,
    /// Run a consented Transfer service through its private local control socket.
    AuthorityTransferService,
    #[command(hide = true)]
    AuthorityTransferExchange,
    /// Run a consented Mail service through its private local control socket.
    AuthorityMailService,
    #[command(hide = true)]
    AuthorityMailExchange,
    #[command(hide = true)]
    AuthorityBridgeService,
    #[command(hide = true)]
    AuthorityBridgeExchange,
    #[command(hide = true)]
    SshChild {
        #[arg(long)]
        port: u16,
    },
    #[command(name = "ssh-command", hide = true)]
    SshRun,
    /// Verify the mandatory container and Landlock restrictions.
    CheckConfinement {
        #[arg(long, default_value = "/State")]
        state: PathBuf,
    },
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?)
}

fn run() -> Result<()> {
    confinement::disable_dumps()?;
    transport::tls_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("The TLS provider was already configured"))?;
    match Arguments::parse().command {
        Command::AuthorityReplica { command } => authority_replica::run(command)?,
        Command::AuthorityClock { command } => authority_clock_monitor::run(command)?,
        Command::RuntimeGuard {
            kind,
            expires,
            arguments,
        } => runtime_guard::run(kind, expires, arguments)?,
        Command::Backup { command } => authority_backup_cli::run(command)?,
        Command::Runtime { command } => runtime_management::run(command)?,
        Command::PrivateRouteService => runtime_service_entry::routes()?,
        Command::PrivateRouteEgress => runtime_management::services::egress::run()?,
        Command::RuntimeServiceInitialise => {
            runtime_service_entry::initialise()?;
        }
        Command::RuntimeServiceVerify => runtime_service_entry::verify_existing()?,
        Command::RuntimeServiceReceipt => runtime_service_entry::receipt()?,
        Command::RuntimeServiceRequesterStatus => runtime_service_entry::bridge_requester(false)?,
        Command::RuntimeServiceRequesterFence => runtime_service_entry::bridge_requester(true)?,
        Command::RuntimeServiceEpoch { command } => {
            println!("{}", runtime_service_epoch_command::run(command)?)
        }
        Command::AuthorityPageService => runtime_service_entry::pages()?,
        Command::AuthorityMediaService => runtime_service_entry::media()?,
        Command::AuthorityMediaExchange => runtime_service_entry::exchange(2)?,
        Command::AuthorityContentExchange => runtime_service_entry::exchange(1)?,
        Command::AuthorityTransferService => runtime_service_entry::transfers()?,
        Command::AuthorityTransferExchange => runtime_service_entry::exchange(4)?,
        Command::AuthorityMailService => runtime_service_entry::mail()?,
        Command::AuthorityMailExchange => runtime_service_entry::exchange(3)?,
        Command::AuthorityBridgeService => runtime_service_entry::bridge()?,
        Command::AuthorityBridgeExchange => runtime_service_entry::exchange(7)?,
        Command::SshService { config: path } => {
            ensure!(
                path == Path::new("/Config/ServiceConfig.json"),
                "service requires its fixed consented configuration"
            );
            let guard = runtime_service_authorization::Guard::load(
                Path::new("/Authorization"),
                Path::new("/Config"),
                8,
            )?;
            let config = ssh_service::Config::load(&path)?;
            let profile =
                confinement::enter_ssh_parent(Path::new("/State"), &[config.listen.port()], &[])?;
            let active = runtime_service_activate::activate(&guard)?;
            runtime()?.block_on(ssh_service::run(config, profile, || active.check(&guard)))?;
        }
        Command::SshChild { port } => ssh_service::child(port)?,
        Command::SshRun => ssh_service::command()?,
        Command::CheckConfinement { state } => {
            let profile = confinement::enter(&state, &[], &[], &[])?;
            confinement::canaries(&state)?;
            println!("{}", serde_json::to_string(&profile)?);
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("HyperNet: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "AuthorityDeploymentTests.rs"]
mod authority_deployment_tests;
