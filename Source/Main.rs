// SPDX-License-Identifier: MIT
#[path = "ApplicationAuthority.rs"]
mod application_authority;
#[path = "Authority.rs"]
mod authority;
#[path = "Bridge.rs"]
mod bridge;
#[path = "Confinement.rs"]
mod confinement;
#[path = "FederationAuthority.rs"]
mod federation_authority;
#[path = "Host.rs"]
mod host;
#[path = "MailAuthority.rs"]
mod mail_authority;
#[path = "MailDisk.rs"]
mod mail_disk;
#[path = "MailStore.rs"]
mod mail_store;
#[path = "MailTransport.rs"]
mod mail_transport;
#[path = "MailTypes.rs"]
mod mail_types;
#[path = "Markup.rs"]
mod markup;
#[path = "PageAuthority.rs"]
mod page_authority;
#[path = "Policy.rs"]
mod policy;
#[path = "Protocol.rs"]
mod protocol;
#[path = "SshAuthority.rs"]
mod ssh_authority;
#[path = "SshProof.rs"]
mod ssh_proof;
#[path = "SshService.rs"]
mod ssh_service;
#[path = "SshTypes.rs"]
mod ssh_types;
#[path = "Store.rs"]
mod store;
#[path = "TransferAuthority.rs"]
mod transfer_authority;
#[path = "TransferDisk.rs"]
mod transfer_disk;
#[path = "TransferStore.rs"]
mod transfer_store;
#[path = "TransferTransport.rs"]
mod transfer_transport;
#[path = "TransferTypes.rs"]
mod transfer_types;
#[path = "Transport.rs"]
mod transport;
#[path = "Types.rs"]
mod types;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

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
    /// Initialise a new authority namespace without opening an ingress listener.
    Initialise {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        admin_key: String,
    },
    /// Run a confined authority broker connected to the trusted voters.
    Authority {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a confined nonvoting host with signed local consent.
    Host {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a consenting bridge between two independently administered networks.
    Bridge {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a selected persistent mail store with exact signed host consent.
    MailStore {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a recipient-selected encrypted transfer store.
    TransferStore {
        #[arg(long)]
        config: PathBuf,
    },
    /// Supervise a separately consented OpenSSH service.
    SshService {
        #[arg(long)]
        config: PathBuf,
    },
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

fn authority_config(path: &Path) -> Result<types::AuthorityConfig> {
    let config: types::AuthorityConfig =
        serde_json::from_slice(&store::read_bounded(path, 32 * 1024)?)
            .context("Invalid authority configuration")?;
    protocol::fixed_hex::<32>(&config.network).map_err(anyhow::Error::msg)?;
    ensure!(
        config.state_directory.is_absolute(),
        "Authority state directory must be absolute"
    );
    ensure!(
        !config.etcd_server_name.is_empty(),
        "Authority voter server name is required"
    );
    Ok(config)
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
        Command::Initialise { config, admin_key } => {
            let config = authority_config(&config)?;
            runtime()?.block_on(async {
                store::Store::connect(&config)
                    .await?
                    .initialise(&admin_key)
                    .await
            })?;
            println!("Authority initialised");
        }
        Command::Authority { config: path } => {
            let config = authority_config(&path)?;
            let tls = transport::tls_config(&config)?;
            let mut reads = vec![
                path,
                config.certificate.clone(),
                config.private_key.clone(),
                config.client_ca.clone(),
                config.etcd_ca.clone(),
                config.etcd_certificate.clone(),
                config.etcd_key.clone(),
            ];
            if let Some(path) = &config.federation_signing_key {
                reads.push(path.clone());
            }
            if let Some(path) = &config.mail_signing_key {
                reads.push(path.clone());
            }
            if let Some(path) = &config.service_signing_key {
                reads.push(path.clone());
            }
            let mut ports = Vec::new();
            for endpoint in &config.etcd_endpoints {
                let url = reqwest::Url::parse(endpoint)?;
                ensure!(
                    url.scheme() == "https"
                        && url.username().is_empty()
                        && url.password().is_none(),
                    "Authority voter endpoints require credential-free HTTPS URLs"
                );
                ports.push(
                    url.port_or_known_default()
                        .context("Authority voter port is missing")?,
                );
            }
            let profile = confinement::enter(
                &config.state_directory,
                &reads,
                &[config.listen.port()],
                &ports,
            )?;
            confinement::canaries(&config.state_directory)?;
            println!("{}", serde_json::to_string(&profile)?);
            runtime()?.block_on(transport::serve(config, tls))?;
        }
        Command::Host { config: path } => {
            let config = host::load(&path)?;
            let mut reads = config.read_paths();
            reads.push(path);
            let profile = confinement::enter(
                &config.state_directory,
                &reads,
                &[],
                &config.connect_ports(),
            )?;
            runtime()?.block_on(host::run(config, profile))?;
        }
        Command::Bridge { config: path } => {
            let config = bridge::load(&path)?;
            let mut reads = config.read_paths();
            reads.push(path);
            let profile = confinement::enter(
                &config.state_directory,
                &reads,
                &[],
                &config.connect_ports(),
            )?;
            runtime()?.block_on(bridge::run(config, profile))?;
        }
        Command::MailStore { config: path } => {
            let config = mail_store::Config::load(&path)?;
            let profile = confinement::enter_mail(
                &config.state_file,
                &[config.listen.port()],
                &[config.relay_address.port()],
                config.consent.state_bytes,
            )?;
            confinement::mail_canaries(&config.state_file)?;
            config.check_resources(&profile)?;
            println!("{}", serde_json::to_string(&profile)?);
            runtime()?.block_on(mail_transport::serve(config))?;
        }
        Command::TransferStore { config: path } => {
            let config = transfer_store::Config::load(&path)?;
            let profile = confinement::enter_mail(
                &config.state_file,
                &[config.listen.port()],
                &[config.relay_address.port()],
                config.consent.state_bytes,
            )?;
            confinement::mail_canaries(&config.state_file)?;
            config.check_resources(&profile)?;
            println!("{}", serde_json::to_string(&profile)?);
            runtime()?.block_on(transfer_transport::serve(config))?;
        }
        Command::SshService { config: path } => {
            let config = ssh_service::Config::load(&path)?;
            let profile = confinement::enter_ssh_parent(
                &config.state_directory,
                &[config.listen.port()],
                &[config.relay_address.port()],
            )?;
            runtime()?.block_on(ssh_service::run(config, profile))?;
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
