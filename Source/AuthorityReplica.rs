// SPDX-License-Identifier: MIT
//! Explicit foreground lifecycle for one independently pinned authority signer.
use crate::{
    authority_application::PolicyApplication,
    authority_clock_handoff::Source,
    authority_files as files,
    consensus::{Engine, peer, records::Configuration, runtime},
    runtime_authorization::{self as authorization, Manifest, Validated},
    runtime_management::files as runtime_files,
    trust_bootstrap, trust_wire,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

#[path = "AuthorityEpochReplica.rs"]
mod epoch;
const RECORD: &str = "Replica.json";
const MAX_CONFIG: usize = 32768;
#[derive(Subcommand)]
pub enum Command {
    Epoch {
        #[command(subcommand)]
        command: epoch::Command,
    },
    /// Create a new signer journal from an independently authenticated complete bootstrap.
    Initialise(Initialise),
    /// Inspect a stopped signer exclusively; this is not a quorum readiness assertion.
    Status(Location),
    /// Serve inside mandatory OCI confinement until SIGINT or SIGTERM.
    Run {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        authorization: PathBuf,
    },
    /// Inspect the live local signer without taking its journal lock.
    LiveStatus(Location),
    /// Apply one exact operator-approved stopped profile successor without replacing signer state.
    ApplyConsent {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        expected_profile_digest: String,
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        history_directory: Option<PathBuf>,
    },
    /// Refresh only the signed monitor's host-boot binding after a real host reboot.
    RefreshClockBoot {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        expected_config_digest: String,
        /// Current host boot identifier authenticated through the existing signed monitor.
        #[arg(long)]
        host_kernel_boot: String,
        /// Fresh operator consent binding the new signed clock boot.
        #[arg(long)]
        authorization: PathBuf,
    },
}
#[derive(Args)]
pub struct Initialise {
    #[arg(long)]
    bootstrap: PathBuf,
    /// SHA256 of the complete bootstrap, verified independently before initialisation.
    #[arg(long)]
    bootstrap_digest: String,
    /// Private Suite-compatible identity containing secretKey and publicKey.
    #[arg(long)]
    key: PathBuf,
    /// Private runtime JSON with all four pinned TLS endpoints and explicit clock source.
    #[arg(long)]
    config: PathBuf,
    /// Exact operator authorization directory.
    #[arg(long)]
    authorization: PathBuf,
    /// New or exactly matching completed private directory; state is never recreated.
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
    /// Last generation retained independently of this deployment; never silently lowered.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    minimum_generation: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    secret_key: String,
    public_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    format: String,
    bootstrap_digest: String,
    signer: String,
    config_generation: u64,
    config_digest: String,
    config: String,
    minimum_generation: u64,
    authorization: Manifest,
    consent_digest: String,
    preparation: Option<epoch::Preparation>,
    #[serde(default)]
    appointment_authorization: Option<Manifest>,
}
impl Record {
    fn verify_appointment(
        &self,
        terminal: &crate::authority_epoch::ValidatedTerminal,
    ) -> Result<()> {
        let appointed = self
            .appointment_authorization
            .as_ref()
            .unwrap_or(&self.authorization);
        epoch::nomination(appointed, terminal)?;
        self.authorization
            .canonical()?
            .same_operational_identity(&appointed.canonical()?)?;
        ensure!(
            self.authorization.generation >= appointed.generation,
            "Appointed operational generation regressed"
        );
        Ok(())
    }
}
struct Deployment {
    directory: PathBuf,
    record: Record,
    configuration: Configuration,
    runtime: runtime::Config,
    key: SigningKey,
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn identity(bytes: &[u8]) -> Result<SigningKey> {
    let identity: Identity = serde_json::from_slice(bytes)?;
    let secret = Zeroizing::new(trust_bootstrap::hex32(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&secret);
    let public = trust_bootstrap::hex32(&identity.public_key)?;
    trust_wire::valid_key(&public)?;
    ensure!(
        public == key.verifying_key().to_bytes(),
        "Replica public and private identities differ"
    );
    Ok(key)
}
fn authenticated(bytes: &[u8], pin: &str) -> Result<(Configuration, Vec<u8>)> {
    trust_bootstrap::hex32(pin)?;
    ensure!(
        digest(bytes) == pin,
        "Bootstrap differs from its independently verified digest"
    );
    let verified = trust_bootstrap::inspect(bytes, true)?;
    let configuration = Configuration::trusted(verified.descriptor().canonical())?;
    let decoded = trust_wire::decode(bytes)?;
    let initial = decoded.array(6)?[3].bytes()?.to_vec();
    ensure!(
        trust_wire::digest(&initial) == configuration.genesis_governance,
        "Bootstrap application state differs"
    );
    Ok((configuration, initial))
}
fn validate_config(
    config: &runtime::Config,
    directory: &Path,
    configuration: &Configuration,
) -> Result<()> {
    ensure!(
        config.listen.port() != 0,
        "A fixed peer listening port is required"
    );
    ensure!(
        config.control_socket
            == if directory == Path::new("/State/Replica") {
                PathBuf::from("/State/Control/Control.sock")
            } else {
                directory.join("Control.sock")
            },
        "The private control socket must use the confined deployment control directory"
    );
    for path in [
        &config.tls.certificate,
        &config.tls.private_key,
        &config.tls.certificate_authority,
    ] {
        ensure!(path.is_absolute(), "TLS input paths must be absolute");
    }
    match &config.clock {
        Source::Private { path } => ensure!(
            path.is_absolute(),
            "Clock observation path must be absolute"
        ),
        Source::Signed {
            path,
            public_key,
            kernel_boot,
        } => {
            ensure!(
                path.is_absolute() && !kernel_boot.is_empty(),
                "Signed clock path and boot binding are required"
            );
            let monitor = trust_bootstrap::hex32(public_key)?;
            trust_wire::valid_key(&monitor)?;
            ensure!(
                !configuration.voters.contains(&monitor),
                "Clock monitor must use an identity separate from every voter"
            );
        }
    }
    confined_inputs(config)?;
    Ok(())
}
fn initialise(input: Initialise) -> Result<Json> {
    ensure!(
        input.directory.is_absolute(),
        "Replica directory must be absolute"
    );
    let parent = input
        .directory
        .parent()
        .context("Replica parent directory is absent")?;
    runtime_files::root(parent)?;
    let bootstrap = files::read_single(&input.bootstrap, trust_wire::MAXIMUM, true)?;
    let (configuration, initial) = authenticated(&bootstrap, &input.bootstrap_digest)?;
    let secret = Zeroizing::new(files::read_single(&input.key, 4096, true)?);
    let key = identity(&secret)?;
    configuration.member(&key.verifying_key().to_bytes())?;
    let supplied_config = files::read_single(&input.config, MAX_CONFIG, true)?;
    let runtime: runtime::Config = serde_json::from_slice(&supplied_config)?;
    let config = serde_json::to_vec(&runtime)?;
    validate_config(&runtime, &input.directory, &configuration)?;
    let signer = hex::encode(key.verifying_key().to_bytes());
    let approved = authorization::verify(
        &input.authorization,
        &digest(&config),
        &signer,
        &input.bootstrap_digest,
    )?;
    ensure!(
        approved.manifest.network == hex::encode(configuration.scope.network)
            && approved.manifest.incarnation == hex::encode(configuration.scope.incarnation),
        "Consent names a different network incarnation"
    );
    approved
        .manifest
        .verify_bootstrap(&trust_bootstrap::inspect(&bootstrap, true)?)?;
    verify_tls(&approved.manifest)?;
    if input.directory.try_exists()? {
        let retained = deployment(&input.directory)?;
        ensure!(
            retained.record.config_digest == digest(&config)
                && retained.record.signer == signer
                && retained.record.bootstrap_digest == input.bootstrap_digest
                && retained.record.authorization.digest()? == approved.profile_digest
                && retained.record.consent_digest == approved.consent_digest,
            "Completed replica differs from initialisation; state cannot be replaced"
        );
        let location = Location {
            directory: input.directory,
            minimum_generation: retained.record.minimum_generation,
        };
        let (retained, engine) = open_pinned(&location, retained)?;
        return status(&retained, &engine, "Initialised");
    }
    // Client construction parses pinned TLS credentials; it performs no DNS lookup or connection.
    peer::transport(
        &configuration,
        key.verifying_key().to_bytes(),
        &runtime.peers,
        &runtime.tls,
    )?;
    files::create_directory(&input.directory)?;
    runtime_files::root(&input.directory)?;
    files::write_new(&input.directory.join("Bootstrap.cbor"), &bootstrap)?;
    files::write_new(&input.directory.join("Identity.json"), &secret)?;
    files::create_directory(&input.directory.join("Journal"))?;
    let engine = Engine::create(
        &input.directory.join("Journal"),
        configuration.clone(),
        key,
        initial,
    )?;
    let record = Record {
        format: "HyperNetAuthorityReplica/1".into(),
        bootstrap_digest: input.bootstrap_digest,
        signer,
        config_generation: 1,
        config_digest: digest(&config),
        config: hex::encode(&config),
        minimum_generation: engine.generation(),
        authorization: approved.manifest,
        consent_digest: approved.consent_digest,
        preparation: None,
        appointment_authorization: None,
    };
    // One final immutable marker makes incomplete initialisation non-serving.
    files::write_new(&input.directory.join(RECORD), &serde_json::to_vec(&record)?)?;
    Ok(
        json!({"status":"Initialised","network":hex::encode(configuration.scope.network),"signer":record.signer,"generation":engine.generation(),"configGeneration":record.config_generation,"configDigest":record.config_digest,"committedHeight":0,"appliedHeight":0}),
    )
}
fn deployment(directory: &Path) -> Result<Deployment> {
    runtime_files::root(directory)?;
    let record: Record = serde_json::from_slice(&files::read_single(
        &directory.join(RECORD),
        crate::authority_epoch::archive::MAX_ARCHIVE_BYTES + 524288,
        true,
    )?)?;
    ensure!(
        record.format == "HyperNetAuthorityReplica/1"
            && record.config_generation > 0
            && record.minimum_generation > 0,
        "Invalid replica completion record"
    );
    let config = hex::decode(&record.config)?;
    ensure!(
        config.len() <= MAX_CONFIG && digest(&config) == record.config_digest,
        "Runtime configuration digest differs"
    );
    let runtime: runtime::Config = serde_json::from_slice(&config)?;
    record.authorization.validate()?;
    ensure!(
        record.authorization.config_digest()? == record.config_digest
            && record.authorization.signer == record.signer
            && record.authorization.bootstrap_digest == record.bootstrap_digest,
        "Retained authorization differs from replica pins"
    );
    trust_bootstrap::hex32(&record.consent_digest)?;
    let bootstrap =
        files::read_single(&directory.join("Bootstrap.cbor"), trust_wire::MAXIMUM, true)?;
    let configuration = if let Some(preparation) = &record.preparation {
        let (configuration, terminal) =
            preparation.configuration(&bootstrap, &record.bootstrap_digest)?;
        record.verify_appointment(&terminal)?;
        configuration
    } else {
        authenticated(&bootstrap, &record.bootstrap_digest)?.0
    };
    validate_config(&runtime, directory, &configuration)?;
    let bytes = Zeroizing::new(files::read_single(
        &directory.join("Identity.json"),
        4096,
        true,
    )?);
    let key = identity(&bytes)?;
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == record.signer,
        "Replica signer differs from initialisation"
    );
    configuration.member(&key.verifying_key().to_bytes())?;
    Ok(Deployment {
        directory: directory.to_path_buf(),
        record,
        configuration,
        runtime,
        key,
    })
}
fn open(input: &Location) -> Result<(Deployment, Engine)> {
    ensure!(
        input.minimum_generation > 0,
        "An independently retained minimum generation is required"
    );
    open_pinned(input, deployment(&input.directory)?)
}
fn open_pinned(input: &Location, initial: Deployment) -> Result<(Deployment, Engine)> {
    let engine = Engine::open(
        &input.directory.join("Journal"),
        initial.configuration.clone(),
        initial.key.clone(),
        input
            .minimum_generation
            .max(initial.record.minimum_generation),
    )?;
    // A completed concurrent clock refresh can precede lock acquisition.
    let current = deployment(&input.directory)?;
    ensure!(
        current.record.bootstrap_digest == initial.record.bootstrap_digest
            && current.record.signer == initial.record.signer
            && current.configuration.bytes == initial.configuration.bytes
            && current.key.verifying_key() == initial.key.verifying_key()
            && engine.generation() >= current.record.minimum_generation,
        "Replica identity or restart floor changed before exclusive access"
    );
    Ok((current, engine))
}

fn status(deployment: &Deployment, engine: &Engine, label: &str) -> Result<Json> {
    Ok(
        json!({"status":label,"network":hex::encode(deployment.configuration.scope.network),"signer":deployment.record.signer,"generation":engine.generation(),"configGeneration":deployment.record.config_generation,"configDigest":deployment.record.config_digest,"view":engine.view(),"committedHeight":engine.committed()?.height,"appliedHeight":engine.applied()?.height,"clockReady":deployment.runtime.clock.health().and_then(|health| health.observe()).is_ok(),"quorum":"NotProbed","epoch":deployment.configuration.scope.epoch,"canVote":engine.can_vote(),"terminal":engine.halted()}),
    )
}
fn refresh(
    input: &Location,
    expected: &str,
    host_boot: &str,
    authorization: &Path,
) -> Result<Json> {
    trust_bootstrap::hex32(expected)?;
    let (mut deployment, engine) = open(input)?;
    ensure!(
        deployment.record.config_digest == expected,
        "Expected prior configuration digest differs"
    );
    let new = Manifest::read(authorization)?;
    let Source::Signed { kernel_boot, .. } = &new.config.clock else {
        anyhow::bail!("Signed clock required")
    };
    ensure!(
        kernel_boot == host_boot,
        "Clock successor has another host boot"
    );
    let mut old_clock = deployment.record.authorization.canonical()?;
    old_clock.clock.kernel_boot = host_boot.into();
    let mut candidate = new.canonical()?;
    candidate.generation = old_clock.generation;
    candidate.previous_profile = old_clock.previous_profile;
    candidate.previous_consent = old_clock.previous_consent;
    ensure!(
        candidate == old_clock,
        "Clock refresh cannot alter another operational field"
    );
    apply_approved(&mut deployment, &engine, &new, authorization, None)
}
fn apply_consent(
    input: &Location,
    expected: &str,
    authorization: &Path,
    history: Option<&Path>,
) -> Result<Json> {
    trust_bootstrap::hex32(expected)?;
    let (mut deployment, engine) = open(input)?;
    let new = Manifest::read(authorization)?;
    if deployment.record.authorization.digest()? == new.digest()? {
        ensure!(
            new.previous_profile.map(hex::encode).as_deref() == Some(expected),
            "Retried consent successor has another predecessor"
        );
        let _ = approved(&deployment, authorization)?;
        return status(&deployment, &engine, "ConsentSuccessorApplied");
    }
    ensure!(
        new.previous_profile.map(hex::encode).as_deref() == Some(expected),
        "Expected immediately preceding local operator profile differs"
    );
    apply_approved(&mut deployment, &engine, &new, authorization, history)
}
fn apply_approved(
    deployment: &mut Deployment,
    engine: &Engine,
    new: &Manifest,
    authorization: &Path,
    history: Option<&Path>,
) -> Result<Json> {
    let mut preceding = deployment.record.authorization.canonical()?;
    let final_manifest = new.canonical()?;
    ensure!(
        final_manifest.generation > preceding.generation,
        "Operator generation did not advance"
    );
    for generation in preceding.generation + 1..final_manifest.generation {
        let directory = history
            .context("Retained signed operational offers required for unapplied generations")?;
        let bytes = files::read_single(
            &directory.join(format!("Generation{generation:020}.cbor")),
            trust_wire::MAXIMUM,
            false,
        )?;
        let value = trust_wire::decode(&bytes)?;
        let f = value.array(6)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDeploymentOffer",
            "Unexpected historical offer"
        );
        let offer =
            crate::authority_deployments::Offer::parse(f[3].bytes()?, f[4].bytes()?, &f[5])?;
        offer.manifest.successor_of(&preceding)?;
        preceding = offer.manifest;
    }
    final_manifest.successor_of(&preceding)?;
    let config = serde_json::to_vec(&new.config)?;
    ensure!(
        config.len() <= MAX_CONFIG,
        "Successor configuration exceeds its bound"
    );
    let approved = authorization::verify(
        authorization,
        &digest(&config),
        &deployment.record.signer,
        &deployment.record.bootstrap_digest,
    )?;
    new.config.clock.health()?.observe()?;
    if deployment.record.preparation.is_some()
        && deployment.record.appointment_authorization.is_none()
    {
        deployment.record.appointment_authorization = Some(deployment.record.authorization.clone());
    }
    deployment.runtime = new.config.clone();
    deployment.record.authorization = approved.manifest;
    deployment.record.consent_digest = approved.consent_digest;
    deployment.record.config = hex::encode(&config);
    deployment.record.config_digest = digest(&config);
    deployment.record.config_generation = deployment
        .record
        .config_generation
        .checked_add(1)
        .context("Configuration generation overflow")?;
    deployment.record.minimum_generation = engine.generation();
    let parent = files::private_directory(&deployment.directory)?;
    files::atomic_at(
        &parent,
        std::ffi::OsStr::new(RECORD),
        &serde_json::to_vec(&deployment.record)?,
        true,
    )?;
    status(deployment, engine, "ConsentSuccessorApplied")
}

fn verify_tls(manifest: &Manifest) -> Result<()> {
    for (name, path, private) in [
        ("Certificate.pem", &manifest.config.tls.certificate, false),
        ("PrivateKey.pem", &manifest.config.tls.private_key, true),
        (
            "Authority.pem",
            &manifest.config.tls.certificate_authority,
            false,
        ),
    ] {
        ensure!(
            digest(&files::read_single(path, 65536, private)?) == manifest.tls_digests[name],
            "TLS input differs from operator consent"
        );
    }
    Ok(())
}
fn approved(deployment: &Deployment, directory: &Path) -> Result<Validated> {
    let value = authorization::verify(
        directory,
        &deployment.record.config_digest,
        &deployment.record.signer,
        &deployment.record.bootstrap_digest,
    )?;
    ensure!(
        value.profile_digest == deployment.record.authorization.digest()?
            && value.consent_digest == deployment.record.consent_digest,
        "Authorization differs from the independently retained initial operator consent"
    );
    verify_tls(&value.manifest)?;
    Ok(value)
}
async fn serve(input: Location, authorization: PathBuf) -> Result<Json> {
    let (deployment, engine) = open(&input)?;
    ensure!(
        engine.can_vote(),
        "Replica is terminal or awaiting certified epoch activation"
    );
    let consent = approved(&deployment, &authorization)?;
    let start = crate::consensus_clock::moment()?;
    let expires_ms = consent
        .manifest
        .expires
        .checked_mul(1000)
        .context("Consent deadline overflow")?;
    let deadline = start
        .boot_ms
        .checked_add(
            expires_ms
                .checked_sub(start.wall_ms)
                .context("Consent has expired")?,
        )
        .context("Boot deadline overflow")?;
    deployment.runtime.clock.health()?.observe()?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = start.wall_ms;
        loop {
            tokio::select! {
                _ = interrupt.recv() => break,
                _ = terminate.recv() => break,
                _ = interval.tick() => {
                    let valid = (|| -> Result<()> {
                        let now = crate::consensus_clock::moment()?;
                        ensure!(now.wall_ms >= previous && now.wall_ms < expires_ms && now.boot_ms < deadline, "Consent expired or clock moved backwards");
                        previous = now.wall_ms;
                        let withdrawal: u64 = serde_json::from_slice(&authorization::public_read(&authorization.join("Withdrawal.json"),64)?)?;
                        ensure!(withdrawal == 0, "Consent withdrawn");
                        Ok(())
                    })();
                    if valid.is_err() { break; }
                }
            }
        }
        let _ = stop.send(true);
    });
    println!(
        "{}",
        serde_json::to_string(&status(&deployment, &engine, "Starting")?)?
    );
    let result = runtime::serve(
        deployment.runtime.clone(),
        engine,
        Arc::new(PolicyApplication::new(deployment.configuration.clone())),
        receiver,
    )
    .await;
    signal.abort();
    let _ = signal.await;
    result?;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        json!({"status":"ReplicaDiagnostic","code":"JournalReopen"})
    );
    let reopen_started = std::time::Instant::now();
    let (deployment, engine) = open(&input)?;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        json!({"status":"ReplicaDiagnostic","code":"JournalReopened","elapsedMs":reopen_started.elapsed().as_millis().min(u64::MAX as u128) as u64})
    );
    status(&deployment, &engine, "Stopped")
}
fn confined_inputs(config: &runtime::Config) -> Result<(Vec<PathBuf>, Vec<u16>)> {
    let mut ports = std::collections::BTreeSet::new();
    for endpoint in &config.peers {
        let origin = reqwest::Url::parse(&endpoint.origin)?;
        let host = origin.host_str().context("Peer origin has no host")?;
        let host = host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host);
        let address: std::net::IpAddr = host
            .parse()
            .context("Confined peers require literal IPv4 or IPv6 addresses")?;
        ensure!(
            !address.is_unspecified() && !address.is_multicast(),
            "Peer address is not a unicast destination"
        );
        ensure!(
            origin.scheme() == "https"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/",
            "Invalid confined peer origin"
        );
        let port = origin
            .port_or_known_default()
            .context("Peer port is absent")?;
        ensure!(port != 0, "Peer port must be fixed");
        ports.insert(port);
    }
    let clock = match &config.clock {
        Source::Private { path } | Source::Signed { path, .. } => path,
    };
    // Atomic monitor updates replace the file; permit only its dedicated read-only directory.
    let clock_parent = clock
        .parent()
        .context("Clock source parent is absent")?
        .to_path_buf();
    Ok((
        vec![
            config.tls.certificate.clone(),
            config.tls.private_key.clone(),
            config.tls.certificate_authority.clone(),
            clock_parent,
        ],
        ports.into_iter().collect(),
    ))
}
pub fn run(command: Command) -> Result<()> {
    let result = match command {
        Command::Epoch { command } => crate::runtime()?.block_on(async { epoch::run(command) })?,
        Command::Run {
            location: input,
            authorization,
        } => {
            let deployment = deployment(&input.directory)?;
            approved(&deployment, &authorization)?;
            let (mut reads, connects) = confined_inputs(&deployment.runtime)?;
            reads.push(authorization.clone());
            let profile = crate::confinement::enter_authority(
                &input.directory,
                &reads,
                &[deployment.runtime.listen.port()],
                &connects,
            )?;
            crate::confinement::canaries(&input.directory)?;
            println!(
                "{}",
                serde_json::to_string(&json!({"status":"Confined","confinement":profile}))?
            );
            // No worker thread, journal lock or listener precedes the mandatory boundary.
            crate::runtime()?.block_on(serve(input, authorization))?
        }
        Command::Initialise(input) => crate::runtime()?.block_on(async { initialise(input) })?,
        Command::LiveStatus(input) => {
            live_status::query(&input.directory, input.minimum_generation)?
        }
        Command::Status(input) => {
            let (deployment, engine) = open(&input)?;
            status(&deployment, &engine, "Offline")?
        }
        Command::ApplyConsent {
            location,
            expected_profile_digest,
            authorization,
            history_directory,
        } => apply_consent(
            &location,
            &expected_profile_digest,
            &authorization,
            history_directory.as_deref(),
        )?,
        Command::RefreshClockBoot {
            location,
            expected_config_digest,
            host_kernel_boot,
            authorization,
        } => refresh(
            &location,
            &expected_config_digest,
            &host_kernel_boot,
            &authorization,
        )?,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
#[path = "AuthorityReplicaTests.rs"]
pub(crate) mod tests;

#[path = "AuthorityReplicaLiveStatus.rs"]
mod live_status;
