// SPDX-License-Identifier: MIT
//! Stopped signer commands prepare, export and activate one exact committee successor.
use super::*;
use crate::authority_epoch::{
    self as epoch,
    archive::{Activated, Retained, Seal},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Preparation {
    chain: Vec<Activated>,
    evidence: String,
    history: String,
}
#[derive(Subcommand)]
pub enum Command {
    /// Export this stopped old signer's terminal share and exact retained application.
    Terminal {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        objects_output: Option<PathBuf>,
    },
    /// Sign the unique successor state after verifying the collected terminal checkpoint.
    Handoff {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        checkpoint: PathBuf,
        /// Optional exact requester/recipient Retained JSON for its history proof.
        #[arg(long)]
        retained: Option<PathBuf>,
    },
    /// Install a nominated successor without opening listeners or emitting votes.
    Prepare {
        #[command(flatten)]
        input: Initialise,
        #[arg(long)]
        transition: PathBuf,
        #[arg(long)]
        history: PathBuf,
        #[arg(long)]
        terminal_state: PathBuf,
        #[arg(long)]
        prior_epochs: Option<PathBuf>,
        #[arg(long)]
        objects: Option<PathBuf>,
    },
    /// Persist three installed successor readiness signatures before voting is possible.
    Activate {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        ready: PathBuf,
        #[arg(long)]
        authorization: PathBuf,
    },
}
fn predecessor(bootstrap: &[u8], pin: &str, chain: &[Activated]) -> Result<Configuration> {
    ensure!(
        serde_json::to_vec(chain)?.len() <= epoch::archive::MAX_ARCHIVE_BYTES,
        "Replica epoch chain exceeds byte budget"
    );
    let (mut configuration, _) = authenticated(bootstrap, pin)?;
    for entry in chain {
        let activation = entry.verify(configuration.descriptor())?;
        configuration = configuration.successor(activation.terminal())?;
    }
    Ok(configuration)
}
impl Preparation {
    pub(super) fn configuration(
        &self,
        bootstrap: &[u8],
        pin: &str,
    ) -> Result<(Configuration, epoch::ValidatedTerminal)> {
        let old = predecessor(bootstrap, pin, &self.chain)?;
        let terminal = epoch::verify_terminal(
            old.descriptor(),
            &old.descriptor().genesis()?,
            None,
            &hex::decode(&self.evidence)?,
            &hex::decode(&self.history)?,
        )?;
        Ok((old.successor(&terminal)?, terminal))
    }
}
pub(super) fn nomination(manifest: &Manifest, terminal: &epoch::ValidatedTerminal) -> Result<()> {
    let signer = trust_bootstrap::hex32(&manifest.signer)?;
    let selected = terminal
        .declaration()
        .nominations
        .iter()
        .find(|n| n.voter == signer)
        .context("Local signer is not nominated")?;
    ensure!(
        hex::encode(selected.profile.id) == manifest.deployment
            && hex::encode(selected.profile.digest) == manifest.digest()?
            && selected.consent.digest == trust_wire::digest(&manifest.consent(0)?),
        "Local consent differs from the committed nomination"
    );
    let mut peers: Vec<_> = manifest.config.peers.iter().map(|p| p.key).collect();
    peers.sort();
    ensure!(
        peers
            == terminal
                .declaration()
                .nominations
                .iter()
                .map(|n| n.voter)
                .collect::<Vec<_>>(),
        "Local transport configuration differs from the nominated committee"
    );
    Ok(())
}
fn prepare(
    input: Initialise,
    transition: PathBuf,
    history: PathBuf,
    state: PathBuf,
    chain: Option<PathBuf>,
    objects: Option<PathBuf>,
) -> Result<Json> {
    ensure!(
        input.directory.is_absolute(),
        "Replica directory must be absolute"
    );
    runtime_files::root(input.directory.parent().context("Replica parent missing")?)?;
    let bootstrap = files::read_single(&input.bootstrap, trust_wire::MAXIMUM, true)?;
    let chain: Vec<Activated> = match chain {
        Some(path) => serde_json::from_slice(&files::read_single(
            &path,
            epoch::archive::MAX_ARCHIVE_BYTES,
            true,
        )?)?,
        None => vec![],
    };
    let old = predecessor(&bootstrap, &input.bootstrap_digest, &chain)?;
    let evidence = files::read_single(&transition, 131072, true)?;
    let history = files::read_single(&history, trust_wire::MAXIMUM, true)?;
    let terminal = epoch::verify_terminal(
        old.descriptor(),
        &old.descriptor().genesis()?,
        None,
        &evidence,
        &history,
    )?;
    let configuration = old.successor(&terminal)?;
    let preparation = Preparation {
        chain,
        evidence: hex::encode(&evidence),
        history: hex::encode(&history),
    };
    let secret = Zeroizing::new(files::read_single(&input.key, 4096, true)?);
    let key = identity(&secret)?;
    configuration.member(&key.verifying_key().to_bytes())?;
    let runtime: runtime::Config =
        serde_json::from_slice(&files::read_single(&input.config, MAX_CONFIG, true)?)?;
    validate_config(&runtime, &input.directory, &configuration)?;
    let config = serde_json::to_vec(&runtime)?;
    let signer = hex::encode(key.verifying_key().to_bytes());
    let consent = authorization::verify(
        &input.authorization,
        &digest(&config),
        &signer,
        &input.bootstrap_digest,
    )?;
    nomination(&consent.manifest, &terminal)?;
    consent
        .manifest
        .verify_future_bootstrap(&trust_bootstrap::inspect(&bootstrap, true)?)?;
    verify_tls(&consent.manifest)?;
    peer::transport(
        &configuration,
        key.verifying_key().to_bytes(),
        &runtime.peers,
        &runtime.tls,
    )?;
    if input.directory.try_exists()? {
        let location = Location {
            directory: input.directory.clone(),
            minimum_generation: 1,
        };
        let (deployment, engine) = open(&location)?;
        ensure!(
            deployment.configuration.bytes == configuration.bytes
                && deployment.record.authorization.digest()? == consent.profile_digest
                && deployment.record.bootstrap_digest == input.bootstrap_digest
                && deployment.record.signer == signer,
            "Existing prepared signer differs; no state replaced"
        );
        let mut result = status(&deployment, &engine, "EpochPrepared")?;
        result["readyShare"] = json!(hex::encode(engine.readiness_share()?));
        return Ok(result);
    }
    let state = files::read_single(&state, crate::authority_capacity::MAX_STATE_BYTES, true)?;
    use crate::consensus::runtime::Application;
    let references = crate::authority_application::PolicyApplication::new(old.clone())
        .retained_inputs(&state)?;
    let index = crate::authority_objects::EpochIndex::new(&state, &references)?;
    let objects = objects
        .as_deref()
        .map(|path| crate::authority_object_files::Directory::open(path, &index))
        .transpose()?;
    ensure!(
        objects.is_some() || references.is_empty(),
        "terminal immutable inputs are missing"
    );
    if let Some(objects) = &objects {
        objects.validate()?;
    }
    files::create_directory(&input.directory)?;
    files::write_new(&input.directory.join("Bootstrap.cbor"), &bootstrap)?;
    files::write_new(&input.directory.join("Identity.json"), &secret)?;
    files::create_directory(&input.directory.join("Journal"))?;
    let engine = Engine::prepare_epoch_with_objects(
        &input.directory.join("Journal"),
        old,
        key,
        &state,
        &terminal,
        objects.as_ref(),
    )?;
    let record = Record {
        format: "HyperNetAuthorityReplica/1".into(),
        bootstrap_digest: input.bootstrap_digest,
        signer,
        config_generation: 1,
        config_digest: digest(&config),
        config: hex::encode(&config),
        minimum_generation: engine.generation(),
        authorization: consent.manifest,
        consent_digest: consent.consent_digest,
        preparation: Some(preparation),
    };
    files::write_new(&input.directory.join(RECORD), &serde_json::to_vec(&record)?)?;
    let deployment = deployment(&input.directory)?;
    let mut result = status(&deployment, &engine, "EpochPrepared")?;
    result["readyShare"] = json!(hex::encode(engine.readiness_share()?));
    Ok(result)
}
pub fn run(command: Command) -> Result<Json> {
    match command {
        Command::Prepare {
            input,
            transition,
            history,
            terminal_state,
            prior_epochs,
            objects,
        } => prepare(
            input,
            transition,
            history,
            terminal_state,
            prior_epochs,
            objects,
        ),
        Command::Terminal {
            location,
            objects_output,
        } => {
            let (deployment, engine) = open(&location)?;
            let mut chain = deployment
                .record
                .preparation
                .as_ref()
                .map_or_else(Vec::new, |p| p.chain.clone());
            if let Some(activation) = engine.current_activation()? {
                let seal = Seal::new(
                    activation.terminal(),
                    Retained {
                        certificate: None,
                        node: None,
                        checkpoint: None,
                    },
                )?;
                chain.push(seal.activate(&activation)?);
            }
            let mut result = status(&deployment, &engine, "TerminalExported")?;
            result["terminalShare"] = json!(hex::encode(engine.terminal_share()?));
            result["terminalState"] = json!(hex::encode(engine.application()));
            result["priorEpochs"] = serde_json::to_value(chain)?;
            use crate::consensus::runtime::Application;
            let refs = crate::authority_application::PolicyApplication::new(
                deployment.configuration.clone(),
            )
            .retained_inputs(engine.application())?;
            let index = crate::authority_objects::EpochIndex::new(engine.application(), &refs)?;
            if let Some(path) = objects_output {
                let reader = engine.input_reader()?;
                crate::authority_object_files::Directory::create(&path, &index, |reference| {
                    Ok(reader
                        .resolve(std::slice::from_ref(reference))?
                        .get(reference)?
                        .to_vec())
                })?;
            } else {
                ensure!(refs.is_empty(), "terminal export requires --objects-output");
            }
            Ok(result)
        }
        Command::Handoff {
            location,
            checkpoint,
            retained,
        } => {
            let (deployment, engine) = open(&location)?;
            let package = files::read_single(&checkpoint, 131072, true)?;
            let retained: Retained = match retained {
                Some(path) => {
                    serde_json::from_slice(&files::read_single(&path, trust_wire::MAXIMUM, true)?)?
                }
                None => Retained {
                    certificate: None,
                    node: None,
                    checkpoint: None,
                },
            };
            let (prefix, checkpoint) = retained.verify(deployment.configuration.descriptor())?;
            let mut result = status(&deployment, &engine, "HandoffExported")?;
            result["handoffShare"] = json!(hex::encode(engine.handoff_share(&package)?));
            result["history"] = json!(hex::encode(engine.terminal_history(
                &package,
                &prefix,
                checkpoint.as_ref().map(|c| c.head())
            )?));
            Ok(result)
        }
        Command::Activate {
            location,
            ready,
            authorization,
        } => {
            let (deployment, mut engine) = open(&location)?;
            approved(&deployment, &authorization)?;
            let preparation = deployment
                .record
                .preparation
                .as_ref()
                .context("Replica is not a future authority")?;
            let bootstrap = files::read_single(
                &location.directory.join("Bootstrap.cbor"),
                trust_wire::MAXIMUM,
                true,
            )?;
            let (_, terminal) =
                preparation.configuration(&bootstrap, &deployment.record.bootstrap_digest)?;
            nomination(&deployment.record.authorization, &terminal)?;
            let ready = files::read_single(&ready, 2048, true)?;
            let activation = epoch::verify_activation(terminal, &ready)?;
            engine.activate_epoch(&activation)?;
            status(&deployment, &engine, "EpochActivated")
        }
    }
}
