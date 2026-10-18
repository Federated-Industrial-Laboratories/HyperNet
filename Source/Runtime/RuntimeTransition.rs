// SPDX-License-Identifier: MIT
//! Stopped profile successors retain identities and state behind one durable activation barrier.
use super::{containers, files, model, services};
use crate::{runtime_manifest::Manifest, trust_wire as wire};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
#[path = "RuntimeTransitionArtifacts.rs"]
mod artifacts;

#[derive(Clone, ValueEnum)]
pub enum SessionPolicy {
    Session,
    Managed,
}
#[derive(Args)]
pub struct Prepare {
    #[arg(long)]
    directory: PathBuf,
    /// New absolute consent expiry in Unix seconds; omission retains the existing interval.
    #[arg(long)]
    valid_until: Option<u64>,
    /// Bind a freshly authenticated witness from the already approved monitor to this host boot.
    #[arg(long)]
    refresh_host_boot: bool,
    #[arg(long)]
    session_policy: Option<SessionPolicy>,
    /// Installed signed package containing the exact new Bin/HyperNet executable and OCI image.
    #[arg(long)]
    installed_prefix: Option<PathBuf>,
    #[arg(long, requires = "installed_prefix")]
    image: Option<String>,
    #[command(flatten)]
    package: super::package::Inputs,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Args)]
pub struct Selection {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    proposal: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    Prepare(Prepare),
    Preview(Selection),
    Apply {
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        preview_digest: String,
        #[arg(long)]
        operation_id: String,
    },
    /// Resume only the already durable exact stopped operation; no rollback or fresh consent.
    Recover {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        operation_id: String,
        /// Complete signed metadata only; serving remains blocked until a fresh reviewed successor.
        #[arg(long)]
        historical: bool,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    root: PathBuf,
    service: bool,
    predecessor: String,
    previous: Manifest,
    successor: Manifest,
    executable: PathBuf,
    package: Option<super::package::Selection>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Replacement {
    digest: String,
    public: bool,
    launch: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Transaction {
    operation: String,
    digest: String,
    proposal: Proposal,
    replacements: BTreeMap<String, Replacement>,
    authority: Option<model::Profile>,
    service: Option<services::Profile>,
    launch_identity: Option<(u64, u64)>,
    initialised: bool,
    lifecycle_generation: u64,
    completed: bool,
}
pub(super) fn require_idle(root: &Path) -> Result<()> {
    ensure!(
        !root.join("Transition.json").try_exists()?,
        "A stopped profile successor is incomplete; resume its exact runtime transition recover operation or withdraw"
    );
    Ok(())
}
pub(super) fn require_servable(root: &Path) -> Result<()> {
    ensure!(
        !root.join("RecoveryNeedsConsent.json").try_exists()?
            && !root.join("PackageCutoverRequired.json").try_exists()?,
        "Historical recovery retained non-serving state; prepare and apply a fresh reviewed consent/package successor before activation"
    );
    Ok(())
}
fn retain_offer(root: &Path, manifest: &Manifest, consent: &[u8]) -> Result<()> {
    if manifest.generation == 1 {
        return Ok(());
    }
    let directory = root.join("OperationalOffers");
    if !directory.try_exists()? {
        files::directory(&directory)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
    }
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(&directory)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "Invalid retained public offer directory"
    );
    let offer = wire::encode(&wire::Value::Array(vec![
        wire::Value::Uint(200),
        wire::Value::Uint(1),
        wire::Value::Text("AuthorityDeploymentOffer".into()),
        wire::Value::Bytes(manifest.encode()?),
        wire::Value::Bytes(consent.to_vec()),
        wire::Value::Array(vec![]),
    ]))?;
    let path = directory.join(format!("Generation{:020}.cbor", manifest.generation));
    if path.try_exists()? {
        ensure!(
            files::public_read(&path, files::MAXIMUM)? == offer,
            "Retained operational generation differs"
        );
    } else {
        files::publish_public(&path, &offer)?;
    }
    Ok(())
}
fn current(root: &Path, service: bool) -> Result<(Manifest, String)> {
    if service {
        let (p, _) = services::load(root)?;
        Ok((p.manifest.clone(), p.digest()?))
    } else {
        let (p, _) = model::load(root)?;
        Ok((p.manifest.canonical()?, p.configuration_digest()?))
    }
}
fn proposal(path: &Path, root: &Path, service: bool) -> Result<Proposal> {
    let p: Proposal = files::json(path)?;
    ensure!(
        p.root == root && p.service == service,
        "Proposal belongs to another installed deployment"
    );
    p.successor.successor_of(&p.previous)?;
    let software_changed = p.successor.software_digest != p.previous.software_digest
        || p.successor
            .roles
            .iter()
            .zip(&p.previous.roles)
            .any(|(new, old)| new.image_digest != old.image_digest);
    ensure!(
        !(software_changed || root.join("PackageCutoverRequired.json").try_exists()?)
            || p.package.is_some(),
        "Software replacement requires the exact reviewed current package target"
    );
    ensure!(
        files::executable(&p.executable)? == hex::encode(p.successor.software_digest),
        "Proposed executable changed"
    );
    Ok(p)
}
fn prepare(args: Prepare, service: bool) -> Result<Value> {
    let root = files::root(&args.directory)?;
    let _lock = files::lock(&root)?;
    let (old, predecessor) = current(&root, service)?;
    ensure!(
        files::public_read(&root.join("Authorization/Withdrawal.json"), 64)? == b"0",
        "Withdrawal is terminal"
    );
    let mut successor = old.clone();
    successor.generation = old
        .generation
        .checked_add(1)
        .context("Profile generation exhausted")?;
    successor.previous_profile = Some(wire::digest(&old.desired()?));
    successor.previous_consent = Some(wire::digest(&old.unsigned_consent(0)?));
    if let Some(until) = args.valid_until {
        successor.validity = (
            files::now()?.checked_mul(1000).context("Time overflow")?,
            until.checked_mul(1000).context("Time overflow")?,
        );
    }
    if args.refresh_host_boot {
        successor.clock.kernel_boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into();
    }
    if let Some(policy) = args.session_policy {
        successor.session_mode = u64::from(matches!(policy, SessionPolicy::Managed));
        successor.clock.kernel_boot = if successor.session_mode == 1 {
            "CurrentHost".into()
        } else {
            fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into()
        };
    }
    if successor.session_mode == 1 {
        successor.clock.kernel_boot = "CurrentHost".into();
    }
    ensure!(
        !root.join("PackageCutoverRequired.json").try_exists()? || args.installed_prefix.is_some(),
        "Historical package recovery requires a fresh reviewed installed target before activation"
    );
    let mut package = None;
    let executable = if let Some(prefix) = &args.installed_prefix {
        let path = prefix.join("Bin/HyperNet");
        successor.software_digest = crate::trust_bootstrap::hex32(&files::executable(&path)?)?;
        ensure!(
            root.join("PackageCutoverRequired.json").try_exists()?
                || files::executable(&std::env::current_exe()?.canonicalize()?)?
                    == hex::encode(old.software_digest),
            "Prepare cutover with the currently consented installed executable"
        );
        let image = args
            .image
            .as_deref()
            .context("Software cutover also requires the installed image digest")?;
        package = Some(super::package::prepare(prefix, args.package, &path, image)?);
        let digest = crate::trust_bootstrap::hex32(
            image
                .strip_prefix("sha256:")
                .context("Immutable image digest required")?,
        )?;
        for role in &mut successor.roles {
            role.image_digest = digest;
        }
        path
    } else {
        std::env::current_exe()?.canonicalize()?
    };
    successor.successor_of(&old)?;
    let p = Proposal {
        root,
        service,
        predecessor,
        previous: old,
        successor,
        executable,
        package,
    };
    files::private_dir(args.output.parent().context("Proposal parent required")?)?;
    files::create(&args.output, &serde_json::to_vec(&p)?)?;
    Ok(
        json!({"status":"SuccessorPrepared","proposal":args.output,"generation":p.successor.generation,"next":"Review with transition preview; no consent or installed state changed"}),
    )
}
fn inspect(p: &Proposal) -> Result<Value> {
    let (old, digest) = current(&p.root, p.service)?;
    ensure!(
        old == p.previous && digest == p.predecessor,
        "Inspected preceding profile changed"
    );
    ensure!(
        files::public_read(&p.root.join("Authorization/Withdrawal.json"), 64)? == b"0",
        "Withdrawal is terminal"
    );
    let digest = files::hex_digest(&serde_json::to_vec(p)?);
    Ok(
        json!({"status":"StoppedSuccessorPreview","previewDigest":digest,"predecessor":p.predecessor,
        "generation":p.successor.generation,"previous":p.previous,"successor":p.successor,
        "executable":p.executable,"state":"All signer, requester, recipient, content, tombstone and generation state is retained",
        "activation":"Stop the manager and workloads before apply. The successor remains stopped and needs current network admission and a fresh service activation."}),
    )
}
fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = crate::authority_files::private_directory(
        path.parent().context("Replacement parent absent")?,
    )?;
    crate::authority_files::atomic_at(
        &parent,
        path.file_name().context("Replacement name absent")?,
        bytes,
        true,
    )
}
fn stage(
    root: &Path,
    replacements: &mut BTreeMap<String, Replacement>,
    relative: &str,
    bytes: &[u8],
    public: bool,
    launch: Option<&str>,
) -> Result<()> {
    ensure!(
        bytes.len() <= files::MAXIMUM,
        "Successor artifact exceeds its bound"
    );
    let digest = files::hex_digest(bytes);
    let path = root.join("TransitionFiles").join(&digest);
    if path.try_exists()? {
        ensure!(
            files::read(&path, files::MAXIMUM)? == bytes,
            "Staged successor artifact differs"
        );
    } else {
        files::create(&path, bytes)?;
    }
    replacements.insert(
        relative.into(),
        Replacement {
            digest,
            public,
            launch: launch.map(Into::into),
        },
    );
    Ok(())
}
fn launch_identity(root: &Path) -> Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(root.join("Launch")) {
        Ok(m) => {
            ensure!(m.is_dir(), "Prepared launch is not a directory");
            Ok(Some((m.dev(), m.ino())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn begin(p: Proposal, operation: String, digest: String) -> Result<Transaction> {
    let root = &p.root;
    let mut replacements = BTreeMap::new();
    if !root.join("TransitionFiles").try_exists()? {
        files::directory(&root.join("TransitionFiles"))?;
    }
    files::private_dir(&root.join("TransitionFiles"))?;
    let (authority, service, initialised, lifecycle_generation) = if p.service {
        let (mut profile, state) = services::load(root)?;
        ensure!(
            !state.withdrawn
                && state.consented
                && state.container.is_none()
                && state.helper.is_none()
                && state.egress.is_none()
                && state.network.is_none(),
            "Stop every owned service resource before replacement"
        );
        let key = services::setup::operator(&profile)?;
        let bytes = p.successor.encode()?;
        stage(
            root,
            &mut replacements,
            "Config/Manifest.cbor",
            &bytes,
            false,
            Some("Config/Manifest.cbor"),
        )?;
        if profile.role()?.role == 5 {
            let route = crate::authority_domains::routes::RegisteredProfile::parse(
                &files::read(&root.join("Config/RouteProfile.cbor"), files::MAXIMUM)?,
                p.successor.network,
                p.successor.incarnation,
            )?;
            stage(
                root,
                &mut replacements,
                "Config/Egress.json",
                &services::egress::configuration(&p.successor, &route)?,
                false,
                Some("Config/Egress.json"),
            )?;
        }
        profile.manifest = p.successor.clone();
        profile
            .artifacts
            .extend(artifacts::configuration(root, &replacements)?);
        profile.validate()?;
        let local = crate::runtime_service_authorization::local_consent(
            &profile.manifest,
            profile.role()?.role,
            profile.manifest.generation,
            &profile.artifacts,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/LocalConsent.cbor",
            &wire::sign_envelope(&local, &key)?,
            true,
            None,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/HostConsent.cbor",
            &wire::sign_envelope(&p.successor.unsigned_consent(0)?, &key)?,
            true,
            None,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/Generation.json",
            p.successor.generation.to_string().as_bytes(),
            true,
            None,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/Manifest.cbor",
            &bytes,
            true,
            None,
        )?;
        (
            None,
            Some(profile),
            state.initialised,
            p.successor.generation,
        )
    } else {
        let (mut profile, mut state) = model::load(root)?;
        ensure!(
            state.withdrawal_generation == 0
                && state.accepted_consent.is_some()
                && state.pending.is_none()
                && !state.resources.iter().any(|r| r.kind == "container"),
            "Stop the authority before replacement"
        );
        containers::withdraw_networks(root, &profile, &mut state)?;
        ensure!(
            state.resources.is_empty(),
            "Owned authority resources remain"
        );
        profile.manifest =
            crate::runtime_authorization::Manifest::from_canonical(p.successor.clone())?;
        let config = serde_json::to_vec(&profile.config)?;
        profile.artifacts.insert(
            "Work/Config/ReplicaConfig.json".into(),
            files::hex_digest(&config),
        );
        profile.validate(root)?;
        stage(
            root,
            &mut replacements,
            "Work/Config/ReplicaConfig.json",
            &config,
            false,
            Some("Config/ReplicaConfig.json"),
        )?;
        let key = model::key(root, "Operator")?;
        stage(
            root,
            &mut replacements,
            "Authorization/Consent.cbor",
            &wire::sign_envelope(&p.successor.unsigned_consent(0)?, &key)?,
            true,
            None,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/DesiredProfile.cbor",
            &p.successor.desired()?,
            true,
            None,
        )?;
        stage(
            root,
            &mut replacements,
            "Authorization/Manifest.cbor",
            &p.successor.encode()?,
            true,
            None,
        )?;
        (
            Some(profile),
            None,
            state.initialised,
            state
                .generation
                .checked_add(1)
                .context("Lifecycle generation exhausted")?,
        )
    };
    let t = Transaction {
        operation,
        digest,
        launch_identity: launch_identity(root)?,
        proposal: p,
        replacements,
        authority,
        service,
        initialised,
        lifecycle_generation,
        completed: false,
    };
    // The durable barrier precedes every mutation of active configuration or authority state.
    crate::runtime_audit::record(
        &t.proposal.root,
        &t.proposal.successor,
        "Transition",
        "Prepared",
    )?;
    files::save(&t.proposal.root.join("Transition.json"), &t)?;
    Ok(t)
}
fn apply_files(t: &Transaction) -> Result<()> {
    let root = &t.proposal.root;
    ensure!(
        launch_identity(root)? == t.launch_identity,
        "Prepared state directory identity changed; no state replaced"
    );
    for (relative, replacement) in &t.replacements {
        let bytes = files::read(
            &root.join("TransitionFiles").join(&replacement.digest),
            files::MAXIMUM,
        )?;
        ensure!(
            files::hex_digest(&bytes) == replacement.digest,
            "Staged successor changed"
        );
        let destination = root.join(relative);
        if replacement.public {
            files::publish_public(&destination, &bytes)?;
        } else {
            replace_private(&destination, &bytes)?;
        }
        if let Some(relative) = &replacement.launch
            && t.launch_identity.is_some()
        {
            publish_launch(root, relative, &bytes)?;
            if relative == "Config/Egress.json" {
                publish_launch(root, "EgressConfig/Egress.json", &bytes)?;
            }
        }
    }
    Ok(())
}
fn publish_launch(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let staged = root
        .join("TransitionFiles")
        .join(format!("Owned{}", files::random_id()));
    files::create(&staged, bytes)?;
    files::podman(&files::strings(&[
        "unshare",
        "/usr/bin/chown",
        "1001:1001",
        staged.to_str().unwrap(),
    ]))?;
    files::podman(&files::strings(&[
        "unshare",
        "/usr/bin/mv",
        "--no-target-directory",
        staged.to_str().unwrap(),
        root.join("Launch").join(relative).to_str().unwrap(),
    ]))?;
    files::podman(&files::strings(&[
        "unshare",
        "/usr/bin/sync",
        "--file-system",
        root.join("Launch").to_str().unwrap(),
    ]))?;
    Ok(())
}
fn finish(mut t: Transaction, historical: bool) -> Result<Value> {
    ensure!(
        files::public_read(&t.proposal.root.join("Authorization/Withdrawal.json"), 64)? == b"0",
        "Withdrawal is terminal; successor cannot resume"
    );
    if historical && !t.completed {
        artifacts::recover(&mut t)?;
    }
    let root = &t.proposal.root;
    let image = format!(
        "sha256:{}",
        hex::encode(t.proposal.successor.roles[0].image_digest)
    );
    let package = if historical {
        crate::runtime_audit::record(root, &t.proposal.successor, "Recovery", "Prepared")?;
        if let Some(selection) = &t.proposal.package {
            super::package::inspect(selection, &t.proposal.executable, &image)?;
        }
        files::save(&root.join("RecoveryNeedsConsent.json"), &t.digest)?;
        if t.proposal.package.is_some() {
            files::save(&root.join("PackageCutoverRequired.json"), &t.digest)?;
        }
        None
    } else {
        ensure!(
            files::executable(&std::env::current_exe()?.canonicalize()?)?
                == hex::encode(t.proposal.successor.software_digest),
            "Run fresh transition apply or recover with the exact proposed installed executable"
        );
        t.proposal
            .package
            .as_ref()
            .map(|selection| super::package::admit(selection, &t.proposal.executable, &image))
            .transpose()?
    };
    if !t.completed {
        // A killed finite command may outlive its manager. Reconcile it before replacing any mount.
        if let Some(profile) = &t.authority {
            let mut state: model::State = files::json(&root.join("State.json"))?;
            containers::stop(root, profile, &mut state)?;
            containers::withdraw_networks(root, profile, &mut state)?;
        } else if let Some(profile) = &t.service {
            let mut state: services::State = files::json(&root.join("ServiceState.json"))?;
            services::control::stop(profile, &mut state)?;
        }
        apply_files(&t)?;
        if let Some(profile) = &t.authority {
            let mut state: model::State = files::json(&root.join("State.json"))?;
            ensure!(state.withdrawal_generation == 0, "Withdrawal is terminal");
            state.profile_digest = model::desired_digest(profile)?;
            state.accepted_consent = Some(hex::encode(wire::digest(
                &t.proposal.successor.unsigned_consent(0)?,
            )));
            state.status = "Stopped".into();
            state.pending = None;
            ensure!(
                state.generation <= t.lifecycle_generation,
                "Lifecycle generation advanced beyond this successor"
            );
            state.generation = t.lifecycle_generation;
            state.receipts.clear();
            files::save(&root.join("Profile.json"), profile)?;
            model::save(root, &state)?;
            if t.launch_identity.is_some() {
                containers::preparation::successor(root, profile)?;
            }
            if !historical {
                containers::verify_image(root, profile, &mut state)?;
            }
            if t.initialised && !historical {
                let status = containers::consent_successor(
                    root,
                    profile,
                    &mut state,
                    &hex::encode(wire::digest(&t.proposal.previous.desired()?)),
                )?;
                super::bootstrap::retain_status(root, profile, &status)?;
            }
            state.last_time = state.last_time.max(files::now()?);
            model::save(root, &state)?;
        } else if let Some(profile) = &t.service {
            let mut state: services::State = files::json(&root.join("ServiceState.json"))?;
            ensure!(
                !state.withdrawn
                    && state.container.is_none()
                    && state.helper.is_none()
                    && state.egress.is_none()
                    && state.network.is_none(),
                "Service state is not stopped"
            );
            state.profile_digest = profile.digest()?;
            state.consented = true;
            files::save(&root.join("ServiceProfile.json"), profile)?;
            services::save(profile, &mut state)?;
            if t.launch_identity.is_some() {
                services::preparation::successor(profile)?;
            }
            // Existing requester/recipient stores are opened and verified, never reinitialised.
            if t.initialised && !historical {
                services::workload::finite(
                    profile,
                    &mut state,
                    &files::strings(&["runtime-service-verify"]),
                    None,
                )?;
            }
        }
        let consent = files::public_read(
            &root.join(if t.proposal.service {
                "Authorization/HostConsent.cbor"
            } else {
                "Authorization/Consent.cbor"
            }),
            files::MAXIMUM,
        )?;
        retain_offer(root, &t.proposal.successor, &consent)?;
        if let Some(package) = &package {
            package.fresh()?;
        }
        if !historical {
            for name in ["RecoveryNeedsConsent.json", "PackageCutoverRequired.json"] {
                if root.join(name).try_exists()? {
                    fs::remove_file(root.join(name))?;
                }
            }
            fs::File::open(root)?.sync_all()?;
        }
        t.completed = true;
        files::save(&root.join("Transition.json"), &t)?;
    }
    ensure!(
        files::public_read(&root.join("Authorization/Withdrawal.json"), 64)? == b"0",
        "Withdrawal is terminal"
    );
    if let Some(package) = &package {
        package.fresh()?;
    }
    fs::rename(
        root.join("Transition.json"),
        root.join("LastTransition.json"),
    )?;
    fs::File::open(root)?.sync_all()?;
    crate::runtime_audit::record(
        root,
        &t.proposal.successor,
        if historical { "Recovery" } else { "Transition" },
        "Committed",
    )?;
    Ok(
        json!({"status":if historical {"HistoricalSuccessorRetained"} else {"SuccessorApplied"},"generation":t.proposal.successor.generation,"operationId":t.operation,"running":false,"servingBlocked":historical,
        "manifest":root.join("Authorization/Manifest.cbor"),"networkAdmission":"Submit this exact successor through deployment register, then request explicit current activation; existing role definitions and publication approvals are retained"}),
    )
}
pub(super) fn run(command: Command, service: bool) -> Result<Value> {
    if let Command::Prepare(args) = command {
        return prepare(args, service);
    }
    let root = match &command {
        Command::Preview(s) | Command::Apply { selection: s, .. } => &s.directory,
        Command::Recover { directory, .. } => directory,
        _ => unreachable!(),
    };
    let root = files::root(root)?;
    let _lock = files::lock(&root)?;
    match command {
        Command::Preview(s) => inspect(&proposal(&s.proposal, &root, service)?),
        Command::Apply {
            selection,
            preview_digest,
            operation_id,
        } => {
            crate::protocol::fixed_hex::<16>(&operation_id).map_err(anyhow::Error::msg)?;
            let _manager = files::manager_lock(&root.join("Manager"))?;
            let p = proposal(&selection.proposal, &root, service)?;
            let digest = files::hex_digest(&serde_json::to_vec(&p)?);
            ensure!(
                digest == preview_digest,
                "Reviewed successor digest differs"
            );
            for name in ["Transition.json", "LastTransition.json"] {
                if root.join(name).try_exists()? {
                    let t: Transaction = files::json(&root.join(name))?;
                    if name == "Transition.json" || t.operation == operation_id {
                        ensure!(
                            t.operation == operation_id && t.digest == digest,
                            "Operation identity already names another exact successor"
                        );
                        if name == "LastTransition.json" {
                            let blocked = root.join("RecoveryNeedsConsent.json").try_exists()?
                                || root.join("PackageCutoverRequired.json").try_exists()?;
                            return Ok(
                                json!({"status":if blocked {"HistoricalSuccessorRetained"} else {"SuccessorApplied"},"generation":t.proposal.successor.generation,"operationId":operation_id,"running":false,"servingBlocked":blocked}),
                            );
                        }
                        return finish(t, false);
                    }
                }
            }
            inspect(&p)?;
            finish(begin(p, operation_id, digest)?, false)
        }
        Command::Recover {
            operation_id,
            historical,
            ..
        } => {
            let _manager = files::manager_lock(&root.join("Manager"))?;
            let t: Transaction = files::json(&root.join("Transition.json"))?;
            ensure!(
                t.operation == operation_id
                    && t.proposal.service == service
                    && t.proposal.root == root,
                "Recovery operation differs from the durable successor"
            );
            finish(t, historical)
        }
        _ => unreachable!(),
    }
}

/// Restrictive operations remain available when a stopped successor has been interrupted.
pub(super) fn restrict(root: &Path, service: bool, withdraw: bool) -> Result<Value> {
    let t: Transaction = files::json(&root.join("Transition.json"))?;
    ensure!(
        t.proposal.root == root && t.proposal.service == service,
        "Stopped successor ownership differs"
    );
    crate::runtime_audit::restrictive(
        root,
        &t.proposal.successor,
        if withdraw { "Withdraw" } else { "Stop" },
        "Prepared",
    );
    if withdraw {
        files::publish_public(&root.join("Authorization/Withdrawal.json"), b"1")?;
    }
    if let Some(profile) = &t.authority {
        let mut state: model::State = files::json(&root.join("State.json"))?;
        if withdraw {
            state.withdrawal_generation = 1;
            state.accepted_consent = None;
            state.status = "Withdrawn".into();
            model::save(root, &state)?;
        }
        containers::stop(root, profile, &mut state)?;
        containers::withdraw_networks(root, profile, &mut state)?;
    } else if let Some(profile) = &t.service {
        let mut state: services::State = files::json(&root.join("ServiceState.json"))?;
        if withdraw {
            state.withdrawn = true;
            services::save(profile, &mut state)?;
        }
        services::control::stop(profile, &mut state)?;
    }
    crate::runtime_audit::restrictive(
        root,
        &t.proposal.successor,
        if withdraw { "Withdraw" } else { "Stop" },
        "Committed",
    );
    Ok(
        json!({"status":if withdraw{"Withdrawn"}else{"StoppedSuccessorPending"},"operationId":t.operation,"running":false,
        "recovery":if withdraw{"Withdrawal is terminal"}else{"Resume the same exact successor with transition recover"}}),
    )
}
pub(super) fn pending_status(root: &Path) -> Result<Value> {
    let t: Transaction = files::json(&root.join("Transition.json"))?;
    let withdrawn = files::public_read(&root.join("Authorization/Withdrawal.json"), 64)? != b"0";
    Ok(
        json!({"status":if withdrawn{"Withdrawn"}else{"StoppedSuccessorPending"},"operationId":t.operation,
        "nextGeneration":t.proposal.successor.generation,"profileDigest":t.digest,"running":"RecoveryInspectionRequired",
        "recoveryRequired":!withdrawn,"withdrawalTerminal":withdrawn}),
    )
}

pub(super) fn withdrawal_receipt(
    root: &Path,
    service: bool,
    output: Option<&Path>,
) -> Result<Value> {
    let t: Transaction = files::json(&root.join("Transition.json"))?;
    ensure!(
        t.proposal.root == root
            && t.proposal.service == service
            && files::public_read(&root.join("Authorization/Withdrawal.json"), 64)? == b"1",
        "Exact durable local withdrawal required"
    );
    let (key, cleanup) = if t.authority.is_some() {
        let state: model::State = files::json(&root.join("State.json"))?;
        (model::key(root, "Operator")?, state.resources.is_empty())
    } else {
        let profile = t
            .service
            .as_ref()
            .context("Interrupted service profile absent")?;
        let state: services::State = files::json(&root.join("ServiceState.json"))?;
        (
            services::setup::operator(profile)?,
            state.container.is_none()
                && state.helper.is_none()
                && state.egress.is_none()
                && state.network.is_none(),
        )
    };
    let manifest = &t.proposal.successor;
    ensure!(
        key.verifying_key().to_bytes() == manifest.operator,
        "Withdrawal operator differs"
    );
    use wire::Value as V;
    let payload = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetLocalWithdrawal".into()),
        V::Bytes(manifest.network.to_vec()),
        V::Bytes(manifest.incarnation.to_vec()),
        V::Bytes(manifest.deployment.to_vec()),
        V::Bytes(manifest.operator.to_vec()),
        V::Bytes(manifest.operational_digest()?.to_vec()),
        V::Uint(1),
        V::Bool(cleanup),
    ]))?;
    let bytes = wire::sign_envelope(&payload, &key)?;
    let destination = output
        .map(Path::to_owned)
        .unwrap_or_else(|| root.join("Authorization/WithdrawalReceipt.cbor"));
    if output.is_some() {
        files::create(&destination, &bytes)?;
    } else {
        files::publish_public(&destination, &bytes)?;
    }
    Ok(
        json!({"withdrawalReceipt":destination,"withdrawalGeneration":1,"cleanupComplete":cleanup,"networkPublished":false}),
    )
}
