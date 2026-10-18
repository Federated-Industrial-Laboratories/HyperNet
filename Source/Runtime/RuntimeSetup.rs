// SPDX-License-Identifier: MIT
//! Import one existing authority appointment without opening listeners or starting workloads.
use super::{files::*, model::*};
use crate::{
    authority_clock_handoff::Source,
    authority_files,
    consensus::{peer, records::Configuration, runtime::Config},
    runtime_authorization::{Manifest, Resources},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Args)]
pub struct Setup {
    #[arg(long)]
    pub directory: PathBuf,
    #[arg(long)]
    pub image: String,
    #[arg(long)]
    pub bootstrap: PathBuf,
    #[arg(long)]
    pub bootstrap_digest: String,
    /// Prepare a non-serving future committee; committed nomination and readiness are still required.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub future_epoch: Option<u64>,
    #[arg(long)]
    pub voter_key: PathBuf,
    #[arg(long)]
    pub replica_config: PathBuf,
    #[arg(long, num_args = 4, required = true)]
    pub peer_certificate: Vec<PathBuf>,
    #[arg(long)]
    pub bind: Ipv4Addr,
    #[arg(long)]
    pub port: u16,
    #[arg(long)]
    pub subnet: Ipv4Addr,
    #[arg(long, default_value_t = 536870912)]
    pub memory_bytes: u64,
    #[arg(long, default_value_t = 64)]
    pub pids: u64,
    #[arg(long, default_value_t = 100000)]
    pub cpu_quota: u64,
    #[arg(long, default_value_t = 1073741824)]
    pub state_bytes: u64,
    #[arg(long, default_value_t = 3600)]
    pub lifetime_seconds: u64,
    #[arg(long, default_value = "Session", value_parser = ["Session", "Managed"])]
    pub session_policy: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Identity {
    public_key: String,
    secret_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}
fn voter(bytes: &[u8]) -> Result<SigningKey> {
    let identity: Identity = serde_json::from_slice(bytes)?;
    let private = Zeroizing::new(crate::trust_bootstrap::hex32(&identity.secret_key)?);
    let key = SigningKey::from_bytes(&private);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == identity.public_key,
        "Voter public and private keys differ"
    );
    Ok(key)
}
fn remember(
    root: &Path,
    relative: &str,
    artifacts: &mut std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remember(
                root,
                &format!("{relative}/{}", entry.file_name().to_str().unwrap()),
                artifacts,
            )?;
        } else {
            let name = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .unwrap()
                .to_string();
            artifacts.insert(name, hex_digest(&read(&entry.path(), MAXIMUM)?));
        }
    }
    Ok(())
}
pub fn setup(args: Setup) -> Result<serde_json::Value> {
    for path in [
        &args.directory,
        &args.bootstrap,
        &args.voter_key,
        &args.replica_config,
    ] {
        safe_path(path)?;
    }
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Runtime setup requires an ordinary local user"
    );
    ensure!(
        args.directory.is_absolute()
            && args.directory.to_string_lossy().len() <= 88
            && !args.directory.exists(),
        "A new absolute runtime directory with space for its private socket is required"
    );
    let parent = args.directory.parent().context("Runtime parent required")?;
    super::files::root(parent)?;
    ensure!(
        (30..=604800).contains(&args.lifetime_seconds),
        "Consent lifetime must be 30 seconds through seven days"
    );
    let bootstrap = read(&args.bootstrap, MAXIMUM)?;
    ensure!(
        hex_digest(&bootstrap) == args.bootstrap_digest,
        "Bootstrap differs from its independently authenticated digest"
    );
    let verified = crate::trust_bootstrap::inspect(&bootstrap, true)?;
    let mut configuration = Configuration::trusted(verified.descriptor().canonical())?;
    let secret = Zeroizing::new(read(&args.voter_key, 4096)?);
    let key = voter(&secret)?;
    let mut config: Config = json(&args.replica_config)?;
    let purpose = if let Some(epoch) = args.future_epoch {
        config.peers.sort_by_key(|p| p.key);
        let committee: Vec<_> = config.peers.iter().map(|p| p.key).collect();
        ensure!(
            committee.windows(2).all(|w| w[0] < w[1])
                && committee
                    .iter()
                    .all(|k| !verified.reservations().iter().any(|(_, old)| old == k)),
            "Future committee must use four distinct fresh voter identities"
        );
        configuration.voters = committee.clone().try_into().expect("four configured peers");
        AuthorityPurpose::FutureAuthority {
            epoch,
            committee: committee.iter().map(hex::encode).collect(),
        }
    } else {
        AuthorityPurpose::Appointed
    };
    configuration.member(&key.verifying_key().to_bytes())?;
    for path in [
        &config.tls.certificate,
        &config.tls.private_key,
        &config.tls.certificate_authority,
    ] {
        safe_path(path)?;
        ensure!(
            path.is_absolute(),
            "Absolute transport input paths required"
        );
    }
    // This verifies all four identities, certificate pins and local credentials without connecting.
    peer::transport(
        &configuration,
        key.verifying_key().to_bytes(),
        &config.peers,
        &config.tls,
    )?;
    let mut tls = BTreeMap::new();
    for (name, path, private) in [
        ("Certificate.pem", &config.tls.certificate, false),
        ("PrivateKey.pem", &config.tls.private_key, true),
        ("Authority.pem", &config.tls.certificate_authority, false),
    ] {
        tls.insert(
            name.to_string(),
            authority_files::read_single(path, 65536, private)?,
        );
    }
    let mut endpoint_leaves = BTreeMap::new();
    for path in &args.peer_certificate {
        use rustls::pki_types::pem::PemObject;
        safe_path(path)?;
        let pem = authority_files::read_single(path, 65536, false)?;
        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            certificates.len() == 1,
            "One exact leaf per peer certificate input is required"
        );
        let leaf = certificates[0].as_ref();
        let digest: [u8; 32] = sha2::Sha256::digest(leaf).into();
        let peer = config
            .peers
            .iter()
            .find(|peer| peer.certificate_sha256 == digest)
            .context("Leaf does not match any configured peer pin")?;
        let transport = crate::runtime_manifest::leaf_key(leaf)?;
        ensure!(
            if purpose.future() {
                !verified
                    .reservations()
                    .iter()
                    .any(|(_, old)| old == &transport)
            } else {
                verified
                    .summary
                    .authority_transports
                    .get(&hex::encode(peer.key))
                    == Some(&hex::encode(transport))
            },
            "Authority transport is not reserved by the accepted bootstrap"
        );
        ensure!(
            endpoint_leaves
                .insert(hex::encode(peer.key), hex::encode(leaf))
                .is_none(),
            "Repeated peer certificate"
        );
    }
    ensure!(
        endpoint_leaves.len() == 4,
        "Complete peer certificate inputs required"
    );
    for endpoint in &mut config.peers {
        let url = reqwest::Url::parse(&endpoint.origin)?;
        let address: std::net::IpAddr = url
            .host_str()
            .context("Peer address absent")?
            .trim_matches(['[', ']'])
            .parse()?;
        endpoint.origin = format!(
            "https://{}/",
            SocketAddr::new(
                address,
                url.port_or_known_default().context("Peer port absent")?
            )
        );
    }
    let clock_directory = match &mut config.clock {
        Source::Signed {
            path, public_key, ..
        } => {
            ensure!(
                verified.summary.clock_monitors.contains(public_key),
                "Clock monitor is not reserved by the accepted bootstrap"
            );
            safe_path(path)?;
            ensure!(path.is_absolute(), "Absolute signed clock path required");
            let parent = path
                .parent()
                .context("Clock parent required")?
                .to_path_buf();
            ensure!(
                parent.canonicalize()? == parent,
                "Clock parent cannot contain symbolic links"
            );
            ancestors(&parent)?;
            let name = path
                .file_name()
                .context("Clock export filename required")?
                .to_owned();
            *path = Path::new("/Clock").join(name);
            parent
        }
        Source::Private { .. } => {
            anyhow::bail!("Installed authority requires a separately signed clock export")
        }
    };
    config.listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, args.port));
    config.control_socket = "/State/Control/Control.sock".into();
    config.tls.certificate = "/Config/Tls/Certificate.pem".into();
    config.tls.private_key = "/Config/Tls/PrivateKey.pem".into();
    config.tls.certificate_authority = "/Config/Tls/Authority.pem".into();
    let created = now()?;
    let operator = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    if args.session_policy == "Managed" {
        let Source::Signed { kernel_boot, .. } = &mut config.clock else {
            unreachable!()
        };
        *kernel_boot = "CurrentHost".into();
    }
    let manifest = Manifest {
        generation: 1,
        previous_profile: None,
        previous_consent: None,
        version: 1,
        deployment: random_id(),
        network: hex::encode(configuration.scope.network),
        incarnation: hex::encode(configuration.scope.incarnation),
        operator: hex::encode(operator.verifying_key().to_bytes()),
        signer: hex::encode(key.verifying_key().to_bytes()),
        bootstrap_digest: args.bootstrap_digest,
        software_digest: executable(&std::env::current_exe()?.canonicalize()?)?,
        image: args.image,
        created,
        expires: created
            .checked_add(args.lifetime_seconds)
            .context("Consent deadline overflow")?,
        bind: args.bind,
        port: args.port,
        subnet: args.subnet,
        resources: Resources {
            memory_bytes: args.memory_bytes,
            pids: args.pids,
            cpu_quota: args.cpu_quota,
            cpu_period: 100000,
            state_bytes: args.state_bytes,
        },
        config,
        tls_digests: tls
            .iter()
            .map(|(name, bytes)| (name.clone(), hex_digest(bytes)))
            .collect(),
        endpoint_leaves,
        session_policy: args.session_policy,
    };
    if purpose.future() {
        manifest.verify_future_bootstrap(&verified)?;
    } else {
        manifest.verify_bootstrap(&verified)?;
    }
    let root = &args.directory;
    let mut profile = Profile {
        version: 1,
        purpose,
        manifest,
        selinux_relabel: selinux_enabled()?,
        root: root.clone(),
        clock_directory,
        artifacts: BTreeMap::new(),
    };
    profile.validate(root)?;
    directory(root)?;
    reserve(root)?;
    for name in [
        "Keys",
        "Work",
        "Work/Config",
        "Work/Config/Tls",
        "Authorization",
        "Diagnostics",
        "Manager",
    ] {
        directory(&root.join(name))?;
    }
    fs::set_permissions(
        root.join("Authorization"),
        fs::Permissions::from_mode(0o755),
    )?;
    create(&root.join("Keys/Operator.key"), &operator.to_bytes())?;
    create(&root.join("Work/Config/Bootstrap.cbor"), &bootstrap)?;
    create(&root.join("Work/Config/Identity.json"), &secret)?;
    create(
        &root.join("Work/Config/ReplicaConfig.json"),
        &serde_json::to_vec(&profile.config)?,
    )?;
    for (name, bytes) in tls {
        create(&root.join("Work/Config/Tls").join(name), &bytes)?;
    }
    super::files::save(&root.join("Seccomp.json"), &seccomp()?)?;
    remember(root, "Keys", &mut profile.artifacts)?;
    remember(root, "Work", &mut profile.artifacts)?;
    profile.artifacts.insert(
        "Seccomp.json".into(),
        hex_digest(&read(&root.join("Seccomp.json"), MAXIMUM)?),
    );
    profile.validate(root)?;
    super::files::save(&root.join("Profile.json"), &profile)?;
    for (name, bytes) in [
        ("Manifest.cbor", profile.manifest.canonical()?.encode()?),
        ("DesiredProfile.cbor", desired(&profile)?),
        ("Withdrawal.json", b"0".to_vec()),
    ] {
        publish_public(&root.join("Authorization").join(name), &bytes)?;
    }
    super::files::save(&root.join("Generation.json"), &1u64)?;
    super::files::save(&root.join("SignerGeneration.json"), &1u64)?;
    let state = State::new(&profile)?;
    crate::runtime_audit::initialise(root, &profile.manifest.canonical()?)?;
    super::model::save(root, &state)?;
    Ok(
        json!({"status":"AwaitingConsent","generation":state.generation,"profileDigest":state.profile_digest,"deployment":profile.deployment,"signer":profile.signer,"expires":profile.expires,"backend":"BasicHotStuff","networkServing":false,"minimumSignerGeneration":1}),
    )
}

pub(super) fn seccomp() -> Result<serde_json::Value> {
    let upstream = fs::read("/usr/share/containers/seccomp.json")?;
    ensure!(upstream.len() <= MAXIMUM, "Seccomp profile exceeds bound");
    let mut seccomp: serde_json::Value = serde_json::from_slice(&upstream)?;
    ensure!(
        seccomp["defaultAction"] == "SCMP_ACT_ERRNO",
        "Deny-by-default seccomp required"
    );
    let calls = seccomp["syscalls"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid seccomp profile"))?;
    for call in calls.iter_mut() {
        call["names"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid seccomp names"))?
            .retain(|n| n != "socket" && n != "socketcall");
    }
    calls.retain(|c| !c["names"].as_array().unwrap().is_empty());
    for family in [1, 2, 10] {
        for protocol in [0, 6] {
            if family == 1 && protocol != 0 {
                continue;
            }
            calls.push(json!({"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":family,"op":"SCMP_CMP_EQ"},{"index":1,"value":15,"valueTwo":1,"op":"SCMP_CMP_MASKED_EQ"},{"index":2,"value":protocol,"op":"SCMP_CMP_EQ"}]}));
        }
    }
    Ok(seccomp)
}
