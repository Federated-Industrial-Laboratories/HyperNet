// SPDX-License-Identifier: MIT
use super::files::{self, *};
use crate::runtime_authorization::Manifest;
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum AuthorityPurpose {
    Appointed,
    FutureAuthority { epoch: u64, committee: Vec<String> },
}
impl AuthorityPurpose {
    pub fn future(&self) -> bool {
        matches!(self, Self::FutureAuthority { .. })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profile {
    pub version: u64,
    pub purpose: AuthorityPurpose,
    pub manifest: Manifest,
    pub selinux_relabel: bool,
    pub root: PathBuf,
    pub clock_directory: PathBuf,
    pub artifacts: BTreeMap<String, String>,
}
impl std::ops::Deref for Profile {
    type Target = Manifest;
    fn deref(&self) -> &Manifest {
        &self.manifest
    }
}
impl Profile {
    pub fn prefix(&self) -> String {
        format!("HyperNetRuntime{}", &self.deployment[..16])
    }
    pub fn network_name(&self) -> String {
        format!("{}Authority", self.prefix())
    }
    pub fn ip(&self, last: u8) -> String {
        let a = self.subnet.octets();
        format!("{}.{}.{}.{}", a[0], a[1], a[2], last)
    }
    pub fn configuration_digest(&self) -> Result<String> {
        Ok(hex_digest(&serde_json::to_vec(self)?))
    }
    pub fn validate(&self, root: &Path) -> Result<()> {
        ensure!(
            self.version == 1 && self.root == root,
            "Unsupported runtime profile"
        );
        self.manifest.canonical()?;
        if let AuthorityPurpose::FutureAuthority { epoch, committee } = &self.purpose {
            let peers: Vec<_> = self
                .config
                .peers
                .iter()
                .map(|p| hex::encode(p.key))
                .collect();
            ensure!(
                *epoch > 0
                    && committee.len() == 4
                    && committee.windows(2).all(|w| w[0] < w[1])
                    && *committee == peers,
                "Future authority purpose differs from its exact committee"
            );
        }
        safe_path(&self.root)?;
        safe_path(&self.clock_directory)?;
        ensure!(
            self.clock_directory.is_absolute(),
            "Absolute clock directory required"
        );
        ensure!(
            !self.bind.is_unspecified()
                && self.config.listen.is_ipv4()
                && self.config.listen.ip().is_unspecified()
                && self.config.control_socket == Path::new("/State/Control/Control.sock")
                && self.config.tls.certificate == Path::new("/Config/Tls/Certificate.pem")
                && self.config.tls.private_key == Path::new("/Config/Tls/PrivateKey.pem")
                && self.config.tls.certificate_authority == Path::new("/Config/Tls/Authority.pem"),
            "Installed authority requires its fixed IPv4 and workload paths"
        );
        let crate::authority_clock_handoff::Source::Signed { path, .. } = &self.config.clock else {
            anyhow::bail!("Installed authority requires a signed clock witness");
        };
        ensure!(
            path.parent() == Some(Path::new("/Clock")),
            "Clock witness must use the fixed read-only mount"
        );
        for peer in &self.config.peers {
            let url = reqwest::Url::parse(&peer.origin)?;
            let _: std::net::Ipv4Addr = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Peer address is absent"))?
                .parse()
                .map_err(|_| anyhow::anyhow!("Installed profile requires literal IPv4 peers"))?;
        }

        const ARTIFACTS: [&str; 8] = [
            "Keys/Operator.key",
            "Seccomp.json",
            "Work/Config/Bootstrap.cbor",
            "Work/Config/Identity.json",
            "Work/Config/ReplicaConfig.json",
            "Work/Config/Tls/Authority.pem",
            "Work/Config/Tls/Certificate.pem",
            "Work/Config/Tls/PrivateKey.pem",
        ];
        ensure!(
            self.artifacts.is_empty() || self.artifacts.keys().map(String::as_str).eq(ARTIFACTS),
            "Runtime artifact membership differs"
        );
        for relative in self.artifacts.keys() {
            let path = Path::new(relative);
            ensure!(
                !path.is_absolute()
                    && path
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "Invalid artifact handle"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Resource {
    pub kind: String,
    pub name: String,
    pub id: Option<String>,
    pub fingerprint: Option<String>,
    pub network_ids: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Receipt {
    pub request_digest: String,
    pub result: serde_json::Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct State {
    pub version: u64,
    pub generation: u64,
    pub withdrawal_generation: u64,
    pub status: String,
    pub accepted_consent: Option<String>,
    pub profile_digest: String,
    pub resources: Vec<Resource>,
    pub initialised: bool,
    pub last_time: u64,
    pub failure_code: Option<String>,
    pub receipts: BTreeMap<String, Receipt>,
    pub pending: Option<String>,
}
impl State {
    pub fn new(profile: &Profile) -> Result<Self> {
        Ok(Self {
            version: 1,
            generation: 1,
            withdrawal_generation: 0,
            status: "AwaitingConsent".into(),
            accepted_consent: None,
            profile_digest: desired_digest(profile)?,
            resources: vec![],
            initialised: false,
            last_time: now()?,
            failure_code: None,
            receipts: BTreeMap::new(),
            pending: None,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, clap::ValueEnum)]
pub enum Operation {
    Preview,
    Status,
    Consent,
    Start,
    Stop,
    Withdraw,
    Diagnose,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    pub operation: Operation,
    pub operation_id: Option<String>,
    pub expected_generation: Option<u64>,
    pub profile_digest: Option<String>,
    pub minimum_signer_generation: Option<u64>,
}
pub fn load(root: &Path) -> Result<(Profile, State)> {
    super::transition::require_idle(root)?;
    let profile: Profile = json(&root.join("Profile.json"))?;
    profile.validate(root)?;
    let mut state: State = json(&root.join("State.json"))?;
    ensure!(
        state.version == 1
            && profile.artifacts.len() == 8
            && state.profile_digest == desired_digest(&profile)?
            && state.resources.len() <= 4
            && state.receipts.len() <= 122,
        "Invalid runtime journal"
    );
    let generation: u64 = json(&root.join("Generation.json"))?;
    ensure!(
        generation >= state.generation,
        "Local generation floor is stale"
    );
    if generation > state.generation {
        state.generation = generation;
        state.status = "Recovering".into();
        state.pending = Some("InterruptedCommit".into());
        state.failure_code = Some("StaleLifecycleState".into());
    }
    let withdrawal = withdrawal(root)?;
    ensure!(
        withdrawal >= state.withdrawal_generation,
        "Withdrawal floor is stale"
    );
    if withdrawal > state.withdrawal_generation {
        state.withdrawal_generation = withdrawal;
        state.status = "Withdrawn".into();
        state.accepted_consent = None;
        state.failure_code = Some("StaleLifecycleState".into());
    }
    Ok((profile, state))
}
pub fn withdrawal(root: &Path) -> Result<u64> {
    Ok(serde_json::from_slice(&public_read(
        &root.join("Authorization/Withdrawal.json"),
        64,
    )?)?)
}
pub fn save(root: &Path, state: &State) -> Result<()> {
    let generation: u64 = json(&root.join("Generation.json"))?;
    ensure!(
        state.generation >= generation,
        "Local generation cannot decrease"
    );
    if state.generation > generation {
        files::save(&root.join("Generation.json"), &state.generation)?;
    }
    files::save(&root.join("State.json"), state)
}
pub fn signer_generation(root: &Path) -> Result<u64> {
    let generation: u64 = json(&root.join("SignerGeneration.json"))?;
    ensure!(generation > 0, "Invalid signer generation floor");
    Ok(generation)
}
pub fn retain_signer_generation(root: &Path, generation: u64) -> Result<()> {
    let previous = signer_generation(root)?;
    ensure!(
        generation >= previous,
        "Signer generation is below the retained floor"
    );
    if generation > previous {
        files::save(&root.join("SignerGeneration.json"), &generation)?;
    }
    Ok(())
}
pub fn key(root: &Path, name: &str) -> Result<SigningKey> {
    let mut bytes = read(&root.join("Keys").join(format!("{name}.key")), 32)?;
    ensure!(bytes.len() == 32, "Invalid signing key");
    let key = SigningKey::from_bytes(bytes.as_slice().try_into()?);
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(key)
}
pub fn desired(p: &Profile) -> Result<Vec<u8>> {
    p.manifest.desired()
}
pub fn desired_digest(p: &Profile) -> Result<String> {
    p.manifest.digest()
}
pub fn consent(p: &Profile, s: &State) -> Result<Vec<u8>> {
    p.manifest.consent(s.withdrawal_generation)
}
pub fn verify_consent(root: &Path, p: &Profile, s: &State) -> Result<()> {
    let verified = crate::runtime_authorization::verify(
        &root.join("Authorization"),
        &p.config_digest()?,
        &p.signer,
        &p.bootstrap_digest,
    )?;
    ensure!(
        verified.manifest.digest()? == p.manifest.digest()?
            && verified.profile_digest == s.profile_digest
            && verified.withdrawal_generation == s.withdrawal_generation
            && s.accepted_consent.as_deref() == Some(verified.consent_digest.as_str()),
        "Consent differs from the exact runtime profile or lifecycle journal"
    );
    Ok(())
}
