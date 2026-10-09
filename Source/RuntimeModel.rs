// SPDX-License-Identifier: MIT
use super::files::{self, *};
use crate::trust_wire::{self as wire, Value as C};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Profile {
    pub version: u64,
    pub deployment: String,
    pub network: String,
    pub incarnation: String,
    pub software_digest: String,
    pub image: String,
    pub etcd: PathBuf,
    pub etcd_digest: String,
    pub etcdctl: PathBuf,
    pub etcdctl_digest: String,
    pub bind: std::net::Ipv4Addr,
    pub port: u16,
    pub voter_port_base: u16,
    pub subnet: std::net::Ipv4Addr,
    pub expires: u64,
    pub created: u64,
    pub operator: String,
    pub administrator: String,
    pub host: String,
    pub session_policy: String,
    pub selinux_relabel: bool,
    pub root: PathBuf,
    pub artifacts: BTreeMap<String, String>,
}
impl Profile {
    pub fn prefix(&self) -> String {
        format!("HyperNetRuntime{}", &self.deployment[..16])
    }
    pub fn network_name(&self) -> String {
        format!("{}Authority", self.prefix())
    }
    pub fn host_network_name(&self) -> String {
        format!("{}Host", self.prefix())
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
            self.version == 1 && self.root == root && self.session_policy == "Session",
            "Unsupported runtime profile"
        );
        for id in [
            &self.deployment,
            &self.network,
            &self.incarnation,
            &self.operator,
            &self.administrator,
            &self.host,
            &self.software_digest,
            &self.etcd_digest,
            &self.etcdctl_digest,
        ] {
            crate::protocol::fixed_hex::<32>(id).map_err(anyhow::Error::msg)?;
        }
        ensure!(
            self.image.starts_with("sha256:") && self.image.len() == 71,
            "Invalid image identity"
        );
        crate::protocol::fixed_hex::<32>(&self.image[7..]).map_err(anyhow::Error::msg)?;
        ensure!(
            self.port > 1024
                && self.voter_port_base > 1024
                && self.voter_port_base < 65532
                && !(self.voter_port_base..self.voter_port_base + 3).contains(&self.port),
            "Invalid or colliding ports"
        );
        ensure!(
            self.subnet.is_private()
                && self.subnet.octets()[3] == 0
                && self.subnet.octets()[2] < 255
                && !self.bind.is_unspecified()
                && !self.bind.is_multicast(),
            "Explicit IPv4 binding and private /24 subnet required"
        );
        ensure!(
            self.expires > self.created
                && self.expires <= u64::MAX / 1000
                && self.expires - self.created <= 604800,
            "Invalid consent lifetime"
        );
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
    pub bootstrap_done: bool,
    pub bootstrap_stage: String,
    pub registration_stage: String,
    pub host_registered: bool,
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
            bootstrap_done: false,
            bootstrap_stage: "Pending".into(),
            registration_stage: "Pending".into(),
            host_registered: false,
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
}
pub fn load(root: &Path) -> Result<(Profile, State)> {
    let profile: Profile = json(&root.join("Profile.json"))?;
    profile.validate(root)?;
    let mut state: State = json(&root.join("State.json"))?;
    ensure!(
        state.version == 1
            && state.profile_digest == desired_digest(&profile)?
            && state.resources.len() <= 16
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
    let withdrawal: u64 = json(&root.join("Withdrawal.json"))?;
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
pub fn key(root: &Path, name: &str) -> Result<SigningKey> {
    let mut bytes = read(&root.join("Keys").join(format!("{name}.key")), 32)?;
    ensure!(bytes.len() == 32, "Invalid signing key");
    let key = SigningKey::from_bytes(bytes.as_slice().try_into()?);
    zeroize::Zeroize::zeroize(&mut bytes);
    Ok(key)
}
fn b(hex: &str) -> Result<C> {
    Ok(C::Bytes(hex::decode(hex)?))
}
fn list(values: Vec<C>) -> C {
    C::Array(values)
}
fn roles() -> C {
    list(vec![C::Uint(0), C::Uint(1)])
}
fn limits() -> C {
    list(vec![
        C::Uint(268435456),
        C::Uint(4096),
        C::Uint(32),
        C::Uint(16),
    ])
}
fn volumes(p: &Profile) -> C {
    let mut values = (0..4)
        .map(|i| sha2::Sha256::digest(format!("{}Volume{i}", p.deployment).as_bytes()).to_vec())
        .collect::<Vec<_>>();
    values.sort();
    list(values.into_iter().map(C::Bytes).collect())
}
fn exposure(p: &Profile) -> Result<C> {
    Ok(list(vec![list(vec![
        b(&p.deployment)?,
        b(&p.configuration_digest()?)?,
    ])]))
}
fn placement(p: &Profile) -> Result<C> {
    Ok(list(vec![
        list(vec![b(&p.deployment)?]),
        volumes(p),
        list(vec![]),
        C::Uint(1),
    ]))
}
fn prefix(kind: u64, p: &Profile) -> Result<Vec<C>> {
    Ok(vec![
        C::Uint(kind),
        C::Uint(1),
        b(&p.network)?,
        b(&p.incarnation)?,
        C::Uint(1),
        C::Null,
    ])
}
pub fn desired(p: &Profile) -> Result<Vec<u8>> {
    let mut v = prefix(117, p)?;
    v.extend([
        b(&p.deployment)?,
        b(&p.software_digest)?,
        C::Uint(1),
        roles(),
        volumes(p),
        exposure(p)?,
        limits(),
        placement(p)?,
        C::Uint(1),
    ]);
    wire::encode(&list(v))
}
pub fn desired_digest(p: &Profile) -> Result<String> {
    Ok(hex::encode(wire::digest(&desired(p)?)))
}
pub fn consent(p: &Profile, s: &State) -> Result<Vec<u8>> {
    let mut v = prefix(105, p)?;
    v.extend([
        b(&p.deployment)?,
        b(&p.deployment)?,
        b(&p.operator)?,
        roles(),
        volumes(p),
        exposure(p)?,
        placement(p)?,
        limits(),
        C::Bool(false),
        list(vec![]),
        list(vec![C::Uint(p.created * 1000), C::Uint(p.expires * 1000)]),
        b(&s.profile_digest)?,
        C::Uint(s.withdrawal_generation),
    ]);
    wire::encode(&list(v))
}
pub fn verify_consent(root: &Path, p: &Profile, s: &State) -> Result<()> {
    let bytes = read(&root.join("Consent.cbor"), MAXIMUM)?;
    let (payload, signatures) = wire::envelope(&bytes, MAXIMUM)?;
    ensure!(
        payload == consent(p, s)?
            && signatures.len() == 1
            && hex::encode(signatures[0].0) == p.operator,
        "Consent does not match this exact local profile"
    );
    ensure!(
        s.accepted_consent.as_deref() == Some(hex_digest(&bytes).as_str()),
        "Consent differs from the lifecycle journal"
    );
    ensure!(now()? < p.expires, "Consent expired");
    Ok(())
}
use sha2::Digest;
