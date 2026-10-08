// SPDX-License-Identifier: MIT
use crate::{confinement, policy, protocol, types};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    network: String,
    endpoint: String,
    ca_certificate: PathBuf,
    identity: PathBuf,
    client_certificate: PathBuf,
    client_key: PathBuf,
    consent_file: PathBuf,
    state_directory: PathBuf,
    relay_address: SocketAddr,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    secret_key: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedConsent {
    payload: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub version: u32,
    pub network: String,
    pub device_key: String,
    pub grants: u64,
    pub expires: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
    pub authority_endpoint: String,
    pub authority_address: SocketAddr,
}

pub struct HostConfig {
    pub state_directory: PathBuf,
    raw: Configuration,
    consent: Consent,
    profile_digest: String,
    signing_key: SigningKey,
    certificate: reqwest::Certificate,
    transport_identity: reqwest::Identity,
}

impl HostConfig {
    pub fn read_paths(&self) -> Vec<PathBuf> {
        vec![]
    }
    pub fn connect_ports(&self) -> Vec<u16> {
        vec![self.raw.relay_address.port()]
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "configuration must be a bounded regular file"
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= maximum, "configuration is too large");
    Ok(bytes)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    protocol::fixed_hex::<N>(value).map_err(anyhow::Error::msg)
}

pub fn load(path: &Path) -> Result<HostConfig> {
    let raw: Configuration = serde_json::from_slice(&read_bounded(path, 16384)?)?;
    let network = fixed_hex::<32>(&raw.network)?;
    let mut identity: Identity = serde_json::from_slice(&read_bounded(&raw.identity, 1024)?)?;
    let mut secret = fixed_hex::<32>(&identity.secret_key)?;
    identity.secret_key.zeroize();
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    let public = fixed_hex::<32>(&identity.public_key)?;
    ensure!(
        signing_key.verifying_key().to_bytes() == public,
        "device identity does not match its key"
    );
    let document = read_bounded(&raw.consent_file, 16384)?;
    let signed: SignedConsent = serde_json::from_slice(&document)?;
    let payload = URL_SAFE_NO_PAD.decode(signed.payload)?;
    ensure!(payload.len() <= 8192, "consent payload is too large");
    let mut message = b"HyperNet/Consent/1\0".to_vec();
    message.extend_from_slice(&payload);
    let signature = ed25519_dalek::Signature::from_bytes(&fixed_hex::<64>(&signed.signature)?);
    VerifyingKey::from_bytes(&public)?.verify_strict(&message, &signature)?;
    let consent: Consent = serde_json::from_slice(&payload)?;
    let current_time = now()?;
    ensure!(
        consent.version == 1
            && fixed_hex::<32>(&consent.network)? == network
            && fixed_hex::<32>(&consent.device_key)? == public,
        "consent identity mismatch"
    );
    ensure!(consent.grants == 2, "consent must grant hosting only");
    ensure!(
        consent.expires > current_time && consent.expires - current_time <= 604800,
        "consent is expired or exceeds seven days"
    );
    ensure!(
        (64 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&consent.memory_bytes)
            && (16..=512).contains(&consent.pids)
            && consent.cpu_period == 100000
            && (1000..=800000).contains(&consent.cpu_quota)
            && (1024 * 1024..=256 * 1024 * 1024).contains(&consent.state_bytes),
        "invalid resource consent"
    );
    ensure!(
        raw.endpoint == consent.authority_endpoint,
        "authority endpoint differs from consent"
    );
    let endpoint = reqwest::Url::parse(&raw.endpoint)?;
    let host = endpoint.host_str().context("authority host is required")?;
    ensure!(
        endpoint.scheme() == "https"
            && host.parse::<std::net::IpAddr>().is_err()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint.path() == "/"
            && endpoint.port_or_known_default() == Some(consent.authority_address.port()),
        "authority must be an HTTPS DNS endpoint with its consented port"
    );
    ensure!(
        !raw.relay_address.ip().is_loopback() && !raw.relay_address.ip().is_unspecified(),
        "an isolated network relay address is required"
    );
    let certificate = reqwest::Certificate::from_pem(&read_bounded(&raw.ca_certificate, 65536)?)?;
    let mut identity_pem = read_bounded(&raw.client_certificate, 65536)?;
    identity_pem.extend_from_slice(&read_bounded(&raw.client_key, 65536)?);
    let transport_identity = reqwest::Identity::from_pem(&identity_pem)?;
    identity_pem.zeroize();
    Ok(HostConfig {
        state_directory: raw.state_directory.clone(),
        raw,
        consent,
        profile_digest: hex::encode(Sha256::digest(&document)),
        signing_key,
        certificate,
        transport_identity,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Heartbeat {
    effective_grants: u64,
    lease_expires: u64,
    profile: String,
    authority_revision: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status<'a> {
    active: bool,
    code: &'a str,
    effective_grants: u64,
    lease_expires: u64,
    epoch: u64,
    profile: &'a str,
    confinement: &'a confinement::Profile,
}

fn store_status(config: &HostConfig, status: Status<'_>) -> Result<()> {
    let bytes = serde_json::to_vec(&status)?;
    let path = config.state_directory.join("Status.json");
    let temporary = config.state_directory.join("Status.new");
    fs::write(&temporary, &bytes)?;
    fs::rename(temporary, path)?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

async fn heartbeat(
    config: &HostConfig,
    client: &reqwest::Client,
    epoch: u64,
) -> Result<(u64, Heartbeat)> {
    let mut request_id = [0u8; 16];
    OsRng.fill_bytes(&mut request_id);
    let request = types::Request {
        version: 1,
        request_id: hex::encode(request_id),
        issued_at: now()?,
        command: types::Command::Heartbeat {
            profile: config.profile_digest.clone(),
        },
    };
    let payload = serde_json::to_vec(&request)?;
    let public = config.signing_key.verifying_key().to_bytes();
    let mut message = types::DOMAIN.to_vec();
    message.extend_from_slice(&fixed_hex::<32>(&config.raw.network)?);
    message.extend_from_slice(&public);
    message.extend_from_slice(&payload);
    let envelope = types::Envelope {
        network: config.raw.network.clone(),
        public_key: hex::encode(public),
        payload: URL_SAFE_NO_PAD.encode(&payload),
        signature: hex::encode(config.signing_key.sign(&message).to_bytes()),
    };
    let command_url = reqwest::Url::parse(&config.raw.endpoint)?.join("V1/Command")?;
    let mut response = client
        .post(command_url)
        .json(&envelope)
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 65536,
            "authority response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let reply: types::Reply = serde_json::from_slice(&bytes)?;
    ensure!(
        reply.ok && reply.code == "Ok" && reply.epoch >= epoch,
        "authority denied hosting"
    );
    let result: Heartbeat = serde_json::from_value(reply.result)?;
    let current_time = now()?;
    ensure!(
        result.profile == config.profile_digest
            && result.authority_revision > 0
            && result.effective_grants & !2 == 0
            && result.lease_expires > current_time
            && result.lease_expires <= current_time.saturating_add(5),
        "invalid hosting lease"
    );
    Ok((reply.epoch, result))
}

pub async fn run(config: HostConfig, profile: confinement::Profile) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let state_name = std::ffi::CString::new(config.state_directory.as_os_str().as_bytes())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::statfs(state_name.as_ptr(), filesystem.as_mut_ptr()) } == 0,
        "state filesystem inspection failed"
    );
    let filesystem = unsafe { filesystem.assume_init() };
    ensure!(
        filesystem.f_type == libc::TMPFS_MAGIC
            && filesystem.f_blocks as u128 * filesystem.f_bsize as u128
                <= config.consent.state_bytes as u128,
        "a bounded tmpfs within storage consent is required"
    );
    ensure!(
        profile.memory_max <= config.consent.memory_bytes
            && profile.pids_max <= config.consent.pids,
        "enforced resource limits exceed consent"
    );
    let cpu: Vec<u64> = profile
        .cpu_max
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    ensure!(
        cpu.len() == 2
            && cpu[0] as u128 * config.consent.cpu_period as u128
                <= config.consent.cpu_quota as u128 * cpu[1] as u128,
        "CPU limit exceeds consent"
    );
    confinement::canaries(&config.state_directory)?;
    let endpoint = reqwest::Url::parse(&config.raw.endpoint)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(config.certificate.clone())
        .identity(config.transport_identity.clone())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .pool_max_idle_per_host(1)
        .resolve(
            endpoint.host_str().context("authority host")?,
            config.raw.relay_address,
        )
        .build()?;
    let mut epoch = 0;
    let mut previous_time = now()?;
    loop {
        let current_time = now()?;
        ensure!(
            current_time >= previous_time,
            "clock rollback stops hosting"
        );
        previous_time = current_time;
        let response = if current_time < config.consent.expires {
            heartbeat(&config, &client, epoch).await.ok()
        } else {
            None
        };
        let (active, grants, expires, code) = if let Some((next_epoch, lease)) = response {
            epoch = next_epoch;
            let grants = policy::effective(policy::PolicyInput {
                requested: 2,
                network: lease.effective_grants,
                user: config.consent.grants,
                host: config.consent.grants,
                application: 2,
                now: now()?,
                expires: lease.lease_expires.min(config.consent.expires),
                current_epoch: epoch,
                minimum_epoch: epoch,
                host_active: true,
            });
            (
                grants == 2,
                grants,
                lease.lease_expires,
                if grants == 2 { "Active" } else { "Denied" },
            )
        } else {
            (false, 0, 0, "AuthorityUnavailableOrDenied")
        };
        store_status(
            &config,
            Status {
                active,
                code,
                effective_grants: grants,
                lease_expires: expires,
                epoch,
                profile: &config.profile_digest,
                confinement: &profile,
            },
        )?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
