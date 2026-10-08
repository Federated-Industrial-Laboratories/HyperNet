// SPDX-License-Identifier: MIT
//! Consented transport between two explicitly pinned federation authorities.
use crate::{confinement, federation_authority, host, protocol, types};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

#[path = "BridgeSync.rs"]
mod synchronisation;

pub const CONSENT_MAXIMUM: usize = 16384;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgeEndpoint {
    pub network: String,
    pub device_key: String,
    pub authority_key: String,
    pub authority_endpoint: String,
    pub authority_address: SocketAddr,
    pub ca_certificate_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgeConsent {
    pub version: u32,
    pub service: String,
    pub agreement_id: String,
    pub treaty_digest: String,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub source: BridgeEndpoint,
    pub destination: BridgeEndpoint,
    pub expires: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedBridgeConsent {
    payload: String,
    source_signature: String,
    destination_signature: String,
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    protocol::fixed_hex::<N>(value).map_err(anyhow::Error::msg)
}

fn endpoint_url(endpoint: &BridgeEndpoint) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(&endpoint.authority_endpoint)?;
    let host = url.host_str().context("authority host is required")?;
    ensure!(
        endpoint.authority_endpoint.len() <= 512
            && url.scheme() == "https"
            && host.parse::<std::net::IpAddr>().is_err()
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port_or_known_default() == Some(endpoint.authority_address.port())
            && endpoint.authority_address.port() > 0
            && !endpoint.authority_address.ip().is_unspecified()
            && !endpoint.authority_address.ip().is_multicast(),
        "authority must be a pinned HTTPS DNS root endpoint"
    );
    Ok(url)
}

pub fn verify_bridge_consent(
    document: &[u8],
    network: &str,
    device: &str,
    now: u64,
) -> Result<BridgeConsent> {
    ensure!(
        document.len() <= CONSENT_MAXIMUM,
        "bridge consent document is too large"
    );
    fixed_hex::<32>(network)?;
    fixed_hex::<32>(device)?;
    let signed: SignedBridgeConsent = serde_json::from_slice(document)?;
    let payload = URL_SAFE_NO_PAD.decode(signed.payload)?;
    ensure!(payload.len() <= 8192, "bridge consent payload is too large");
    let consent: BridgeConsent = serde_json::from_slice(&payload)?;
    ensure!(
        consent.version == 1 && consent.service == "FederationPages",
        "unsupported bridge consent"
    );
    fixed_hex::<16>(&consent.agreement_id)?;
    fixed_hex::<32>(&consent.treaty_digest)?;
    ensure!(
        host::valid_namespace(&consent.source_namespace)
            && host::valid_namespace(&consent.destination_namespace),
        "invalid federation namespace"
    );
    let mut identities = BTreeSet::new();
    for endpoint in [&consent.source, &consent.destination] {
        fixed_hex::<32>(&endpoint.network)?;
        fixed_hex::<32>(&endpoint.ca_certificate_digest)?;
        ensure!(
            identities.insert(fixed_hex::<32>(&endpoint.device_key)?)
                && identities.insert(fixed_hex::<32>(&endpoint.authority_key)?),
            "federation keys must be distinct"
        );
        endpoint_url(endpoint)?;
    }
    ensure!(
        consent.source.network != consent.destination.network,
        "federation requires distinct networks"
    );
    ensure!(
        [&consent.source, &consent.destination]
            .iter()
            .any(|endpoint| endpoint.network == network && endpoint.device_key == device),
        "bridge consent identity mismatch"
    );
    let mut message = b"HyperNet/BridgeConsent/1\0".to_vec();
    message.extend_from_slice(&payload);
    for (endpoint, signature) in [
        (&consent.source, &signed.source_signature),
        (&consent.destination, &signed.destination_signature),
    ] {
        VerifyingKey::from_bytes(&fixed_hex::<32>(&endpoint.device_key)?)?.verify_strict(
            &message,
            &ed25519_dalek::Signature::from_bytes(&fixed_hex::<64>(signature)?),
        )?;
    }
    ensure!(
        consent.expires > now && consent.expires - now <= 604800,
        "bridge consent is expired or exceeds seven days"
    );
    ensure!(
        (64 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&consent.memory_bytes)
            && (16..=512).contains(&consent.pids)
            && consent.cpu_period == 100000
            && (1000..=800000).contains(&consent.cpu_quota)
            && (1024 * 1024..=256 * 1024 * 1024).contains(&consent.state_bytes),
        "invalid bridge resource consent"
    );
    Ok(consent)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionConfiguration {
    network: String,
    endpoint: String,
    identity: PathBuf,
    ca_certificate: PathBuf,
    client_certificate: PathBuf,
    client_key: PathBuf,
    relay_address: SocketAddr,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    consent_file: PathBuf,
    treaty_file: PathBuf,
    state_directory: PathBuf,
    source: ConnectionConfiguration,
    destination: ConnectionConfiguration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    secret_key: String,
    public_key: String,
}

struct Credentials {
    configuration: ConnectionConfiguration,
    key: SigningKey,
    ca: reqwest::Certificate,
    certificate_digest: String,
    identity: reqwest::Identity,
}

pub struct BridgeConfig {
    pub state_directory: PathBuf,
    consent: BridgeConsent,
    treaty: types::FederationTreaty,
    profile: String,
    source: Credentials,
    destination: Credentials,
}

impl BridgeConfig {
    pub fn read_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    pub fn connect_ports(&self) -> Vec<u16> {
        BTreeSet::from([
            self.source.configuration.relay_address.port(),
            self.destination.configuration.relay_address.port(),
        ])
        .into_iter()
        .collect()
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "a bounded regular configuration file is required"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "configuration is too large");
    Ok(bytes)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn credentials(configuration: ConnectionConfiguration) -> Result<Credentials> {
    let mut identity: Identity =
        serde_json::from_slice(&read_bounded(&configuration.identity, 1024)?)?;
    let mut secret = fixed_hex::<32>(&identity.secret_key)?;
    identity.secret_key.zeroize();
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    ensure!(
        key.verifying_key().to_bytes() == fixed_hex::<32>(&identity.public_key)?,
        "bridge identity key mismatch"
    );
    let certificate = read_bounded(&configuration.ca_certificate, 65536)?;
    let ca = reqwest::Certificate::from_pem(&certificate)?;
    let mut transport = read_bounded(&configuration.client_certificate, 65536)?;
    transport.extend_from_slice(&read_bounded(&configuration.client_key, 65536)?);
    let parsed = reqwest::Identity::from_pem(&transport);
    transport.zeroize();
    Ok(Credentials {
        configuration,
        key,
        ca,
        certificate_digest: hex::encode(Sha256::digest(certificate)),
        identity: parsed?,
    })
}

pub fn load(path: &Path) -> Result<BridgeConfig> {
    let raw: Configuration = serde_json::from_slice(&read_bounded(path, 16384)?)?;
    let source = credentials(raw.source)?;
    let destination = credentials(raw.destination)?;
    let document = read_bounded(&raw.consent_file, CONSENT_MAXIMUM)?;
    let consent = verify_bridge_consent(
        &document,
        &source.configuration.network,
        &hex::encode(source.key.verifying_key().as_bytes()),
        now()?,
    )?;
    for (endpoint, credentials) in [
        (&consent.source, &source),
        (&consent.destination, &destination),
    ] {
        ensure!(
            endpoint.network == credentials.configuration.network
                && endpoint.device_key == hex::encode(credentials.key.verifying_key().as_bytes())
                && endpoint.authority_endpoint == credentials.configuration.endpoint
                && endpoint.ca_certificate_digest == credentials.certificate_digest,
            "bridge endpoint differs from signed consent"
        );
        let relay = credentials.configuration.relay_address;
        ensure!(
            !relay.ip().is_loopback()
                && !relay.ip().is_unspecified()
                && !relay.ip().is_multicast()
                && relay.port() == endpoint.authority_address.port(),
            "an isolated fixed relay address is required"
        );
    }
    ensure!(
        source.configuration.relay_address != destination.configuration.relay_address,
        "each authority requires its own relay"
    );
    let treaty: types::FederationTreaty =
        serde_json::from_slice(&read_bounded(&raw.treaty_file, 8192)?)?;
    ensure!(
        federation_authority::treaty_digest(&treaty).map_err(anyhow::Error::msg)?
            == consent.treaty_digest
            && treaty.agreement_id == consent.agreement_id
            && treaty.source_network == consent.source.network
            && treaty.destination_network == consent.destination.network
            && treaty.source_bridge_key == consent.source.device_key
            && treaty.destination_bridge_key == consent.destination.device_key
            && treaty.source_authority_key == consent.source.authority_key
            && treaty.destination_authority_key == consent.destination.authority_key
            && treaty.source_namespace == consent.source_namespace
            && treaty.destination_namespace == consent.destination_namespace
            && consent.expires <= treaty.expires,
        "bridge consent does not match the exact treaty"
    );
    Ok(BridgeConfig {
        state_directory: raw.state_directory,
        consent,
        treaty,
        profile: hex::encode(Sha256::digest(document)),
        source,
        destination,
    })
}

struct Connection {
    configuration: ConnectionConfiguration,
    key: SigningKey,
    client: reqwest::Client,
    epoch: AtomicU64,
}

impl Connection {
    fn new(credentials: Credentials) -> Result<Self> {
        let endpoint = reqwest::Url::parse(&credentials.configuration.endpoint)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(credentials.ca)
            .identity(credentials.identity)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .connect_timeout(Duration::from_secs(1))
            .pool_max_idle_per_host(4)
            .resolve(
                endpoint.host_str().context("authority host")?,
                credentials.configuration.relay_address,
            )
            .build()?;
        Ok(Self {
            configuration: credentials.configuration,
            key: credentials.key,
            client,
            epoch: AtomicU64::new(0),
        })
    }

    async fn request(&self, command: types::Command) -> Result<types::Reply> {
        let minimum_epoch = self.epoch.load(Ordering::Acquire);
        let mut request_id = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);
        let request = types::Request {
            version: 1,
            request_id: hex::encode(request_id),
            issued_at: now()?,
            command,
        };
        let payload = serde_json::to_vec(&request)?;
        ensure!(
            payload.len() <= types::MAX_PAYLOAD,
            "bridge request is too large"
        );
        let public = self.key.verifying_key().to_bytes();
        let mut signed = types::DOMAIN.to_vec();
        signed.extend_from_slice(&fixed_hex::<32>(&self.configuration.network)?);
        signed.extend_from_slice(&public);
        signed.extend_from_slice(&payload);
        let envelope = types::Envelope {
            network: self.configuration.network.clone(),
            public_key: hex::encode(public),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(self.key.sign(&signed).to_bytes()),
        };
        let url = reqwest::Url::parse(&self.configuration.endpoint)?.join("V1/Command")?;
        let mut response = self
            .client
            .post(url)
            .json(&envelope)
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 256 * 1024,
                "bridge response is too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let reply: types::Reply = serde_json::from_slice(&bytes)?;
        ensure!(
            reply.ok && reply.code == "Ok" && reply.epoch >= minimum_epoch,
            "federation authority denied the operation"
        );
        self.epoch.fetch_max(reply.epoch, Ordering::AcqRel);
        Ok(reply)
    }
}

pub async fn run(config: BridgeConfig, profile: confinement::Profile) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let state = std::ffi::CString::new(config.state_directory.as_os_str().as_bytes())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    ensure!(
        unsafe { libc::statfs(state.as_ptr(), filesystem.as_mut_ptr()) } == 0,
        "bridge state inspection failed"
    );
    let filesystem = unsafe { filesystem.assume_init() };
    ensure!(
        filesystem.f_type == libc::TMPFS_MAGIC
            && filesystem.f_blocks as u128 * filesystem.f_bsize as u128
                <= config.consent.state_bytes as u128,
        "bridge state requires a consent-bounded tmpfs"
    );
    ensure!(
        profile.memory_max <= config.consent.memory_bytes
            && profile.pids_max <= config.consent.pids,
        "bridge resource limits exceed consent"
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
        "bridge CPU limit exceeds consent"
    );
    confinement::canaries(&config.state_directory)?;
    synchronisation::run(config, profile).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn specification() -> Value {
        let public = |seed| {
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .as_bytes(),
            )
        };
        json!({
            "version":1,"service":"FederationPages","agreementId":hex::encode([5;16]),
            "treatyDigest":hex::encode([6;32]),"sourceNamespace":"Public","destinationNamespace":"Guests",
            "source":{"network":hex::encode([7;32]),"deviceKey":public(1),"authorityKey":public(3),
                "authorityEndpoint":"https://source.example:8443/","authorityAddress":"192.0.2.1:8443",
                "caCertificateDigest":hex::encode([9;32])},
            "destination":{"network":hex::encode([8;32]),"deviceKey":public(2),"authorityKey":public(4),
                "authorityEndpoint":"https://destination.example:8443/","authorityAddress":"192.0.2.2:8443",
                "caCertificateDigest":hex::encode([10;32])},
            "expires":200,"memoryBytes":67108864,"pids":32,"cpuQuota":10000,"cpuPeriod":100000,"stateBytes":1048576
        })
    }

    fn document(value: &Value) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        let mut message = b"HyperNet/BridgeConsent/1\0".to_vec();
        message.extend_from_slice(&payload);
        let signature = |seed| {
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .sign(&message)
                    .to_bytes(),
            )
        };
        serde_json::to_vec(&json!({"payload":URL_SAFE_NO_PAD.encode(payload),
            "sourceSignature":signature(1),"destinationSignature":signature(2)}))
        .unwrap()
    }

    fn accepted(value: &Value) -> bool {
        verify_bridge_consent(
            &document(value),
            value["source"]["network"].as_str().unwrap(),
            value["source"]["deviceKey"].as_str().unwrap(),
            100,
        )
        .is_ok()
    }

    #[test]
    fn consent_requires_both_exact_endpoint_signatures() {
        let value = specification();
        assert!(accepted(&value));
        let mut signed: Value = serde_json::from_slice(&document(&value)).unwrap();
        signed["destinationSignature"] = signed["sourceSignature"].clone();
        assert!(
            verify_bridge_consent(
                &serde_json::to_vec(&signed).unwrap(),
                value["source"]["network"].as_str().unwrap(),
                value["source"]["deviceKey"].as_str().unwrap(),
                100
            )
            .is_err()
        );
        let mut changed = value.clone();
        changed["destination"]["authorityAddress"] = json!("192.0.2.3:8443");
        signed = serde_json::from_slice(&document(&value)).unwrap();
        signed["payload"] = json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap()));
        assert!(
            verify_bridge_consent(
                &serde_json::to_vec(&signed).unwrap(),
                value["source"]["network"].as_str().unwrap(),
                value["source"]["deviceKey"].as_str().unwrap(),
                100
            )
            .is_err()
        );
    }

    #[test]
    fn consent_rejects_shared_roles_unbounded_resources_and_endpoint_escape() {
        let value = specification();
        for (field, invalid) in [
            ("memoryBytes", json!(67108863)),
            ("pids", json!(513)),
            ("cpuPeriod", json!(100001)),
            ("cpuQuota", json!(800001)),
            ("stateBytes", json!(268435457)),
            ("expires", json!(100)),
            ("expires", json!(604901)),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(!accepted(&changed));
        }
        for url in [
            "http://source.example:8443/",
            "https://source.example:8443/Other",
            "https://source.example:8443/?target=other",
            "https://user@source.example:8443/",
            "https://192.0.2.1:8443/",
            "https://source.example:9443/",
            "https://source_bad.example:8443/",
        ] {
            let mut changed = value.clone();
            changed["source"]["authorityEndpoint"] = json!(url);
            assert!(!accepted(&changed));
        }
        for address in ["0.0.0.0:8443", "224.0.0.1:8443", "[ff02::1]:8443"] {
            let mut changed = value.clone();
            changed["source"]["authorityAddress"] = json!(address);
            assert!(!accepted(&changed));
        }
        let mut changed = value.clone();
        changed["destination"]["authorityKey"] = changed["source"]["deviceKey"].clone();
        assert!(!accepted(&changed));
        let mut changed = value.clone();
        changed["services"] = json!(["Pages"]);
        assert!(!accepted(&changed));
        let mut changed = value;
        changed["destination"]["network"] = changed["source"]["network"].clone();
        assert!(!accepted(&changed));
    }
}
