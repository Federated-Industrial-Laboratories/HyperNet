// SPDX-License-Identifier: MIT
// Selected-host opaque mail storage with fresh authority and bounded durable state.
use crate::{
    confinement, mail_authority as authority,
    mail_disk::{Disk, Record},
    mail_types::*,
    protocol, store, types,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    network: String,
    identity: PathBuf,
    consent_file: PathBuf,
    authority_ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
    ca_certificate: PathBuf,
    state_file: PathBuf,
    listen: SocketAddr,
    relay_address: SocketAddr,
}
pub struct Config {
    pub state_file: PathBuf,
    pub listen: SocketAddr,
    pub relay_address: SocketAddr,
    pub consent: MailHostConsent,
    pub key: SigningKey,
    pub tls: Arc<ServerConfig>,
    authority_ca: reqwest::Certificate,
    transport_identity: reqwest::Identity,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw: Configuration = serde_json::from_slice(&store::read_bounded(path, 16384)?)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Identity {
            secret_key: String,
            public_key: String,
        }
        let mut bytes = store::read_private(&raw.identity, 4096)?;
        let parsed = serde_json::from_slice::<Identity>(&bytes);
        bytes.zeroize();
        let mut identity = parsed?;
        let secret = protocol::fixed_hex::<32>(&identity.secret_key).map_err(anyhow::Error::msg);
        identity.secret_key.zeroize();
        let mut secret = secret?;
        let key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        ensure!(
            hex::encode(key.verifying_key().as_bytes()) == identity.public_key,
            "mail signing identity mismatch"
        );
        let object: SignedMailObject =
            serde_json::from_slice(&store::read_bounded(&raw.consent_file, 16384)?)?;
        let consent = authority::host_consent(&object, &raw.network).map_err(anyhow::Error::msg)?;
        ensure!(
            consent.host_key == identity.public_key
                && consent.expires > store::now()?
                && consent.expires <= store::now()? + MAX_LIFETIME,
            "mail consent identity or expiry mismatch"
        );
        ensure!(
            raw.state_file == Path::new("/State/MailState.bin")
                && raw.listen.port() > 0
                && raw.relay_address.port() > 0,
            "invalid confined mail state or listener"
        );
        let endpoint = reqwest::Url::parse(&consent.endpoint)?;
        ensure!(
            endpoint.port_or_known_default() == Some(consent.address.port()),
            "mail endpoint and consented address ports differ"
        );
        let ca = store::read_bounded(&raw.ca_certificate, 65536)?;
        ensure!(
            authority::hash(&ca) == consent.ca_digest,
            "mail TLS root differs from consent"
        );
        let cert = store::read_bounded(&raw.certificate, 65536)?;
        let certificates = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !certificates.is_empty()
                && authority::hash(certificates[0].as_ref()) == consent.certificate_digest,
            "mail certificate differs from consent"
        );
        let private = zeroize::Zeroizing::new(store::read_private(&raw.private_key, 65536)?);
        let private_key = PrivateKeyDer::from_pem_slice(&private)?;
        let provider = Arc::new(crate::transport::tls_provider());
        let loaded = provider
            .key_provider
            .load_private_key(private_key.clone_key())
            .map_err(|_| anyhow::anyhow!("invalid mail TLS key"))?;
        if let Some(public) = loaded.public_key() {
            let mut forbidden = hex::decode("302a300506032b6570032100")?;
            forbidden.extend(key.verifying_key().as_bytes());
            ensure!(
                public.as_ref() != forbidden,
                "mail and TLS signing keys must differ"
            );
        }
        let mut tls = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)?;
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut pem = zeroize::Zeroizing::new(cert);
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&private);
        let transport_identity = reqwest::Identity::from_pem(&pem)?;
        let authority_ca =
            reqwest::Certificate::from_pem(&store::read_bounded(&raw.authority_ca, 65536)?)?;
        Ok(Self {
            state_file: raw.state_file,
            listen: raw.listen,
            relay_address: raw.relay_address,
            consent,
            key,
            tls: Arc::new(tls),
            authority_ca,
            transport_identity,
        })
    }
    pub fn check_resources(&self, profile: &confinement::Profile) -> Result<()> {
        let cpu: Vec<u64> = profile
            .cpu_max
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        ensure!(
            profile.memory_max <= self.consent.memory_bytes
                && profile.pids_max <= self.consent.pids
                && cpu.len() == 2
                && cpu[0] as u128 * self.consent.cpu_period as u128
                    <= self.consent.cpu_quota as u128 * cpu[1] as u128,
            "mail resource limits exceed consent"
        );
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        ensure!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } == 0
                && limit.rlim_max <= self.consent.state_bytes,
            "mail file limit exceeds consent"
        );
        Ok(())
    }
    fn client(&self) -> Result<reqwest::Client> {
        let endpoint = reqwest::Url::parse(&self.consent.authority_endpoint)?;
        Ok(reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.authority_ca.clone())
            .identity(self.transport_identity.clone())
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(1))
            .resolve(
                endpoint.host_str().context("missing authority TLS name")?,
                self.relay_address,
            )
            .build()?)
    }
}
fn nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreRequest {
    pub operation: SignedMailObject,
    pub payload: Option<String>,
}
pub struct MailStore {
    config: Config,
    client: reqwest::Client,
    disk: Disk,
}
impl MailStore {
    pub fn new(config: Config) -> Result<Self> {
        let client = config.client()?;
        let disk = Disk::open(&config.state_file, &config.consent, store::now()?)?;
        Ok(Self {
            config,
            client,
            disk,
        })
    }
    async fn request(&self, command: types::Command) -> Result<types::Reply> {
        let request = types::Request {
            version: 1,
            request_id: nonce(),
            issued_at: store::now()?,
            command,
        };
        let payload = serde_json::to_vec(&request)?;
        let mut bytes = types::DOMAIN.to_vec();
        bytes.extend(
            protocol::fixed_hex::<32>(&self.config.consent.network).map_err(anyhow::Error::msg)?,
        );
        bytes.extend(self.config.key.verifying_key().as_bytes());
        bytes.extend(&payload);
        let object = types::Envelope {
            network: self.config.consent.network.clone(),
            public_key: self.config.consent.host_key.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(self.config.key.sign(&bytes).to_bytes()),
        };
        let url =
            reqwest::Url::parse(&self.config.consent.authority_endpoint)?.join("V1/Command")?;
        let mut response = self
            .client
            .post(url)
            .json(&object)
            .send()
            .await
            .context("MailAuthorityUnavailable")?;
        ensure!(response.status().is_success(), "MailAuthorityUnavailable");
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(body.len() + chunk.len() <= 65536, "MailInvalidPermission");
            body.extend_from_slice(&chunk);
        }
        let reply: types::Reply = serde_json::from_slice(&body)?;
        if !reply.ok {
            bail!("{}", reply.code);
        }
        Ok(reply)
    }
    fn evidence<T: serde::de::DeserializeOwned>(
        &self,
        domain: &[u8],
        object: &SignedMailObject,
    ) -> Result<T> {
        ensure!(
            object.public_key == self.config.consent.authority_signer,
            "MailWrongAuthority"
        );
        authority::verify(domain, object, &self.config.consent.network).map_err(anyhow::Error::msg)
    }
    #[allow(clippy::too_many_arguments)]
    fn fresh(
        &self,
        network: &str,
        host: &str,
        generation: u64,
        revision: i64,
        epoch: u64,
        issued: u64,
        expires: u64,
        now: u64,
    ) -> Result<()> {
        ensure!(
            network == self.config.consent.network
                && host == self.config.consent.host_key
                && generation == self.config.consent.generation
                && issued <= now
                && expires > now
                && expires <= issued.saturating_add(5)
                && expires <= self.config.consent.expires,
            "MailStalePermission"
        );
        self.disk.floor(revision, epoch, generation, now)
    }
    pub async fn policy(&mut self) -> Result<()> {
        let now = store::now()?;
        ensure!(now < self.config.consent.expires, "MailConsentExpired");
        let reply = self
            .request(types::Command::MailPolicySync {
                host_key: self.config.consent.host_key.clone(),
            })
            .await?;
        let object: SignedMailObject = serde_json::from_value(reply.result["policy"].clone())?;
        let policy: MailPolicy = self.evidence(POLICY, &object)?;
        let now = store::now()?;
        self.fresh(
            &policy.network,
            &policy.host_key,
            policy.host_generation,
            policy.authority_revision,
            policy.authority_epoch,
            policy.issued_at,
            policy.expires,
            now,
        )?;
        ensure!(
            policy.version == 1 && policy.addresses.len() <= 64,
            "MailInvalidPermission"
        );
        let mut state = self.disk.state.clone();
        state.records.retain(|_, record| {
            record.route.expires > now
                && policy.addresses.iter().any(|a| {
                    a.address_id == record.route.recipient_address
                        && record.stored_at.saturating_add(a.retention_seconds) > now
                })
        });
        state.authority_revision = policy.authority_revision;
        state.authority_epoch = policy.authority_epoch;
        state.host_generation = policy.host_generation;
        state.time = now;
        self.disk.commit(state)?;
        Ok(())
    }
    pub async fn execute(&mut self, request: StoreRequest) -> Result<Value> {
        let now = store::now()?;
        ensure!(
            now < self.config.consent.expires && now >= self.disk.state.time,
            "MailConsentExpired"
        );
        let op = authority::operation(&request.operation, &self.config.consent.network, now)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            op.host_key == self.config.consent.host_key,
            "MailPermissionDenied"
        );
        let payload = if let Some(payload) = &request.payload {
            ensure!(op.action == "Put", "MailInvalidObject");
            let bytes = URL_SAFE_NO_PAD.decode(payload)?;
            ensure!(
                bytes.len() <= MAX_CIPHERTEXT
                    && bytes.len() as u64 == op.payload_bytes
                    && op.payload_digest.as_deref() == Some(&authority::hash(&bytes)),
                "MailInvalidObject"
            );
            Some(bytes)
        } else {
            ensure!(op.action != "Put", "MailInvalidObject");
            None
        };
        let reply = self
            .request(types::Command::MailAuthorise {
                host_key: self.config.consent.host_key.clone(),
                operation: request.operation.clone(),
            })
            .await?;
        let admission: SignedMailObject =
            serde_json::from_value(reply.result["permission"].clone())?;
        let permission: MailPermission = self.evidence(PERMISSION, &admission)?;
        let now = store::now()?;
        self.fresh(
            &permission.network,
            &permission.host_key,
            permission.host_generation,
            permission.authority_revision,
            permission.authority_epoch,
            permission.issued_at,
            permission.expires,
            now,
        )?;
        ensure!(
            permission.version == 1
                && permission.operation_digest
                    == authority::object_digest(OPERATION, &request.operation)
                        .map_err(anyhow::Error::msg)?
                && permission.address_id == op.address_id
                && permission.manifest_generation == op.manifest_generation
                && permission.manifest_digest == op.manifest_digest,
            "MailInvalidPermission"
        );
        let mut state = self.disk.state.clone();
        state.records.retain(|_, r| r.route.expires > now);
        state.authority_revision = permission.authority_revision;
        state.authority_epoch = permission.authority_epoch;
        state.host_generation = permission.host_generation;
        state.time = now;
        let result = match op.action.as_str() {
            "Put" => {
                let bytes = payload.context("MailInvalidObject")?;
                let ciphertext: MailCiphertext = serde_json::from_slice(&bytes)?;
                let route = op.route.as_ref().context("MailInvalidObject")?;
                ensure!(ciphertext.route == *route, "MailInvalidObject");
                let sender = authority::manifest(&ciphertext.sender_manifest, &route.network)
                    .map_err(anyhow::Error::msg)?;
                let recipient = authority::manifest(&ciphertext.recipient_manifest, &route.network)
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    sender.address_id == route.sender_address
                        && sender.generation == op.manifest_generation
                        && authority::object_digest(MANIFEST, &ciphertext.sender_manifest)
                            .map_err(anyhow::Error::msg)?
                            == op.manifest_digest
                        && recipient.address_id == route.recipient_address
                        && recipient.generation == route.recipient_generation
                        && authority::object_digest(MANIFEST, &ciphertext.recipient_manifest)
                            .map_err(anyhow::Error::msg)?
                            == route.recipient_manifest_digest,
                    "MailInvalidObject"
                );
                ensure!(
                    !URL_SAFE_NO_PAD.decode(&ciphertext.welcome)?.is_empty()
                        && !URL_SAFE_NO_PAD.decode(&ciphertext.message)?.is_empty(),
                    "MailInvalidObject"
                );
                let digest = op.payload_digest.as_ref().context("MailInvalidObject")?;
                if let Some(existing) = state.records.get(&route.message_id) {
                    ensure!(
                        existing.route == *route && existing.payload_digest == *digest,
                        "MailMessageConflict"
                    );
                    json!({"receipt":existing.receipt})
                } else {
                    ensure!(
                        state.records.len() < 512
                            && state
                                .records
                                .values()
                                .filter(|r| r.route.recipient_address == route.recipient_address)
                                .count()
                                < 64,
                        "MailQuotaExceeded"
                    );
                    let receipt = self.receipt(route, digest, "Stored", now)?;
                    state.records.insert(
                        route.message_id.clone(),
                        Record {
                            route: route.clone(),
                            stored_at: now,
                            payload: Some(URL_SAFE_NO_PAD.encode(bytes)),
                            payload_digest: digest.clone(),
                            operation: request.operation,
                            admission,
                            receipt: receipt.clone(),
                            acknowledged: BTreeSet::new(),
                        },
                    );
                    json!({"receipt":receipt})
                }
            }
            "List" => {
                let entries: Vec<_> = state
                    .records
                    .iter()
                    .filter(|(id, r)| {
                        r.route.recipient_address == op.address_id
                            && r.payload.is_some()
                            && op.after.as_ref().is_none_or(|after| *id > after)
                    })
                    .take(33)
                    .collect();
                let more = entries.len() > 32;
                let shown: Vec<_> = entries.into_iter().take(32).collect();
                let next = if more {
                    shown.last().map(|(id, _)| (*id).clone())
                } else {
                    None
                };
                json!({"entries":shown.iter().map(|(_,r)|&r.receipt).collect::<Vec<_>>(),"next":next})
            }
            "Fetch" => {
                let record = state
                    .records
                    .get(op.message_id.as_ref().context("MailInvalidObject")?)
                    .context("MailUnavailable")?;
                ensure!(
                    record.route.recipient_address == op.address_id && record.payload.is_some(),
                    "MailPermissionDenied"
                );
                json!({"payload":record.payload,"operation":record.operation,"admission":record.admission,"receipt":record.receipt})
            }
            "Receipt" => {
                if let Some(record) = state
                    .records
                    .get(op.message_id.as_ref().context("MailInvalidObject")?)
                {
                    ensure!(
                        record.route.sender_address == op.address_id
                            && op.route.as_ref() == Some(&record.route)
                            && op.payload_digest.as_ref() == Some(&record.payload_digest),
                        "MailPermissionDenied"
                    );
                    json!({"receipt":record.receipt})
                } else {
                    json!({"receipt":null})
                }
            }
            "Acknowledge" | "Delete" => {
                let record = state
                    .records
                    .get_mut(op.message_id.as_ref().context("MailInvalidObject")?)
                    .context("MailUnavailable")?;
                ensure!(
                    record.route.recipient_address == op.address_id
                        && op.payload_digest.as_ref() == Some(&record.payload_digest),
                    "MailPermissionDenied"
                );
                if op.action == "Delete" {
                    record.payload = None;
                    record.receipt =
                        self.receipt(&record.route, &record.payload_digest, "Deleted", now)?;
                } else {
                    ensure!(record.payload.is_some(), "MailUnavailable");
                    record.acknowledged.insert(op.device_id.clone());
                }
                let receipt = if op.action == "Acknowledge" {
                    self.receipt(&record.route, &record.payload_digest, "Received", now)?
                } else {
                    record.receipt.clone()
                };
                json!({"receipt":receipt})
            }
            _ => bail!("MailInvalidObject"),
        };
        // Recheck the lease immediately before committing; a stored receipt follows fsync.
        ensure!(store::now()? < permission.expires, "MailStalePermission");
        self.disk.commit(state)?;
        Ok(result)
    }
    fn receipt(
        &self,
        route: &MailRoute,
        digest: &str,
        status: &str,
        now: u64,
    ) -> Result<SignedMailObject> {
        let value = MailReceipt {
            version: 1,
            network: route.network.clone(),
            host_key: self.config.consent.host_key.clone(),
            host_generation: self.config.consent.generation,
            message_id: route.message_id.clone(),
            replacement: route.replacement,
            payload_digest: digest.into(),
            recipient_address: route.recipient_address.clone(),
            recipient_generation: route.recipient_generation,
            status: status.into(),
            recorded_at: now,
            expires: route.expires,
        };
        authority::sign(RECEIPT, &route.network, &value, &self.config.key)
            .map_err(anyhow::Error::msg)
    }
}
