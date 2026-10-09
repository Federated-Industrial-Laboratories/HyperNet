// SPDX-License-Identifier: MIT
// Selected-host opaque transfer storage with fresh authority and bounded durable state.
use crate::{
    confinement,
    mail_authority::{hash, sign, verify},
    protocol, store, transfer_authority as authority,
    transfer_disk::{Disk, Record},
    transfer_types::*,
    types,
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
    pub consent: HostConsent,
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
            "transfer signing identity mismatch"
        );
        let object: types::Envelope =
            serde_json::from_slice(&store::read_bounded(&raw.consent_file, 16384)?)?;
        let consent = authority::host_consent(&object, &raw.network).map_err(anyhow::Error::msg)?;
        ensure!(
            consent.host_key == identity.public_key
                && consent.expires > store::now()?
                && consent.expires <= store::now()? + MAX_LIFETIME,
            "transfer consent identity or expiry mismatch"
        );
        ensure!(
            raw.state_file == Path::new("/State/TransferState.bin")
                && raw.listen.port() > 0
                && raw.relay_address.port() > 0,
            "invalid confined transfer state or listener"
        );
        let endpoint = reqwest::Url::parse(&consent.endpoint)?;
        ensure!(
            endpoint.port_or_known_default() == Some(consent.address.port()),
            "transfer endpoint and consented address ports differ"
        );
        let ca = store::read_bounded(&raw.ca_certificate, 65536)?;
        ensure!(
            hash(&ca) == consent.ca_digest,
            "transfer TLS root differs from consent"
        );
        let cert = store::read_bounded(&raw.certificate, 65536)?;
        let certificates = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !certificates.is_empty()
                && hash(certificates[0].as_ref()) == consent.certificate_digest,
            "transfer certificate differs from consent"
        );
        let private = zeroize::Zeroizing::new(store::read_private(&raw.private_key, 65536)?);
        let private_key = PrivateKeyDer::from_pem_slice(&private)?;
        let provider = Arc::new(crate::transport::tls_provider());
        let loaded = provider
            .key_provider
            .load_private_key(private_key.clone_key())
            .map_err(|_| anyhow::anyhow!("invalid transfer TLS key"))?;
        if let Some(public) = loaded.public_key() {
            let mut forbidden = hex::decode("302a300506032b6570032100")?;
            forbidden.extend(key.verifying_key().as_bytes());
            ensure!(
                public.as_ref() != forbidden,
                "transfer and TLS signing keys must differ"
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
            "transfer resource limits exceed consent"
        );
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        ensure!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } == 0
                && limit.rlim_max <= self.consent.state_bytes,
            "transfer file limit exceeds consent"
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
    pub operation: types::Envelope,
    pub payload: Option<String>,
}
pub struct TransferStore {
    config: Config,
    client: reqwest::Client,
    disk: Disk,
}
impl TransferStore {
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
            .context("TransferAuthorityUnavailable")?;
        ensure!(
            response.status().is_success(),
            "TransferAuthorityUnavailable"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= 65536,
                "TransferInvalidPermission"
            );
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
        object: &types::Envelope,
    ) -> Result<T> {
        ensure!(
            object.public_key == self.config.consent.authority_signer,
            "TransferWrongAuthority"
        );
        verify(domain, object, &self.config.consent.network).map_err(anyhow::Error::msg)
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
            "TransferStalePermission"
        );
        self.disk.floor(revision, epoch, generation, now)
    }
    pub async fn policy(&mut self) -> Result<()> {
        ensure!(
            store::now()? < self.config.consent.expires,
            "TransferConsentExpired"
        );
        let reply = self
            .request(types::Command::TransferPolicySync {
                host_key: self.config.consent.host_key.clone(),
            })
            .await?;
        let object: types::Envelope = serde_json::from_value(reply.result["policy"].clone())?;
        let policy: StorePolicy = self.evidence(POLICY, &object)?;
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
            policy.version == 1 && policy.transfers.len() <= 256,
            "TransferInvalidPermission"
        );
        let mut next = self.disk.state.clone();
        next.records.retain(|id, _| policy.transfers.contains(id));
        next.authority_revision = policy.authority_revision;
        next.authority_epoch = policy.authority_epoch;
        next.host_generation = policy.host_generation;
        next.time = now;
        self.disk.commit(next)
    }
    fn receipt(&self, id: &str, record: &Record, now: u64) -> Result<types::Envelope> {
        let receipt = StoreReceipt {
            version: 1,
            network: self.config.consent.network.clone(),
            host_key: self.config.consent.host_key.clone(),
            transfer_id: id.into(),
            offer_digest: record.offer_digest.clone(),
            payload_digest: record.payload_digest.clone(),
            payload_bytes: record.payload_bytes,
            stored_bytes: record.stored_bytes,
            status: record.status.clone(),
            recorded_at: now,
        };
        sign(
            RECEIPT,
            &self.config.consent.network,
            &receipt,
            &self.config.key,
        )
        .map_err(anyhow::Error::msg)
    }
    pub async fn execute(&mut self, request: StoreRequest) -> Result<Value> {
        let now = store::now()?;
        ensure!(now < self.config.consent.expires, "TransferConsentExpired");
        let op = authority::operation(&request.operation, &self.config.consent.network, now)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            op.host_key == self.config.consent.host_key,
            "TransferPermissionDenied"
        );
        let payload = match request.payload {
            Some(p) => Some(URL_SAFE_NO_PAD.decode(p)?),
            None => None,
        };
        if op.action == "Put" {
            let bytes = payload.as_ref().context("TransferInvalidObject")?;
            ensure!(
                bytes.len() as u64 == op.chunk_bytes && Some(hash(bytes)) == op.chunk_digest,
                "TransferInvalidObject"
            );
        } else {
            ensure!(payload.is_none(), "TransferInvalidObject");
        }
        let reply = self
            .request(types::Command::TransferAuthorise {
                host_key: self.config.consent.host_key.clone(),
                operation: request.operation.clone(),
            })
            .await?;
        let evidence: types::Envelope = serde_json::from_value(reply.result["permission"].clone())?;
        let permission: Permission = self.evidence(PERMISSION, &evidence)?;
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
                    == crate::mail_authority::object_digest(OPERATION, &request.operation)
                        .map_err(anyhow::Error::msg)?
                && permission.transfer.offer_digest == op.offer_digest
                && permission.transfer.body.transfer_id == op.transfer_id,
            "TransferInvalidPermission"
        );
        let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(permission.expires))
            .duration_since(std::time::SystemTime::now())
            .context("TransferStalePermission")?;
        let deadline = std::time::Instant::now() + remaining;
        let offer = &permission.transfer.body;
        let mut next = self.disk.state.clone();
        let previous = next.records.get(&op.transfer_id).cloned();
        let mut record = if let Some(existing) = &previous {
            existing.clone()
        } else {
            ensure!(next.records.len() < 256, "TransferQuotaExceeded");
            Record {
                offer_digest: op.offer_digest.clone(),
                payload_digest: offer.payload_digest.clone(),
                payload_bytes: offer.payload_bytes,
                payload: String::new(),
                stored_bytes: 0,
                status: "Staging".into(),
                receipt: request.operation.clone(),
            }
        };
        ensure!(
            record.offer_digest == op.offer_digest
                && record.payload_digest == offer.payload_digest
                && record.payload_bytes == offer.payload_bytes,
            "TransferConflict"
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(&record.payload)?;
        ensure!(
            bytes.len() as u64 == record.stored_bytes
                || (record.status == "Deleted" && bytes.is_empty()),
            "TransferCorruptState"
        );
        let mut fetched = None;
        match op.action.as_str() {
            "Status" => {}
            "Put" => {
                ensure!(record.status != "Deleted", "TransferDeleted");
                let chunk = payload.unwrap();
                if op.offset < record.stored_bytes {
                    let end = op
                        .offset
                        .checked_add(op.chunk_bytes)
                        .context("TransferConflict")?;
                    ensure!(
                        end <= record.stored_bytes
                            && bytes[op.offset as usize..end as usize] == chunk,
                        "TransferConflict"
                    );
                } else {
                    ensure!(
                        record.status == "Staging" && op.offset == record.stored_bytes,
                        "TransferOffsetConflict"
                    );
                    ensure!(
                        record.stored_bytes + op.chunk_bytes <= record.payload_bytes,
                        "TransferConflict"
                    );
                    bytes.extend(chunk);
                    record.stored_bytes = bytes.len() as u64;
                    record.payload = URL_SAFE_NO_PAD.encode(&bytes);
                }
            }
            "Commit" => {
                ensure!(record.status != "Deleted", "TransferDeleted");
                ensure!(
                    record.stored_bytes == record.payload_bytes
                        && hash(&bytes) == record.payload_digest,
                    "TransferIntegrityFailure"
                );
                record.status = "Complete".into();
            }
            "Fetch" => {
                ensure!(
                    record.status == "Complete" && hash(&bytes) == record.payload_digest,
                    "TransferIncomplete"
                );
                let end = op
                    .offset
                    .checked_add(op.chunk_bytes)
                    .context("TransferInvalidObject")?;
                ensure!(end <= record.stored_bytes, "TransferInvalidObject");
                fetched = Some(URL_SAFE_NO_PAD.encode(&bytes[op.offset as usize..end as usize]));
            }
            "Delete" => {
                record.status = "Deleted".into();
                record.payload.clear();
            }
            _ => bail!("TransferInvalidObject"),
        }
        if previous.as_ref().is_none_or(|old| {
            old.stored_bytes != record.stored_bytes || old.status != record.status
        }) {
            record.receipt = self.receipt(&op.transfer_id, &record, now)?;
        }
        let receipt = record.receipt.clone();
        next.records.insert(op.transfer_id, record);
        let used: u64 = next
            .records
            .values()
            .filter(|r| r.status != "Deleted")
            .map(|r| r.payload_bytes)
            .sum();
        ensure!(
            used <= self.config.consent.state_bytes / 4,
            "TransferQuotaExceeded"
        );
        next.authority_revision = permission.authority_revision;
        next.authority_epoch = permission.authority_epoch;
        next.host_generation = permission.host_generation;
        next.time = now;
        ensure!(
            std::time::Instant::now() < deadline,
            "TransferStalePermission"
        );
        self.disk.commit(next)?;
        // Fsync may outlast admission; recover an uncertain write through fresh Status.
        let finished = store::now()?;
        ensure!(
            std::time::Instant::now() < deadline
                && finished >= now
                && finished < permission.expires,
            "TransferStalePermission"
        );
        if let Some(payload) = fetched {
            Ok(json!({"receipt":receipt,"payload":payload,"offset":op.offset}))
        } else {
            Ok(json!({"receipt":receipt}))
        }
    }
}
