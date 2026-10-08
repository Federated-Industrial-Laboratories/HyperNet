// SPDX-License-Identifier: MIT
use crate::{authority, federation_authority, page_authority, protocol::VerifiedRequest, types::*};
use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use etcd_client::{
    Certificate, Client, Compare, CompareOp, ConnectOptions, GetOptions, Identity, TlsOptions, Txn,
    TxnOp,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Floor {
    network: String,
    cluster: u64,
    revision: i64,
    time: u64,
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Clock is before the Unix epoch")?
        .as_secs())
}

pub fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("File exceeds its permitted size");
    }
    Ok(bytes)
}

pub fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("Private file must be a regular file readable only by its owner");
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("Private file exceeds its permitted size");
    }
    Ok(bytes)
}

pub fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("State file needs a parent directory")?;
    let temporary = parent.join("AuthorityFloorPending.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub struct Store {
    client: Client,
    namespace: String,
    network: String,
    floor: Floor,
    floor_path: PathBuf,
    _lock: File,
    federation_signing_key: Option<SigningKey>,
}

impl Store {
    pub async fn connect(config: &AuthorityConfig) -> Result<Self> {
        let federation_signing_key = config
            .federation_signing_key
            .as_ref()
            .map(|path| -> Result<SigningKey> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields, rename_all = "camelCase")]
                struct Identity {
                    secret_key: String,
                    public_key: String,
                }
                let mut bytes = read_private(path, 4096)?;
                let parsed = serde_json::from_slice::<Identity>(&bytes);
                bytes.zeroize();
                let mut identity = parsed.context("Invalid federation signing identity")?;
                let parsed = crate::protocol::fixed_hex::<32>(&identity.secret_key);
                identity.secret_key.zeroize();
                let mut secret = parsed.map_err(anyhow::Error::msg)?;
                let key = SigningKey::from_bytes(&secret);
                secret.zeroize();
                if hex::encode(key.verifying_key().as_bytes()) != identity.public_key {
                    bail!("Federation signing identity mismatch");
                }
                Ok(key)
            })
            .transpose()?;
        crate::protocol::fixed_hex::<32>(&config.network).map_err(anyhow::Error::msg)?;
        if config.etcd_endpoints.len() < 3 || config.etcd_endpoints.len() > 7 {
            bail!("Configure three to seven authority voter endpoints");
        }
        let unique: std::collections::BTreeSet<_> = config.etcd_endpoints.iter().collect();
        if unique.len() != config.etcd_endpoints.len() {
            bail!("Authority endpoints must be distinct");
        }
        if config
            .etcd_endpoints
            .iter()
            .any(|endpoint| !endpoint.starts_with("https://"))
        {
            bail!("Authority voter endpoints require HTTPS");
        }
        fs::create_dir_all(&config.state_directory)?;
        let directory = fs::symlink_metadata(&config.state_directory)?;
        if !directory.is_dir() || directory.permissions().mode() & 0o077 != 0 {
            bail!("Authority state directory must be private");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(config.state_directory.join("Authority.lock"))?;
        use std::os::fd::AsRawFd;
        // One process owns the persistent rollback floor in this directory.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("Authority state directory is already in use");
        }
        let floor_path = config.state_directory.join("AuthorityFloor.json");
        let floor = match read_private(&floor_path, 4096) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("Invalid authority floor")?,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Floor::default()
            }
            Err(error) => return Err(error),
        };
        if floor.cluster != 0 && floor.network != config.network {
            bail!("Authority floor belongs to another network");
        }
        let tls = TlsOptions::new()
            .domain_name(&config.etcd_server_name)
            .ca_certificate(Certificate::from_pem(read_bounded(
                &config.etcd_ca,
                64 * 1024,
            )?))
            .identity(Identity::from_pem(
                read_bounded(&config.etcd_certificate, 64 * 1024)?,
                read_private(&config.etcd_key, 64 * 1024)?,
            ));
        let options = ConnectOptions::new()
            .with_tls(tls)
            .with_timeout(Duration::from_secs(3))
            .with_connect_timeout(Duration::from_secs(3))
            .with_require_leader(true);
        let mut client = Client::connect(&config.etcd_endpoints, Some(options))
            .await
            .context("Authority cluster is unavailable")?;
        let membership = client
            .member_list()
            .await
            .context("Cannot verify authority voter membership")?;
        let voters = membership
            .members()
            .iter()
            .filter(|member| !member.is_learner())
            .count();
        if !(3..=7).contains(&voters) || voters % 2 == 0 {
            bail!("The authority cluster requires three, five or seven voting members");
        }
        Ok(Self {
            client,
            namespace: format!("/HyperNet/{}/Authority", config.network),
            network: config.network.clone(),
            floor,
            floor_path,
            _lock: lock,
            federation_signing_key,
        })
    }

    fn accept_floor(&mut self, cluster: u64, revision: i64, time: u64) -> Result<()> {
        if cluster == 0 || revision <= 0 {
            bail!("Invalid authority identity or revision");
        }
        if self.floor.cluster != 0 && self.floor.cluster != cluster {
            bail!(
                "Authority cluster identity changed; establish a new network identity for disaster recovery"
            );
        }
        if revision < self.floor.revision {
            bail!("Authority revision moved backwards");
        }
        if self.floor.time > time.saturating_add(2) {
            bail!("Clock moved backwards");
        }
        self.floor = Floor {
            network: self.network.clone(),
            cluster,
            revision,
            time: time.max(self.floor.time),
        };
        atomic_private(&self.floor_path, &serde_json::to_vec(&self.floor)?)?;
        Ok(())
    }

    pub async fn initialise(&mut self, admin: &str) -> Result<()> {
        if self
            .federation_signing_key
            .as_ref()
            .is_some_and(|key| hex::encode(key.verifying_key().as_bytes()) == admin)
        {
            bail!("Federation signing key must be separate from membership");
        }
        let key = crate::protocol::fixed_hex::<32>(admin).map_err(anyhow::Error::msg)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .context("Invalid initial administrator key")?;
        if self.floor.cluster != 0 {
            bail!("This authority directory already has a network floor");
        }
        let now = now()?;
        let state = serde_json::to_vec(&State::initial(self.network.clone(), admin.into(), now))?;
        let response = self
            .client
            .txn(
                Txn::new()
                    .when([Compare::version(
                        self.namespace.as_str(),
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then([TxnOp::put(self.namespace.as_str(), state, None)]),
            )
            .await?;
        if !response.succeeded() {
            bail!("Network authority is already initialised");
        }
        let header = response
            .header()
            .context("Authority response has no header")?;
        self.accept_floor(header.cluster_id(), header.revision(), now)?;
        Ok(())
    }

    pub async fn health(&mut self) -> Result<()> {
        if self.floor.cluster == 0 {
            bail!("Authority floor is missing; provision it from the initialised healthy network");
        }
        let response = self.client.get(self.namespace.as_str(), None).await?;
        let header = response
            .header()
            .context("Authority response has no header")?;
        let kv = response
            .kvs()
            .first()
            .context("Network authority is not initialised")?;
        if kv.value().len() > MAX_STATE {
            bail!("Authority state exceeds its size bound");
        }
        let state: State = serde_json::from_slice(kv.value())?;
        if !(1..=4).contains(&state.version) || state.network != self.network {
            bail!("Authority state identity is invalid");
        }
        let now = now()?;
        if state.high_water_time > now.saturating_add(2) {
            bail!("Authority clock moved backwards");
        }
        self.accept_floor(header.cluster_id(), header.revision(), now)?;
        Ok(())
    }

    pub async fn execute(&mut self, request: &VerifiedRequest, certificate: Option<&str>) -> Reply {
        match self.transition(request, certificate).await {
            Ok(reply) => reply,
            Err(_) => Reply::error("AuthorityUnavailable"),
        }
    }

    async fn transition(
        &mut self,
        request: &VerifiedRequest,
        certificate: Option<&str>,
    ) -> Result<Reply> {
        for _ in 0..16 {
            let response = self.client.get(self.namespace.as_str(), None).await?;
            let header = response.header().context("Missing authority header")?;
            let now = now()?;
            if request.request.issued_at.saturating_add(60) < now
                || request.request.issued_at > now.saturating_add(30)
            {
                return Ok(Reply::error("StaleRequest"));
            }
            self.accept_floor(header.cluster_id(), header.revision(), now)?;
            let kv = response.kvs().first().context("Missing authority state")?;
            if kv.value().len() > MAX_STATE {
                bail!("Authority state exceeds its size bound");
            }
            let mut state: State = serde_json::from_slice(kv.value())?;
            if state.network != self.network {
                bail!("Authority network identity mismatch");
            }
            if let Command::Invite { device_key, .. } = &request.request.command
                && self
                    .federation_signing_key
                    .as_ref()
                    .is_some_and(|key| hex::encode(key.verifying_key().as_bytes()) == *device_key)
            {
                return Ok(Reply::error("DedicatedAuthorityKeyRequired"));
            }
            let mut operations = Vec::new();
            let reply = if page_authority::handles(&request.request.command) {
                if let Err(code) = page_authority::preflight(&state, request, certificate, now) {
                    return Ok(Reply::error(code));
                }
                let wanted = match page_authority::required_blobs(&state, request, now) {
                    Ok(keys) => keys,
                    Err(code) => return Ok(Reply::error(code)),
                };
                let prefix = format!("/HyperNet/{}/Pages/", self.network);
                let mut blobs = std::collections::BTreeMap::new();
                for key in wanted {
                    let fetched = self
                        .client
                        .get(
                            format!("{prefix}{key}"),
                            Some(GetOptions::new().with_revision(header.revision())),
                        )
                        .await?;
                    let fetched_header =
                        fetched.header().context("Missing page response header")?;
                    self.accept_floor(fetched_header.cluster_id(), fetched_header.revision(), now)?;
                    if let Some(value) = fetched.kvs().first() {
                        if value.value().len() > page_authority::MAX_BUNDLE {
                            bail!("Page object exceeds its bound");
                        }
                        blobs.insert(key, value.value().to_vec());
                    }
                }
                let change = match page_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    header.revision(),
                    &blobs,
                ) {
                    Ok(change) => change,
                    Err(code) => return Ok(Reply::error(code)),
                };
                for key in change.deletes {
                    operations.push(TxnOp::delete(format!("{prefix}{key}"), None));
                }
                for (key, value) in change.puts {
                    operations.push(TxnOp::put(format!("{prefix}{key}"), value, None));
                }
                change.reply
            } else if federation_authority::handles(&request.request.command) {
                if let Err(code) =
                    federation_authority::preflight(&state, request, certificate, now)
                {
                    return Ok(Reply::error(code));
                }
                let wanted = match federation_authority::required_blobs(&state, request, now) {
                    Ok(keys) => keys,
                    Err(code) => return Ok(Reply::error(code)),
                };
                let prefix = format!("/HyperNet/{}/Federation/", self.network);
                let mut blobs = std::collections::BTreeMap::new();
                for key in wanted {
                    let path = if let Some(native) = key.strip_prefix("Native/") {
                        format!("/HyperNet/{}/Pages/{native}", self.network)
                    } else {
                        format!("{prefix}{key}")
                    };
                    let fetched = self
                        .client
                        .get(
                            path,
                            Some(GetOptions::new().with_revision(header.revision())),
                        )
                        .await?;
                    let fetched_header = fetched
                        .header()
                        .context("Missing federation response header")?;
                    self.accept_floor(fetched_header.cluster_id(), fetched_header.revision(), now)?;
                    if let Some(value) = fetched.kvs().first() {
                        if value.value().len() > federation_authority::MAX_BLOB {
                            bail!("Federation object exceeds its bound");
                        }
                        blobs.insert(key, value.value().to_vec());
                    }
                }
                let change = match federation_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    header.revision(),
                    &blobs,
                    self.federation_signing_key.as_ref(),
                ) {
                    Ok(change) => change,
                    Err(code) => return Ok(Reply::error(code)),
                };
                for key in change.deletes {
                    operations.push(TxnOp::delete(format!("{prefix}{key}"), None));
                }
                for (key, value) in change.puts {
                    operations.push(TxnOp::put(format!("{prefix}{key}"), value, None));
                }
                change.reply
            } else {
                match authority::apply(&mut state, request, certificate, now, header.revision()) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
            };
            let bytes = serde_json::to_vec(&state)?;
            if bytes.len() > MAX_STATE {
                return Ok(Reply::error("CapacityExceeded"));
            }
            operations.push(TxnOp::put(self.namespace.as_str(), bytes, None));
            let transaction = self
                .client
                .txn(
                    Txn::new()
                        .when([Compare::mod_revision(
                            self.namespace.as_str(),
                            CompareOp::Equal,
                            kv.mod_revision(),
                        )])
                        .and_then(operations),
                )
                .await?;
            if transaction.succeeded() {
                let header = transaction.header().context("Missing transaction header")?;
                self.accept_floor(header.cluster_id(), header.revision(), now)?;
                return Ok(reply);
            }
        }
        Ok(Reply::error("AuthorityBusy"))
    }
}
