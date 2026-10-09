// SPDX-License-Identifier: MIT
use crate::{
    authority, federation_authority, mail_authority, page_authority, protocol::VerifiedRequest,
    types::*,
};
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
    clients: Vec<Client>,
    active_endpoint: usize,
    namespace: String,
    network: String,
    floor: Floor,
    floor_path: PathBuf,
    _lock: File,
    federation_signing_key: Option<SigningKey>,
    mail_signing_key: Option<SigningKey>,
    service_signing_key: Option<SigningKey>,
    page_media_signing_key: Option<SigningKey>,
}

fn load_signing_key(path: &Option<PathBuf>) -> Result<Option<SigningKey>> {
    path.as_ref()
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
            let mut identity = parsed.context("Invalid mail or federation signing identity")?;
            let parsed = crate::protocol::fixed_hex::<32>(&identity.secret_key);
            identity.secret_key.zeroize();
            let mut secret = parsed.map_err(anyhow::Error::msg)?;
            let key = SigningKey::from_bytes(&secret);
            secret.zeroize();
            if hex::encode(key.verifying_key().as_bytes()) != identity.public_key {
                bail!("Authority signing identity mismatch");
            }
            Ok(key)
        })
        .transpose()
}

impl Store {
    pub async fn connect(config: &AuthorityConfig) -> Result<Self> {
        let federation_signing_key = load_signing_key(&config.federation_signing_key)?;
        let mail_signing_key = load_signing_key(&config.mail_signing_key)?;
        let service_signing_key = load_signing_key(&config.service_signing_key)?;
        let page_media_signing_key = load_signing_key(&config.page_media_signing_key)?;
        if let Some(media) = &page_media_signing_key {
            for other in [
                &federation_signing_key,
                &mail_signing_key,
                &service_signing_key,
            ]
            .into_iter()
            .flatten()
            {
                if media.verifying_key() == other.verifying_key() {
                    bail!("Page media requires a dedicated signing identity");
                }
            }
        }
        if let Some(service) = &service_signing_key {
            for key in [&mail_signing_key, &federation_signing_key]
                .into_iter()
                .flatten()
            {
                if service.verifying_key() == key.verifying_key() {
                    bail!("Service signing key must be dedicated");
                }
            }
        }
        if let (Some(a), Some(b)) = (&federation_signing_key, &mail_signing_key)
            && a.verifying_key() == b.verifying_key()
        {
            bail!("Mail and federation require separate signing identities");
        }
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
        // Independent channels make transport failover deterministic. A balanced channel
        // may repeatedly select a voter which has stopped accepting connections.
        let mut clients = Vec::new();
        for endpoint in &config.etcd_endpoints {
            clients.push(Client::connect([endpoint], Some(options.clone())).await?);
        }
        let mut selected = None;
        for (index, client) in clients.iter_mut().enumerate() {
            if let Ok(membership) = client.member_list().await {
                selected = Some((index, membership));
                break;
            }
        }
        let (active_endpoint, membership) =
            selected.context("Cannot verify authority voter membership")?;
        let client = clients[active_endpoint].clone();
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
            clients,
            active_endpoint,
            namespace: format!("/HyperNet/{}/Authority", config.network),
            network: config.network.clone(),
            floor,
            floor_path,
            _lock: lock,
            federation_signing_key,
            mail_signing_key,
            service_signing_key,
            page_media_signing_key,
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
        if [
            &self.federation_signing_key,
            &self.mail_signing_key,
            &self.service_signing_key,
            &self.page_media_signing_key,
        ]
        .iter()
        .any(|signer| {
            signer
                .as_ref()
                .is_some_and(|key| hex::encode(key.verifying_key().as_bytes()) == admin)
        }) {
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

    fn next_endpoint(&mut self) {
        self.active_endpoint = (self.active_endpoint + 1) % self.clients.len();
        self.client = self.clients[self.active_endpoint].clone();
    }

    pub async fn health(&mut self) -> Result<()> {
        for attempt in 0..self.clients.len() {
            match self.health_once().await {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.downcast_ref::<etcd_client::Error>().is_some()
                        && attempt + 1 < self.clients.len() =>
                {
                    self.next_endpoint()
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!()
    }

    async fn health_once(&mut self) -> Result<()> {
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
        if state.version != crate::types::STATE_VERSION || state.network != self.network {
            bail!("Authority state identity is invalid");
        }
        for signer in [
            &self.federation_signing_key,
            &self.mail_signing_key,
            &self.service_signing_key,
            &self.page_media_signing_key,
        ]
        .into_iter()
        .flatten()
        {
            if mail_authority::reserved_identity_conflict(
                &state,
                &hex::encode(signer.verifying_key().as_bytes()),
            ) {
                bail!(
                    "Authority signing identities must be separate from membership and mail keys"
                );
            }
        }
        let now = now()?;
        if state.high_water_time > now.saturating_add(2) {
            bail!("Authority clock moved backwards");
        }
        self.accept_floor(header.cluster_id(), header.revision(), now)?;
        Ok(())
    }

    pub async fn execute(&mut self, request: &VerifiedRequest, certificate: Option<&str>) -> Reply {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(7);
        for attempt in 0..self.clients.len() {
            let operation = async {
                if mail_authority::read_only(&request.request.command)
                    || crate::media_authority::read_only(&request.request.command)
                    || crate::transfer_authority::read_only(&request.request.command)
                    || crate::ssh_authority::read_only(&request.request.command)
                {
                    self.mail_read_only(request, certificate).await
                } else {
                    self.transition(request, certificate).await
                }
            };
            let attempt_deadline =
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(2));
            match tokio::time::timeout_at(attempt_deadline, operation).await {
                Ok(Ok(reply)) => return reply,
                Ok(Err(error))
                    if error.downcast_ref::<etcd_client::Error>().is_some()
                        && attempt + 1 < self.clients.len() =>
                {
                    self.next_endpoint()
                }
                Err(_)
                    if attempt + 1 < self.clients.len()
                        && tokio::time::Instant::now() < deadline =>
                {
                    self.next_endpoint()
                }
                _ => return Reply::error("AuthorityUnavailable"),
            }
        }
        Reply::error("AuthorityUnavailable")
    }

    async fn mail_read_only(
        &mut self,
        request: &VerifiedRequest,
        certificate: Option<&str>,
    ) -> Result<Reply> {
        let response = self.client.get(self.namespace.as_str(), None).await?;
        let header = response.header().context("Missing authority header")?;
        let current = now()?;
        if request.request.issued_at.saturating_add(60) < current
            || request.request.issued_at > current.saturating_add(30)
        {
            return Ok(Reply::error("StaleRequest"));
        }
        self.accept_floor(header.cluster_id(), header.revision(), current)?;
        let kv = response.kvs().first().context("Missing authority state")?;
        if kv.value().len() > MAX_STATE {
            bail!("Authority state exceeds its size bound");
        }
        let state: State = serde_json::from_slice(kv.value())?;
        if state.network != self.network {
            bail!("Authority network mismatch");
        }
        if let Err(code) = crate::application_authority::admit(&state, request) {
            return Ok(Reply::error(code));
        }
        if crate::media_authority::read_only(&request.request.command) {
            return Ok(crate::media_authority::authorise(
                &state,
                request,
                certificate,
                current,
                header.revision(),
                self.page_media_signing_key.as_ref(),
            )
            .unwrap_or_else(Reply::error));
        }
        if crate::transfer_authority::read_only(&request.request.command) {
            return Ok(crate::transfer_authority::authorise(
                &state,
                request,
                certificate,
                current,
                header.revision(),
                self.service_signing_key.as_ref(),
            )
            .unwrap_or_else(Reply::error));
        }
        if crate::ssh_authority::read_only(&request.request.command) {
            return Ok(crate::ssh_authority::authorise(
                &state,
                request,
                certificate,
                current,
                header.revision(),
                self.service_signing_key.as_ref(),
            )
            .unwrap_or_else(Reply::error));
        }
        Ok(
            match mail_authority::authorise(
                &state,
                request,
                certificate,
                current,
                header.revision(),
                self.mail_signing_key.as_ref(),
            ) {
                Ok(reply) => reply,
                Err(code) => Reply::error(code),
            },
        )
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
            if let Err(code) = crate::application_authority::admit(&state, request) {
                return Ok(Reply::error(code));
            }
            let application_key =
                if let Command::ApplicationGrantCreate { consent } = &request.request.command {
                    Some(consent.public_key.as_str())
                } else {
                    None
                };
            if application_key.is_some_and(|candidate| {
                [
                    &self.federation_signing_key,
                    &self.mail_signing_key,
                    &self.service_signing_key,
                    &self.page_media_signing_key,
                ]
                .into_iter()
                .flatten()
                .any(|key| hex::encode(key.verifying_key().as_bytes()) == candidate)
            }) {
                return Ok(Reply::error("DedicatedAuthorityKeyRequired"));
            }
            let membership_key = match &request.request.command {
                Command::Invite { device_key, .. } | Command::Grant { device_key, .. } => {
                    Some(device_key.as_str())
                }
                Command::Redeem { .. } => Some(request.key.as_str()),
                _ => None,
            };
            if membership_key.is_some_and(|candidate| {
                [
                    &self.federation_signing_key,
                    &self.mail_signing_key,
                    &self.service_signing_key,
                    &self.page_media_signing_key,
                ]
                .into_iter()
                .flatten()
                .any(|key| hex::encode(key.verifying_key().as_bytes()) == candidate)
            }) {
                return Ok(Reply::error("DedicatedAuthorityKeyRequired"));
            }
            if let Command::MailAddressCreate { manifest }
            | Command::MailAddressUpdate { manifest, .. } = &request.request.command
            {
                let value = match mail_authority::manifest(manifest, &state.network) {
                    Ok(value) => value,
                    Err(code) => return Ok(Reply::error(code)),
                };
                for signer in [
                    &self.federation_signing_key,
                    &self.mail_signing_key,
                    &self.service_signing_key,
                    &self.page_media_signing_key,
                ]
                .into_iter()
                .flatten()
                {
                    let public = hex::encode(signer.verifying_key().as_bytes());
                    if value.owner_key == public
                        || value.devices.iter().any(|device| {
                            device.request_key == public || device.mls_signature_key == public
                        })
                    {
                        return Ok(Reply::error("DedicatedAuthorityKeyRequired"));
                    }
                }
            }
            let native_key = match &request.request.command {
                Command::SshServiceRegister { consent } => {
                    crate::ssh_authority::consent(consent, &state.network)
                        .and_then(|c| crate::ssh_authority::public_key(&c.ssh_host_key))
                        .ok()
                }
                Command::SshGrantCreate { ssh_public_key, .. } => {
                    crate::ssh_authority::public_key(ssh_public_key).ok()
                }
                Command::SshGrantAccept { grant_id } => {
                    state.ssh.grants.get(grant_id).and_then(|grant| {
                        crate::ssh_authority::public_key(&grant.ssh_public_key).ok()
                    })
                }
                _ => None,
            };
            if native_key.is_some_and(|candidate| {
                [
                    &self.federation_signing_key,
                    &self.mail_signing_key,
                    &self.service_signing_key,
                    &self.page_media_signing_key,
                ]
                .into_iter()
                .flatten()
                .any(|k| hex::encode(k.verifying_key().as_bytes()) == candidate)
            }) {
                return Ok(Reply::error("DedicatedAuthorityKeyRequired"));
            }
            let mut operations = Vec::new();
            let reply = if crate::application_authority::handles(&request.request.command) {
                match crate::application_authority::apply(
                    &mut state,
                    request,
                    now,
                    header.revision(),
                ) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
            } else if page_authority::handles(&request.request.command) {
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
            } else if crate::media_authority::handles(&request.request.command) {
                match crate::media_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    header.revision(),
                    self.page_media_signing_key.as_ref(),
                ) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
            } else if crate::transfer_authority::handles(&request.request.command) {
                match crate::transfer_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    self.service_signing_key.as_ref(),
                ) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
            } else if crate::ssh_authority::handles(&request.request.command) {
                match crate::ssh_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    self.service_signing_key.as_ref(),
                ) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
            } else if mail_authority::handles(&request.request.command) {
                match mail_authority::apply(
                    &mut state,
                    request,
                    certificate,
                    now,
                    header.revision(),
                    self.mail_signing_key.as_ref(),
                ) {
                    Ok(reply) => reply,
                    Err(code) => return Ok(Reply::error(code)),
                }
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
            if matches!(request.request.command, Command::PageReview { .. }) {
                // Recheck the signed decision deadline immediately before the compare-and-swap.
                if let Err(code) =
                    page_authority::preflight(&state, request, certificate, crate::store::now()?)
                {
                    return Ok(Reply::error(code));
                }
            }
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
