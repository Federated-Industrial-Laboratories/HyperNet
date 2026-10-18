// SPDX-License-Identifier: MIT
//! Exact local operator consent for an appointed authority workload.
use crate::{
    authority_files as files,
    consensus::runtime::Config,
    trust_bootstrap,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Resources {
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    pub generation: u64,
    pub previous_profile: Option<[u8; 32]>,
    pub previous_consent: Option<[u8; 32]>,
    pub version: u64,
    pub deployment: String,
    pub network: String,
    pub incarnation: String,
    pub operator: String,
    pub signer: String,
    pub bootstrap_digest: String,
    pub software_digest: String,
    pub image: String,
    pub created: u64,
    pub expires: u64,
    pub bind: Ipv4Addr,
    pub port: u16,
    pub subnet: Ipv4Addr,
    pub resources: Resources,
    pub config: Config,
    pub tls_digests: BTreeMap<String, String>,
    pub endpoint_leaves: BTreeMap<String, String>,
    pub session_policy: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Validated {
    pub manifest: Manifest,
    pub profile_digest: String,
    pub consent_digest: String,
    pub withdrawal_generation: u64,
}
fn id(value: &str) -> Result<V> {
    let bytes = trust_bootstrap::hex32(value)?;
    ensure!(
        bytes != [0; 32] && hex::encode(bytes) == value,
        "Noncanonical or zero runtime identifier"
    );
    Ok(V::Bytes(bytes.to_vec()))
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn path(value: &Path) -> Result<()> {
    ensure!(
        value.is_absolute()
            && value
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && value.as_os_str().len() <= 4096,
        "Runtime input must have a bounded absolute path without traversal"
    );
    Ok(())
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && matches!(self.session_policy.as_str(), "Session" | "Managed"),
            "Unsupported runtime manifest"
        );
        for value in [
            &self.deployment,
            &self.network,
            &self.incarnation,
            &self.operator,
            &self.signer,
            &self.bootstrap_digest,
            &self.software_digest,
        ] {
            id(value)?;
        }
        wire::valid_key(&trust_bootstrap::hex32(&self.operator)?)?;
        wire::valid_key(&trust_bootstrap::hex32(&self.signer)?)?;
        ensure!(
            self.operator != self.signer,
            "Operator and authority signer must be independent identities"
        );
        ensure!(
            self.created > 0
                && self.expires > self.created
                && self.expires - self.created <= 604800
                && self.expires <= u64::MAX / 1000,
            "Invalid finite consent interval"
        );
        let image = self
            .image
            .strip_prefix("sha256:")
            .context("An immutable local image digest is required")?;
        id(image)?;
        ensure!(
            !self.bind.is_multicast() && !self.bind.is_broadcast() && self.port != 0,
            "Invalid authority exposure"
        );
        ensure!(
            self.subnet.is_private() && self.subnet.octets()[3] == 0,
            "An explicit private IPv4 /24 subnet is required"
        );
        let r = &self.resources;
        ensure!(
            r.memory_bytes > 0
                && r.pids > 0
                && r.cpu_quota > 0
                && (1000..=1000000).contains(&r.cpu_period)
                && r.state_bytes >= 1024 * 1024 * 1024,
            "Finite positive workload resources are required"
        );
        ensure!(
            self.config.listen.port() == self.port,
            "Listener port differs from consent"
        );
        path(&self.config.control_socket)?;
        for p in [
            &self.config.tls.certificate,
            &self.config.tls.private_key,
            &self.config.tls.certificate_authority,
        ] {
            path(p)?;
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut origins = std::collections::BTreeSet::new();
        for peer in &self.config.peers {
            wire::valid_key(&peer.key)?;
            ensure!(
                keys.insert(peer.key) && peer.certificate_sha256 != [0; 32],
                "Repeated peer or missing TLS pin"
            );
            let url = reqwest::Url::parse(&peer.origin)?;
            let host = url
                .host_str()
                .context("Peer address is absent")?
                .trim_matches(['[', ']']);
            let address: std::net::IpAddr =
                host.parse().context("Peer requires a literal address")?;
            ensure!(
                !address.is_unspecified()
                    && !address.is_multicast()
                    && url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.port_or_known_default().is_some_and(|p| p != 0)
                    && origins.insert(url.to_string()),
                "Invalid or repeated pinned peer origin"
            );
        }
        ensure!(
            !keys.contains(&trust_bootstrap::hex32(&self.operator)?),
            "Operator must be independent of every authority voter"
        );
        ensure!(
            keys.contains(&trust_bootstrap::hex32(&self.signer)?),
            "Signer is not in the exact peer set"
        );
        match &self.config.clock {
            crate::authority_clock_handoff::Source::Signed {
                path: p,
                public_key,
                kernel_boot,
            } => {
                path(p)?;
                let key = trust_bootstrap::hex32(public_key)?;
                wire::valid_key(&key)?;
                ensure!(
                    !keys.contains(&key) && !kernel_boot.is_empty() && kernel_boot.len() <= 128,
                    "Clock requires an independent key and explicit host boot"
                );
            }
            crate::authority_clock_handoff::Source::Private { .. } => {
                anyhow::bail!("Runtime consent requires a signed clock witness")
            }
        }
        ensure!(
            self.tls_digests.keys().map(String::as_str).eq([
                "Authority.pem",
                "Certificate.pem",
                "PrivateKey.pem"
            ]),
            "Exact TLS input digest set required"
        );
        for digest in self.tls_digests.values() {
            id(digest)?;
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 65536,
            "Runtime manifest exceeds its input bound"
        );
        Ok(())
    }
    pub fn config_digest(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&self.config)?))
    }
    pub fn canonical(&self) -> Result<crate::runtime_manifest::Manifest> {
        use crate::runtime_manifest as m;
        self.validate()?;
        let parse = trust_bootstrap::hex32;
        let signer = parse(&self.signer)?;
        let deployment = parse(&self.deployment)?;
        let volume = wire::digest(format!("{}/ReplicaState", self.deployment).as_bytes());
        let mut endpoints = Vec::new();
        let mut ordered = Vec::new();
        ensure!(
            self.endpoint_leaves.len() == 4,
            "Exactly four pinned peer leaves are required"
        );
        for peer in &self.config.peers {
            let leaf = hex::decode(
                self.endpoint_leaves
                    .get(&hex::encode(peer.key))
                    .context("Peer leaf is absent")?,
            )?;
            ensure!(
                hash(&leaf) == hex::encode(peer.certificate_sha256),
                "Peer leaf differs from the configured TLS pin"
            );
            let url = reqwest::Url::parse(&peer.origin)?;
            let address = url
                .host_str()
                .context("Peer address is absent")?
                .trim_matches(['[', ']'])
                .parse()?;
            let port = url.port_or_known_default().context("Peer port is absent")?;
            let endpoint_id = wire::digest(&wire::encode(&V::Array(vec![
                V::Text("AuthorityEndpoint".into()),
                V::Bytes(peer.key.to_vec()),
            ]))?);
            ordered.push(endpoint_id);
            endpoints.push(m::Endpoint {
                endpoint_id,
                service_key: peer.key,
                address,
                port,
                transport_key: m::leaf_key(&leaf)?,
                leaf_der: leaf,
            });
        }
        endpoints.sort_by_key(|e| e.endpoint_id);
        let own = endpoints
            .iter()
            .find(|e| e.service_key == signer)
            .context("Own endpoint is absent")?;
        ensure!(
            own.address == std::net::IpAddr::V4(self.bind) && own.port == self.port,
            "Published endpoint differs from local consent"
        );
        let crate::authority_clock_handoff::Source::Signed {
            path,
            public_key,
            kernel_boot,
        } = &self.config.clock
        else {
            anyhow::bail!("Signed clock required")
        };
        ensure!(
            path.parent() == Some(Path::new("/Clock"))
                && self.config.control_socket == Path::new("/State/Control/Control.sock")
                && self.config.tls.certificate == Path::new("/Config/Tls/Certificate.pem")
                && self.config.tls.private_key == Path::new("/Config/Tls/PrivateKey.pem")
                && self.config.tls.certificate_authority == Path::new("/Config/Tls/Authority.pem"),
            "Runtime requires fixed credential and state handles"
        );
        let r = &self.resources;
        let mut outbound = ordered.clone();
        outbound.sort();
        let manifest = m::Manifest {
            generation: self.generation,
            previous_profile: self.previous_profile,
            previous_consent: self.previous_consent,
            network: parse(&self.network)?,
            incarnation: parse(&self.incarnation)?,
            deployment,
            host: deployment,
            operator: parse(&self.operator)?,
            bootstrap_digest: parse(&self.bootstrap_digest)?,
            software_digest: parse(&self.software_digest)?,
            validity: (self.created * 1000, self.expires * 1000),
            session_mode: u64::from(self.session_policy == "Managed"),
            roles: vec![m::Role {
                role: 0,
                service_key: signer,
                image_digest: parse(
                    self.image
                        .strip_prefix("sha256:")
                        .context("Image digest required")?,
                )?,
                memory_bytes: r.memory_bytes,
                pids: r.pids,
                cpu_quota: r.cpu_quota,
                cpu_period: r.cpu_period,
                state_admission_bytes: r.state_bytes,
                bind_endpoint_ids: vec![own.endpoint_id],
                outbound_endpoint_ids: outbound,
                volume_ids: vec![volume],
            }],
            volumes: vec![m::Volume {
                volume_id: volume,
                read_only: false,
                storage_admission_bytes: r.state_bytes,
            }],
            endpoints,
            clock: m::Clock {
                monitor_key: parse(public_key)?,
                kernel_boot: kernel_boot.clone(),
                witness_file_name: path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .context("Clock filename required")?
                    .into(),
                maximum_error_ms: 250,
                maximum_observation_age_ms: 1000,
            },
            placement: m::Placement {
                hosts: vec![deployment],
                volumes: vec![volume],
                backups: vec![],
                copies: 1,
            },
            limits: [
                crate::consensus::storage::MAX_BYTES,
                crate::consensus::storage::MAX_OBJECTS as u64,
                16,
                crate::consensus::runtime::MAX_PENDING as u64,
            ],
            consent_policy: m::ConsentPolicy {
                allow_opaque: false,
                reviewer_roots: vec![],
            },
            authority_config: Some(m::AuthorityConfig {
                listen_address: self.config.listen.ip(),
                listen_port: self.config.listen.port(),
                ordered_peer_endpoint_ids: ordered,
                tls_file_digests: [
                    parse(&self.tls_digests["Authority.pem"])?,
                    parse(&self.tls_digests["Certificate.pem"])?,
                    parse(&self.tls_digests["PrivateKey.pem"])?,
                ],
                subnet_address: self.subnet.into(),
                subnet_prefix: 24,
            }),
        };
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn from_canonical(manifest: crate::runtime_manifest::Manifest) -> Result<Self> {
        use crate::consensus::peer::{Credentials, Endpoint};
        manifest.validate()?;
        ensure!(
            manifest.roles.len() == 1
                && manifest.roles[0].role == 0
                && manifest.validity.0.is_multiple_of(1000)
                && manifest.validity.1.is_multiple_of(1000),
            "Installed authority requires one exact role and whole-second consent"
        );
        let role = &manifest.roles[0];
        let c = manifest
            .authority_config
            .as_ref()
            .context("Authority configuration absent")?;
        let own = manifest
            .endpoints
            .iter()
            .find(|e| e.endpoint_id == role.bind_endpoint_ids[0])
            .context("Owned endpoint absent")?;
        let std::net::IpAddr::V4(bind) = own.address else {
            anyhow::bail!("Installed bind requires IPv4")
        };
        let std::net::IpAddr::V4(subnet) = c.subnet_address else {
            anyhow::bail!("Installed subnet requires IPv4")
        };
        let peers = c
            .ordered_peer_endpoint_ids
            .iter()
            .map(|id| {
                let e = manifest
                    .endpoints
                    .iter()
                    .find(|e| e.endpoint_id == *id)
                    .unwrap();
                Endpoint {
                    key: e.service_key,
                    origin: format!("https://{}/", std::net::SocketAddr::new(e.address, e.port)),
                    certificate_sha256: sha2::Sha256::digest(&e.leaf_der).into(),
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Four peers required"))?;
        let result = Self {
            generation: manifest.generation,
            previous_profile: manifest.previous_profile,
            previous_consent: manifest.previous_consent,
            version: 1,
            deployment: hex::encode(manifest.deployment),
            network: hex::encode(manifest.network),
            incarnation: hex::encode(manifest.incarnation),
            operator: hex::encode(manifest.operator),
            signer: hex::encode(role.service_key),
            bootstrap_digest: hex::encode(manifest.bootstrap_digest),
            software_digest: hex::encode(manifest.software_digest),
            image: format!("sha256:{}", hex::encode(role.image_digest)),
            created: manifest.validity.0 / 1000,
            expires: manifest.validity.1 / 1000,
            bind,
            port: own.port,
            subnet,
            resources: Resources {
                memory_bytes: role.memory_bytes,
                pids: role.pids,
                cpu_quota: role.cpu_quota,
                cpu_period: role.cpu_period,
                state_bytes: role.state_admission_bytes,
            },
            config: Config {
                listen: std::net::SocketAddr::new(c.listen_address, c.listen_port),
                peers,
                tls: Credentials {
                    certificate: "/Config/Tls/Certificate.pem".into(),
                    private_key: "/Config/Tls/PrivateKey.pem".into(),
                    certificate_authority: "/Config/Tls/Authority.pem".into(),
                },
                clock: crate::authority_clock_handoff::Source::Signed {
                    path: Path::new("/Clock").join(&manifest.clock.witness_file_name),
                    public_key: hex::encode(manifest.clock.monitor_key),
                    kernel_boot: manifest.clock.kernel_boot.clone(),
                },
                control_socket: "/State/Control/Control.sock".into(),
            },
            tls_digests: ["Authority.pem", "Certificate.pem", "PrivateKey.pem"]
                .into_iter()
                .zip(c.tls_file_digests.iter().map(hex::encode))
                .map(|(name, digest)| (name.into(), digest))
                .collect(),
            endpoint_leaves: manifest
                .endpoints
                .iter()
                .map(|e| (hex::encode(e.service_key), hex::encode(&e.leaf_der)))
                .collect(),
            session_policy: if manifest.session_mode == 1 {
                "Managed"
            } else {
                "Session"
            }
            .into(),
        };
        ensure!(
            result.canonical()? == manifest,
            "Installed manifest contains unsupported resource semantics"
        );
        Ok(result)
    }
    /// Prospective consent grants no vote; installation must also prove the committed nomination.
    pub fn verify_future_bootstrap(
        &self,
        verified: &crate::trust_bootstrap::Verified,
    ) -> Result<()> {
        let canonical = self.canonical()?;
        ensure!(
            verified.fully_accepted()
                && verified.summary.network == self.network
                && verified.summary.incarnation == self.incarnation,
            "Future authority bootstrap context differs"
        );
        for endpoint in &canonical.endpoints {
            ensure!(
                !verified
                    .reservations()
                    .iter()
                    .any(|(_, key)| *key == endpoint.service_key || *key == endpoint.transport_key),
                "Future authority reuses an initial dedicated identity"
            );
        }
        ensure!(
            verified
                .summary
                .clock_monitors
                .contains(&hex::encode(canonical.clock.monitor_key)),
            "Future authority clock monitor lacks authenticated bootstrap reservation"
        );
        Ok(())
    }
    pub fn verify_bootstrap(&self, verified: &crate::trust_bootstrap::Verified) -> Result<()> {
        let canonical = self.canonical()?;
        ensure!(
            verified.summary.network == self.network
                && verified.summary.incarnation == self.incarnation,
            "Manifest bootstrap context differs"
        );
        for endpoint in &canonical.endpoints {
            ensure!(
                verified
                    .summary
                    .authority_transports
                    .get(&hex::encode(endpoint.service_key))
                    == Some(&hex::encode(endpoint.transport_key)),
                "Manifest authority transport differs from its authenticated bootstrap reservation"
            );
        }
        ensure!(
            verified
                .summary
                .clock_monitors
                .contains(&hex::encode(canonical.clock.monitor_key)),
            "Manifest clock monitor lacks an authenticated bootstrap reservation"
        );
        Ok(())
    }
    pub fn read(directory: &Path) -> Result<Self> {
        Self::from_canonical(crate::runtime_manifest::Manifest::parse(&public_read(
            &directory.join("Manifest.cbor"),
            crate::runtime_manifest::MAXIMUM,
        )?)?)
    }
    pub fn desired(&self) -> Result<Vec<u8>> {
        self.canonical()?.desired()
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(wire::digest(&self.desired()?)))
    }
    pub fn consent(&self, withdrawal_generation: u64) -> Result<Vec<u8>> {
        self.canonical()?.unsigned_consent(withdrawal_generation)
    }
}
pub fn public_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::{
        ffi::CString,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    let parent = files::directory(path.parent().context("Authorization parent is absent")?)?;
    ensure!(
        parent.metadata()?.mode() & 0o022 == 0,
        "Authorization directory is writable by another user"
    );
    let name = CString::new(
        path.file_name()
            .context("Authorization filename is absent")?
            .as_bytes(),
    )?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "Cannot safely read authorization artifact: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= maximum as u64,
        "Unsafe or oversized authorization artifact"
    );
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "Authorization artifact grew beyond its bound"
    );
    Ok(bytes)
}
pub fn verify(
    directory: &Path,
    expected_config_digest: &str,
    expected_signer: &str,
    expected_bootstrap_digest: &str,
) -> Result<Validated> {
    path(directory)?;
    let manifest = Manifest::read(directory)?;
    manifest.validate()?;
    ensure!(
        manifest.config_digest()? == expected_config_digest
            && manifest.signer == expected_signer
            && manifest.bootstrap_digest == expected_bootstrap_digest,
        "Consent does not bind this replica"
    );
    let desired = public_read(&directory.join("DesiredProfile.cbor"), wire::MAXIMUM)?;
    ensure!(
        desired == manifest.desired()?,
        "Desired profile differs from the manifest"
    );
    let withdrawal_generation: u64 =
        serde_json::from_slice(&public_read(&directory.join("Withdrawal.json"), 64)?)?;
    ensure!(
        withdrawal_generation == 0,
        "Local hosting consent has been withdrawn"
    );
    let signed = public_read(&directory.join("Consent.cbor"), wire::MAXIMUM)?;
    let (payload, signatures) = wire::envelope(&signed, 1)?;
    ensure!(
        signatures[0].0 == trust_bootstrap::hex32(&manifest.operator)?
            && payload == manifest.consent(withdrawal_generation)?,
        "Hosting consent signature or exact profile differs"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        now >= manifest.created && now < manifest.expires,
        "Hosting consent is outside its validity interval"
    );
    Ok(Validated {
        profile_digest: hex::encode(wire::digest(&desired)),
        consent_digest: hex::encode(wire::digest(&payload)),
        withdrawal_generation,
        manifest,
    })
}
