// SPDX-License-Identifier: MIT
//! Canonical deployment resources shared by consent, admission and local activation.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
pub type Key = [u8; 32];
pub const MAXIMUM: usize = 48 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Role {
    pub role: u64,
    pub service_key: Key,
    pub image_digest: Key,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_admission_bytes: u64,
    pub bind_endpoint_ids: Vec<Key>,
    pub outbound_endpoint_ids: Vec<Key>,
    pub volume_ids: Vec<Key>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Volume {
    pub volume_id: Key,
    pub read_only: bool,
    pub storage_admission_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub endpoint_id: Key,
    pub service_key: Key,
    pub address: IpAddr,
    pub port: u16,
    pub transport_key: Key,
    pub leaf_der: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Clock {
    pub monitor_key: Key,
    pub kernel_boot: String,
    pub witness_file_name: String,
    pub maximum_error_ms: u64,
    pub maximum_observation_age_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Placement {
    pub hosts: Vec<Key>,
    pub volumes: Vec<Key>,
    pub backups: Vec<Key>,
    pub copies: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentPolicy {
    pub allow_opaque: bool,
    pub reviewer_roots: Vec<Key>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfig {
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub ordered_peer_endpoint_ids: Vec<Key>,
    pub tls_file_digests: [Key; 3],
    pub subnet_address: IpAddr,
    pub subnet_prefix: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub generation: u64,
    pub previous_profile: Option<Key>,
    pub previous_consent: Option<Key>,
    pub network: Key,
    pub incarnation: Key,
    pub deployment: Key,
    pub host: Key,
    pub operator: Key,
    pub bootstrap_digest: Key,
    pub software_digest: Key,
    pub validity: (u64, u64),
    pub session_mode: u64,
    pub roles: Vec<Role>,
    pub volumes: Vec<Volume>,
    pub endpoints: Vec<Endpoint>,
    pub clock: Clock,
    pub placement: Placement,
    pub limits: [u64; 4],
    pub consent_policy: ConsentPolicy,
    pub authority_config: Option<AuthorityConfig>,
}
fn b(key: &Key) -> V {
    V::Bytes(key.to_vec())
}
fn a(values: impl IntoIterator<Item = V>) -> V {
    V::Array(values.into_iter().collect())
}
fn ids(keys: &[Key]) -> V {
    a(keys.iter().map(b))
}
fn key(value: &V) -> Result<Key> {
    let key = value.fixed::<32>()?;
    ensure!(key != [0; 32], "Zero manifest identifier");
    Ok(key)
}
fn keys(value: &V) -> Result<Vec<Key>> {
    value.list(16)?.iter().map(key).collect()
}
fn sorted<T: Ord>(values: &[T]) -> Result<()> {
    ensure!(
        values.windows(2).all(|v| v[0] < v[1]),
        "Unsorted or repeated manifest entry"
    );
    Ok(())
}
fn valid_ids(values: &[Key], maximum: usize) -> Result<()> {
    ensure!(
        values.len() <= maximum && !values.contains(&[0; 32]),
        "Invalid manifest identifier set"
    );
    sorted(values)
}
fn address(family: &V, value: &V) -> Result<IpAddr> {
    Ok(match family.uint()? {
        4 => IpAddr::V4(Ipv4Addr::from(value.fixed::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(value.fixed::<16>()?)),
        _ => anyhow::bail!("Unsupported literal address family"),
    })
}
fn address_values(value: IpAddr) -> [V; 2] {
    match value {
        IpAddr::V4(ip) => [V::Uint(4), V::Bytes(ip.octets().to_vec())],
        IpAddr::V6(ip) => [V::Uint(6), V::Bytes(ip.octets().to_vec())],
    }
}
pub fn leaf_key(leaf: &[u8]) -> Result<Key> {
    ensure!(
        !leaf.is_empty() && leaf.len() <= 4096,
        "TLS leaf exceeds its certificate bound"
    );
    let certificate = rustls::pki_types::CertificateDer::from(leaf);
    let parsed = rustls::server::ParsedCertificate::try_from(&certificate)?;
    let spki = parsed.subject_public_key_info();
    // RFC 8410 encodes Ed25519 without algorithm parameters.
    const PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    ensure!(
        spki.as_ref().len() == 44 && spki.as_ref().starts_with(PREFIX),
        "Transport certificate must contain an exact Ed25519 public key"
    );
    let public = spki.as_ref()[12..].try_into()?;
    wire::valid_key(&public)?;
    Ok(public)
}
impl Manifest {
    pub fn services(&self) -> BTreeMap<u64, Key> {
        self.roles.iter().map(|r| (r.role, r.service_key)).collect()
    }
    pub fn owned_transports(&self) -> Result<BTreeMap<Key, Key>> {
        let mut result = BTreeMap::new();
        for role in &self.roles {
            for id in &role.bind_endpoint_ids {
                let endpoint = self
                    .endpoints
                    .iter()
                    .find(|e| e.endpoint_id == *id)
                    .ok_or_else(|| anyhow::anyhow!("Missing owned endpoint"))?;
                if let Some(prior) = result.insert(role.service_key, endpoint.transport_key) {
                    ensure!(
                        prior == endpoint.transport_key,
                        "One service must retain one transport identity"
                    );
                }
            }
        }
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            [
                self.network,
                self.incarnation,
                self.deployment,
                self.host,
                self.bootstrap_digest,
                self.software_digest
            ]
            .iter()
            .all(|id| *id != [0; 32]),
            "Zero manifest identity or digest"
        );
        ensure!(
            self.generation > 0
                && ((self.generation == 1
                    && self.previous_profile.is_none()
                    && self.previous_consent.is_none())
                    || (self.generation > 1
                        && self.previous_profile.is_some_and(|v| v != [0; 32])
                        && self.previous_consent.is_some_and(|v| v != [0; 32]))),
            "Manifest successor generation or predecessor differs"
        );
        wire::valid_key(&self.operator)?;
        wire::valid_key(&self.clock.monitor_key)?;
        ensure!(
            self.network != self.incarnation && self.operator != self.clock.monitor_key,
            "Overlapping manifest identities"
        );
        ensure!(
            self.session_mode <= 1
                && (self.clock.kernel_boot == "CurrentHost") == (self.session_mode == 1)
                && self.validity.0 > 0
                && self.validity.1 > self.validity.0
                && self.validity.1 - self.validity.0 <= 604800000,
            "Invalid finite session consent"
        );
        ensure!(
            (1..=9).contains(&self.roles.len())
                && self.volumes.len() <= 16
                && self.endpoints.len() <= 16,
            "Manifest resource count exceeds bound"
        );
        sorted(&self.roles.iter().map(|r| r.role).collect::<Vec<_>>())?;
        sorted(&self.volumes.iter().map(|v| v.volume_id).collect::<Vec<_>>())?;
        sorted(
            &self
                .endpoints
                .iter()
                .map(|e| e.endpoint_id)
                .collect::<Vec<_>>(),
        )?;
        let services = self
            .roles
            .iter()
            .map(|r| r.service_key)
            .collect::<BTreeSet<_>>();
        ensure!(
            services.len() == self.roles.len()
                && !services.contains(&self.operator)
                && !services.contains(&self.clock.monitor_key),
            "Overlapping local service identity"
        );
        let mut used_endpoints = BTreeSet::new();
        let mut used_volumes = BTreeSet::new();
        let mut binds = BTreeSet::new();
        for role in &self.roles {
            wire::valid_key(&role.service_key)?;
            ensure!(
                role.role <= 8
                    && role.image_digest != [0; 32]
                    && role.memory_bytes > 0
                    && role.pids > 0
                    && role.cpu_quota > 0
                    && (1000..=1000000).contains(&role.cpu_period)
                    && role.state_admission_bytes > 0,
                "Invalid role resource admission"
            );
            for list in [
                &role.bind_endpoint_ids,
                &role.outbound_endpoint_ids,
                &role.volume_ids,
            ] {
                valid_ids(list, 16)?;
            }
            for id in &role.bind_endpoint_ids {
                let endpoint = self
                    .endpoints
                    .iter()
                    .find(|e| e.endpoint_id == *id)
                    .ok_or_else(|| anyhow::anyhow!("Unknown bind endpoint"))?;
                ensure!(
                    endpoint.service_key == role.service_key && binds.insert(*id),
                    "Bind endpoint is not owned by this role"
                );
                used_endpoints.insert(*id);
            }
            for id in &role.outbound_endpoint_ids {
                used_endpoints.insert(*id);
            }
            for id in &role.volume_ids {
                used_volumes.insert(*id);
            }
        }
        ensure!(
            used_endpoints == self.endpoints.iter().map(|e| e.endpoint_id).collect()
                && used_volumes == self.volumes.iter().map(|v| v.volume_id).collect(),
            "Undeclared or unused manifest resource"
        );
        for volume in &self.volumes {
            ensure!(
                volume.volume_id != [0; 32] && volume.storage_admission_bytes > 0,
                "Invalid volume admission"
            );
        }
        let mut transport_services = BTreeMap::new();
        for endpoint in &self.endpoints {
            wire::valid_key(&endpoint.service_key)?;
            wire::valid_key(&endpoint.transport_key)?;
            ensure!(
                endpoint.endpoint_id != [0; 32]
                    && !endpoint.address.is_unspecified()
                    && !endpoint.address.is_multicast()
                    && !matches!(endpoint.address,IpAddr::V4(ip) if ip.is_broadcast())
                    && endpoint.port > 0,
                "Invalid endpoint address"
            );
            ensure!(
                leaf_key(&endpoint.leaf_der)? == endpoint.transport_key,
                "TLS leaf public key differs from transport identity"
            );
            ensure!(
                endpoint.service_key != self.operator
                    && endpoint.service_key != self.clock.monitor_key
                    && endpoint.transport_key != self.operator
                    && endpoint.transport_key != self.clock.monitor_key
                    && !services.contains(&endpoint.transport_key),
                "Transport or peer overlaps another identity class"
            );
            if let Some(prior) =
                transport_services.insert(endpoint.transport_key, endpoint.service_key)
            {
                ensure!(
                    prior == endpoint.service_key,
                    "Transport key belongs to different services"
                );
            }
        }
        ensure!(
            self.endpoints
                .iter()
                .all(|e| !transport_services.contains_key(&e.service_key)),
            "Transport key overlaps a referenced service"
        );
        self.owned_transports()?;
        let c = &self.clock;
        ensure!(
            c.maximum_error_ms == 250
                && c.maximum_observation_age_ms == 1000
                && !c.kernel_boot.is_empty()
                && c.kernel_boot.len() <= 128
                && c.kernel_boot.bytes().all(|v| v.is_ascii_graphic()),
            "Invalid signed clock bounds or boot identity"
        );
        ensure!(
            !c.witness_file_name.is_empty()
                && c.witness_file_name.len() <= 255
                && c.witness_file_name != "."
                && c.witness_file_name != ".."
                && c.witness_file_name
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v)),
            "Invalid clock witness handle"
        );
        valid_ids(&self.placement.hosts, 16)?;
        valid_ids(&self.placement.volumes, 16)?;
        valid_ids(&self.placement.backups, 16)?;
        ensure!(
            self.placement.hosts.contains(&self.host)
                && self.placement.volumes
                    == self.volumes.iter().map(|v| v.volume_id).collect::<Vec<_>>()
                && self.placement.copies > 0
                && self.placement.copies <= self.placement.hosts.len() as u64,
            "Placement differs from admitted local resources"
        );
        valid_ids(&self.consent_policy.reviewer_roots, 16)?;
        for root in &self.consent_policy.reviewer_roots {
            wire::valid_key(root)?;
        }
        ensure!(
            self.authority_config.is_some() == self.roles.iter().any(|r| r.role == 0),
            "Authority configuration must match the authority role"
        );
        if let Some(config) = &self.authority_config {
            let role = self.roles.iter().find(|r| r.role == 0).unwrap();
            ensure!(
                config.listen_port > 0
                    && !config.listen_address.is_multicast()
                    && config.ordered_peer_endpoint_ids.len() == 4
                    && config
                        .ordered_peer_endpoint_ids
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        == 4
                    && config.tls_file_digests.iter().all(|v| *v != [0; 32]),
                "Invalid authority configuration pins"
            );
            ensure!(
                config
                    .ordered_peer_endpoint_ids
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    == role.outbound_endpoint_ids.iter().copied().collect(),
                "Ordered authority peers differ from the outbound endpoints"
            );
            let peers = config
                .ordered_peer_endpoint_ids
                .iter()
                .map(|id| {
                    self.endpoints
                        .iter()
                        .find(|e| e.endpoint_id == *id)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            ensure!(
                peers
                    .iter()
                    .map(|e| e.service_key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 4
                    && peers
                        .iter()
                        .filter(|e| e.service_key == role.service_key)
                        .count()
                        == 1
                    && role.bind_endpoint_ids.len() == 1
                    && peers
                        .iter()
                        .any(|e| e.endpoint_id == role.bind_endpoint_ids[0]
                            && e.port == config.listen_port),
                "Authority must bind its exact committee endpoint"
            );
            ensure!(
                matches!(config.subnet_address,IpAddr::V4(ip) if ip.is_private() && ip.octets()[3]==0)
                    && config.subnet_prefix == 24,
                "Installed authority requires a private IPv4 /24 subnet"
            );
            let owned = peers
                .iter()
                .find(|e| e.service_key == role.service_key)
                .unwrap();
            ensure!(
                config.listen_address.is_ipv4() == owned.address.is_ipv4()
                    && (config.listen_address.is_unspecified()
                        || config.listen_address == owned.address),
                "Authority listener differs from its owned endpoint"
            );
            ensure!(
                role.volume_ids.iter().any(|id| self
                    .volumes
                    .iter()
                    .any(|volume| volume.volume_id == *id
                        && !volume.read_only
                        && volume.storage_admission_bytes >= role.state_admission_bytes)),
                "Authority requires a writable volume with its admitted state capacity"
            );
            ensure!(
                role.state_admission_bytes >= 1024 * 1024 * 1024,
                "Authority storage admission requires journal replacement and pending-store headroom"
            );
        }
        Ok(())
    }
    pub fn successor_of(&self, previous: &Self) -> Result<()> {
        self.validate()?;
        previous.validate()?;
        ensure!(
            self.generation
                == previous
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Manifest generation exhausted"))?
                && self.previous_profile == Some(wire::digest(&previous.desired()?))
                && self.previous_consent == Some(wire::digest(&previous.unsigned_consent(0)?)),
            "Successor does not name the exact preceding profile and consent"
        );
        self.same_operational_identity(previous)
    }
    /// Stable installed resource identity excludes only explicitly renewable operating conditions.
    pub fn operational_digest(&self) -> Result<Key> {
        self.validate()?;
        let mut stable = self.clone();
        stable.generation = 1;
        stable.previous_profile = None;
        stable.previous_consent = None;
        stable.validity = (1, 2);
        stable.session_mode = 0;
        stable.clock.kernel_boot = "InitialHost".into();
        stable.software_digest = [1; 32];
        for role in &mut stable.roles {
            role.image_digest = [1; 32];
        }
        Ok(wire::digest(&stable.encode()?))
    }
    pub fn permits_definition(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        ensure!(
            self.generation >= original.generation,
            "Operational profile predates the approved service definition"
        );
        self.same_operational_identity(original)
    }
    pub fn same_operational_identity(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.operational_digest()? == previous.operational_digest()?,
            "Stopped successor cannot change permanent identities, permissions, routes, storage or resource limits"
        );
        Ok(())
    }
    fn placement_value(&self) -> V {
        a([
            ids(&self.placement.hosts),
            ids(&self.placement.volumes),
            ids(&self.placement.backups),
            V::Uint(self.placement.copies),
        ])
    }
    fn exposure(&self) -> V {
        let mut rows = self
            .roles
            .iter()
            .flat_map(|r| {
                r.bind_endpoint_ids
                    .iter()
                    .map(move |id| (r.service_key, *id))
            })
            .collect::<Vec<_>>();
        rows.sort();
        a(rows
            .iter()
            .map(|(service, endpoint)| a([b(service), b(endpoint)])))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let roles = a(self.roles.iter().map(|r| {
            a([
                V::Uint(r.role),
                b(&r.service_key),
                b(&r.image_digest),
                V::Uint(r.memory_bytes),
                V::Uint(r.pids),
                V::Uint(r.cpu_quota),
                V::Uint(r.cpu_period),
                V::Uint(r.state_admission_bytes),
                ids(&r.bind_endpoint_ids),
                ids(&r.outbound_endpoint_ids),
                ids(&r.volume_ids),
            ])
        }));
        let volumes = a(self.volumes.iter().map(|v| {
            a([
                b(&v.volume_id),
                V::Bool(v.read_only),
                V::Uint(v.storage_admission_bytes),
            ])
        }));
        let endpoints = a(self.endpoints.iter().map(|e| {
            let [family, address] = address_values(e.address);
            a([
                b(&e.endpoint_id),
                b(&e.service_key),
                family,
                address,
                V::Uint(u64::from(e.port)),
                b(&e.transport_key),
                V::Bytes(e.leaf_der.clone()),
            ])
        }));
        let c = &self.clock;
        let clock = a([
            b(&c.monitor_key),
            V::Text(c.kernel_boot.clone()),
            V::Text(c.witness_file_name.clone()),
            V::Uint(c.maximum_error_ms),
            V::Uint(c.maximum_observation_age_ms),
        ]);
        let config = self.authority_config.as_ref().map_or(V::Null, |c| {
            let [family, address] = address_values(c.listen_address);
            let [subnet_family, subnet] = address_values(c.subnet_address);
            a([
                family,
                address,
                V::Uint(u64::from(c.listen_port)),
                ids(&c.ordered_peer_endpoint_ids),
                ids(&c.tls_file_digests),
                subnet_family,
                subnet,
                V::Uint(c.subnet_prefix),
            ])
        });
        let bytes = wire::encode(&a([
            V::Uint(200),
            V::Uint(1),
            V::Text("HyperNetRuntimeManifest".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.deployment),
            b(&self.host),
            b(&self.operator),
            b(&self.bootstrap_digest),
            b(&self.software_digest),
            a([V::Uint(self.validity.0), V::Uint(self.validity.1)]),
            V::Uint(self.session_mode),
            roles,
            volumes,
            endpoints,
            clock,
            self.placement_value(),
            a(self.limits.map(V::Uint)),
            a([
                V::Bool(self.consent_policy.allow_opaque),
                ids(&self.consent_policy.reviewer_roots),
            ]),
            config,
            V::Uint(self.generation),
            self.previous_profile.as_ref().map_or(V::Null, b),
            self.previous_consent.as_ref().map_or(V::Null, b),
        ]))?;
        ensure!(bytes.len() <= MAXIMUM, "Canonical manifest exceeds 48 KiB");
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAXIMUM, "Canonical manifest exceeds 48 KiB");
        let value = wire::decode(bytes)?;
        let v = value.array(23)?;
        ensure!(
            v[0].uint()? == 200 && v[1].uint()? == 1 && v[2].text()? == "HyperNetRuntimeManifest",
            "Invalid runtime manifest envelope"
        );
        let validity = v[10].array(2)?;
        let c = v[15].array(5)?;
        let p = v[16].array(4)?;
        let l = v[17].array(4)?;
        let consent = v[18].array(2)?;
        let roles = v[12]
            .list(9)?
            .iter()
            .map(|v| {
                let r = v.array(11)?;
                Ok(Role {
                    role: r[0].uint()?,
                    service_key: key(&r[1])?,
                    image_digest: key(&r[2])?,
                    memory_bytes: r[3].uint()?,
                    pids: r[4].uint()?,
                    cpu_quota: r[5].uint()?,
                    cpu_period: r[6].uint()?,
                    state_admission_bytes: r[7].uint()?,
                    bind_endpoint_ids: keys(&r[8])?,
                    outbound_endpoint_ids: keys(&r[9])?,
                    volume_ids: keys(&r[10])?,
                })
            })
            .collect::<Result<_>>()?;
        let volumes = v[13]
            .list(16)?
            .iter()
            .map(|v| {
                let r = v.array(3)?;
                Ok(Volume {
                    volume_id: key(&r[0])?,
                    read_only: r[1].boolean()?,
                    storage_admission_bytes: r[2].uint()?,
                })
            })
            .collect::<Result<_>>()?;
        let endpoints = v[14]
            .list(16)?
            .iter()
            .map(|v| {
                let r = v.array(7)?;
                Ok(Endpoint {
                    endpoint_id: key(&r[0])?,
                    service_key: key(&r[1])?,
                    address: address(&r[2], &r[3])?,
                    port: r[4].uint()?.try_into()?,
                    transport_key: key(&r[5])?,
                    leaf_der: r[6].bytes()?.to_vec(),
                })
            })
            .collect::<Result<_>>()?;
        let authority_config = if v[19] == V::Null {
            None
        } else {
            let r = v[19].array(8)?;
            Some(AuthorityConfig {
                listen_address: address(&r[0], &r[1])?,
                listen_port: r[2].uint()?.try_into()?,
                ordered_peer_endpoint_ids: keys(&r[3])?,
                tls_file_digests: keys(&r[4])?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Three TLS file pins required"))?,
                subnet_address: address(&r[5], &r[6])?,
                subnet_prefix: r[7].uint()?,
            })
        };
        let manifest = Self {
            generation: v[20].uint()?,
            previous_profile: if v[21] == V::Null {
                None
            } else {
                Some(key(&v[21])?)
            },
            previous_consent: if v[22] == V::Null {
                None
            } else {
                Some(key(&v[22])?)
            },
            network: key(&v[3])?,
            incarnation: key(&v[4])?,
            deployment: key(&v[5])?,
            host: key(&v[6])?,
            operator: key(&v[7])?,
            bootstrap_digest: key(&v[8])?,
            software_digest: key(&v[9])?,
            validity: (validity[0].uint()?, validity[1].uint()?),
            session_mode: v[11].uint()?,
            roles,
            volumes,
            endpoints,
            clock: Clock {
                monitor_key: key(&c[0])?,
                kernel_boot: c[1].text()?.into(),
                witness_file_name: c[2].text()?.into(),
                maximum_error_ms: c[3].uint()?,
                maximum_observation_age_ms: c[4].uint()?,
            },
            placement: Placement {
                hosts: keys(&p[0])?,
                volumes: keys(&p[1])?,
                backups: keys(&p[2])?,
                copies: p[3].uint()?,
            },
            limits: [l[0].uint()?, l[1].uint()?, l[2].uint()?, l[3].uint()?],
            consent_policy: ConsentPolicy {
                allow_opaque: consent[0].boolean()?,
                reviewer_roots: keys(&consent[1])?,
            },
            authority_config,
        };
        ensure!(manifest.encode()? == bytes, "Noncanonical manifest");
        Ok(manifest)
    }
    fn prefix(&self, kind: u64) -> Vec<V> {
        vec![
            V::Uint(kind),
            V::Uint(1),
            b(&self.network),
            b(&self.incarnation),
            V::Uint(self.generation),
            if kind == 117 {
                self.previous_profile.as_ref()
            } else {
                self.previous_consent.as_ref()
            }
            .map_or(V::Null, b),
        ]
    }
    pub fn desired(&self) -> Result<Vec<u8>> {
        let digest = wire::digest(&self.encode()?);
        let mut values = self.prefix(117);
        values.extend([
            b(&self.deployment),
            b(&self.software_digest),
            V::Uint(1),
            a(self.roles.iter().map(|r| V::Uint(r.role))),
            ids(&self.volumes.iter().map(|v| v.volume_id).collect::<Vec<_>>()),
            self.exposure(),
            a(self.limits.map(V::Uint)),
            self.placement_value(),
            b(&digest),
            V::Uint(self.generation),
        ]);
        wire::encode(&a(values))
    }
    pub fn unsigned_consent(&self, withdrawal_generation: u64) -> Result<Vec<u8>> {
        let profile = wire::digest(&self.desired()?);
        let mut values = self.prefix(105);
        values.extend([
            b(&self.host),
            b(&self.deployment),
            b(&self.operator),
            a(self.roles.iter().map(|r| V::Uint(r.role))),
            ids(&self.volumes.iter().map(|v| v.volume_id).collect::<Vec<_>>()),
            self.exposure(),
            self.placement_value(),
            a(self.limits.map(V::Uint)),
            V::Bool(self.consent_policy.allow_opaque),
            ids(&self.consent_policy.reviewer_roots),
            a([V::Uint(self.validity.0), V::Uint(self.validity.1)]),
            b(&profile),
            V::Uint(withdrawal_generation),
        ]);
        wire::encode(&a(values))
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeManifestTests.rs"]
pub(crate) mod tests;
