// SPDX-License-Identifier: MIT
// Reader routes name one relay and one final TLS identity without a direct fallback address.
use crate::{authority_proof::Digest, runtime_manifest, trust_wire};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Assurance {
    Organisation,
    Independent,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub service: Digest,
    pub server_name: String,
    pub transport_key: Digest,
    pub leaf_der: Vec<u8>,
    pub certificate_authority_pem: String,
}
impl Identity {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.service != [0; 32], "route service identity is absent");
        ensure!(
            !self.server_name.is_empty()
                && self.server_name.len() <= 253
                && self.server_name.is_ascii()
                && !self.server_name.contains('%'),
            "invalid route TLS server name"
        );
        let _ = rustls::pki_types::ServerName::try_from(self.server_name.clone())?;
        ensure!(
            runtime_manifest::leaf_key(&self.leaf_der)? == self.transport_key,
            "route TLS leaf differs from its pinned transport key"
        );
        ensure!(
            !self.certificate_authority_pem.is_empty()
                && self.certificate_authority_pem.len() <= 65536,
            "route certificate authority exceeds its bound"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub bytes: u64,
    pub duration_ms: u64,
    pub idle_ms: u64,
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.bytes >= 16384
                && self.bytes <= 1024 * 1024 * 1024
                && (1000..=3600000).contains(&self.duration_ms)
                && (100..=self.duration_ms).contains(&self.idle_ms),
            "route limits exceed the finite stream bounds"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)] // The shared reader profile is consumed by client builds.
pub struct Profile {
    pub version: u64,
    pub network: Digest,
    pub incarnation: Digest,
    pub relay_address: SocketAddr,
    pub relay: Identity,
    pub destination: Identity,
    pub domain: String,
    pub relay_domain: String,
    pub protocol: u64,
    pub assurance: Assurance,
    pub minimum_assurance: Assurance,
    pub limits: Limits,
    pub voucher: Vec<u8>,
}
#[allow(dead_code)] // Server builds retain this shared profile contract for independent clients.
impl Profile {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.network != [0; 32] && self.incarnation != [0; 32],
            "route network or version is invalid"
        );
        ensure!(
            self.relay_address.port() != 0
                && !self.relay_address.ip().is_unspecified()
                && !self.relay_address.ip().is_multicast()
                && !matches!(self.relay_address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast()),
            "route requires an exact numeric relay endpoint"
        );
        self.relay.validate()?;
        self.destination.validate()?;
        self.limits.validate()?;
        ensure!(
            self.relay.service != self.destination.service
                && self.relay.transport_key != self.destination.transport_key
                && self.assurance >= self.minimum_assurance
                && (self.assurance != Assurance::Independent || self.domain != self.relay_domain),
            "route identity separation or privacy assurance differs"
        );
        ensure!(
            matches!(self.protocol, 1..=7)
                && !self.relay_domain.is_empty()
                && self.relay_domain.len() <= 255
                && self
                    .relay_domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_/".contains(&b))
                && !self.domain.is_empty()
                && self.domain.len() <= 255
                && self
                    .domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_/".contains(&b))
                && !self.voucher.is_empty()
                && self.voucher.len() <= trust_wire::MAXIMUM / 2,
            "route domain, protocol or voucher is invalid"
        );
        Ok(())
    }
}
