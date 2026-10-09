// SPDX-License-Identifier: MIT
// Separately consented OpenSSH endpoints and short current-policy session leases.
use crate::types::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CONSENT: &[u8] = b"HyperNet/SshConsent/1\0";
pub const LEASE: &[u8] = b"HyperNet/SshLease/1\0";
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SshConsent {
    pub version: u32,
    pub network: String,
    pub service_key: String,
    pub generation: u64,
    pub endpoint: String,
    pub address: std::net::SocketAddr,
    pub ssh_host_key: String,
    pub account: String,
    pub purpose: String,
    pub command_digest: String,
    pub image_digest: String,
    pub authority_endpoint: String,
    pub authority_address: std::net::SocketAddr,
    pub authority_signer: String,
    pub certificate_digest: String,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
    pub maximum_session_seconds: u64,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRecord {
    pub consent: Envelope,
    pub consent_digest: String,
    pub body: SshConsent,
    pub active: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub service_key: String,
    pub service_generation: u64,
    pub member_key: String,
    pub ssh_public_key: String,
    pub account: String,
    pub purpose: String,
    pub expires: u64,
    pub accepted: bool,
    pub revoked: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lease {
    pub version: u32,
    pub network: String,
    pub authority_epoch: u64,
    pub authority_revision: i64,
    pub service_key: String,
    pub service_generation: u64,
    pub consent_digest: String,
    pub issued_at: u64,
    pub expires: u64,
    pub grant: Grant,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SshState {
    pub services: BTreeMap<String, ServiceRecord>,
    pub grants: BTreeMap<String, Grant>,
    pub key_history: BTreeSet<String>,
    #[serde(default)]
    pub key_owners: BTreeMap<String, String>,
}

impl SshState {
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
            && self.grants.is_empty()
            && self.key_history.is_empty()
            && self.key_owners.is_empty()
    }
}
