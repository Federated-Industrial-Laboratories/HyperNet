// SPDX-License-Identifier: MIT
// Reference-bound static page media and independently consented durable hosts.
use crate::{markup::media::Asset, types::Envelope};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const HOST: &[u8] = b"HyperNet/PageMediaHost/1\0";
pub const OPERATION: &[u8] = b"HyperNet/PageMediaOperation/1\0";
pub const PERMISSION: &[u8] = b"HyperNet/PageMediaPermission/1\0";
pub const POLICY: &[u8] = b"HyperNet/PageMediaPolicy/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/PageMediaReceipt/1\0";
pub const CHUNK: u64 = 32768;
pub const MAX_REQUEST: usize = 65536;
pub const MAX_LIFETIME: u64 = 604800;
pub const UPLOAD_LIFETIME: u64 = 86400;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostConsent {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub generation: u64,
    pub services: Vec<String>,
    pub endpoint: String,
    pub address: std::net::SocketAddr,
    pub ca_digest: String,
    pub certificate_digest: String,
    pub authority_endpoint: String,
    pub authority_address: std::net::SocketAddr,
    pub authority_signer: String,
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
    pub state_bytes: u64,
    pub expires: u64,
    pub namespaces: Vec<String>,
    pub retention_seconds: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRecord {
    pub consent: Envelope,
    pub digest: String,
    pub body: HostConsent,
    pub active: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetRecord {
    pub agreement_id: Option<String>,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub page_id: String,
    pub revision: u64,
    pub source_digest: String,
    pub author: String,
    pub namespace: String,
    pub asset: Asset,
    pub upload_expires: u64,
    pub expires: u64,
    pub receipts: BTreeMap<String, Envelope>,
    pub reviewed_by: BTreeSet<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub admission: Option<crate::types::SignedEvidence>,
    pub agreement_id: Option<String>,
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub page_id: String,
    pub revision: u64,
    pub asset_id: String,
    pub source_digest: String,
    pub action: String,
    pub offset: u64,
    pub chunk_bytes: u64,
    pub chunk_digest: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permission {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub authority_revision: i64,
    pub authority_epoch: u64,
    pub issued_at: u64,
    pub expires: u64,
    pub operation_digest: String,
    pub asset: AssetRecord,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreReceipt {
    pub agreement_id: Option<String>,
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub page_id: String,
    pub revision: u64,
    pub asset_id: String,
    pub source_digest: String,
    pub digest: String,
    pub bytes: u64,
    pub stored_bytes: u64,
    pub status: String,
    pub requester_key: String,
    pub action: String,
    pub recorded_at: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorePolicy {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub authority_revision: i64,
    pub authority_epoch: u64,
    pub issued_at: u64,
    pub expires: u64,
    pub assets: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaState {
    pub hosts: BTreeMap<String, HostRecord>,
    pub assets: BTreeMap<String, AssetRecord>,
    pub minimum_copies: u16,
}
impl Default for MediaState {
    fn default() -> Self {
        Self {
            hosts: BTreeMap::new(),
            assets: BTreeMap::new(),
            minimum_copies: 1,
        }
    }
}
pub fn asset_key(agreement: Option<&str>, page: &str, revision: u64, asset: &str) -> String {
    match agreement {
        Some(agreement) => format!("{agreement}/{page}/{revision}/{asset}"),
        None => format!("Native/{page}/{revision}/{asset}"),
    }
}
