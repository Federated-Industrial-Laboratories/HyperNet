// SPDX-License-Identifier: MIT
// Public mail authority metadata and separately persisted opaque store objects.
use crate::types::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub type SignedMailObject = Envelope;
pub const MANIFEST: &[u8] = b"HyperNet/MailManifest/1\0";
pub const HOST: &[u8] = b"HyperNet/MailHost/1\0";
pub const OPERATION: &[u8] = b"HyperNet/MailOperation/1\0";
pub const PERMISSION: &[u8] = b"HyperNet/MailPermission/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/MailReceipt/1\0";
pub const POLICY: &[u8] = b"HyperNet/MailPolicy/1\0";
pub const MAX_CIPHERTEXT: usize = 128 * 1024;
pub const MAX_STORE_REQUEST: usize = 192 * 1024;
pub const MAX_LIFETIME: u64 = 604800;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceBinding {
    pub device_id: String,
    pub request_key: String,
    pub mls_signature_key: String,
    pub permissions: Vec<String>,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddressManifest {
    pub version: u32,
    pub network: String,
    pub address_id: String,
    pub owner_key: String,
    pub generation: u64,
    pub previous_digest: Option<String>,
    pub expires: u64,
    pub devices: Vec<DeviceBinding>,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub retention_seconds: u64,
    pub deleted: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailKeyPackage {
    pub device_id: String,
    pub reference: String,
    pub expires: u64,
    pub package: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyPackageClaim {
    pub version: u32,
    pub network: String,
    pub sender_address: String,
    pub sender_device: String,
    pub claim_id: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub recipient_manifest_digest: String,
    pub expires: u64,
    pub packages: Vec<MailKeyPackage>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailHostConsent {
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
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailRoute {
    pub version: u32,
    pub profile: String,
    pub network: String,
    pub message_id: String,
    pub replacement: u64,
    pub sender_address: String,
    pub sender_device: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub recipient_manifest_digest: String,
    pub claim_id: String,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailCiphertext {
    pub route: MailRoute,
    pub sender_manifest: SignedMailObject,
    pub recipient_manifest: SignedMailObject,
    pub welcome: String,
    pub message: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailOperation {
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub action: String,
    pub address_id: String,
    pub device_id: String,
    pub message_id: Option<String>,
    pub manifest_generation: u64,
    pub manifest_digest: String,
    pub payload_digest: Option<String>,
    pub payload_bytes: u64,
    pub after: Option<String>,
    pub route: Option<MailRoute>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailPermission {
    pub version: u32,
    pub network: String,
    pub authority_epoch: u64,
    pub authority_revision: i64,
    pub host_key: String,
    pub host_generation: u64,
    pub operation_digest: String,
    pub address_id: String,
    pub manifest_generation: u64,
    pub manifest_digest: String,
    pub issued_at: u64,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailReceipt {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub message_id: String,
    pub replacement: u64,
    pub payload_digest: String,
    pub recipient_address: String,
    pub recipient_generation: u64,
    pub status: String,
    pub recorded_at: u64,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailPolicy {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub host_generation: u64,
    pub authority_epoch: u64,
    pub authority_revision: i64,
    pub issued_at: u64,
    pub expires: u64,
    pub addresses: Vec<MailPlacement>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailPlacement {
    pub address_id: String,
    pub generation: u64,
    pub manifest_digest: String,
    pub retention_seconds: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddressRecord {
    pub member: String,
    pub manifest: SignedMailObject,
    pub digest: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRecord {
    pub consent: SignedMailObject,
    pub digest: String,
    pub body: MailHostConsent,
    pub active: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageRecord {
    pub address_id: String,
    pub generation: u64,
    pub package: MailKeyPackage,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailState {
    pub addresses: BTreeMap<String, AddressRecord>,
    pub hosts: BTreeMap<String, HostRecord>,
    pub packages: BTreeMap<String, PackageRecord>,
    pub claims: BTreeMap<String, KeyPackageClaim>,
    pub consumed: BTreeMap<String, ConsumedPackage>,
    pub device_history: BTreeSet<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumedPackage {
    pub address_id: String,
    pub device_id: String,
    pub generation: u64,
    pub reference: String,
    pub expires: u64,
    pub retain_until: u64,
}
