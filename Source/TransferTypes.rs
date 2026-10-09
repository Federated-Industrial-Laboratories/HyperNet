// SPDX-License-Identifier: MIT
// Immutable encrypted transfer offers and current selected-store permissions.
use crate::types::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const HOST: &[u8] = b"HyperNet/TransferHost/1\0";
pub const OFFER: &[u8] = b"HyperNet/TransferOffer/1\0";
pub const ACCEPTANCE: &[u8] = b"HyperNet/TransferAcceptance/1\0";
pub const OPERATION: &[u8] = b"HyperNet/TransferOperation/1\0";
pub const PERMISSION: &[u8] = b"HyperNet/TransferPermission/1\0";
pub const POLICY: &[u8] = b"HyperNet/TransferPolicy/1\0";
pub const RECEIPT: &[u8] = b"HyperNet/TransferReceipt/1\0";
pub const MAX_FILE: u64 = 8 * 1024 * 1024;
pub const CHUNK: u64 = 64 * 1024;
pub const MAX_REQUEST: usize = 128 * 1024;
pub const MAX_LIFETIME: u64 = 604800;
pub type HostConsent = crate::mail_types::MailHostConsent;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Offer {
    pub version: u32,
    pub network: String,
    pub transfer_id: String,
    pub sender_key: String,
    pub recipient_key: String,
    pub recipient_encryption_key: String,
    pub payload_bytes: u64,
    pub payload_digest: String,
    pub file_bytes: u64,
    pub label: String,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Acceptance {
    pub version: u32,
    pub network: String,
    pub transfer_id: String,
    pub offer_digest: String,
    pub host_key: String,
    pub destination: String,
    pub expires: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferRecord {
    pub offer: Envelope,
    pub body: Offer,
    pub offer_digest: String,
    pub acceptance: Option<Envelope>,
    pub accepted: Option<Acceptance>,
    pub cancelled: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Operation {
    pub version: u32,
    pub network: String,
    pub operation_id: String,
    pub issued_at: u64,
    pub host_key: String,
    pub transfer_id: String,
    pub offer_digest: String,
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
    pub transfer: TransferRecord,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreReceipt {
    pub version: u32,
    pub network: String,
    pub host_key: String,
    pub transfer_id: String,
    pub offer_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub stored_bytes: u64,
    pub status: String,
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
    pub transfers: Vec<String>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferState {
    pub hosts: BTreeMap<String, crate::mail_types::HostRecord>,
    pub offers: BTreeMap<String, TransferRecord>,
}
