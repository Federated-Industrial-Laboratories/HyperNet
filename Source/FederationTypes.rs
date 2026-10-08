// SPDX-License-Identifier: MIT
use super::{Envelope, PageBundle, PageDescriptor};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationTreaty {
    pub version: u32,
    pub agreement_id: String,
    pub source_network: String,
    pub destination_network: String,
    pub source_authority_key: String,
    pub destination_authority_key: String,
    pub source_bridge_key: String,
    pub destination_bridge_key: String,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub service: String,
    pub profile: String,
    pub expires: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedEvidence {
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationAdmission {
    pub version: u32,
    pub agreement_digest: String,
    pub source_network: String,
    pub destination_network: String,
    pub source_bridge_key: String,
    pub destination_bridge_key: String,
    pub destination_profile: String,
    pub request_id: String,
    pub authority_revision: u64,
    pub issued_at: u64,
    pub valid_until: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationExportEvidence {
    pub version: u32,
    pub agreement_digest: String,
    pub admission_digest: String,
    pub descriptor: PageDescriptor,
    pub author_share_digest: String,
    pub source_profile: String,
    pub authority_revision: u64,
    pub issued_at: u64,
    pub valid_until: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationAgreement {
    pub treaty: FederationTreaty,
    pub digest: String,
    pub version: u64,
    pub active: bool,
    pub source_revision: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationShareRecord {
    pub descriptor_digest: String,
    pub share_digest: String,
    pub allowed: bool,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub last_withdrawal_generation: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationPublication {
    pub descriptor: PageDescriptor,
    pub reviewer: String,
    pub approval_digest: String,
    pub publication_version: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationPageRecord {
    pub version: u64,
    pub observed: PageDescriptor,
    pub pending: bool,
    pub published: Option<FederationPublication>,
    pub admission: SignedEvidence,
    pub export: SignedEvidence,
    pub bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FederationPageBlob {
    pub bundle: PageBundle,
    pub author_share: Envelope,
    pub approval: Option<Envelope>,
}
