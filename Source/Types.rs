// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[path = "FederationTypes.rs"]
mod federation;
pub use federation::*;

pub const STATE_VERSION: u32 = 8;

pub const MEMBER: u64 = 1;
pub const HOST: u64 = 2;
pub const ADMIN: u64 = 4;
pub const FEDERATION: u64 = 8;
pub const ALL: u64 = MEMBER | HOST | ADMIN | FEDERATION;
pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_ENVELOPE: usize = 96 * 1024;
pub const MAX_STATE: usize = 1024 * 1024;
pub const DOMAIN: &[u8] = b"HyperNet/Request/1\0";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    pub network: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    pub version: u32,
    pub request_id: String,
    pub issued_at: u64,
    pub command: Command,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields, rename_all_fields = "camelCase")]
pub enum Command {
    ApplicationConsent {
        owner_key: String,
        expires: u64,
        namespaces: Vec<String>,
        page_ids: Option<Vec<String>>,
        permissions: Vec<String>,
        review_policy_digest: Option<String>,
        review_mode: Option<String>,
    },
    ApplicationGrantCreate {
        consent: Envelope,
    },
    ApplicationGrantGet {
        application_key: String,
    },
    ApplicationGrantList {
        after: Option<String>,
    },
    ApplicationGrantRevoke {
        application_key: String,
    },
    TransferHostRegister {
        consent: Envelope,
    },
    TransferHostWithdraw {
        host_key: String,
        expected_generation: u64,
    },
    TransferHosts,
    TransferOfferCreate {
        offer: Envelope,
    },
    TransferOfferGet {
        transfer_id: String,
    },
    TransferOfferList {
        after: Option<String>,
    },
    TransferOfferAccept {
        acceptance: Envelope,
    },
    TransferOfferCancel {
        transfer_id: String,
        offer_digest: String,
    },
    TransferAuthorise {
        host_key: String,
        operation: Envelope,
    },
    TransferPolicySync {
        host_key: String,
    },
    SshServiceRegister {
        consent: Envelope,
    },
    SshServiceWithdraw {
        service_key: String,
        expected_generation: u64,
    },
    SshServices,
    SshServiceGet {
        service_key: String,
    },
    SshGrantCreate {
        grant_id: String,
        service_key: String,
        service_generation: u64,
        ssh_public_key: String,
        ssh_key_proof: String,
        account: String,
        purpose: String,
        expires: u64,
    },
    SshGrantAccept {
        grant_id: String,
    },
    SshGrantRevoke {
        grant_id: String,
    },
    SshGrantGet {
        grant_id: String,
    },
    SshAuthorise {
        service_key: String,
        grant_id: String,
    },
    MailAddressCreate {
        manifest: crate::mail_types::SignedMailObject,
    },
    MailAddressUpdate {
        address_id: String,
        expected_generation: u64,
        manifest: crate::mail_types::SignedMailObject,
    },
    MailAddressDelete {
        address_id: String,
        expected_generation: u64,
        manifest: crate::mail_types::SignedMailObject,
    },
    MailAddressGet {
        address_id: String,
    },
    MailHostRegister {
        consent: crate::mail_types::SignedMailObject,
    },
    MailHostWithdraw {
        host_key: String,
        expected_generation: u64,
    },
    MailHosts,
    MailKeyPackagesPublish {
        address_id: String,
        device_id: String,
        manifest_generation: u64,
        packages: Vec<crate::mail_types::MailKeyPackage>,
    },
    MailKeyPackagesClaim {
        sender_address: String,
        sender_device: String,
        recipient_address: String,
        recipient_manifest_digest: String,
        claim_id: String,
        expires: u64,
    },
    MailKeyPackagesClaimStatus {
        sender_address: String,
        sender_device: String,
        claim_id: String,
    },
    MailAuthorise {
        host_key: String,
        operation: crate::mail_types::SignedMailObject,
    },
    MailPolicySync {
        host_key: String,
    },
    Status {
        #[serde(rename = "deviceKey")]
        device_key: Option<String>,
    },
    Invite {
        verifier: String,
        #[serde(rename = "deviceKey")]
        device_key: String,
        grants: u64,
        expires: u64,
    },
    Redeem {
        secret: String,
    },
    Grant {
        #[serde(rename = "deviceKey")]
        device_key: String,
        grants: u64,
        expires: u64,
    },
    Revoke {
        #[serde(rename = "deviceKey")]
        device_key: String,
    },
    Consent {
        profile: String,
        grants: u64,
        expires: u64,
        certificate: String,
        document: String,
    },
    Withdraw,
    Heartbeat {
        profile: String,
    },
    PageSubmit {
        page_id: String,
        expected_version: u64,
        namespace: String,
        audience: String,
        profile: String,
        digest: String,
        body: String,
    },
    PageQueue {
        namespace: Option<String>,
        after: Option<String>,
    },
    PageInspect {
        page_id: String,
    },
    PageReview {
        page_id: String,
        expected_version: u64,
        revision: u64,
        digest: String,
        profile: String,
        author: String,
        namespace: String,
        audience: String,
        submission_digest: String,
        decision: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application_policy_digest: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application_review_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        review_expires: Option<u64>,
    },
    PageWithdraw {
        page_id: String,
        expected_version: u64,
    },
    PageList {
        namespace: Option<String>,
        after: Option<String>,
    },
    PageRead {
        page_id: String,
    },
    PageSync {
        profile: String,
        known_inventory: Option<String>,
        fetch: Option<String>,
    },
    PageReplicaRequest {
        page_id: String,
        replica_device_key: String,
        publication_version: u64,
    },
    PageReplicaResult {
        ticket_id: String,
    },
    ReplicaDeliver {
        profile: String,
        ticket_id: String,
        bundle: PageBundle,
    },
    FederationAccept {
        treaty: FederationTreaty,
    },
    FederationWithdraw {
        agreement_id: String,
        expected_version: u64,
    },
    FederationAgreements,
    BridgeConsent {
        agreement_id: String,
        profile: String,
        expires: u64,
        certificate: String,
        document: String,
    },
    BridgeWithdraw,
    FederationShare {
        agreement_id: String,
        agreement_digest: String,
        page_id: String,
        publication_version: u64,
        descriptor_digest: String,
        allow: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_generation: Option<u64>,
    },
    FederationShareStatus {
        agreement_id: String,
        page_id: String,
    },
    FederationUnshare {
        agreement_id: String,
        page_id: String,
        expected_generation: u64,
    },
    FederationPermit {
        agreement_id: String,
        profile: String,
    },
    FederationExport {
        agreement_id: String,
        profile: String,
        admission: SignedEvidence,
        page_id: Option<String>,
        include_bundle: bool,
    },
    FederationImport {
        agreement_id: String,
        profile: String,
        admission: SignedEvidence,
        export: SignedEvidence,
        bundle: Option<PageBundle>,
        author_share: Option<Envelope>,
    },
    FederationQueue {
        agreement_id: String,
        after: Option<String>,
    },
    FederationInspect {
        agreement_id: String,
        page_id: String,
    },
    FederationReview {
        agreement_id: String,
        page_id: String,
        expected_version: u64,
        descriptor_digest: String,
        decision: String,
    },
    FederationPageWithdraw {
        agreement_id: String,
        page_id: String,
        expected_version: u64,
    },
    FederationList {
        agreement_id: String,
        after: Option<String>,
    },
    FederationRead {
        agreement_id: String,
        page_id: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Reply {
    pub ok: bool,
    pub code: String,
    pub epoch: u64,
    pub result: Value,
}

impl Reply {
    pub fn error(code: &str) -> Self {
        Self {
            ok: false,
            code: code.into(),
            epoch: 0,
            result: Value::Null,
        }
    }

    pub fn success(epoch: u64, result: Value) -> Self {
        Self {
            ok: true,
            code: "Ok".into(),
            epoch,
            result,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Member {
    pub grants: u64,
    pub expires: u64,
    pub revoked: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Invitation {
    pub issuer: String,
    pub device_key: String,
    pub grants: u64,
    pub expires: u64,
    pub redeemed: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Consent {
    pub profile: String,
    pub grants: u64,
    pub expires: u64,
    pub certificate: String,
    pub active: bool,
    pub document: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageDescriptor {
    pub page_id: String,
    pub publication_version: u64,
    pub revision: u64,
    pub author: String,
    pub reviewer: String,
    pub namespace: String,
    pub audience: String,
    pub profile: String,
    pub digest: String,
    pub submission_digest: String,
    pub approval_digest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageBundle {
    pub submission: Envelope,
    pub approval: Envelope,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingPage {
    pub revision: u64,
    pub digest: String,
    pub profile: String,
    pub audience: String,
    pub submission_digest: String,
    pub bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublishedPage {
    pub descriptor: PageDescriptor,
    pub bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageRecord {
    pub version: u64,
    pub author: String,
    pub namespace: String,
    pub pending: Option<PendingPage>,
    pub published: Option<PublishedPage>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplicaTicket {
    pub ticket_id: String,
    pub descriptor: PageDescriptor,
    pub expires: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TicketRecord {
    pub ticket: ReplicaTicket,
    pub reader: String,
    pub host: String,
    pub host_profile: String,
    pub delivered: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageSyncResult {
    pub profile: String,
    pub authority_revision: u64,
    pub valid_until: u64,
    pub inventory_digest: String,
    pub entries: Option<Vec<PageDescriptor>>,
    pub bundle: Option<PageBundle>,
    pub requests: Vec<ReplicaTicket>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Receipt {
    pub digest: String,
    pub expires: u64,
    pub reply: Reply,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct State {
    #[serde(deserialize_with = "state_version")]
    pub version: u32,
    pub network: String,
    pub epoch: u64,
    pub high_water_time: u64,
    pub members: BTreeMap<String, Member>,
    pub invitations: BTreeMap<String, Invitation>,
    pub consents: BTreeMap<String, Consent>,
    pub receipts: BTreeMap<String, Receipt>,
    pub pages: BTreeMap<String, PageRecord>,
    pub replica_tickets: BTreeMap<String, TicketRecord>,
    pub federation_agreements: BTreeMap<String, FederationAgreement>,
    pub bridge_consents: BTreeMap<String, Consent>,
    pub federation_shares: BTreeMap<String, FederationShareRecord>,
    pub federation_pages: BTreeMap<String, FederationPageRecord>,
    pub mail: crate::mail_types::MailState,
    pub transfers: crate::transfer_types::TransferState,
    pub ssh: crate::ssh_types::SshState,
    pub applications: BTreeMap<String, crate::application_authority::ApplicationRecord>,
}

fn state_version<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    if version != STATE_VERSION {
        return Err(serde::de::Error::custom("UnsupportedState"));
    }
    Ok(version)
}

impl State {
    pub fn initial(network: String, admin: String, now: u64) -> Self {
        Self {
            version: STATE_VERSION,
            network,
            epoch: 1,
            high_water_time: now,
            members: BTreeMap::from([(
                admin,
                Member {
                    grants: MEMBER | HOST | ADMIN,
                    expires: u64::MAX,
                    revoked: false,
                },
            )]),
            invitations: BTreeMap::new(),
            consents: BTreeMap::new(),
            receipts: BTreeMap::new(),
            pages: BTreeMap::new(),
            replica_tickets: BTreeMap::new(),
            federation_agreements: BTreeMap::new(),
            bridge_consents: BTreeMap::new(),
            federation_shares: BTreeMap::new(),
            federation_pages: BTreeMap::new(),
            mail: Default::default(),
            transfers: Default::default(),
            ssh: Default::default(),
            applications: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthorityConfig {
    pub network: String,
    pub listen: std::net::SocketAddr,
    pub state_directory: std::path::PathBuf,
    pub certificate: std::path::PathBuf,
    pub private_key: std::path::PathBuf,
    pub client_ca: std::path::PathBuf,
    pub etcd_endpoints: Vec<String>,
    pub etcd_ca: std::path::PathBuf,
    pub etcd_certificate: std::path::PathBuf,
    pub etcd_key: std::path::PathBuf,
    pub etcd_server_name: String,
    #[serde(default)]
    pub federation_signing_key: Option<std::path::PathBuf>,
    #[serde(default)]
    pub mail_signing_key: Option<std::path::PathBuf>,
    #[serde(default)]
    pub service_signing_key: Option<std::path::PathBuf>,
}
