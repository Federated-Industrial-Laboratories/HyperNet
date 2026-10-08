// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const MEMBER: u64 = 1;
pub const HOST: u64 = 2;
pub const ADMIN: u64 = 4;
pub const ALL: u64 = MEMBER | HOST | ADMIN;
pub const MAX_PAYLOAD: usize = 16 * 1024;
pub const MAX_ENVELOPE: usize = 24 * 1024;
pub const MAX_STATE: usize = 1024 * 1024;
pub const DOMAIN: &[u8] = b"HyperNet/Request/1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    pub network: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    pub version: u32,
    pub request_id: String,
    pub issued_at: u64,
    pub command: Command,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Command {
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
    },
    Withdraw,
    Heartbeat {
        profile: String,
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
    pub version: u32,
    pub network: String,
    pub epoch: u64,
    pub high_water_time: u64,
    pub members: BTreeMap<String, Member>,
    pub invitations: BTreeMap<String, Invitation>,
    pub consents: BTreeMap<String, Consent>,
    pub receipts: BTreeMap<String, Receipt>,
}

impl State {
    pub fn initial(network: String, admin: String, now: u64) -> Self {
        Self {
            version: 1,
            network,
            epoch: 1,
            high_water_time: now,
            members: BTreeMap::from([(
                admin,
                Member {
                    grants: ALL,
                    expires: u64::MAX,
                    revoked: false,
                },
            )]),
            invitations: BTreeMap::new(),
            consents: BTreeMap::new(),
            receipts: BTreeMap::new(),
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
}
