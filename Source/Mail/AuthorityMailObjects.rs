// SPDX-License-Identifier: MIT
// Owner signatures bind MLS identities and explicit storage placement; authority cannot replace them.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
pub const MANIFEST_DOMAIN: &[u8] = b"HyperNet/MailManifest/1\0";
pub const MAXIMUM_MANIFEST: usize = 16384;
pub const MAXIMUM_PACKAGE: usize = 4096;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Signed {
    pub network: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    pub device_id: String,
    pub request_key: String,
    pub mls_signature_key: String,
    pub permissions: Vec<String>,
    pub expires: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub network: String,
    pub address_id: String,
    pub owner_key: String,
    pub generation: u64,
    pub previous_digest: Option<String>,
    pub expires: u64,
    pub devices: Vec<Device>,
    pub storage_hosts: Vec<String>,
    pub required_copies: u16,
    pub retention_seconds: u64,
    pub deleted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub device_id: String,
    pub reference: String,
    pub expires: u64,
    pub package: String,
}
pub fn hex_id(s: &str) -> Result<Digest> {
    let b: Digest = hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid mail identifier"))?;
    ensure!(
        b != [0; 32] && hex::encode(b) == s,
        "noncanonical mail identifier"
    );
    Ok(b)
}
pub fn native(s: &str) -> Result<Key> {
    let k = hex_id(s)?;
    wire::valid_key(&k)?;
    Ok(k)
}
pub fn decode(s: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        s.len() <= maximum.saturating_mul(4) / 3 + 4,
        "mail object exceeds its bound"
    );
    let b = B64.decode(s)?;
    ensure!(
        b.len() <= maximum && B64.encode(&b) == s,
        "noncanonical mail encoding"
    );
    Ok(b)
}
pub fn named(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
pub fn address(n: Digest, owner: Key) -> Digest {
    named(b"HyperNet/MailAddress/1\0", &[&n, &owner])
}
pub fn device(address: Digest, request: Key) -> Digest {
    named(b"HyperNet/MailDevice/1\0", &[&address, &request])
}
#[derive(Clone, Debug)]
pub struct Publication {
    pub manifest: Manifest,
    pub digest: Digest,
    pub bytes: Vec<u8>,
}
impl Publication {
    pub fn parse(bytes: &[u8], n: Digest) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_MANIFEST,
            "mailbox manifest exceeds its bound"
        );
        let signed: Signed = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&signed)? == bytes && hex_id(&signed.network)? == n,
            "mailbox envelope context or encoding differs"
        );
        let owner = native(&signed.public_key)?;
        let payload = decode(&signed.payload, MAXIMUM_MANIFEST)?;
        let manifest: Manifest = serde_json::from_slice(&payload)?;
        ensure!(
            serde_json::to_vec(&manifest)? == payload,
            "noncanonical mailbox manifest"
        );
        let mut message = MANIFEST_DOMAIN.to_vec();
        message.extend(n);
        message.extend(owner);
        message.extend(&payload);
        let signature_bytes = hex::decode(&signed.signature)?;
        ensure!(
            signature_bytes.len() == 64 && hex::encode(&signature_bytes) == signed.signature,
            "noncanonical mailbox signature"
        );
        let signature = Signature::from_slice(&signature_bytes)?;
        VerifyingKey::from_bytes(&owner)?.verify_strict(&message, &signature)?;
        let m = &manifest;
        let address = hex_id(&m.address_id)?;
        ensure!(
            m.version == 1
                && hex_id(&m.network)? == n
                && native(&m.owner_key)? == owner
                && address == self::address(n, owner)
                && m.generation > 0
                && m.expires > 0
                && (m.generation == 1) == m.previous_digest.is_none()
                && m.devices.len() <= 8
                && m.storage_hosts.len() <= 4
                && (60..=604800).contains(&m.retention_seconds)
                && usize::from(m.required_copies) <= m.storage_hosts.len()
                && if m.deleted {
                    m.devices.is_empty() && m.storage_hosts.is_empty() && m.required_copies == 0
                } else {
                    !m.devices.is_empty() && m.required_copies > 0
                },
            "invalid signed mailbox policy"
        );
        if let Some(previous) = &m.previous_digest {
            hex_id(previous)?;
        }
        let mut hosts = std::collections::BTreeSet::new();
        for host in &m.storage_hosts {
            ensure!(hosts.insert(native(host)?), "duplicate mail store");
        }
        let mut keys = std::collections::BTreeSet::from([owner]);
        let mut devices = std::collections::BTreeSet::new();
        for d in &m.devices {
            let request = native(&d.request_key)?;
            let signing = native(&d.mls_signature_key)?;
            ensure!(
                hex_id(&d.device_id)? == device(address, request)
                    && devices.insert(&d.device_id)
                    && keys.insert(request)
                    && keys.insert(signing)
                    && d.expires > 0
                    && d.expires <= m.expires
                    && !d.permissions.is_empty()
                    && d.permissions.len() <= 3
                    && d.permissions
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == d.permissions.len()
                    && d.permissions
                        .iter()
                        .all(|p| matches!(p.as_str(), "Read" | "Send" | "Delete")),
                "invalid mailbox device identity or rights"
            );
        }
        Ok(Self {
            // Native mailbox continuity uses the existing signed-object SHA-256,
            // not the authority CBOR record-digest wrapper.
            digest: Sha256::digest(&message).into(),
            manifest,
            bytes: bytes.to_vec(),
        })
    }
    pub fn id(&self) -> Result<Digest> {
        hex_id(&self.manifest.address_id)
    }
    pub fn owner(&self) -> Result<Key> {
        native(&self.manifest.owner_key)
    }
    pub fn device(&self, request: Key, permission: &str, at: u64) -> Result<&Device> {
        ensure!(
            !self.manifest.deleted && self.manifest.expires.saturating_mul(1000) > at,
            "mailbox expired or deleted"
        );
        self.manifest
            .devices
            .iter()
            .find(|d| {
                native(&d.request_key).ok() == Some(request)
                    && d.expires.saturating_mul(1000) > at
                    && d.permissions.iter().any(|p| p == permission)
            })
            .context("mailbox device lacks the current requested right")
    }
}
impl Package {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_PACKAGE * 2,
            "mail package exceeds its bound"
        );
        let p: Self = serde_json::from_slice(bytes)?;
        ensure!(
            serde_json::to_vec(&p)? == bytes
                && p.expires > 0
                && decode(&p.reference, 32)?.len() == 32
                && !decode(&p.package, MAXIMUM_PACKAGE)?.is_empty(),
            "invalid mail package"
        );
        hex_id(&p.device_id)?;
        Ok(p)
    }
    pub fn id(&self, n: Digest, i: Digest, address: Digest) -> Result<Digest> {
        Ok(named(
            b"HyperNet/MailInventory/1\0",
            &[&n, &i, &address, &decode(&self.reference, 32)?],
        ))
    }
}
