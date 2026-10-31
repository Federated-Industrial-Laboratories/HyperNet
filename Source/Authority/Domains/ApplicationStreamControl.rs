// SPDX-License-Identifier: MIT
// Canonical local-control contract, mirrored unchanged by the companion SDK.
use super::local::Binding;
use crate::{
    authority_proof::{Digest, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const MAXIMUM_FRAME: usize = 16 * 1024;
pub const MAXIMUM_PENDING: usize = 4;
pub const MAXIMUM_CHECK_MS: u64 = 5000;
pub const CAPABILITY: &str = "checkAuthority-v2";

pub trait Record: Serialize + DeserializeOwned {
    const LABEL: &'static str;
    fn validate(&self) -> Result<()>;
    fn binding_digest(&self) -> Digest;
    fn validate_binding(&self, binding: &Binding) -> Result<()> {
        ensure!(
            self.binding_digest() == binding.digest()?,
            "application check names another binding"
        );
        Ok(())
    }
}
fn nonzero(value: Digest) -> bool {
    value != [0; 32]
}
fn boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
            }
        })
}
pub fn encode<T: Record>(record: &T) -> Result<Vec<u8>> {
    record.validate()?;
    let bytes = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(T::LABEL.into()),
        V::Bytes(serde_json::to_vec(record)?),
    ]))?;
    ensure!(
        bytes.len() <= MAXIMUM_FRAME,
        "application check frame exceeds its bound"
    );
    Ok(bytes)
}
pub fn parse<T: Record>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAXIMUM_FRAME,
        "application check frame exceeds its bound"
    );
    let value = wire::decode(bytes)?;
    let f = value.array(4)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == T::LABEL,
        "unsupported application check record"
    );
    let record: T = serde_json::from_slice(f[3].bytes()?)?;
    ensure!(
        encode(&record)? == bytes,
        "noncanonical application check record"
    );
    Ok(record)
}
#[allow(dead_code)] // Core produces signatures; the companion uses the same schema to verify them.
pub fn sign<T: Record>(
    record: &T,
    binding: &Binding,
    key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>> {
    binding.validate()?;
    record.validate_binding(binding)?;
    ensure!(
        key.verifying_key().to_bytes() == binding.endpoint,
        "application check signer differs from binding"
    );
    let bytes = wire::sign_envelope(&encode(record)?, key)?;
    ensure!(
        bytes.len() <= MAXIMUM_FRAME,
        "signed application check exceeds its bound"
    );
    Ok(bytes)
}
// Core signs this contract; the companion verifies the same canonical source.
#[allow(dead_code)]
pub fn verify<T: Record>(bytes: &[u8], binding: &Binding) -> Result<T> {
    binding.validate()?;
    ensure!(
        bytes.len() <= MAXIMUM_FRAME,
        "signed application check exceeds its bound"
    );
    let (payload, signatures) = wire::envelope(bytes, 1)?;
    ensure!(
        signatures.len() == 1 && signatures[0].0 == binding.endpoint,
        "application check signature differs from binding"
    );
    let record: T = parse(&payload)?;
    record.validate_binding(binding)?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub binding_digest: Digest,
    pub companion_instance: Digest,
    pub nonce: Digest,
    pub kernel_boot: String,
    pub control_generation: u64,
}
impl Record for Challenge {
    const LABEL: &'static str = "ApplicationChecksChallenge";
    fn binding_digest(&self) -> Digest {
        self.binding_digest
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            nonzero(self.binding_digest)
                && nonzero(self.companion_instance)
                && nonzero(self.nonce)
                && boot(&self.kernel_boot)
                && self.control_generation > 0,
            "invalid application check challenge"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attachment {
    pub relay_service: Digest,
    pub profile_digest: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IncomingPath {
    PublicListener,
    ApprovedAttachment,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportProtection {
    Tls13FinalService,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Privacy {
    pub transport_protection: TransportProtection,
    pub endpoint_mode: u64,
    pub incoming_path: IncomingPath,
    pub attachment: Option<Attachment>,
    /// An attachment proves this transport path, never physical independence or current policy.
    pub physical_independence_verified: bool,
    pub profile_currentness_asserted: bool,
}
impl Privacy {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.physical_independence_verified && !self.profile_currentness_asserted,
            "unsupported application privacy assurance"
        );
        ensure!(
            matches!(
                (&self.incoming_path, &self.attachment, self.endpoint_mode),
                (IncomingPath::PublicListener, None, 2)
                    | (IncomingPath::ApprovedAttachment, Some(_), 3)
            ),
            "application incoming path differs from endpoint mode"
        );
        if let Some(a) = &self.attachment {
            ensure!(
                nonzero(a.relay_service) && nonzero(a.profile_digest),
                "invalid approved attachment"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ready {
    pub challenge: Challenge,
    pub endpoint_instance: Digest,
    pub monotonic_offset_ns: i64,
    pub boottime_offset_ns: i64,
    pub capabilities: Vec<String>,
    pub privacy: Privacy,
}
impl Record for Ready {
    const LABEL: &'static str = "ApplicationChecksReady";
    fn binding_digest(&self) -> Digest {
        self.challenge.binding_digest
    }
    fn validate(&self) -> Result<()> {
        self.challenge.validate()?;
        self.privacy.validate()?;
        ensure!(
            nonzero(self.endpoint_instance)
                && self.monotonic_offset_ns == 0
                && self.boottime_offset_ns == 0
                && self.capabilities == [CAPABILITY],
            "unsupported application check endpoint"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub binding_digest: Digest,
    pub companion_instance: Digest,
    pub endpoint_instance: Digest,
    pub control_generation: u64,
    pub local_connection_id: String,
    pub session: VersionRef,
    pub nonce: Digest,
    pub action_digest: Digest,
    pub caller_started_boot_ms: u64,
    pub caller_deadline_boot_ms: u64,
}
impl Request {
    pub fn matches_ready(&self, ready: &Ready) -> Result<()> {
        self.validate()?;
        ensure!(
            self.binding_digest == ready.challenge.binding_digest
                && self.companion_instance == ready.challenge.companion_instance
                && self.endpoint_instance == ready.endpoint_instance
                && self.control_generation == ready.challenge.control_generation,
            "application check belongs to another control session"
        );
        Ok(())
    }
}
impl Record for Request {
    const LABEL: &'static str = "ApplicationAuthorityCheck";
    fn binding_digest(&self) -> Digest {
        self.binding_digest
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            nonzero(self.binding_digest)
                && nonzero(self.companion_instance)
                && nonzero(self.endpoint_instance)
                && nonzero(self.nonce)
                && nonzero(self.action_digest)
                && self.control_generation > 0,
            "invalid application check correlation"
        );
        ensure!(
            !self.local_connection_id.is_empty()
                && self.local_connection_id.len() <= 128
                && self
                    .local_connection_id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')),
            "invalid local connection identifier"
        );
        ensure!(
            self.session.kind == 173
                && nonzero(self.session.id)
                && nonzero(self.session.digest)
                && self.session.generation > 0,
            "invalid application check stream reference"
        );
        ensure!(
            self.caller_started_boot_ms > 0
                && self.caller_deadline_boot_ms > self.caller_started_boot_ms
                && self.caller_deadline_boot_ms - self.caller_started_boot_ms <= MAXIMUM_CHECK_MS,
            "invalid application check absolute deadline"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancel {
    pub request: Request,
}
impl Record for Cancel {
    const LABEL: &'static str = "ApplicationAuthorityCancel";
    fn binding_digest(&self) -> Digest {
        self.request.binding_digest
    }
    fn validate(&self) -> Result<()> {
        self.request.validate()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    Permitted,
    Denied,
    Unavailable,
    Expired,
    NotActive,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authority {
    pub network: Digest,
    pub incarnation: Digest,
    pub configuration: Digest,
    pub epoch: u64,
    pub height: u64,
    pub state: Digest,
    pub statement_digest: Digest,
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
    pub code: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub request: Request,
    pub disposition: Disposition,
    pub authority: Option<Authority>,
    pub not_after_boot_ms: u64,
    pub privacy: Privacy,
}
impl Record for Receipt {
    const LABEL: &'static str = "ApplicationAuthorityReceipt";
    fn binding_digest(&self) -> Digest {
        self.request.binding_digest
    }
    fn validate_binding(&self, binding: &Binding) -> Result<()> {
        self.request.validate_binding(binding)?;
        if let Some(authority) = &self.authority {
            ensure!(
                authority.network == binding.network
                    && authority.incarnation == binding.incarnation,
                "application authority belongs to another network"
            );
        }
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.privacy.validate()?;
        ensure!(
            self.not_after_boot_ms <= self.request.caller_deadline_boot_ms,
            "application receipt extends caller deadline"
        );
        ensure!(
            matches!(
                self.disposition,
                Disposition::Permitted | Disposition::Denied
            ) == self.authority.is_some(),
            "application receipt authority differs from disposition"
        );
        if let Some(a) = &self.authority {
            ensure!(
                nonzero(a.network)
                    && nonzero(a.incarnation)
                    && nonzero(a.configuration)
                    && nonzero(a.state)
                    && nonzero(a.statement_digest)
                    && a.expires_at_ms > a.evaluated_at_ms
                    && self.not_after_boot_ms > self.request.caller_started_boot_ms,
                "invalid application authority observation"
            );
            ensure!(
                (a.code == 0) == (self.disposition == Disposition::Permitted),
                "application authority code differs from disposition"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Domains/ApplicationStreamControlTests.rs"]
mod tests;
