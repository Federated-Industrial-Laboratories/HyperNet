// SPDX-License-Identifier: MIT
// Encrypted transfers bind one immutable offer, explicit recipient acceptance and an exact consenting store.
use super::*;
use crate::runtime_manifest::Manifest;
use bech32::{FromBase32, ToBase32, Variant};
#[path = "../../Transfers/AuthorityTransferCommands.rs"]
mod commands;
pub use commands::{Command, Effect};
#[path = "../../Transfers/AuthorityTransferEvaluation.rs"]
mod evaluation;
pub use evaluation::{evaluate, expected_recipient};
#[path = "../../Transfers/AuthorityTransferRequest.rs"]
mod request;
pub use request::Request;
#[path = "../../Transfers/AuthorityTransferReceipt.rs"]
mod receipt;
pub use receipt::{RECEIPT_LIMIT, Receipt};
pub const MAXIMUM_PAYLOAD: u64 = 8 * 1024 * 1024;
pub const CHUNK: u64 = 64 * 1024;
pub const MAXIMUM_LIFETIME_MS: u64 = 7 * 24 * 3600 * 1000;
pub const BANK_HEADER: u64 = 64;

#[derive(Clone, Debug)]
pub struct Profile {
    pub manifest: Manifest,
    pub service: Key,
    pub endpoint: Option<Digest>,
    pub volume: Digest,
    pub state_bytes: u64,
    pub maximum_payload: u64,
    pub maximum_lifetime_ms: u64,
    pub envelope: Vec<u8>,
}
impl Profile {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityTransferProfile".into()),
            b(&self.manifest.encode()?),
            b(&self.service),
            self.endpoint.as_ref().map_or(V::Null, |v| b(v)),
            b(&self.volume),
            V::Uint(self.state_bytes),
            V::Uint(self.maximum_payload),
            V::Uint(self.maximum_lifetime_ms),
        ]))
    }
    pub fn parse(envelope: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= (crate::runtime_manifest::MAXIMUM + 1024),
            "transfer profile exceeds its bound"
        );
        let (bytes, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(10)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityTransferProfile",
            "invalid transfer profile"
        );
        let p = Self {
            manifest: Manifest::parse(f[3].bytes()?)?,
            service: key(&f[4])?,
            endpoint: if f[5] == V::Null {
                None
            } else {
                Some(id(&f[5])?)
            },
            volume: id(&f[6])?,
            state_bytes: f[7].uint()?,
            maximum_payload: f[8].uint()?,
            maximum_lifetime_ms: f[9].uint()?,
            envelope: envelope.to_vec(),
        };
        let m = &p.manifest;
        let role = m
            .roles
            .iter()
            .find(|r| r.role == 4)
            .context("transfer role absent")?;
        let volume = m
            .volumes
            .iter()
            .find(|v| v.volume_id == p.volume)
            .context("transfer volume absent")?;
        ensure!(
            m.network == network
                && m.incarnation == incarnation
                && signatures.len() == 1
                && signatures[0].0 == m.operator
                && role.service_key == p.service
                && match p.endpoint {
                    Some(id) => role.bind_endpoint_ids == [id],
                    None => role.bind_endpoint_ids.is_empty(),
                }
                && role.volume_ids.contains(&p.volume)
                && !volume.read_only
                && m.consent_policy.allow_opaque
                && p.state_bytes <= volume.storage_admission_bytes
                && p.state_bytes <= role.state_admission_bytes
                && p.state_bytes
                    .checked_mul(3)
                    .is_some_and(|n| n <= role.memory_bytes)
                && p.state_bytes.is_multiple_of(2)
                && (1..=MAXIMUM_PAYLOAD).contains(&p.maximum_payload)
                && (1..=MAXIMUM_LIFETIME_MS).contains(&p.maximum_lifetime_ms)
                && p.state_bytes / 2
                    >= BANK_HEADER + disk_header_bytes() + reservation_bytes(p.maximum_payload)?,
            "transfer profile exceeds its exact signed deployment consent"
        );
        Ok(p)
    }
}

#[derive(Clone, Debug)]
pub struct Service {
    pub profile: Profile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Service {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(4)?;
        let out = Self {
            profile: Profile::parse(f[0].bytes()?, n, i)?,
            manager: key(&f[1])?,
            grant: version(&f[2])?,
            withdrawn: f[3].boolean()?,
        };
        ensure!(out.grant.kind == 102, "transfer manager grant differs");
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.profile.envelope),
            b(&self.manager),
            reference(&self.grant),
            V::Bool(self.withdrawn),
        ])
    }
}
pub fn validate_service(
    value: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    let s = Service::parse(value, n, i)?;
    ensure!(
        lookup == s.profile.service && generation == 1 + u64::from(s.withdrawn),
        "transfer service generation differs"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Offer {
    #[cfg(test)]
    pub network: Digest,
    #[cfg(test)]
    pub incarnation: Digest,
    pub id: Digest,
    pub sender: Key,
    pub recipient: Key,
    pub encryption_key: String,
    pub payload_bytes: u64,
    pub payload_digest: Digest,
    pub file_bytes: u64,
    #[cfg(test)]
    pub label: String,
    pub expires: u64,
    pub envelope: Vec<u8>,
}
impl Offer {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityTransferOffer".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.id),
            b(&self.sender),
            b(&self.recipient),
            V::Text(self.encryption_key.clone()),
            V::Uint(self.payload_bytes),
            b(&self.payload_digest),
            V::Uint(self.file_bytes),
            V::Text(self.label.clone()),
            V::Uint(self.expires),
        ]))
    }
    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(envelope.len() <= 2048, "transfer offer exceeds its bound");
        let (bytes, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(14)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityTransferOffer"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "invalid transfer offer context"
        );
        let _label = label(&f[12], 64)?;
        let out = Self {
            #[cfg(test)]
            network: n,
            #[cfg(test)]
            incarnation: i,
            id: id(&f[5])?,
            sender: key(&f[6])?,
            recipient: key(&f[7])?,
            encryption_key: f[8].text()?.into(),
            payload_bytes: f[9].uint()?,
            payload_digest: id(&f[10])?,
            file_bytes: f[11].uint()?,
            #[cfg(test)]
            label: _label,
            expires: f[13].uint()?,
            envelope: envelope.to_vec(),
        };
        ensure!(
            out.encryption_key.len() == 62,
            "invalid age recipient length"
        );
        let (hrp, data, variant) = bech32::decode(&out.encryption_key)?;
        let native = Vec::<u8>::from_base32(&data)?;
        ensure!(
            hrp == "age"
                && variant == Variant::Bech32
                && native.len() == 32
                && native.iter().any(|v| *v != 0)
                && bech32::encode("age", native.to_base32(), Variant::Bech32)?
                    == out.encryption_key
                && signatures.len() == 1
                && signatures[0].0 == out.sender
                && out.sender != out.recipient
                && (1..=MAXIMUM_PAYLOAD).contains(&out.payload_bytes)
                && out.file_bytes < out.payload_bytes
                && out.expires > 0,
            "invalid signed transfer offer"
        );
        Ok(out)
    }
}
#[derive(Clone, Debug)]
pub struct Acceptance {
    pub service: VersionRef,
    pub capability: VersionRef,
    pub destination: String,
    pub expires: u64,
    pub intent: Digest,
}
impl Acceptance {
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(5)?;
        let out = Self {
            service: version(&f[0])?,
            capability: version(&f[1])?,
            destination: label(&f[2], 64)?,
            expires: f[3].uint()?,
            intent: id(&f[4])?,
        };
        ensure!(
            out.service.kind == 134
                && out.service.generation == 1
                && out.capability.kind == 102
                && out.expires > 0,
            "invalid transfer acceptance"
        );
        Ok(out)
    }
    fn value(&self) -> V {
        a(vec![
            reference(&self.service),
            reference(&self.capability),
            V::Text(self.destination.clone()),
            V::Uint(self.expires),
            b(&self.intent),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Agreement {
    pub offer: Offer,
    pub capability: VersionRef,
    pub acceptance: Option<Acceptance>,
    pub cancelled: bool,
    pub creation: Digest,
}
impl Agreement {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(5)?;
        let out = Self {
            offer: Offer::parse(f[0].bytes()?, n, i)?,
            capability: version(&f[1])?,
            acceptance: if f[2] == V::Null {
                None
            } else {
                Some(Acceptance::parse(&f[2])?)
            },
            cancelled: f[3].boolean()?,
            creation: id(&f[4])?,
        };
        ensure!(
            out.capability.kind == 102
                && out
                    .acceptance
                    .as_ref()
                    .is_none_or(|a| a.expires <= out.offer.expires),
            "invalid transfer agreement"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.offer.envelope),
            reference(&self.capability),
            self.acceptance.as_ref().map_or(V::Null, Acceptance::value),
            V::Bool(self.cancelled),
            b(&self.creation),
        ])
    }
}
pub fn validate_agreement(
    value: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    let t = Agreement::parse(value, n, i)?;
    ensure!(
        lookup == t.offer.id
            && generation == 1 + u64::from(t.acceptance.is_some()) + u64::from(t.cancelled),
        "transfer agreement generation differs"
    );
    Ok(())
}
pub fn validate_state(state: &State) -> Result<()> {
    for r in state.records.values().filter(|r| r.reference.kind == 135) {
        let t = Agreement::parse(&r.payload, state.network, state.incarnation)?;
        if let Some(a) = t.acceptance {
            let s = state.record(134, a.service.id)?;
            ensure!(
                s.reference.generation >= a.service.generation
                    && (s.reference.generation != a.service.generation || s.reference == a.service),
                "accepted transfer store is missing or changed"
            );
        }
    }
    Ok(())
}
/// Canonical storage reserves the eventual complete byte string, including its CBOR header.
pub fn reservation_bytes(payload: u64) -> Result<u64> {
    ensure!(
        payload <= MAXIMUM_PAYLOAD,
        "transfer payload exceeds profile"
    );
    let empty = wire::encode(&a(vec![
        b(&[1; 32]),
        b(&[1; 32]),
        b(&[1; 32]),
        V::Uint(payload),
        V::Uint(u64::MAX),
        b(&[]),
        a(vec![]),
        V::Bool(false),
        V::Bool(false),
    ]))?
    .len() as u64;
    let header = if payload < 24 {
        1
    } else if payload <= 255 {
        2
    } else if payload <= 65535 {
        3
    } else {
        5
    };
    let chunks = payload.div_ceil(CHUNK);
    let chunk_header = if chunks < 24 { 1 } else { 2 };
    empty
        .checked_add(payload)
        .and_then(|n| n.checked_add(header - 1 + chunks * 34 + chunk_header - 1))
        .context("transfer storage reservation overflow")
}
pub fn disk_header_bytes() -> u64 {
    // The largest record-array header admits exactly the domain metadata record bound.
    wire::encode(&a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityTransferStorage".into()),
        b(&[1; 32]),
        b(&[1; 32]),
        b(&[1; 32]),
        V::Uint(u64::MAX),
        a(vec![]),
    ]))
    .expect("fixed storage header")
    .len() as u64
        + 2
}

#[cfg(test)]
#[path = "../../Transfers/AuthorityTransferTests.rs"]
mod tests;
