// SPDX-License-Identifier: MIT
// Opaque mail storage is bounded by the exact operator-signed role-three deployment.
use super::*;
use crate::runtime_manifest::Manifest;
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
    pub fn parse(envelope: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= (crate::runtime_manifest::MAXIMUM + 1024),
            "mail profile exceeds its bound"
        );
        let (bytes, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(10)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityMailProfile",
            "invalid mail profile"
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
            .find(|r| r.role == 3)
            .context("mail role absent")?;
        let volume = m
            .volumes
            .iter()
            .find(|v| v.volume_id == p.volume)
            .context("mail volume absent")?;
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
            "mail profile exceeds its exact signed deployment consent"
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
        ensure!(out.grant.kind == 102, "mail manager grant differs");
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
        "mail service generation differs"
    );
    Ok(())
}

#[cfg(test)]
include!("../../Tests/Support/Mail/AuthorityMailProfile.rs");
