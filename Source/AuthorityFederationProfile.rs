// SPDX-License-Identifier: MIT
// Each bridge profile grants one service identity only its own network's installed resources.
use super::*;
use crate::runtime_manifest::Manifest;

#[derive(Clone, Debug)]
pub struct BridgeProfile {
    pub manifest: Manifest,
    pub service: Key,
    pub volume: Digest,
    pub agreements: Vec<(Digest, Digest)>,
    pub state_bytes: u64,
    pub envelope: Vec<u8>,
}
impl BridgeProfile {
    // Administrative clients construct the same canonical profile before operator signing.
    #[allow(dead_code)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityBridgeProfile".into()),
            b(&self.manifest.encode()?),
            b(&self.service),
            b(&self.volume),
            a(self
                .agreements
                .iter()
                .map(|(id, digest)| a(vec![b(id), b(digest)]))
                .collect()),
            V::Uint(self.state_bytes),
        ]))
    }
    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= crate::runtime_manifest::MAXIMUM + 16384,
            "bridge profile exceeds exact signed resource bound"
        );
        let (payload, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&payload)?;
        let f = value.array(8)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityBridgeProfile",
            "bridge profile format differs"
        );
        let out = Self {
            manifest: Manifest::parse(f[3].bytes()?)?,
            service: key(&f[4])?,
            volume: id(&f[5])?,
            agreements: f[6]
                .list(MAXIMUM_RECORDS)?
                .iter()
                .map(|v| {
                    let f = v.array(2)?;
                    Ok((id(&f[0])?, id(&f[1])?))
                })
                .collect::<Result<_>>()?,
            state_bytes: f[7].uint()?,
            envelope: envelope.to_vec(),
        };
        let role = out
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 7)
            .context("bridge role absent from manifest")?;
        let volume = out
            .manifest
            .volumes
            .iter()
            .find(|v| v.volume_id == out.volume)
            .context("bridge volume absent")?;
        ensure!(
            out.manifest.network == n
                && out.manifest.incarnation == i
                && signatures.len() == 1
                && signatures[0].0 == out.manifest.operator
                && role.service_key == out.service
                && role.volume_ids.contains(&out.volume)
                && !volume.read_only
                && out.state_bytes <= volume.storage_admission_bytes
                && out.state_bytes <= role.state_admission_bytes
                && !out.agreements.is_empty()
                && out.agreements.windows(2).all(|p| p[0].0 < p[1].0),
            "bridge profile exceeds its exact operator consent"
        );
        page::serialized_bank_bytes(out.state_bytes)?;
        Ok(out)
    }
}
#[derive(Clone, Debug)]
pub struct Bridge {
    pub profile: BridgeProfile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Bridge {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(4)?;
        Ok(Self {
            profile: BridgeProfile::parse(f[0].bytes()?, n, i)?,
            manager: key(&f[1])?,
            grant: exact_ref(&f[2], 102)?,
            withdrawn: f[3].boolean()?,
        })
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
