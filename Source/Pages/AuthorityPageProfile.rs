// SPDX-License-Identifier: MIT
// Hosting and application policy bind existing admissions to finite native Page rights.
use super::*;
use crate::runtime_manifest::Manifest;

#[derive(Clone, Debug)]
pub struct HostProfile {
    pub manifest: Manifest,
    pub role: u64,
    pub service: Key,
    pub volume: Digest,
    pub namespaces: Vec<String>,
    pub state_bytes: u64,
    pub maximum_asset_bytes: u64,
    pub retention_ms: u64,
    pub content: Option<ContentPolicy>,
    pub envelope: Vec<u8>,
}
impl HostProfile {
    pub fn cache_bytes(&self) -> Result<u64> {
        if self.content.is_none() {
            return Ok(self.state_bytes);
        }
        self.state_bytes
            .checked_sub(
                self.content
                    .as_ref()
                    .map_or(Ok(0), ContentPolicy::admission_bytes)?,
            )
            .filter(|n| *n >= 8192)
            .context("Page metadata cache has no reserved capacity")
    }

    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= crate::runtime_manifest::MAXIMUM + 2048,
            "Page host profile exceeds its bound"
        );
        let (bytes, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(12)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityPageHostProfile",
            "Page host profile tag differs"
        );
        let p = Self {
            manifest: Manifest::parse(f[3].bytes()?)?,
            role: f[4].uint()?,
            service: key(&f[5])?,
            volume: id(&f[6])?,
            namespaces: names(&f[7], 16)?,
            state_bytes: f[8].uint()?,
            maximum_asset_bytes: f[9].uint()?,
            retention_ms: f[10].uint()?,
            content: if f[11] == V::Null {
                None
            } else {
                Some(ContentPolicy::parse(&f[11])?)
            },
            envelope: envelope.to_vec(),
        };
        let role = p
            .manifest
            .roles
            .iter()
            .find(|r| r.role == p.role)
            .context("Page host role absent")?;
        let volume = p
            .manifest
            .volumes
            .iter()
            .find(|v| v.volume_id == p.volume)
            .context("Page host volume absent")?;
        ensure!(
            p.manifest.network == n
                && p.manifest.incarnation == i
                && matches!(p.role, 1 | 2)
                && signatures.len() == 1
                && signatures[0].0 == p.manifest.operator
                && role.service_key == p.service
                && role.volume_ids.contains(&p.volume)
                && !volume.read_only
                && p.state_bytes <= volume.storage_admission_bytes
                && p.state_bytes <= role.state_admission_bytes
                && p.maximum_asset_bytes > 0
                && p.maximum_asset_bytes <= p.state_bytes
                && p.maximum_asset_bytes
                    <= if p.role == 1 {
                        if p.content.is_some() {
                            8 * 1024 * 1024
                        } else {
                            crate::authority_objects::PAGE_BUNDLE_BYTES as u64
                        }
                    } else {
                        markup::media::MAX_PAGE_BYTES
                    }
                && (1..=MAXIMUM_LIFETIME_MS).contains(&p.retention_ms),
            "Page host profile exceeds exact operator consent"
        );
        serialized_bank_bytes(p.cache_bytes()?)?;
        if let Some(content) = &p.content {
            ensure!(
                !content.opaque
                    || (p.manifest.consent_policy.allow_opaque
                        && content.reviewers.iter().all(|key| p
                            .manifest
                            .consent_policy
                            .reviewer_roots
                            .contains(key))),
                "opaque content exceeds signed deployment consent or trusted reviewers"
            );
            ensure!(
                p.role == 1 && p.maximum_asset_bytes <= content.staging_bytes,
                "content storage requires a Page host and a complete staging reservation"
            );
        }
        if p.role == 2 {
            media_storage_budget(p.state_bytes)?;
        }
        Ok(p)
    }
}
#[derive(Clone, Debug)]
pub struct Host {
    pub profile: HostProfile,
    pub manager: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Host {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(4)?;
        Ok(Self {
            profile: HostProfile::parse(f[0].bytes()?, n, i)?,
            manager: key(&f[1])?,
            grant: required_version(&f[2], 102)?,
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

pub const APPLICATION_PERMISSIONS: [&str; 8] = [
    "MediaInspect",
    "MediaRead",
    "MediaSubmit",
    "PagesRead",
    "PagesSearch",
    "PagesSubmit",
    "ReviewDecide",
    "ReviewInspect",
];
#[derive(Clone, Debug)]
pub struct ApplicationPolicy {
    pub application: Key,
    pub owner: Key,
    pub registration: VersionRef,
    pub grant: VersionRef,
    pub namespaces: Vec<String>,
    pub pages: Option<Vec<[u8; 16]>>,
    pub permissions: Vec<String>,
    pub review: Option<(u64, Digest)>,
    pub expires_ms: u64,
    pub previous: Option<VersionRef>,
    pub envelope: Vec<u8>,
}
impl ApplicationPolicy {
    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= MAXIMUM_PROVENANCE,
            "Page application consent exceeds its bound"
        );
        let (bytes, signatures) = wire::envelope(envelope, 2)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(15)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityPageApplicationPolicy"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "Page application consent context differs"
        );
        let pages = if f[10] == V::Null {
            None
        } else {
            let pages = f[10]
                .list(16)?
                .iter()
                .map(V::fixed)
                .collect::<Result<Vec<[u8; 16]>>>()?;
            ensure!(
                !pages.is_empty()
                    && !pages.contains(&[0; 16])
                    && pages.windows(2).all(|w| w[0] < w[1]),
                "Page application page scope differs"
            );
            Some(pages)
        };
        let permissions = f[11]
            .list(APPLICATION_PERMISSIONS.len())?
            .iter()
            .map(|v| Ok(v.text()?.to_owned()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !permissions.is_empty()
                && permissions.windows(2).all(|w| w[0] < w[1])
                && permissions
                    .iter()
                    .all(|p| APPLICATION_PERMISSIONS.contains(&p.as_str())),
            "invalid Page application permission set"
        );
        let review = if f[12] == V::Null {
            None
        } else {
            let r = f[12].array(2)?;
            Some((r[0].uint()?, id(&r[1])?))
        };
        let p = Self {
            application: key(&f[5])?,
            owner: key(&f[6])?,
            registration: required_version(&f[7], 127)?,
            grant: required_version(&f[8], 102)?,
            namespaces: names(&f[9], 8)?,
            pages,
            permissions,
            review,
            expires_ms: f[13].uint()?,
            previous: optional_version(&f[14], 148)?,
            envelope: envelope.to_vec(),
        };
        let deciding = p.permissions.iter().any(|p| p == "ReviewDecide");
        ensure!(
            p.application != p.owner
                && p.registration.id == p.application
                && p.expires_ms > 0
                && p.previous.as_ref().is_none_or(|r| r.id == p.application)
                && deciding == p.review.is_some()
                && p.review
                    .as_ref()
                    .is_none_or(|(mode, _)| *mode <= 1
                        && p.permissions.iter().any(|p| p == "ReviewInspect"))
                && signatures.len() == 2
                && signatures.iter().any(|s| s.0 == p.owner)
                && signatures.iter().any(|s| s.0 == p.application),
            "Page application consent lacks exact possession or review restrictions"
        );
        Ok(p)
    }
    pub fn allows(&self, permission: &str, namespace: &str, page: Option<[u8; 16]>) -> bool {
        self.permissions.iter().any(|p| p == permission)
            && self.namespaces.iter().any(|n| n == namespace)
            && self
                .pages
                .as_ref()
                .is_none_or(|pages| page.is_some_and(|p| pages.contains(&p)))
    }
}

#[derive(Clone, Debug)]
pub struct PlacementPolicy {
    pub namespace: String,
    pub minimum_copies: u64,
    pub administrator: Key,
    pub grant: VersionRef,
}
impl PlacementPolicy {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(4)?;
        let out = Self {
            namespace: namespace(&f[0])?,
            minimum_copies: f[1].uint()?,
            administrator: key(&f[2])?,
            grant: required_version(&f[3], 102)?,
        };
        ensure!(
            (1..=3).contains(&out.minimum_copies),
            "media placement copy count exceeds declared host bounds"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Text(self.namespace.clone()),
            V::Uint(self.minimum_copies),
            b(&self.administrator),
            reference(&self.grant),
        ])
    }
}

#[cfg(test)]
include!("../../Tests/Support/Pages/AuthorityPageProfile.rs");
