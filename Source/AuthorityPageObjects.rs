// SPDX-License-Identifier: MIT
// Portable Page statements use the existing signed Intent schema without online dispatch.
use super::*;

#[derive(Clone, Debug)]
pub struct Author {
    pub intent: Intent,
    pub raw_page: [u8; 16],
    pub namespace: String,
    pub source: Reference,
    pub grant: VersionRef,
    pub application: Option<VersionRef>,
    pub expires_ms: u64,
    pub bytes: Vec<u8>,
}
fn statement(bytes: &[u8], n: Digest, i: Digest, action: &str) -> Result<Intent> {
    ensure!(
        bytes.len() <= MAXIMUM_PROVENANCE,
        "Page provenance exceeds its bound"
    );
    let intent = Intent::from_signed(bytes)?;
    ensure!(
        intent.network == n
            && intent.incarnation == i
            && intent.action == action
            && intent.profile_generation == 0
            && intent.expected.is_empty(),
        "Page provenance context differs"
    );
    Ok(intent)
}
impl Author {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let intent = statement(bytes, n, i, "PageAuthorStatement")?;
        let value = wire::decode(&intent.parameters)?;
        let f = value.array(11)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "PageAuthorStatement"
                && f[5].uint()? == 0
                && f[6].text()? == markup::PROFILE,
            "Page author statement profile differs"
        );
        let raw_page = f[3].fixed()?;
        let namespace = namespace(&f[4])?;
        let source = source(&f[7])?;
        let grant = required_version(&f[8], 102)?;
        let application = optional_version(&f[9], 148)?;
        let expires_ms = f[10].uint()?;
        ensure!(
            intent.resource == page_id(&raw_page)? && intent.revision > 0 && expires_ms > 0,
            "Page author statement identity differs"
        );
        Ok(Self {
            intent,
            raw_page,
            namespace,
            source,
            grant,
            application,
            expires_ms,
            bytes: bytes.to_vec(),
        })
    }
    #[cfg(test)]
    pub fn parameters(
        raw_page: [u8; 16],
        namespace: &str,
        source: &Reference,
        grant: &VersionRef,
        application: Option<&VersionRef>,
        expires_ms: u64,
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageAuthorStatement".into()),
            b(&raw_page),
            V::Text(namespace.into()),
            V::Uint(0),
            V::Text(markup::PROFILE.into()),
            source.value(),
            reference(grant),
            application.map_or(V::Null, reference),
            V::Uint(expires_ms),
        ]))
    }
}

#[derive(Clone, Debug)]
pub struct Reviewer {
    pub intent: Intent,
    pub revision: VersionRef,
    pub source: Reference,
    pub author: Key,
    pub author_statement: Digest,
    pub grant: VersionRef,
    pub application: Option<VersionRef>,
    pub approve: bool,
    pub mode: u64,
    pub policy: Option<Digest>,
    pub expires_ms: u64,
    pub bytes: Vec<u8>,
}
impl Reviewer {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let intent = statement(bytes, n, i, "PageReviewStatement")?;
        let value = wire::decode(&intent.parameters)?;
        let f = value.array(13)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "PageReviewStatement",
            "Page review statement profile differs"
        );
        let out = Self {
            intent,
            revision: required_version(&f[3], 141)?,
            source: source(&f[4])?,
            author: key(&f[5])?,
            author_statement: id(&f[6])?,
            grant: required_version(&f[7], 102)?,
            application: optional_version(&f[8], 148)?,
            approve: f[9].boolean()?,
            mode: f[10].uint()?,
            policy: optional_id(&f[11])?,
            expires_ms: f[12].uint()?,
            bytes: bytes.to_vec(),
        };
        ensure!(
            out.mode <= 1
                && out.expires_ms > 0
                && out.intent.revision > 0
                && (out.application.is_some() == out.policy.is_some())
                && (out.application.is_some() || out.mode == 0),
            "Page review provenance restrictions differ"
        );
        Ok(out)
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn parameters(
        revision: &VersionRef,
        source: &Reference,
        author: Key,
        author_statement: Digest,
        grant: &VersionRef,
        application: Option<&VersionRef>,
        approve: bool,
        mode: u64,
        policy: Option<Digest>,
        expires_ms: u64,
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageReviewStatement".into()),
            reference(revision),
            source.value(),
            b(&author),
            b(&author_statement),
            reference(grant),
            application.map_or(V::Null, reference),
            V::Bool(approve),
            V::Uint(mode),
            policy.as_ref().map_or(V::Null, |v| b(v)),
            V::Uint(expires_ms),
        ]))
    }
}

#[derive(Clone, Debug)]
pub struct Bundle {
    pub author: Author,
    pub review: Reviewer,
    pub source: Vec<u8>,
}
impl Bundle {
    #[cfg(test)]
    pub fn encode(source: &[u8], author: &[u8], review: &[u8]) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ApprovedPageBundle".into()),
            b(source),
            b(author),
            b(review),
        ]))
    }
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(
            bytes.len() <= crate::authority_objects::PAGE_BUNDLE_BYTES,
            "Page bundle exceeds its bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(6)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "ApprovedPageBundle",
            "Page bundle profile differs"
        );
        let source = f[3].bytes()?.to_vec();
        let author = Author::parse(f[4].bytes()?, n, i)?;
        let review = Reviewer::parse(f[5].bytes()?, n, i)?;
        author.source.verify(&source)?;
        let document = markup::parse(std::str::from_utf8(&source)?).map_err(anyhow::Error::msg)?;
        ensure!(
            review.approve
                && review.source == author.source
                && review.author == author.intent.requester
                && review.author_statement == author.intent.digest
                && review.intent.resource == author.intent.resource
                && review.intent.revision == author.intent.revision
                && (document.forms.is_empty() || bytes.len() <= markup::forms::MAX_BUNDLE_BYTES),
            "Page bundle does not bind one exact author and approved revision"
        );
        Ok(Self {
            author,
            review,
            source,
        })
    }
}

pub fn asset_value(asset: &markup::media::Asset) -> V {
    a(vec![
        V::Text(asset.id.clone()),
        V::Text(asset.profile.clone()),
        V::Uint(asset.width.into()),
        V::Uint(asset.height.into()),
        V::Uint(asset.bytes),
        V::Text(asset.digest.clone()),
        a(asset.hosts.iter().map(|h| V::Text(h.clone())).collect()),
        V::Uint(asset.copies.into()),
    ])
}
pub fn asset(value: &V) -> Result<markup::media::Asset> {
    let f = value.array(8)?;
    let asset = markup::media::Asset {
        id: namespace(&f[0])?,
        profile: f[1].text()?.into(),
        width: u32::try_from(f[2].uint()?)?,
        height: u32::try_from(f[3].uint()?)?,
        bytes: f[4].uint()?,
        digest: f[5].text()?.into(),
        hosts: f[6]
            .list(3)?
            .iter()
            .map(|v| Ok(v.text()?.into()))
            .collect::<Result<_>>()?,
        copies: u16::try_from(f[7].uint()?)?,
    };
    markup::media::validate_asset(&asset).map_err(anyhow::Error::msg)?;
    Ok(asset)
}
