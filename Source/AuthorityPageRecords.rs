// SPDX-License-Identifier: MIT
// Page heads change monotonically while immutable revisions retain their exact provenance.
use super::*;

#[derive(Clone, Debug)]
pub struct Ledger {
    pub raw_page: [u8; 16],
    pub author: Key,
    pub namespace: String,
    pub last_revision: u64,
    pub pending: Option<VersionRef>,
    pub published: Option<VersionRef>,
}
impl Ledger {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(6)?;
        let out = Self {
            raw_page: f[0].fixed()?,
            author: key(&f[1])?,
            namespace: namespace(&f[2])?,
            last_revision: f[3].uint()?,
            pending: optional_version(&f[4], 141)?,
            published: optional_version(&f[5], 142)?,
        };
        ensure!(out.last_revision > 0, "Page ledger has no revision floor");
        page_id(&out.raw_page)?;
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.raw_page),
            b(&self.author),
            V::Text(self.namespace.clone()),
            V::Uint(self.last_revision),
            self.pending.as_ref().map_or(V::Null, reference),
            self.published.as_ref().map_or(V::Null, reference),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub id: String,
    pub recipient: Digest,
    pub owner: Key,
    pub schema: Digest,
}
impl Form {
    pub(super) fn parse(value: &V) -> Result<Self> {
        let f = value.array(4)?;
        Ok(Self {
            id: namespace(&f[0])?,
            recipient: id(&f[1])?,
            owner: key(&f[2])?,
            schema: id(&f[3])?,
        })
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Text(self.id.clone()),
            b(&self.recipient),
            b(&self.owner),
            b(&self.schema),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Revision {
    pub author: objects::Author,
    pub assets: Vec<markup::media::Asset>,
    pub forms: Vec<Form>,
}
impl Revision {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(3)?;
        let out = Self {
            author: objects::Author::parse(f[0].bytes()?, n, i)?,
            assets: f[1]
                .list(markup::media::MAX_ASSETS)?
                .iter()
                .map(objects::asset)
                .collect::<Result<_>>()?,
            forms: f[2]
                .list(markup::forms::MAX_FORMS)?
                .iter()
                .map(Form::parse)
                .collect::<Result<_>>()?,
        };
        markup::media::validate_assets(&out.assets).map_err(anyhow::Error::msg)?;
        ensure!(
            out.author.metadata.value()
                == objects::SourceMetadata {
                    assets: out.assets.clone(),
                    forms: out.forms.clone()
                }
                .value(),
            "Page revision metadata differs from signed author declaration"
        );
        ensure!(
            out.forms
                .iter()
                .map(|f| &f.id)
                .collect::<BTreeSet<_>>()
                .len()
                == out.forms.len(),
            "repeated Page form identity"
        );
        Ok(out)
    }
    pub fn from_author(author: objects::Author) -> Result<Self> {
        let metadata = objects::SourceMetadata::parse(&author.metadata.value())?;
        Ok(Self {
            author,
            assets: metadata.assets,
            forms: metadata.forms,
        })
    }
    pub fn from_source(author: objects::Author, bytes: &[u8]) -> Result<Self> {
        author.source.verify(bytes)?;
        ensure!(
            objects::SourceMetadata::from_source(bytes)?.value() == author.metadata.value(),
            "Page source differs from signed metadata"
        );
        Self::from_author(author)
    }
    pub fn identity(&self) -> Result<Digest> {
        revision_id(self.author.intent.resource, self.author.intent.revision)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.author.bytes),
            a(self.assets.iter().map(objects::asset_value).collect()),
            a(self.forms.iter().map(Form::value).collect()),
        ])
    }
    pub fn verify_source(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            Self::from_source(self.author.clone(), bytes)?.value() == self.value(),
            "Page metadata differs from exact inert source"
        );
        Ok(())
    }
}
pub fn revision_id(page: Digest, revision: u64) -> Result<Digest> {
    ensure!(revision > 0, "zero Page revision");
    identity("PageRevision", vec![b(&page), V::Uint(revision)])
}

#[derive(Clone, Debug)]
pub struct Review {
    pub statement: objects::Reviewer,
    pub bundle: Option<Reference>,
    pub recorded_ms: u64,
}
impl Review {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(3)?;
        let out = Self {
            statement: objects::Reviewer::parse(f[0].bytes()?, n, i)?,
            bundle: if f[1] == V::Null {
                None
            } else {
                Some(bundle(&f[1])?)
            },
            recorded_ms: f[2].uint()?,
        };
        ensure!(
            out.statement.approve == out.bundle.is_some()
                && out.recorded_ms > 0
                && out.recorded_ms < out.statement.expires_ms
                && out.statement.expires_ms - out.recorded_ms <= REVIEW_LIFETIME_MS,
            "Page decision, deadline or bundle disagree"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.statement.bytes),
            self.bundle.as_ref().map_or(V::Null, Reference::value),
            V::Uint(self.recorded_ms),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct Asset {
    pub revision: VersionRef,
    pub manifest: markup::media::Asset,
    pub hosts: Vec<VersionRef>,
    pub required_copies: u64,
    pub upload_expires_ms: u64,
    pub expires_ms: u64,
}
impl Asset {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(6)?;
        let out = Self {
            revision: {
                let r = version(&f[0])?;
                ensure!(
                    matches!(r.kind, 141 | 155),
                    "media origin is not a native or qualified revision"
                );
                r
            },
            manifest: objects::asset(&f[1])?,
            hosts: f[2]
                .list(3)?
                .iter()
                .map(|v| required_version(v, 143))
                .collect::<Result<_>>()?,
            required_copies: f[3].uint()?,
            upload_expires_ms: f[4].uint()?,
            expires_ms: f[5].uint()?,
        };
        validate_versions(&out.hosts, 3)?;
        let mut hosts = out
            .manifest
            .hosts
            .iter()
            .map(|h| {
                hex::decode(h)
                    .map_err(anyhow::Error::from)
                    .and_then(|b| key(&V::Bytes(b)))
            })
            .collect::<Result<Vec<_>>>()?;
        hosts.sort();
        ensure!(
            (out.revision.kind == 155 || out.hosts.iter().map(|r| r.id).eq(hosts))
                && out.required_copies >= out.manifest.copies.into()
                && out.required_copies <= out.hosts.len() as u64
                && out.upload_expires_ms > 0
                && out.upload_expires_ms <= out.expires_ms,
            "Page asset placement differs"
        );
        Ok(out)
    }
    pub fn identity(&self) -> Result<Digest> {
        asset_id(&self.revision, &self.manifest.id)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.revision),
            objects::asset_value(&self.manifest),
            a(self.hosts.iter().map(reference).collect()),
            V::Uint(self.required_copies),
            V::Uint(self.upload_expires_ms),
            V::Uint(self.expires_ms),
        ])
    }
}
pub fn asset_id(revision: &VersionRef, asset: &str) -> Result<Digest> {
    ensure!(
        matches!(revision.kind, 141 | 155) && markup::namespace(asset),
        "invalid Page asset identity"
    );
    identity(
        "PageAsset",
        vec![reference(revision), V::Text(asset.into())],
    )
}

#[derive(Clone, Debug)]
pub struct CopyReceipt {
    pub asset: VersionRef,
    pub host: VersionRef,
    pub request: Digest,
    pub digest: Digest,
    pub bytes: u64,
    pub recorded_ms: u64,
    pub envelope: Vec<u8>,
}
impl CopyReceipt {
    pub fn parse(envelope: &[u8], n: Digest, i: Digest) -> Result<Self> {
        ensure!(envelope.len() <= 2048, "media receipt exceeds its bound");
        let (bytes, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&bytes)?;
        let f = value.array(11)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityPageMediaReceipt"
                && id(&f[3])? == n
                && id(&f[4])? == i,
            "media receipt context differs"
        );
        let out = Self {
            asset: required_version(&f[5], 144)?,
            host: required_version(&f[6], 143)?,
            request: id(&f[7])?,
            digest: id(&f[8])?,
            bytes: f[9].uint()?,
            recorded_ms: f[10].uint()?,
            envelope: envelope.to_vec(),
        };
        ensure!(
            out.bytes > 0
                && out.bytes <= markup::media::MAX_PAGE_BYTES
                && out.recorded_ms > 0
                && signatures.len() == 1
                && signatures[0].0 == out.host.id,
            "media receipt signer or size differs"
        );
        Ok(out)
    }
    pub fn payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityPageMediaReceipt".into()),
            b(&n),
            b(&i),
            reference(&self.asset),
            reference(&self.host),
            b(&self.request),
            b(&self.digest),
            V::Uint(self.bytes),
            V::Uint(self.recorded_ms),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Inspection {
    pub reviewer: Key,
    pub grant: VersionRef,
    pub application: Option<VersionRef>,
    pub intent: Digest,
    pub expires_ms: u64,
}
impl Inspection {
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(5)?;
        let out = Self {
            reviewer: key(&f[0])?,
            grant: required_version(&f[1], 102)?,
            application: optional_version(&f[2], 148)?,
            intent: id(&f[3])?,
            expires_ms: f[4].uint()?,
        };
        ensure!(out.expires_ms > 0, "media inspection expiry missing");
        Ok(out)
    }
    fn value(&self) -> V {
        a(vec![
            b(&self.reviewer),
            reference(&self.grant),
            self.application.as_ref().map_or(V::Null, reference),
            b(&self.intent),
            V::Uint(self.expires_ms),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Evidence {
    pub asset: VersionRef,
    pub copies: Vec<CopyReceipt>,
    pub inspections: Vec<Inspection>,
}
impl Evidence {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.array(3)?;
        let out = Self {
            asset: required_version(&f[0], 144)?,
            copies: f[1]
                .list(3)?
                .iter()
                .map(|v| CopyReceipt::parse(v.bytes()?, n, i))
                .collect::<Result<_>>()?,
            inspections: f[2]
                .list(4096)?
                .iter()
                .map(Inspection::parse)
                .collect::<Result<_>>()?,
        };
        ensure!(
            out.copies.windows(2).all(|w| w[0].host.id < w[1].host.id)
                && out.copies.iter().all(|r| r.asset == out.asset)
                && out
                    .inspections
                    .windows(2)
                    .all(|w| w[0].reviewer < w[1].reviewer),
            "media evidence is not exact and unique"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.asset),
            a(self.copies.iter().map(|r| b(&r.envelope)).collect()),
            a(self.inspections.iter().map(Inspection::value).collect()),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct Ticket {
    pub publication: VersionRef,
    pub reader: Key,
    pub grant: VersionRef,
    pub application: Option<VersionRef>,
    pub host: VersionRef,
    pub expires_ms: u64,
    pub delivered: Option<Reference>,
    pub creation: Digest,
}
impl Ticket {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(8)?;
        let out = Self {
            publication: required_version(&f[0], 142)?,
            reader: key(&f[1])?,
            grant: required_version(&f[2], 102)?,
            application: optional_version(&f[3], 148)?,
            host: required_version(&f[4], 147)?,
            expires_ms: f[5].uint()?,
            delivered: if f[6] == V::Null {
                None
            } else {
                Some(bundle(&f[6])?)
            },
            creation: id(&f[7])?,
        };
        ensure!(out.expires_ms > 0, "Page replica ticket expiry absent");
        Ok(out)
    }
    pub fn identity(&self) -> Result<Digest> {
        ticket_id(self.reader, self.host.id)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.publication),
            b(&self.reader),
            reference(&self.grant),
            self.application.as_ref().map_or(V::Null, reference),
            reference(&self.host),
            V::Uint(self.expires_ms),
            self.delivered.as_ref().map_or(V::Null, Reference::value),
            b(&self.creation),
        ])
    }
}
pub fn ticket_id(reader: Key, host: Key) -> Result<Digest> {
    identity("PageReplicaSlot", vec![b(&reader), b(&host)])
}

pub fn validate_record(
    kind: u64,
    value: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    if matches!(kind, 159..=161) {
        return content::validate_record(kind, value, n, i, lookup, generation);
    }
    let correct = match kind {
        140 => {
            let p = Ledger::parse(value)?;
            page_id(&p.raw_page)? == lookup && p.last_revision <= generation
        }
        141 => Revision::parse(value, n, i)?.identity()? == lookup && generation == 1,
        142 => Review::parse(value, n, i)?.statement.revision.id == lookup && generation == 1,
        143 | 147 => {
            let p = Host::parse(value, n, i)?;
            p.profile.service == lookup
                && p.profile.role == if kind == 143 { 2 } else { 1 }
                && generation == 1 + u64::from(p.withdrawn)
        }
        144 => Asset::parse(value)?.identity()? == lookup && generation == 1,
        145 => Evidence::parse(value, n, i)?.asset.id == lookup,
        146 => Ticket::parse(value)?.identity()? == lookup,
        148 => {
            let p = ApplicationPolicy::parse(value.bytes()?, n, i)?;
            p.application == lookup
                && match p.previous {
                    None => generation == 1,
                    Some(r) => r.generation.checked_add(1) == Some(generation),
                }
        }
        149 => namespace_id(&PlacementPolicy::parse(value)?.namespace)? == lookup,
        _ => false,
    };
    ensure!(correct, "Page record identity or generation differs");
    Ok(())
}

pub fn validate_state(state: &State) -> Result<()> {
    validate_records(state, false)
}
/// Requester context can name an undisclosed pending revision without exposing its metadata.
/// Every present record is still structurally checked and authenticated by its retained quorum floor.
pub fn validate_context(state: &State) -> Result<()> {
    validate_records(state, true)
}
fn dependencies_present(state: &State, record: &Record) -> Result<bool> {
    let references = match record.reference.kind {
        140 => {
            let p = Ledger::parse(&record.payload)?;
            p.pending.into_iter().chain(p.published).collect::<Vec<_>>()
        }
        142 => vec![
            Review::parse(&record.payload, state.network, state.incarnation)?
                .statement
                .revision,
        ],
        144 => {
            let p = Asset::parse(&record.payload)?;
            std::iter::once(p.revision).chain(p.hosts).collect()
        }
        145 => vec![Evidence::parse(&record.payload, state.network, state.incarnation)?.asset],
        146 => {
            let p = Ticket::parse(&record.payload)?;
            vec![p.publication, p.host]
        }
        _ => vec![],
    };
    let mut complete = true;
    for reference in references {
        let Some(dependency) = state.records.get(&reference.index()) else {
            complete = false;
            continue;
        };
        ensure!(
            dependency.reference == reference
                || matches!(reference.kind, 143 | 147)
                    && dependency.reference.generation > reference.generation,
            "available Page context dependency differs"
        );
        // These finite schemas form the DAG ledger/ticket -> review/asset -> revision/host.
        complete &= dependencies_present(state, dependency)?;
    }
    Ok(complete)
}
fn validate_records(state: &State, partial: bool) -> Result<()> {
    let exact = |r: &VersionRef| -> Result<&Record> {
        let selected = state.record(r.kind, r.id)?;
        ensure!(selected.reference == *r, "Page domain dependency differs");
        Ok(selected)
    };
    for r in state.records.values() {
        if partial && !dependencies_present(state, r)? {
            continue;
        }
        match r.reference.kind {
            140 => {
                let ledger = Ledger::parse(&r.payload)?;
                if let Some(pending) = ledger.pending {
                    let p = Revision::parse(
                        &exact(&pending)?.payload,
                        state.network,
                        state.incarnation,
                    )?;
                    ensure!(
                        p.author.raw_page == ledger.raw_page
                            && p.author.intent.requester == ledger.author
                            && p.author.namespace == ledger.namespace
                            && p.author.intent.revision == ledger.last_revision,
                        "pending Page differs from its ledger"
                    );
                }
                if let Some(published) = ledger.published {
                    let p = Review::parse(
                        &exact(&published)?.payload,
                        state.network,
                        state.incarnation,
                    )?;
                    let source = Revision::parse(
                        &exact(&p.statement.revision)?.payload,
                        state.network,
                        state.incarnation,
                    )?;
                    ensure!(
                        p.statement.approve
                            && source.author.raw_page == ledger.raw_page
                            && source.author.intent.requester == ledger.author
                            && source.author.namespace == ledger.namespace,
                        "published Page differs from its ledger"
                    );
                }
            }
            142 => {
                let p = Review::parse(&r.payload, state.network, state.incarnation)?;
                let revision = Revision::parse(
                    &exact(&p.statement.revision)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    p.statement.source == revision.author.source
                        && p.statement.author == revision.author.intent.requester
                        && p.statement.author_statement == revision.author.intent.digest
                        && p.statement.intent.resource == revision.author.intent.resource
                        && p.statement.intent.revision == revision.author.intent.revision,
                    "Page review differs from exact submission"
                );
            }
            144 => {
                let asset = Asset::parse(&r.payload)?;
                let revision = if asset.revision.kind == 141 {
                    Revision::parse(
                        &exact(&asset.revision)?.payload,
                        state.network,
                        state.incarnation,
                    )?
                } else {
                    super::super::federation::ForeignRevision::parse(
                        &exact(&asset.revision)?.payload,
                    )?
                    .metadata
                };
                ensure!(
                    revision.assets.contains(&asset.manifest),
                    "media asset is absent from exact Page revision"
                );
                for host in &asset.hosts {
                    let record = state.record(host.kind, host.id)?;
                    ensure!(
                        record.reference.generation >= host.generation,
                        "media host history is missing"
                    );
                }
            }
            145 => {
                let evidence = Evidence::parse(&r.payload, state.network, state.incarnation)?;
                let asset = Asset::parse(&exact(&evidence.asset)?.payload)?;
                for receipt in evidence.copies {
                    ensure!(
                        asset.hosts.contains(&receipt.host)
                            && hex::encode(receipt.digest) == asset.manifest.digest
                            && receipt.bytes == asset.manifest.bytes,
                        "media receipt differs from reserved asset"
                    );
                }
            }
            146 => {
                let ticket = Ticket::parse(&r.payload)?;
                let review = Review::parse(
                    &exact(&ticket.publication)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    review.statement.approve
                        && ticket
                            .delivered
                            .as_ref()
                            .is_none_or(|b| Some(b) == review.bundle.as_ref())
                        && state.record(147, ticket.host.id)?.reference.generation
                            >= ticket.host.generation,
                    "Page replica ticket differs from exact publication"
                );
            }
            _ => {}
        }
    }
    Ok(())
}
pub fn retained_inputs(_state: &State) -> Result<Vec<Reference>> {
    Ok(vec![])
}
