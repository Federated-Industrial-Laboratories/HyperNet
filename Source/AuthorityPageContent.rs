// SPDX-License-Identifier: MIT
// Content placement binds immutable bytes to explicit hosts before publication can become serving.
use super::*;

#[path = "AuthorityPageContentAuthorise.rs"]
mod authorise;
use crate::authority_domains::sealed_publication as sealed;
pub use authorise::Effect;
#[path = "AuthorityPageContentPlacement.rs"]
mod placement;
pub(crate) use placement::{select_placement, select_replica};

pub const PLACEMENT_KIND: u64 = 159;
pub const COPIES_KIND: u64 = 160;
pub const TOMBSTONE_KIND: u64 = 161;
#[derive(Clone, Debug)]
pub struct Placement {
    pub revision: VersionRef,
    pub owner: Key,
    pub grant: VersionRef,
    pub namespace: String,
    pub digest: Digest,
    pub bytes: u64,
    pub opaque: bool,
    pub hosts: Vec<VersionRef>,
    pub copies: u64,
    pub failure_domains: u64,
    pub expires_ms: u64,
}
impl Placement {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(11)?;
        let p = Self {
            revision: version(&f[0])?,
            owner: key(&f[1])?,
            grant: required_version(&f[2], 102)?,
            namespace: namespace(&f[3])?,
            digest: id(&f[4])?,
            bytes: f[5].uint()?,
            opaque: f[6].boolean()?,
            hosts: f[7]
                .list(16)?
                .iter()
                .map(|v| required_version(v, 147))
                .collect::<Result<_>>()?,
            copies: f[8].uint()?,
            failure_domains: f[9].uint()?,
            expires_ms: f[10].uint()?,
        };
        validate_versions(&p.hosts, 16)?;
        ensure!(
            matches!(p.revision.kind, 141 | 113)
                && p.bytes > 0
                && p.copies > 0
                && p.copies <= p.hosts.len() as u64
                && p.failure_domains > 0
                && p.failure_domains <= p.copies
                && p.expires_ms > 0
                && p.opaque == (p.revision.kind == 113),
            "content placement scope differs"
        );
        Ok(p)
    }
    pub fn identity(&self) -> Result<Digest> {
        identity(
            "PageContentPlacement",
            vec![reference(&self.revision), b(&self.digest)],
        )
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.revision),
            b(&self.owner),
            reference(&self.grant),
            V::Text(self.namespace.clone()),
            b(&self.digest),
            V::Uint(self.bytes),
            V::Bool(self.opaque),
            a(self.hosts.iter().map(reference).collect()),
            V::Uint(self.copies),
            V::Uint(self.failure_domains),
            V::Uint(self.expires_ms),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Copy {
    pub placement: VersionRef,
    pub host: VersionRef,
    pub digest: Digest,
    pub bytes: u64,
    pub request: Digest,
    pub recorded_ms: u64,
    pub expires_ms: u64,
    pub envelope: Vec<u8>,
}
impl Copy {
    pub fn parse(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(bytes.len() <= 2048, "durable copy receipt exceeds bound");
        let (payload, signers) = wire::envelope(bytes, 1)?;
        let v = wire::decode(&payload)?;
        let f = v.array(12)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "PageContentCopy"
                && id(&f[3])? == network
                && id(&f[4])? == incarnation,
            "durable copy context differs"
        );
        let r = Self {
            placement: required_version(&f[5], PLACEMENT_KIND)?,
            host: required_version(&f[6], 147)?,
            digest: id(&f[7])?,
            bytes: f[8].uint()?,
            request: id(&f[9])?,
            recorded_ms: f[10].uint()?,
            expires_ms: f[11].uint()?,
            envelope: bytes.to_vec(),
        };
        ensure!(
            r.bytes > 0
                && r.recorded_ms > 0
                && r.recorded_ms < r.expires_ms
                && signers.len() == 1
                && signers[0].0 == r.host.id,
            "durable copy signer or lifetime differs"
        );
        Ok(r)
    }
    pub fn payload(&self, network: Digest, incarnation: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageContentCopy".into()),
            b(&network),
            b(&incarnation),
            reference(&self.placement),
            reference(&self.host),
            b(&self.digest),
            V::Uint(self.bytes),
            b(&self.request),
            V::Uint(self.recorded_ms),
            V::Uint(self.expires_ms),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Copies {
    pub placement: VersionRef,
    pub copies: Vec<Copy>,
}
impl Copies {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(2)?;
        let p = Self {
            placement: required_version(&f[0], PLACEMENT_KIND)?,
            copies: f[1]
                .list(16)?
                .iter()
                .map(|v| Copy::parse(v.bytes()?, n, i))
                .collect::<Result<_>>()?,
        };
        ensure!(
            p.copies.windows(2).all(|w| w[0].host.id < w[1].host.id)
                && p.copies.iter().all(|r| r.placement == p.placement),
            "durable copies repeat or refer to another placement"
        );
        Ok(p)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.placement),
            a(self.copies.iter().map(|r| b(&r.envelope)).collect()),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Tombstone {
    pub placement: VersionRef,
    pub withdrawn_ms: u64,
}
impl Tombstone {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(2)?;
        let p = Self {
            placement: required_version(&f[0], PLACEMENT_KIND)?,
            withdrawn_ms: f[1].uint()?,
        };
        ensure!(p.withdrawn_ms > 0, "content tombstone lacks time");
        Ok(p)
    }
    pub fn value(&self) -> V {
        a(vec![reference(&self.placement), V::Uint(self.withdrawn_ms)])
    }
}
pub fn validate_record(
    kind: u64,
    v: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    let expected = match kind {
        PLACEMENT_KIND => {
            ensure!(generation == 1, "immutable content placement changed");
            Placement::parse(v)?.identity()?
        }
        COPIES_KIND => Copies::parse(v, n, i)?.placement.id,
        TOMBSTONE_KIND => {
            ensure!(generation == 1, "content tombstone changed");
            Tombstone::parse(v)?.placement.id
        }
        _ => anyhow::bail!("unknown content record"),
    };
    ensure!(lookup == expected, "content lookup differs");
    Ok(())
}
#[derive(Clone, Debug)]
pub enum Command {
    Authorise {
        placement: VersionRef,
        host: VersionRef,
        effect: Effect,
        offset: u64,
        bytes: u64,
        digest: Option<Digest>,
    },
    Place {
        revision: VersionRef,
        hosts: Vec<VersionRef>,
        copies: u64,
        failure_domains: u64,
        expires_ms: u64,
    },
    Get {
        placement: VersionRef,
    },
    Receipt {
        receipt: Copy,
    },
    Withdraw {
        placement: VersionRef,
    },
}
impl Command {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.list(7)?;
        Ok(match f.first().context("empty content command")?.text()? {
            "PageContentAuthorise" => {
                let f = value.array(7)?;
                let effect = Effect::parse(&f[3])?;
                let offset = f[4].uint()?;
                let bytes = f[5].uint()?;
                let digest = if f[6] == V::Null {
                    None
                } else {
                    Some(id(&f[6])?)
                };
                ensure!(
                    (effect == Effect::Purge && offset == 0 && bytes == 0 && digest.is_none())
                        || (effect != Effect::Purge
                            && bytes > 0
                            && bytes
                                <= if effect == Effect::Search {
                                    crate::markup::MAX_BYTES as u64
                                } else {
                                    32768
                                }
                            && (effect != Effect::Search || offset == 0)
                            && offset.checked_add(bytes).is_some()
                            && digest.is_some()
                                == matches!(effect, Effect::Upload | Effect::Repair)),
                    "content effect extent differs"
                );
                Self::Authorise {
                    placement: required_version(&f[1], PLACEMENT_KIND)?,
                    host: required_version(&f[2], 147)?,
                    effect,
                    offset,
                    bytes,
                    digest,
                }
            }
            "PageContentPlace" => {
                let f = value.array(6)?;
                let hosts = f[2]
                    .list(16)?
                    .iter()
                    .map(|v| required_version(v, 147))
                    .collect::<Result<Vec<_>>>()?;
                validate_versions(&hosts, 16)?;
                let copies = f[3].uint()?;
                let failure_domains = f[4].uint()?;
                ensure!(
                    copies > 0
                        && copies <= hosts.len() as u64
                        && failure_domains > 0
                        && failure_domains <= copies,
                    "invalid content placement policy"
                );
                Self::Place {
                    revision: required_version(&f[1], 141)?,
                    hosts,
                    copies,
                    failure_domains,
                    expires_ms: f[5].uint()?,
                }
            }
            "PageContentGet" => Self::Get {
                placement: required_version(&value.array(2)?[1], PLACEMENT_KIND)?,
            },
            "PageContentReceipt" => Self::Receipt {
                receipt: Copy::parse(value.array(2)?[1].bytes()?, n, i)?,
            },
            "PageContentWithdraw" => Self::Withdraw {
                placement: required_version(&value.array(2)?[1], PLACEMENT_KIND)?,
            },
            _ => anyhow::bail!("unknown content command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Authorise { .. } => "PageContentAuthorise",
            Self::Place { .. } => "PageContentPlace",
            Self::Get { .. } => "PageContentGet",
            Self::Receipt { .. } => "PageContentReceipt",
            Self::Withdraw { .. } => "PageContentWithdraw",
        }
    }
    pub fn value(&self) -> V {
        let mut v = vec![V::Text(self.name().into())];
        v.extend(match self {
            Self::Authorise {
                placement,
                host,
                effect,
                offset,
                bytes,
                digest,
            } => vec![
                reference(placement),
                reference(host),
                V::Uint(effect.code()),
                V::Uint(*offset),
                V::Uint(*bytes),
                digest.map_or(V::Null, |d| b(&d)),
            ],
            Self::Place {
                revision,
                hosts,
                copies,
                failure_domains,
                expires_ms,
            } => vec![
                reference(revision),
                a(hosts.iter().map(reference).collect()),
                V::Uint(*copies),
                V::Uint(*failure_domains),
                V::Uint(*expires_ms),
            ],
            Self::Get { placement } | Self::Withdraw { placement } => vec![reference(placement)],
            Self::Receipt { receipt } => vec![b(&receipt.envelope)],
        });
        a(v)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Authorise { placement, .. } => placement.id,
            Self::Place { revision, .. } => revision.id,
            Self::Get { placement } | Self::Withdraw { placement } => placement.id,
            Self::Receipt { receipt } => receipt.placement.id,
        }
    }
    pub fn mutation(&self) -> bool {
        !matches!(self, Self::Get { .. } | Self::Authorise { .. })
    }
    pub fn mutation_indices(&self, state: &State) -> Result<Vec<(u64, Digest)>> {
        Ok(match self {
            Self::Place { revision, .. } => {
                let revision = Revision::parse(
                    &state.record(141, revision.id)?.payload,
                    state.network,
                    state.incarnation,
                )?;
                vec![(PLACEMENT_KIND, placement_id(&revision)?)]
            }
            Self::Get { .. } | Self::Authorise { .. } => vec![],
            Self::Receipt { receipt } => vec![(COPIES_KIND, receipt.placement.id)],
            Self::Withdraw { placement } => vec![(TOMBSTONE_KIND, placement.id)],
        })
    }
}
pub fn placement_id(revision: &Revision) -> Result<Digest> {
    let record = Record::next(
        &State::empty(
            revision.author.intent.network,
            revision.author.intent.incarnation,
        ),
        141,
        revision.identity()?,
        revision.value(),
    )?;
    identity(
        "PageContentPlacement",
        vec![
            reference(&record.reference),
            b(&revision.author.source.content_sha256()),
        ],
    )
}

pub(crate) fn live(c: &mut Evaluation<'_>, reference: &VersionRef) -> Result<Placement> {
    let r = c.exact(reference)?;
    let p = Placement::parse(&r.payload)?;
    ensure!(
        p.expires_ms > c.at
            && !c
                .state
                .records
                .contains_key(&(TOMBSTONE_KIND, reference.id)),
        "content placement expired or withdrawn"
    );
    if p.opaque {
        let (outer, state, policy) = sealed::live(c, &p.revision)?;
        ensure!(
            state.placement == *reference
                && p.owner == policy.publisher
                && p.namespace == state.namespace
                && p.digest == outer.ciphertext
                && p.bytes == outer.bytes
                && p.grant == state.author_grant,
            "opaque placement differs from sealed publication"
        );
        c.expires = c.expires.min(p.expires_ms);
        return Ok(p);
    }
    let revision = c.revision(&p.revision, true)?;
    let (_, ledger) = c.ledger(revision.author.raw_page)?;
    ensure!(
        ledger.pending.as_ref() == Some(&p.revision)
            || ledger
                .published
                .as_ref()
                .is_some_and(|r| r.id == p.revision.id),
        "content revision is no longer current"
    );
    ensure!(
        revision.author.intent.requester == p.owner
            && revision.author.namespace == p.namespace
            && revision.author.source.content_sha256() == p.digest
            && revision.author.source.len() as u64 == p.bytes,
        "content placement differs from its revision"
    );
    c.principal(
        p.owner,
        &p.grant,
        revision.author.application.as_ref(),
        "PagesSubmit",
        &p.namespace,
        Some(revision.author.raw_page),
        p.bytes,
    )?;
    c.expires = c.expires.min(p.expires_ms);
    Ok(p)
}
fn owner_scope(
    c: &mut Evaluation<'_>,
    p: &Placement,
    requester: Key,
    grant: &VersionRef,
) -> Result<()> {
    ensure!(requester == p.owner, "content operation requires its owner");
    let resource = if p.opaque {
        let record = c.exact(&p.revision)?;
        let outer = sealed::Outer::parse(&record.bytes, c.state.network, c.state.incarnation)?;
        ensure!(
            outer.ciphertext == p.digest && outer.bytes == p.bytes,
            "opaque owner scope differs"
        );
        outer.object
    } else {
        c.revision(&p.revision, false)?.author.intent.resource
    };
    c.capability(grant, requester, &[2], (2, resource), Some(&p.namespace), 0)
}
// Shared by metadata lookup and the single-state certified Page view.
pub(crate) fn get(
    c: &mut Evaluation<'_>,
    operation: &Operation,
    placement: &VersionRef,
    intent: &Intent,
) -> Result<()> {
    use super::evaluation::grant;
    let record = c.exact(placement)?;
    let p = Placement::parse(&record.payload)?;
    let withdrawn = c
        .state
        .records
        .contains_key(&(TOMBSTONE_KIND, placement.id));
    if withdrawn {
        c.select(TOMBSTONE_KIND, placement.id)?;
    } else {
        live(c, placement)?;
    }
    if operation.grant.is_none() {
        let host = p
            .hosts
            .iter()
            .find(|h| h.id == intent.requester)
            .context("content query is outside host consent")?;
        c.host(host, Some(&p.namespace), true)?;
    } else if withdrawn {
        ensure!(
            intent.requester == p.owner,
            "withdrawn content metadata requires its owner"
        );
        owner_scope(c, &p, intent.requester, grant(operation)?)?;
    } else if p.opaque {
        let (outer, state, _) = sealed::live(c, &p.revision)?;
        let effect = if state.status == 0 {
            Effect::Inspect
        } else if intent.requester == outer.reviewer {
            Effect::Repair
        } else {
            Effect::Read
        };
        sealed::content_access(c, &p, effect, intent.requester, grant(operation)?)?;
    } else {
        let body = c.revision(&p.revision, true)?;
        let (_, ledger) = c.ledger(body.author.raw_page)?;
        let owner_access = p.owner == intent.requester
            && c.optional(|c| {
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    body.author.application.as_ref(),
                    "PagesSubmit",
                    &p.namespace,
                    Some(body.author.raw_page),
                    0,
                )
            })
            .is_some();
        let action = if owner_access {
            "PagesSubmit"
        } else if ledger
            .published
            .as_ref()
            .is_some_and(|r| r.id == p.revision.id)
        {
            c.publication(body.author.raw_page)?;
            "PagesRead"
        } else {
            "ReviewInspect"
        };
        c.principal(
            intent.requester,
            grant(operation)?,
            None,
            action,
            &p.namespace,
            Some(body.author.raw_page),
            0,
        )?;
    }
    for host in &p.hosts {
        let current = c.select(147, host.id)?;
        // Metadata discovery retains inactive consent; a selected byte effect
        // separately requires the exact live host and its capability closure.
        c.host(&current.reference, Some(&p.namespace), false)?;
        let _ = c.optional(|c| c.host(&current.reference, Some(&p.namespace), true));
    }
    if c.state.records.contains_key(&(COPIES_KIND, placement.id)) {
        c.select(COPIES_KIND, placement.id)?;
    }
    Ok(())
}
pub(crate) fn evaluate(
    c: &mut Evaluation<'_>,
    operation: &Operation,
    command: &Command,
    intent: &Intent,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    replay: bool,
) -> Result<()> {
    use super::evaluation::{add, grant};
    match command {
        Command::Authorise { .. } => authorise::evaluate(c, operation, command, intent)?,
        Command::Place {
            revision,
            hosts,
            copies,
            failure_domains,
            expires_ms,
        } => {
            ensure!(
                revision.kind == 141,
                "sealed staging owns opaque placement creation"
            );
            let body = c.revision(revision, true)?;
            let (_, ledger) = c.ledger(body.author.raw_page)?;
            ensure!(
                intent.requester == body.author.intent.requester
                    && ledger.pending.as_ref() == Some(revision),
                "content placement requires the pending author"
            );
            c.principal(
                intent.requester,
                grant(operation)?,
                body.author.application.as_ref(),
                "PagesSubmit",
                &body.author.namespace,
                Some(body.author.raw_page),
                body.author.source.len() as u64,
            )?;
            let replayed_placement = replay.then(|| placement_id(&body)).transpose()?;
            let mut domains = BTreeSet::new();
            let mut expiry = body.author.expires_ms;
            for host in hosts {
                let h = c.host(host, Some(&body.author.namespace), true)?;
                let policy = h
                    .profile
                    .content
                    .as_ref()
                    .context("host has no durable content consent")?;
                ensure!(
                    body.author.source.len() as u64 <= h.profile.maximum_asset_bytes,
                    "content exceeds host object bound"
                );
                domains.insert(policy.failure_domain);
                expiry = expiry
                    .min(c.at.saturating_add(h.profile.retention_ms))
                    .min(h.profile.manifest.validity.1);
                let retained = next
                    .records
                    .values()
                    .filter(|r| {
                        r.reference.kind == PLACEMENT_KIND
                            && Some(r.reference.id) != replayed_placement
                            && !next.records.contains_key(&(TOMBSTONE_KIND, r.reference.id))
                    })
                    .map(|r| Placement::parse(&r.payload))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|p| p.expires_ms > c.at && p.hosts.iter().any(|r| r.id == host.id))
                    .try_fold(0u64, |sum, p| {
                        sum.checked_add(p.bytes)
                            .context("content admission overflow")
                    })?;
                ensure!(
                    retained
                        .checked_add(body.author.source.len() as u64)
                        .is_some_and(|n| n <= policy.data_bytes),
                    "content placement quota reached"
                );
            }
            ensure!(
                *copies > 0
                    && *copies <= hosts.len() as u64
                    && *failure_domains > 0
                    && *failure_domains <= *copies
                    && *failure_domains <= domains.len() as u64
                    && *expires_ms > c.at
                    && *expires_ms <= expiry,
                "content placement exceeds current consent or failure-domain policy"
            );
            let placement = Placement {
                revision: revision.clone(),
                owner: intent.requester,
                grant: grant(operation)?.clone(),
                namespace: body.author.namespace,
                digest: body.author.source.content_sha256(),
                bytes: body.author.source.len() as u64,
                opaque: false,
                hosts: hosts.clone(),
                copies: *copies,
                failure_domains: *failure_domains,
                expires_ms: *expires_ms,
            };
            let id = placement.identity()?;
            if replay {
                ensure!(
                    c.select(PLACEMENT_KIND, id)?.payload == placement.value(),
                    "content placement replay differs"
                );
            } else {
                ensure!(
                    !next.records.contains_key(&(PLACEMENT_KIND, id)),
                    "content placement is immutable"
                );
                add(next, changed, PLACEMENT_KIND, id, placement.value())?;
            }
        }
        Command::Get { placement } => get(c, operation, placement, intent)?,
        Command::Receipt { receipt } => {
            let p = live(c, &receipt.placement)?;
            ensure!(
                p.hosts.contains(&receipt.host),
                "copy acknowledgement requires its selected host"
            );
            if intent.requester == receipt.host.id {
                ensure!(
                    operation.grant.is_none(),
                    "host copy acknowledgement uses intrinsic authority"
                );
            } else if p.opaque {
                let (_, state, _) = sealed::live(c, &p.revision)?;
                sealed::content_access(
                    c,
                    &p,
                    if state.status == 0 {
                        Effect::Upload
                    } else {
                        Effect::Repair
                    },
                    intent.requester,
                    grant(operation)?,
                )?;
            } else {
                ensure!(
                    intent.requester == p.owner,
                    "copy acknowledgement requires host or owner"
                );
                let body = c.revision(&p.revision, true)?;
                c.principal(
                    intent.requester,
                    grant(operation)?,
                    None,
                    "PagesSubmit",
                    &p.namespace,
                    Some(body.author.raw_page),
                    0,
                )?;
            }
            c.host(&receipt.host, Some(&p.namespace), true)?;
            ensure!(
                receipt.digest == p.digest
                    && receipt.bytes == p.bytes
                    && receipt.recorded_ms <= c.at
                    && receipt.expires_ms == p.expires_ms,
                "durable copy differs from placement"
            );
            let mut copies = if let Ok(r) = c.state.record(COPIES_KIND, receipt.placement.id) {
                let r = c.select(COPIES_KIND, r.reference.id)?;
                Copies::parse(&r.payload, c.state.network, c.state.incarnation)?
            } else {
                Copies {
                    placement: receipt.placement.clone(),
                    copies: vec![],
                }
            };
            let changed_receipt = if let Some(old) = copies
                .copies
                .iter_mut()
                .find(|r| r.host.id == receipt.host.id)
            {
                if old.envelope == receipt.envelope {
                    false
                } else {
                    ensure!(
                        !replay
                            && old.host == receipt.host
                            && receipt.recorded_ms > old.recorded_ms,
                        "durable copy repair acknowledgement is not newer for the same exact host"
                    );
                    *old = receipt.clone();
                    true
                }
            } else {
                ensure!(!replay, "durable copy replay absent");
                copies.copies.push(receipt.clone());
                copies.copies.sort_by_key(|r| r.host.id);
                true
            };
            if changed_receipt {
                add(
                    next,
                    changed,
                    COPIES_KIND,
                    receipt.placement.id,
                    copies.value(),
                )?;
            }
        }
        Command::Withdraw { placement } => {
            let record = c.exact(placement)?;
            let p = Placement::parse(&record.payload)?;
            ensure!(
                intent.requester == p.owner,
                "content withdrawal requires the owner"
            );
            owner_scope(c, &p, intent.requester, grant(operation)?)?;
            if replay {
                c.select(TOMBSTONE_KIND, placement.id)?;
            } else {
                ensure!(
                    !next.records.contains_key(&(TOMBSTONE_KIND, placement.id)),
                    "content placement is already withdrawn"
                );
                add(
                    next,
                    changed,
                    TOMBSTONE_KIND,
                    placement.id,
                    Tombstone {
                        placement: placement.clone(),
                        withdrawn_ms: c.at,
                    }
                    .value(),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "AuthorityPageContentTests.rs"]
mod tests;
