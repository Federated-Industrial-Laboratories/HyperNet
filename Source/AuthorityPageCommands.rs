// SPDX-License-Identifier: MIT
// Page operations select one finite resource and declare every immutable input explicitly.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaEffect {
    Upload,
    Read,
    Inspect,
}
impl MediaEffect {
    pub fn code(self) -> u64 {
        match self {
            Self::Upload => 0,
            Self::Read => 1,
            Self::Inspect => 2,
        }
    }
    fn parse(v: &V) -> Result<Self> {
        Ok(match v.uint()? {
            0 => Self::Upload,
            1 => Self::Read,
            2 => Self::Inspect,
            _ => anyhow::bail!("unsupported media effect"),
        })
    }
}
#[derive(Clone, Debug)]
pub enum Command {
    Context {
        action: u64,
        scope_kind: u64,
        resource: Digest,
        namespace: Option<String>,
    },
    ApplicationGet {
        application: Key,
    },
    Application {
        policy: ApplicationPolicy,
    },
    HostRegister {
        profile: HostProfile,
    },
    HostWithdraw {
        role: u64,
        host: Key,
        generation: u64,
    },
    HostGet {
        role: u64,
        host: Key,
    },
    Hosts {
        role: u64,
        namespace: String,
        after: Option<Digest>,
    },
    Submit {
        author: objects::Author,
    },
    Queue {
        namespace: String,
        after: Option<Digest>,
    },
    Inspect {
        page: [u8; 16],
    },
    Review {
        review: objects::Reviewer,
        bundle: Option<Reference>,
    },
    Withdraw {
        page: [u8; 16],
        as_reviewer: bool,
    },
    List {
        namespace: String,
        after: Option<Digest>,
    },
    Read {
        page: [u8; 16],
    },
    Sync {
        host: Key,
        namespace: String,
        after: Option<Digest>,
        fetch: Option<[u8; 16]>,
    },
    ReplicaQueue {
        host: Key,
        namespace: String,
        after: Option<Digest>,
    },
    ReplicaContext {
        page: [u8; 16],
        host: VersionRef,
    },
    ReplicaRequest {
        page: [u8; 16],
        host: VersionRef,
        expires_ms: u64,
    },
    ReplicaDeliver {
        ticket: VersionRef,
        bundle: Reference,
    },
    ReplicaResult {
        ticket: VersionRef,
    },
    MediaGet {
        asset: VersionRef,
    },
    MediaAuthorise {
        asset: VersionRef,
        host: VersionRef,
        effect: MediaEffect,
        offset: u64,
        bytes: u64,
        digest: Option<Digest>,
    },
    MediaReceipt {
        receipt: CopyReceipt,
    },
    MediaInspect {
        asset: VersionRef,
        receipt: CopyReceipt,
        expires_ms: u64,
    },
    MediaPolicy {
        namespace: String,
        copies: u64,
    },
}
fn raw_page(v: &V) -> Result<[u8; 16]> {
    let p = v.fixed()?;
    page_id(&p)?;
    Ok(p)
}
fn role(v: &V) -> Result<u64> {
    let r = v.uint()?;
    ensure!(matches!(r, 1 | 2), "unsupported Page host role");
    Ok(r)
}
impl Command {
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = value.list(10)?;
        let name = f.first().context("empty Page command")?.text()?;
        Ok(match name {
            "PageContext" => {
                let f = value.array(5)?;
                let action = f[1].uint()?;
                let scope_kind = f[2].uint()?;
                let resource = id(&f[3])?;
                let namespace = if f[4] == V::Null {
                    None
                } else {
                    Some(namespace(&f[4])?)
                };
                ensure!(
                    matches!(action, 0 | 2 | 3 | 5 | 21 | 26)
                        && matches!(scope_kind, 0 | 1 | 2 | 3 | 5)
                        && (scope_kind != 0 || resource == n)
                        && (scope_kind != 2 || namespace.is_some()),
                    "unsupported Page context request"
                );
                Self::Context {
                    action,
                    scope_kind,
                    resource,
                    namespace,
                }
            }
            "PageApplicationGet" => {
                let f = value.array(2)?;
                Self::ApplicationGet {
                    application: key(&f[1])?,
                }
            }
            "PageApplicationPolicy" => {
                let f = value.array(2)?;
                Self::Application {
                    policy: ApplicationPolicy::parse(f[1].bytes()?, n, i)?,
                }
            }
            "PageHostRegister" => {
                let f = value.array(2)?;
                Self::HostRegister {
                    profile: HostProfile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "PageHostWithdraw" => {
                let f = value.array(4)?;
                Self::HostWithdraw {
                    role: role(&f[1])?,
                    host: key(&f[2])?,
                    generation: f[3].uint()?,
                }
            }
            "PageHostGet" => {
                let f = value.array(3)?;
                Self::HostGet {
                    role: role(&f[1])?,
                    host: key(&f[2])?,
                }
            }
            "PageHosts" => {
                let f = value.array(4)?;
                Self::Hosts {
                    role: role(&f[1])?,
                    namespace: namespace(&f[2])?,
                    after: optional_id(&f[3])?,
                }
            }
            "PageSubmit" => {
                let f = value.array(2)?;
                Self::Submit {
                    author: objects::Author::parse(f[1].bytes()?, n, i)?,
                }
            }
            "PageQueue" => {
                let f = value.array(3)?;
                Self::Queue {
                    namespace: namespace(&f[1])?,
                    after: optional_id(&f[2])?,
                }
            }
            "PageInspect" => {
                let f = value.array(2)?;
                Self::Inspect {
                    page: raw_page(&f[1])?,
                }
            }
            "PageReview" => {
                let f = value.array(3)?;
                let review = objects::Reviewer::parse(f[1].bytes()?, n, i)?;
                let bundle = if f[2] == V::Null {
                    None
                } else {
                    Some(bundle(&f[2])?)
                };
                ensure!(
                    review.approve == bundle.is_some(),
                    "Page review bundle and decision differ"
                );
                Self::Review { review, bundle }
            }
            "PageWithdraw" => {
                let f = value.array(3)?;
                Self::Withdraw {
                    page: raw_page(&f[1])?,
                    as_reviewer: f[2].boolean()?,
                }
            }
            "PageList" => {
                let f = value.array(3)?;
                Self::List {
                    namespace: namespace(&f[1])?,
                    after: optional_id(&f[2])?,
                }
            }
            "PageRead" => {
                let f = value.array(2)?;
                Self::Read {
                    page: raw_page(&f[1])?,
                }
            }
            "PageSync" => {
                let f = value.array(5)?;
                Self::Sync {
                    host: key(&f[1])?,
                    namespace: namespace(&f[2])?,
                    after: optional_id(&f[3])?,
                    fetch: if f[4] == V::Null {
                        None
                    } else {
                        Some(raw_page(&f[4])?)
                    },
                }
            }
            "PageReplicaQueue" => {
                let f = value.array(4)?;
                Self::ReplicaQueue {
                    host: key(&f[1])?,
                    namespace: namespace(&f[2])?,
                    after: optional_id(&f[3])?,
                }
            }
            "PageReplicaContext" => {
                let f = value.array(3)?;
                Self::ReplicaContext {
                    page: raw_page(&f[1])?,
                    host: required_version(&f[2], 147)?,
                }
            }
            "PageReplicaRequest" => {
                let f = value.array(4)?;
                Self::ReplicaRequest {
                    page: raw_page(&f[1])?,
                    host: required_version(&f[2], 147)?,
                    expires_ms: f[3].uint()?,
                }
            }
            "PageReplicaDeliver" => {
                let f = value.array(3)?;
                Self::ReplicaDeliver {
                    ticket: required_version(&f[1], 146)?,
                    bundle: bundle(&f[2])?,
                }
            }
            "PageReplicaResult" => {
                let f = value.array(2)?;
                Self::ReplicaResult {
                    ticket: required_version(&f[1], 146)?,
                }
            }
            "PageMediaGet" => {
                let f = value.array(2)?;
                Self::MediaGet {
                    asset: required_version(&f[1], 144)?,
                }
            }
            "PageMediaAuthorise" => {
                let f = value.array(7)?;
                let effect = MediaEffect::parse(&f[3])?;
                let digest = optional_id(&f[6])?;
                let bytes = f[5].uint()?;
                ensure!(
                    (1..=32768).contains(&bytes)
                        && (effect == MediaEffect::Upload) == digest.is_some(),
                    "media operation payload restrictions differ"
                );
                Self::MediaAuthorise {
                    asset: required_version(&f[1], 144)?,
                    host: required_version(&f[2], 143)?,
                    effect,
                    offset: f[4].uint()?,
                    bytes,
                    digest,
                }
            }
            "PageMediaReceipt" => {
                let f = value.array(2)?;
                Self::MediaReceipt {
                    receipt: CopyReceipt::parse(f[1].bytes()?, n, i)?,
                }
            }
            "PageMediaInspect" => {
                let f = value.array(4)?;
                let asset = required_version(&f[1], 144)?;
                let receipt = CopyReceipt::parse(f[2].bytes()?, n, i)?;
                ensure!(receipt.asset == asset, "inspection receipt asset differs");
                Self::MediaInspect {
                    asset,
                    receipt,
                    expires_ms: f[3].uint()?,
                }
            }
            "PageMediaPolicy" => {
                let f = value.array(3)?;
                let copies = f[2].uint()?;
                ensure!((1..=3).contains(&copies), "media policy copy count differs");
                Self::MediaPolicy {
                    namespace: namespace(&f[1])?,
                    copies,
                }
            }
            _ => anyhow::bail!("unsupported Page domain operation"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Context { .. } => "PageContext",
            Self::ApplicationGet { .. } => "PageApplicationGet",
            Self::Application { .. } => "PageApplicationPolicy",
            Self::HostRegister { .. } => "PageHostRegister",
            Self::HostWithdraw { .. } => "PageHostWithdraw",
            Self::HostGet { .. } => "PageHostGet",
            Self::Hosts { .. } => "PageHosts",
            Self::Submit { .. } => "PageSubmit",
            Self::Queue { .. } => "PageQueue",
            Self::Inspect { .. } => "PageInspect",
            Self::Review { .. } => "PageReview",
            Self::Withdraw { .. } => "PageWithdraw",
            Self::List { .. } => "PageList",
            Self::Read { .. } => "PageRead",
            Self::Sync { .. } => "PageSync",
            Self::ReplicaQueue { .. } => "PageReplicaQueue",
            Self::ReplicaContext { .. } => "PageReplicaContext",
            Self::ReplicaRequest { .. } => "PageReplicaRequest",
            Self::ReplicaDeliver { .. } => "PageReplicaDeliver",
            Self::ReplicaResult { .. } => "PageReplicaResult",
            Self::MediaGet { .. } => "PageMediaGet",
            Self::MediaAuthorise { .. } => "PageMediaAuthorise",
            Self::MediaReceipt { .. } => "PageMediaReceipt",
            Self::MediaInspect { .. } => "PageMediaInspect",
            Self::MediaPolicy { .. } => "PageMediaPolicy",
        }
    }
    pub fn value(&self) -> V {
        let mut v = vec![V::Text(self.name().into())];
        v.extend(match self {
            Self::Context {
                action,
                scope_kind,
                resource,
                namespace,
            } => vec![
                V::Uint(*action),
                V::Uint(*scope_kind),
                b(resource),
                namespace.as_ref().map_or(V::Null, |v| V::Text(v.clone())),
            ],
            Self::ApplicationGet { application } => vec![b(application)],
            Self::Application { policy } => vec![b(&policy.envelope)],
            Self::HostRegister { profile } => vec![b(&profile.envelope)],
            Self::HostWithdraw {
                role,
                host,
                generation,
            } => vec![V::Uint(*role), b(host), V::Uint(*generation)],
            Self::HostGet { role, host } => vec![V::Uint(*role), b(host)],
            Self::Hosts {
                role,
                namespace,
                after,
            } => vec![
                V::Uint(*role),
                V::Text(namespace.clone()),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::Submit { author } => vec![b(&author.bytes)],
            Self::Queue { namespace, after } | Self::List { namespace, after } => vec![
                V::Text(namespace.clone()),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::Inspect { page } | Self::Read { page } => vec![b(page)],
            Self::Review { review, bundle } => vec![
                b(&review.bytes),
                bundle.as_ref().map_or(V::Null, Reference::value),
            ],
            Self::Withdraw { page, as_reviewer } => vec![b(page), V::Bool(*as_reviewer)],
            Self::Sync {
                host,
                namespace,
                after,
                fetch,
            } => vec![
                b(host),
                V::Text(namespace.clone()),
                after.as_ref().map_or(V::Null, |v| b(v)),
                fetch.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::ReplicaQueue {
                host,
                namespace,
                after,
            } => vec![
                b(host),
                V::Text(namespace.clone()),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::ReplicaContext { page, host } => vec![b(page), reference(host)],
            Self::ReplicaRequest {
                page,
                host,
                expires_ms,
            } => vec![b(page), reference(host), V::Uint(*expires_ms)],
            Self::ReplicaDeliver { ticket, bundle } => vec![reference(ticket), bundle.value()],
            Self::ReplicaResult { ticket } => vec![reference(ticket)],
            Self::MediaGet { asset } => vec![reference(asset)],
            Self::MediaAuthorise {
                asset,
                host,
                effect,
                offset,
                bytes,
                digest,
            } => vec![
                reference(asset),
                reference(host),
                V::Uint(effect.code()),
                V::Uint(*offset),
                V::Uint(*bytes),
                digest.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::MediaReceipt { receipt } => vec![b(&receipt.envelope)],
            Self::MediaInspect {
                asset,
                receipt,
                expires_ms,
            } => vec![reference(asset), b(&receipt.envelope), V::Uint(*expires_ms)],
            Self::MediaPolicy { namespace, copies } => {
                vec![V::Text(namespace.clone()), V::Uint(*copies)]
            }
        });
        a(v)
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Application { .. }
                | Self::HostRegister { .. }
                | Self::HostWithdraw { .. }
                | Self::Submit { .. }
                | Self::Review { .. }
                | Self::Withdraw { .. }
                | Self::ReplicaRequest { .. }
                | Self::ReplicaDeliver { .. }
                | Self::MediaReceipt { .. }
                | Self::MediaInspect { .. }
                | Self::MediaPolicy { .. }
        )
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Context { resource, .. } => *resource,
            Self::ApplicationGet { application } => *application,
            Self::Application { policy } => policy.application,
            Self::HostRegister { profile } => profile.manifest.deployment,
            Self::HostWithdraw { host, .. }
            | Self::HostGet { host, .. }
            | Self::Sync { host, .. }
            | Self::ReplicaQueue { host, .. } => *host,
            Self::Hosts { namespace, .. }
            | Self::Queue { namespace, .. }
            | Self::List { namespace, .. }
            | Self::MediaPolicy { namespace, .. } => {
                namespace_id(namespace).expect("parsed namespace")
            }
            Self::Submit { author } => author.intent.resource,
            Self::Review { review, .. } => review.intent.resource,
            Self::Inspect { page }
            | Self::Withdraw { page, .. }
            | Self::Read { page }
            | Self::ReplicaContext { page, .. }
            | Self::ReplicaRequest { page, .. } => page_id(page).expect("parsed Page identity"),
            Self::ReplicaDeliver { ticket, .. } | Self::ReplicaResult { ticket } => ticket.id,
            Self::MediaGet { asset }
            | Self::MediaAuthorise { asset, .. }
            | Self::MediaInspect { asset, .. } => asset.id,
            Self::MediaReceipt { receipt } => receipt.asset.id,
        }
    }
    pub fn command_inputs(&self) -> Vec<Reference> {
        match self {
            Self::Submit { author } => vec![author.source.clone()],
            Self::Review { bundle, .. } => bundle.iter().cloned().collect(),
            Self::ReplicaDeliver { bundle, .. } => vec![bundle.clone()],
            _ => vec![],
        }
    }
    pub fn required_inputs(&self, state: &State) -> Result<Vec<Reference>> {
        let mut refs = self.command_inputs();
        match self {
            Self::Review { review, .. } => {
                if let Ok(r) = state.record(141, review.revision.id) {
                    let revision = Revision::parse(&r.payload, state.network, state.incarnation)?;
                    refs.push(revision.author.source);
                }
            }
            Self::Inspect { page } => {
                if let Ok(r) = state.record(140, page_id(page)?) {
                    let ledger = Ledger::parse(&r.payload)?;
                    if let Some(pending) = ledger.pending {
                        let revision = Revision::parse(
                            &state.record(141, pending.id)?.payload,
                            state.network,
                            state.incarnation,
                        )?;
                        refs.push(revision.author.source);
                    }
                }
            }
            Self::Read { page }
            | Self::Sync {
                fetch: Some(page), ..
            } => {
                if let Ok(r) = state.record(140, page_id(page)?)
                    && let Some(published) = Ledger::parse(&r.payload)?.published
                {
                    refs.extend(
                        Review::parse(
                            &state.record(142, published.id)?.payload,
                            state.network,
                            state.incarnation,
                        )?
                        .bundle,
                    );
                }
            }
            Self::ReplicaResult { ticket } => {
                if let Ok(r) = state.record(146, ticket.id) {
                    // Pending results disclose metadata only; delivered results
                    // require the exact bundle named by the current ticket.
                    refs.extend(Ticket::parse(&r.payload)?.delivered);
                }
            }
            Self::ReplicaDeliver { ticket, .. } => {
                if let Ok(r) = state.record(146, ticket.id) {
                    let ticket = Ticket::parse(&r.payload)?;
                    let published = Review::parse(
                        &state.record(142, ticket.publication.id)?.payload,
                        state.network,
                        state.incarnation,
                    )?;
                    refs.extend(published.bundle);
                }
            }
            _ => {}
        }
        refs.sort();
        refs.dedup();
        Ok(refs)
    }
    pub fn mutation_indices(
        &self,
        state: &State,
        intent: &Intent,
        inputs: &Resolved,
    ) -> Result<Vec<(u64, Digest)>> {
        let mut out = match self {
            Self::Application { policy } => vec![(148, policy.application)],
            Self::HostRegister { profile } => {
                vec![(if profile.role == 1 { 147 } else { 143 }, profile.service)]
            }
            Self::HostWithdraw { role, host, .. } => {
                vec![(if *role == 1 { 147 } else { 143 }, *host)]
            }
            Self::Submit { author } => {
                let revision = Revision::from_source(author.clone(), inputs.get(&author.source)?)?;
                let record = Record::next(
                    &State::empty(state.network, state.incarnation),
                    141,
                    revision.identity()?,
                    revision.value(),
                )?;
                let mut indices = vec![(140, author.intent.resource), record.reference.index()];
                for asset in &revision.assets {
                    indices.push((144, asset_id(&record.reference, &asset.id)?));
                }
                indices
            }
            Self::Review { review, .. } => {
                vec![(140, review.intent.resource), (142, review.revision.id)]
            }
            Self::Withdraw { page, .. } => vec![(140, page_id(page)?)],
            Self::ReplicaRequest { host, .. } => vec![(146, ticket_id(intent.requester, host.id)?)],
            Self::ReplicaDeliver { ticket, .. } => vec![ticket.index()],
            Self::MediaReceipt { receipt } => vec![(145, receipt.asset.id)],
            Self::MediaInspect { asset, .. } => vec![(145, asset.id)],
            Self::MediaPolicy { namespace, .. } => vec![(149, namespace_id(namespace)?)],
            _ => vec![],
        };
        out.sort();
        out.dedup();
        Ok(out)
    }
}
