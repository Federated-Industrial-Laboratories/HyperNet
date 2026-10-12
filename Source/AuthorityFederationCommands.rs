// SPDX-License-Identifier: MIT
// Federation commands bind one explicit agreement, exact counterpart evidence and finite effects.
use super::*;

#[derive(Clone, Debug)]
pub enum Command {
    SourceContext {
        agreement: Digest,
        page: Option<[u8; 16]>,
        after: Option<Digest>,
    },
    Context {
        action: u64,
        resource: Digest,
        namespace: Option<String>,
    },
    InventoryContext {
        agreement: Digest,
        action: u64,
    },
    PageContext {
        agreement: Digest,
        page: [u8; 16],
        action: u64,
    },
    ContentAuthorise {
        placement: VersionRef,
        host: VersionRef,
        offset: u64,
        bytes: u64,
        proof: ForeignProof,
    },
    MediaGet {
        asset: VersionRef,
        proof: ForeignProof,
    },
    MediaAuthorise {
        asset: VersionRef,
        host: VersionRef,
        effect: page::MediaEffect,
        offset: u64,
        bytes: u64,
        digest: Option<Digest>,
        proof: ForeignProof,
    },
    MediaReceipt {
        receipt: page::CopyReceipt,
        proof: ForeignProof,
    },
    MediaInspect {
        asset: VersionRef,
        receipt: page::CopyReceipt,
        expires_ms: u64,
        proof: ForeignProof,
    },
    TrustAccept {
        bootstrap: Vec<u8>,
        identity: NetworkIdentity,
    },
    TrustGet {
        trust: Digest,
    },
    TrustWithdraw {
        trust: VersionRef,
    },
    Accept {
        treaty: Treaty,
        foreign: VersionRef,
    },
    Get {
        agreement: Digest,
    },
    Agreements {
        after: Option<Digest>,
    },
    Withdraw {
        agreement: VersionRef,
    },
    BridgeRegister {
        profile: BridgeProfile,
    },
    BridgeGet {
        service: Key,
    },
    BridgeWithdraw {
        bridge: VersionRef,
    },
    Share {
        share: Share,
    },
    ShareStatus {
        agreement: Digest,
        page: [u8; 16],
    },
    Unshare {
        share: VersionRef,
    },
    Admission {
        agreement: VersionRef,
        bridge: VersionRef,
        page: Option<[u8; 16]>,
        exchange: Digest,
        revision: Option<VersionRef>,
        after: Option<Digest>,
    },
    Export {
        agreement: VersionRef,
        bridge: VersionRef,
        admission: ForeignProof,
        include_bundle: bool,
        inventory: Option<Vec<Digest>>,
    },
    Import {
        agreement: VersionRef,
        bridge: VersionRef,
        export: ForeignProof,
        bundle: Reference,
    },
    Queue {
        agreement: Digest,
        after: Option<Digest>,
    },
    Inspect {
        page: Digest,
        export: ForeignProof,
    },
    Review {
        review: ForeignReview,
        export: ForeignProof,
    },
    List {
        agreement: Digest,
        export: ForeignProof,
    },
    Read {
        page: Digest,
        export: ForeignProof,
    },
    PageWithdraw {
        page: VersionRef,
    },
    ForeignSeal {
        trust: VersionRef,
        floor: VersionRef,
        evidence: Vec<u8>,
        history: Vec<u8>,
    },
    ForeignActivate {
        trust: VersionRef,
        floor: VersionRef,
        ready: Vec<u8>,
    },
}
fn after(v: &V) -> Result<Option<Digest>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}
impl Command {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.list(8)?;
        let name = f.first().context("empty federation command")?.text()?;
        let exact = |len| -> Result<()> {
            ensure!(f.len() == len, "federation command arity differs");
            Ok(())
        };
        Ok(match name {
            "FederationSourceContext" => {
                exact(4)?;
                ensure!(
                    f[2] == V::Null || f[3] == V::Null,
                    "source context mixes Page and inventory"
                );
                Self::SourceContext {
                    agreement: id(&f[1])?,
                    page: if f[2] == V::Null {
                        None
                    } else {
                        Some(f[2].fixed()?)
                    },
                    after: after(&f[3])?,
                }
            }
            "FederationInventoryContext" => {
                exact(3)?;
                let action = f[2].uint()?;
                ensure!(matches!(action, 0 | 3), "inventory action differs");
                Self::InventoryContext {
                    agreement: id(&f[1])?,
                    action,
                }
            }
            "FederationPageContext" => {
                exact(4)?;
                let action = f[3].uint()?;
                ensure!(
                    matches!(action, 0 | 3 | 4),
                    "unsupported foreign Page principal"
                );
                Self::PageContext {
                    agreement: id(&f[1])?,
                    page: f[2].fixed()?,
                    action,
                }
            }
            "FederationContentAuthorise" => {
                exact(7)?;
                ensure!(
                    f[3].uint()? == 1,
                    "foreign content permits only explicit source reads"
                );
                let offset = f[4].uint()?;
                let bytes = f[5].uint()?;
                ensure!(
                    bytes > 0 && bytes <= 32768 && offset.checked_add(bytes).is_some(),
                    "foreign content range differs"
                );
                let proof = ForeignProof::parse(f[6].bytes()?)?;
                proof.require_action("FederationAdmission")?;
                Self::ContentAuthorise {
                    placement: exact_ref(&f[1], 159)?,
                    host: exact_ref(&f[2], 147)?,
                    offset,
                    bytes,
                    proof,
                }
            }
            "FederationMediaGet" => {
                exact(3)?;
                let proof = ForeignProof::parse(f[2].bytes()?)?;
                proof.require_action("FederationExport")?;
                Self::MediaGet {
                    asset: exact_ref(&f[1], 144)?,
                    proof,
                }
            }
            "FederationMediaAuthorise" => {
                exact(8)?;
                let native = page::Command::parse(
                    &a(vec![
                        V::Text("PageMediaAuthorise".into()),
                        f[1].clone(),
                        f[2].clone(),
                        f[3].clone(),
                        f[4].clone(),
                        f[5].clone(),
                        f[6].clone(),
                    ]),
                    n,
                    i,
                )?;
                let page::Command::MediaAuthorise {
                    asset,
                    host,
                    effect,
                    offset,
                    bytes,
                    digest,
                } = native
                else {
                    unreachable!()
                };
                Self::MediaAuthorise {
                    asset,
                    host,
                    effect,
                    offset,
                    bytes,
                    digest,
                    proof: ForeignProof::parse(f[7].bytes()?)?,
                }
            }
            "FederationMediaReceipt" => {
                exact(3)?;
                let proof = ForeignProof::parse(f[2].bytes()?)?;
                proof.require_action("FederationExport")?;
                Self::MediaReceipt {
                    receipt: page::CopyReceipt::parse(f[1].bytes()?, n, i)?,
                    proof,
                }
            }
            "FederationMediaInspect" => {
                exact(5)?;
                let proof = ForeignProof::parse(f[4].bytes()?)?;
                proof.require_action("FederationExport")?;
                Self::MediaInspect {
                    asset: exact_ref(&f[1], 144)?,
                    receipt: page::CopyReceipt::parse(f[2].bytes()?, n, i)?,
                    expires_ms: f[3].uint()?,
                    proof,
                }
            }
            "FederationContext" => {
                exact(4)?;
                let action = f[1].uint()?;
                ensure!(
                    matches!(action, 0 | 3 | 4 | 13 | 22 | 26),
                    "unsupported federation context action"
                );
                Self::Context {
                    action,
                    resource: id(&f[2])?,
                    namespace: if f[3] == V::Null {
                        None
                    } else {
                        Some(namespace(&f[3])?)
                    },
                }
            }
            "FederationTrustAccept" => {
                exact(3)?;
                Self::TrustAccept {
                    bootstrap: f[1].bytes()?.to_vec(),
                    identity: NetworkIdentity::parse(&f[2])?,
                }
            }
            "FederationTrustGet" => {
                exact(2)?;
                Self::TrustGet { trust: id(&f[1])? }
            }
            "FederationTrustWithdraw" => {
                exact(2)?;
                Self::TrustWithdraw {
                    trust: exact_ref(&f[1], 150)?,
                }
            }
            "FederationAccept" => {
                exact(3)?;
                Self::Accept {
                    treaty: Treaty::parse(&f[1])?,
                    foreign: exact_ref(&f[2], 150)?,
                }
            }
            "FederationGet" => {
                exact(2)?;
                Self::Get {
                    agreement: id(&f[1])?,
                }
            }
            "FederationAgreements" => {
                exact(2)?;
                Self::Agreements {
                    after: after(&f[1])?,
                }
            }
            "FederationWithdraw" => {
                exact(2)?;
                Self::Withdraw {
                    agreement: exact_ref(&f[1], 151)?,
                }
            }
            "FederationBridgeRegister" => {
                exact(2)?;
                Self::BridgeRegister {
                    profile: BridgeProfile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "FederationBridgeGet" => {
                exact(2)?;
                Self::BridgeGet {
                    service: key(&f[1])?,
                }
            }
            "FederationBridgeWithdraw" => {
                exact(2)?;
                Self::BridgeWithdraw {
                    bridge: exact_ref(&f[1], 152)?,
                }
            }
            "FederationShare" => {
                exact(2)?;
                let share = Share::parse(&f[1], n, i)?;
                ensure!(
                    share.allowed && share.withdrawal_generation == 0,
                    "share command cannot forge retained withdrawal floors"
                );
                Self::Share { share }
            }
            "FederationShareStatus" => {
                exact(3)?;
                Self::ShareStatus {
                    agreement: id(&f[1])?,
                    page: f[2].fixed()?,
                }
            }
            "FederationUnshare" => {
                exact(2)?;
                Self::Unshare {
                    share: exact_ref(&f[1], 153)?,
                }
            }
            "FederationAdmission" => {
                exact(7)?;
                ensure!(
                    (f[3] == V::Null && f[5] == V::Null) || (f[3] != V::Null && f[6] == V::Null),
                    "admission mixes Page and inventory selection"
                );
                Self::Admission {
                    agreement: exact_ref(&f[1], 151)?,
                    bridge: exact_ref(&f[2], 152)?,
                    page: if f[3] == V::Null {
                        None
                    } else {
                        Some(f[3].fixed()?)
                    },
                    exchange: id(&f[4])?,
                    revision: optional_ref(&f[5], 141)?,
                    after: after(&f[6])?,
                }
            }
            "FederationExport" => {
                exact(6)?;
                let proof = ForeignProof::parse(f[3].bytes()?)?;
                proof.require_action("FederationAdmission")?;
                let Self::Admission { page, after, .. } = proof.command()? else {
                    anyhow::bail!("export admission command differs")
                };
                let inventory = Self::parse_inventory(&f[5], page, after)?;
                Self::Export {
                    agreement: exact_ref(&f[1], 151)?,
                    bridge: exact_ref(&f[2], 152)?,
                    admission: proof,
                    include_bundle: f[4].boolean()?,
                    inventory,
                }
            }
            "FederationImport" => {
                exact(5)?;
                let export = ForeignProof::parse(f[3].bytes()?)?;
                export.require_action("FederationExport")?;
                let bundle = Reference::parse(&f[4])?;
                ensure!(
                    bundle.class() == crate::authority_objects::Class::PageBundle,
                    "federation import object class differs"
                );
                Self::Import {
                    agreement: exact_ref(&f[1], 151)?,
                    bridge: exact_ref(&f[2], 152)?,
                    export,
                    bundle,
                }
            }
            "FederationQueue" => {
                exact(3)?;
                Self::Queue {
                    agreement: id(&f[1])?,
                    after: after(&f[2])?,
                }
            }
            "FederationInspect" | "FederationRead" => {
                exact(3)?;
                let export = ForeignProof::parse(f[2].bytes()?)?;
                export.require_action("FederationExport")?;
                if name == "FederationInspect" {
                    Self::Inspect {
                        page: id(&f[1])?,
                        export,
                    }
                } else {
                    Self::Read {
                        page: id(&f[1])?,
                        export,
                    }
                }
            }
            "FederationReview" => {
                exact(3)?;
                let review = ForeignReview::parse(&f[1], n, i)?;
                let export = ForeignProof::parse(f[2].bytes()?)?;
                export.require_action("FederationExport")?;
                Self::Review { review, export }
            }
            "FederationList" => {
                exact(3)?;
                let export = ForeignProof::parse(f[2].bytes()?)?;
                export.require_action("FederationExport")?;
                Self::List {
                    agreement: id(&f[1])?,
                    export,
                }
            }
            "FederationPageWithdraw" => {
                exact(2)?;
                Self::PageWithdraw {
                    page: exact_ref(&f[1], 154)?,
                }
            }
            "FederationForeignSeal" => {
                exact(5)?;
                Self::ForeignSeal {
                    trust: exact_ref(&f[1], 150)?,
                    floor: exact_ref(&f[2], 157)?,
                    evidence: f[3].bytes()?.to_vec(),
                    history: f[4].bytes()?.to_vec(),
                }
            }
            "FederationForeignActivate" => {
                exact(4)?;
                Self::ForeignActivate {
                    trust: exact_ref(&f[1], 150)?,
                    floor: exact_ref(&f[2], 157)?,
                    ready: f[3].bytes()?.to_vec(),
                }
            }
            _ => anyhow::bail!("unsupported federation command"),
        })
    }
    pub fn parse_inventory(
        v: &V,
        page: Option<[u8; 16]>,
        after: Option<Digest>,
    ) -> Result<Option<Vec<Digest>>> {
        if page.is_some() {
            ensure!(
                *v == V::Null && after.is_none(),
                "Page export carries an inventory selection"
            );
            return Ok(None);
        }
        let f = v.array(2)?;
        let ids = f[1]
            .list(MAXIMUM_CONTEXT_RECORDS)?
            .iter()
            .map(id)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            ids.windows(2).all(|p| p[0] < p[1])
                && ids.first().is_none_or(|id| after.is_none_or(|a| *id > a))
                && f[0] == ids.last().map_or(V::Null, |id| b(id)),
            "inventory selection reorders, repeats or changes its exact end"
        );
        Ok(Some(ids))
    }
    pub fn inventory_value(inventory: &Option<Vec<Digest>>) -> V {
        inventory.as_ref().map_or(V::Null, |ids| {
            a(vec![
                ids.last().map_or(V::Null, |id| b(id)),
                a(ids.iter().map(|id| b(id)).collect()),
            ])
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::SourceContext { .. } => "FederationSourceContext",
            Self::InventoryContext { .. } => "FederationInventoryContext",
            Self::PageContext { .. } => "FederationPageContext",
            Self::ContentAuthorise { .. } => "FederationContentAuthorise",
            Self::MediaGet { .. } => "FederationMediaGet",
            Self::MediaAuthorise { .. } => "FederationMediaAuthorise",
            Self::MediaReceipt { .. } => "FederationMediaReceipt",
            Self::MediaInspect { .. } => "FederationMediaInspect",
            Self::Context { .. } => "FederationContext",
            Self::TrustAccept { .. } => "FederationTrustAccept",
            Self::TrustGet { .. } => "FederationTrustGet",
            Self::TrustWithdraw { .. } => "FederationTrustWithdraw",
            Self::Accept { .. } => "FederationAccept",
            Self::Get { .. } => "FederationGet",
            Self::Agreements { .. } => "FederationAgreements",
            Self::Withdraw { .. } => "FederationWithdraw",
            Self::BridgeRegister { .. } => "FederationBridgeRegister",
            Self::BridgeGet { .. } => "FederationBridgeGet",
            Self::BridgeWithdraw { .. } => "FederationBridgeWithdraw",
            Self::Share { .. } => "FederationShare",
            Self::ShareStatus { .. } => "FederationShareStatus",
            Self::Unshare { .. } => "FederationUnshare",
            Self::Admission { .. } => "FederationAdmission",
            Self::Export { .. } => "FederationExport",
            Self::Import { .. } => "FederationImport",
            Self::Queue { .. } => "FederationQueue",
            Self::Inspect { .. } => "FederationInspect",
            Self::Review { .. } => "FederationReview",
            Self::List { .. } => "FederationList",
            Self::Read { .. } => "FederationRead",
            Self::PageWithdraw { .. } => "FederationPageWithdraw",
            Self::ForeignSeal { .. } => "FederationForeignSeal",
            Self::ForeignActivate { .. } => "FederationForeignActivate",
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        f.extend(match self {
            Self::SourceContext {
                agreement,
                page,
                after,
            } => vec![
                b(agreement),
                page.as_ref().map_or(V::Null, |v| b(v)),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::InventoryContext { agreement, action } => vec![b(agreement), V::Uint(*action)],
            Self::PageContext {
                agreement,
                page,
                action,
            } => vec![b(agreement), b(page), V::Uint(*action)],
            Self::ContentAuthorise {
                placement,
                host,
                offset,
                bytes,
                proof,
            } => vec![
                reference(placement),
                reference(host),
                V::Uint(1),
                V::Uint(*offset),
                V::Uint(*bytes),
                b(&proof.bytes),
            ],
            Self::MediaGet { asset, proof } => vec![reference(asset), b(&proof.bytes)],
            Self::MediaAuthorise {
                asset,
                host,
                effect,
                offset,
                bytes,
                digest,
                proof,
            } => vec![
                reference(asset),
                reference(host),
                V::Uint(effect.code()),
                V::Uint(*offset),
                V::Uint(*bytes),
                digest.as_ref().map_or(V::Null, |v| b(v)),
                b(&proof.bytes),
            ],
            Self::MediaReceipt { receipt, proof } => vec![b(&receipt.envelope), b(&proof.bytes)],
            Self::MediaInspect {
                asset,
                receipt,
                expires_ms,
                proof,
            } => vec![
                reference(asset),
                b(&receipt.envelope),
                V::Uint(*expires_ms),
                b(&proof.bytes),
            ],
            Self::Context {
                action,
                resource,
                namespace,
            } => vec![
                V::Uint(*action),
                b(resource),
                namespace.as_ref().map_or(V::Null, |s| V::Text(s.clone())),
            ],
            Self::TrustAccept {
                bootstrap,
                identity,
            } => vec![b(bootstrap), identity.value()],
            Self::TrustGet { trust } => vec![b(trust)],
            Self::TrustWithdraw { trust } => vec![reference(trust)],
            Self::Accept { treaty, foreign } => vec![treaty.value(), reference(foreign)],
            Self::Get { agreement } => vec![b(agreement)],
            Self::Agreements { after } => vec![after.as_ref().map_or(V::Null, |id| b(id))],
            Self::Withdraw { agreement } => vec![reference(agreement)],
            Self::BridgeRegister { profile } => vec![b(&profile.envelope)],
            Self::BridgeGet { service } => vec![b(service)],
            Self::BridgeWithdraw { bridge } => vec![reference(bridge)],
            Self::Share { share } => vec![share.value()],
            Self::ShareStatus { agreement, page } => vec![b(agreement), b(page)],
            Self::Unshare { share } => vec![reference(share)],
            Self::Admission {
                agreement,
                bridge,
                page,
                exchange,
                revision,
                after,
            } => vec![
                reference(agreement),
                reference(bridge),
                page.as_ref().map_or(V::Null, |v| b(v)),
                b(exchange),
                revision.as_ref().map_or(V::Null, reference),
                after.as_ref().map_or(V::Null, |v| b(v)),
            ],
            Self::Export {
                agreement,
                bridge,
                admission,
                include_bundle,
                inventory,
            } => vec![
                reference(agreement),
                reference(bridge),
                b(&admission.bytes),
                V::Bool(*include_bundle),
                Self::inventory_value(inventory),
            ],
            Self::Import {
                agreement,
                bridge,
                export,
                bundle,
            } => vec![
                reference(agreement),
                reference(bridge),
                b(&export.bytes),
                bundle.value(),
            ],
            Self::Queue { agreement, after } => {
                vec![b(agreement), after.as_ref().map_or(V::Null, |id| b(id))]
            }
            Self::List { agreement, export } => vec![b(agreement), b(&export.bytes)],
            Self::Inspect { page, export } | Self::Read { page, export } => {
                vec![b(page), b(&export.bytes)]
            }
            Self::Review { review, export } => vec![review.value(), b(&export.bytes)],
            Self::PageWithdraw { page } => vec![reference(page)],
            Self::ForeignSeal {
                trust,
                floor,
                evidence,
                history,
            } => vec![reference(trust), reference(floor), b(evidence), b(history)],
            Self::ForeignActivate {
                trust,
                floor,
                ready,
            } => vec![reference(trust), reference(floor), b(ready)],
        });
        a(f)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::SourceContext { agreement, .. } | Self::InventoryContext { agreement, .. } => {
                *agreement
            }
            Self::PageContext {
                agreement,
                page,
                action,
            } => identity(
                "FederationPageContext",
                vec![b(agreement), b(page), V::Uint(*action)],
            )
            .expect("fixed Page context identity"),
            Self::ContentAuthorise { placement, .. } => placement.id,
            Self::MediaGet { asset, .. }
            | Self::MediaAuthorise { asset, .. }
            | Self::MediaInspect { asset, .. } => asset.id,
            Self::MediaReceipt { receipt, .. } => receipt.asset.id,
            Self::Context { resource, .. } => *resource,
            Self::TrustAccept { identity, .. } => super::identity(
                "ForeignTrust",
                vec![b(&identity.network), b(&identity.incarnation)],
            )
            .expect("fixed identity"),
            Self::TrustGet { trust } => *trust,
            Self::TrustWithdraw { trust } => trust.id,
            Self::Accept { treaty, .. } => treaty.id,
            Self::Get { agreement }
            | Self::Queue { agreement, .. }
            | Self::List { agreement, .. } => *agreement,
            Self::Agreements { .. } => wire::digest(b"FederationAgreements"),
            Self::Withdraw { agreement }
            | Self::Admission { agreement, .. }
            | Self::Export { agreement, .. }
            | Self::Import { agreement, .. } => agreement.id,
            Self::BridgeRegister { profile } => profile.service,
            Self::BridgeGet { service } => *service,
            Self::BridgeWithdraw { bridge } => bridge.id,
            Self::Share { share } => share.identity().expect("fixed share identity"),
            Self::ShareStatus { agreement, page } => {
                share_id(*agreement, *page).expect("fixed share identity")
            }
            Self::Unshare { share } => share.id,
            Self::Inspect { page, .. } | Self::Read { page, .. } => *page,
            Self::Review { review, .. } => review.revision.id,
            Self::PageWithdraw { page } => page.id,
            Self::ForeignSeal { trust, .. } | Self::ForeignActivate { trust, .. } => trust.id,
        }
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::ContentAuthorise { .. }
                | Self::MediaGet { .. }
                | Self::MediaAuthorise { .. }
                | Self::MediaReceipt { .. }
                | Self::MediaInspect { .. }
                | Self::TrustAccept { .. }
                | Self::TrustWithdraw { .. }
                | Self::Accept { .. }
                | Self::Withdraw { .. }
                | Self::BridgeRegister { .. }
                | Self::BridgeWithdraw { .. }
                | Self::Share { .. }
                | Self::Unshare { .. }
                | Self::Export { .. }
                | Self::Import { .. }
                | Self::Inspect { .. }
                | Self::Review { .. }
                | Self::Read { .. }
                | Self::List { .. }
                | Self::PageWithdraw { .. }
                | Self::ForeignSeal { .. }
                | Self::ForeignActivate { .. }
        )
    }
    pub fn media_command(&self) -> Option<page::Command> {
        match self {
            Self::ContentAuthorise {
                placement,
                host,
                offset,
                bytes,
                ..
            } => Some(page::Command::Content(page::content::Command::Authorise {
                placement: placement.clone(),
                host: host.clone(),
                effect: page::content::Effect::Read,
                offset: *offset,
                bytes: *bytes,
                digest: None,
            })),
            Self::MediaAuthorise {
                asset,
                host,
                effect,
                offset,
                bytes,
                digest,
                ..
            } => Some(page::Command::MediaAuthorise {
                asset: asset.clone(),
                host: host.clone(),
                effect: *effect,
                offset: *offset,
                bytes: *bytes,
                digest: *digest,
            }),
            _ => None,
        }
    }
    pub fn foreign_proof(&self) -> Option<&ForeignProof> {
        match self {
            Self::ContentAuthorise { proof, .. }
            | Self::MediaGet { proof, .. }
            | Self::MediaAuthorise { proof, .. }
            | Self::MediaReceipt { proof, .. }
            | Self::MediaInspect { proof, .. } => Some(proof),
            _ => None,
        }
    }
    pub fn command_inputs(&self) -> Vec<Reference> {
        vec![]
    }
    pub fn required_inputs(&self, _state: &State) -> Result<Vec<Reference>> {
        Ok(vec![])
    }
    pub fn mutation_indices(&self, state: &State) -> Result<BTreeSet<(u64, Digest)>> {
        let mut out = BTreeSet::new();
        match self {
            Self::ContentAuthorise { proof, .. }
            | Self::MediaGet { proof, .. }
            | Self::MediaAuthorise { proof, .. } => {
                out.insert(proof.floor.index());
            }
            Self::MediaReceipt { receipt, proof } => {
                out.extend([(145, receipt.asset.id), proof.floor.index()]);
            }
            Self::MediaInspect { asset, proof, .. } => {
                out.extend([(145, asset.id), proof.floor.index()]);
            }
            Self::TrustAccept { .. } => {
                out.extend([(150, self.resource()), (157, self.resource())]);
            }
            Self::TrustWithdraw { trust } => {
                out.insert(trust.index());
            }
            Self::Accept { .. } | Self::Withdraw { .. } => {
                out.insert((151, self.resource()));
            }
            Self::BridgeRegister { .. } | Self::BridgeWithdraw { .. } => {
                out.insert((152, self.resource()));
            }
            Self::Share { .. } | Self::Unshare { .. } => {
                out.insert((153, self.resource()));
            }
            Self::Export { admission, .. } => {
                out.insert(admission.floor.index());
            }
            Self::Import {
                agreement, export, ..
            } => {
                let treaty = Agreement::parse(
                    &state.record(151, agreement.id)?.payload,
                    state.network,
                    state.incarnation,
                )?
                .treaty;
                let (page, native) = export.exported_revision()?;
                let id = qualified_page(agreement.id, &treaty.source, page)?;
                out.insert((154, id));
                let (share, metadata) = export.exported_share_metadata()?;
                let revision = revision_id(id, &native, &share)?;
                out.insert((155, revision));
                let reference = &state.record(155, revision)?.reference;
                for asset in &metadata.assets {
                    out.insert((144, page::asset_id(reference, &asset.id)?));
                }
                out.insert(export.floor.index());
            }
            Self::Inspect { export, .. }
            | Self::Read { export, .. }
            | Self::List { export, .. } => {
                out.insert(export.floor.index());
            }
            Self::Review { review, export } => {
                let revision =
                    ForeignRevision::parse(&state.record(155, review.revision.id)?.payload)?;
                out.extend([
                    (154, revision.page),
                    (156, review.revision.id),
                    export.floor.index(),
                ]);
            }
            Self::PageWithdraw { page } => {
                out.insert(page.index());
            }
            Self::ForeignSeal { floor, .. } | Self::ForeignActivate { floor, .. } => {
                out.insert(floor.index());
            }
            _ => {}
        }
        Ok(out)
    }
}
