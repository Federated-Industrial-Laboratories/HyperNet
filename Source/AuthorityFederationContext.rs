// SPDX-License-Identifier: MIT
// Federation rights intersect current local grants with exact bilateral and operator consent.
use super::*;

impl page::Evaluation<'_> {
    pub(super) fn federation_agreement(&mut self, reference: &VersionRef) -> Result<Agreement> {
        let record = self.exact(reference)?;
        let agreement =
            Agreement::parse(&record.payload, self.state.network, self.state.incarnation)?;
        ensure!(
            !agreement.withdrawn && agreement.treaty.expires_ms > self.at.saturating_add(1250),
            "federation agreement is withdrawn or expired"
        );
        self.capability(
            &agreement.grant,
            agreement.approver,
            &[22],
            (2, agreement.treaty.id),
            None,
            0,
        )?;
        let trust_record = self.exact(&agreement.foreign)?;
        let trust = ForeignTrust::parse(
            &trust_record.payload,
            self.state.network,
            self.state.incarnation,
        )?;
        let source = agreement
            .treaty
            .source_side(self.state.network, self.state.incarnation)?;
        ensure!(
            !trust.withdrawn && &trust.identity == agreement.treaty.foreign(source),
            "agreement foreign identity is not independently accepted"
        );
        self.capability(
            &trust.grant,
            trust.approver,
            &[22],
            (2, trust.identity()?),
            None,
            0,
        )?;
        self.expires = self.expires.min(agreement.treaty.expires_ms);
        Ok(agreement)
    }
    pub(super) fn federation_profile(&mut self, profile: &BridgeProfile) -> Result<()> {
        let manifest = &profile.manifest;
        let deployment = self
            .index
            .deployments
            .get(&manifest.deployment)
            .context("bridge deployment is absent")?
            .clone();
        ensure!(
            deployment.operator == manifest.operator
                && deployment.services.get(&7) == Some(&profile.service)
                && self.governance.record_bytes(117, manifest.deployment)? == manifest.desired()?
                && self.governance.record_bytes(105, manifest.deployment)?
                    == manifest.unsigned_consent(0)?,
            "bridge profile differs from exact admitted deployment"
        );
        self.dependencies
            .extend([deployment.reference, deployment.profile, deployment.consent]);
        if let Some(withdrawal) = self.index.withdrawals.get(&manifest.deployment) {
            self.dependencies.push(withdrawal.reference.clone());
            anyhow::bail!("bridge deployment withdrawn")
        }
        ensure!(
            crate::authority_membership::current(self.at, manifest.validity),
            "bridge deployment expired"
        );
        self.capability(
            &deployment.grant,
            deployment.registrar,
            &[13],
            (5, manifest.deployment),
            None,
            0,
        )?;
        self.expires = self.expires.min(manifest.validity.1);
        Ok(())
    }
    pub(super) fn federation_bridge(
        &mut self,
        reference: &VersionRef,
        treaty: &Treaty,
    ) -> Result<Bridge> {
        let selected = self.exact(reference)?;
        let bridge = Bridge::parse(
            &selected.payload,
            self.state.network,
            self.state.incarnation,
        )?;
        let source = treaty.source_side(self.state.network, self.state.incarnation)?;
        ensure!(
            !bridge.withdrawn
                && bridge.profile.service == treaty.bridge(source)
                && bridge
                    .profile
                    .agreements
                    .contains(&(treaty.id, treaty.digest()?))
                && bridge.profile.manifest.bootstrap_digest == treaty.local(source).file_digest,
            "bridge did not consent to these exact bilateral terms or local bootstrap"
        );
        self.federation_profile(&bridge.profile)?;
        self.capability(
            &bridge.grant,
            bridge.manager,
            &[26],
            (5, bridge.profile.manifest.deployment),
            None,
            0,
        )?;
        Ok(bridge)
    }
    pub(super) fn federation_foreign(
        &mut self,
        proof: &ForeignProof,
        treaty: &Treaty,
        objects: &Resolved,
        replay: bool,
    ) -> Result<VerifiedForeign> {
        self.exact(&proof.trust)?;
        self.select(157, proof.floor.id)?;
        let verified = proof.verify(self.state, treaty, self.at, objects, replay)?;
        self.expires = self.expires.min(verified.expires_ms);
        Ok(verified)
    }
    pub(super) fn federation_destination_context(
        &mut self,
        treaty: &Treaty,
        raw: [u8; 16],
    ) -> Result<()> {
        super::super::publication_modes::permitted(
            self,
            &treaty.destination_namespace,
            Some(qualified_page(treaty.id, &treaty.source, raw)?),
            0,
        )?;
        for id in &treaty.destination_hosts {
            let host = self.select(143, *id)?;
            self.host(&host.reference, Some(&treaty.destination_namespace), true)?;
        }
        self.minimum_copies(&treaty.destination_namespace)?;
        let id = qualified_page(treaty.id, &treaty.source, raw)?;
        if !self.state.records.contains_key(&(154, id)) {
            return Ok(());
        }
        let head = ForeignPage::parse(&self.select(154, id)?.payload)?;
        ensure!(
            head.source == treaty.source && head.agreement == treaty.id && head.raw_page == raw,
            "destination context names another foreign Page"
        );
        let revision = self.select(155, revision_id(id, &head.observed, &head.source_share)?)?;
        let value = ForeignRevision::parse(&revision.payload)?;
        ensure!(
            value.page == id && value.native == head.observed && value.share == head.source_share,
            "destination context differs from its retained revision"
        );
        // Retained placement and copy evidence keep repeated imports from recreating existing assets.
        for manifest in &value.metadata.assets {
            let asset = self.select(144, page::asset_id(&revision.reference, &manifest.id)?)?;
            if self.state.records.contains_key(&(145, asset.reference.id)) {
                self.select(145, asset.reference.id)?;
            }
        }
        Ok(())
    }
    pub(super) fn federation_source(
        &mut self,
        treaty: &Treaty,
        raw: [u8; 16],
    ) -> Result<(Record, page::Review, page::Revision, Record, Share)> {
        ensure!(
            treaty
                .source
                .matches(self.state.network, self.state.incarnation),
            "export is not evaluated in its source network"
        );
        let (head, ledger, review, revision) = self.publication(raw)?;
        ensure!(
            revision.author.namespace == treaty.source_namespace,
            "source publication is outside treaty namespace"
        );
        let share_record = self.select(153, share_id(treaty.id, raw)?)?;
        let share = Share::parse(
            &share_record.payload,
            self.state.network,
            self.state.incarnation,
        )?;
        ensure!(
            share.allowed
                && share.author == revision.author.intent.requester
                && ledger.published.as_ref() == Some(&share.publication)
                && share.revision == review.statement.revision,
            "source author has not shared this exact current publication"
        );
        self.capability(
            &share.grant,
            share.author,
            &[4],
            (2, head.reference.id),
            Some(&treaty.source_namespace),
            revision.author.source.len() as u64,
        )?;
        self.application(
            share.author,
            &share.grant,
            revision.author.application.as_ref(),
            "PagesSubmit",
            &treaty.source_namespace,
            Some(raw),
        )?;
        let mut bytes = 0u64;
        for asset in &revision.assets {
            ensure!(
                treaty.media_profiles.contains(&asset.profile)
                    && asset.hosts.iter().all(|host| hex::decode(host)
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                        .is_some_and(|key| treaty.source_hosts.contains(&key))),
                "source media exceeds bilateral host or format scope"
            );
            bytes = bytes
                .checked_add(asset.bytes)
                .context("federation media byte count overflow")?;
        }
        ensure!(
            bytes <= treaty.media_bytes,
            "source media exceeds bilateral byte consent"
        );
        self.media_metadata(&review.statement.revision, &revision)?;
        page::content::select_placement(self, &review.statement.revision, &revision, false)?;
        Ok((head, review, revision, share_record, share))
    }
    pub(super) fn federation_revision(
        &mut self,
        page_id: Digest,
        published: bool,
    ) -> Result<(Record, ForeignPage, Record, ForeignRevision)> {
        let head = self.select(154, page_id)?;
        let page = ForeignPage::parse(&head.payload)?;
        ensure!(
            !published || !page.withdrawn,
            "foreign page was withdrawn locally"
        );
        let revision = if published {
            let approval = self.exact(
                page.published
                    .as_ref()
                    .context("foreign page has no local approval")?,
            )?;
            let review = ForeignReview::parse(
                &approval.payload,
                self.state.network,
                self.state.incarnation,
            )?;
            ensure!(review.approve, "foreign page was rejected locally");
            review.revision
        } else {
            page.pending
                .clone()
                .context("foreign page has no pending local review")?
        };
        let selected = self.exact(&revision)?;
        let revision = ForeignRevision::parse(&selected.payload)?;
        ensure!(
            revision.page == page_id
                && revision.native == page.observed
                && revision.share == page.source_share,
            "foreign page head differs from its exact imported revision"
        );
        Ok((head, page, selected, revision))
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Authority checks bind the participant, grant, application, qualified page, treaty and effect amount independently."
    )]
    pub(super) fn federation_principal(
        &mut self,
        requester: Key,
        grant: &VersionRef,
        application: Option<&VersionRef>,
        action: u64,
        treaty: &Treaty,
        page: Digest,
        raw: [u8; 16],
        bytes: u64,
    ) -> Result<()> {
        self.capability(
            grant,
            requester,
            &[action],
            (2, page),
            Some(&treaty.destination_namespace),
            bytes,
        )?;
        self.application(
            requester,
            grant,
            application,
            match action {
                0 => "PagesRead",
                3 => "ReviewDecide",
                _ => anyhow::bail!("unsupported local foreign publication action"),
            },
            &treaty.destination_namespace,
            Some(raw),
        )?;
        Ok(())
    }
    pub(super) fn federation_media(
        &mut self,
        revision: &VersionRef,
        value: &ForeignRevision,
        treaty: &Treaty,
        reviewer: Option<&ForeignReview>,
    ) -> Result<()> {
        for manifest in &value.metadata.assets {
            let selected = self.select(144, page::asset_id(revision, &manifest.id)?)?;
            let asset = page::Asset::parse(&selected.payload)?;
            ensure!(
                asset.revision == *revision && asset.manifest == *manifest,
                "foreign asset differs from its exact approved source"
            );
            for host in &asset.hosts {
                let record = self.select(143, host.id)?;
                self.host(
                    &record.reference,
                    Some(&treaty.destination_namespace),
                    false,
                )?;
            }
            let Some(reviewer) = reviewer else {
                if self
                    .state
                    .records
                    .contains_key(&(145, selected.reference.id))
                {
                    self.select(145, selected.reference.id)?;
                }
                continue;
            };
            let evidence_record = self.select(145, selected.reference.id)?;
            let evidence = page::Evidence::parse(
                &evidence_record.payload,
                self.state.network,
                self.state.incarnation,
            )?;
            ensure!(
                evidence.asset == selected.reference,
                "foreign media evidence names another asset"
            );
            let inspection = evidence
                .inspections
                .iter()
                .find(|r| r.reviewer == reviewer.reviewer)
                .context("foreign media has no exact reviewer inspection")?;
            ensure!(
                inspection.grant == reviewer.grant
                    && inspection.application == reviewer.application
                    && inspection.expires_ms > self.at.saturating_add(1250),
                "foreign media inspection is stale or from another grant"
            );
            let mut copies = 0;
            for receipt in &evidence.copies {
                if self
                    .optional(|c| c.host(&receipt.host, Some(&treaty.destination_namespace), true))
                    .is_some()
                {
                    ensure!(
                        asset.hosts.contains(&receipt.host)
                            && treaty.destination_hosts.contains(&receipt.host.id)
                            && receipt.bytes == manifest.bytes
                            && hex::encode(receipt.digest) == manifest.digest,
                        "foreign media copy exceeds exact destination placement"
                    );
                    copies += 1;
                }
            }
            ensure!(
                copies
                    >= asset
                        .required_copies
                        .max(treaty.copies)
                        .max(self.minimum_copies(&treaty.destination_namespace)?),
                "foreign media lacks currently approved destination copies"
            );
        }
        Ok(())
    }
    pub(super) fn federation_page_media_context(
        &mut self,
        revision: &VersionRef,
        value: &ForeignRevision,
        treaty: &Treaty,
    ) -> Result<()> {
        self.federation_media(revision, value, treaty, None)?;
        self.minimum_copies(&treaty.destination_namespace)?;
        for manifest in &value.metadata.assets {
            let record = self
                .state
                .record(144, page::asset_id(revision, &manifest.id)?)?;
            let asset = page::Asset::parse(&record.payload)?;
            for host in &asset.hosts {
                let current = self.state.record(143, host.id)?.reference.clone();
                // Metadata remains inspectable when a copy is unavailable; effects recheck live consent.
                let _ =
                    self.optional(|c| c.host(&current, Some(&treaty.destination_namespace), true));
            }
        }
        Ok(())
    }
}
