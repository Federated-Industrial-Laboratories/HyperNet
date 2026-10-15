// SPDX-License-Identifier: MIT
// Exact live Page authorization is reconstructed from committed governance and domain state.
use super::*;
pub(crate) struct Evaluation<'a> {
    pub(crate) state: &'a State,
    pub(crate) governance: Governance,
    pub(crate) index: Index,
    pub(crate) at: u64,
    pub(crate) dependencies: Vec<VersionRef>,
    pub(crate) selected: BTreeMap<(u64, Digest), Record>,
    pub(crate) expires: u64,
}
impl Evaluation<'_> {
    pub(crate) fn optional<T>(
        &mut self,
        evaluate: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Option<T> {
        let prior = (
            self.dependencies.clone(),
            self.selected.clone(),
            self.expires,
        );
        match evaluate(self) {
            Ok(value) => Some(value),
            Err(_) => {
                self.dependencies = prior.0;
                self.selected = prior.1;
                self.expires = prior.2;
                None
            }
        }
    }
    pub(crate) fn select(&mut self, kind: u64, id: Digest) -> Result<Record> {
        let record = self.state.record(kind, id)?.clone();
        self.dependencies.push(record.reference.clone());
        self.selected
            .insert(record.reference.index(), record.clone());
        Ok(record)
    }
    pub(crate) fn exact(&mut self, r: &VersionRef) -> Result<Record> {
        let record = self.select(r.kind, r.id)?;
        ensure!(record.reference == *r, "Page dependency is stale");
        Ok(record)
    }
    pub(crate) fn capability(
        &mut self,
        grant: &VersionRef,
        subject: Key,
        actions: &[u64],
        scope: (u64, Digest),
        namespace: Option<&str>,
        bytes: u64,
    ) -> Result<()> {
        self.capability_usage(grant, subject, actions, scope, namespace, [bytes, 1, 1, 1])
    }
    pub(crate) fn capability_usage(
        &mut self,
        grant: &VersionRef,
        subject: Key,
        actions: &[u64],
        scope: (u64, Digest),
        namespace: Option<&str>,
        usage: [u64; 4],
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "Page capability is stale"
        );
        let cap = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions,
                scope,
                namespace: namespace.map(namespace_id).transpose()?,
                usage,
                evaluated_at_ms: self.at,
                expected: &[],
            },
        )?;
        self.dependencies.extend(cap.dependencies);
        self.expires = self.expires.min(cap.expires_ms);
        Ok(())
    }
    pub(crate) fn application(
        &mut self,
        subject: Key,
        grant: &VersionRef,
        required: Option<&VersionRef>,
        permission: &str,
        namespace: &str,
        page: Option<[u8; 16]>,
    ) -> Result<Option<ApplicationPolicy>> {
        let registration = self
            .governance
            .record_bytes(127, subject)
            .ok()
            .map(|v| v.to_vec());
        match registration {
            None => {
                ensure!(
                    required.is_none(),
                    "ordinary Page principal supplied application policy"
                );
                Ok(None)
            }
            Some(bytes) => {
                let registration = crate::authority_applications::Registration::parse(
                    &bytes,
                    self.state.network,
                    self.state.incarnation,
                )?;
                ensure!(
                    registration.grant == *grant
                        && current(self.at, registration.validity)
                        && self.governance.record_bytes(128, subject).is_err(),
                    "Page application admission is stale or withdrawn"
                );
                self.dependencies.push(registration.reference.clone());
                let record = self.select(148, subject)?;
                ensure!(
                    required.is_none_or(|r| *r == record.reference),
                    "Page application policy version differs"
                );
                let policy = ApplicationPolicy::parse(
                    record.payload.bytes()?,
                    self.state.network,
                    self.state.incarnation,
                )?;
                ensure!(
                    policy.registration == registration.reference
                        && policy.grant == *grant
                        && policy.owner == registration.owner
                        && policy.expires_ms > self.at.saturating_add(1250)
                        && policy.expires_ms <= registration.validity.1
                        && policy.allows(permission, namespace, page),
                    "Page native application consent does not permit this operation"
                );
                self.expires = self.expires.min(policy.expires_ms);
                Ok(Some(policy))
            }
        }
    }
    pub(crate) fn read_subject(
        &mut self,
        requester: Key,
        grant: &VersionRef,
        scope: (u64, Digest),
        namespace: Option<&str>,
    ) -> Result<Key> {
        let bytes = self.governance.record_bytes(102, grant.id)?;
        let v = wire::decode(bytes)?;
        let subject = v.array(17)?[8].fixed::<32>()?;
        if subject == requester {
            return Ok(subject);
        }
        use crate::authority_domains::sealed_identity as identity;
        let binding = self
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 108)
            .find_map(|r| {
                identity::Binding::parse(
                    &identity::payload(r).ok()?,
                    self.state.network,
                    self.state.incarnation,
                )
                .ok()
                .filter(|d| d.signing_key == requester)
            })
            .context("reader has no admitted device identity")?;
        let root_record = self.exact(&binding.root)?;
        let root = identity::Root::parse(
            &identity::payload(&root_record)?,
            self.state.network,
            self.state.incarnation,
        )?;
        let mut admission = identity::admitted_device(self.state, &root, &binding, self.at, scope)?;
        if admission.is_none()
            && let Some(namespace) = namespace
        {
            admission = identity::admitted_device(
                self.state,
                &root,
                &binding,
                self.at,
                (1, namespace_id(namespace)?),
            )?;
        }
        let admission =
            admission.context("reader device admission does not cover this resource")?;
        let member = identity::current_member(
            &self.governance,
            self.state.network,
            binding.member,
            self.at,
        )?;
        ensure!(
            member.key == subject,
            "reader device cannot borrow another member grant"
        );
        self.exact(&binding.reference)?;
        self.exact(&admission.reference)?;
        self.dependencies.extend(member.dependencies);
        self.expires = self
            .expires
            .min(member.expires_ms)
            .min(binding.validity.1)
            .min(admission.validity.1);
        Ok(subject)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_capability(
        &mut self,
        grant: &VersionRef,
        requester: Key,
        actions: &[u64],
        scope: (u64, Digest),
        namespace: Option<&str>,
        bytes: u64,
    ) -> Result<()> {
        ensure!(
            actions.iter().all(|a| matches!(a, 0 | 1)),
            "device mapping is limited to reading and search"
        );
        let subject = self.read_subject(requester, grant, scope, namespace)?;
        self.capability(grant, subject, actions, scope, namespace, bytes)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Capability and application checks bind the participant, grant, action, scope and requested extent explicitly."
    )]
    pub(crate) fn principal(
        &mut self,
        subject: Key,
        grant: &VersionRef,
        application: Option<&VersionRef>,
        permission: &str,
        namespace: &str,
        page: Option<[u8; 16]>,
        bytes: u64,
    ) -> Result<Option<ApplicationPolicy>> {
        let action = match permission {
            "PagesRead" | "MediaRead" => 0,
            "PagesSubmit" | "MediaSubmit" => 2,
            "ReviewInspect" | "ReviewDecide" | "MediaInspect" => 3,
            _ => anyhow::bail!("unknown native Page permission"),
        };
        let scope = match page {
            Some(page) => (2, page_id(&page)?),
            None => (1, namespace_id(namespace)?),
        };
        if action == 0 {
            self.read_capability(grant, subject, &[action], scope, Some(namespace), bytes)?;
        } else {
            self.capability(grant, subject, &[action], scope, Some(namespace), bytes)?;
        }
        self.application(subject, grant, application, permission, namespace, page)
    }
    pub(crate) fn profile(&mut self, p: &HostProfile, live: bool) -> Result<()> {
        let m = &p.manifest;
        let r = self
            .index
            .deployments
            .get(&m.deployment)
            .context("Page deployment absent")?
            .clone();
        ensure!(
            r.operator == m.operator
                && r.services.get(&p.role) == Some(&p.service)
                && self.governance.record_bytes(117, m.deployment)? == m.desired()?
                && self.governance.record_bytes(105, m.deployment)? == m.unsigned_consent(0)?,
            "Page profile differs from admitted deployment"
        );
        self.dependencies
            .extend([r.reference, r.profile, r.consent]);
        if let Some(w) = self.index.withdrawals.get(&m.deployment) {
            self.dependencies.push(w.reference.clone());
            ensure!(!live, "Page deployment withdrawn");
        }
        if live {
            ensure!(current(self.at, m.validity), "Page deployment expired");
            self.expires = self.expires.min(m.validity.1);
            self.capability(&r.grant, r.registrar, &[13], (5, m.deployment), None, 0)?;
        }
        Ok(())
    }
    pub(crate) fn host(
        &mut self,
        r: &VersionRef,
        namespace: Option<&str>,
        live: bool,
    ) -> Result<Host> {
        ensure!(
            matches!(r.kind, 143 | 147),
            "unsupported Page host reference"
        );
        let record = self.exact(r)?;
        let host = Host::parse(&record.payload, self.state.network, self.state.incarnation)?;
        self.profile(&host.profile, live)?;
        if live {
            ensure!(
                !host.withdrawn
                    && namespace.is_none_or(|n| host.profile.namespaces.iter().any(|s| s == n)),
                "Page host is withdrawn or namespace is not consented"
            );
            self.capability(
                &host.grant,
                host.manager,
                &[26],
                (5, host.profile.manifest.deployment),
                None,
                0,
            )?;
            self.capability(
                &host.grant,
                host.manager,
                &[5],
                (3, host.profile.service),
                None,
                0,
            )?;
        }
        Ok(host)
    }
    pub(crate) fn ledger(&mut self, page: [u8; 16]) -> Result<(Record, Ledger)> {
        let r = self.select(140, page_id(&page)?)?;
        let ledger = Ledger::parse(&r.payload)?;
        Ok((r, ledger))
    }
    pub(crate) fn revision(&mut self, r: &VersionRef, live: bool) -> Result<Revision> {
        let record = self.exact(r)?;
        let revision =
            Revision::parse(&record.payload, self.state.network, self.state.incarnation)?;
        if live {
            crate::authority_domains::publication_modes::permitted(
                self,
                &revision.author.namespace,
                Some(revision.author.intent.resource),
                0,
            )?;
            let a = &revision.author;
            ensure!(
                a.expires_ms > self.at.saturating_add(1250),
                "Page author provenance expired"
            );
            self.expires = self.expires.min(a.expires_ms);
            let policy = self.principal(
                a.intent.requester,
                &a.grant,
                a.application.as_ref(),
                "PagesSubmit",
                &a.namespace,
                Some(a.raw_page),
                a.source.len() as u64,
            )?;
            ensure!(
                policy.is_some() == a.application.is_some(),
                "Page author omits exact application policy"
            );
        }
        Ok(revision)
    }
    pub(crate) fn publication(
        &mut self,
        page: [u8; 16],
    ) -> Result<(Record, Ledger, Review, Revision)> {
        let (head, ledger) = self.ledger(page)?;
        let publication = ledger.published.as_ref().context("Page is not published")?;
        let record = self.exact(publication)?;
        let review = Review::parse(&record.payload, self.state.network, self.state.incarnation)?;
        let revision = self.revision(&review.statement.revision, true)?;
        let s = &review.statement;
        ensure!(s.approve, "Page publication is not approved");
        let policy = self.principal(
            s.intent.requester,
            &s.grant,
            s.application.as_ref(),
            "ReviewDecide",
            &revision.author.namespace,
            Some(page),
            revision.author.source.len() as u64,
        )?;
        ensure!(
            policy.is_some() == s.application.is_some()
                && policy.as_ref().map(|p| p.review) == s.policy.map(|p| Some((s.mode, p))),
            "Page review mode or policy changed"
        );
        Ok((head, ledger, review, revision))
    }
    pub(crate) fn asset(
        &mut self,
        r: &VersionRef,
        live: bool,
    ) -> Result<(Asset, Revision, Ledger)> {
        let record = self.exact(r)?;
        let asset = Asset::parse(&record.payload)?;
        let revision = self.revision(&asset.revision, live)?;
        let (_, ledger) = self.ledger(revision.author.raw_page)?;
        if live {
            ensure!(
                asset.expires_ms > self.at.saturating_add(1250)
                    && (ledger.pending.as_ref() == Some(&asset.revision)
                        || ledger
                            .published
                            .as_ref()
                            .is_some_and(|p| p.id == asset.revision.id)),
                "media asset is not part of a current Page revision"
            );
            self.expires = self.expires.min(asset.expires_ms);
        }
        Ok((asset, revision, ledger))
    }
    pub(crate) fn minimum_copies(&mut self, namespace: &str) -> Result<u64> {
        let id = namespace_id(namespace)?;
        if !self.state.records.contains_key(&(149, id)) {
            return Ok(1);
        }
        let record = self.select(149, id)?;
        let policy = PlacementPolicy::parse(&record.payload)?;
        // Once ordered, a restrictive placement policy does not disappear with its author's grant.
        Ok(policy.minimum_copies)
    }
    pub(crate) fn media_metadata(
        &mut self,
        revision_ref: &VersionRef,
        revision: &Revision,
    ) -> Result<()> {
        for manifest in &revision.assets {
            let record = self.select(144, asset_id(revision_ref, &manifest.id)?)?;
            let asset = Asset::parse(&record.payload)?;
            for host in &asset.hosts {
                let current = self.select(143, host.id)?;
                self.host(&current.reference, Some(&revision.author.namespace), false)?;
            }
            if self.state.records.contains_key(&(145, record.reference.id)) {
                self.select(145, record.reference.id)?;
            }
        }
        Ok(())
    }
    pub(crate) fn media_complete(
        &mut self,
        revision_ref: &VersionRef,
        revision: &Revision,
        reviewer: &objects::Reviewer,
    ) -> Result<()> {
        let minimum = self.minimum_copies(&revision.author.namespace)?;
        for manifest in &revision.assets {
            let record = self.select(144, asset_id(revision_ref, &manifest.id)?)?;
            let (asset, _, _) = self.asset(&record.reference, true)?;
            self.principal(
                reviewer.intent.requester,
                &reviewer.grant,
                reviewer.application.as_ref(),
                "MediaInspect",
                &revision.author.namespace,
                Some(revision.author.raw_page),
                manifest.bytes,
            )?;
            let record = self.select(145, record.reference.id)?;
            let evidence =
                Evidence::parse(&record.payload, self.state.network, self.state.incarnation)?;
            ensure!(
                evidence.asset == self.state.record(144, record.reference.id)?.reference,
                "media evidence does not bind exact asset"
            );
            let inspection = evidence
                .inspections
                .iter()
                .find(|v| v.reviewer == reviewer.intent.requester)
                .context("exact media inspection missing")?;
            ensure!(
                inspection.grant == reviewer.grant
                    && inspection.application == reviewer.application
                    && inspection.expires_ms > self.at.saturating_add(1250),
                "media review acknowledgement is stale"
            );
            let mut copies = 0;
            for receipt in evidence.copies {
                if self
                    .optional(|c| c.host(&receipt.host, Some(&revision.author.namespace), true))
                    .is_some()
                {
                    ensure!(
                        asset.hosts.contains(&receipt.host)
                            && hex::encode(receipt.digest) == manifest.digest
                            && receipt.bytes == manifest.bytes,
                        "media copy receipt differs"
                    );
                    copies += 1;
                }
            }
            ensure!(
                copies >= asset.required_copies.max(minimum),
                "media copies do not meet current placement policy"
            );
        }
        Ok(())
    }
    pub(crate) fn ticket(&mut self, r: &VersionRef) -> Result<(Ticket, Review, Revision)> {
        let record = self.exact(r)?;
        let ticket = Ticket::parse(&record.payload)?;
        ensure!(
            ticket.expires_ms > self.at.saturating_add(1250),
            "Page replica ticket expired"
        );
        let review_record = self.exact(&ticket.publication)?;
        let review = Review::parse(
            &review_record.payload,
            self.state.network,
            self.state.incarnation,
        )?;
        let revision = self.revision(&review.statement.revision, true)?;
        let (_, ledger, _, _) = self.publication(revision.author.raw_page)?;
        ensure!(
            ledger.published.as_ref() == Some(&ticket.publication),
            "Page replica publication changed"
        );
        self.principal(
            ticket.reader,
            &ticket.grant,
            ticket.application.as_ref(),
            "PagesRead",
            &revision.author.namespace,
            Some(revision.author.raw_page),
            revision.author.source.len() as u64,
        )?;
        self.host(&ticket.host, Some(&revision.author.namespace), true)?;
        self.expires = self.expires.min(ticket.expires_ms);
        Ok((ticket, review, revision))
    }
}
