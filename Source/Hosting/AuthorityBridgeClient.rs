// SPDX-License-Identifier: MIT
// The registered Bridge host uses its own retained stream and independently checks every metadata change.
use super::*;
use crate::{
    authority_challenge::{self, FEDERATION_DURATION_MS, MAXIMUM_DURATION_MS, Session},
    authority_domains::{self as domains, Command as DomainCommand, Operation, result},
    authority_floor::Store,
    authority_local_transport as transport,
    authority_membership::{Reservations, reference},
    authority_objects::Resolved,
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, Intent, OperationResult,
        Restrictions, SignedRequest, VersionRef,
    },
};
use rand::{RngCore, rngs::OsRng};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn random() -> Result<[u8; 32]> {
    let mut v = [0; 32];
    OsRng.try_fill_bytes(&mut v)?;
    ensure!(v != [0; 32], "zero Bridge request nonce");
    Ok(v)
}
pub struct Client<'a> {
    config: &'a Config,
    guard: &'a Guard,
    active: &'a Active,
    store: Store,
    session: Session,
    disk: disk::Disk,
}
impl<'a> Client<'a> {
    pub fn open(config: &'a Config, guard: &'a Guard, active: &'a Active) -> Result<Self> {
        active.check(guard)?;
        let store = Store::open(
            Path::new("/State/Requester"),
            guard.bootstrap.descriptor().clone(),
        )
        .context("open Bridge requester floor")?;
        store.require_requester(config.profile.service)?;
        let disk = disk::Disk::open_bridge(
            Path::new("/State/BridgeState.bin"),
            &config.profile,
            guard.health()?.observe()?.wall_ms,
        )
        .context("open Bridge metadata and bundle cache")?;
        let out = Self {
            config,
            guard,
            active,
            store,
            session: Session::new()?,
            disk,
        };
        out.check_cache()
            .context("authenticate retained Bridge cache")?;
        Ok(out)
    }
    fn check_cache(&self) -> Result<()> {
        let (state, records) = self.disk.context();
        let scope = self.store.descriptor().scope();
        let mut refs = crate::authority_governance::Governance::record_versions(
            scope.network,
            scope.incarnation,
            records,
        )?;
        refs.extend(state.records.values().map(|r| r.reference.clone()));
        let pending = self
            .store
            .resume_ordinary()?
            .map(|r| Intent::from_signed(r.signed()))
            .transpose()?;
        let historical = self.store.historical_cache_references()?;
        for r in refs {
            ensure!(
                self.store.generations().contains(&r)
                    || historical.contains(&r)
                    || pending
                        .as_ref()
                        .is_some_and(|p| p.action == "AuthorityDomain" && p.expected.contains(&r)),
                "Bridge cache lacks retained quorum authentication"
            );
        }
        if let Some(intent) = pending {
            let operation = Operation::parse(&intent)?;
            self.permitted(&operation.command)?;
            self.disk.objects(&operation.command.command_inputs())?;
        }
        Ok(())
    }
    fn permitted(&self, command: &DomainCommand) -> Result<()> {
        ensure!(
            matches!(
                command,
                DomainCommand::Federation(
                    federation::Command::Get { .. }
                        | federation::Command::SourceContext { .. }
                        | federation::Command::BridgeGet { .. }
                        | federation::Command::Admission { .. }
                        | federation::Command::Export { .. }
                        | federation::Command::Import { .. }
                        | federation::Command::MediaGet { .. }
                        | federation::Command::MediaReceipt { .. }
                        | federation::Command::MediaAuthorise { .. }
                        | federation::Command::ContentAuthorise { .. }
                )
            ),
            "bridge retained an operation outside finite maintenance"
        );
        Ok(())
    }
    fn envelope(&mut self, request: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        let health = self.guard.health()?;
        let now = health.observe()?;
        let duration =
            authority_challenge::maximum_duration_ms(&SignedRequest::from_signed(request)?);
        let challenge =
            self.session
                .issue(request, &self.config.key, random()?, duration, health)?;
        let parsed = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            self.store.descriptor().scope().value(),
            b(request),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))?;
        Ok((
            challenge,
            ordered,
            now.boot_ms
                .checked_add(duration)
                .context("Bridge deadline overflow")?,
        ))
    }
    fn status(&mut self) -> Result<()> {
        self.active.check(self.guard)?;
        let descriptor = self.store.descriptor().clone();
        let scope = descriptor.scope();
        let request = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(55),
                V::Uint(1),
                b(&scope.network),
                b(&scope.incarnation),
                b(&self.store.requester()),
                b(&random()?),
                V::Uint(scope.epoch),
                V::Uint(self.store.prefix().height()),
            ]))?,
            &self.config.key,
        )?;
        let (challenge, ordered, deadline) = self.envelope(&request)?;
        let outcome = (|| {
            let (reply, history) = transport::exchange(
                &descriptor,
                &ordered,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
            )?;
            let result = proof::verify_response(
                &descriptor,
                proof::ProofContext {
                    intent: &request,
                    challenge: &challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: self.store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: None,
                },
                proof::Response {
                    ordered_request: &ordered,
                    operation_result: &reply.result,
                    certificate: &reply.certificate,
                    ancestry: &history.nodes,
                },
                |_, _, _| anyhow::bail!("ordinary result on Bridge stream status path"),
            )?;
            let result = history.attach(&self.store, result)?;
            if result.disposition() != Disposition::Permit {
                let code = result.code();
                self.store.observe(result)?;
                anyhow::bail!("Bridge stream status refused with code {code}");
            }
            ensure!(
                matches!(
                    result.stream_response(),
                    Some(proof::StreamResponse::Status(_))
                ),
                "Bridge status returned another control response"
            );
            self.store
                .accept(result, &mut self.session, self.guard.health()?, 0)?
                .perform(
                    &mut self.store,
                    &mut self.session,
                    self.guard.health()?,
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Bridge status restrictions differ"
                        );
                        Ok(())
                    },
                    |_, _| Ok(()),
                )
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        }
        outcome
    }
    fn prepare(&mut self, command: DomainCommand) -> Result<Vec<u8>> {
        self.permitted(&command)?;
        if let Some(pending) = self.store.resume_ordinary()? {
            let intent = Intent::from_signed(pending.signed())?;
            let operation = Operation::parse(&intent)?;
            ensure!(
                operation.grant.is_none() && operation.command.value() == command.value(),
                "another exact Bridge operation is pending"
            );
            return Ok(pending.signed().to_vec());
        }
        let snapshot = |expected: &[VersionRef]| {
            domains::snapshot(&a(vec![
                a(vec![
                    V::Uint(self.store.prefix().scope().epoch),
                    V::Uint(self.store.prefix().height()),
                    b(self.store.prefix().policy_state()),
                ]),
                a(expected.iter().map(reference).collect()),
            ]))
        };
        let mut operation = Operation {
            grant: None,
            command: command.clone(),
            snapshot: snapshot(&[])?,
        };
        let slot = self.store.ordinary_slot()?;
        let scope = self.store.descriptor().scope();
        let mut fields = vec![
            V::Uint(20),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            V::Uint(slot.generation()),
            b(&slot.generation_id()),
            V::Uint(slot.sequence()),
            V::Uint(slot.acknowledged_through()),
            b(&self.store.requester()),
            V::Text("AuthorityDomain".into()),
            b(&command.resource()),
            V::Uint(u64::from(command.mutation())),
            V::Uint(0),
            V::Uint(slot.minimum_policy_epoch()),
            V::Uint(slot.minimum_policy_height()),
            a(vec![]),
            b(&operation.parameters()?),
        ];
        if command.mutation() {
            let probe = wire::sign_envelope(&wire::encode(&a(fields.clone()))?, &self.config.key)?;
            let intent = Intent::from_signed(&probe)?;
            let (state, records) = self.disk.context();
            let inputs = self.disk.objects(&command.required_inputs(state)?)?;
            let decision = operation.prepare_with_inputs(
                state,
                &result::merge(&self.guard.bootstrap, records)?,
                &Reservations(self.guard.bootstrap.reservations().to_vec()),
                &intent,
                self.guard.health()?.observe()?.wall_ms,
                false,
                false,
                &inputs,
            )?;
            ensure!(
                decision.code == 0,
                "Bridge delivery preflight refused with code {}",
                decision.code
            );
            operation.snapshot = snapshot(&decision.dependencies)?;
            fields[15] = a(decision.dependencies.iter().map(reference).collect());
            fields[16] = b(&operation.parameters()?);
        }
        let signed = wire::sign_envelope(&wire::encode(&a(fields))?, &self.config.key)?;
        Ok(self
            .store
            .prepare_ordinary(slot, &signed)?
            .signed()
            .to_vec())
    }
    pub fn pending(&self) -> Result<Option<federation::Command>> {
        self.store
            .resume_ordinary()?
            .map(|request| {
                let operation = Operation::parse(&Intent::from_signed(request.signed())?)?;
                self.permitted(&operation.command)?;
                let DomainCommand::Federation(command) = operation.command else {
                    unreachable!()
                };
                Ok(command)
            })
            .transpose()
    }
    pub fn action(&mut self, command: federation::Command) -> Result<Completion> {
        self.active.check(self.guard)?;
        ensure!(
            self.store.resume_fence()?.is_none(),
            "Bridge requester has an unresolved explicit fence"
        );
        if self.store.needs_stream_status()? {
            self.status()?;
        }
        let signed = self.prepare(command.into())?;
        let intent = Intent::from_signed(&signed)?;
        let operation = Operation::parse(&intent)?;
        let input_refs = operation.command.command_inputs();
        let inputs = self.disk.objects(&input_refs)?;
        let (challenge, ordered, deadline) = self.envelope(&signed)?;
        let outcome = (|| {
            let descriptor = self.store.descriptor().clone();
            let (reply, history, outputs) = transport::exchange_objects(
                &descriptor,
                &ordered,
                &inputs,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
                &mut |bytes| {
                    domains::response_inputs(
                        &intent,
                        &wire::decode(&OperationResult::parse(bytes)?.value)?,
                    )
                },
            )
            .context("obtain Bridge authority response and history")?;
            let (state, records) = {
                let (s, r) = self.disk.context();
                (s.clone(), r.to_vec())
            };
            let mut objects = inputs.objects().cloned().collect::<Vec<_>>();
            for object in outputs.objects() {
                if let Some(old) = objects.iter().find(|v| v.reference() == object.reference()) {
                    ensure!(
                        old.bytes() == object.bytes(),
                        "Bridge output substituted retained bytes"
                    );
                } else {
                    objects.push(object.clone());
                }
            }
            let mut candidate = None;
            let verified = proof::verify_response(
                &descriptor,
                proof::ProofContext {
                    intent: &signed,
                    challenge: &challenge,
                    restrictions: Restrictions::default(),
                    minimum_height: self.store.prefix().height(),
                    maximum_effect: 1,
                    expected_stream: None,
                },
                proof::Response {
                    ordered_request: &ordered,
                    operation_result: &reply.result,
                    certificate: &reply.certificate,
                    ancestry: &history.nodes,
                },
                |i, r, e| {
                    ensure!(
                        e.restrictions == Restrictions::default(),
                        "Bridge maintenance restrictions differ"
                    );
                    if r.disposition == Disposition::Refuse {
                        let v = wire::decode(&r.value)?;
                        let f = v.array(4)?;
                        ensure!(
                            f[0].uint()? == 201
                                && f[1].uint()? == 1
                                && f[2].text()? == "AuthorityDomain"
                                && f[3].array(0)?.is_empty()
                                && e.maximum_effect == 0,
                            "invalid Bridge refusal"
                        );
                        return ActionValidation::new(vec![]);
                    }
                    let selected =
                        result::verify(&self.guard.bootstrap, &state, &records, i, r, e, &objects)
                            .context("independently evaluate Bridge domain response")?;
                    let validation = ActionValidation::mutation(
                        selected.versions.clone(),
                        selected.updates.clone(),
                    )?;
                    candidate = Some(selected);
                    Ok(validation)
                },
            )
            .context("verify Bridge authority response")?;
            let verified = history
                .attach(&self.store, verified)
                .context("attach Bridge requester history")?;
            if verified.disposition() != Disposition::Permit {
                let code = verified.code();
                self.store.observe(verified)?;
                anyhow::bail!("Bridge maintenance refused with code {code}");
            }
            let candidate = candidate.context("Bridge permit omitted verified domain context")?;
            result::minimum(&candidate.versions, self.store.generations())?;
            let registered = federation::Bridge::parse(
                &candidate
                    .state
                    .record(152, self.config.profile.service)?
                    .payload,
                descriptor.scope().network,
                descriptor.scope().incarnation,
            )?;
            ensure!(
                !registered.withdrawn
                    && registered.profile.envelope == self.config.profile.envelope,
                "Bridge quorum selected another local host profile"
            );
            transport::remaining(deadline)?;
            self.store
                .accept(verified, &mut self.session, self.guard.health()?, 0)?
                .perform(
                    &mut self.store,
                    &mut self.session,
                    self.guard.health()?,
                    1,
                    |r| {
                        self.active.check(self.guard)?;
                        ensure!(
                            *r == Restrictions::default(),
                            "Bridge maintenance restrictions changed"
                        );
                        Ok(())
                    },
                    |_, _| {
                        self.disk.publish_bridge(
                            candidate.state,
                            candidate.records,
                            &outputs,
                            &self.config.profile,
                            self.guard.health()?.observe()?.wall_ms,
                            &operation.command.command_inputs(),
                        )?;
                        transport::remaining(deadline)?;
                        Ok(Completion {
                            value: candidate.value,
                            ordered: ordered.clone(),
                            result: reply.result.clone(),
                            certificate: reply.certificate.clone(),
                            node: reply.node.clone(),
                            objects: Resolved::parse(&outputs.references(), &outputs.value())?,
                            predecessors: intent
                                .expected
                                .iter()
                                .filter(|r| r.kind == 157)
                                .map(|r| Ok(state.record(r.kind, r.id)?.bytes.clone()))
                                .collect::<Result<Vec<_>>>()?,
                        })
                    },
                )
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        }
        outcome
    }
    pub fn recover(&mut self) -> Result<()> {
        if let Some(command) = self.pending()? {
            if matches!(
                command,
                federation::Command::MediaAuthorise { .. }
                    | federation::Command::ContentAuthorise { .. }
            ) {
                let payload = self.disk.bridge_payload()?.to_vec();
                self.media(command, &payload)?;
            } else {
                self.action(command)?;
            }
        }
        Ok(())
    }
    pub fn service(&self) -> Digest {
        self.config.profile.service
    }
    pub fn now(&self) -> Result<u64> {
        Ok(self.guard.health()?.observe()?.wall_ms)
    }
    pub fn deadline(&self) -> Result<u64> {
        self.guard
            .health()?
            .observe()?
            .boot_ms
            .checked_add(FEDERATION_DURATION_MS)
            .context("bridge deadline overflow")
    }
    pub fn media(&mut self, command: federation::Command, payload: &[u8]) -> Result<Vec<u8>> {
        self.active.check(self.guard)?;
        if self.store.needs_stream_status()? {
            self.status()?;
        }
        ensure!(
            payload.len() <= 32768,
            "bridge media payload exceeds one admitted extent"
        );
        let retained = self.store.resume_ordinary()?.is_some();
        if !retained {
            self.disk.stage_bridge_payload(payload, self.now()?)?;
        } else {
            ensure!(
                self.disk.bridge_payload()? == payload,
                "pending bridge media payload differs from retained exact bytes"
            );
        }
        let signed = self.prepare(command.into())?;
        let request = page::MediaRequest::parse(&signed)?;
        let host = match request.command() {
            page::Command::MediaAuthorise { host, .. }
            | page::Command::Content(page::content::Command::Authorise { host, .. }) => host,
            _ => unreachable!(),
        };
        let path = self
            .config
            .media
            .get(&host.id)
            .context("media store has no consented private bridge mount")?;
        let deadline = self.deadline()?;
        let packet = |reconcile| {
            wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text(request.exchange_tag().into()),
                b(&signed),
                b(payload),
                V::Bool(reconcile),
            ]))
        };
        let exchange = |reconcile| {
            transport::LocalControl::open(path)?.exchange_limit(
                &packet(reconcile)?,
                deadline,
                page::MEDIA_RECEIPT_LIMIT,
            )
        };
        let bytes = match exchange(retained) {
            Ok(bytes) => bytes,
            Err(_) if !retained && transport::remaining(deadline).is_ok() => exchange(true)?,
            Err(error) => return Err(error),
        };
        transport::remaining(deadline)?;
        let receipt = page::MediaReceipt::parse(&bytes)?;
        let descriptor = self.store.descriptor_for_scope(&receipt.scope()?)?;
        let report = receipt.verify(&self.guard.bootstrap, &descriptor)?;
        ensure!(
            report.request().digest == request.intent().digest,
            "bridge media completion changed request"
        );
        self.status()?;
        ensure!(
            report.result().disposition() == Disposition::Permit,
            "bridge media effect refused"
        );
        let (state, records) = self.disk.context();
        let candidate = result::verify(
            &self.guard.bootstrap,
            state,
            records,
            request.intent(),
            &report.result().result,
            &report.result().executed,
            &[],
        )?;
        result::minimum(&candidate.versions, self.store.generations())?;
        self.store.retain_media_context(&report)?;
        self.disk.publish_bridge(
            candidate.state,
            candidate.records,
            &Resolved::default(),
            &self.config.profile,
            self.now()?,
            &[],
        )?;
        self.store.record_media(report)?;
        self.active.check(self.guard)?;
        transport::remaining(deadline)?;
        Ok(bytes)
    }
    pub fn local_media_report(&self, bytes: &[u8]) -> Result<page::MediaReport> {
        let receipt = page::MediaReceipt::parse(bytes)?;
        receipt.verify(
            &self.guard.bootstrap,
            &self.store.descriptor_for_scope(&receipt.scope()?)?,
        )
    }
    pub fn context(&self) -> (&domains::State, &[Vec<u8>]) {
        self.disk.context()
    }
    fn search_bundle(
        &self,
        agreement: Digest,
        raw: [u8; 16],
        native: &VersionRef,
    ) -> Result<(Resolved, Vec<u8>)> {
        ensure!(
            self.config.profile.search,
            "bridge indexing consent is absent"
        );
        self.active.check(self.guard)?;
        let state = self.disk.context().0;
        for record in state.records.values().filter(|r| r.reference.kind == 155) {
            let revision = federation::ForeignRevision::parse(&record.payload)?;
            if revision.agreement != agreement
                || revision.native != *native
                || revision.metadata.author.raw_page != raw
            {
                continue;
            }
            ensure!(
                self.disk.live(&revision.bundle, self.now()?),
                "retained imported search body expired"
            );
            let objects = self.disk.objects(std::slice::from_ref(&revision.bundle))?;
            let bundle = page::objects::Bundle::parse(
                objects.get(&revision.bundle)?,
                revision.source.network,
                revision.source.incarnation,
            )?;
            revision.metadata.verify_source(&bundle.source)?;
            return Ok((objects, bundle.source));
        }
        anyhow::bail!("exact imported search body is not retained")
    }
    pub fn stage(&mut self, objects: &Resolved) -> Result<()> {
        let (state, records) = self.disk.context();
        self.disk.publish_bridge(
            state.clone(),
            records.to_vec(),
            objects,
            &self.config.profile,
            self.guard.health()?.observe()?.wall_ms,
            &objects.references(),
        )
    }
    pub fn portable(
        &self,
        completion: &Completion,
        trust: &domains::Record,
        floor: &domains::Record,
    ) -> Result<federation::ForeignProof> {
        let selected = federation::ForeignFloor::parse(&floor.payload)?;
        let verified = crate::trust_bootstrap::inspect(trust.payload.array(5)?[0].bytes()?, true)?;
        let identity = federation::NetworkIdentity::verified(&verified);
        ensure!(
            identity == federation::NetworkIdentity::verified(&self.guard.bootstrap),
            "portable proof anchor accepts another source bootstrap"
        );
        let descriptor =
            crate::authority_epoch::archive::resolve(verified.descriptor(), &selected.epochs)?
                .descriptor;
        ensure!(
            descriptor.canonical() == self.store.descriptor().canonical(),
            "portable proof anchor requires explicit epoch adoption"
        );
        let (prefix, checkpoint) = selected.retained.verify(&descriptor)?;
        let deadline = crate::authority_challenge::boot_time_ms()?
            .checked_add(MAXIMUM_DURATION_MS)
            .context("bridge proof deadline overflow")?;
        let control = transport::LocalControl::open(Path::new("/Authority/Control.sock"))?;
        let history = transport::HistoryEvidence::fetch(
            &control,
            &prefix,
            checkpoint.as_ref().map(|v| v.head()),
            &completion.node,
            deadline,
        )?;
        let (checkpoint, history_proof) = history.proofs();
        let proof = federation::ForeignProof {
            trust: trust.reference.clone(),
            floor: floor.reference.clone(),
            anchor: floor.bytes.clone(),
            ordered: completion.ordered.clone(),
            result: completion.result.clone(),
            certificate: completion.certificate.clone(),
            ancestry: history.nodes,
            checkpoint,
            history: history_proof,
            predecessors: completion.predecessors.clone(),
            bytes: vec![],
        };
        federation::ForeignProof::parse(&proof.encode()?)
    }
}
pub struct Completion {
    pub value: V,
    pub ordered: Vec<u8>,
    pub result: Vec<u8>,
    pub certificate: Vec<u8>,
    pub node: Vec<u8>,
    pub objects: Resolved,
    pub predecessors: Vec<Vec<u8>>,
}

// Borrowing is confined to synchronous journal operations. No requester borrow crosses peer I/O.
pub struct Shared<'a>(std::cell::RefCell<Client<'a>>);
impl<'a> Shared<'a> {
    pub fn new(client: Client<'a>) -> Self {
        Self(std::cell::RefCell::new(client))
    }
    pub fn context(&self) -> (domains::State, Vec<Vec<u8>>) {
        let client = self.0.borrow();
        let (state, records) = client.context();
        (state.clone(), records.to_vec())
    }
    pub fn service(&self) -> Digest {
        self.0.borrow().service()
    }
    pub fn now(&self) -> Result<u64> {
        self.0.borrow().now()
    }
    pub fn deadline(&self) -> Result<u64> {
        self.0.borrow().deadline()
    }
    pub fn action(&self, command: federation::Command) -> Result<Completion> {
        self.0.borrow_mut().action(command)
    }
    pub fn media(&self, command: federation::Command, payload: &[u8]) -> Result<Vec<u8>> {
        self.0.borrow_mut().media(command, payload)
    }
    pub fn local_media_report(&self, bytes: &[u8]) -> Result<page::MediaReport> {
        self.0.borrow().local_media_report(bytes)
    }
    pub fn search_bundle(
        &self,
        agreement: Digest,
        raw: [u8; 16],
        native: &VersionRef,
    ) -> Result<(Resolved, Vec<u8>)> {
        self.0.borrow().search_bundle(agreement, raw, native)
    }
    pub fn stage(&self, objects: &Resolved) -> Result<()> {
        self.0.borrow_mut().stage(objects)
    }
    pub fn portable(
        &self,
        completion: &Completion,
        trust: &Record,
        floor: &Record,
    ) -> Result<federation::ForeignProof> {
        self.0.borrow().portable(completion, trust, floor)
    }
    pub fn recover(&self) -> Result<()> {
        self.0.borrow_mut().recover()
    }
}
