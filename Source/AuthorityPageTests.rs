// SPDX-License-Identifier: MIT
// Publication contracts use actual signed provenance and exact immutable input closures.
use super::*;
use crate::{
    authority_deployment_tests as deployment, authority_governance::Governance,
    authority_objects::Object,
};

struct Fixture {
    state: State,
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    grant: VersionRef,
    sequence: u64,
}
impl Fixture {
    fn new() -> Self {
        let f = deployment::Fixture::with_actions(vec![0, 2, 3, 5, 10, 11, 12, 13, 21, 26]);
        let grant = Governance::parse(f.scope.network, f.scope.incarnation, &f.records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        Self {
            state: State::empty(f.scope.network, f.scope.incarnation),
            records: f.records,
            reserved: f.reservations,
            grant,
            sequence: 1,
        }
    }
    fn author(&self, body: &[u8], revision: u64) -> objects::Author {
        self.author_for([71; 16], body, revision)
    }
    fn author_for(&self, page: [u8; 16], body: &[u8], revision: u64) -> objects::Author {
        let source = Reference::for_bytes(Class::PageSource, body).unwrap();
        let parameters =
            objects::Author::parameters(page, "Books", &source, &self.grant, None, 700000).unwrap();
        let bytes = deployment::signed(
            &deployment::key(5),
            "PageAuthorStatement",
            page_id(&page).unwrap(),
            revision,
            wire::decode(&parameters).unwrap(),
            vec![],
        );
        objects::Author::parse(&bytes, self.state.network, self.state.incarnation).unwrap()
    }
    fn reviewer(&self, author: &objects::Author, approve: bool, expires: u64) -> objects::Reviewer {
        let record = self
            .state
            .record(
                141,
                revision_id(author.intent.resource, author.intent.revision).unwrap(),
            )
            .unwrap();
        let parameters = objects::Reviewer::parameters(
            &record.reference,
            &author.source,
            author.intent.requester,
            author.intent.digest,
            &self.grant,
            None,
            approve,
            0,
            None,
            expires,
        )
        .unwrap();
        let bytes = deployment::signed(
            &deployment::key(5),
            "PageReviewStatement",
            author.intent.resource,
            author.intent.revision,
            wire::decode(&parameters).unwrap(),
            vec![],
        );
        objects::Reviewer::parse(&bytes, self.state.network, self.state.incarnation).unwrap()
    }
    fn request_as(
        &self,
        command: Command,
        grant: Option<VersionRef>,
        seed: u8,
    ) -> (Intent, Operation) {
        let operation = Operation {
            grant,
            command: command.into(),
            snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        let intent = Intent {
            network: self.state.network,
            incarnation: self.state.incarnation,
            generation: 1,
            generation_id: [182; 32],
            sequence: self.sequence,
            acknowledged_through: self.sequence - 1,
            requester: deployment::key(seed).verifying_key().to_bytes(),
            action: "AuthorityDomain".into(),
            resource: operation.command.resource(),
            revision: u64::from(operation.mutation()),
            profile_generation: 0,
            minimum_policy_epoch: 0,
            minimum_policy_height: 0,
            expected: vec![],
            parameters: operation.parameters().unwrap(),
            digest: wire::digest(&self.sequence.to_be_bytes()),
        };
        (intent, operation)
    }
    fn evaluate(
        &self,
        command: Command,
        objects: Vec<Object>,
        at: u64,
    ) -> (Intent, Operation, Decision, Resolved) {
        let grant = if matches!(
            command,
            Command::ApplicationGet { .. }
                | Command::Application { .. }
                | Command::HostWithdraw { .. }
                | Command::ReplicaDeliver { .. }
                | Command::ReplicaResult { .. }
                | Command::Sync { .. }
                | Command::ReplicaQueue { .. }
        ) {
            None
        } else {
            Some(self.grant.clone())
        };
        self.evaluate_as(command, objects, at, 5, grant)
    }
    fn evaluate_as(
        &self,
        command: Command,
        objects: Vec<Object>,
        at: u64,
        seed: u8,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision, Resolved) {
        let expected = command.required_inputs(&self.state).unwrap();
        let inputs = Resolved::exact(&expected, objects).unwrap();
        let (mut intent, mut operation) = self.request_as(command.clone(), grant, seed);
        let prepared = evaluate(
            &operation,
            &command,
            &self.state,
            &self.records,
            &self.reserved,
            &intent,
            at,
            false,
            false,
            &inputs,
        )
        .unwrap();
        if prepared.code != 0 {
            return (intent, operation, prepared, inputs);
        }
        intent.expected = prepared.dependencies;
        operation.snapshot = snapshot(&deployment::snapshot(&intent.expected)).unwrap();
        intent.parameters = operation.parameters().unwrap();
        let decision = evaluate(
            &operation,
            &command,
            &self.state,
            &self.records,
            &self.reserved,
            &intent,
            at,
            false,
            true,
            &inputs,
        )
        .unwrap();
        (intent, operation, decision, inputs)
    }
    fn apply(&mut self, command: Command, objects: Vec<Object>, at: u64) -> (Intent, Decision) {
        let (intent, _, decision, _) = self.evaluate(command, objects, at);
        assert_eq!(decision.code, 0);
        if let Some(state) = &decision.state {
            self.state = state.clone();
        }
        State::parse(
            &self.state.value(),
            self.state.network,
            self.state.incarnation,
        )
        .unwrap();
        self.sequence += 1;
        (intent, decision)
    }
    fn hosts(&mut self) -> Vec<HostProfile> {
        self.hosts_with_storage(8 * 1024 * 1024)
    }
    fn hosts_with_storage(&mut self, physical_bytes: u64) -> Vec<HostProfile> {
        self.hosts_with_storage_until(physical_bytes, 20000)
    }
    fn hosts_with_storage_until(
        &mut self,
        physical_bytes: u64,
        expires_ms: u64,
    ) -> Vec<HostProfile> {
        let f = deployment::Fixture::with_actions(vec![0, 2, 3, 5, 10, 11, 12, 13, 21, 26]);
        let mut manifest = deployment::manifest();
        manifest.validity.1 = expires_ms;
        (self.records, _, _, _) = deployment::admitted(&f, &deployment::offer(manifest.clone()));
        [1, 2]
            .into_iter()
            .map(|role| {
                let mut p = HostProfile {
                    manifest: manifest.clone(),
                    role,
                    service: deployment::key(99 + role as u8).verifying_key().to_bytes(),
                    volume: [100 + role as u8; 32],
                    namespaces: vec!["Books".into()],
                    state_bytes: if role == 2 {
                        physical_bytes
                    } else {
                        8 * 1024 * 1024
                    },
                    maximum_asset_bytes: if role == 1 {
                        crate::authority_objects::PAGE_BUNDLE_BYTES as u64
                    } else {
                        markup::media::MAX_PAGE_BYTES.min(physical_bytes)
                    },
                    retention_ms: MAXIMUM_LIFETIME_MS,
                    envelope: vec![],
                };
                p.envelope =
                    wire::sign_envelope(&p.payload().unwrap(), &deployment::key(90)).unwrap();
                let p = HostProfile::parse(&p.envelope, self.state.network, self.state.incarnation)
                    .unwrap();
                self.apply(Command::HostRegister { profile: p.clone() }, vec![], 5000);
                p
            })
            .collect()
    }
}
fn input(class: Class, bytes: &[u8]) -> Object {
    Object::verify(Reference::for_bytes(class, bytes).unwrap(), bytes.to_vec()).unwrap()
}
#[test]
fn replica_ticket_reservation_has_a_bounded_lifetime_and_expired_delivery_can_be_replaced() {
    let mut f = Fixture::new();
    let hosts = f.hosts_with_storage_until(8 * 1024 * 1024, 200000);
    let body = b"HyperNetPage/2\n# Books\n: Approved stock list.\n";
    let author = f.author(body, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![input(Class::PageSource, body)],
        5000,
    );
    let review = f.reviewer(&author, true, 10000);
    let bundle = objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
    let bundle_ref = Reference::for_bytes(Class::PageBundle, &bundle).unwrap();
    f.apply(
        Command::Review {
            review,
            bundle: Some(bundle_ref.clone()),
        },
        vec![
            input(Class::PageSource, body),
            input(Class::PageBundle, &bundle),
        ],
        5000,
    );
    let host = f
        .state
        .record(147, hosts[0].service)
        .unwrap()
        .reference
        .clone();
    let request = |expires_ms| Command::ReplicaRequest {
        page: author.raw_page,
        host: host.clone(),
        expires_ms,
    };
    let before = f.state.value();
    let excess = f.evaluate(request(65001), vec![], 5000).2;
    assert_eq!(excess.code, 3);
    assert!(excess.state.is_none());
    assert_eq!(f.state.value(), before);
    f.apply(request(65000), vec![], 5000);
    let id = ticket_id(author.intent.requester, hosts[0].service).unwrap();
    let old = f.state.record(146, id).unwrap().reference.clone();
    let deliver = |ticket| Command::ReplicaDeliver {
        ticket,
        bundle: bundle_ref.clone(),
    };
    assert_eq!(
        f.evaluate_as(
            deliver(old.clone()),
            vec![input(Class::PageBundle, &bundle)],
            63749,
            100,
            None
        )
        .2
        .code,
        0,
    );
    for at in [63750, 65000] {
        let refused = f
            .evaluate_as(
                deliver(old.clone()),
                vec![input(Class::PageBundle, &bundle)],
                at,
                100,
                None,
            )
            .2;
        assert_eq!(
            refused.code, 3,
            "delivery must preserve the 1250ms expiry margin"
        );
        assert!(refused.state.is_none());
        assert_eq!(
            f.evaluate(
                Command::ReplicaResult {
                    ticket: old.clone()
                },
                vec![],
                at
            )
            .2
            .code,
            3
        );
    }
    f.apply(request(120001), vec![], 65001);
    let current = f.state.record(146, id).unwrap().reference.clone();
    assert_eq!(current.generation, old.generation + 1);
    let delivered = f
        .evaluate_as(
            deliver(current.clone()),
            vec![input(Class::PageBundle, &bundle)],
            90000,
            100,
            None,
        )
        .2;
    assert_eq!(delivered.code, 0);
    f.state = delivered.state.unwrap();
    f.sequence += 1;
    let (intent, _, result, _) = f.evaluate(
        Command::ReplicaResult { ticket: current },
        vec![input(Class::PageBundle, &bundle)],
        90000,
    );
    assert_eq!(result.code, 0);
    assert_eq!(
        response_inputs(&intent, &result.value).unwrap(),
        vec![bundle_ref]
    );
}
#[test]
fn page_host_owner_context_prepares_fresh_withdrawal_after_authority_revocation() {
    fn withdraw(f: &mut Fixture, host: &HostProfile, base: &[Vec<u8>], at: u64) {
        let get = Command::HostGet {
            role: host.role,
            host: host.service,
        };
        let (_, _, denied, _) = f.evaluate_as(get.clone(), vec![], at, 92, None);
        assert_eq!(
            denied.code, 3,
            "another principal cannot inspect owner context"
        );
        assert!(denied.state.is_none());
        let (_, _, owner, _) = f.evaluate_as(get.clone(), vec![], at, 90, None);
        assert_eq!(owner.code, 0);
        assert!(owner.state.is_none());
        assert_eq!(f.evaluate_as(get.clone(), vec![], at, 5, None).2.code, 0);
        let body = owner.value.array(5).unwrap()[4].array(4).unwrap();
        let mut fresh = State::empty(f.state.network, f.state.incarnation);
        assert!(fresh.records.is_empty());
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
            let record =
                Record::parse(bytes.bytes().unwrap(), fresh.network, fresh.incarnation).unwrap();
            fresh.records.insert(record.reference.index(), record);
        }
        assert_eq!(
            fresh.records.len(),
            1,
            "owner context discloses only its selected host"
        );
        State::parse_context(&fresh.value(), fresh.network, fresh.incarnation).unwrap();
        let mut governance = BTreeMap::new();
        for bytes in base
            .iter()
            .map(Vec::as_slice)
            .chain(body[2].list(64).unwrap().iter().map(|v| v.bytes().unwrap()))
        {
            let reference =
                Governance::record_versions(fresh.network, fresh.incarnation, &[bytes.to_vec()])
                    .unwrap()
                    .remove(0);
            governance.insert(reference.index(), bytes.to_vec());
        }
        let governance = governance.into_values().collect::<Vec<_>>();
        let kind = if host.role == 1 { 147 } else { 143 };
        let generation = fresh
            .record(kind, host.service)
            .unwrap()
            .reference
            .generation;
        let command = Command::HostWithdraw {
            role: host.role,
            host: host.service,
            generation,
        };
        let (probe, operation) = f.request_as(command.clone(), None, 90);
        let prepared = operation
            .prepare_with_inputs(
                &fresh,
                &governance,
                &f.reserved,
                &probe,
                at,
                false,
                false,
                &Resolved::default(),
            )
            .unwrap();
        assert_eq!(
            prepared.code, 0,
            "certified owner context must suffice for a fresh cache"
        );
        let (intent, operation, decision, _) = f.evaluate_as(command, vec![], at, 90, None);
        assert_eq!(decision.code, 0);
        f.state = decision.state.unwrap();
        f.sequence += 1;
        assert!(
            Host::parse(
                &f.state.record(kind, host.service).unwrap().payload,
                fresh.network,
                fresh.incarnation
            )
            .unwrap()
            .withdrawn
        );
        assert_eq!(
            operation
                .prepare_with_inputs(
                    &f.state,
                    &f.records,
                    &f.reserved,
                    &intent,
                    at,
                    true,
                    true,
                    &Resolved::default()
                )
                .unwrap()
                .code,
            0,
            "the exact committed withdrawal can be replayed"
        );
        assert_eq!(
            f.evaluate_as(get, vec![], at, 90, None).2.code,
            0,
            "ownership inspection survives host withdrawal"
        );
    }
    let mut f = Fixture::new();
    let base = f.records.clone();
    let hosts = f.hosts();
    withdraw(&mut f, &hosts[0], &base, 5000);
    let registrar = Governance::parse(f.state.network, f.state.incarnation, &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [24; 32])
        .unwrap();
    for grant in [f.grant.clone(), registrar] {
        f.records.push(
            wire::encode(&a(vec![
                V::Uint(126),
                V::Uint(1),
                b(&f.state.network),
                b(&f.state.incarnation),
                V::Uint(1),
                V::Null,
                reference(&grant),
                b(deployment::key(5).verifying_key().as_bytes()),
                deployment::snapshot(&[]),
            ]))
            .unwrap(),
        );
    }
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let registration = crate::authority_deployment_records::Index::parse(
        &f.records,
        &f.reserved,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap()
    .deployments[&hosts[1].manifest.deployment]
        .reference
        .clone();
    let refs = vec![registration.clone()];
    let signed = deployment::signed(
        &deployment::key(90),
        "AuthorityDeploymentWithdraw",
        registration.id,
        1,
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentWithdraw".into()),
            reference(&registration),
            V::Uint(1),
            deployment::snapshot(&refs),
        ]),
        refs,
    );
    let intent = Intent::from_signed(&signed).unwrap();
    let stopped = crate::authority_deployments::Operation::parse(&intent)
        .unwrap()
        .authorise(&f.records, &f.reserved, &intent, 30000, false, None)
        .unwrap();
    assert_eq!(stopped.code, 0);
    f.records.extend(stopped.records);
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    assert_eq!(
        f.evaluate_as(
            Command::HostGet {
                role: 2,
                host: hosts[1].service
            },
            vec![],
            30000,
            5,
            Some(f.grant.clone())
        )
        .2
        .code,
        3,
        "historical ownership does not restore revoked discretionary access"
    );
    withdraw(&mut f, &hosts[1], &base, 30000);
}
#[test]
fn page_replacement_review_and_withdrawal_preserve_exact_object_history() {
    let mut f = Fixture::new();
    let body = b"HyperNetPage/2\n# Books\n: First approved edition.\n";
    let author = f.author(body, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![input(Class::PageSource, body)],
        5000,
    );
    let review = f.reviewer(&author, true, 7000);
    let bundle = objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
    let bundle_ref = Reference::for_bytes(Class::PageBundle, &bundle).unwrap();
    f.apply(
        Command::Review {
            review: review.clone(),
            bundle: Some(bundle_ref.clone()),
        },
        vec![
            input(Class::PageSource, body),
            input(Class::PageBundle, &bundle),
        ],
        5000,
    );
    let (_, read) = f.apply(
        Command::Read { page: [71; 16] },
        vec![input(Class::PageBundle, &bundle)],
        10000,
    );
    assert_eq!(
        read.code, 0,
        "completed approval does not expire with its decision deadline"
    );
    let second = b"HyperNetPage/2\n# Books\n: Replacement awaiting review.\n";
    let author2 = f.author(second, 3);
    f.apply(
        Command::Submit {
            author: author2.clone(),
        },
        vec![input(Class::PageSource, second)],
        11000,
    );
    let old = Ledger::parse(&f.state.record(140, author.intent.resource).unwrap().payload)
        .unwrap()
        .published;
    assert_eq!(old.as_ref().unwrap().id, review.revision.id);
    f.apply(
        Command::Read { page: [71; 16] },
        vec![input(Class::PageBundle, &bundle)],
        11000,
    );
    let reject = f.reviewer(&author2, false, 15000);
    f.apply(
        Command::Review {
            review: reject,
            bundle: None,
        },
        vec![input(Class::PageSource, second)],
        12000,
    );
    let ledger =
        Ledger::parse(&f.state.record(140, author.intent.resource).unwrap().payload).unwrap();
    assert!(ledger.pending.is_none());
    assert_eq!(ledger.published, old);
    f.apply(
        Command::Withdraw {
            page: [71; 16],
            as_reviewer: false,
        },
        vec![],
        13000,
    );
    let before = f.state.value();
    let stale = f.reviewer(&author, true, 18000);
    let stale_bundle = objects::Bundle::encode(body, &author.bytes, &stale.bytes).unwrap();
    let (_, _, denied, _) = f.evaluate(
        Command::Review {
            review: stale,
            bundle: Some(Reference::for_bytes(Class::PageBundle, &stale_bundle).unwrap()),
        },
        vec![
            input(Class::PageSource, body),
            input(Class::PageBundle, &stale_bundle),
        ],
        13000,
    );
    assert_ne!(denied.code, 0);
    assert!(denied.state.is_none());
    assert_eq!(before, f.state.value());
    let mut expected = vec![author.source, author2.source, bundle_ref];
    expected.sort();
    assert_eq!(
        retained_inputs(&f.state).unwrap(),
        expected,
        "accepted history exports the complete exact immutable closure"
    );
}

#[test]
fn page_provenance_and_response_sidecar_cannot_substitute_revision_or_network() {
    let mut f = Fixture::new();
    let source = b"HyperNetPage/2\n# Provenance\n: Exact source.\n";
    let author = f.author(source, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![input(Class::PageSource, source)],
        5000,
    );
    let (inspection, result) = f.apply(
        Command::Inspect { page: [71; 16] },
        vec![input(Class::PageSource, source)],
        5000,
    );
    assert_eq!(
        response_inputs(&inspection, &result.value).unwrap(),
        vec![author.source.clone()]
    );
    let review = f.reviewer(&author, true, 10000);
    let bytes = objects::Bundle::encode(source, &author.bytes, &review.bytes).unwrap();
    objects::Bundle::parse(&bytes, f.state.network, f.state.incarnation).unwrap();
    assert!(objects::Bundle::parse(&bytes, f.state.network, [99; 32]).is_err());
    let other = b"HyperNetPage/2\n# Provenance\n: Different source.\n";
    let altered = objects::Bundle::encode(other, &author.bytes, &review.bytes).unwrap();
    assert!(objects::Bundle::parse(&altered, f.state.network, f.state.incarnation).is_err());
    let before = f.state.value();
    let reference = Reference::for_bytes(Class::PageBundle, &altered).unwrap();
    let (_, _, denied, _) = f.evaluate(
        Command::Review {
            review,
            bundle: Some(reference),
        },
        vec![
            input(Class::PageSource, source),
            input(Class::PageBundle, &altered),
        ],
        5000,
    );
    assert_eq!(denied.code, 3);
    assert!(denied.state.is_none());
    assert_eq!(before, f.state.value());
}

#[test]
fn page_pending_admission_and_pagination_use_resource_budgets() {
    let mut f = Fixture::new();
    let source = b"HyperNetPage/2\n# Catalogue\n: Current catalogue entry.\n";
    let mut expected = BTreeSet::new();
    // Cross both former incidental limits (four pending and sixteen authored Pages).
    for number in 1..=40u8 {
        let author = f.author_for([number; 16], source, 1);
        expected.insert(author.intent.resource);
        f.apply(
            Command::Submit { author },
            vec![input(Class::PageSource, source)],
            5000,
        );
    }
    let mut found = BTreeSet::new();
    let mut after = None;
    let mut batches = Vec::new();
    loop {
        let (_, result) = f.apply(
            Command::Queue {
                namespace: "Books".into(),
                after,
            },
            vec![],
            5000,
        );
        let body = result.value.array(5).unwrap()[4].array(4).unwrap();
        let mut batch = 0;
        assert!(result.versions.len() <= MAXIMUM_CONTEXT_RECORDS);
        assert!(wire::encode(&result.value).is_ok());
        for value in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
            let record =
                Record::parse(value.bytes().unwrap(), f.state.network, f.state.incarnation)
                    .unwrap();
            if record.reference.kind == 140 {
                batch += 1;
                assert!(
                    found.insert(record.reference.id),
                    "pagination repeated a Page"
                );
            }
        }
        assert!(batch > 0, "capacity pagination must make progress");
        batches.push(batch);
        if body[3] == V::Null {
            break;
        }
        let cursor = id(&body[3]).unwrap();
        assert!(after.is_none_or(|prior| cursor > prior));
        after = Some(cursor);
    }
    assert!(
        batches.len() > 1,
        "the complete provenance must reach a real result bound"
    );
    assert!(
        batches[0] > 4,
        "small fixed batches must not replace capacity accounting"
    );
    assert_eq!(
        found, expected,
        "pagination must not skip its first undisclosed entry"
    );
}

#[test]
fn page_context_retains_head_without_disclosing_pending_revision_metadata() {
    let mut f = Fixture::new();
    let source = b"HyperNetPage/2\n# Pending\n: Unapproved opening hours.\n";
    let author = f.author(source, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![input(Class::PageSource, source)],
        5000,
    );
    let (intent, result) = f.apply(
        Command::Context {
            action: 0,
            scope_kind: 2,
            resource: author.intent.resource,
            namespace: Some("Books".into()),
        },
        vec![],
        5000,
    );
    assert!(response_inputs(&intent, &result.value).unwrap().is_empty());
    let body = result.value.array(5).unwrap()[4].array(4).unwrap();
    let mut context = State::empty(f.state.network, f.state.incarnation);
    for value in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
        let record =
            Record::parse(value.bytes().unwrap(), context.network, context.incarnation).unwrap();
        assert_eq!(record.reference.kind, 140);
        context.records.insert(record.reference.index(), record);
    }
    assert!(State::parse(&context.value(), context.network, context.incarnation).is_err());
    State::parse_context(&context.value(), context.network, context.incarnation).unwrap();
}

#[test]
fn page_application_policy_requires_dual_consent_and_exact_author_policy_version() {
    let mut f = Fixture::new();
    let application = deployment::key(150).verifying_key().to_bytes();
    let owner = deployment::key(5).verifying_key().to_bytes();
    let tier = Governance::parse(f.state.network, f.state.incarnation, &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 101)
        .unwrap();
    let grant = wire::encode(&a(vec![
        V::Uint(102),
        V::Uint(1),
        b(&f.state.network),
        b(&f.state.incarnation),
        V::Uint(1),
        V::Null,
        b(&[172; 32]),
        b(&owner),
        b(&application),
        reference(&tier),
        a(vec![V::Uint(0), V::Uint(2), V::Uint(3)]),
        a(vec![a(vec![V::Uint(0), b(&f.state.network)])]),
        a(vec![V::Uint(1000), V::Uint(600000)]),
        reference(&f.grant),
        V::Uint(0),
        a(vec![
            V::Uint(268435456),
            V::Uint(20480),
            V::Uint(128),
            V::Uint(32),
        ]),
        deployment::snapshot(&[]),
    ]))
    .unwrap();
    let delegated = crate::authority_applications::record_reference(&grant).unwrap();
    let registration = wire::encode(&a(vec![
        V::Uint(127),
        V::Uint(1),
        b(&f.state.network),
        b(&f.state.incarnation),
        V::Uint(1),
        V::Null,
        b(&application),
        b(&owner),
        reference(&delegated),
        a(vec![V::Uint(1000), V::Uint(600000)]),
        deployment::snapshot(&[]),
    ]))
    .unwrap();
    let registered = crate::authority_applications::record_reference(&registration).unwrap();
    f.records.extend([grant, registration]);
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let mut policy = ApplicationPolicy {
        application,
        owner,
        registration: registered,
        grant: delegated.clone(),
        namespaces: vec!["Books".into()],
        pages: Some(vec![[71; 16]]),
        permissions: vec!["PagesSubmit".into()],
        review: None,
        expires_ms: 500000,
        previous: None,
        envelope: vec![],
    };
    let payload = policy
        .payload(f.state.network, f.state.incarnation)
        .unwrap();
    let owner_only = wire::sign_envelope(&payload, &deployment::key(5)).unwrap();
    assert!(ApplicationPolicy::parse(&owner_only, f.state.network, f.state.incarnation).is_err());
    let mut signatures = [5, 150]
        .into_iter()
        .map(|seed| {
            wire::envelope(
                &wire::sign_envelope(&payload, &deployment::key(seed)).unwrap(),
                1,
            )
            .unwrap()
            .1
            .remove(0)
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|p| p.0);
    policy.envelope = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        a(signatures
            .into_iter()
            .map(|(key, signature)| a(vec![b(&key), b(&signature)]))
            .collect()),
    ]))
    .unwrap();
    let policy =
        ApplicationPolicy::parse(&policy.envelope, f.state.network, f.state.incarnation).unwrap();
    f.apply(Command::Application { policy }, vec![], 5000);
    let policy = f.state.record(148, application).unwrap().reference.clone();
    let source = b"HyperNetPage/2\n# Application\n: Scoped submission.\n";
    let source_ref = Reference::for_bytes(Class::PageSource, source).unwrap();
    let statement = |bound: Option<&VersionRef>, page: [u8; 16]| {
        let parameters =
            objects::Author::parameters(page, "Books", &source_ref, &delegated, bound, 400000)
                .unwrap();
        let signed = deployment::signed(
            &deployment::key(150),
            "PageAuthorStatement",
            page_id(&page).unwrap(),
            1,
            wire::decode(&parameters).unwrap(),
            vec![],
        );
        objects::Author::parse(&signed, f.state.network, f.state.incarnation).unwrap()
    };
    let evaluate = |author| {
        f.evaluate_as(
            Command::Submit { author },
            vec![input(Class::PageSource, source)],
            5000,
            150,
            Some(delegated.clone()),
        )
        .2
    };
    assert_eq!(evaluate(statement(None, [71; 16])).code, 3);
    assert_eq!(evaluate(statement(Some(&policy), [72; 16])).code, 3);
    assert_eq!(evaluate(statement(Some(&policy), [71; 16])).code, 0);
}

#[test]
fn page_media_requires_exact_copy_and_inspection_then_stops_on_host_withdrawal() {
    let mut f = Fixture::new();
    let bootstrap_records = f.records.clone();
    let hosts = f.hosts();
    let media = &hosts[1];
    let source = format!(
        "HyperNetPage/2\n# Red square\n@Asset {{\"id\":\"Icon\",\"profile\":\"HyperNetRaster/1\",\"width\":1,\"height\":1,\"bytes\":3,\"digest\":\"{}\",\"hosts\":[\"{}\"],\"copies\":1}}\n@Image {{\"id\":\"Picture\",\"asset\":\"Icon\",\"alt\":\"Red square\",\"rows\":3}}\n",
        "7fa54a42524916a1648ec76ce75d295024840b7a3a4f4bbaf3e43155d0014767",
        hex::encode(media.service)
    );
    let author = f.author(source.as_bytes(), 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![input(Class::PageSource, source.as_bytes())],
        5000,
    );
    let revision = f
        .state
        .record(141, revision_id(author.intent.resource, 1).unwrap())
        .unwrap()
        .reference
        .clone();
    let asset = f
        .state
        .record(144, asset_id(&revision, "Icon").unwrap())
        .unwrap()
        .reference
        .clone();
    let host = f
        .state
        .record(143, media.service)
        .unwrap()
        .reference
        .clone();
    let review = f.reviewer(&author, true, 12000);
    let bundle = objects::Bundle::encode(source.as_bytes(), &author.bytes, &review.bytes).unwrap();
    let decision = Command::Review {
        review,
        bundle: Some(Reference::for_bytes(Class::PageBundle, &bundle).unwrap()),
    };
    let objects = || {
        vec![
            input(Class::PageSource, source.as_bytes()),
            input(Class::PageBundle, &bundle),
        ]
    };
    assert_eq!(f.evaluate(decision.clone(), objects(), 5000).2.code, 3);
    let mut receipt = CopyReceipt {
        asset: asset.clone(),
        host: host.clone(),
        request: [91; 32],
        digest: hex::decode("7fa54a42524916a1648ec76ce75d295024840b7a3a4f4bbaf3e43155d0014767")
            .unwrap()
            .try_into()
            .unwrap(),
        bytes: 3,
        recorded_ms: 5000,
        envelope: vec![],
    };
    receipt.envelope = wire::sign_envelope(
        &receipt
            .payload(f.state.network, f.state.incarnation)
            .unwrap(),
        &deployment::key(101),
    )
    .unwrap();
    let receipt =
        CopyReceipt::parse(&receipt.envelope, f.state.network, f.state.incarnation).unwrap();
    f.apply(
        Command::MediaReceipt {
            receipt: receipt.clone(),
        },
        vec![],
        5000,
    );
    assert_eq!(
        f.evaluate(decision.clone(), objects(), 5000).2.code,
        3,
        "host receipt does not replace reviewer inspection"
    );
    f.apply(
        Command::MediaInspect {
            asset: asset.clone(),
            receipt,
            expires_ms: 12000,
        },
        vec![],
        5000,
    );
    f.apply(decision, objects(), 5000);
    let page_host = f
        .state
        .record(147, hosts[0].service)
        .unwrap()
        .reference
        .clone();
    let governance = Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let mut grant_fields = wire::decode(governance.record_bytes(102, f.grant.id).unwrap())
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    grant_fields[6] = b(&[174; 32]);
    grant_fields[10] = a(vec![V::Uint(0)]);
    grant_fields[13] = reference(&f.grant);
    grant_fields[14] = V::Uint(0);
    grant_fields[16] = deployment::snapshot(&[]);
    let reader_bytes = wire::encode(&a(grant_fields)).unwrap();
    let reader_grant = crate::authority_applications::record_reference(&reader_bytes).unwrap();
    f.records.push(reader_bytes);
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    assert_eq!(
        f.evaluate_as(
            Command::HostGet {
                role: 1,
                host: hosts[0].service
            },
            vec![],
            5000,
            5,
            Some(reader_grant.clone())
        )
        .2
        .code,
        3
    );
    let (context_intent, _, context, _) = f.evaluate_as(
        Command::ReplicaContext {
            page: author.raw_page,
            host: page_host.clone(),
        },
        vec![],
        5000,
        5,
        Some(reader_grant.clone()),
    );
    assert_eq!(context.code, 0);
    assert!(
        response_inputs(&context_intent, &context.value)
            .unwrap()
            .is_empty()
    );
    let body = context.value.array(5).unwrap()[4].array(4).unwrap();
    let mut fresh = State::empty(f.state.network, f.state.incarnation);
    for v in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
        let record = Record::parse(v.bytes().unwrap(), fresh.network, fresh.incarnation).unwrap();
        fresh.records.insert(record.reference.index(), record);
    }
    // A fresh consumer retains independently verified bootstrap governance, then
    // merges only the exact current records disclosed by this authorised context.
    let returned = body[2]
        .list(64)
        .unwrap()
        .iter()
        .map(|v| v.bytes().unwrap().to_vec())
        .collect::<Vec<_>>();
    let mut governance = BTreeMap::new();
    for bytes in bootstrap_records.into_iter().chain(returned) {
        let reference = Governance::record_versions(
            fresh.network,
            fresh.incarnation,
            std::slice::from_ref(&bytes),
        )
        .unwrap()
        .remove(0);
        governance.insert(reference.index(), bytes);
    }
    let governance = governance.into_values().collect::<Vec<_>>();
    let (probe, operation) = f.request_as(
        Command::ReplicaRequest {
            page: author.raw_page,
            host: page_host.clone(),
            expires_ms: 10000,
        },
        Some(reader_grant),
        5,
    );
    assert_eq!(
        operation
            .prepare_with_inputs(
                &fresh,
                &governance,
                &f.reserved,
                &probe,
                5000,
                false,
                false,
                &Resolved::default()
            )
            .unwrap()
            .code,
        0,
        "reader replica context must suffice for a fresh local request preflight"
    );
    f.apply(
        Command::ReplicaRequest {
            page: author.raw_page,
            host: page_host,
            expires_ms: 10000,
        },
        vec![],
        5000,
    );
    let ticket = f
        .state
        .record(
            146,
            ticket_id(author.intent.requester, hosts[0].service).unwrap(),
        )
        .unwrap()
        .reference
        .clone();
    let result_command = Command::ReplicaResult {
        ticket: ticket.clone(),
    };
    let (pending_intent, _, pending, _) = f.evaluate(result_command.clone(), vec![], 5000);
    assert_eq!(pending.code, 0);
    assert!(
        response_inputs(&pending_intent, &pending.value)
            .unwrap()
            .is_empty()
    );
    // The client evaluates only returned context and objects. Pending delivery
    // must not need the publication bytes retained by the authority.
    let network = f.state.network;
    let incarnation = f.state.incarnation;
    let result_context = |value: &V| {
        let mut state = State::empty(network, incarnation);
        for value in value.array(5).unwrap()[4].array(4).unwrap()[1]
            .list(MAXIMUM_CONTEXT_RECORDS)
            .unwrap()
        {
            let record =
                Record::parse(value.bytes().unwrap(), state.network, state.incarnation).unwrap();
            state.records.insert(record.reference.index(), record);
        }
        State::parse_context(&state.value(), state.network, state.incarnation).unwrap()
    };
    let pending_context = result_context(&pending.value);
    assert!(
        crate::authority_domains::result::inputs(
            &result_command.clone().into(),
            &pending_context,
            &[],
        )
        .is_ok()
    );
    let (_, _, delivered, _) = f.evaluate_as(
        Command::ReplicaDeliver {
            ticket: ticket.clone(),
            bundle: Reference::for_bytes(Class::PageBundle, &bundle).unwrap(),
        },
        vec![input(Class::PageBundle, &bundle)],
        5000,
        100,
        None,
    );
    assert_eq!(delivered.code, 0);
    f.state = delivered.state.unwrap();
    f.sequence += 1;
    let (intent, _, result, _) = f.evaluate(
        result_command.clone(),
        vec![input(Class::PageBundle, &bundle)],
        5000,
    );
    assert_eq!(result.code, 0);
    assert_eq!(
        response_inputs(&intent, &result.value).unwrap(),
        vec![Reference::for_bytes(Class::PageBundle, &bundle).unwrap()]
    );
    let delivered_context = result_context(&result.value);
    let command = result_command.into();
    assert!(
        crate::authority_domains::result::inputs(&command, &delivered_context, &[]).is_err(),
        "delivered results still require their exact bundle"
    );
    let mut substituted = bundle.clone();
    *substituted.last_mut().unwrap() ^= 1;
    assert!(
        crate::authority_domains::result::inputs(
            &command,
            &delivered_context,
            &[input(Class::PageBundle, &substituted)],
        )
        .is_err(),
        "a different object cannot satisfy the certified delivered reference"
    );
    let resolved = crate::authority_domains::result::inputs(
        &command,
        &delivered_context,
        &[input(Class::PageBundle, &bundle)],
    )
    .unwrap();
    assert_eq!(
        resolved
            .get(&Reference::for_bytes(Class::PageBundle, &bundle).unwrap())
            .unwrap(),
        bundle
    );
    let domain_records = result.value.array(5).unwrap()[4].array(4).unwrap()[1]
        .list(MAXIMUM_CONTEXT_RECORDS)
        .unwrap();
    let kinds = domain_records
        .iter()
        .map(|v| {
            Record::parse(v.bytes().unwrap(), f.state.network, f.state.incarnation)
                .unwrap()
                .reference
                .kind
        })
        .collect::<Vec<_>>();
    for kind in [143, 144, 145] {
        assert!(
            kinds.contains(&kind),
            "fresh ticket reader lacks media metadata {kind}"
        );
    }
    let read = Command::MediaAuthorise {
        asset: asset.clone(),
        host,
        effect: MediaEffect::Read,
        offset: 0,
        bytes: 3,
        digest: None,
    };
    assert_eq!(f.evaluate(read.clone(), vec![], 5000).2.code, 0);
    f.apply(
        Command::HostWithdraw {
            role: 2,
            host: media.service,
            generation: 1,
        },
        vec![],
        5000,
    );
    assert_eq!(
        f.evaluate(read, vec![], 5000).2.code,
        3,
        "withdrawn consent must stop fresh media access"
    );
}

#[test]
fn page_media_admission_uses_the_physical_bank_budget_atomically() {
    let mut f = Fixture::new();
    let hosts = f.hosts();
    let source = format!(
        "HyperNetPage/2\n# Icon\n@Asset {{\"id\":\"Icon\",\"profile\":\"HyperNetRaster/1\",\"width\":1,\"height\":1,\"bytes\":3,\"digest\":\"{}\",\"hosts\":[\"{}\"],\"copies\":1}}\n@Image {{\"id\":\"Picture\",\"asset\":\"Icon\",\"alt\":\"Red square\",\"rows\":3}}\n",
        "7fa54a42524916a1648ec76ce75d295024840b7a3a4f4bbaf3e43155d0014767",
        hex::encode(hosts[1].service)
    );
    let author = f.author(source.as_bytes(), 1);
    f.apply(
        Command::Submit { author },
        vec![input(Class::PageSource, source.as_bytes())],
        5000,
    );
    let asset = Asset::parse(
        &f.state
            .records
            .values()
            .find(|r| r.reference.kind == 144)
            .unwrap()
            .payload,
    )
    .unwrap();
    let charge = media_storage_charge(&asset).unwrap();
    let overhead =
        serialized_bank_bytes(1024 * 1024).unwrap() - media_storage_budget(1024 * 1024).unwrap();
    let physical = 2 * (charge + overhead + STORAGE_BANK_HEADER_BYTES - 1);
    assert_eq!(media_storage_budget(physical).unwrap(), charge - 1);
    let mut limited = Fixture::new();
    limited.hosts_with_storage(physical);
    let before = limited.state.value();
    let author = limited.author(source.as_bytes(), 1);
    let result = limited
        .evaluate(
            Command::Submit { author },
            vec![input(Class::PageSource, source.as_bytes())],
            5000,
        )
        .2;
    assert_eq!(result.code, 2);
    assert!(result.state.is_none());
    assert_eq!(limited.state.value(), before);
}

#[test]
fn page_and_namespace_ids_preserve_canonical_scope_and_validation() {
    let page_bytes = hex::decode("8518ca010264506167655001010101010101010101010101010101").unwrap();
    let namespace_bytes = hex::decode("8518ca0101694e616d65737061636565426f6f6b73").unwrap();
    let page_digest = "9481e09c3f0f621d53055dd1f4616dfb4805753b78d662152cf69372dd9afce0";
    let namespace_digest = "da274c051f9e628b8c8fd48f653e7a522231ba28625f3a21e68150516319a6cd";
    assert_eq!(
        wire::decode(&page_bytes).unwrap(),
        a(vec![
            V::Uint(202),
            V::Uint(1),
            V::Uint(2),
            V::Text("Page".into()),
            b(&[1; 16])
        ])
    );
    assert_eq!(
        wire::decode(&namespace_bytes).unwrap(),
        a(vec![
            V::Uint(202),
            V::Uint(1),
            V::Uint(1),
            V::Text("Namespace".into()),
            V::Text("Books".into())
        ])
    );
    assert_eq!(hex::encode(wire::digest(&page_bytes)), page_digest);
    assert_eq!(hex::encode(page_id(&[1; 16]).unwrap()), page_digest);
    assert_eq!(
        hex::encode(wire::digest(&namespace_bytes)),
        namespace_digest
    );
    assert_eq!(
        hex::encode(namespace_id("Books").unwrap()),
        namespace_digest
    );
    assert!(page_id(&[0; 16]).is_err());
    let mut nonzero = [0; 16];
    nonzero[15] = 1;
    assert!(page_id(&nonzero).is_ok());
    for name in ["A", "a0", &"A".repeat(32)] {
        assert!(namespace_id(name).is_ok(), "{name:?}");
    }
    for name in [
        "",
        "1Books",
        "Books_",
        "Books-",
        " Books",
        "Books\n",
        "Bóoks",
        "\u{202e}Books",
        &"A".repeat(33),
    ] {
        assert!(namespace_id(name).is_err(), "{name:?}");
    }
    assert_ne!(
        namespace_id("Books").unwrap(),
        namespace_id("books").unwrap()
    );
}
