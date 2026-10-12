// SPDX-License-Identifier: MIT
// Independent bootstrap acceptance and restrictive owners cannot create cross-network membership.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_governance::Governance};
fn request(
    state: &State,
    command: Command,
    grant: Option<VersionRef>,
    signer: u8,
) -> (Intent, Operation) {
    let operation = Operation {
        grant,
        command: command.into(),
        snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let bytes = deployment::signed(
        &deployment::key(signer),
        "AuthorityDomain",
        operation.command.resource(),
        u64::from(operation.command.mutation()),
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    );
    let mut intent = Intent::from_signed(&bytes).unwrap();
    intent.network = state.network;
    intent.incarnation = state.incarnation;
    (intent, operation)
}
#[test]
fn independently_accepted_foreign_identity_requires_local_capability_and_owner_can_withdraw() {
    let local = deployment::Fixture::with_actions(vec![0, 10, 11, 12, 13, 22, 26]);
    let foreign =
        deployment::Fixture::with_network(vec![0, 10, 11, 12, 13, 22, 26], [71; 32], [72; 32]);
    let accepted = crate::trust_bootstrap::inspect(&foreign.bootstrap, true).unwrap();
    let root = Governance::parse(local.scope.network, local.scope.incarnation, &local.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.id == [23; 32])
        .unwrap();
    let mut state = State::empty(local.scope.network, local.scope.incarnation);
    let command = Command::TrustAccept {
        bootstrap: foreign.bootstrap.clone(),
        identity: NetworkIdentity::verified(&accepted),
    };
    let (intent, operation) = request(&state, command.clone(), None, 5);
    assert_ne!(
        operation
            .prepare(
                &state,
                &local.records,
                &local.reservations,
                &intent,
                5000,
                false,
                false
            )
            .unwrap()
            .code,
        0
    );
    let (intent, operation) = request(&state, command, Some(root), 5);
    let decision = operation
        .prepare(
            &state,
            &local.records,
            &local.reservations,
            &intent,
            5000,
            false,
            false,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    state = decision.state.unwrap();
    State::parse(&state.value(), state.network, state.incarnation).unwrap();
    assert!(state.requesters().is_empty());
    let trust = state
        .records
        .values()
        .find(|r| r.reference.kind == 150)
        .unwrap()
        .reference
        .clone();
    let floor = ForeignFloor::parse(&state.record(157, trust.id).unwrap().payload).unwrap();
    assert_eq!(
        floor
            .resolve(
                &ForeignTrust::parse(
                    &state.record(150, trust.id).unwrap().payload,
                    state.network,
                    state.incarnation
                )
                .unwrap()
            )
            .unwrap()
            .descriptor
            .scope(),
        accepted.descriptor().scope()
    );
    for (signer, allowed) in [(6, false), (5, true)] {
        let (intent, operation) = request(
            &state,
            Command::TrustWithdraw {
                trust: trust.clone(),
            },
            None,
            signer,
        );
        let decision = operation
            .prepare(
                &state,
                &local.records,
                &local.reservations,
                &intent,
                5000,
                false,
                false,
            )
            .unwrap();
        assert_eq!(decision.code == 0, allowed);
        if allowed {
            state = decision.state.unwrap();
        }
    }
    assert!(
        ForeignTrust::parse(
            &state.record(150, trust.id).unwrap().payload,
            state.network,
            state.incarnation
        )
        .unwrap()
        .withdrawn
    );
}
#[test]
fn resharing_same_source_requires_distinct_local_review_identity() {
    let page = [81; 32];
    let native = VersionRef {
        kind: 141,
        id: [82; 32],
        generation: 1,
        digest: [83; 32],
    };
    let first = VersionRef {
        kind: 153,
        id: [84; 32],
        generation: 1,
        digest: [85; 32],
    };
    let next = VersionRef {
        generation: 3,
        digest: [86; 32],
        ..first.clone()
    };
    assert_ne!(
        revision_id(page, &native, &first).unwrap(),
        revision_id(page, &native, &next).unwrap()
    );
    assert!(revision_id(page, &native, &VersionRef { kind: 102, ..first }).is_err());
}

pub(super) struct SourceFixture {
    pub(super) local: deployment::Fixture,
    pub(super) records: Vec<Vec<u8>>,
    pub(super) state: State,
    pub(super) grant: VersionRef,
    pub(super) treaty: Treaty,
}
impl SourceFixture {
    fn new() -> Self {
        Self::configured(false)
    }
    pub(super) fn configured(destination: bool) -> Self {
        let local = deployment::Fixture::with_actions(vec![0, 2, 3, 4, 5, 10, 11, 12, 13, 22, 26]);
        let foreign =
            deployment::Fixture::with_network(vec![0, 10, 11, 12, 13, 22, 26], [71; 32], [72; 32]);
        let own = crate::trust_bootstrap::inspect(&local.bootstrap, true).unwrap();
        let peer = crate::trust_bootstrap::inspect(&foreign.bootstrap, true).unwrap();
        let grant = Governance::parse(local.scope.network, local.scope.incarnation, &local.records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.id == [23; 32])
            .unwrap();
        let mut manifest = deployment::manifest();
        manifest.bootstrap_digest = own.file_digest();
        let records = deployment::admitted(&local, &deployment::offer(manifest.clone())).0;
        let mut treaty = Treaty {
            id: [171; 32],
            source: NetworkIdentity::verified(&own),
            destination: NetworkIdentity::verified(&peer),
            source_bridge: deployment::key(106).verifying_key().to_bytes(),
            destination_bridge: deployment::key(126).verifying_key().to_bytes(),
            source_namespace: "Books".into(),
            destination_namespace: "Imported".into(),
            media_profiles: vec![],
            source_hosts: vec![],
            destination_hosts: vec![],
            media_bytes: 0,
            copies: 0,
            expires_ms: 20000,
        };
        if destination {
            std::mem::swap(&mut treaty.source, &mut treaty.destination);
            std::mem::swap(&mut treaty.source_bridge, &mut treaty.destination_bridge);
            treaty.media_profiles = vec!["HyperNetRaster/1".into()];
            treaty.source_hosts = vec![deployment::key(121).verifying_key().to_bytes()];
            treaty.destination_hosts = vec![deployment::key(101).verifying_key().to_bytes()];
            treaty.media_bytes = 3;
            treaty.copies = 1;
        }
        let state = State::empty(local.scope.network, local.scope.incarnation);
        let mut out = Self {
            local,
            records,
            state,
            grant,
            treaty,
        };
        out.apply(
            Command::TrustAccept {
                bootstrap: foreign.bootstrap,
                identity: NetworkIdentity::verified(&peer),
            }
            .into(),
            vec![],
            5,
            Some(out.grant.clone()),
        );
        let foreign = out
            .state
            .records
            .values()
            .find(|r| r.reference.kind == 150)
            .unwrap()
            .reference
            .clone();
        out.apply(
            Command::Accept {
                treaty: out.treaty.clone(),
                foreign,
            }
            .into(),
            vec![],
            5,
            Some(out.grant.clone()),
        );
        let mut profile = BridgeProfile {
            manifest,
            service: out.treaty.bridge(!destination),
            volume: [107; 32],
            agreements: vec![(out.treaty.id, out.treaty.digest().unwrap())],
            state_bytes: 8 * 1024 * 1024,
            envelope: vec![],
        };
        profile.envelope =
            wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
        let profile =
            BridgeProfile::parse(&profile.envelope, out.state.network, out.state.incarnation)
                .unwrap();
        out.apply(
            Command::BridgeRegister { profile }.into(),
            vec![],
            5,
            Some(out.grant.clone()),
        );
        out
    }
    pub(super) fn evaluate(
        &self,
        command: crate::authority_domains::Command,
        objects: Vec<crate::authority_objects::Object>,
        seed: u8,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        let operation = Operation {
            grant,
            command,
            snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        let signed = deployment::signed(
            &deployment::key(seed),
            "AuthorityDomain",
            operation.command.resource(),
            u64::from(operation.command.mutation()),
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            vec![],
        );
        let mut intent = Intent::from_signed(&signed).unwrap();
        let _ = objects;
        let inputs = Resolved::exact(
            &operation.command.required_inputs(&self.state).unwrap(),
            vec![],
        )
        .unwrap();
        let prepared = operation
            .prepare_with_inputs(
                &self.state,
                &self.records,
                &self.local.reservations,
                &intent,
                5000,
                false,
                false,
                &inputs,
            )
            .unwrap();
        if prepared.code != 0 {
            return (intent, operation, prepared);
        }
        let mut operation = operation;
        intent.expected = prepared.dependencies;
        operation.snapshot = snapshot(&deployment::snapshot(&intent.expected)).unwrap();
        intent.parameters = operation.parameters().unwrap();
        let decision = operation
            .prepare_with_inputs(
                &self.state,
                &self.records,
                &self.local.reservations,
                &intent,
                5000,
                false,
                true,
                &inputs,
            )
            .unwrap();
        (intent, operation, decision)
    }
    pub(super) fn apply(
        &mut self,
        command: crate::authority_domains::Command,
        objects: Vec<crate::authority_objects::Object>,
        seed: u8,
        grant: Option<VersionRef>,
    ) -> Decision {
        let label = command.name();
        let (_, _, decision) = self.evaluate(command, objects, seed, grant);
        assert_eq!(decision.code, 0, "{label} refused");
        if let Some(state) = &decision.state {
            self.state = state.clone();
        }
        decision
    }
    fn publish(&mut self, raw: [u8; 16]) {
        use crate::authority_objects::{Class, Object};
        let body = b"HyperNetPage/2\n# Books\n: Approved stock list.\n";
        let source = Reference::for_bytes(Class::PageSource, body).unwrap();
        let parameters =
            page::objects::Author::parameters(raw, "Books", body, &self.grant, None, 20000)
                .unwrap();
        let author = page::objects::Author::parse(
            &deployment::signed(
                &deployment::key(5),
                "PageAuthorStatement",
                page::page_id(&raw).unwrap(),
                1,
                wire::decode(&parameters).unwrap(),
                vec![],
            ),
            self.state.network,
            self.state.incarnation,
        )
        .unwrap();
        self.apply(
            page::Command::Submit {
                author: author.clone(),
            }
            .into(),
            vec![Object::verify(source.clone(), body.to_vec()).unwrap()],
            5,
            Some(self.grant.clone()),
        );
        let revision = self
            .state
            .record(141, page::revision_id(author.intent.resource, 1).unwrap())
            .unwrap()
            .reference
            .clone();
        let manifest = Bridge::parse(
            &self
                .state
                .record(152, self.treaty.source_bridge)
                .unwrap()
                .payload,
            self.state.network,
            self.state.incarnation,
        )
        .unwrap()
        .profile
        .manifest;
        page::complete_content(
            &mut self.state,
            &self.records,
            &self.local.reservations,
            &self.grant,
            &manifest,
            &revision,
        );
        let parameters = page::objects::Reviewer::parameters(
            &revision,
            &source,
            author.intent.requester,
            author.intent.digest,
            &self.grant,
            None,
            true,
            0,
            None,
            20000,
        )
        .unwrap();
        let review = page::objects::Reviewer::parse(
            &deployment::signed(
                &deployment::key(5),
                "PageReviewStatement",
                author.intent.resource,
                1,
                wire::decode(&parameters).unwrap(),
                vec![],
            ),
            self.state.network,
            self.state.incarnation,
        )
        .unwrap();
        let bundle = page::objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
        let bundle_ref = Reference::for_bytes(Class::PageBundle, &bundle).unwrap();
        self.apply(
            page::Command::Review {
                review,
                bundle: Some(bundle_ref.clone()),
            }
            .into(),
            vec![
                Object::verify(source, body.to_vec()).unwrap(),
                Object::verify(bundle_ref, bundle).unwrap(),
            ],
            5,
            Some(self.grant.clone()),
        );
        let mut share = Share {
            agreement: self.treaty.id,
            page: raw,
            publication: self
                .state
                .record(142, revision.id)
                .unwrap()
                .reference
                .clone(),
            revision,
            author: author.intent.requester,
            grant: self.grant.clone(),
            statement: vec![],
            allowed: true,
            withdrawal_generation: 0,
        };
        share.statement = deployment::signed(
            &deployment::key(5),
            "FederationShareStatement",
            share.identity().unwrap(),
            1,
            share.statement_value(),
            vec![],
        );
        self.apply(
            Command::Share { share }.into(),
            vec![],
            5,
            Some(self.grant.clone()),
        );
    }
    pub(super) fn verify_context(
        &self,
        prior: &State,
        intent: &Intent,
        decision: &Decision,
    ) -> Result<crate::authority_domains::result::Candidate> {
        use crate::authority_proof::{Disposition, ExecutedResult, OperationResult, Restrictions};
        let result = OperationResult {
            action: "AuthorityDomain".into(),
            disposition: Disposition::Permit,
            code: 0,
            value: wire::encode(&decision.value)?,
        };
        let executed = ExecutedResult {
            scope: self.local.scope.clone(),
            height: 1,
            committed_node: [181; 32],
            ordered_request: [182; 32],
            intent: intent.digest,
            challenge: [183; 32],
            requester: intent.requester,
            recipient: intent.requester,
            action: intent.action.clone(),
            resource: intent.resource,
            revision: intent.revision,
            profile_generation: 0,
            maximum_effect: 1,
            result: wire::digest(&result.value),
            policy_state: [184; 32],
            minimum_policy_height: 0,
            evaluated_at_ms: 5000,
            expires_at_ms: 6000,
            restrictions: Restrictions::default(),
        };
        let bootstrap = crate::trust_bootstrap::inspect(&self.local.bootstrap, true)?;
        crate::authority_domains::result::verify(
            &bootstrap,
            prior,
            &self.records,
            intent,
            &result,
            &executed,
            &[],
        )
    }
    pub(super) fn context(&self, value: &V) -> (State, Vec<Vec<u8>>) {
        let body = value.array(5).unwrap()[4].array(4).unwrap();
        let mut state = State::empty(self.state.network, self.state.incarnation);
        for value in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
            let record =
                Record::parse(value.bytes().unwrap(), state.network, state.incarnation).unwrap();
            state.records.insert(record.reference.index(), record);
        }
        let state = State::parse_context(&state.value(), state.network, state.incarnation).unwrap();
        let records = body[2]
            .list(MAXIMUM_CONTEXT_RECORDS)
            .unwrap()
            .iter()
            .map(|v| v.bytes().unwrap().to_vec())
            .collect::<Vec<_>>();
        let bootstrap = crate::trust_bootstrap::inspect(&self.local.bootstrap, true).unwrap();
        (
            state,
            crate::authority_domains::result::merge(&bootstrap, &records).unwrap(),
        )
    }
}
#[test]
fn source_context_populates_cold_bridge_and_paginates_complete_current_publications() {
    let mut f = SourceFixture::new();
    // Four native/share records per publication must cross the actual 64-reference result bound.
    let count = MAXIMUM_CONTEXT_RECORDS / 4 + 1;
    for id in 1..=count {
        f.publish([id as u8; 16]);
    }
    let get = f
        .evaluate(
            Command::Get {
                agreement: f.treaty.id,
            }
            .into(),
            vec![],
            106,
            None,
        )
        .2;
    assert_eq!(get.code, 0);
    assert!(
        !f.context(&get.value)
            .0
            .records
            .keys()
            .any(|(kind, _)| *kind == 140)
    );
    let exact = Command::SourceContext {
        agreement: f.treaty.id,
        page: Some([1; 16]),
        after: None,
    };
    let (intent, operation, result) = f.evaluate(exact.clone().into(), vec![], 106, None);
    assert_eq!(result.code, 0);
    assert!(response_inputs(&intent, &result.value).unwrap().is_empty());
    assert!(exact.command_inputs().is_empty());
    assert!(exact.required_inputs(&f.state).unwrap().is_empty());
    let (cold, records) = f.context(&result.value);
    for kind in [140, 141, 142, 150, 151, 152, 153, 157] {
        assert!(cold.records.keys().any(|(k, _)| *k == kind));
    }
    let checked = operation
        .prepare(
            &cold,
            &records,
            &f.local.reservations,
            &intent,
            5000,
            false,
            true,
        )
        .unwrap();
    assert_eq!(checked.code, 0);
    assert_eq!(checked.value, result.value);
    let empty = State::empty(f.state.network, f.state.incarnation);
    assert_eq!(
        f.verify_context(&empty, &intent, &result).unwrap().value,
        result.value
    );
    for (seed, grant) in [(5, None), (106, Some(f.grant.clone())), (105, None)] {
        assert_eq!(
            f.evaluate(exact.clone().into(), vec![], seed, grant).2.code,
            3
        );
    }
    let old_cache = f.state.clone();
    let mut after = None;
    let mut seen = BTreeSet::new();
    let mut rounds = 0;
    loop {
        let cmd = Command::SourceContext {
            agreement: f.treaty.id,
            page: None,
            after,
        };
        let (intent, op, decision) = f.evaluate(cmd.into(), vec![], 106, None);
        assert_eq!(decision.code, 0);
        let (partial, records) = f.context(&decision.value);
        let checked = op
            .prepare(
                &partial,
                &records,
                &f.local.reservations,
                &intent,
                5000,
                false,
                true,
            )
            .unwrap();
        assert_eq!(checked.code, 0);
        assert_eq!(checked.value, decision.value);
        assert_eq!(
            f.verify_context(&old_cache, &intent, &decision)
                .unwrap()
                .value,
            decision.value
        );
        let ids = partial
            .records
            .values()
            .filter(|r| r.reference.kind == 153)
            .map(|r| r.reference.id)
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|id| after.is_none_or(|a| *id > a)));
        if ids.is_empty() {
            break;
        }
        if rounds == 0 {
            assert!(ids.len() > 4 && ids.len() < count);
        }
        assert!(ids.iter().all(|id| seen.insert(*id)));
        let selection = Some(ids.clone());
        assert_eq!(
            Command::parse_inventory(&Command::inventory_value(&selection), None, after).unwrap(),
            selection
        );
        after = ids.last().copied();
        rounds += 1;
    }
    assert_eq!(seen.len(), count);
    assert!(rounds > 1);
    let share = f
        .state
        .record(153, share_id(f.treaty.id, [1; 16]).unwrap())
        .unwrap()
        .reference
        .clone();
    f.apply(Command::Unshare { share }.into(), vec![], 5, None);
    assert!(f.verify_context(&f.state, &intent, &result).is_err());
    let (inventory_intent, _, inventory_result) = f.evaluate(
        Command::SourceContext {
            agreement: f.treaty.id,
            page: None,
            after: None,
        }
        .into(),
        vec![],
        106,
        None,
    );
    assert_eq!(inventory_result.code, 0);
    let merged = f
        .verify_context(&old_cache, &inventory_intent, &inventory_result)
        .unwrap();
    let unshared = share_id(f.treaty.id, [1; 16]).unwrap();
    assert!(
        !f.context(&inventory_result.value)
            .0
            .records
            .contains_key(&(153, unshared))
    );
    // An omitted record stays retained; only the certified discovery selection is evaluated.
    assert!(merged.state.records.contains_key(&(153, unshared)));
    assert_eq!(
        operation
            .prepare(
                &f.state,
                &f.records,
                &f.local.reservations,
                &intent,
                5000,
                false,
                true
            )
            .unwrap()
            .code,
        3
    );
    assert_eq!(
        f.evaluate(exact.clone().into(), vec![], 106, None).2.code,
        3
    );
    let bridge = f
        .state
        .record(152, f.treaty.source_bridge)
        .unwrap()
        .reference
        .clone();
    f.apply(Command::BridgeWithdraw { bridge }.into(), vec![], 90, None);
    assert_eq!(
        f.evaluate(
            Command::SourceContext {
                agreement: f.treaty.id,
                page: None,
                after: None
            }
            .into(),
            vec![],
            106,
            None
        )
        .2
        .code,
        3
    );
}
#[test]
fn export_inventory_selection_is_exact_sorted_and_disjoint_from_page_exports() {
    let selection = Some(vec![[11; 32], [12; 32]]);
    let value = Command::inventory_value(&selection);
    assert_eq!(
        Command::parse_inventory(&value, None, Some([10; 32])).unwrap(),
        selection
    );
    assert!(Command::parse_inventory(&value, Some([1; 16]), None).is_err());
    assert!(Command::parse_inventory(&value, None, Some([11; 32])).is_err());
    assert!(Command::parse_inventory(&V::Null, None, None).is_err());
    for ids in [vec![[12; 32], [11; 32]], vec![[11; 32], [11; 32]]] {
        assert!(
            Command::parse_inventory(&Command::inventory_value(&Some(ids)), None, None).is_err()
        );
    }
    assert!(
        Command::parse_inventory(&a(vec![b(&[13; 32]), a(vec![b(&[11; 32])])]), None, None)
            .is_err()
    );
    assert_eq!(
        Command::parse_inventory(&Command::inventory_value(&Some(vec![])), None, None).unwrap(),
        Some(vec![])
    );
}
