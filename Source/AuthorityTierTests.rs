// SPDX-License-Identifier: MIT
// Tier history preserves bootstrap identity while preview prevents unseen policy changes.
use super::{
    membership_tests::{code, execute, snapshot},
    tests::Fixture,
    *,
};
use crate::{authority_governance::Requirement, authority_tiers::Spec};
fn proposal(
    f: &Fixture,
    prior: &[u8],
    previous: Option<&[u8]>,
    spec: &Spec,
    apply: bool,
    token: Option<[u8; 32]>,
) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    let mut refs = governance
        .current_capability(
            f.grant,
            &Requirement {
                subject: f.requester.verifying_key().to_bytes(),
                actions: &[9],
                scope: (0, f.app.config.scope.network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 6000,
                expected: &[],
            },
        )
        .unwrap()
        .dependencies;
    let generation = if let Some(old) = previous {
        let (_, r) = Spec::from_record(
            old,
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
        )
        .unwrap();
        refs.push(r.clone());
        r.generation + 1
    } else {
        1
    };
    refs.sort_by_key(VersionRef::index);
    refs.dedup();
    let action = if apply {
        "AuthorityTierApply"
    } else {
        "AuthorityTierPreview"
    };
    let params = array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(action.into()),
        b(&f.grant),
        previous.map_or(V::Null, b),
        spec.value(),
        snapshot(f, prior, &refs),
        token.map_or(V::Null, |v| b(&v)),
    ]);
    let signed = membership_tests::signed(f, prior, &f.requester, action, spec.id, params, refs);
    let (payload, _) = wire::envelope(&signed, 1).unwrap();
    let v = wire::decode(&payload).unwrap();
    let mut fields = v.array(17).unwrap().to_vec();
    fields[11] = V::Uint(generation);
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), &f.requester).unwrap()
}
fn preview(f: &Fixture, prior: &[u8], old: Option<&[u8]>, spec: &Spec) -> (Vec<u8>, [u8; 32]) {
    let request = proposal(f, prior, old, spec, false, None);
    let executed = execute(f, prior, &request, &f.requester, 6000);
    assert_eq!(code(&executed), 0);
    let result =
        crate::authority_proof::OperationResult::parse(tests::result_bytes(&executed)).unwrap();
    let value = wire::decode(&result.value).unwrap();
    let view = value.array(5).unwrap()[4].array(7).unwrap()[1]
        .fixed()
        .unwrap();
    (executed.state, view)
}
fn initial(f: &Fixture) -> (Vec<u8>, Spec) {
    let state = State::parse(&f.app.config, &f.initial).unwrap();
    let bytes = state
        .records
        .iter()
        .find(|r| {
            wire::decode(r).unwrap().list(32).unwrap()[0]
                .uint()
                .unwrap()
                == 101
        })
        .unwrap()
        .clone();
    let spec = Spec::from_record(
        &bytes,
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
    )
    .unwrap()
    .0;
    (bytes, spec)
}
#[test]
fn tier_impacts_include_signed_recipient_admission_snapshot() {
    use crate::{authority_deployment_tests as deployment, authority_domains::Record};
    let f = Fixture::with_actions(1000, vec![0, 1, 9]);
    let mut state = State::parse(&f.app.config, &f.initial).unwrap();
    let (_, tier) = initial(&f);
    let governance = Governance::parse(
        state.domains.network,
        state.domains.incarnation,
        &state.records,
    )
    .unwrap();
    let grant = governance
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
        .unwrap();
    let binding = VersionRef {
        kind: 108,
        id: [190; 32],
        generation: 1,
        digest: [191; 32],
    };
    let payload = wire::encode(&array(vec![
        V::Uint(109),
        V::Uint(1),
        b(&state.domains.network),
        b(&state.domains.incarnation),
        V::Uint(1),
        V::Null,
        b(&[192; 32]),
        reference(&binding),
        array(vec![array(vec![V::Uint(0), b(&state.domains.network)])]),
        array(vec![V::Uint(1000), V::Uint(18000)]),
        b(&[193; 32]),
        deployment::snapshot(&[grant]),
    ]))
    .unwrap();
    let signed = wire::sign_envelope(&payload, &f.requester).unwrap();
    let record = Record::parse(&signed, state.domains.network, state.domains.incarnation).unwrap();
    let expected = record.reference.clone();
    state.domains.records.insert(expected.index(), record);
    let impacts = tier_evaluation::impacts(&state, tier.id, [194; 32]).unwrap();
    let row = impacts
        .iter()
        .find(|row| row.array(5).unwrap()[1].fixed::<32>().unwrap() == expected.id)
        .unwrap()
        .array(5)
        .unwrap();
    assert_eq!(row[0].uint().unwrap(), 4);
    assert_eq!(
        row[2].fixed::<32>().unwrap(),
        wire::digest(&wire::encode_state(&array(vec![reference(&expected)])).unwrap())
    );
}
#[test]
fn tier_impacts_include_nested_page_statements_and_application_consent() {
    use crate::{
        authority_deployment_tests as deployment,
        authority_domains::{Record, page},
        authority_objects::{Class, Reference},
    };
    let f = Fixture::with_actions(1000, vec![0, 1, 9]);
    let mut state = State::parse(&f.app.config, &f.initial).unwrap();
    let n = state.domains.network;
    let i = state.domains.incarnation;
    let grant = Governance::parse(n, i, &state.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
        .unwrap();
    let application = deployment::key(150);
    let application_key = application.verifying_key().to_bytes();
    let application_grant = VersionRef {
        id: [195; 32],
        ..grant.clone()
    };
    let reviewer_grant = VersionRef {
        id: [196; 32],
        ..grant.clone()
    };
    let policy = page::ApplicationPolicy {
        application: application_key,
        owner: f.requester.verifying_key().to_bytes(),
        registration: VersionRef {
            kind: 127,
            id: application_key,
            generation: 1,
            digest: [197; 32],
        },
        grant: application_grant.clone(),
        namespaces: vec!["Books".into()],
        pages: None,
        permissions: vec!["PagesSubmit".into()],
        review: None,
        expires_ms: 18000,
        previous: None,
        envelope: vec![],
    };
    let payload = policy.payload(n, i).unwrap();
    let mut signatures = [&f.requester, &application]
        .into_iter()
        .map(|key| {
            wire::envelope(&wire::sign_envelope(&payload, key).unwrap(), 1)
                .unwrap()
                .1
                .remove(0)
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|s| s.0);
    let consent = wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        array(
            signatures
                .into_iter()
                .map(|(key, signature)| array(vec![b(&key), b(&signature)]))
                .collect(),
        ),
    ]))
    .unwrap();
    let application_record =
        Record::next(&state.domains, 148, application_key, b(&consent)).unwrap();
    let source = b"HyperNetPage/2\n# Books\n: Signed publication dependencies.\n";
    let raw = [71; 16];
    let page_id = page::page_id(&raw).unwrap();
    let parameters = page::objects::Author::parameters(
        raw,
        "Books",
        source,
        &grant,
        Some(&application_record.reference),
        18000,
    )
    .unwrap();
    let author = page::objects::Author::parse(
        &deployment::signed(
            &application,
            "PageAuthorStatement",
            page_id,
            1,
            wire::decode(&parameters).unwrap(),
            vec![],
        ),
        n,
        i,
    )
    .unwrap();
    let revision = page::Revision::from_author(author.clone()).unwrap();
    let revision_record = Record::next(
        &state.domains,
        141,
        revision.identity().unwrap(),
        revision.value(),
    )
    .unwrap();
    let parameters = page::objects::Reviewer::parameters(
        &revision_record.reference,
        &author.source,
        author.intent.requester,
        author.intent.digest,
        &reviewer_grant,
        None,
        true,
        0,
        None,
        18000,
    )
    .unwrap();
    let statement = page::objects::Reviewer::parse(
        &deployment::signed(
            &f.requester,
            "PageReviewStatement",
            page_id,
            1,
            wire::decode(&parameters).unwrap(),
            vec![],
        ),
        n,
        i,
    )
    .unwrap();
    let bundle = page::objects::Bundle::encode(source, &author.bytes, &statement.bytes).unwrap();
    let review = page::Review {
        statement,
        bundle: Some(Reference::for_bytes(Class::PageBundle, &bundle).unwrap()),
        recorded_ms: 6000,
    };
    let review_record = Record::next(
        &state.domains,
        142,
        revision_record.reference.id,
        review.value(),
    )
    .unwrap();
    let ledger = page::Ledger {
        raw_page: raw,
        author: application_key,
        namespace: "Books".into(),
        last_revision: 1,
        pending: None,
        published: Some(review_record.reference.clone()),
    };
    let ledger_record = Record::next(&state.domains, 140, page_id, ledger.value()).unwrap();
    let expected_versions = array(vec![
        reference(&revision_record.reference),
        reference(&review_record.reference),
    ]);
    let expected_digest = wire::digest(&wire::encode_state(&expected_versions).unwrap());
    let revision_id = revision_record.reference.id;
    for record in [
        application_record,
        revision_record,
        review_record,
        ledger_record,
    ] {
        state
            .domains
            .records
            .insert(record.reference.index(), record);
    }
    // Distinct roots ensure each signed layer contributes its own dependency, then
    // the shared revision subject and the Page head follow the transitive closure.
    for root in [grant.id, application_grant.id, reviewer_grant.id] {
        let impacts = tier_evaluation::impacts(&state, root, [198; 32]).unwrap();
        let rows = impacts
            .iter()
            .map(|row| {
                let row = row.array(5).unwrap();
                (row[1].fixed::<32>().unwrap(), row)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(rows.contains_key(&page_id));
        assert_eq!(rows[&revision_id][0].uint().unwrap(), 3);
        assert_eq!(
            rows[&revision_id][2].fixed::<32>().unwrap(),
            expected_digest
        );
        if root == application_grant.id {
            assert!(rows.contains_key(&application_key));
        }
    }
}
#[test]
fn tier_preview_apply_retains_genesis_and_durable_history() {
    let f = Fixture::with_actions(1000, vec![0, 1, 9, 11, 12, 25]);
    let (old, mut spec) = initial(&f);
    spec.label = "Readers and administrators".into();
    let (state, view) = preview(&f, &f.initial, Some(&old), &spec);
    let request = proposal(&f, &state, Some(&old), &spec, true, Some(view));
    let first = execute(&f, &state, &request, &f.requester, 6500);
    assert_eq!(code(&first), 0);
    let parsed = State::parse(&f.app.config, &first.state).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap();
    let updated = governance.record_bytes(101, spec.id).unwrap().to_vec();
    let initial_state = State::parse(&f.app.config, &f.initial).unwrap();
    let initial_governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &initial_state.records,
    )
    .unwrap();
    assert_eq!(
        governance
            .record_bytes(100, f.app.config.scope.network)
            .unwrap(),
        initial_governance
            .record_bytes(100, f.app.config.scope.network)
            .unwrap()
    );
    assert_eq!(
        Spec::from_record(
            &updated,
            f.app.config.scope.network,
            f.app.config.scope.incarnation
        )
        .unwrap()
        .1
        .generation,
        2
    );
    governance
        .current_capability(
            f.grant,
            &Requirement {
                subject: f.requester.verifying_key().to_bytes(),
                actions: &[0],
                scope: (0, f.app.config.scope.network),
                namespace: None,
                usage: [0; 4],
                evaluated_at_ms: 6500,
                expected: &[],
            },
        )
        .unwrap();
    spec.rank = 4;
    let (state, view) = preview(&f, &first.state, Some(&updated), &spec);
    let request = proposal(&f, &state, Some(&updated), &spec, true, Some(view));
    let second = execute(&f, &state, &request, &f.requester, 7000);
    assert_eq!(code(&second), 0);
    f.app.validate_checkpoint(&second.state, 4).unwrap();
    let mut corrupted = wire::decode_state(&second.state)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    let mut history = corrupted[9].list(2048).unwrap().to_vec();
    history.remove(0);
    corrupted[9] = array(history);
    assert!(
        State::parse(
            &f.app.config,
            &wire::encode_state(&array(corrupted)).unwrap()
        )
        .is_err()
    );
}
#[test]
fn tier_apply_refuses_unreviewed_policy_view_without_partial_mutation() {
    let f = Fixture::with_actions(1000, vec![0, 1, 9, 11, 12, 25]);
    let (_, mut spec) = initial(&f);
    spec.id = [67; 32];
    spec.label = "Namespace readers".into();
    let (state, _) = preview(&f, &f.initial, None, &spec);
    let request = proposal(&f, &state, None, &spec, true, Some([99; 32]));
    let refused = execute(&f, &state, &request, &f.requester, 6500);
    assert_eq!(code(&refused), 12);
    let parsed = State::parse(&f.app.config, &refused.state).unwrap();
    assert!(
        Governance::parse(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            &parsed.records
        )
        .unwrap()
        .record_bytes(101, spec.id)
        .is_err()
    );
    let (state, view) = preview(&f, &refused.state, None, &spec);
    let request = proposal(&f, &state, None, &spec, true, Some(view));
    let created = execute(&f, &state, &request, &f.requester, 7000);
    assert_eq!(code(&created), 0);
    State::parse(&f.app.config, &created.state).unwrap();
}
#[test]
fn current_tier_cannot_change_a_grant_identity_or_accept_future_policy() {
    use crate::authority_tiers::current_reference;
    let old = VersionRef {
        kind: 101,
        id: [1; 32],
        generation: 1,
        digest: [2; 32],
    };
    let mut current = old.clone();
    current.generation = 2;
    current.digest = [3; 32];
    assert!(current_reference(&current, &old).is_ok());
    assert!(current_reference(&old, &current).is_err());
    current.id = [4; 32];
    assert!(current_reference(&current, &old).is_err());
    current = old.clone();
    current.digest = [9; 32];
    assert!(current_reference(&current, &old).is_err());
}

#[test]
fn current_tier_attenuates_historical_grants_and_parent_revocation_remains_permanent() {
    let f = Fixture::with_actions(1000, vec![0, 1, 9, 10, 11, 12, 25]);
    let (_, mut spec) = initial(&f);
    spec.id = [67; 32];
    spec.actions = vec![0, 1];
    spec.depth = 1;
    let (state, view) = preview(&f, &f.initial, None, &spec);
    let created = execute(
        &f,
        &state,
        &proposal(&f, &state, None, &spec, true, Some(view)),
        &f.requester,
        6500,
    );
    assert_eq!(code(&created), 0);
    let state = State::parse(&f.app.config, &created.state).unwrap();
    let gov = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    let mut tier = gov.record_bytes(101, spec.id).unwrap().to_vec();
    let initial_tier = Spec::from_record(
        &tier,
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
    )
    .unwrap()
    .1;
    let candidate = membership_tests::key(80);
    let member = membership_tests::public(&candidate);
    let child = membership_tests::child(&f, member, 68);
    let mut child = child.array(8).unwrap().to_vec();
    child[2] = reference(&initial_tier);
    child[3] = array(vec![V::Uint(0), V::Uint(1)]);
    let delegated = execute(
        &f,
        &created.state,
        &membership_tests::delegate(&f, &created.state, array(child), 7000),
        &f.requester,
        7000,
    );
    assert_eq!(code(&delegated), 0);
    let reader = membership_tests::reader(&f, &delegated.state, 68);
    let acceptance = membership_tests::accepted(&f, &candidate, reader, 81, 500000);
    let admission = membership_tests::admit(&f, &delegated.state, &acceptance, 7200);
    let delegated = execute(&f, &delegated.state, &admission, &f.requester, 7200);
    assert_eq!(code(&delegated), 0);
    let allowed = |state: &[u8], action: u64| {
        let state = State::parse(&f.app.config, state).unwrap();
        Governance::parse(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            &state.records,
        )
        .unwrap()
        .current_capability(
            [68; 32],
            &Requirement {
                subject: member,
                actions: &[action],
                scope: (0, f.app.config.scope.network),
                namespace: None,
                usage: [0; 4],
                evaluated_at_ms: 8000,
                expected: &[],
            },
        )
        .is_ok()
    };
    assert!(allowed(&delegated.state, 1));
    assert!(!allowed(&delegated.state, 9));
    spec.rank = 0;
    let (state, view) = preview(&f, &delegated.state, Some(&tier), &spec);
    let ranked = execute(
        &f,
        &state,
        &proposal(&f, &state, Some(&tier), &spec, true, Some(view)),
        &f.requester,
        7500,
    );
    assert_eq!(code(&ranked), 0);
    assert!(allowed(&ranked.state, 1));
    assert!(!allowed(&ranked.state, 9));
    let parsed = State::parse(&f.app.config, &ranked.state).unwrap();
    tier = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap()
    .record_bytes(101, spec.id)
    .unwrap()
    .to_vec();
    spec.actions = vec![0];
    spec.limits = [5, 6, 1, 1];
    let (state, view) = preview(&f, &ranked.state, Some(&tier), &spec);
    let narrowed = execute(
        &f,
        &state,
        &proposal(&f, &state, Some(&tier), &spec, true, Some(view)),
        &f.requester,
        8000,
    );
    assert_eq!(code(&narrowed), 0);
    assert!(!allowed(&narrowed.state, 1));
    assert!(allowed(&narrowed.state, 0));
    let scoped_use = |state: &[u8], scope: (u64, [u8; 32]), usage: [u64; 4]| {
        let parsed = State::parse(&f.app.config, state).unwrap();
        Governance::parse(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            &parsed.records,
        )
        .unwrap()
        .current_capability(
            [68; 32],
            &Requirement {
                subject: member,
                actions: &[0],
                scope,
                namespace: None,
                usage,
                evaluated_at_ms: 8000,
                expected: &[],
            },
        )
        .is_ok()
    };
    assert!(scoped_use(
        &narrowed.state,
        (0, f.app.config.scope.network),
        [5, 6, 1, 1]
    ));
    assert!(!scoped_use(
        &narrowed.state,
        (0, f.app.config.scope.network),
        [6, 6, 1, 1]
    ));
    let parsed = State::parse(&f.app.config, &narrowed.state).unwrap();
    tier = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap()
    .record_bytes(101, spec.id)
    .unwrap()
    .to_vec();
    spec.scopes = vec![(1, [72; 32])];
    let (state, view) = preview(&f, &narrowed.state, Some(&tier), &spec);
    let narrowed = execute(
        &f,
        &state,
        &proposal(&f, &state, Some(&tier), &spec, true, Some(view)),
        &f.requester,
        8200,
    );
    assert_eq!(code(&narrowed), 0);
    assert!(scoped_use(&narrowed.state, (1, [72; 32]), [5, 6, 1, 1]));
    assert!(!scoped_use(&narrowed.state, (1, [73; 32]), [0; 4]));
    assert!(!allowed(&narrowed.state, 0));
    let parsed = State::parse(&f.app.config, &narrowed.state).unwrap();
    let gov = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap();
    let child = wire::decode(gov.record_bytes(102, [68; 32]).unwrap()).unwrap();
    assert_eq!(child.array(17).unwrap()[9], reference(&initial_tier));
    let target = gov
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
        .unwrap();
    let refs = gov
        .current_capability(
            f.grant,
            &Requirement {
                subject: f.requester.verifying_key().to_bytes(),
                actions: &[12],
                scope: (0, f.app.config.scope.network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 8500,
                expected: &[],
            },
        )
        .unwrap()
        .dependencies;
    let parameters = array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityRevokeGrant".into()),
        b(&f.grant),
        reference(&target),
        snapshot(&f, &narrowed.state, &refs),
    ]);
    let request = membership_tests::signed(
        &f,
        &narrowed.state,
        &f.requester,
        "AuthorityRevokeGrant",
        f.grant,
        parameters,
        refs,
    );
    let revoked = execute(&f, &narrowed.state, &request, &f.requester, 8500);
    assert_eq!(code(&revoked), 0);
    let parsed = State::parse(&f.app.config, &revoked.state).unwrap();
    let gov = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap();
    assert!(gov.revoked_chain([68; 32]).unwrap());
    assert!(!allowed(&revoked.state, 1));
}

#[test]
fn delegation_cannot_issue_rights_removed_from_the_current_parent_tier() {
    let f = Fixture::with_actions(1000, vec![0, 1, 9, 11, 12, 25]);
    let (root, mut administrator) = initial(&f);
    let mut readers = administrator.clone();
    readers.id = [78; 32];
    readers.actions = vec![0, 1];
    readers.depth = 0;
    let (state, view) = preview(&f, &f.initial, None, &readers);
    let created = execute(
        &f,
        &state,
        &proposal(&f, &state, None, &readers, true, Some(view)),
        &f.requester,
        6500,
    );
    assert_eq!(code(&created), 0);
    let parsed = State::parse(&f.app.config, &created.state).unwrap();
    let gov = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &parsed.records,
    )
    .unwrap();
    let reader_tier = Spec::from_record(
        gov.record_bytes(101, readers.id).unwrap(),
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
    )
    .unwrap()
    .1;
    administrator.actions.retain(|action| *action != 1);
    let (state, view) = preview(&f, &created.state, Some(&root), &administrator);
    let narrowed = execute(
        &f,
        &state,
        &proposal(&f, &state, Some(&root), &administrator, true, Some(view)),
        &f.requester,
        7000,
    );
    assert_eq!(code(&narrowed), 0);
    let mut child =
        membership_tests::child(&f, membership_tests::public(&membership_tests::key(80)), 79)
            .array(8)
            .unwrap()
            .to_vec();
    child[2] = reference(&reader_tier);
    child[3] = array(vec![V::Uint(0), V::Uint(1)]);
    let request = membership_tests::delegate(&f, &narrowed.state, array(child), 7500);
    let refused = execute(&f, &narrowed.state, &request, &f.requester, 7500);
    assert_eq!(code(&refused), 4);
    let parsed = State::parse(&f.app.config, &refused.state).unwrap();
    assert!(
        Governance::parse(
            f.app.config.scope.network,
            f.app.config.scope.incarnation,
            &parsed.records
        )
        .unwrap()
        .record_bytes(102, [79; 32])
        .is_err()
    );
}
