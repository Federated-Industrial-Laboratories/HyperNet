// SPDX-License-Identifier: MIT
// Certified views preserve publication and live-content checks in one ordered state.
use super::*;

fn fixture() -> Fixture {
    let f = deployment::Fixture::with_actions(vec![0, 1, 2, 3, 5, 10, 11, 12, 13, 21, 26]);
    let grant = Governance::parse(f.scope.network, f.scope.incarnation, &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    Fixture {
        search: false,
        state: State::empty(f.scope.network, f.scope.incarnation),
        records: f.records,
        reserved: f.reservations,
        grant,
        sequence: 1,
    }
}
fn publish(f: &mut Fixture, page: [u8; 16], expires: u64) -> VersionRef {
    let body = b"HyperNetPage/2\n# Current view\n: Exact approved content.\n";
    let author = f.author_for(page, body, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![],
        5000,
    );
    let revision = f
        .state
        .record(141, revision_id(author.intent.resource, 1).unwrap())
        .unwrap()
        .reference
        .clone();
    if !f.state.records.keys().any(|(kind, _)| *kind == 147) {
        f.hosts();
    }
    let host = f
        .state
        .record(147, deployment::key(100).verifying_key().to_bytes())
        .unwrap()
        .reference
        .clone();
    f.apply(
        Command::Content(content::Command::Place {
            revision: revision.clone(),
            hosts: vec![host],
            copies: 1,
            failure_domains: 1,
            expires_ms: expires,
        }),
        vec![],
        5000,
    );
    let placement = f.content(&revision, 5000, true);
    let review = f.reviewer(&author, true, 10000);
    let bundle = objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
    f.apply(
        Command::Review {
            review,
            bundle: Some(Reference::for_bytes(Class::PageBundle, &bundle).unwrap()),
        },
        vec![],
        5000,
    );
    placement
}
fn selected(f: &Fixture, decision: &Decision) -> BTreeMap<(u64, Digest), Record> {
    decision.value.array(5).unwrap()[4].array(4).unwrap()[1]
        .list(MAXIMUM_CONTEXT_RECORDS)
        .unwrap()
        .iter()
        .map(|v| {
            let r =
                Record::parse(v.bytes().unwrap(), f.state.network, f.state.incarnation).unwrap();
            (r.reference.index(), r)
        })
        .collect()
}
fn references(values: impl IntoIterator<Item = VersionRef>) -> Vec<VersionRef> {
    values
        .into_iter()
        .map(|r| (r.index(), r))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}
#[test]
fn page_view_certifies_read_and_full_content_get_in_one_state() {
    let mut f = fixture();
    let placement = publish(&mut f, [71; 16], 9000);
    let (_, _, read, _) = f.evaluate(Command::Read { page: [71; 16] }, vec![], 6000);
    let (_, _, get, _) = f.evaluate(
        Command::Content(content::Command::Get {
            placement: placement.clone(),
        }),
        vec![],
        6000,
    );
    let command = Command::View { page: [71; 16] };
    assert!(
        matches!(Command::parse(&command.value(), f.state.network, f.state.incarnation)
        .unwrap(), Command::View { page } if page == [71; 16])
    );
    let (intent, _, view, _) = f.evaluate(command, vec![], 6000);
    assert_eq!((read.code, get.code, view.code), (0, 0, 0));
    assert!(view.state.is_none());
    assert_eq!(
        view.dependencies,
        references(read.dependencies.iter().chain(&get.dependencies).cloned())
    );
    assert_eq!(
        view.versions,
        references(read.versions.iter().chain(&get.versions).cloned())
    );
    assert_eq!(view.expires_ms, read.expires_ms.min(get.expires_ms));
    assert_eq!(view.expires_ms, 9000);
    let mut expected = selected(&f, &read);
    expected.extend(selected(&f, &get));
    let actual = selected(&f, &view);
    assert_eq!(actual.len(), expected.len());
    for (index, record) in expected {
        assert_eq!(actual[&index].bytes, record.bytes);
    }
    assert_eq!(actual[&placement.index()].reference, placement);
    assert!(response_inputs(&intent, &view.value).unwrap().is_empty());
    assert_eq!(
        f.evaluate_as(
            Command::View { page: [71; 16] },
            vec![],
            6000,
            9,
            Some(f.grant.clone())
        )
        .2
        .code,
        3,
        "another recipient cannot borrow the reader's grant"
    );
}
#[test]
fn page_view_refuses_expired_or_withdrawn_content_even_for_metadata_owner() {
    let mut f = fixture();
    let placement = publish(&mut f, [71; 16], 6500);
    assert_eq!(
        f.evaluate(Command::View { page: [71; 16] }, vec![], 6000)
            .2
            .code,
        0
    );
    assert_eq!(
        f.evaluate(Command::Read { page: [71; 16] }, vec![], 6600)
            .2
            .code,
        0
    );
    assert_eq!(
        f.evaluate(Command::View { page: [71; 16] }, vec![], 6600)
            .2
            .code,
        3
    );
    f.apply(
        Command::Content(content::Command::Withdraw {
            placement: placement.clone(),
        }),
        vec![],
        6000,
    );
    assert_eq!(
        f.evaluate(
            Command::Content(content::Command::Get { placement }),
            vec![],
            6000
        )
        .2
        .code,
        0
    );
    assert_eq!(
        f.evaluate(Command::Read { page: [71; 16] }, vec![], 6000)
            .2
            .code,
        0
    );
    assert_eq!(
        f.evaluate(Command::View { page: [71; 16] }, vec![], 6000)
            .2
            .code,
        3
    );
}
#[test]
fn search_catalogue_contains_bounded_complete_views_and_omits_unusable_items() {
    let mut f = fixture();
    let mut expected = BTreeSet::new();
    let mut unavailable = BTreeSet::new();
    for number in 1..=16u8 {
        let page = [number; 16];
        let placement = publish(&mut f, page, if number == 1 { 6500 } else { 9000 });
        if number == 2 {
            f.apply(
                Command::Content(content::Command::Withdraw {
                    placement: placement.clone(),
                }),
                vec![],
                6000,
            );
        }
        if number <= 2 {
            unavailable.extend([page_id(&page).unwrap(), placement.id]);
        } else {
            expected.insert(page_id(&page).unwrap());
        }
    }
    let mut found = BTreeSet::new();
    let mut after = None;
    let mut batches = 0;
    loop {
        let (_, _, result, _) = f.evaluate(
            Command::SearchList {
                namespace: "Books".into(),
                after,
            },
            vec![],
            6600,
        );
        assert_eq!(result.code, 0);
        assert!(result.versions.len() <= 64);
        assert!(wire::encode(&result.value).is_ok());
        let records = selected(&f, &result);
        assert!(
            records
                .values()
                .all(|r| !unavailable.contains(&r.reference.id)),
            "a refused item leaked partial metadata"
        );
        for r in records.values().filter(|r| r.reference.kind == 140) {
            let ledger = Ledger::parse(&r.payload).unwrap();
            let (_, _, view, _) = f.evaluate(
                Command::View {
                    page: ledger.raw_page,
                },
                vec![],
                6600,
            );
            assert_eq!(view.code, 0);
            for (index, exact) in selected(&f, &view) {
                assert_eq!(records[&index].bytes, exact.bytes);
            }
            assert!(view.versions.iter().all(|v| result.versions.contains(v)));
            assert!(result.expires_ms <= view.expires_ms);
            assert!(found.insert(r.reference.id), "continuation repeated a view");
        }
        batches += 1;
        let next = &result.value.array(5).unwrap()[4].array(4).unwrap()[3];
        if *next == V::Null {
            break;
        }
        let cursor = id(next).unwrap();
        assert!(after.is_none_or(|prior| cursor > prior));
        after = Some(cursor);
    }
    assert!(
        batches > 1,
        "complete view closures must paginate at the existing proof bound"
    );
    assert_eq!(found, expected);
}

#[test]
fn page_view_and_search_recheck_application_revocation_after_prior_success() {
    let mut f = fixture();
    publish(&mut f, [71; 16], 9000);
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
        a(vec![V::Uint(0), V::Uint(1)]),
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
        registration: registered.clone(),
        grant: delegated.clone(),
        namespaces: vec!["Books".into()],
        pages: None,
        permissions: vec!["PagesRead".into(), "PagesSearch".into()],
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

    let view = Command::View { page: [71; 16] };
    let search = Command::SearchList {
        namespace: "Books".into(),
        after: None,
    };
    for command in [view.clone(), search.clone()] {
        let (intent, operation, decision, _) =
            f.evaluate_as(command.clone(), vec![], 6000, 150, Some(delegated.clone()));
        assert_eq!(decision.code, 0);
        if matches!(command, Command::View { .. }) {
            assert_eq!(
                crate::authority_read::evaluate_domain(
                    &operation,
                    &f.state,
                    &f.records,
                    &f.reserved,
                    intent.requester,
                    6000
                )
                .unwrap()
                .code,
                0
            );
        }
    }
    f.records.push(
        wire::encode(&a(vec![
            V::Uint(128),
            V::Uint(1),
            b(&f.state.network),
            b(&f.state.incarnation),
            V::Uint(1),
            V::Null,
            reference(&registered),
            b(&owner),
            deployment::snapshot(&[]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    for command in [view, search] {
        let (intent, operation, decision, _) =
            f.evaluate_as(command.clone(), vec![], 6001, 150, Some(delegated.clone()));
        assert_eq!(decision.code, 3);
        if matches!(command, Command::View { .. }) {
            assert_eq!(
                crate::authority_read::evaluate_domain(
                    &operation,
                    &f.state,
                    &f.records,
                    &f.reserved,
                    intent.requester,
                    6001
                )
                .unwrap()
                .code,
                3
            );
        }
    }
}

#[test]
fn fresh_page_view_matches_ordered_authority_and_refuses_expiry_withdrawal_recipient() {
    let mut f = fixture();
    let placement = publish(&mut f, [72; 16], 6500);
    let (intent, op, ordered, _) = f.evaluate(Command::View { page: [72; 16] }, vec![], 6000);
    let before = wire::encode(&f.state.value()).unwrap();
    let fresh = crate::authority_read::evaluate_domain(
        &op,
        &f.state,
        &f.records,
        &f.reserved,
        intent.requester,
        6000,
    )
    .unwrap();
    assert_eq!(
        (fresh.code, &fresh.value, &fresh.versions, fresh.expires_ms),
        (
            ordered.code,
            &ordered.value,
            &ordered.versions,
            ordered.expires_ms
        )
    );
    assert!(fresh.state.is_none());
    assert_eq!(wire::encode(&f.state.value()).unwrap(), before);
    assert_eq!(
        crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            deployment::key(9).verifying_key().to_bytes(),
            6000
        )
        .unwrap()
        .code,
        3
    );
    assert_eq!(
        crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            intent.requester,
            6600
        )
        .unwrap()
        .code,
        3
    );
    let host = f
        .state
        .records
        .values()
        .find(|r| r.reference.kind == 147)
        .unwrap()
        .reference
        .clone();
    let authorise = Operation {
        grant: Some(f.grant.clone()),
        command: crate::authority_domains::Command::Page(Command::Content(
            content::Command::Authorise {
                placement: placement.clone(),
                host,
                effect: content::Effect::Read,
                offset: 0,
                bytes: 1,
                digest: None,
            },
        )),
        snapshot: op.snapshot.clone(),
    };
    let scope = crate::authority_proof::Scope {
        network: f.state.network,
        incarnation: f.state.incarnation,
        configuration: [88; 32],
        epoch: op.snapshot.epoch,
    };
    assert!(
        crate::authority_read::Request::sign(
            &scope,
            &deployment::key(5),
            intent.requester,
            [89; 32],
            op.snapshot.height,
            crate::authority_read::Query::Domain(authorise)
        )
        .is_err()
    );
    f.apply(
        Command::Content(content::Command::Withdraw { placement }),
        vec![],
        6000,
    );
    assert_eq!(
        crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            intent.requester,
            6000
        )
        .unwrap()
        .code,
        3
    );
}
