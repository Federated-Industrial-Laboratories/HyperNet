// SPDX-License-Identifier: MIT
// Committed publication needs exact immutable bytes; certified reads select only approved output.
use super::*;
use crate::{
    authority_domains::{
        self as domains,
        page::{self, Command, objects},
    },
    authority_objects::{Class, Object, Reference, Resolved},
};

fn inputs(objects: &[(Class, &[u8])]) -> Resolved {
    let mut values = objects
        .iter()
        .map(|(class, bytes)| {
            Object::verify(Reference::for_bytes(*class, bytes).unwrap(), bytes.to_vec()).unwrap()
        })
        .collect::<Vec<_>>();
    values.sort_by_key(|v| v.reference().clone());
    Resolved::exact(
        &values
            .iter()
            .map(|v| v.reference().clone())
            .collect::<Vec<_>>(),
        values,
    )
    .unwrap()
}
fn request(
    f: &tests::Fixture,
    prior: &[u8],
    sequence: u8,
    command: Command,
    inputs: &Resolved,
) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let grant = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap()
    .versions()
    .into_iter()
    .find(|r| r.kind == 102 && r.id == f.grant)
    .unwrap();
    let snapshot = |refs: &[VersionRef]| {
        domains::snapshot(&array(vec![
            array(vec![
                V::Uint(f.app.config.scope.epoch),
                V::Uint(state.height),
                b(&wire::digest(prior)),
            ]),
            array(refs.iter().map(reference).collect()),
        ]))
        .unwrap()
    };
    let mut operation = domains::Operation {
        grant: Some(grant),
        command: command.into(),
        snapshot: snapshot(&[]),
    };
    let signed = f.intent(sequence, &[], u64::from(operation.mutation()));
    let (payload, _) = wire::envelope(&signed, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[9] = V::Text("AuthorityDomain".into());
    fields[10] = b(&operation.command.resource());
    fields[14] = V::Uint(state.height);
    fields[16] = b(&operation.parameters().unwrap());
    let provisional =
        wire::sign_envelope(&wire::encode(&array(fields.clone())).unwrap(), &f.requester).unwrap();
    let intent = Intent::from_signed(&provisional).unwrap();
    let decision = operation
        .prepare_with_inputs(
            &state.domains,
            &state.records,
            &state.reservations,
            &intent,
            5000,
            false,
            false,
            inputs,
        )
        .unwrap();
    assert_eq!(decision.code, 0);
    operation.snapshot = snapshot(&decision.dependencies);
    fields[15] = array(decision.dependencies.iter().map(reference).collect());
    fields[16] = b(&operation.parameters().unwrap());
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), &f.requester).unwrap()
}

#[test]
fn committed_page_requires_exact_inputs_and_certified_read_selects_approved_bundle() {
    let f = tests::Fixture::with_actions(1000, vec![0, 2, 3]);
    let grant = f.expected.iter().find(|r| r.kind == 102).unwrap();
    let body = b"HyperNetPage/2\n# Bookshop\n: Approved opening hours.\n";
    let source = Reference::for_bytes(Class::PageSource, body).unwrap();
    let statement =
        objects::Author::parameters([71; 16], "Books", &source, grant, None, 700000).unwrap();
    let author = crate::authority_deployment_tests::signed(
        &f.requester,
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&statement).unwrap(),
        vec![],
    );
    let author = objects::Author::parse(&author, [20; 32], [21; 32]).unwrap();
    let submit_inputs = inputs(&[(Class::PageSource, body)]);
    let submit = request(
        &f,
        &f.initial,
        1,
        Command::Submit {
            author: author.clone(),
        },
        &submit_inputs,
    );
    let committed = f.committed(&submit, 3500, 5000, 1);
    assert_eq!(
        f.app.command_inputs(&committed.command).unwrap(),
        vec![source.clone()]
    );
    assert!(
        f.app
            .validate(&f.initial, &committed.command, 5000, &Resolved::default())
            .is_err()
    );
    f.app
        .validate(&f.initial, &committed.command, 5000, &submit_inputs)
        .unwrap();
    let submitted = f
        .app
        .execute(&f.initial, &committed, &submit_inputs)
        .unwrap();
    assert_eq!(
        crate::authority_proof::OperationResult::parse(tests::result_bytes(&submitted))
            .unwrap()
            .code,
        0
    );
    assert_eq!(
        f.app.retained_inputs(&submitted.state).unwrap(),
        vec![source.clone()]
    );
    let state = State::parse(&f.app.config, &submitted.state).unwrap();
    let revision = state
        .domains
        .record(141, page::revision_id(author.intent.resource, 1).unwrap())
        .unwrap();
    let statement = objects::Reviewer::parameters(
        &revision.reference,
        &source,
        author.intent.requester,
        author.intent.digest,
        grant,
        None,
        true,
        0,
        None,
        10000,
    )
    .unwrap();
    let review = crate::authority_deployment_tests::signed(
        &f.requester,
        "PageReviewStatement",
        author.intent.resource,
        1,
        wire::decode(&statement).unwrap(),
        vec![],
    );
    let review = objects::Reviewer::parse(&review, [20; 32], [21; 32]).unwrap();
    let bundle = objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
    let bundle_ref = Reference::for_bytes(Class::PageBundle, &bundle).unwrap();
    let review_inputs = inputs(&[(Class::PageSource, body), (Class::PageBundle, &bundle)]);
    let approve = request(
        &f,
        &submitted.state,
        2,
        Command::Review {
            review,
            bundle: Some(bundle_ref.clone()),
        },
        &review_inputs,
    );
    let committed = f.committed(&approve, 3500, 5000, 2);
    assert_eq!(
        f.app.command_inputs(&committed.command).unwrap(),
        vec![bundle_ref.clone()]
    );
    assert_eq!(
        f.app
            .required_inputs(&submitted.state, &committed.command)
            .unwrap(),
        review_inputs.references()
    );
    let approved = f
        .app
        .execute(&submitted.state, &committed, &review_inputs)
        .unwrap();
    assert_eq!(
        crate::authority_proof::OperationResult::parse(tests::result_bytes(&approved))
            .unwrap()
            .code,
        0
    );
    assert_eq!(
        f.app.retained_inputs(&approved.state).unwrap(),
        review_inputs.references()
    );
    let read_inputs = inputs(&[(Class::PageBundle, &bundle)]);
    let read = request(
        &f,
        &approved.state,
        3,
        Command::Read { page: [71; 16] },
        &read_inputs,
    );
    let committed = f.committed(&read, 3500, 5000, 3);
    assert!(f.app.command_inputs(&committed.command).unwrap().is_empty());
    assert!(
        f.app
            .execute(&approved.state, &committed, &Resolved::default())
            .is_err()
    );
    let read = f
        .app
        .execute(&approved.state, &committed, &read_inputs)
        .unwrap();
    assert_eq!(
        f.app
            .result_inputs(&committed.command, tests::result_bytes(&read))
            .unwrap(),
        vec![bundle_ref]
    );
    f.app.validate_checkpoint(&read.state, 3).unwrap();
}

fn submission(f: &tests::Fixture, prior: &[u8]) -> (Vec<u8>, Resolved) {
    let body = b"HyperNetPage/2\n# Concurrent bookshop\n: Current permission.\n";
    let source = Reference::for_bytes(Class::PageSource, body).unwrap();
    let grant = f
        .expected
        .iter()
        .find(|r| r.kind == 102 && r.id == f.grant)
        .unwrap();
    let statement =
        objects::Author::parameters([71; 16], "Books", &source, grant, None, 700000).unwrap();
    let author = crate::authority_deployment_tests::signed(
        &f.requester,
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&statement).unwrap(),
        vec![],
    );
    let author = objects::Author::parse(&author, [20; 32], [21; 32]).unwrap();
    let objects = inputs(&[(Class::PageSource, body)]);
    (
        request(f, prior, 1, Command::Submit { author }, &objects),
        objects,
    )
}
fn code(execution: &Execution) -> u64 {
    crate::authority_proof::OperationResult::parse(tests::result_bytes(execution))
        .unwrap()
        .code
}

#[test]
fn domain_page_mutation_survives_unrelated_receipts_but_checks_point_and_dependencies() {
    let mut f = tests::Fixture::with_extra_administrator(1000, vec![0, 2, 3]);
    let (submit, objects) = submission(&f, &f.initial);
    let requester = f.requester.clone();
    let grant = f.grant;
    f.requester = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    f.grant = [92; 32];
    let context = request(
        &f,
        &f.initial,
        1,
        Command::Context {
            action: 2,
            scope_kind: 2,
            resource: page::page_id(&[71; 16]).unwrap(),
            namespace: Some("Books".into()),
        },
        &Resolved::default(),
    );
    let interleaved = f
        .app
        .execute(
            &f.initial,
            &f.committed(&context, 3500, 5000, 1),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&interleaved), 0);
    let initial = State::parse(&f.app.config, &f.initial).unwrap();
    let before = State::parse(&f.app.config, &interleaved.state).unwrap();
    assert_eq!(before.records, initial.records);
    assert_eq!(before.domains.value(), initial.domains.value());
    assert_ne!(wire::digest(&interleaved.state), wire::digest(&f.initial));
    f.requester = requester;
    f.grant = grant;
    let committed = f.committed(&submit, 3500, 5000, 2);
    f.app
        .validate(&interleaved.state, &committed.command, 5000, &objects)
        .unwrap();
    let accepted = f
        .app
        .execute(&interleaved.state, &committed, &objects)
        .unwrap();
    assert_eq!(code(&accepted), 0);
    assert_eq!(
        f.app.retained_inputs(&accepted.state).unwrap(),
        objects.references()
    );
    let after = State::parse(&f.app.config, &accepted.state).unwrap();
    assert!(
        after
            .domains
            .record(140, page::page_id(&[71; 16]).unwrap())
            .is_ok()
    );

    // Alter the signed request consistently, so each failure reaches evaluation
    // rather than depending on a malformed signature or duplicated envelope field.
    for case in [
        "dependency",
        "missingDependency",
        "currentDigest",
        "future",
        "epoch",
    ] {
        let (payload, _) = wire::envelope(&submit, 1).unwrap();
        let mut intent = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
        let mut parameters = wire::decode(intent[16].bytes().unwrap())
            .unwrap()
            .array(6)
            .unwrap()
            .to_vec();
        let mut snapshot = parameters[5].array(2).unwrap().to_vec();
        let mut point = snapshot[0].array(3).unwrap().to_vec();
        if case == "dependency" || case == "missingDependency" {
            let mut refs = intent[15].list(64).unwrap().to_vec();
            if case == "dependency" {
                let mut changed = refs[0].array(4).unwrap().to_vec();
                changed[3] = b(&[88; 32]);
                refs[0] = array(changed);
            } else {
                refs.pop();
            }
            intent[15] = array(refs);
            snapshot[1] = intent[15].clone();
        } else {
            match case {
                "currentDigest" => {
                    point[1] = V::Uint(1);
                    point[2] = b(&[88; 32]);
                }
                "future" => point[1] = V::Uint(2),
                "epoch" => point[0] = V::Uint(1),
                _ => unreachable!(),
            }
            intent[13] = point[0].clone();
            intent[14] = point[1].clone();
        }
        snapshot[0] = array(point);
        parameters[5] = array(snapshot);
        intent[16] = b(&wire::encode(&array(parameters)).unwrap());
        let changed =
            wire::sign_envelope(&wire::encode(&array(intent)).unwrap(), &f.requester).unwrap();
        let refused = f
            .app
            .execute(
                &interleaved.state,
                &f.committed(&changed, 3500, 5000, 2),
                &objects,
            )
            .unwrap();
        assert_eq!(code(&refused), 12, "{case}");
        let denied = State::parse(&f.app.config, &refused.state).unwrap();
        assert_eq!(denied.domains.value(), before.domains.value(), "{case}");
        assert_eq!(denied.records, before.records, "{case}");
        assert!(f.app.retained_inputs(&refused.state).unwrap().is_empty());
    }
}

#[test]
fn domain_page_mutation_rechecks_revocation_and_conflicting_head_after_its_floor() {
    for revoke in [false, true] {
        let mut f = tests::Fixture::with_extra_administrator(1000, vec![0, 2, 3, 12]);
        let (submit, objects) = submission(&f, &f.initial);
        let requester = f.requester.clone();
        let grant = f.grant;
        f.requester = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
        f.grant = [92; 32];
        let (change, change_inputs) = if revoke {
            (
                transaction_tests::revoke(&f, &f.initial, grant, 1),
                Resolved::default(),
            )
        } else {
            submission(&f, &f.initial)
        };
        let intervened = f
            .app
            .execute(
                &f.initial,
                &f.committed(&change, 3500, 5000, 1),
                &change_inputs,
            )
            .unwrap();
        assert_eq!(code(&intervened), 0);
        let before = State::parse(&f.app.config, &intervened.state).unwrap();
        f.requester = requester;
        f.grant = grant;
        let refused = f
            .app
            .execute(
                &intervened.state,
                &f.committed(&submit, 3500, 5000, 2),
                &objects,
            )
            .unwrap();
        assert_eq!(code(&refused), 3);
        let after = State::parse(&f.app.config, &refused.state).unwrap();
        assert_eq!(after.domains.value(), before.domains.value());
        assert_eq!(after.records, before.records);
    }
}
