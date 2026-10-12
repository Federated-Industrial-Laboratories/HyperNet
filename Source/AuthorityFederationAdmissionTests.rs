// SPDX-License-Identifier: MIT
// Destination preflight starts from certified response context, including retained import state.
use super::*;
use crate::{
    authority_deployment_tests as deployment,
    authority_domains::federation::tests::SourceFixture,
    authority_objects::{Class, Object},
};

#[path = "AuthorityFederationReaderTests.rs"]
mod reader_tests;

fn insert(state: &mut State, kind: u64, id: Digest, value: V) -> Record {
    let record = Record::next(state, kind, id, value).unwrap();
    state
        .records
        .insert(record.reference.index(), record.clone());
    record
}

fn destination() -> SourceFixture {
    let mut f = SourceFixture::configured(true);
    let bridge = Bridge::parse(
        &f.state
            .record(152, f.treaty.destination_bridge)
            .unwrap()
            .payload,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    let mut host = page::HostProfile {
        manifest: bridge.profile.manifest,
        role: 2,
        service: f.treaty.destination_hosts[0],
        volume: [102; 32],
        namespaces: vec![f.treaty.destination_namespace.clone()],
        state_bytes: 8 * 1024 * 1024,
        maximum_asset_bytes: markup::media::MAX_PAGE_BYTES.min(8 * 1024 * 1024),
        retention_ms: page::MAXIMUM_LIFETIME_MS,
        envelope: vec![],
    };
    host.envelope = wire::sign_envelope(&host.payload().unwrap(), &deployment::key(90)).unwrap();
    let host =
        page::HostProfile::parse(&host.envelope, f.state.network, f.state.incarnation).unwrap();
    f.apply(
        page::Command::HostRegister { profile: host }.into(),
        vec![],
        5,
        Some(f.grant.clone()),
    );
    insert(
        &mut f.state,
        149,
        page::namespace_id(&f.treaty.destination_namespace).unwrap(),
        page::PlacementPolicy {
            namespace: f.treaty.destination_namespace.clone(),
            minimum_copies: 1,
            administrator: deployment::key(5).verifying_key().to_bytes(),
            grant: f.grant.clone(),
        }
        .value(),
    );
    f
}

fn admission(f: &SourceFixture, raw: Option<[u8; 16]>) -> Command {
    Command::Admission {
        agreement: f.state.record(151, f.treaty.id).unwrap().reference.clone(),
        bridge: f
            .state
            .record(152, f.treaty.destination_bridge)
            .unwrap()
            .reference
            .clone(),
        page: raw,
        exchange: [191; 32],
        revision: None,
        after: None,
    }
}

fn source_signed(
    f: &SourceFixture,
    action: &str,
    resource: Digest,
    revision: u64,
    parameters: V,
) -> Vec<u8> {
    let key = deployment::key(5);
    let signed = deployment::signed(&key, action, resource, revision, parameters, vec![]);
    let (payload, _) = wire::envelope(&signed, 1).unwrap();
    let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
        unreachable!()
    };
    fields[2] = b(&f.treaty.source.network);
    fields[3] = b(&f.treaty.source.incarnation);
    wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), &key).unwrap()
}

// Portable-proof verification is a separate boundary; this fixture supplies its typed output.
fn exported_media(f: &SourceFixture, raw: [u8; 16], number: u64) -> (VerifiedForeign, Resolved) {
    let body = format!(
        "HyperNetPage/2\n# Icon\n@Asset {{\"id\":\"Icon\",\"profile\":\"HyperNetRaster/1\",\"width\":1,\"height\":1,\"bytes\":3,\"digest\":\"{}\",\"hosts\":[\"{}\"],\"copies\":1}}\n@Image {{\"id\":\"Picture\",\"asset\":\"Icon\",\"alt\":\"Red square\",\"rows\":3}}\n",
        "7fa54a42524916a1648ec76ce75d295024840b7a3a4f4bbaf3e43155d0014767",
        hex::encode(f.treaty.source_hosts[0])
    );
    let source = Reference::for_bytes(Class::PageSource, body.as_bytes()).unwrap();
    let page_id = page::page_id(&raw).unwrap();
    let author = page::objects::Author::parse(
        &source_signed(
            f,
            "PageAuthorStatement",
            page_id,
            number,
            wire::decode(
                &page::objects::Author::parameters(raw, "Books", &source, &f.grant, None, 20000)
                    .unwrap(),
            )
            .unwrap(),
        ),
        f.treaty.source.network,
        f.treaty.source.incarnation,
    )
    .unwrap();
    let metadata = page::Revision::from_source(author.clone(), body.as_bytes()).unwrap();
    let mut state = State::empty(f.treaty.source.network, f.treaty.source.incarnation);
    let native = insert(
        &mut state,
        141,
        metadata.identity().unwrap(),
        metadata.value(),
    );
    let reviewer = page::objects::Reviewer::parse(
        &source_signed(
            f,
            "PageReviewStatement",
            page_id,
            number,
            wire::decode(
                &page::objects::Reviewer::parameters(
                    &native.reference,
                    &source,
                    author.intent.requester,
                    author.intent.digest,
                    &f.grant,
                    None,
                    true,
                    0,
                    None,
                    20000,
                )
                .unwrap(),
            )
            .unwrap(),
        ),
        state.network,
        state.incarnation,
    )
    .unwrap();
    let bundle_bytes =
        page::objects::Bundle::encode(body.as_bytes(), &author.bytes, &reviewer.bytes).unwrap();
    let bundle = Reference::for_bytes(Class::PageBundle, &bundle_bytes).unwrap();
    let review = insert(
        &mut state,
        142,
        native.reference.id,
        page::Review {
            statement: reviewer,
            bundle: Some(bundle.clone()),
            recorded_ms: 5000,
        }
        .value(),
    );
    for generation in 1..=number {
        insert(
            &mut state,
            140,
            page_id,
            page::Ledger {
                raw_page: raw,
                author: author.intent.requester,
                namespace: "Books".into(),
                last_revision: generation,
                pending: None,
                published: Some(review.reference.clone()),
            }
            .value(),
        );
    }
    let mut share = Share {
        agreement: f.treaty.id,
        page: raw,
        publication: review.reference,
        revision: native.reference,
        author: author.intent.requester,
        grant: f.grant.clone(),
        statement: vec![],
        allowed: true,
        withdrawal_generation: 0,
    };
    share.statement = source_signed(
        f,
        "FederationShareStatement",
        share.identity().unwrap(),
        1,
        share.statement_value(),
    );
    insert(&mut state, 153, share.identity().unwrap(), share.value());
    let operation = Operation {
        command: admission(f, Some(raw)).into(),
        grant: None,
        snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let signed = deployment::signed(
        &deployment::key(106),
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    );
    let trust = f
        .state
        .records
        .values()
        .find(|r| r.reference.kind == 150)
        .unwrap()
        .reference
        .clone();
    let proof = ForeignProof {
        trust: trust.clone(),
        floor: f.state.record(157, trust.id).unwrap().reference.clone(),
        anchor: vec![],
        ordered: wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            f.local.scope.value(),
            b(&signed),
            V::Null,
            V::Uint(20000),
        ]))
        .unwrap(),
        result: vec![],
        certificate: vec![],
        ancestry: vec![],
        checkpoint: None,
        history: None,
        predecessors: vec![],
        bytes: vec![],
    };
    let object = Object::verify(bundle.clone(), bundle_bytes).unwrap();
    (
        VerifiedForeign {
            command: Command::Export {
                agreement: f.state.record(151, f.treaty.id).unwrap().reference.clone(),
                bridge: f
                    .state
                    .record(152, f.treaty.destination_bridge)
                    .unwrap()
                    .reference
                    .clone(),
                admission: proof,
                include_bundle: true,
                inventory: None,
            },
            state,
            floor: ForeignFloor::initial(trust.id),
            expires_ms: 20000,
            digest: [192; 32],
            cursor: None,
        },
        Resolved::exact(std::slice::from_ref(&bundle), vec![object]).unwrap(),
    )
}

fn import_cached(
    f: &SourceFixture,
    state: &State,
    records: &[Vec<u8>],
    intent: &Intent,
    proof: &VerifiedForeign,
    objects: &Resolved,
) -> Result<State> {
    let mut c = page::Evaluation {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        index: Index::parse(
            records,
            &f.local.reservations,
            state.network,
            state.incarnation,
        )?,
        at: 5000,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    let agreement = c.federation_agreement(&state.record(151, f.treaty.id)?.reference)?;
    let mut next = state.clone();
    import(
        &mut c,
        &mut next,
        &mut BTreeSet::new(),
        intent,
        &agreement,
        proof,
        &objects.references()[0],
        objects,
        false,
    )?;
    Ok(next)
}

#[test]
fn admission_context_supports_cold_import_and_preserves_repeated_import_state() {
    let mut f = destination();
    let raw = [193; 16];
    let (proof, objects) = exported_media(&f, raw, 1);
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
    let (minimal, minimal_records) = f.context(&get.value);
    assert!(!minimal.records.keys().any(|(kind, _)| *kind == 143));
    let (intent, operation, result) =
        f.evaluate(admission(&f, Some(raw)).into(), vec![], 106, None);
    assert_eq!(result.code, 0);
    assert!(import_cached(&f, &minimal, &minimal_records, &intent, &proof, &objects).is_err());
    let (cold, records) = f.context(&result.value);
    for kind in [143, 149, 150, 151, 152] {
        assert!(cold.records.keys().any(|(k, _)| *k == kind));
    }
    assert_eq!(
        operation
            .prepare(
                &cold,
                &records,
                &f.local.reservations,
                &intent,
                5000,
                false,
                true
            )
            .unwrap()
            .value,
        result.value
    );
    let checked = f.verify_context(&minimal, &intent, &result).unwrap();
    assert_eq!(checked.value, result.value);
    let cold = checked.state;
    f.state = import_cached(&f, &cold, &records, &intent, &proof, &objects).unwrap();
    let id = qualified_page(f.treaty.id, &f.treaty.source, raw).unwrap();
    let mut head = ForeignPage::parse(&f.state.record(154, id).unwrap().payload).unwrap();
    let asset = f
        .state
        .records
        .values()
        .find(|r| r.reference.kind == 144)
        .unwrap()
        .clone();
    let original = asset.reference.clone();
    let revision = page::Asset::parse(&asset.payload).unwrap().revision;
    insert(
        &mut f.state,
        145,
        asset.reference.id,
        page::Evidence {
            asset: asset.reference,
            copies: vec![],
            inspections: vec![],
        }
        .value(),
    );
    let mut review = ForeignReview {
        revision,
        reviewer: deployment::key(5).verifying_key().to_bytes(),
        grant: f.grant.clone(),
        application: None,
        mode: 0,
        policy: None,
        approve: true,
        statement: vec![],
        decided_at_ms: 5000,
    };
    review.statement = deployment::signed(
        &deployment::key(5),
        "FederationReviewStatement",
        review.revision.id,
        1,
        review.statement_value(),
        vec![],
    );
    let published = insert(&mut f.state, 156, review.revision.id, review.value()).reference;
    head.pending = None;
    head.published = Some(published.clone());
    head.withdrawn = true;
    insert(&mut f.state, 154, id, head.value());
    let (intent, _, result) = f.evaluate(admission(&f, Some(raw)).into(), vec![], 106, None);
    assert_eq!(result.code, 0);
    let (cold, records) = f.context(&result.value);
    for kind in [144, 145, 154, 155] {
        assert!(cold.records.keys().any(|(k, _)| *k == kind));
    }
    assert!(!cold.records.keys().any(|(kind, _)| *kind == 156));
    assert_eq!(
        f.verify_context(&minimal, &intent, &result).unwrap().value,
        result.value
    );
    let repeated = import_cached(&f, &cold, &records, &intent, &proof, &objects).unwrap();
    let head = ForeignPage::parse(&repeated.record(154, id).unwrap().payload).unwrap();
    assert!(head.pending.is_none() && head.withdrawn);
    assert_eq!(head.published, Some(published));
    assert_eq!(
        repeated.record(144, original.id).unwrap().reference,
        original
    );
    assert_eq!(
        repeated.record(145, original.id).unwrap().reference,
        cold.record(145, original.id).unwrap().reference
    );
    let (next, objects) = exported_media(&f, raw, 2);
    let updated = import_cached(&f, &cold, &records, &intent, &next, &objects).unwrap();
    let head = ForeignPage::parse(&updated.record(154, id).unwrap().payload).unwrap();
    assert!(head.pending.is_some() && head.withdrawn);
    assert!(head.published.is_none());
    assert_ne!(
        head.observed,
        ForeignPage::parse(&cold.record(154, id).unwrap().payload)
            .unwrap()
            .observed
    );
}

#[test]
fn admission_context_requires_exact_bridge_and_live_destination_host_consent() {
    let mut f = destination();
    let command = admission(&f, Some([193; 16]));
    for (signer, grant) in [(5, None), (106, Some(f.grant.clone()))] {
        assert_eq!(
            f.evaluate(command.clone().into(), vec![], signer, grant)
                .2
                .code,
            3
        );
    }
    let inventory = f.evaluate(admission(&f, None).into(), vec![], 106, None).2;
    assert_eq!(inventory.code, 0);
    assert!(
        !f.context(&inventory.value)
            .0
            .records
            .keys()
            .any(|(kind, _)| matches!(kind, 143 | 144 | 149 | 154 | 155))
    );
    let id = f.treaty.destination_hosts[0];
    let mut host = page::Host::parse(
        &f.state.record(143, id).unwrap().payload,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    host.withdrawn = true;
    insert(&mut f.state, 143, id, host.value());
    assert_eq!(f.evaluate(command.into(), vec![], 106, None).2.code, 3);
}
