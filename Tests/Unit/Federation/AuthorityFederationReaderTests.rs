// SPDX-License-Identifier: MIT
// Certified Page context supplies the exact metadata needed by independent reviewer and reader caches.
use super::*;

fn evaluation<'a>(
    f: &SourceFixture,
    state: &'a State,
    records: &[Vec<u8>],
) -> page::Evaluation<'a> {
    page::Evaluation {
        state,
        governance: Governance::parse(state.network, state.incarnation, records).unwrap(),
        index: Index::parse(
            records,
            &f.local.reservations,
            state.network,
            state.incarnation,
        )
        .unwrap(),
        at: 5000,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    }
}

fn certified_context(f: &SourceFixture, raw: [u8; 16], action: u64) -> (State, Vec<Vec<u8>>, u64) {
    let (intent, operation, decision) = f.evaluate(
        Command::PageContext {
            agreement: f.treaty.id,
            page: raw,
            action,
        }
        .into(),
        vec![],
        5,
        Some(f.grant.clone()),
    );
    assert_eq!(decision.code, 0);
    let (state, records) = f.context(&decision.value);
    let checked = operation
        .prepare(
            &state,
            &records,
            &f.local.reservations,
            &intent,
            5000,
            false,
            true,
        )
        .unwrap();
    assert_eq!(checked.value, decision.value);
    let empty = State::empty(state.network, state.incarnation);
    assert_eq!(
        f.verify_context(&empty, &intent, &decision).unwrap().value,
        decision.value
    );
    (state, records, decision.expires_ms)
}

fn imported() -> (SourceFixture, [u8; 16], VersionRef, ForeignReview) {
    let mut f = destination();
    let raw = [194; 16];
    // A distinct host grant must be returned even when the participant already knows its own grant.
    let g = Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let mut fields = wire::decode(g.record_bytes(102, f.grant.id).unwrap())
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    fields[6] = b(&[195; 32]);
    fields[10] = a(vec![V::Uint(5), V::Uint(26)]);
    fields[13] = reference(&f.grant);
    fields[14] = V::Uint(0);
    fields[16] = deployment::snapshot(&[]);
    let bytes = wire::encode(&a(fields)).unwrap();
    let host_grant = crate::authority_applications::record_reference(&bytes).unwrap();
    f.records.push(bytes);
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let host = f.treaty.destination_hosts[0];
    let configured = page::Host::parse(
        &f.state.record(143, host).unwrap().payload,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    f.state.records.remove(&(143, host)).unwrap();
    f.apply(
        page::Command::HostRegister {
            profile: Box::new(configured.profile),
        }
        .into(),
        vec![],
        5,
        Some(host_grant),
    );
    let host = f.state.record(143, host).unwrap().reference.clone();
    let (export, objects) = exported_media(&f, raw, 1);
    let (intent, _, admitted) = f.evaluate(admission(&f, Some(raw)).into(), vec![], 106, None);
    assert_eq!(admitted.code, 0);
    f.state = import_cached(&f, &f.state, &f.records, &intent, &export, &objects).unwrap();
    let asset = f
        .state
        .records
        .values()
        .find(|r| r.reference.kind == 144)
        .unwrap()
        .clone();
    let value = page::Asset::parse(&asset.payload).unwrap();
    let mut receipt = page::CopyReceipt {
        asset: asset.reference.clone(),
        host,
        request: [196; 32],
        digest: hex::decode(&value.manifest.digest)
            .unwrap()
            .try_into()
            .unwrap(),
        bytes: value.manifest.bytes,
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
        page::CopyReceipt::parse(&receipt.envelope, f.state.network, f.state.incarnation).unwrap();
    insert(
        &mut f.state,
        145,
        asset.reference.id,
        page::Evidence {
            asset: asset.reference.clone(),
            copies: vec![receipt],
            inspections: vec![],
        }
        .value(),
    );
    let mut review = ForeignReview {
        revision: value.revision,
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
        0,
        review.statement_value(),
        vec![],
    );
    (f, raw, asset.reference, review)
}

#[test]
fn page_context_hydrates_cold_reviewer_media_approval_and_reader_dependencies() {
    let (mut f, raw, asset, review) = imported();
    let (cold, records, _) = certified_context(&f, raw, 3);
    for kind in [143, 144, 145, 149, 150, 151, 154, 155, 157] {
        assert!(cold.records.keys().any(|(k, _)| *k == kind));
    }
    let g = Governance::parse(cold.network, cold.incarnation, &records).unwrap();
    assert!(g.record_bytes(102, [195; 32]).is_ok());
    assert!(g.record_bytes(102, [24; 32]).is_ok());
    let value =
        ForeignRevision::parse(&cold.record(155, review.revision.id).unwrap().payload).unwrap();
    let media = page::Asset::parse(&cold.record(144, asset.id).unwrap().payload).unwrap();
    let mut c = evaluation(&f, &cold, &records);
    // Page inspection and media inspection authorization need no prior per-asset client cache.
    c.federation_principal(
        review.reviewer,
        &review.grant,
        None,
        3,
        &f.treaty,
        value.page,
        raw,
        media.manifest.bytes,
        true,
    )
    .unwrap();
    c.application(
        review.reviewer,
        &review.grant,
        None,
        "MediaInspect",
        &f.treaty.destination_namespace,
        Some(raw),
    )
    .unwrap();
    c.federation_media(&review.revision, &value, &f.treaty, None)
        .unwrap();
    c.host(&media.hosts[0], Some(&f.treaty.destination_namespace), true)
        .unwrap();
    assert!(
        c.federation_media(&review.revision, &value, &f.treaty, Some(&review))
            .is_err(),
        "copy receipt must not replace reviewer inspection"
    );
    let mut evidence = page::Evidence::parse(
        &f.state.record(145, asset.id).unwrap().payload,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    evidence.inspections.push(page::Inspection {
        reviewer: review.reviewer,
        grant: review.grant.clone(),
        application: None,
        intent: [197; 32],
        expires_ms: 12000,
    });
    insert(&mut f.state, 145, asset.id, evidence.value());
    let (cold, records, _) = certified_context(&f, raw, 3);
    let mut c = evaluation(&f, &cold, &records);
    c.federation_media(&review.revision, &value, &f.treaty, Some(&review))
        .unwrap();
    // Commit the already checked decision, then recreate a reader from its PageContext alone.
    let published = insert(&mut f.state, 156, review.revision.id, review.value()).reference;
    let mut head = ForeignPage::parse(&f.state.record(154, value.page).unwrap().payload).unwrap();
    head.published = Some(published.clone());
    head.pending = None;
    insert(&mut f.state, 154, value.page, head.value());
    let (cold, records, _) = certified_context(&f, raw, 0);
    assert_eq!(cold.record(156, published.id).unwrap().reference, published);
    let mut c = evaluation(&f, &cold, &records);
    current_review(&mut c, &head, &f.treaty, &value).unwrap();
    c.federation_principal(
        review.reviewer,
        &review.grant,
        None,
        0,
        &f.treaty,
        value.page,
        raw,
        media.manifest.bytes,
        true,
    )
    .unwrap();
    c.application(
        review.reviewer,
        &review.grant,
        None,
        "MediaRead",
        &f.treaty.destination_namespace,
        Some(raw),
    )
    .unwrap();
    c.federation_media(&review.revision, &value, &f.treaty, None)
        .unwrap();
    c.host(&media.hosts[0], Some(&f.treaty.destination_namespace), true)
        .unwrap();
    // Placement remains a current policy dependency rather than a cache default of one copy.
    let id = page::namespace_id(&f.treaty.destination_namespace).unwrap();
    let mut policy =
        page::PlacementPolicy::parse(&f.state.record(149, id).unwrap().payload).unwrap();
    policy.minimum_copies = 2;
    insert(&mut f.state, 149, id, policy.value());
    let (cold, records, _) = certified_context(&f, raw, 0);
    assert!(
        evaluation(&f, &cold, &records)
            .federation_media(&review.revision, &value, &f.treaty, Some(&review))
            .is_err()
    );
}

#[test]
fn page_context_retains_withdrawn_host_metadata_without_restoring_live_authority() {
    let (mut f, raw, asset, review) = imported();
    let id = f.treaty.destination_hosts[0];
    let mut host = page::Host::parse(
        &f.state.record(143, id).unwrap().payload,
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    host.withdrawn = true;
    insert(&mut f.state, 143, id, host.value());
    let (cold, records, expires) = certified_context(&f, raw, 3);
    let current = &cold.record(143, id).unwrap().reference;
    let mut c = evaluation(&f, &cold, &records);
    let value =
        ForeignRevision::parse(&cold.record(155, review.revision.id).unwrap().payload).unwrap();
    c.federation_media(&review.revision, &value, &f.treaty, None)
        .unwrap();
    assert!(
        c.host(current, Some(&f.treaty.destination_namespace), true)
            .is_err()
    );
    assert!(cold.records.contains_key(&(144, asset.id)));
    assert!(
        Governance::parse(cold.network, cold.incarnation, &records)
            .unwrap()
            .record_bytes(102, [195; 32])
            .is_err()
    );
    let mut c = evaluation(&f, &cold, &records);
    c.federation_media(&review.revision, &value, &f.treaty, None)
        .unwrap();
    c.minimum_copies(&f.treaty.destination_namespace).unwrap();
    let prior = (c.dependencies.clone(), c.selected.len(), c.expires);
    assert!(
        c.optional(|c| c.host(current, Some(&f.treaty.destination_namespace), true))
            .is_none()
    );
    assert_eq!((c.dependencies, c.selected.len(), c.expires), prior);
    assert_eq!(expires, f.treaty.expires_ms);
}
