// SPDX-License-Identifier: MIT
// Admission regressions exercise bounded reuse, candidate consent and exact restricted authority.
use super::*;
use crate::{
    authority_deployment_tests as support, authority_membership::Reservations,
    authority_proof::Intent,
};
use ed25519_dalek::SigningKey;
const N: Digest = [20; 32];
const I: Digest = [21; 32];
const P: Digest = [201; 32];
const AT: u64 = 5000;
pub(crate) fn signer(id: u64) -> SigningKey {
    SigningKey::from_bytes(&wire::digest(&id.to_be_bytes()))
}
pub(crate) fn snapshot(records: &[Vec<u8>], old: Option<&Slot>) -> Snapshot {
    let g = Governance::parse(N, I, records).unwrap();
    let root = g
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    let mut refs = g
        .current_capability(
            root.id,
            &Requirement {
                subject: support::key(5).verifying_key().to_bytes(),
                actions: &[0, 10, 11, 30],
                scope: (0, N),
                namespace: None,
                usage: [0; 4],
                evaluated_at_ms: AT,
                expected: &[],
            },
        )
        .unwrap()
        .dependencies;
    if let Some(p) = g.admission().policies.get(&P) {
        refs.push(p.reference.clone());
    }
    if let Some(s) = old {
        refs.push(s.reference.clone());
        refs.extend(Governance::record_versions(N, I, &s.material).unwrap());
    }
    refs.sort_by_key(VersionRef::index);
    refs.dedup();
    Snapshot::parse(&a(vec![
        a(vec![V::Uint(0), V::Uint(0), b(&[99; 32])]),
        a(refs.iter().map(reference).collect()),
    ]))
    .unwrap()
}
pub(crate) fn record(
    kind: u64,
    id: Digest,
    payload: V,
    snapshot: &Snapshot,
    old: Option<&[u8]>,
) -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(kind),
        V::Uint(1),
        b(&N),
        b(&I),
        V::Uint(old.map_or(1, |old| record_reference(old, N, I).unwrap().generation + 1)),
        old.map_or(V::Null, |old| b(&wire::digest(old))),
        b(&id),
        payload,
        snapshot.value.clone(),
    ]))
    .unwrap()
}
fn intent(op: &Operation, key: &SigningKey) -> Intent {
    intent_with_expected(op, key, op.snapshot.references.clone())
}
fn intent_with_expected(op: &Operation, key: &SigningKey, expected: Vec<VersionRef>) -> Intent {
    let r = record_reference(&op.next, N, I).unwrap();
    let signed = support::signed(
        key,
        "AuthorityAdmission",
        r.id,
        r.generation,
        wire::decode(&op.parameters().unwrap()).unwrap(),
        expected,
    );
    let intent = Intent::from_signed(&signed).unwrap();
    Operation::parse(&intent).unwrap();
    intent
}
pub(crate) fn fixture() -> (Vec<Vec<u8>>, Reservations, Policy) {
    fixture_with(
        support::Fixture::with_actions(vec![0, 10, 11, 12, 13, 26, 30]),
        800000.into(),
    )
}
fn fixture_with(
    f: support::Fixture,
    end: crate::trust_validity::End,
) -> (Vec<Vec<u8>>, Reservations, Policy) {
    let snap = snapshot(&f.records, None);
    let root = Governance::parse(N, I, &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    let templates = [
        Template {
            role: 0,
            destination: [204; 32],
            application: None,
            page: None,
            limits: [65536, 64, 8, 8],
            connections: 16,
            bytes: 65536,
            voucher_ms: 120000,
        },
        Template {
            role: 1,
            destination: [205; 32],
            application: Some([206; 32]),
            page: None,
            limits: [65536, 64, 8, 8],
            connections: 16,
            bytes: 65536,
            voucher_ms: 120000,
        },
    ];
    let bytes = record(
        POLICY,
        P,
        a(vec![
            b(&support::key(5).verifying_key().to_bytes()),
            reference(&root),
            b(&signer(100).verifying_key().to_bytes()),
            b(&signer(101).verifying_key().to_bytes()),
            V::Bool(true),
            V::Uint(64),
            Validity(1000, end).value(),
            b(&[202; 32]),
            b(&[203; 32]),
            a(templates.iter().map(Template::value).collect()),
            a(vec![]),
        ]),
        &snap,
        None,
    );
    let op = Operation {
        transition: Transition::Policy,
        policy: bytes.clone(),
        previous: None,
        next: bytes.clone(),
        acceptance: vec![],
        legacy: vec![],
        snapshot: snap,
    };
    let result = op
        .authorise(
            &f.records,
            &f.reservations,
            &intent(&op, &support::key(5)),
            AT,
            false,
        )
        .unwrap();
    (
        result.records,
        f.reservations,
        Policy::parse(&bytes, N, I).unwrap(),
    )
}
fn role(role: u64, key: &SigningKey, relay: &SigningKey) -> Role {
    let member = key.verifying_key().to_bytes();
    let relay = relay.verifying_key().to_bytes();
    let payload = wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetJoinRequest".into()),
        b(&N),
        b(&I),
        b(&[90; 32]),
        b(&member),
        b(&member),
        b(&relay),
        V::Uint(1),
    ]))
    .unwrap();
    Role {
        role,
        member,
        relay,
        request: wire::sign_envelope(&payload, key).unwrap(),
    }
}
pub(crate) fn reserve(
    records: &[Vec<u8>],
    p: &Policy,
    slot: u64,
    ordinal: u64,
    old: Option<&Slot>,
    keys: &[(SigningKey, SigningKey)],
) -> Operation {
    let snap = snapshot(records, old);
    let mut claim = [7; 32];
    claim[..8].copy_from_slice(&ordinal.to_be_bytes());
    let roles = keys
        .iter()
        .enumerate()
        .map(|(index, (key, relay))| role(index as u64, key, relay))
        .collect::<Vec<_>>();
    let payload = a(vec![
        b(&P),
        V::Uint(slot),
        V::Uint(old.map_or(1, |s| s.assignment + 1)),
        b(&claim),
        b(&[91; 32]),
        b(&[92; 32]),
        V::Uint(0),
        V::Uint(AT + CHALLENGE_MS),
        a(roles.iter().map(Role::value).collect()),
        b(&wire::digest(&ordinal.to_be_bytes())),
        V::Uint(1),
        a(old.map_or(vec![], |s| s.material.iter().map(|v| b(v)).collect())),
        a(vec![]),
    ]);
    let next = record(
        SLOT,
        identifier(P, slot, 0, 0).unwrap(),
        payload,
        &snap,
        old.map(|s| s.bytes.as_slice()),
    );
    Operation {
        transition: Transition::Reserve,
        policy: p.bytes.clone(),
        previous: old.map(|s| s.bytes.clone()),
        next,
        acceptance: vec![],
        legacy: vec![],
        snapshot: snap,
    }
}
fn apply(records: &mut Vec<Vec<u8>>, reserved: &Reservations, op: &Operation) -> Slot {
    *records = op
        .authorise(records, reserved, &intent(op, &signer(100)), AT, false)
        .unwrap()
        .records;
    Slot::parse(&op.next, N, I).unwrap()
}
fn enrol(
    records: &[Vec<u8>],
    p: &Policy,
    old: &Slot,
    keys: &[(SigningKey, SigningKey)],
) -> Operation {
    let snap = snapshot(records, Some(old));
    enrol_with_snapshot(records, p, old, keys, snap)
}
pub(crate) fn enrol_with_snapshot(
    records: &[Vec<u8>],
    p: &Policy,
    old: &Slot,
    keys: &[(SigningKey, SigningKey)],
    snap: Snapshot,
) -> Operation {
    let g = Governance::parse(N, I, records).unwrap();
    let parent = wire::decode(g.record_bytes(102, p.parent.id).unwrap()).unwrap();
    let tier = crate::authority_membership::version(&parent.array(17).unwrap()[9]).unwrap();
    let mut next = old.clone();
    next.state = 1;
    next.challenge_until = 0;
    next.material = enrol_material(p, old, &tier, &snap, N, I).unwrap();
    let next = record(
        SLOT,
        old.reference.id,
        next.payload(),
        &snap,
        Some(&old.bytes),
    );
    Operation {
        transition: Transition::Enrol,
        policy: p.bytes.clone(),
        previous: Some(old.bytes.clone()),
        next,
        acceptance: keys
            .iter()
            .map(|(key, _)| {
                wire::sign_envelope(&old.acceptance_payload(N, I).unwrap(), key).unwrap()
            })
            .collect(),
        legacy: vec![],
        snapshot: snap,
    }
}
pub(crate) fn retire(records: &[Vec<u8>], p: &Policy, old: &Slot) -> Operation {
    let snap = snapshot(records, Some(old));
    let mut next = old.clone();
    next.state = 3;
    next.challenge_until = 0;
    let next = record(
        SLOT,
        old.reference.id,
        next.payload(),
        &snap,
        Some(&old.bytes),
    );
    Operation {
        transition: Transition::Retire,
        policy: p.bytes.clone(),
        previous: Some(old.bytes.clone()),
        next,
        acceptance: vec![],
        legacy: vec![],
        snapshot: snap,
    }
}
#[test]
fn reused_slot_enrolment_requires_each_exact_signed_material_predecessor() {
    let (mut records, reserved, p) = fixture();
    let keys = [(signer(200), signer(201)), (signer(202), signer(203))];
    let operation = reserve(&records, &p, 0, 1, None, &keys);
    let pending = apply(&mut records, &reserved, &operation);
    let operation = enrol(&records, &p, &pending, &keys);
    let active = apply(&mut records, &reserved, &operation);
    let operation = retire(&records, &p, &active);
    let retired = apply(&mut records, &reserved, &operation);
    let operation = reserve(&records, &p, 0, 2, Some(&retired), &keys);
    let pending = apply(&mut records, &reserved, &operation);
    let operation = enrol(&records, &p, &pending, &keys);
    let predecessors = operation
        .updates(N, I)
        .unwrap()
        .into_iter()
        .map(|(old, _)| old)
        .filter(|old| old.kind != SLOT)
        .collect::<Vec<_>>();
    assert_eq!(predecessors.iter().filter(|r| r.kind == 102).count(), 5);
    assert_eq!(predecessors.iter().filter(|r| r.kind == 125).count(), 2);
    for old in &predecessors {
        let mut missing = operation.snapshot.references.clone();
        missing.retain(|r| r != old);
        let request = intent_with_expected(&operation, &signer(100), missing);
        assert!(
            operation
                .authorise(&records, &reserved, &request, AT, false)
                .err()
                .unwrap()
                .to_string()
                .contains("exact signed predecessor")
        );
        let mut changed = operation.snapshot.references.clone();
        let reference = changed
            .iter_mut()
            .find(|r| r.index() == old.index())
            .unwrap();
        reference.digest = [255; 32];
        let request = intent_with_expected(&operation, &signer(100), changed);
        assert!(
            operation
                .authorise(&records, &reserved, &request, AT, false)
                .err()
                .unwrap()
                .to_string()
                .contains("exact signed predecessor")
        );
    }
    // A fully signed list cannot repair a snapshot that omitted the material.
    let mut omitted = operation.snapshot.value.array(2).unwrap().to_vec();
    omitted[1] = a(operation
        .snapshot
        .references
        .iter()
        .filter(|r| !predecessors.contains(r))
        .map(reference)
        .collect());
    let omitted = Snapshot::parse(&a(omitted)).unwrap();
    let missing = enrol_with_snapshot(&records, &p, &pending, &keys, omitted);
    for request in [
        intent(&missing, &signer(100)),
        intent_with_expected(
            &missing,
            &signer(100),
            operation.snapshot.references.clone(),
        ),
    ] {
        assert!(
            missing
                .authorise(&records, &reserved, &request, AT, false)
                .err()
                .unwrap()
                .to_string()
                .contains("exact signed predecessor")
        );
    }
    let request = intent(&operation, &signer(100));
    let outcome = operation
        .authorise(&records, &reserved, &request, AT, false)
        .unwrap();
    assert!(
        predecessors
            .iter()
            .all(|old| outcome.dependencies.contains(old))
    );
    operation
        .authorise(&outcome.records, &reserved, &request, AT, true)
        .unwrap();
}
#[test]
fn restricted_slots_reuse_capacity_without_reviving_old_claims_or_keys() {
    let (mut records, reserved, p) = fixture();
    let keys = [(signer(200), signer(201)), (signer(202), signer(203))];
    let mut previous = None;
    let mut old_enrol: Option<Operation> = None;
    let mut size = None;
    for ordinal in 1..=70 {
        let op = reserve(&records, &p, 0, ordinal, previous.as_ref(), &keys);
        let pending = apply(&mut records, &reserved, &op);
        if let Some(op) = &old_enrol {
            assert!(
                op.authorise(&records, &reserved, &intent(op, &signer(100)), AT, false)
                    .is_err()
            );
        }
        let op = enrol(&records, &p, &pending, &keys);
        let active = apply(&mut records, &reserved, &op);
        old_enrol = Some(op);
        let g = Governance::parse(N, I, &records).unwrap();
        let reader = identifier(P, 0, 0, 1).unwrap();
        let member = keys[0].0.verifying_key().to_bytes();
        assert!(
            g.current_capability(
                reader,
                &Requirement {
                    subject: member,
                    actions: &[0],
                    scope: (0, N),
                    namespace: None,
                    usage: [0; 4],
                    evaluated_at_ms: AT,
                    expected: &[]
                }
            )
            .is_ok()
        );
        assert!(
            g.current_capability(
                reader,
                &Requirement {
                    subject: member,
                    actions: &[11],
                    scope: (0, N),
                    namespace: None,
                    usage: [0; 4],
                    evaluated_at_ms: AT,
                    expected: &[]
                }
            )
            .is_err()
        );
        let oldclaim = reserve(
            &records,
            &p,
            1,
            ordinal,
            None,
            &[(signer(300 + ordinal * 2), signer(301 + ordinal * 2))],
        );
        assert!(
            oldclaim
                .authorise(
                    &records,
                    &reserved,
                    &intent(&oldclaim, &signer(100)),
                    AT,
                    false
                )
                .is_err()
        );
        let op = retire(&records, &p, &active);
        let retired = apply(&mut records, &reserved, &op);
        assert!(
            Governance::parse(N, I, &records)
                .unwrap()
                .current_capability(
                    reader,
                    &Requirement {
                        subject: member,
                        actions: &[0],
                        scope: (0, N),
                        namespace: None,
                        usage: [0; 4],
                        evaluated_at_ms: AT,
                        expected: &[]
                    }
                )
                .is_err()
        );
        assert_eq!(records.len(), *size.get_or_insert(records.len()));
        previous = Some(retired);
    }
}
#[test]
fn full_participant_capacity_is_bounded_and_all_role_keys_require_consent() {
    let (mut records, reserved, p) = fixture();
    for slot in 0..64 {
        let keys = [
            (signer(1000 + slot * 4), signer(1001 + slot * 4)),
            (signer(1002 + slot * 4), signer(1003 + slot * 4)),
        ];
        let reservation = reserve(&records, &p, slot, slot + 1, None, &keys);
        let pending = apply(&mut records, &reserved, &reservation);
        let op = enrol(&records, &p, &pending, &keys);
        if slot == 0 {
            let mut wrong = op.clone();
            wrong.acceptance.pop();
            assert!(
                Operation::parse(&Intent {
                    parameters: wrong.parameters().unwrap(),
                    ..intent(&op, &signer(100))
                })
                .is_err()
            );
        }
        apply(&mut records, &reserved, &op);
    }
    let index = Index::parse(&records, N, I).unwrap();
    assert_eq!(index.slots.len(), 64);
    assert_eq!(index.requester_keys().len(), 129);
    assert!(records.len() < 520);
    assert!(records.iter().map(Vec::len).sum::<usize>() < 1024 * 1024);
    let mut bad = p.clone();
    bad.maximum_slots = 65;
    assert!(
        Policy::parse(
            &record(POLICY, P, bad.payload(), &snapshot(&records, None), None),
            N,
            I
        )
        .is_err()
    );
}

#[test]
fn explicit_manual_adoption_preserves_only_the_first_stream_origin() {
    let (mut records, reserved, mut p) = fixture();
    records.retain(|bytes| record_reference(bytes, N, I).is_err());
    let keys = [(signer(800), signer(801)), (signer(802), signer(803))];
    let unrelated = (signer(804), signer(805));
    let g = Governance::parse(N, I, &records).unwrap();
    let root = g.record_bytes(102, p.parent.id).unwrap();
    let snap = snapshot(&records, None);
    let mut manual = vec![];
    for (index, (key, _)) in keys.iter().chain(std::iter::once(&unrelated)).enumerate() {
        let member = key.verifying_key().to_bytes();
        let mut fields = wire::decode(root).unwrap().array(17).unwrap().to_vec();
        fields[6] = b(&[230 + index as u8; 32]);
        fields[8] = b(&member);
        fields[10] = a(vec![V::Uint(0)]);
        fields[13] = reference(&p.parent);
        fields[14] = V::Uint(0);
        fields[16] = snap.value.clone();
        let reader = wire::encode(&a(fields)).unwrap();
        let reader_ref = Governance::record_versions(N, I, std::slice::from_ref(&reader))
            .unwrap()
            .remove(0);
        manual.push(
            wire::encode(&a(vec![
                V::Uint(125),
                V::Uint(1),
                b(&N),
                b(&I),
                V::Uint(1),
                V::Null,
                b(&[232 + index as u8; 32]),
                b(&member),
                p.validity.value(),
                V::Bool(false),
                reference(&reader_ref),
                snap.value.clone(),
            ]))
            .unwrap(),
        );
        records.push(reader);
    }
    p.legacy = Governance::record_versions(N, I, &manual).unwrap();
    records.extend(manual.clone());
    p.bytes = record(POLICY, P, p.payload(), &snap, None);
    p = Policy::parse(&p.bytes, N, I).unwrap();
    records.push(p.bytes.clone());
    records.sort_by_key(|bytes| {
        Governance::record_versions(N, I, std::slice::from_ref(bytes)).unwrap()[0].index()
    });
    let cached_manual = records.clone();
    let op = reserve(&records, &p, 0, 1, None, &keys);
    let pending = apply(&mut records, &reserved, &op);
    let mut op = enrol(&records, &p, &pending, &keys);
    assert!(
        op.authorise(&records, &reserved, &intent(&op, &signer(100)), AT, false)
            .is_err()
    );
    op.transition = Transition::Adopt;
    op.legacy = manual[..keys.len()].to_vec();
    op.snapshot.references.extend(p.legacy.clone());
    op.snapshot.references.sort_by_key(VersionRef::index);
    let mut value = op.snapshot.value.array(2).unwrap().to_vec();
    value[1] = a(op.snapshot.references.iter().map(reference).collect());
    op.snapshot.value = a(value);
    let g = Governance::parse(N, I, &records).unwrap();
    let parent = wire::decode(g.record_bytes(102, p.parent.id).unwrap()).unwrap();
    let tier = crate::authority_membership::version(&parent.array(17).unwrap()[9]).unwrap();
    let mut active = Slot::parse(&op.next, N, I).unwrap();
    let mut legacy_streams = keys
        .iter()
        .map(|(key, _)| key.verifying_key().to_bytes())
        .collect::<Vec<_>>();
    legacy_streams.sort();
    active.legacy_streams = legacy_streams.clone();
    active.material = enrol_material(&p, &pending, &tier, &op.snapshot, N, I).unwrap();
    op.next = record(
        SLOT,
        pending.reference.id,
        active.payload(),
        &op.snapshot,
        Some(&pending.bytes),
    );
    let active = apply(&mut records, &reserved, &op);
    assert_eq!(active.legacy_streams, legacy_streams);
    assert_legacy_capability_closure(&records, &cached_manual, &p, &active);
    let op = retire(&records, &p, &active);
    let retired = apply(&mut records, &reserved, &op);
    let op = reserve(&records, &p, 0, 2, Some(&retired), &keys);
    let pending = apply(&mut records, &reserved, &op);
    let op = enrol(&records, &p, &pending, &keys);
    let active = apply(&mut records, &reserved, &op);
    assert!(active.legacy_streams.is_empty());
    assert_legacy_capability_closure(&records, &cached_manual, &p, &active);
}

fn assert_legacy_capability_closure(
    records: &[Vec<u8>],
    prior: &[Vec<u8>],
    policy: &Policy,
    slot: &Slot,
) {
    let governance = Governance::parse(N, I, records).unwrap();
    for role in &slot.roles {
        let request = Requirement {
            subject: role.member,
            actions: &[0],
            scope: (0, N),
            namespace: None,
            usage: [0; 4],
            evaluated_at_ms: AT,
            expected: &[],
        };
        let grant = identifier(policy.reference.id, slot.slot, role.role, 1).unwrap();
        let decision = governance.current_capability(grant, &request).unwrap();
        let returned = decision
            .dependencies
            .iter()
            .map(|r| governance.record_bytes(r.kind, r.id).unwrap().to_vec())
            .collect::<Vec<_>>();
        let minimal = Governance::parse(N, I, &returned)
            .unwrap()
            .current_capability(grant, &request)
            .unwrap();
        assert_eq!(minimal.dependencies, decision.dependencies);
        for old in &policy.legacy {
            let value = wire::decode(governance.record_bytes(125, old.id).unwrap()).unwrap();
            let fields = value.array(12).unwrap();
            if !slot
                .roles
                .iter()
                .any(|r| fields[7].fixed::<32>().unwrap() == r.member)
            {
                assert!(!fields[9].boolean().unwrap());
                assert!(
                    !decision
                        .dependencies
                        .iter()
                        .any(|r| r.index() == old.index())
                );
                continue;
            }
            let retired = decision
                .dependencies
                .iter()
                .find(|r| r.index() == old.index())
                .unwrap();
            assert_eq!(retired.generation, 2);
            assert!(fields[9].boolean().unwrap());
            let incomplete = returned
                .iter()
                .zip(&decision.dependencies)
                .filter(|(_, r)| *r != retired)
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>();
            let refs = Governance::record_versions(N, I, &incomplete).unwrap();
            let merged = crate::authority_domains::result::replace_governance(
                N,
                I,
                prior,
                &incomplete,
                &refs,
            )
            .unwrap();
            assert!(Governance::parse(N, I, &merged).is_err());
        }
        let merged = crate::authority_domains::result::replace_governance(
            N,
            I,
            prior,
            &returned,
            &decision.dependencies,
        )
        .unwrap();
        let independent = Governance::parse(N, I, &merged)
            .unwrap()
            .current_capability(grant, &request)
            .unwrap();
        assert_eq!(independent.dependencies, decision.dependencies);
    }
}

#[test]
fn revoked_parent_remains_inspectable_for_terminal_retirement() {
    let (mut records, reserved, p) = fixture();
    let keys = [(signer(900), signer(901))];
    let op = reserve(&records, &p, 0, 1, None, &keys);
    let pending = apply(&mut records, &reserved, &op);
    let op = enrol(&records, &p, &pending, &keys);
    let active = apply(&mut records, &reserved, &op);
    let snap = snapshot(&records, Some(&active));
    let revocation = wire::encode(&a(vec![
        V::Uint(126),
        V::Uint(1),
        b(&N),
        b(&I),
        V::Uint(1),
        V::Null,
        reference(&p.parent),
        b(&p.owner),
        snap.value.clone(),
    ]))
    .unwrap();
    records.push(revocation);
    records.sort_by_key(|bytes| {
        Governance::record_versions(N, I, std::slice::from_ref(bytes)).unwrap()[0].index()
    });
    assert!(
        p.authorise(&Governance::parse(N, I, &records).unwrap(), N, AT)
            .is_err()
    );
    let domains = crate::authority_domains::State::empty(N, I);
    let context = disclose(
        &records,
        &domains,
        &reserved,
        p.registrar,
        P,
        Some(active.claim),
        N,
        I,
        AT,
    )
    .unwrap();
    assert!(context.domains.is_empty());
    assert_eq!(context.selected.unwrap().claim, active.claim);
    let snapshot = Snapshot::parse(&a(vec![
        a(vec![V::Uint(0), V::Uint(0), b(&[99; 32])]),
        a(vec![reference(&p.reference), reference(&active.reference)]),
    ]))
    .unwrap();
    let mut next = active.clone();
    next.state = 3;
    next.challenge_until = 0;
    let op = Operation {
        transition: Transition::Retire,
        policy: p.bytes.clone(),
        previous: Some(active.bytes.clone()),
        next: record(
            SLOT,
            active.reference.id,
            next.payload(),
            &snapshot,
            Some(&active.bytes),
        ),
        acceptance: vec![],
        legacy: vec![],
        snapshot,
    };
    let retired = apply(&mut records, &reserved, &op);
    assert_eq!(retired.state, 3);
}

#[test]
fn permanent_native_membership_keeps_finite_candidate_challenges() {
    let (mut records, reserved, p) = fixture_with(
        support::Fixture::persistent_with_actions(vec![0, 10, 11, 12, 13, 26, 30]),
        crate::trust_validity::End::UntilWithdrawn,
    );
    let keys = [(signer(950), signer(951))];
    let op = reserve(&records, &p, 0, 1, None, &keys);
    let pending = apply(&mut records, &reserved, &op);
    assert_eq!(pending.challenge_until, AT + CHALLENGE_MS);
    let op = enrol(&records, &p, &pending, &keys);
    assert!(
        op.authorise(
            &records,
            &reserved,
            &intent(&op, &signer(100)),
            AT + CHALLENGE_MS,
            false
        )
        .is_err()
    );
    let active = apply(&mut records, &reserved, &op);
    let governance = Governance::parse(N, I, &records).unwrap();
    assert_eq!(
        governance
            .grant_validity(identifier(P, 0, 0, 1).unwrap())
            .unwrap()
            .1,
        crate::trust_validity::End::UntilWithdrawn
    );
    assert!(
        governance
            .current_capability(
                identifier(P, 0, 0, 1).unwrap(),
                &Requirement {
                    subject: keys[0].0.verifying_key().to_bytes(),
                    actions: &[0],
                    scope: (0, N),
                    namespace: None,
                    usage: [0; 4],
                    evaluated_at_ms: 9_000_000_000_000,
                    expected: &[]
                }
            )
            .is_ok()
    );
    let op = retire(&records, &p, &active);
    apply(&mut records, &reserved, &op);
    assert!(
        Governance::parse(N, I, &records)
            .unwrap()
            .current_capability(
                identifier(P, 0, 0, 1).unwrap(),
                &Requirement {
                    subject: keys[0].0.verifying_key().to_bytes(),
                    actions: &[0],
                    scope: (0, N),
                    namespace: None,
                    usage: [0; 4],
                    evaluated_at_ms: 9_000_000_000_000,
                    expected: &[]
                }
            )
            .is_err()
    );
}

// Shared native/route regression uses fully admitted services from the route fixture.
pub(crate) fn append_route_slot(
    records: &mut Vec<Vec<u8>>,
    reserved: &Reservations,
    relay: Digest,
    authority: Digest,
    destination: Digest,
) -> Slot {
    let (_, _, mut policy) = fixture();
    policy.parent = Governance::parse(N, I, records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [23; 32])
        .unwrap();
    policy.relay = relay;
    policy.authority = authority;
    for template in &mut policy.templates {
        template.destination = destination;
    }
    let snap = snapshot(records, None);
    policy.bytes = record(POLICY, P, policy.payload(), &snap, None);
    policy = Policy::parse(&policy.bytes, N, I).unwrap();
    let operation = Operation {
        transition: Transition::Policy,
        policy: policy.bytes.clone(),
        previous: None,
        next: policy.bytes.clone(),
        acceptance: vec![],
        legacy: vec![],
        snapshot: snap,
    };
    *records = operation
        .authorise(
            records,
            reserved,
            &intent(&operation, &support::key(5)),
            AT,
            false,
        )
        .unwrap()
        .records;
    let keys = [(signer(7000), signer(7001)), (signer(7002), signer(7003))];
    let pending = apply(
        records,
        reserved,
        &reserve(records, &policy, 0, 1, None, &keys),
    );
    apply(records, reserved, &enrol(records, &policy, &pending, &keys))
}
