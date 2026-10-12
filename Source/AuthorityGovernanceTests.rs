// SPDX-License-Identifier: MIT
use super::*;
#[test]
fn validity_and_limits_never_treat_zero_as_unlimited() {
    assert!(!conservative(1250, (1, 10000)));
    assert!(conservative(1251, (1, 10000)));
    assert!(!conservative(8750, (1, 10000)));
    assert!(!conservative(u64::MAX, (0, u64::MAX)));
    assert!(!within([1, 0, 0, 0], [0, 10, 10, 10]));
    assert!(within([0, 0, 0, 0], [0, 0, 0, 0]));
}
#[test]
fn scope_subset_does_not_infer_names_or_union_capabilities() {
    assert!(!scope_subset(&[(1, [3; 32])], &[(1, [4; 32])], [1; 32]));
    assert!(scope_subset(&[(1, [3; 32])], &[(0, [1; 32])], [1; 32]));
    assert!(!scope_subset(&[(1, [3; 32])], &[(0, [2; 32])], [1; 32]));
}
fn b(v: [u8; 32]) -> V {
    V::Bytes(v.to_vec())
}
fn list(v: Vec<V>) -> V {
    V::Array(v)
}
fn vr(kind: u64, id: [u8; 32], record: &[u8]) -> V {
    list(vec![
        V::Uint(kind),
        b(id),
        V::Uint(1),
        b(wire::digest(record)),
    ])
}
fn rec(kind: u64, body: Vec<V>) -> Vec<u8> {
    let mut value = vec![
        V::Uint(kind),
        V::Uint(1),
        b([1; 32]),
        b([2; 32]),
        V::Uint(1),
        V::Null,
    ];
    value.extend(body);
    wire::encode(&list(value)).unwrap()
}
fn fixture() -> (Vec<Vec<u8>>, Key, Key) {
    let root = ed25519_dalek::SigningKey::from_bytes(&[71; 32])
        .verifying_key()
        .to_bytes();
    let child = ed25519_dalek::SigningKey::from_bytes(&[72; 32])
        .verifying_key()
        .to_bytes();
    let recovery = ed25519_dalek::SigningKey::from_bytes(&[73; 32])
        .verifying_key()
        .to_bytes();
    let lim = list(vec![V::Uint(100); 4]);
    let scope = list(vec![list(vec![V::Uint(0), b([1; 32])])]);
    let actions = list(vec![V::Uint(0), V::Uint(11), V::Uint(25)]);
    let validity = list(vec![V::Uint(0), V::Uint(100000)]);
    let recovery_record = rec(
        114,
        vec![
            V::Uint(0),
            V::Uint(1),
            list(vec![b([6; 32])]),
            list(vec![list(vec![b([6; 32]), b(recovery)])]),
            V::Bool(false),
            list(vec![b([7; 32])]),
            V::Null,
        ],
    );
    let tier = rec(
        101,
        vec![
            b([3; 32]),
            V::Uint(0),
            V::Text("Reader".into()),
            actions.clone(),
            scope.clone(),
            V::Uint(2),
            lim.clone(),
            V::Null,
        ],
    );
    let root_grant = rec(
        102,
        vec![
            b([4; 32]),
            b(root),
            b(root),
            vr(101, [3; 32], &tier),
            actions,
            scope.clone(),
            validity.clone(),
            V::Null,
            V::Uint(2),
            lim.clone(),
            V::Null,
        ],
    );
    let child_grant = rec(
        102,
        vec![
            b([5; 32]),
            b(root),
            b(child),
            vr(101, [3; 32], &tier),
            list(vec![V::Uint(0)]),
            scope,
            validity.clone(),
            vr(102, [4; 32], &root_grant),
            V::Uint(0),
            lim.clone(),
            list(vec![
                list(vec![V::Uint(0), V::Uint(1), b([99; 32])]),
                list(vec![]),
            ]),
        ],
    );
    let expected = list(vec![
        list(vec![V::Uint(0), V::Uint(1), b([99; 32])]),
        list(vec![]),
    ]);
    let admission = rec(
        125,
        vec![
            b([8; 32]),
            b(child),
            validity,
            V::Bool(false),
            vr(102, [5; 32], &child_grant),
            expected,
        ],
    );
    let policy = rec(
        100,
        vec![
            V::Uint(0),
            V::Bool(false),
            V::Uint(1),
            list(vec![b([9; 32])]),
            list(vec![V::Uint(0)]),
            V::Uint(0),
            vr(114, [1; 32], &recovery_record),
            lim,
            V::Bool(true),
            list(vec![b([4; 32])]),
            V::Null,
        ],
    );
    (
        vec![
            policy,
            tier,
            root_grant,
            child_grant,
            recovery_record,
            admission,
        ],
        root,
        child,
    )
}
#[test]
fn complete_chain_binds_actions_current_parent_and_signed_dependencies() {
    let (records, root, child) = fixture();
    let governance = Governance::parse([1; 32], [2; 32], &records).unwrap();
    let expected = governance.versions();
    let mut request = Requirement {
        subject: root,
        actions: &[0],
        scope: (2, [88; 32]),
        namespace: None,
        usage: [1, 1, 0, 0],
        evaluated_at_ms: 5000,
        expected: &expected,
    };
    assert!(governance.capability([4; 32], &request).is_ok());
    request.actions = &[9];
    assert!(governance.capability([4; 32], &request).is_err());
    request.actions = &[0];
    request.subject = child;
    assert!(governance.capability([5; 32], &request).is_ok());
    request.actions = &[0, 25];
    assert!(governance.capability([5; 32], &request).is_err());
    request.actions = &[0];
    request.expected = &[];
    assert!(governance.capability([5; 32], &request).is_err());
    let mut changed = records.clone();
    let mut parent = wire::decode(&records[2])
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    parent[4] = V::Uint(2);
    parent[5] = b(wire::digest(&records[2]));
    parent[16] = list(vec![
        list(vec![V::Uint(0), V::Uint(1), b([99; 32])]),
        list(vec![]),
    ]);
    parent[10] = list(vec![]);
    parent[11] = list(vec![]);
    parent[14] = V::Uint(0);
    parent[15] = list(vec![V::Uint(0); 4]);
    changed[2] = wire::encode(&list(parent)).unwrap();
    let revoked = Governance::parse([1; 32], [2; 32], &changed).unwrap();
    let expected = revoked.versions();
    request.expected = &expected;
    assert!(revoked.capability([5; 32], &request).is_err());
}

fn expected_snapshot() -> V {
    list(vec![
        list(vec![V::Uint(0), V::Uint(1), b([99; 32])]),
        list(vec![]),
    ])
}

fn grant_reference(bytes: &[u8]) -> V {
    let decoded = wire::decode(bytes).unwrap();
    let fields = decoded.array(17).unwrap();
    list(vec![
        V::Uint(102),
        fields[6].clone(),
        fields[4].clone(),
        b(wire::digest(bytes)),
    ])
}

fn revocation(grant: &[u8], revoker: Key) -> Vec<u8> {
    rec(
        126,
        vec![grant_reference(grant), b(revoker), expected_snapshot()],
    )
}

fn capability(governance: &Governance, grant: Digest, subject: Key) -> Result<CapabilityDecision> {
    governance.capability(
        grant,
        &Requirement {
            subject,
            actions: &[0],
            scope: (2, [88; 32]),
            namespace: None,
            usage: [1, 1, 0, 0],
            evaluated_at_ms: 5000,
            expected: &governance.versions(),
        },
    )
}

fn changed(bytes: &[u8], field: usize, value: V) -> Vec<u8> {
    let mut values = wire::decode(bytes).unwrap().list(32).unwrap().to_vec();
    values[field] = value;
    wire::encode(&list(values)).unwrap()
}

fn advanced(bytes: &[u8]) -> Vec<u8> {
    let mut values = wire::decode(bytes).unwrap().list(32).unwrap().to_vec();
    values[4] = V::Uint(values[4].uint().unwrap() + 1);
    values[5] = b(wire::digest(bytes));
    *values.last_mut().unwrap() = expected_snapshot();
    wire::encode(&list(values)).unwrap()
}

#[test]
fn revocation_denies_the_exact_grant_and_every_dependent_chain() {
    let (records, root, child) = fixture();
    for target in [2, 3] {
        let mut revoked = records.clone();
        revoked.push(revocation(&records[target], root));
        let governance = Governance::parse([1; 32], [2; 32], &revoked).unwrap();
        assert_eq!(
            capability(&governance, [5; 32], child)
                .unwrap_err()
                .to_string(),
            "grant is permanently revoked"
        );
        if target == 2 {
            assert!(capability(&governance, [4; 32], root).is_err());
        } else {
            assert!(capability(&governance, [4; 32], root).is_ok());
        }
    }
}

#[test]
fn later_generations_and_changed_subjects_cannot_revive_a_revoked_grant_id() {
    let (mut records, root, child) = fixture();
    let tombstone = revocation(&records[2], root);
    let replacement = ed25519_dalek::SigningKey::from_bytes(&[74; 32])
        .verifying_key()
        .to_bytes();
    records[2] = changed(&advanced(&records[2]), 7, b(replacement));
    records[2] = changed(&records[2], 8, b(replacement));
    records[3] = changed(&advanced(&records[3]), 7, b(replacement));
    records[3] = changed(&records[3], 13, grant_reference(&records[2]));
    records[5] = changed(&advanced(&records[5]), 10, grant_reference(&records[3]));
    let permitted = Governance::parse([1; 32], [2; 32], &records).unwrap();
    assert!(capability(&permitted, [4; 32], replacement).is_ok());
    assert!(capability(&permitted, [5; 32], child).is_ok());
    records.push(tombstone);
    let revoked = Governance::parse([1; 32], [2; 32], &records).unwrap();
    for (grant, subject) in [([4; 32], replacement), ([5; 32], child)] {
        assert_eq!(
            capability(&revoked, grant, subject)
                .unwrap_err()
                .to_string(),
            "grant is permanently revoked"
        );
    }
}

#[test]
fn revocation_versions_use_the_grant_id_and_bind_exact_signed_expectations() {
    let (mut records, root, _) = fixture();
    let tombstone = revocation(&records[3], root);
    records.push(tombstone.clone());
    let governance = Governance::parse([1; 32], [2; 32], &records).unwrap();
    assert_eq!(governance.record_bytes(126, [5; 32]).unwrap(), tombstone);
    assert!(governance.record_bytes(126, root).is_err());
    assert!(
        governance
            .record_bytes(126, wire::digest(&records[3]))
            .is_err()
    );
    let expected = governance.versions();
    let index = expected.iter().position(|r| r.kind == 126).unwrap();
    assert_eq!(
        expected[index],
        VersionRef {
            kind: 126,
            id: [5; 32],
            generation: 1,
            digest: wire::digest(&tombstone),
        }
    );
    assert!(capability(&governance, [4; 32], root).is_ok());
    for field in 0..3 {
        let mut stale = expected.clone();
        match field {
            0 => stale[index].generation += 1,
            1 => stale[index].digest[0] ^= 1,
            _ => stale[index].id = [6; 32],
        }
        let error = governance
            .capability(
                [4; 32],
                &Requirement {
                    subject: root,
                    actions: &[0],
                    scope: (2, [88; 32]),
                    namespace: None,
                    usage: [1, 1, 0, 0],
                    evaluated_at_ms: 5000,
                    expected: &stale,
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("governance"));
    }
}

#[test]
fn revocation_rejects_absent_future_and_same_generation_conflicting_targets() {
    let (records, root, _) = fixture();
    let tombstone = revocation(&records[3], root);
    for field in 1..4 {
        let mut target = grant_reference(&records[3]).array(4).unwrap().to_vec();
        target[field] = match field {
            1 => b([77; 32]),
            2 => V::Uint(2),
            _ => b([78; 32]),
        };
        let mut invalid = records.clone();
        invalid.push(changed(&tombstone, 6, list(target)));
        assert!(Governance::parse([1; 32], [2; 32], &invalid).is_err());
    }
    let mut duplicate = records;
    duplicate.push(tombstone.clone());
    duplicate.push(tombstone);
    assert!(Governance::parse([1; 32], [2; 32], &duplicate).is_err());
}

#[test]
fn revocation_requires_its_exact_schema_key_snapshot_and_context() {
    let (records, root, _) = fixture();
    let tombstone = revocation(&records[3], root);
    let mut wrong_kind = grant_reference(&records[3]).array(4).unwrap().to_vec();
    wrong_kind[0] = V::Uint(101);
    let mut short = wire::decode(&tombstone).unwrap().array(9).unwrap().to_vec();
    short.pop();
    let mut long = wire::decode(&tombstone).unwrap().array(9).unwrap().to_vec();
    long.push(V::Null);
    for invalid in [
        changed(&tombstone, 6, list(wrong_kind)),
        changed(&tombstone, 7, b([0; 32])),
        changed(&tombstone, 8, V::Null),
        changed(&tombstone, 8, list(vec![])),
        changed(&tombstone, 2, b([88; 32])),
        changed(&tombstone, 3, b([88; 32])),
        changed(&tombstone, 4, V::Uint(0)),
        wire::encode(&list(short)).unwrap(),
        wire::encode(&list(long)).unwrap(),
    ] {
        let mut state = records.clone();
        state.push(invalid);
        assert!(Governance::parse([1; 32], [2; 32], &state).is_err());
    }
}

#[test]
fn admission_validity_bounds_the_subject_and_every_delegating_ancestor() {
    let (mut records, root, parent) = fixture();
    let child = ed25519_dalek::SigningKey::from_bytes(&[75; 32])
        .verifying_key()
        .to_bytes();
    records[3] = changed(&records[3], 10, list(vec![V::Uint(0), V::Uint(11)]));
    records[3] = changed(&records[3], 14, V::Uint(1));
    records[5] = changed(&records[5], 8, list(vec![V::Uint(1000), V::Uint(6501)]));
    records[5] = changed(&records[5], 10, grant_reference(&records[3]));
    let child_grant = rec(
        102,
        vec![
            b([10; 32]),
            b(parent),
            b(child),
            vr(101, [3; 32], &records[1]),
            list(vec![V::Uint(0)]),
            list(vec![list(vec![V::Uint(0), b([1; 32])])]),
            list(vec![V::Uint(0), V::Uint(100000)]),
            grant_reference(&records[3]),
            V::Uint(0),
            list(vec![V::Uint(100); 4]),
            expected_snapshot(),
        ],
    );
    let child_admission = rec(
        125,
        vec![
            b([11; 32]),
            b(child),
            list(vec![V::Uint(2000), V::Uint(8501)]),
            V::Bool(false),
            grant_reference(&child_grant),
            expected_snapshot(),
        ],
    );
    records.insert(4, child_grant);
    records.push(child_admission);
    let governance = Governance::parse([1; 32], [2; 32], &records).unwrap();
    let own = capability(&governance, [5; 32], parent).unwrap();
    assert_eq!((own.not_before_ms, own.expires_ms), (1000, 6501));
    let delegated = capability(&governance, [10; 32], child).unwrap();
    assert_eq!(
        (delegated.not_before_ms, delegated.expires_ms),
        (2000, 6501)
    );
    assert_eq!(
        capability(&governance, [4; 32], root).unwrap().expires_ms,
        100000
    );
    let mut request = Requirement {
        subject: child,
        actions: &[0],
        scope: (2, [88; 32]),
        namespace: None,
        usage: [1, 1, 0, 0],
        evaluated_at_ms: 5000,
        expected: &[],
    };
    let discovery = governance.current_capability([10; 32], &request).unwrap();
    assert_eq!(
        (discovery.not_before_ms, discovery.expires_ms),
        (2000, 6501)
    );
    request.evaluated_at_ms = 5251;
    assert!(governance.current_capability([10; 32], &request).is_err());
    records[6] = changed(&records[6], 8, list(vec![V::Uint(1000), V::Uint(9501)]));
    let governance = Governance::parse([1; 32], [2; 32], &records).unwrap();
    assert_eq!(
        capability(&governance, [10; 32], child).unwrap().expires_ms,
        8501
    );
}
