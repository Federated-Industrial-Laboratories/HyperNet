// SPDX-License-Identifier: MIT
// A separately admitted member's evidence must reach a cold enrolment endpoint.
use super::*;

const MEMBER: Digest = [92; 32];
const DEVICE: Digest = [93; 32];

fn member(f: &mut Fixture) -> VersionRef {
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    let value = wire::decode(governance.record_bytes(102, f.grant.id).unwrap()).unwrap();
    let mut fields = value.array(17).unwrap().to_vec();
    fields[6] = b(&[94; 32]);
    fields[8] = b(&public(75));
    fields[10] = a(vec![V::Uint(0), V::Uint(4), V::Uint(23)]);
    fields[11] = a(vec![a(vec![V::Uint(4), b(&MEMBER)])]);
    fields[12] = a(vec![V::Uint(1000), V::Uint(20000)]);
    fields[13] = reference(&f.grant);
    fields[14] = V::Uint(0);
    fields[16] = deployment::snapshot(&[]);
    f.records.push(wire::encode(&a(fields)).unwrap());
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let reader = Governance::parse([20; 32], [21; 32], &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [94; 32])
        .unwrap();
    f.records.push(
        wire::encode(&a(vec![
            V::Uint(125),
            V::Uint(1),
            b(&[20; 32]),
            b(&[21; 32]),
            V::Uint(1),
            V::Null,
            b(&MEMBER),
            b(&public(75)),
            a(vec![V::Uint(1000), V::Uint(20000)]),
            V::Bool(false),
            reference(&reader),
            deployment::snapshot(&[]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    reader
}

fn root(snapshot: &V) -> Command {
    let mut policy = wire::decode(&custody()).unwrap().array(8).unwrap().to_vec();
    policy[5] = b(&MEMBER);
    let custody = wire::encode(&a(policy)).unwrap();
    let root = record(signed(
        107,
        1,
        None,
        vec![
            b(&MEMBER),
            b(&public(70)),
            b(&wire::digest(&custody)),
            snapshot.array(2).unwrap()[0].clone(),
        ],
        70,
    ));
    let acceptance = signed(
        121,
        0,
        None,
        vec![
            b(&[95; 32]),
            b(&MEMBER),
            V::Null,
            reference(&root.reference),
            V::Null,
            b(&[96; 32]),
        ],
        75,
    );
    Command::Root {
        root,
        acceptance,
        custody,
        recovery: None,
    }
}

fn device(root: &VersionRef, snapshot: &V) -> Command {
    let binding = record(signed(
        108,
        1,
        None,
        vec![
            b(&MEMBER),
            reference(root),
            b(&DEVICE),
            b(&public(71)),
            b(&[72; 32]),
            a(vec![V::Uint(0)]),
            a(vec![V::Uint(1000), V::Uint(15000)]),
        ],
        70,
    ));
    let challenge = signed(
        123,
        0,
        None,
        vec![
            b(&[97; 32]),
            b(&binding.reference.digest),
            b(&public(5)),
            b(&[98; 32]),
            V::Uint(10000),
        ],
        5,
    );
    let possession = signed(
        122,
        0,
        None,
        vec![
            b(&[97; 32]),
            b(&binding.reference.digest),
            b(&public(5)),
            b(&wire::digest(&wire::envelope(&challenge, 1).unwrap().0)),
            V::Uint(10000),
        ],
        71,
    );
    let admission = record(signed(
        109,
        1,
        None,
        vec![
            b(&MEMBER),
            reference(&binding.reference),
            a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
            a(vec![V::Uint(1000), V::Uint(15000)]),
            b(&wire::digest(&wire::envelope(&possession, 1).unwrap().0)),
            snapshot.clone(),
        ],
        5,
    ));
    Command::Device {
        binding,
        admission: Box::new(admission),
        challenge,
        possession,
        delegate: None,
    }
}

fn merge_context(f: &mut Fixture, decision: &Decision) {
    let body = decision.value.array(5).unwrap()[4].array(4).unwrap();
    for record in body[1].list(64).unwrap() {
        let record = Record::parse(record.bytes().unwrap(), [20; 32], [21; 32]).unwrap();
        f.state.records.insert(record.reference.index(), record);
    }
    for record in body[2].list(64).unwrap() {
        let bytes = record.bytes().unwrap().to_vec();
        if !f.records.contains(&bytes) {
            f.records.push(bytes);
        }
    }
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    super::super::super::result::derive_keys(&mut f.state).unwrap();
}

#[test]
fn recipient_context_supplies_target_membership_for_cold_admission() {
    let mut authority = Fixture::new();
    let reader = member(&mut authority);
    let directory = authority.run(
        |_| Command::Directory {
            member: MEMBER,
            view: None,
            after: None,
        },
        5,
        Some(authority.grant.clone()),
    );
    assert_eq!(directory.code, 0);
    assert!(
        directory
            .dependencies
            .iter()
            .any(|r| r.kind == 125 && r.id == MEMBER)
    );
    let mut cold = Fixture::new();
    assert_eq!(cold.run(root, 5, Some(cold.grant.clone())).code, 3);
    merge_context(&mut cold, &directory);
    assert_eq!(cold.run(root, 5, Some(cold.grant.clone())).code, 0);
    assert_eq!(
        authority.run(root, 5, Some(authority.grant.clone())).code,
        0
    );
    let root = authority
        .state
        .record(107, MEMBER)
        .unwrap()
        .reference
        .clone();
    let context = authority.run(
        |_| Command::Context {
            kind: 107,
            lookup: MEMBER,
        },
        5,
        Some(authority.grant.clone()),
    );
    assert_eq!(context.code, 0);
    assert!(
        context
            .dependencies
            .iter()
            .any(|r| r.kind == 125 && r.id == MEMBER)
    );

    // Root possession alone is insufficient: admission needs the target's membership.
    let mut endpoint = Fixture::new();
    endpoint.state = authority.state.clone();
    assert_eq!(
        endpoint
            .run(|s| device(&root, s), 5, Some(endpoint.grant.clone()))
            .code,
        3
    );
    merge_context(&mut endpoint, &context);
    let admitted = endpoint.run(|s| device(&root, s), 5, Some(endpoint.grant.clone()));
    assert_eq!(admitted.code, 0);
    assert!(
        admitted
            .dependencies
            .iter()
            .any(|r| r.kind == 125 && r.id == MEMBER)
    );

    // A member-scoped capability still cannot retrieve another member's evidence.
    let denied = authority.run(
        |_| Command::Directory {
            member: public(5),
            view: None,
            after: None,
        },
        75,
        Some(reader),
    );
    assert_eq!(denied.code, 3);

    let (intent, operation) = authority.intent(
        Command::Directory {
            member: MEMBER,
            view: None,
            after: None,
        },
        deployment::snapshot(&[]),
        5,
        Some(authority.grant.clone()),
    );
    let directory = authority.run(
        |_| Command::Directory {
            member: MEMBER,
            view: None,
            after: None,
        },
        5,
        Some(authority.grant.clone()),
    );
    assert_eq!(
        verify_directory_result(
            &operation,
            &authority.state,
            &authority.records,
            &intent,
            5000,
            &directory.value,
        )
        .unwrap()
        .versions,
        directory.versions
    );
    // Independent verification requires the exact target membership in the response.
    let mut without_member = directory.value.array(5).unwrap().to_vec();
    let mut body = without_member[4].array(4).unwrap().to_vec();
    body[2] = a(body[2]
        .list(64)
        .unwrap()
        .iter()
        .filter(|r| wire::decode(r.bytes().unwrap()).unwrap().list(32).unwrap()[0] != V::Uint(125))
        .cloned()
        .collect());
    without_member[4] = a(body);
    assert!(
        verify_directory_result(
            &operation,
            &authority.state,
            &authority.records,
            &intent,
            5000,
            &a(without_member),
        )
        .is_err()
    );

    // Discovery retains revoked membership; it does not turn that evidence into permission.
    let membership = authority
        .records
        .iter_mut()
        .find(|bytes| wire::decode(bytes).unwrap().list(32).unwrap()[0] == V::Uint(125))
        .unwrap();
    let mut fields = wire::decode(membership)
        .unwrap()
        .array(12)
        .unwrap()
        .to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(membership));
    fields[9] = V::Bool(true);
    *membership = wire::encode(&a(fields)).unwrap();
    for command in [
        Command::Context {
            kind: 107,
            lookup: MEMBER,
        },
        Command::Directory {
            member: MEMBER,
            view: None,
            after: None,
        },
    ] {
        let discovered = authority.run(|_| command.clone(), 5, Some(authority.grant.clone()));
        assert_eq!(discovered.code, 0);
        assert!(
            discovered
                .dependencies
                .iter()
                .any(|r| r.kind == 125 && r.generation == 2)
        );
    }
    assert_eq!(
        authority
            .run(|s| device(&root, s), 5, Some(authority.grant.clone()))
            .code,
        3
    );
}

fn update_member(f: &mut Fixture, expires: u64, revoked: bool) {
    let bytes = f
        .records
        .iter_mut()
        .find(|bytes| wire::decode(bytes).unwrap().list(32).unwrap()[0] == V::Uint(125))
        .unwrap();
    let mut fields = wire::decode(bytes).unwrap().array(12).unwrap().to_vec();
    fields[4] = V::Uint(fields[4].uint().unwrap() + 1);
    fields[5] = b(&wire::digest(bytes));
    fields[8] = a(vec![V::Uint(1000), V::Uint(expires)]);
    fields[9] = V::Bool(revoked);
    *bytes = wire::encode(&a(fields)).unwrap();
}
#[test]
fn recipient_roster_freeze_requires_current_member_and_binds_its_expiry() {
    let mut f = Fixture::new();
    member(&mut f);
    assert_eq!(f.run(root, 5, Some(f.grant.clone())).code, 0);
    let root = f.state.record(107, MEMBER).unwrap().reference.clone();
    assert_eq!(
        f.run(|s| device(&root, s), 5, Some(f.grant.clone())).code,
        0
    );
    let created = f.run(
        |snapshot| Command::Audience {
            audience: record(signed(
                110,
                1,
                None,
                vec![
                    b(&[86; 32]),
                    b(&public(5)),
                    a(vec![reference(&root)]),
                    a(vec![]),
                    V::Null,
                    V::Bool(false),
                    snapshot.clone(),
                ],
                5,
            )),
            acceptances: vec![acceptance(&root, None, 5)],
        },
        5,
        Some(f.grant.clone()),
    );
    assert_eq!(created.code, 0);
    let audience = Audience::parse(
        &payload(f.state.record(110, [86; 32]).unwrap()).unwrap(),
        [20; 32],
        [21; 32],
    )
    .unwrap();
    update_member(&mut f, 10000, false);
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    let selected = roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).unwrap();
    assert_eq!(selected.expires_ms, 10000);
    assert!(
        selected
            .dependencies
            .iter()
            .any(|r| r.kind == 125 && r.id == MEMBER && r.generation == 2)
    );
    let freeze = |snapshot: &V| Command::Freeze {
        roster: record(signed(
            111,
            1,
            None,
            vec![
                b(&[87; 32]),
                V::Uint(1),
                V::Uint(1),
                reference(&audience.reference),
                a(selected.roots.iter().map(|r| b(r)).collect()),
                a(selected
                    .devices
                    .iter()
                    .map(|(r, d, a_)| a(vec![b(r), b(d), b(a_)]))
                    .collect()),
                snapshot.clone(),
            ],
            5,
        )),
        scope: (2, [87; 32]),
    };
    let frozen = f.run(freeze, 5, Some(f.grant.clone()));
    assert_eq!(frozen.code, 0);
    assert_eq!(frozen.expires_ms, 10000);
    assert!(
        frozen
            .dependencies
            .iter()
            .any(|r| r.kind == 125 && r.id == MEMBER)
    );
    let admission = f
        .state
        .record(109, selected.devices[0].1)
        .unwrap()
        .reference
        .clone();
    for (expires, revoked) in [(6000, false), (10000, true)] {
        update_member(&mut f, expires, revoked);
        let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
        assert!(roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).is_err());
        assert_eq!(f.run(freeze, 5, Some(f.grant.clone())).code, 17);
        assert_eq!(
            f.state.record(109, admission.id).unwrap().reference,
            admission
        );
    }
}

#[test]
fn recipient_roster_checks_current_bootstrap_grant_revocation() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    f.audience();
    let audience = Audience::parse(
        &payload(f.state.record(110, [86; 32]).unwrap()).unwrap(),
        [20; 32],
        [21; 32],
    )
    .unwrap();
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    let selected = roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).unwrap();
    assert!(selected.dependencies.contains(&f.grant));
    f.records.push(
        wire::encode(&a(vec![
            V::Uint(126),
            V::Uint(1),
            b(&[20; 32]),
            b(&[21; 32]),
            V::Uint(1),
            V::Null,
            reference(&f.grant),
            b(&public(5)),
            deployment::snapshot(&[]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    assert!(roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).is_err());
    let evidence = member_evidence(&governance, [20; 32], public(5)).unwrap();
    assert!(evidence.iter().any(|r| r.kind == 126 && r.id == f.grant.id));
}
