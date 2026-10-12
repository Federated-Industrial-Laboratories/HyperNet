// SPDX-License-Identifier: MIT
// Membership removal invalidates encryption and publication while device admission remains live.
use super::*;
use domains::sealed_identity as identity;
use sha2::{Digest as _, Sha256};
const MEMBER: Digest = [92; 32];

fn fixture() -> Fixture {
    let mut f = Fixture::new();
    let governance = Governance::parse([20; 32], [21; 32], &f.records).unwrap();
    let value = wire::decode(governance.record_bytes(102, f.grant.id).unwrap()).unwrap();
    let mut fields = value.array(17).unwrap().to_vec();
    fields[6] = b(&[94; 32]);
    fields[8] = b(&public(75));
    fields[10] = a(vec![V::Uint(0)]);
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

    // Keep publisher/reviewer authority separate from the ordinary audience member.
    f.state
        .records
        .retain(|(kind, _), _| !matches!(kind, 107..=111));
    f.state.keys.retain(|_, (class, _)| !matches!(class, 5..=7));
    let snapshot = deployment::snapshot(&[]);
    let root = f.put(
        107,
        vec![
            b(&MEMBER),
            b(&public(70)),
            b(&[72; 32]),
            snapshot.array(2).unwrap()[0].clone(),
        ],
        70,
    );
    let binding = f.put(
        108,
        vec![
            b(&MEMBER),
            reference(&root),
            b(&[83; 32]),
            b(&public(73)),
            b(&[74; 32]),
            a(vec![V::Uint(0)]),
            a(vec![V::Uint(1000), V::Uint(19000)]),
        ],
        70,
    );
    let admission = f.put(
        109,
        vec![
            b(&MEMBER),
            reference(&binding),
            a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
            a(vec![V::Uint(1000), V::Uint(19000)]),
            b(&[75; 32]),
            snapshot.clone(),
        ],
        5,
    );
    let audience = f.put(
        110,
        vec![
            b(&[76; 32]),
            b(&public(5)),
            a(vec![reference(&root)]),
            a(vec![]),
            V::Null,
            V::Bool(false),
            snapshot.clone(),
        ],
        5,
    );
    for (publication, revision) in [([77; 32], 1), ([88; 32], 2)] {
        f.put(
            111,
            vec![
                b(&publication),
                V::Uint(revision),
                V::Uint(revision),
                reference(&audience),
                a(vec![b(&root.digest)]),
                a(vec![a(vec![
                    b(&root.digest),
                    b(&binding.digest),
                    b(&admission.digest),
                ])]),
                snapshot.clone(),
            ],
            5,
        );
    }
    domains::result::derive_keys(&mut f.state).unwrap();
    f
}
fn remove_member(f: &mut Fixture, revoked: bool) {
    let bytes = f
        .records
        .iter_mut()
        .find(|bytes| wire::decode(bytes).unwrap().list(32).unwrap()[0] == V::Uint(125))
        .unwrap();
    let mut fields = wire::decode(bytes).unwrap().array(12).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(bytes));
    fields[8] = a(vec![
        V::Uint(1000),
        V::Uint(if revoked { 20000 } else { 6000 }),
    ]);
    fields[9] = V::Bool(revoked);
    *bytes = wire::encode(&a(fields)).unwrap();
}
fn prepare(f: &mut Fixture) -> Decision {
    let roster = f.state.record(111, [77; 32]).unwrap().reference.clone();
    let grant = f.grant.clone();
    f.run(
        |_| {
            Command::Prepare {
                object: [78; 32],
                roster: roster.clone(),
                author_grant: grant.clone(),
                namespace: "Books".into(),
            }
            .into()
        },
        5,
    )
}
#[test]
fn sealed_member_removal_after_freeze_blocks_commit_and_later_ciphertext() {
    for revoked in [false, true] {
        let mut f = fixture();
        f.policy();
        let prepared = prepare(&mut f);
        assert_eq!(prepared.code, 0);
        assert!(
            prepared
                .dependencies
                .iter()
                .any(|r| r.kind == 125 && r.id == MEMBER)
        );
        let staged = f.stage();
        assert_eq!(staged.code, 0);
        assert!(
            staged
                .dependencies
                .iter()
                .any(|r| r.kind == 125 && r.id == MEMBER)
        );
        f.copy();
        let outer = f.outer();
        let binding = f.state.record(108, [83; 32]).unwrap().reference.clone();
        let admitted = f
            .state
            .record(109, binding.digest)
            .unwrap()
            .reference
            .clone();
        let active_records = f.records.clone();
        remove_member(&mut f, revoked);
        let context = f.run(|_| Command::Context { object: [78; 32] }.into(), 5);
        assert_eq!(context.code, 0);
        assert!(
            context
                .dependencies
                .iter()
                .any(|r| r.kind == 125 && r.id == MEMBER && r.generation == 2)
        );
        assert_ne!(prepare(&mut f).code, 0);
        assert_ne!(
            f.run(
                |_| Command::Commit {
                    outer: outer.clone()
                }
                .into(),
                5
            )
            .code,
            0
        );
        assert_ne!(f.stage_revision([88; 32], 2).code, 0);
        assert!(!f.state.records.contains_key(&(113, [88; 32])));
        assert_eq!(
            f.state.record(109, binding.digest).unwrap().reference,
            admitted
        );
        let admission = identity::Admission::parse(
            &identity::payload(f.state.record(109, binding.digest).unwrap()).unwrap(),
            [20; 32],
            [21; 32],
        )
        .unwrap();
        assert!(crate::authority_membership::current(
            5000,
            admission.validity
        ));
        assert!(!identity::revoked(&f.state, &binding));
        assert!(!identity::revoked(&f.state, &admitted));
        // Positive controls distinguish membership refusal from placement or revision errors.
        f.records = active_records;
        assert_eq!(
            f.run(
                |_| Command::Commit {
                    outer: outer.clone()
                }
                .into(),
                5
            )
            .code,
            0
        );
        assert_eq!(f.stage_revision([88; 32], 2).code, 0);
    }
}

fn request(command: DomainCommand, grant: Option<VersionRef>, seed: u8) -> (Operation, Vec<u8>) {
    let operation = Operation {
        grant,
        command,
        snapshot: domains::snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let signed = deployment::signed(
        &deployment::key(seed),
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        vec![],
    );
    (operation, signed)
}
fn evaluate_request(
    f: &Fixture,
    state: &State,
    records: &[Vec<u8>],
    operation: &Operation,
    signed: &[u8],
) -> Decision {
    operation
        .prepare(
            state,
            records,
            &f.reserved,
            &Intent::from_signed(signed).unwrap(),
            5000,
            false,
            false,
        )
        .unwrap()
}
fn retain(state: &mut State, records: &mut Vec<Vec<u8>>, decision: &Decision) {
    assert_eq!(decision.code, 0);
    let body = decision.value.array(5).unwrap()[4].array(4).unwrap();
    for value in body[1].list(64).unwrap() {
        let record = domains::Record::parse(value.bytes().unwrap(), [20; 32], [21; 32]).unwrap();
        state.records.insert(record.reference.index(), record);
    }
    for value in body[2].list(64).unwrap() {
        let bytes = value.bytes().unwrap().to_vec();
        let incoming =
            Governance::record_versions([20; 32], [21; 32], std::slice::from_ref(&bytes))
                .unwrap()
                .remove(0);
        records.retain(|old| {
            Governance::record_versions([20; 32], [21; 32], std::slice::from_ref(old)).unwrap()[0]
                .index()
                != incoming.index()
        });
        records.push(bytes);
    }
    crate::authority_membership::sort_records(records).unwrap();
    domains::result::derive_keys(state).unwrap();
}
#[test]
fn sealed_cold_device_content_lookup_supplies_host_evidence_and_exact_read_response() {
    let mut f = fixture();
    f.policy();
    assert_eq!(f.stage().code, 0);
    f.copy();
    let outer = f.outer();
    assert_eq!(
        f.run(
            |_| Command::Commit {
                outer: outer.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    let reader = Governance::parse([20; 32], [21; 32], &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 102 && r.id == [94; 32])
        .unwrap();
    let device = f.state.record(108, [83; 32]).unwrap().reference.clone();
    let publication =
        PublicationState::parse(&f.state.record(PUBLICATION_STATE, outer.id).unwrap().payload)
            .unwrap();
    let placement = publication.placement;
    let mut state = State::empty([20; 32], [21; 32]);
    let mut records = f
        .records
        .iter()
        .filter(|bytes| {
            let value = wire::decode(bytes).unwrap();
            let row = value.list(32).unwrap();
            matches!(row[0].uint().unwrap(), 100 | 101 | 114 | 131)
                || row[0] == V::Uint(102) && row[6] == b(&f.grant.id)
        })
        .cloned()
        .collect::<Vec<_>>();
    // Match the device-owned installed fetch sequence, with no administrator cache.
    for (command, grant) in [
        (
            identity::Command::Context {
                kind: 108,
                lookup: device.id,
            }
            .into(),
            None,
        ),
        (
            Command::ReaderContext {
                object: [78; 32],
                device: device.clone(),
            }
            .into(),
            Some(reader.clone()),
        ),
        (
            Command::Read {
                outer: outer.clone(),
                device: device.clone(),
            }
            .into(),
            Some(reader.clone()),
        ),
        (
            page::Command::Content(page::content::Command::Get {
                placement: placement.clone(),
            })
            .into(),
            Some(reader.clone()),
        ),
    ] {
        let (operation, signed) = request(command, grant, 73);
        let result = evaluate_request(&f, &f.state, &f.records, &operation, &signed);
        retain(&mut state, &mut records, &result);
    }
    let command = page::Command::Content(page::content::Command::Authorise {
        placement: placement.clone(),
        host: f.host.clone(),
        effect: page::content::Effect::Read,
        offset: 0,
        bytes: 64,
        digest: None,
    });
    let (operation, signed) = request(command.clone().into(), Some(reader.clone()), 73);
    let without_host = records
        .iter()
        .filter(|bytes| {
            !matches!(
                wire::decode(bytes).unwrap().list(32).unwrap()[0]
                    .uint()
                    .unwrap(),
                105 | 117 | 129 | 130
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate_request(&f, &state, &without_host, &operation, &signed).code,
        3
    );
    let result = evaluate_request(&f, &state, &records, &operation, &signed);
    assert_eq!(result.code, 0);
    for kind in [105, 117, 125, 129] {
        assert!(result.dependencies.iter().any(|r| r.kind == kind));
    }
    assert_eq!(
        operation
            .expected_recipient(
                &state,
                &records,
                &f.reserved,
                &Intent::from_signed(&signed).unwrap()
            )
            .unwrap(),
        f.host.id
    );
    for seed in [74, 75] {
        let (other, bytes) = request(command.clone().into(), Some(reader.clone()), seed);
        assert_ne!(
            evaluate_request(&f, &state, &records, &other, &bytes).code,
            0
        );
    }
    let (other, bytes) = request(command.clone().into(), Some(f.grant.clone()), 73);
    assert_ne!(
        evaluate_request(&f, &state, &records, &other, &bytes).code,
        0
    );

    // The typed opaque read response binds this device's exact range and selected store.
    let participant = page::MediaRequest::parse(&signed).unwrap();
    let result = crate::authority_proof::OperationResult {
        action: "AuthorityDomain".into(),
        disposition: crate::authority_proof::Disposition::Permit,
        code: 0,
        value: wire::encode(&result.value).unwrap(),
    };
    let copies = page::content::Copies::parse(
        &state.record(160, placement.id).unwrap().payload,
        [20; 32],
        [21; 32],
    )
    .unwrap();
    let bytes = vec![42; 64];
    let chunk_digest: Digest = Sha256::digest(&bytes).into();
    let mut response = vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("PageContentEffect".into()),
        reference(&placement),
        reference(&f.host),
        V::Uint(page::content::Effect::Read.code()),
        V::Uint(0),
        V::Uint(64),
        b(&chunk_digest),
        b(&bytes),
        b(&copies.copies[0].envelope),
    ];
    assert!(participant.result_content(&result).unwrap().2.is_none());
    participant
        .validate_response(&result, &wire::encode(&a(response.clone())).unwrap())
        .unwrap();
    response[9] = b(&[43; 64]);
    assert!(
        participant
            .validate_response(&result, &wire::encode(&a(response)).unwrap())
            .is_err()
    );

    // Withdrawal is discoverable while the exact selected host version stays unchanged.
    let registration = Governance::parse([20; 32], [21; 32], &f.records)
        .unwrap()
        .versions()
        .into_iter()
        .find(|r| r.kind == 129)
        .unwrap();
    f.records.push(
        wire::encode(&a(vec![
            V::Uint(130),
            V::Uint(1),
            b(&[20; 32]),
            b(&[21; 32]),
            V::Uint(1),
            V::Null,
            b(&registration.id),
            reference(&registration),
            b(&public(90)),
            V::Uint(1),
            deployment::snapshot(&[]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    let (lookup, bytes) = request(
        page::Command::Content(page::content::Command::Get {
            placement: placement.clone(),
        })
        .into(),
        Some(reader),
        73,
    );
    let result = evaluate_request(&f, &f.state, &f.records, &lookup, &bytes);
    assert!(result.dependencies.iter().any(|r| r.kind == 130));
    retain(&mut state, &mut records, &result);
    assert_eq!(state.record(147, f.host.id).unwrap().reference, f.host);
    assert_ne!(
        evaluate_request(&f, &state, &records, &operation, &signed).code,
        0
    );
}
