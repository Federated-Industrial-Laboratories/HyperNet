// SPDX-License-Identifier: MIT
// Sealed publication ordering binds author intent, recipient removal and actual placement evidence.
use super::*;
use crate::{
    authority_deployment_tests as deployment, authority_governance::Governance,
    authority_membership::Reservations, authority_proof::Intent,
};
use domains::{Command as DomainCommand, Decision, Operation, State, page};
#[path = "AuthoritySealedPublicationMembershipTests.rs"]
mod membership;
fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
fn signed(kind: u64, body: Vec<V>, seed: u8) -> Vec<u8> {
    let mut f = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&[20; 32]),
        b(&[21; 32]),
        V::Uint(1),
        V::Null,
    ];
    f.extend(body);
    wire::sign_envelope(&wire::encode(&a(f)).unwrap(), &deployment::key(seed)).unwrap()
}
struct Fixture {
    state: State,
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    grant: VersionRef,
    reviewer: VersionRef,
    host: VersionRef,
}
impl Fixture {
    fn new() -> Self {
        let f = deployment::Fixture::with_actions(vec![
            0, 1, 2, 3, 4, 5, 7, 9, 10, 11, 12, 13, 23, 26, 29, 30,
        ]);
        let mut m = deployment::manifest();
        m.consent_policy.allow_opaque = true;
        m.consent_policy.reviewer_roots = vec![public(5)];
        let (mut records, _, _, _) = deployment::admitted(&f, &deployment::offer(m.clone()));
        for r in &mut records {
            let v = wire::decode(r).unwrap();
            let mut fields = v.list(32).unwrap().to_vec();
            if fields[0].uint().unwrap() == 100 {
                fields[10] = a(vec![V::Uint(0), V::Uint(1)]);
                *r = wire::encode(&a(fields)).unwrap();
            }
        }
        let grant = Governance::parse([20; 32], [21; 32], &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let reviewer = deployment::scoped_grant(&mut records, &grant, [232; 32], &[(2, [78; 32])]);
        let mut f = Self {
            state: State::empty([20; 32], [21; 32]),
            records,
            reserved: f.reservations,
            grant: grant.clone(),
            reviewer,
            host: grant,
        };
        let mut h = page::HostProfile {
            manifest: m,
            role: 1,
            service: public(100),
            volume: [101; 32],
            namespaces: vec!["Books".into()],
            state_bytes: 8 * 1024 * 1024,
            maximum_asset_bytes: 1024 * 1024,
            retention_ms: 15000,
            content: Some(page::ContentPolicy {
                search: false,
                metadata_bytes: 65536,
                data_bytes: 2 * 1024 * 1024,
                staging_bytes: 1024 * 1024,
                quarantine_bytes: 1024 * 1024,
                maximum_objects: 128,
                opaque: true,
                failure_domain: [91; 32],
                reviewers: vec![public(5)],
            }),
            envelope: vec![],
        };
        h.envelope = wire::sign_envelope(&h.payload().unwrap(), &deployment::key(90)).unwrap();
        assert_eq!(
            f.run(
                |_| page::Command::HostRegister {
                    profile: Box::new(h.clone())
                }
                .into(),
                5
            )
            .code,
            0
        );
        f.host = f.state.record(147, public(100)).unwrap().reference.clone();
        f.recipients();
        f
    }
    fn run(&mut self, build: impl Fn(&V) -> DomainCommand, seed: u8) -> Decision {
        let mut snapshot = deployment::snapshot(&[]);
        for exact in [false, true] {
            let command = build(&snapshot);
            let reviewer = matches!(
                &command,
                DomainCommand::SealedPublication(
                    Command::Prepare { .. } | Command::Stage { .. } | Command::Context { .. }
                ) | DomainCommand::Page(page::Command::Content(
                    page::content::Command::Receipt { .. }
                ))
            );
            let operation = Operation {
                grant: Some(if reviewer {
                    self.reviewer.clone()
                } else {
                    self.grant.clone()
                }),
                command,
                snapshot: domains::snapshot(&snapshot).unwrap(),
            };
            let intent = Intent {
                network: [20; 32],
                incarnation: [21; 32],
                generation: 1,
                generation_id: [90; 32],
                sequence: 1,
                acknowledged_through: 0,
                requester: public(seed),
                action: "AuthorityDomain".into(),
                resource: operation.command.resource(),
                revision: u64::from(operation.mutation()),
                profile_generation: 0,
                minimum_policy_epoch: 0,
                minimum_policy_height: 0,
                expected: operation.snapshot.references.clone(),
                parameters: operation.parameters().unwrap(),
                digest: [91; 32],
            };
            let d = operation
                .prepare(
                    &self.state,
                    &self.records,
                    &self.reserved,
                    &intent,
                    5000,
                    false,
                    exact,
                )
                .unwrap();
            if d.code != 0 || exact {
                if d.code == 0
                    && exact
                    && matches!(operation.command, DomainCommand::SealedPublication(_))
                {
                    let state = d.state.as_ref().unwrap_or(&self.state);
                    let repeated = operation
                        .prepare(
                            state,
                            &self.records,
                            &self.reserved,
                            &intent,
                            5000,
                            operation.mutation(),
                            true,
                        )
                        .unwrap();
                    assert_eq!(
                        repeated.code,
                        0,
                        "certified sealed result must remain independently replayable: {}",
                        operation.command.name()
                    );
                    assert_eq!(
                        repeated.value,
                        d.value,
                        "sealed consumer replay must reconstruct the exact result: {}",
                        operation.command.name()
                    );
                }
                if let Some(state) = &d.state {
                    self.state = state.clone();
                    State::parse(&self.state.value(), [20; 32], [21; 32]).unwrap();
                }
                return d;
            }
            snapshot = deployment::snapshot(&d.dependencies);
        }
        unreachable!()
    }
    fn put(&mut self, kind: u64, body: Vec<V>, seed: u8) -> VersionRef {
        let bytes = signed(kind, body, seed);
        let record = Record::parse(&bytes, [20; 32], [21; 32]).unwrap();
        let reference = record.reference.clone();
        self.state.put(record).unwrap();
        reference
    }
    fn recipients(&mut self) {
        let s = deployment::snapshot(&[]);
        let root = self.put(
            107,
            vec![
                b(&public(5)),
                b(&public(70)),
                b(&[72; 32]),
                s.array(2).unwrap()[0].clone(),
            ],
            70,
        );
        let binding = self.put(
            108,
            vec![
                b(&public(5)),
                reference(&root),
                b(&[83; 32]),
                b(&public(73)),
                b(&[74; 32]),
                a(vec![V::Uint(0)]),
                a(vec![V::Uint(1000), V::Uint(19000)]),
            ],
            70,
        );
        let admission = self.put(
            109,
            vec![
                b(&public(5)),
                reference(&binding),
                a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
                a(vec![V::Uint(1000), V::Uint(19000)]),
                b(&[75; 32]),
                s.clone(),
            ],
            5,
        );
        let audience = self.put(
            110,
            vec![
                b(&[76; 32]),
                b(&public(5)),
                a(vec![reference(&root)]),
                a(vec![]),
                V::Null,
                V::Bool(false),
                s.clone(),
            ],
            5,
        );
        self.put(
            111,
            vec![
                b(&[77; 32]),
                V::Uint(1),
                V::Uint(1),
                reference(&audience),
                a(vec![b(&root.digest)]),
                a(vec![a(vec![
                    b(&root.digest),
                    b(&binding.digest),
                    b(&admission.digest),
                ])]),
                s,
            ],
            5,
        );
        domains::result::derive_keys(&mut self.state).unwrap();
    }
    fn placement(&self) -> Placement {
        Placement {
            hosts: vec![public(100)],
            volumes: vec![[101; 32]],
            backups: vec![],
            copies: 1,
        }
    }
    fn policy(&mut self) {
        let audience = self.state.record(110, [76; 32]).unwrap().reference.clone();
        let place = self.placement();
        let d = self.run(
            |s| {
                Command::Policy {
                    policy: signed_record(
                        &signed(
                            104,
                            vec![
                                b(&[78; 32]),
                                b(&page::namespace_id("Books").unwrap()),
                                b(&public(5)),
                                reference(&audience),
                                a(vec![V::Uint(1)]),
                                V::Bool(false),
                                place.value(),
                                s.array(2).unwrap()[0].clone(),
                                V::Null,
                                s.clone(),
                            ],
                            5,
                        ),
                        [20; 32],
                        [21; 32],
                    )
                    .unwrap(),
                }
                .into()
            },
            5,
        );
        assert_eq!(d.code, 0);
    }
    fn stage(&mut self) -> Decision {
        self.stage_revision([77; 32], 1)
    }
    fn stage_revision(&mut self, publication: Digest, revision: u64) -> Decision {
        let policy = self.state.record(104, [78; 32]).unwrap().reference.clone();
        let audience = self.state.record(110, [76; 32]).unwrap().reference.clone();
        let roster = self
            .state
            .record(111, publication)
            .unwrap()
            .reference
            .digest;
        let place = self.placement();
        let host = page::Host::parse(
            &self.state.record(147, public(100)).unwrap().payload,
            [20; 32],
            [21; 32],
        )
        .unwrap();
        let grant = self.grant.clone();
        self.run(
            |s| {
                Command::Stage {
                    outer: signed_record(
                        &signed(
                            113,
                            vec![
                                b(&publication),
                                b(&[78; 32]),
                                V::Uint(revision),
                                V::Uint(revision),
                                reference(&audience),
                                b(&roster),
                                b(&[79; 32]),
                                V::Uint(400),
                                place.value(),
                                a(vec![b(&wire::digest(&host.profile.envelope))]),
                                s.array(2).unwrap()[0].clone(),
                                b(&[80; 32]),
                                s.clone(),
                            ],
                            5,
                        ),
                        [20; 32],
                        [21; 32],
                    )
                    .unwrap(),
                    policy: policy.clone(),
                    author_grant: grant.clone(),
                    namespace: "Books".into(),
                    failure_domains: 1,
                    expires_ms: 17000,
                }
                .into()
            },
            5,
        )
    }
    fn copy(&mut self) {
        self.copy_publication([77; 32]);
    }
    fn copy_publication(&mut self, publication: Digest) {
        let s = PublicationState::parse(
            &self
                .state
                .record(PUBLICATION_STATE, publication)
                .unwrap()
                .payload,
        )
        .unwrap();
        let p = page::content::Placement::parse(
            &self.state.record(159, s.placement.id).unwrap().payload,
        )
        .unwrap();
        let mut receipt = page::content::Copy {
            placement: s.placement,
            host: self.host.clone(),
            digest: p.digest,
            bytes: p.bytes,
            request: [81; 32],
            recorded_ms: 5000,
            expires_ms: 17000,
            envelope: vec![],
        };
        receipt.envelope = wire::sign_envelope(
            &receipt.payload([20; 32], [21; 32]).unwrap(),
            &deployment::key(100),
        )
        .unwrap();
        assert_eq!(
            self.run(
                |_| page::Command::Content(page::content::Command::Receipt {
                    receipt: receipt.clone()
                })
                .into(),
                5
            )
            .code,
            0
        );
    }
    fn outer(&self) -> VersionRef {
        self.state.record(113, [77; 32]).unwrap().reference.clone()
    }
    fn revoke(&mut self) {
        let binding = self.state.record(108, [83; 32]).unwrap().reference.clone();
        self.put(
            158,
            vec![
                reference(&binding),
                b(&public(70)),
                deployment::snapshot(&[]),
            ],
            70,
        );
    }
}
#[test]
fn sealed_publication_requires_durable_copy_and_revocation_stops_serving() {
    let mut f = Fixture::new();
    f.policy();
    assert_eq!(f.stage().code, 0);
    let outer = f.outer();
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
    f.copy();
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
    let device = f.state.record(108, [83; 32]).unwrap().reference.clone();
    assert_eq!(
        f.run(
            |_| Command::Read {
                outer: outer.clone(),
                device: device.clone()
            }
            .into(),
            73
        )
        .code,
        0
    );
    f.revoke();
    assert_ne!(
        f.run(
            |_| Command::Read {
                outer: outer.clone(),
                device: device.clone()
            }
            .into(),
            73
        )
        .code,
        0
    );
}
#[test]
fn sealed_finalisation_refuses_a_roster_removed_after_freeze() {
    let mut f = Fixture::new();
    f.policy();
    f.revoke();
    assert_ne!(f.stage().code, 0);
    assert!(!f.state.records.contains_key(&(113, [77; 32])));
}

#[test]
fn sealed_publication_refuses_stream_and_broad_review_authority() {
    let mut f = Fixture::new();
    f.policy();
    let precise = f.reviewer.clone();
    let mixed = deployment::scoped_grant(
        &mut f.records,
        &f.grant,
        [233; 32],
        &[(2, [78; 32]), (3, [78; 32])],
    );
    let stream = deployment::scoped_grant(&mut f.records, &f.grant, [234; 32], &[(3, [78; 32])]);
    for grant in [f.grant.clone(), mixed, stream] {
        f.reviewer = grant;
        assert_eq!(f.stage().code, 3);
        assert!(!f.state.records.contains_key(&(113, [77; 32])));
    }
    f.reviewer = precise;
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
    let device = f.state.record(108, [83; 32]).unwrap().reference.clone();
    assert_eq!(
        f.run(
            |_| Command::Read {
                outer: outer.clone(),
                device: device.clone()
            }
            .into(),
            73
        )
        .code,
        0
    );
    // Retained broad-review history remains readable as state, but live serving
    // cannot continue under the ambiguous reviewer permission.
    let mut legacy =
        PublicationState::parse(&f.state.record(PUBLICATION_STATE, outer.id).unwrap().payload)
            .unwrap();
    legacy.reviewer_grant = f.grant.clone();
    let next = Record::next(&f.state, PUBLICATION_STATE, outer.id, legacy.value()).unwrap();
    f.state.records.insert(next.reference.index(), next);
    f.state = State::parse(&f.state.value(), [20; 32], [21; 32]).unwrap();
    assert_eq!(
        f.run(
            |_| Command::Read {
                outer: outer.clone(),
                device: device.clone()
            }
            .into(),
            73
        )
        .code,
        3
    );
}
#[test]
fn sealed_withdrawal_tombstones_exact_stored_ciphertext() {
    let mut f = Fixture::new();
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
    let s = PublicationState::parse(&f.state.record(162, outer.id).unwrap().payload).unwrap();
    assert_eq!(
        f.run(
            |_| Command::Withdraw {
                outer: outer.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    assert!(f.state.records.contains_key(&(161, s.placement.id)));
    assert_eq!(
        PublicationState::parse(&f.state.record(162, outer.id).unwrap().payload)
            .unwrap()
            .status,
        2
    );
}

#[test]
fn sealed_namespace_refuses_plaintext_metadata_before_host_admission() {
    let mut f = Fixture::new();
    f.policy();
    assert_eq!(
        f.run(
            |_| Command::Namespace {
                namespace: "Books".into(),
                modes: vec![1]
            }
            .into(),
            5
        )
        .code,
        0
    );
    let source = b"HyperNetPage/2\n# Confidential\n: Private text.\n";
    let parameters =
        page::objects::Author::parameters([71; 16], "Books", source, &f.grant, None, 17000)
            .unwrap();
    let bytes = deployment::signed(
        &deployment::key(5),
        "PageAuthorStatement",
        page::page_id(&[71; 16]).unwrap(),
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let author = page::objects::Author::parse(&bytes, [20; 32], [21; 32]).unwrap();
    assert_ne!(
        f.run(
            |_| page::Command::Submit {
                author: author.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    assert!(!f.state.records.values().any(|r| r.reference.kind == 141));
    assert_eq!(f.stage().code, 0);
}
#[test]
fn sealed_reviewer_prepare_returns_complete_object_scoped_dependencies() {
    let mut f = Fixture::new();
    f.policy();
    let roster = f.state.record(111, [77; 32]).unwrap().reference.clone();
    let grant = f.grant.clone();
    let d = f.run(
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
    );
    assert_eq!(d.code, 0);
    let body = d.value.array(5).unwrap()[4].array(4).unwrap();
    let mut selected = State::empty([20; 32], [21; 32]);
    for bytes in body[1].list(64).unwrap() {
        let r = Record::parse(bytes.bytes().unwrap(), [20; 32], [21; 32]).unwrap();
        selected.records.insert(r.reference.index(), r);
    }
    domains::result::derive_keys(&mut selected).unwrap();
    for kind in [104, 107, 108, 109, 110, 111, 147] {
        assert!(
            selected.records.values().any(|r| r.reference.kind == kind),
            "missing current dependency {kind}"
        );
    }
    f.state = selected;
    assert_eq!(f.stage().code, 0);
}

#[test]
fn sealed_replacement_replays_exact_prior_withdrawal_and_tombstone() {
    let mut f = Fixture::new();
    f.policy();
    assert_eq!(f.stage().code, 0);
    f.copy();
    let old = f.outer();
    assert_eq!(
        f.run(|_| Command::Commit { outer: old.clone() }.into(), 5)
            .code,
        0
    );
    let old_state =
        PublicationState::parse(&f.state.record(PUBLICATION_STATE, old.id).unwrap().payload)
            .unwrap();
    let record = f.state.record(111, [77; 32]).unwrap();
    let mut body = record.payload.list(16).unwrap().to_vec();
    body[0] = b(&[84; 32]);
    body[1] = V::Uint(2);
    body[2] = V::Uint(2);
    f.put(111, body, 5);
    assert_eq!(f.stage_revision([84; 32], 2).code, 0);
    f.copy_publication([84; 32]);
    let next = f.state.record(113, [84; 32]).unwrap().reference.clone();
    assert_eq!(
        f.run(
            |_| Command::Commit {
                outer: next.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    assert_eq!(
        PublicationState::parse(&f.state.record(PUBLICATION_STATE, old.id).unwrap().payload)
            .unwrap()
            .status,
        2
    );
    assert_eq!(
        page::content::Tombstone::parse(
            &f.state.record(161, old_state.placement.id).unwrap().payload
        )
        .unwrap()
        .placement,
        old_state.placement
    );
}

#[path = "../Authority/AuthorityLocalSearchLeaseTests.rs"]
mod local_search_tests;
