// SPDX-License-Identifier: MIT
// Recipient regressions cover independent ownership, possession, revocation and frozen-roster races.
use super::*;
use crate::authority_deployment_tests as deployment;
#[path = "AuthoritySealedIdentityContextTests.rs"]
mod context;
fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
fn signed(kind: u64, generation: u64, previous: Option<Digest>, body: Vec<V>, seed: u8) -> Vec<u8> {
    let mut f = vec![
        V::Uint(kind),
        V::Uint(1),
        b(&[20; 32]),
        b(&[21; 32]),
        V::Uint(generation),
        previous.as_ref().map_or(V::Null, |v| b(v)),
    ];
    f.extend(body);
    wire::sign_envelope(&wire::encode(&a(f)).unwrap(), &deployment::key(seed)).unwrap()
}
fn custody() -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("RecipientCustody".into()),
        b(&[20; 32]),
        b(&[21; 32]),
        b(&public(5)),
        V::Uint(1),
        a(vec![a(vec![b(&public(5)), b(&public(80))])]),
    ]))
    .unwrap()
}
fn acceptance(root: &VersionRef, previous: Option<&VersionRef>, seed: u8) -> Vec<u8> {
    signed(
        121,
        0,
        None,
        vec![
            b(&[81; 32]),
            b(&public(5)),
            previous.map_or(V::Null, reference),
            reference(root),
            V::Null,
            b(&[82; 32]),
        ],
        seed,
    )
}
fn record(bytes: Vec<u8>) -> Record {
    signed_record(&bytes, [20; 32], [21; 32]).unwrap()
}
struct Fixture {
    state: State,
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    grant: VersionRef,
    reviewer: VersionRef,
}
impl Fixture {
    fn new() -> Self {
        let f = deployment::Fixture::with_actions(vec![0, 4, 10, 11, 12, 23, 29, 30]);
        let grant = Governance::parse(f.scope.network, f.scope.incarnation, &f.records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let mut records = f.records;
        let reviewer = deployment::scoped_grant(&mut records, &grant, [232; 32], &[(2, [87; 32])]);
        Self {
            state: State::empty(f.scope.network, f.scope.incarnation),
            records,
            reserved: f.reservations,
            grant,
            reviewer,
        }
    }
    fn intent(
        &self,
        command: Command,
        snapshot: V,
        seed: u8,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation) {
        let operation = Operation {
            grant,
            command: command.into(),
            snapshot: super::super::snapshot(&snapshot).unwrap(),
        };
        let intent = Intent {
            network: self.state.network,
            incarnation: self.state.incarnation,
            generation: 1,
            generation_id: [90; 32],
            sequence: 1,
            acknowledged_through: 0,
            requester: public(seed),
            action: "AuthorityDomain".into(),
            resource: operation.command.resource(),
            revision: u64::from(operation.mutation()),
            profile_generation: 0,
            minimum_policy_epoch: operation.snapshot.epoch,
            minimum_policy_height: operation.snapshot.height,
            expected: operation.snapshot.references.clone(),
            parameters: operation.parameters().unwrap(),
            digest: [91; 32],
        };
        (intent, operation)
    }
    fn run(
        &mut self,
        build: impl Fn(&V) -> Command,
        seed: u8,
        grant: Option<VersionRef>,
    ) -> Decision {
        let snapshot = deployment::snapshot(&[]);
        let (intent, op) = self.intent(build(&snapshot), snapshot, seed, grant.clone());
        let preview = op
            .prepare(
                &self.state,
                &self.records,
                &self.reserved,
                &intent,
                5000,
                false,
                false,
            )
            .unwrap();
        if preview.code != 0 {
            return preview;
        }
        let snapshot = deployment::snapshot(&preview.dependencies);
        let (intent, op) = self.intent(build(&snapshot), snapshot, seed, grant);
        let decision = op
            .prepare(
                &self.state,
                &self.records,
                &self.reserved,
                &intent,
                5000,
                false,
                true,
            )
            .unwrap();
        if let Some(state) = &decision.state {
            self.state = state.clone();
            State::parse(&state.value(), state.network, state.incarnation).unwrap();
        }
        decision
    }
    fn root(&mut self) {
        let policy = custody();
        let d = self.run(
            |s| {
                let r = record(signed(
                    107,
                    1,
                    None,
                    vec![
                        b(&public(5)),
                        b(&public(70)),
                        b(&wire::digest(&policy)),
                        s.array(2).unwrap()[0].clone(),
                    ],
                    70,
                ));
                Command::Root {
                    acceptance: acceptance(&r.reference, None, 5),
                    root: r,
                    custody: policy.clone(),
                    recovery: None,
                }
            },
            5,
            Some(self.grant.clone()),
        );
        assert_eq!(d.code, 0);
    }
    fn binding(&self, seed: u8, generation: u64, previous: Option<Digest>) -> Record {
        let root = &self.state.record(107, public(5)).unwrap().reference;
        record(signed(
            108,
            generation,
            previous,
            vec![
                b(&public(5)),
                reference(root),
                b(&[83; 32]),
                b(&public(seed)),
                b(&[seed + 1; 32]),
                a(vec![V::Uint(0)]),
                a(vec![V::Uint(1000), V::Uint(15000)]),
            ],
            70,
        ))
    }
    fn device(&mut self, seed: u8, wrong: bool) -> Decision {
        self.device_with_purpose(seed, wrong, false)
    }
    fn device_with_purpose(&mut self, seed: u8, wrong: bool, enrol: bool) -> Decision {
        let prior = self
            .state
            .records
            .get(&(108, [83; 32]))
            .map(|r| r.reference.clone());
        let mut binding = self.binding(
            seed,
            prior.as_ref().map_or(1, |r| r.generation + 1),
            prior.as_ref().map(|r| r.digest),
        );
        if enrol {
            let mut fields = wire::decode(&payload(&binding).unwrap())
                .unwrap()
                .array(13)
                .unwrap()
                .to_vec();
            fields[11] = a(vec![V::Uint(0), V::Uint(1)]);
            binding = record(
                wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), &deployment::key(70))
                    .unwrap(),
            );
        }
        self.run(
            |s| {
                let challenge = signed(
                    123,
                    0,
                    None,
                    vec![
                        b(&[84; 32]),
                        b(&binding.reference.digest),
                        b(&public(5)),
                        b(&[85; 32]),
                        V::Uint(10000),
                    ],
                    5,
                );
                let digest = wire::digest(&wire::envelope(&challenge, 1).unwrap().0);
                let possession = signed(
                    122,
                    0,
                    None,
                    vec![
                        b(&[84; 32]),
                        b(&binding.reference.digest),
                        b(&public(5)),
                        b(&digest),
                        V::Uint(10000),
                    ],
                    if wrong { 79 } else { seed },
                );
                let admission = record(signed(
                    109,
                    1,
                    None,
                    vec![
                        b(&public(5)),
                        reference(&binding.reference),
                        a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
                        a(vec![V::Uint(1000), V::Uint(15000)]),
                        b(&wire::digest(&wire::envelope(&possession, 1).unwrap().0)),
                        s.clone(),
                    ],
                    5,
                ));
                Command::Device {
                    binding: binding.clone(),
                    admission: Box::new(admission),
                    challenge,
                    possession,
                    delegate: None,
                }
            },
            5,
            Some(self.grant.clone()),
        )
    }
    fn revoke(&mut self, target: VersionRef, seed: u8) -> Decision {
        let grant = if target.kind == 109 {
            Some(self.grant.clone())
        } else {
            None
        };
        self.run(
            |s| Command::Revoke {
                revocation: record(signed(
                    158,
                    1,
                    None,
                    vec![reference(&target), b(&public(seed)), s.clone()],
                    seed,
                )),
            },
            seed,
            grant,
        )
    }
    fn audience(&mut self) {
        let root = self.state.record(107, public(5)).unwrap().reference.clone();
        let d = self.run(
            |s| Command::Audience {
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
                        s.clone(),
                    ],
                    5,
                )),
                acceptances: vec![acceptance(&root, None, 5)],
            },
            5,
            Some(self.grant.clone()),
        );
        assert_eq!(d.code, 0);
    }
}
#[test]
fn root_device_and_signed_state_survive_roundtrip() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    let r = f.state.record(108, [83; 32]).unwrap();
    assert_eq!(r.reference.digest, wire::digest(&payload(r).unwrap()));
    assert_ne!(r.reference.digest, wire::digest(&r.bytes));
    assert!(f.state.requesters().contains(&public(70)));
    assert!(f.state.requesters().contains(&public(71)));
}
#[test]
fn possession_wrong_signer_and_unowned_replacement_are_refused() {
    let mut f = Fixture::new();
    f.root();
    assert_ne!(f.device(71, true).code, 0);
    assert!(!f.state.records.contains_key(&(108, [83; 32])));
    assert_eq!(f.device(71, false).code, 0);
    assert_ne!(f.device(73, false).code, 0);
}
#[test]
fn revocation_cannot_reuse_old_keys_even_for_same_owner() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    let old = f.state.record(108, [83; 32]).unwrap().reference.clone();
    assert_ne!(f.revoke(old.clone(), 5).code, 0);
    assert_eq!(f.revoke(old, 70).code, 0);
    assert_ne!(f.device(71, false).code, 0);
    assert_eq!(f.device(73, false).code, 0);
    assert!(f.state.keys.contains_key(&public(71)));
}
#[test]
fn network_member_cannot_substitute_recipient_root() {
    let mut f = Fixture::new();
    f.root();
    let old = f.state.record(107, public(5)).unwrap().reference.clone();
    let policy = custody();
    let d = f.run(
        |s| {
            let root = record(signed(
                107,
                2,
                Some(old.digest),
                vec![
                    b(&public(5)),
                    b(&public(74)),
                    b(&wire::digest(&policy)),
                    s.array(2).unwrap()[0].clone(),
                ],
                74,
            ));
            Command::Root {
                acceptance: acceptance(&root.reference, Some(&old), 5),
                root,
                custody: policy.clone(),
                recovery: None,
            }
        },
        5,
        Some(f.grant.clone()),
    );
    assert_ne!(d.code, 0);
    assert_eq!(f.state.record(107, public(5)).unwrap().reference, old);
}
#[test]
fn frozen_roster_rechecks_removal_at_commit() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    f.audience();
    let audience_record = f.state.record(110, [86; 32]).unwrap();
    let audience = Audience::parse(
        &payload(audience_record).unwrap(),
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    let governance = Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let CurrentRoster { roots, devices, .. } =
        roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).unwrap();
    let admission = f.state.record(109, devices[0].1).unwrap().reference.clone();
    assert_eq!(f.revoke(admission, 5).code, 0);
    let d = f.run(
        |s| Command::Freeze {
            roster: record(signed(
                111,
                1,
                None,
                vec![
                    b(&[87; 32]),
                    V::Uint(1),
                    V::Uint(1),
                    reference(&audience.reference),
                    a(roots.iter().map(|r| b(r)).collect()),
                    a(devices
                        .iter()
                        .map(|(r, binding, a_)| a(vec![b(r), b(binding), b(a_)]))
                        .collect()),
                    s.clone(),
                ],
                5,
            )),
            scope: (2, [87; 32]),
        },
        5,
        Some(f.reviewer.clone()),
    );
    assert_ne!(d.code, 0);
    assert!(!f.state.records.contains_key(&(111, [87; 32])));
}

#[test]
fn current_roster_commits_its_complete_dependency_snapshot() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    f.audience();
    let audience = Audience::parse(
        &payload(f.state.record(110, [86; 32]).unwrap()).unwrap(),
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    let governance = Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let CurrentRoster { roots, devices, .. } =
        roster(&f.state, &governance, &audience, 5000, (2, [87; 32])).unwrap();
    let freeze = |s: &V| Command::Freeze {
        roster: record(signed(
            111,
            1,
            None,
            vec![
                b(&[87; 32]),
                V::Uint(1),
                V::Uint(1),
                reference(&audience.reference),
                a(roots.iter().map(|r| b(r)).collect()),
                a(devices
                    .iter()
                    .map(|(r, d, a_)| a(vec![b(r), b(d), b(a_)]))
                    .collect()),
                s.clone(),
            ],
            5,
        )),
        scope: (2, [87; 32]),
    };
    assert_eq!(f.run(freeze, 5, Some(f.grant.clone())).code, 3);
    assert!(!f.state.records.contains_key(&(111, [87; 32])));
    let mixed = deployment::scoped_grant(
        &mut f.records,
        &f.grant,
        [233; 32],
        &[(2, [87; 32]), (3, [87; 32])],
    );
    assert_eq!(f.run(freeze, 5, Some(mixed)).code, 3);
    let d = f.run(freeze, 5, Some(f.reviewer.clone()));
    assert_eq!(d.code, 0);
    for kind in [107, 108, 109, 110] {
        assert!(d.dependencies.iter().any(|r| r.kind == kind));
    }
    let frozen = Roster::parse(
        &payload(f.state.record(111, [87; 32]).unwrap()).unwrap(),
        f.state.network,
        f.state.incarnation,
    )
    .unwrap();
    assert_eq!(frozen.snapshot.references, d.dependencies);
}

#[test]
fn directory_requires_capability_and_returns_only_the_exact_member() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device(71, false).code, 0);
    let d = f.run(
        |_| Command::Directory {
            member: public(5),
            view: None,
            after: None,
        },
        5,
        Some(f.grant.clone()),
    );
    assert_eq!(d.code, 0);
    let body = d.value.array(5).unwrap()[4].array(4).unwrap();
    assert_eq!(body[1].list(16).unwrap().len(), 3);
    let view = body[3].array(2).unwrap()[0].fixed::<32>().unwrap();
    assert_ne!(view, [0; 32]);
    let denied = f.run(
        |_| Command::Directory {
            member: public(5),
            view: None,
            after: None,
        },
        70,
        None,
    );
    assert_eq!(denied.code, 3);
    let other = f.run(
        |_| Command::Directory {
            member: [99; 32],
            view: None,
            after: None,
        },
        5,
        Some(f.grant.clone()),
    );
    assert_eq!(other.code, 0);
    assert!(
        other.value.array(5).unwrap()[4].array(4).unwrap()[1]
            .list(16)
            .unwrap()
            .is_empty()
    );
    let changed = f.run(
        |_| Command::Directory {
            member: public(5),
            view: Some([99; 32]),
            after: Some((107, public(5))),
        },
        5,
        Some(f.grant.clone()),
    );
    assert_ne!(changed.code, 0);
}

#[test]
fn encryption_key_aliases_cannot_escape_permanent_reservations() {
    let canonical = [9; 32];
    validate_encryption_key(canonical).unwrap();
    let mut alias = canonical;
    alias[31] |= 0x80;
    assert!(validate_encryption_key(alias).is_err());
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    assert!(validate_encryption_key(prime).is_err());
    assert!(validate_encryption_key([0; 32]).is_err());
    let mut state = State::empty([20; 32], [21; 32]);
    state.keys.insert(alias, (ENCRYPTION_KEY, [5; 32]));
    assert!(validate_state(&state, false).is_err());
}

#[test]
fn ordinary_root_rotation_requires_both_owner_keys_and_keeps_old_key_reserved() {
    use ed25519_dalek::Signer;
    let mut f = Fixture::new();
    f.root();
    let old = f.state.record(107, public(5)).unwrap().reference.clone();
    let policy = custody();
    let d = f.run(
        |s| {
            let envelope = signed(
                107,
                2,
                Some(old.digest),
                vec![
                    b(&public(5)),
                    b(&public(74)),
                    b(&wire::digest(&policy)),
                    s.array(2).unwrap()[0].clone(),
                ],
                74,
            );
            let (body, mut signatures) = wire::envelope(&envelope, 1).unwrap();
            signatures.push((
                public(70),
                deployment::key(70)
                    .sign(&wire::signature_message(&body, &public(70)))
                    .to_bytes(),
            ));
            signatures.sort_by_key(|(key, _)| *key);
            let root = record(
                wire::encode(&a(vec![
                    V::Uint(0),
                    V::Uint(1),
                    b(&body),
                    a(signatures
                        .iter()
                        .map(|(key, signature)| a(vec![b(key), b(signature)]))
                        .collect()),
                ]))
                .unwrap(),
            );
            Command::Root {
                acceptance: acceptance(&root.reference, Some(&old), 5),
                root,
                custody: policy.clone(),
                recovery: None,
            }
        },
        5,
        Some(f.grant.clone()),
    );
    assert_eq!(d.code, 0);
    assert_eq!(
        f.state.record(107, public(5)).unwrap().reference.generation,
        2
    );
    assert!(f.state.keys.contains_key(&public(70)));
    assert!(f.state.keys.contains_key(&public(74)));
}

#[test]
fn delegated_enrolment_requires_exact_current_delegate_admission() {
    let mut f = Fixture::new();
    f.root();
    assert_eq!(f.device_with_purpose(71, false, true).code, 0);
    let delegate = f.state.record(108, [83; 32]).unwrap().reference.clone();
    let root = f.state.record(107, public(5)).unwrap().reference.clone();
    let binding = record(signed(
        108,
        1,
        None,
        vec![
            b(&public(5)),
            reference(&root),
            b(&[88; 32]),
            b(&public(73)),
            b(&[74; 32]),
            a(vec![V::Uint(0)]),
            a(vec![V::Uint(1000), V::Uint(15000)]),
        ],
        71,
    ));
    let build = |s: &V| {
        let challenge = signed(
            123,
            0,
            None,
            vec![
                b(&[89; 32]),
                b(&binding.reference.digest),
                b(&public(5)),
                b(&[90; 32]),
                V::Uint(10000),
            ],
            5,
        );
        let proof = signed(
            122,
            0,
            None,
            vec![
                b(&[89; 32]),
                b(&binding.reference.digest),
                b(&public(5)),
                b(&wire::digest(&wire::envelope(&challenge, 1).unwrap().0)),
                V::Uint(10000),
            ],
            73,
        );
        let admission = record(signed(
            109,
            1,
            None,
            vec![
                b(&public(5)),
                reference(&binding.reference),
                a(vec![a(vec![V::Uint(0), b(&[20; 32])])]),
                a(vec![V::Uint(1000), V::Uint(15000)]),
                b(&wire::digest(&wire::envelope(&proof, 1).unwrap().0)),
                s.clone(),
            ],
            5,
        ));
        Command::Device {
            binding: binding.clone(),
            admission: Box::new(admission),
            challenge,
            possession: proof,
            delegate: Some(delegate.clone()),
        }
    };
    let prior = f.state.clone();
    assert_eq!(f.run(build, 5, Some(f.grant.clone())).code, 0);
    f.state = prior;
    let admission = f
        .state
        .record(109, delegate.digest)
        .unwrap()
        .reference
        .clone();
    assert_eq!(f.revoke(admission, 5).code, 0);
    assert_ne!(f.run(build, 5, Some(f.grant.clone())).code, 0);
    assert!(!f.state.records.contains_key(&(108, [88; 32])));
}
