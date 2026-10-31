// SPDX-License-Identifier: MIT
use super::*;
use crate::trust_bootstrap::{
    self as bootstrap, Assurance, DraftSpec, RecoveryKey, RecoverySpec, RouteSpec,
};
use ed25519_dalek::SigningKey;

pub(crate) struct Fixture {
    pub app: PolicyApplication,
    pub initial: Vec<u8>,
    pub bootstrap: Vec<u8>,
    pub requester: SigningKey,
    pub expected: Vec<VersionRef>,
    pub grant: [u8; 32],
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().to_bytes())
}
impl Fixture {
    pub fn new() -> Self {
        Self::at(1000)
    }
    pub fn configuration(&self) -> &Configuration {
        &self.app.config
    }
    pub fn at(now: u64) -> Self {
        Self::with_actions(now, vec![25])
    }
    pub fn with_actions(now: u64, actions: Vec<u64>) -> Self {
        Self::with_administrators(now, actions, 0)
    }
    pub fn with_extra_administrator(now: u64, actions: Vec<u64>) -> Self {
        Self::with_administrators(now, actions, 1)
    }
    pub fn with_receipt_capacity_administrators(now: u64, actions: Vec<u64>) -> Self {
        let count = crate::authority_capacity::MAX_STREAM_BYTES
            .div_ceil(crate::consensus::MAX_RESULT_BYTES);
        Self::with_administrators(now, actions, count)
    }
    fn with_administrators(now: u64, actions: Vec<u64>, extra: usize) -> Self {
        let mut voters = (1..=4).map(public).collect::<Vec<_>>();
        voters.sort();
        let mut recovery = (6..=8).map(key).collect::<Vec<_>>();
        recovery.sort_by_key(|k| k.verifying_key().to_bytes());
        let authority_transports = voters
            .iter()
            .enumerate()
            .map(|(index, voter)| (voter.clone(), public(30 + index as u8)))
            .collect();
        let spec = DraftSpec {
            voters,
            authority_transports,
            clock_monitors: vec![public(40)],
            administrator: public(5),
            administrator_actions: actions,
            enrolment: "InvitationOnly".into(),
            public_reading: false,
            minimum_route: Assurance::Independent,
            publication_modes: vec!["HostReadable".into()],
            default_publication_mode: "HostReadable".into(),
            limits: [100, 100, 10, 10],
            recovery: RecoverySpec {
                custody: "OwnerThreshold".into(),
                keys: recovery
                    .iter()
                    .map(|k| RecoveryKey {
                        principal: "11".repeat(32),
                        public_key: hex::encode(k.verifying_key().to_bytes()),
                    })
                    .collect(),
                accepted_keys: recovery[..2]
                    .iter()
                    .map(|k| hex::encode(k.verifying_key().to_bytes()))
                    .collect(),
                immutable_shared: false,
            },
            route: RouteSpec {
                relay_service: "12".repeat(32),
                relay_origin: "https://relay.invalid/".into(),
                relay_transport_key: public(9),
                relay_domain: "13".repeat(32),
                admission_service: "14".repeat(32),
                admission_origin: "https://admission.invalid/".into(),
                admission_transport_key: public(10),
                admission_domain: "15".repeat(32),
                assurance: Assurance::Independent,
                not_before_ms: now.checked_sub(500).unwrap(),
                expires_ms: now.checked_add(999000).unwrap(),
            },
        };
        let draft = bootstrap::draft(spec, [[20; 32], [21; 32], [22; 32], [23; 32]], now).unwrap();
        let draft = if extra > 0 {
            // Independent roots are authenticated by the completed bootstrap,
            // not inserted later without a member transaction or audit evidence.
            let mut bundle = wire::decode(&draft).unwrap().array(6).unwrap().to_vec();
            let mut genesis = wire::decode(bundle[3].bytes().unwrap())
                .unwrap()
                .array(6)
                .unwrap()
                .to_vec();
            let mut records = genesis[4]
                .list(34)
                .unwrap()
                .iter()
                .map(|v| v.bytes().unwrap().to_vec())
                .collect::<Vec<_>>();
            let template = wire::decode(&records[2])
                .unwrap()
                .array(17)
                .unwrap()
                .to_vec();
            let mut roots = vec![b(&[23; 32])];
            let mut roles = Reservations::parse(&genesis[5]).unwrap();
            for index in 0..extra {
                let offset = u8::try_from(index).unwrap();
                let subject = key(77u8.checked_add(offset).unwrap())
                    .verifying_key()
                    .to_bytes();
                let id = [92u8.checked_add(offset).unwrap(); 32];
                let mut grant = template.clone();
                grant[6] = b(&id);
                grant[7] = b(&subject);
                grant[8] = grant[7].clone();
                records.push(wire::encode(&array(grant)).unwrap());
                roots.push(b(&id));
                roles.0.push((4, subject));
            }
            let mut policy = wire::decode(&records[0])
                .unwrap()
                .array(17)
                .unwrap()
                .to_vec();
            policy[15] = array(roots);
            records[0] = wire::encode(&array(policy)).unwrap();
            let policy_digest = wire::digest(&records[0]);
            crate::authority_membership::sort_records(&mut records).unwrap();
            genesis[4] = array(records.iter().map(|v| b(v)).collect());
            roles.0.sort();
            genesis[5] = roles.value();
            let initial = wire::encode(&array(genesis)).unwrap();
            let mut descriptor = wire::decode(bundle[2].bytes().unwrap())
                .unwrap()
                .array(11)
                .unwrap()
                .to_vec();
            descriptor[6] = b(&policy_digest);
            descriptor[8] = b(&wire::digest(&initial));
            bundle[2] = b(&wire::encode(&array(descriptor)).unwrap());
            bundle[3] = b(&initial);
            wire::encode(&array(bundle)).unwrap()
        } else {
            draft
        };
        let acceptances = recovery[..2]
            .iter()
            .map(|k| bootstrap::accept(&draft, k, now).unwrap())
            .collect::<Vec<_>>();
        let complete = bootstrap::assemble(&draft, &acceptances, now).unwrap();
        let verified = bootstrap::check(&complete, true, now).unwrap();
        let config = Configuration::trusted(verified.descriptor().canonical()).unwrap();
        let initial = wire::decode(&complete).unwrap().array(6).unwrap()[3]
            .bytes()
            .unwrap()
            .to_vec();
        let state = State::parse(&config, &initial).unwrap();
        let governance = Governance::parse(
            config.scope.network,
            config.scope.incarnation,
            &state.records,
        )
        .unwrap();
        let expected = governance.versions();
        let grant = expected.iter().find(|r| r.kind == 102).unwrap().id;
        Self {
            app: PolicyApplication::new(config),
            initial,
            bootstrap: complete,
            requester: key(5),
            expected,
            grant,
        }
    }
    pub fn intent(&self, sequence: u8, expected: &[VersionRef], revision: u64) -> Vec<u8> {
        let c = &self.app.config;
        let parameters = wire::encode(&array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityInspect".into()),
            b(&self.grant),
            V::Uint(100),
            b(&c.scope.network),
        ]))
        .unwrap();
        let payload = wire::encode(&array(vec![
            V::Uint(20),
            V::Uint(1),
            b(&c.scope.network),
            b(&c.scope.incarnation),
            V::Uint(1),
            b(&streams::initial_id(
                c.scope.network,
                c.scope.incarnation,
                self.requester.verifying_key().to_bytes(),
            )
            .unwrap()),
            V::Uint(u64::from(sequence)),
            V::Uint(u64::from(sequence) - 1),
            b(&self.requester.verifying_key().to_bytes()),
            V::Text("AuthorityInspect".into()),
            b(&c.scope.network),
            V::Uint(revision),
            V::Uint(0),
            V::Uint(c.scope.epoch),
            V::Uint(0),
            array(expected.iter().map(reference).collect()),
            b(&parameters),
        ]))
        .unwrap();
        wire::sign_envelope(&payload, &self.requester).unwrap()
    }
    pub fn committed(&self, intent: &[u8], created: u64, evaluated: u64, height: u64) -> Committed {
        self.with_recipient(intent, created, evaluated, height, &self.requester)
    }
    pub(super) fn with_recipient(
        &self,
        intent: &[u8],
        created: u64,
        evaluated: u64,
        height: u64,
        recipient: &SigningKey,
    ) -> Committed {
        let c = &self.app.config;
        let parsed = SignedRequest::from_signed(intent).unwrap();
        let challenge = wire::encode(&array(vec![
            V::Uint(21),
            V::Uint(1),
            b(&c.scope.network),
            b(&c.scope.incarnation),
            b(&recipient.verifying_key().to_bytes()),
            b(&[30; 32]),
            b(&[height as u8; 32]),
            b(&parsed.digest()),
            b(&[31; 32]),
            V::Uint(created),
            V::Uint(created + 5000),
            V::Uint(5000),
        ]))
        .unwrap();
        let challenge = wire::sign_envelope(&challenge, recipient).unwrap();
        let command = wire::encode(&array(vec![
            V::Uint(22),
            V::Uint(1),
            c.scope.value(),
            b(intent),
            b(&challenge),
            V::Uint(created + 5000),
        ]))
        .unwrap();
        Committed {
            node: [height as u8; 32],
            height,

            evaluated_at: evaluated,
            command,
        }
    }
}
pub(super) fn result_bytes(execution: &Execution) -> &[u8] {
    match &execution.output {
        ExecutionOutput::Result { result, .. } => result,
        ExecutionOutput::Inert => panic!("expected a certified operation result"),
    }
}
pub(crate) fn state_parses(application: &PolicyApplication) -> usize {
    application
        .state_parses
        .load(std::sync::atomic::Ordering::Relaxed)
}
fn attestation_bytes(execution: &Execution) -> &[u8] {
    match &execution.output {
        ExecutionOutput::Result { attestation, .. } => attestation,
        ExecutionOutput::Inert => panic!("inert positions have no result attestation"),
    }
}
fn code(result: &Execution) -> u64 {
    wire::decode(result_bytes(result))
        .unwrap()
        .array(6)
        .unwrap()[4]
        .uint()
        .unwrap()
}
#[test]
fn imported_checkpoint_state_requires_exact_configuration_and_applied_height() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    let applied = f
        .app
        .execute(
            &f.initial,
            &f.committed(&intent, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    f.app.validate_checkpoint(&applied.state, 1).unwrap();
    assert!(f.app.validate_checkpoint(&applied.state, 2).is_err());
    assert!(f.app.validate_checkpoint(&f.initial, 1).is_err());
    let mut obsolete = wire::decode(&applied.state)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    obsolete.push(V::Bool(false));
    assert!(
        f.app
            .validate_checkpoint(&wire::encode(&array(obsolete)).unwrap(), 1)
            .is_err()
    );
    for index in [2, 3, 4] {
        let mut changed = wire::decode(&applied.state).unwrap();
        let V::Array(fields) = &mut changed else {
            unreachable!()
        };
        fields[index] = if index == 4 { V::Uint(1) } else { b(&[99; 32]) };
        assert!(
            f.app
                .validate_checkpoint(&wire::encode(&changed).unwrap(), 1)
                .is_err()
        );
    }
}
#[test]
fn independently_executed_inspection_is_exact_and_replay_preserves_logical_result() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    let committed = f.committed(&intent, 10000, 11251, 1);
    let one = f
        .app
        .execute(
            &f.initial,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let two = f
        .app
        .execute(
            &f.initial,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&one), 0);
    assert_eq!(one.state, two.state);
    assert_eq!(result_bytes(&one), result_bytes(&two));
    assert_eq!(attestation_bytes(&one), attestation_bytes(&two));
    let value = wire::decode(result_bytes(&one)).unwrap();
    let value = wire::decode(value.array(6).unwrap()[5].bytes().unwrap()).unwrap();
    let dependencies = value.array(5).unwrap()[3].list(64).unwrap();
    let expected = f
        .expected
        .iter()
        .filter(|v| matches!(v.kind, 100 | 101 | 102 | 114))
        .map(reference)
        .collect::<Vec<_>>();
    assert_eq!(dependencies, expected.as_slice());
    let retry = f
        .app
        .execute(
            &one.state,
            &f.committed(&intent, 15000, 16251, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_bytes(&retry), result_bytes(&one));
    assert_ne!(attestation_bytes(&retry), attestation_bytes(&one));
    let state = State::parse(&f.app.config, &retry.state).unwrap();
    let completion = state
        .streams
        .metadata(&f.requester.verifying_key().to_bytes())
        .unwrap()
        .unwrap()
        .completion
        .unwrap();
    assert_eq!(completion.sequence, 1);
    assert_eq!(completion.result_digest, wire::digest(result_bytes(&one)));
    assert!(
        f.app
            .execute(
                &one.state,
                &committed,
                &crate::authority_objects::Resolved::default()
            )
            .is_err()
    );
}
#[test]
fn current_dependencies_and_operation_identity_cannot_be_substituted() {
    let f = Fixture::new();
    let empty = f.intent(1, &[], 1);
    let refusal = f
        .app
        .execute(
            &f.initial,
            &f.committed(&empty, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&refusal), 3);
    let proper = f.intent(1, &f.expected, 1);
    let conflict = f
        .app
        .execute(
            &refusal.state,
            &f.committed(&proper, 15000, 16251, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&conflict), 28);
    let stale = f.intent(1, &f.expected, 2);
    assert_eq!(
        code(
            &f.app
                .execute(
                    &f.initial,
                    &f.committed(&stale, 10000, 11251, 1),
                    &crate::authority_objects::Resolved::default()
                )
                .unwrap()
        ),
        12
    );
}
#[test]
fn recipient_and_challenge_plausibility_and_expiry_are_enforced() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    assert_eq!(
        code(
            &f.app
                .execute(
                    &f.initial,
                    &f.committed(&intent, 12501, 11250, 1),
                    &crate::authority_objects::Resolved::default()
                )
                .unwrap()
        ),
        7
    );
    assert_eq!(
        code(
            &f.app
                .execute(
                    &f.initial,
                    &f.committed(&intent, 10000, 13750, 1),
                    &crate::authority_objects::Resolved::default()
                )
                .unwrap()
        ),
        7
    );
    assert!(
        f.app
            .execute(
                &f.initial,
                &f.with_recipient(&intent, 10000, 11251, 1, &key(9)),
                &crate::authority_objects::Resolved::default()
            )
            .is_err()
    );
}
#[test]
fn inert_progress_advances_only_height_and_preserves_stream_receipt() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    let applied = f
        .app
        .execute(
            &f.initial,
            &f.committed(&intent, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let mut state = State::parse(&f.app.config, &applied.state).unwrap();
    let prior = state.encode(&f.app.config).unwrap();
    for tag in [V::Null, b(&[99; 32])] {
        let command = wire::encode(&array(vec![
            V::Uint(53),
            V::Uint(1),
            f.app.config.scope.value(),
            tag,
        ]))
        .unwrap();
        let mut position = Committed {
            node: [91; 32],
            height: 2,
            evaluated_at: 100000,
            command,
        };
        f.app
            .validate(
                &prior,
                &position.command,
                position.evaluated_at,
                &crate::authority_objects::Resolved::default(),
            )
            .unwrap();
        let inert = f
            .app
            .execute(
                &prior,
                &position,
                &crate::authority_objects::Resolved::default(),
            )
            .unwrap();
        assert!(matches!(inert.output, ExecutionOutput::Inert));
        state.height = 2;
        assert_eq!(inert.state, state.encode(&f.app.config).unwrap());
        f.app.validate_checkpoint(&inert.state, 2).unwrap();
        assert!(
            f.app
                .execute(
                    &inert.state,
                    &position,
                    &crate::authority_objects::Resolved::default()
                )
                .is_err()
        );
        position.height = 4;
        assert!(
            f.app
                .execute(
                    &inert.state,
                    &position,
                    &crate::authority_objects::Resolved::default()
                )
                .is_err()
        );
    }
}

#[test]
fn inert_progress_refuses_other_scopes_malformed_terminal_tags_and_extensions() {
    let f = Fixture::new();
    let fields = vec![V::Uint(53), V::Uint(1), f.app.config.scope.value(), V::Null];
    for variant in 0..6 {
        let mut changed = fields.clone();
        match variant {
            0 => changed[1] = V::Uint(2),
            1 => {
                let V::Array(scope) = &mut changed[2] else {
                    unreachable!()
                };
                scope[0] = b(&[99; 32]);
            }
            2 => changed[3] = b(&[0; 32]),
            3 => changed[3] = b(&[99; 31]),
            4 => changed[3] = V::Uint(99),
            _ => changed.push(V::Null),
        }
        let command = wire::encode(&array(changed)).unwrap();
        assert!(
            f.app
                .validate(
                    &f.initial,
                    &command,
                    2000,
                    &crate::authority_objects::Resolved::default()
                )
                .is_err()
        );
        let position = Committed {
            node: [91; 32],
            height: 1,

            evaluated_at: 2000,
            command,
        };
        assert!(
            f.app
                .execute(
                    &f.initial,
                    &position,
                    &crate::authority_objects::Resolved::default()
                )
                .is_err()
        );
    }
}

#[test]
fn early_challenge_evaluation_caps_the_result_without_rewriting_the_request() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    for created in [10000, 11250] {
        let committed = f.committed(&intent, created, 10000, 1);
        let original = committed.command.clone();
        let execution = f
            .app
            .execute(
                &f.initial,
                &committed,
                &crate::authority_objects::Resolved::default(),
            )
            .unwrap();
        assert_eq!(code(&execution), 0);
        let value = wire::decode(attestation_bytes(&execution)).unwrap();
        let fields = value.array(23).unwrap();
        assert_eq!(fields[19].uint().unwrap(), 13750);
        assert_eq!(fields[5].fixed::<32>().unwrap(), wire::digest(&original));
        assert_eq!(committed.command, original);
    }
}
