// SPDX-License-Identifier: MIT

use super::*;
use crate::authority_challenge::boot_time_ms;
use crate::authority_proof::tests::Fixture;
use crate::trust_wire::{self as wire, Value as V};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "AuthorityReadFloorTests.rs"]
mod read;

#[path = "AuthorityFloorClockTests.rs"]
mod clock;

fn health() -> ClockHealth {
    ClockHealth::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        boot_time_ms().unwrap(),
        boot_time_ms().unwrap() + 30000,
        100,
    )
    .unwrap()
    .frozen()
}
pub(crate) struct Directory(pub(crate) PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "HyperNetAuthorityFloor{}",
            crate::random_hex::<16>()
        ));
        files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture(session: &mut Session, sample: ClockHealth) -> Fixture {
    let mut f = Fixture::new(sample.observe().unwrap().wall_ms);
    f.challenge = session
        .issue(&f.intent, &f.recipient, [91; 32], 5000, sample)
        .unwrap();
    f.rebuild();
    f
}
fn expected(f: &mut Fixture, values: &[VersionRef]) {
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let value = wire::decode(&payload).unwrap();
    let mut fields = value.array(17).unwrap().to_vec();
    fields[15] = V::Array(
        values
            .iter()
            .map(|v| {
                V::Array(vec![
                    V::Uint(v.kind),
                    V::Bytes(v.id.to_vec()),
                    V::Uint(v.generation),
                    V::Bytes(v.digest.to_vec()),
                ])
            })
            .collect(),
    );
    let payload = wire::encode(&V::Array(fields)).unwrap();
    f.intent = wire::sign_envelope(&payload, &SigningKey::from_bytes(&[1; 32])).unwrap();
    let (challenge, _) = wire::envelope(&f.challenge, 1).unwrap();
    let value = wire::decode(&challenge).unwrap();
    let mut fields = value.array(12).unwrap().to_vec();
    fields[7] = V::Bytes(wire::digest(&payload).to_vec());
    f.challenge =
        wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &f.recipient).unwrap();
}
fn expired_refusal(first: &Fixture, time: u64, expectations: &[VersionRef]) -> Fixture {
    let mut f = Fixture::new(time - 10000);
    f.intent = first.intent.clone();
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let (challenge, _) = wire::envelope(&f.challenge, 1).unwrap();
    let V::Array(mut fields) = wire::decode(&challenge).unwrap() else {
        unreachable!()
    };
    fields[7] = V::Bytes(wire::digest(&payload).to_vec());
    f.challenge =
        wire::sign_envelope(&wire::encode(&V::Array(fields)).unwrap(), &f.recipient).unwrap();
    let _ = expectations;
    let value = wire::decode(&f.operation).unwrap();
    let mut result = value.array(6).unwrap().to_vec();
    result[3] = V::Uint(1);
    result[4] = V::Uint(7);
    f.operation = wire::encode(&V::Array(result)).unwrap();
    f.evaluated_at = time + 1;
    f.rebuild();
    let value = wire::decode(&f.ancestry[0]).unwrap();
    let mut node = value.array(9).unwrap().to_vec();
    node[3] = V::Uint(2);
    node[4] = V::Uint(2);
    node[5] = V::Bytes(wire::digest(&first.ancestry[0]).to_vec());
    let node = wire::encode(&V::Array(node)).unwrap();
    f.ancestry = vec![first.ancestry[0].clone(), node.clone()];
    let (payload, _) = wire::envelope(&f.certificate, 4).unwrap();
    let value = wire::decode(&payload).unwrap();
    let mut fields = value.array(23).unwrap().to_vec();
    fields[3] = V::Uint(2);
    fields[4] = V::Bytes(wire::digest(&node).to_vec());
    fields[14] = V::Uint(0);
    let payload = wire::encode(&V::Array(fields)).unwrap();
    let signatures = crate::authority_proof::tests::signers()[..3]
        .iter()
        .map(|k| {
            let key = k.verifying_key().to_bytes();
            V::Array(vec![
                V::Bytes(key.to_vec()),
                V::Bytes(
                    k.sign(&wire::signature_message(&payload, &key))
                        .to_bytes()
                        .to_vec(),
                ),
            ])
        })
        .collect();
    f.certificate = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        V::Bytes(payload),
        V::Array(signatures),
    ]))
    .unwrap();
    f
}
#[test]
fn certified_floor_survives_restart_and_partial_restore_is_refused() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    let initial = std::fs::read(directory.0.join(FLOOR)).unwrap();
    let permit = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    assert_eq!(store.prefix().height(), 1);
    assert_eq!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                64,
                |_| Ok(()),
                |r, _| Ok(r.action.clone())
            )
            .unwrap(),
        "ReadPage"
    );
    assert!(
        store
            .accept(f.verify().unwrap(), &mut session, sample, 0)
            .is_err()
    );
    let current = std::fs::read(directory.0.join(FLOOR)).unwrap();
    drop(store);
    let reopened = Store::open(&directory.0, f.descriptor.clone()).unwrap();
    assert_eq!(reopened.prefix().height(), 1);
    drop(reopened);
    std::fs::write(directory.0.join(FLOOR), initial).unwrap();
    assert!(Store::open(&directory.0, f.descriptor.clone()).is_err());
    std::fs::write(directory.0.join(FLOOR), current).unwrap();
    std::fs::remove_file(directory.0.join(WITNESS)).unwrap();
    assert!(Store::open(&directory.0, f.descriptor.clone()).is_err());
}
#[test]
fn duplicate_permits_do_not_repeat_effects_or_reset_deadlines() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    let first = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    let second = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    first
        .perform(
            &mut store,
            &mut session,
            sample,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(
        second
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("duplicate effect") }
            )
            .is_err()
    );
    let f = fixture(&mut session, sample);
    let directory = Directory::new();
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    let permit = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                65,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("oversized effect") }
            )
            .is_err()
    );
    let permit = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| anyhow::bail!("consent withdrawn"),
                |_, _| -> Result<()> { panic!("withdrawn effect") }
            )
            .is_err()
    );
}
#[test]
fn external_floor_change_prevents_effects() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    let permit = store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    std::fs::write(directory.0.join(WITNESS), b"{}").unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("altered floor effect") }
            )
            .is_err()
    );
    assert!(
        store
            .accept(f.verify().unwrap(), &mut session, sample, 0)
            .is_err()
    );
}
#[test]
fn failed_floor_publication_poisoned_state_cannot_be_reused() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        store
            .accept(f.verify().unwrap(), &mut session, sample, 0)
            .is_err()
    );
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(store.poisoned);
    assert!(
        store
            .accept(f.verify().unwrap(), &mut session, sample, 0)
            .is_err()
    );
}
#[test]
fn generation_removal_cannot_be_undone_by_a_later_signed_stale_result() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    let mut first = f.verify().unwrap();
    first.generations = vec![VersionRef {
        kind: 102,
        id: [92; 32],
        generation: 3,
        digest: [93; 32],
    }];
    store.accept(first, &mut session, sample, 0).unwrap();
    let mut stale = f.verify().unwrap();
    let proof::SignedRequest::Intent(stale_intent) = &mut stale.request else {
        unreachable!()
    };
    stale_intent.expected = vec![VersionRef {
        kind: 102,
        id: [92; 32],
        generation: 2,
        digest: [94; 32],
    }];
    assert!(store.accept(stale, &mut session, sample, 0).is_err());
    let mut fork = f.verify().unwrap();
    fork.generations = vec![VersionRef {
        kind: 102,
        id: [92; 32],
        generation: 3,
        digest: [94; 32],
    }];
    assert!(store.accept(fork, &mut session, sample, 0).is_err());
}
#[test]
fn expired_newer_refusal_restricts_older_live_permits_without_installing_expected_versions() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session, sample);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    assert!(store.observe(f.verify().unwrap()).is_err());
    let known = VersionRef {
        kind: 102,
        id: [92; 32],
        generation: 3,
        digest: [93; 32],
    };
    let mut first = f.verify().unwrap();
    first.generations = vec![known.clone()];
    let pending = store.accept(first, &mut session, sample, 0).unwrap();
    let wall_floor = store.stored.wall_floor_ms;
    let refused = expired_refusal(
        &f,
        sample.observe().unwrap().wall_ms,
        &[
            VersionRef {
                kind: 102,
                id: [90; 32],
                generation: 1000,
                digest: [91; 32],
            },
            VersionRef {
                kind: 102,
                id: [92; 32],
                generation: 2,
                digest: [94; 32],
            },
        ],
    );
    let observed = refused.verify().unwrap();
    assert!(observed.executed.expires_at_ms < sample.observe().unwrap().wall_ms);
    assert!(session.check(&observed, 0, sample).is_err());
    store.observe(observed).unwrap();
    assert_eq!(store.prefix().height(), 2);
    assert_eq!(store.stored.wall_floor_ms, wall_floor);
    assert_eq!(store.generations(), std::slice::from_ref(&known));
    assert!(
        pending
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("older permit produced an effect") }
            )
            .is_err()
    );
    drop(store);
    let reopened = Store::open(&directory.0, f.descriptor).unwrap();
    assert_eq!(reopened.prefix().height(), 2);
    assert_eq!(reopened.generations(), &[known]);
    assert_eq!(reopened.stored.wall_floor_ms, wall_floor);
}
#[test]
fn signed_expectations_alone_never_install_a_generation_floor() {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let mut f = Fixture::new(sample.observe().unwrap().wall_ms);
    expected(
        &mut f,
        &[VersionRef {
            kind: 102,
            id: [95; 32],
            generation: 999,
            digest: [96; 32],
        }],
    );
    f.challenge = session
        .issue(&f.intent, &f.recipient, [97; 32], 5000, sample)
        .unwrap();
    f.rebuild();
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor.clone(),
        proof::Intent::from_signed(&f.intent).unwrap().requester,
        sample,
    )
    .unwrap();
    prepared_fixture(&mut store, &f.intent);
    store
        .accept(f.verify().unwrap(), &mut session, sample, 0)
        .unwrap();
    assert!(store.generations().is_empty());
    drop(store);
    assert!(
        Store::open(&directory.0, f.descriptor)
            .unwrap()
            .generations()
            .is_empty()
    );
}

// Existing floor tests begin with one already prepared requester operation.
pub(crate) fn prepared_fixture(store: &mut Store, signed: &[u8]) {
    let request = proof::Intent::from_signed(signed).unwrap();
    store.require_requester(request.requester).unwrap();
    store.stored.sequence += 1;
    store.stored.tracker.ordinary = Some(tracker::Ordinary {
        signed: hex::encode(signed),
        original: None,
        latest: None,
        body_saved: false,
        complete: false,
        effect: tracker::Effect::Unclaimed,
    });
    let bytes = serde_json::to_vec(&store.stored).unwrap();
    store.digest = digest(&bytes);
    files::atomic_at(
        &store.directory,
        OsStr::new(WITNESS),
        &serde_json::to_vec(&Witness {
            sequence: store.stored.sequence,
            digest: hex::encode(store.digest),
        })
        .unwrap(),
        true,
    )
    .unwrap();
    files::atomic_at(&store.directory, OsStr::new(FLOOR), &bytes, true).unwrap();
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn encoded(values: Vec<V>) -> Vec<u8> {
    wire::encode(&V::Array(values)).unwrap()
}
fn quorum(values: Vec<V>) -> Vec<u8> {
    let payload = encoded(values);
    let signatures = proof::tests::signers()[..3]
        .iter()
        .map(|signer| {
            let key = signer.verifying_key().to_bytes();
            V::Array(vec![
                b(&key),
                b(&signer
                    .sign(&wire::signature_message(&payload, &key))
                    .to_bytes()),
            ])
        })
        .collect();
    encoded(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        V::Array(signatures),
    ])
}
pub(crate) fn certified(
    store: &Store,
    session: &mut Session,
    sample: ClockHealth,
    signed: &[u8],
    operation: &[u8],
    expected: Option<&[u8]>,
) -> VerifiedResult {
    let request = proof::SignedRequest::from_signed(signed).unwrap();
    let signer = SigningKey::from_bytes(&[1; 32]);
    let challenge = session
        .issue(signed, &signer, [98; 32], 5000, sample)
        .unwrap();
    let parsed = proof::Challenge::from_signed(&challenge).unwrap();
    let scope = store.prefix().scope();
    let ordered = encoded(vec![
        V::Uint(22),
        V::Uint(1),
        scope.value(),
        b(signed),
        b(&challenge),
        V::Uint(parsed.expires_at_ms),
    ]);
    let height = store.prefix().height() + 1;
    // Frozen recipient time and a permitted authority offset keep repeated fixtures monotonic.
    let evaluated = parsed
        .created_at_ms
        .checked_add(crate::authority_governance::UNCERTAINTY_MS)
        .unwrap()
        .max(store.prefix().evaluated_at_ms());
    assert!(
        evaluated
            .checked_add(crate::authority_governance::UNCERTAINTY_MS)
            .unwrap()
            < parsed.expires_at_ms
    );
    let node = encoded(vec![
        V::Uint(14),
        V::Uint(1),
        scope.value(),
        V::Uint(height),
        V::Uint(store.prefix().view() + 1),
        b(store.prefix().node()),
        b(&wire::digest(&ordered)),
        V::Uint(evaluated),
        b(&[88; 32]),
    ]);
    let result = OperationResult::parse(operation).unwrap();
    let certificate = quorum(vec![
        V::Uint(23),
        V::Uint(1),
        scope.value(),
        V::Uint(height),
        b(&wire::digest(&node)),
        b(&wire::digest(&ordered)),
        b(&request.digest()),
        b(&parsed.digest),
        b(&request.requester()),
        b(&request.requester()),
        V::Text(request.action().into()),
        b(&request.resource()),
        V::Uint(request.revision()),
        V::Uint(request.profile_generation()),
        V::Uint(u64::from(result.disposition == Disposition::Permit)),
        b(&wire::digest(operation)),
        b(&[89; 32]),
        V::Uint(request.minimum_policy_height()),
        V::Uint(evaluated),
        V::Uint(parsed.expires_at_ms),
        V::Null,
        V::Null,
        V::Null,
    ]);
    proof::verify_response(
        &store.descriptor,
        proof::ProofContext {
            intent: signed,
            challenge: &challenge,
            restrictions: proof::Restrictions::default(),
            minimum_height: store.prefix().height(),
            maximum_effect: 1,
            expected_stream: expected,
        },
        proof::Response {
            ordered_request: &ordered,
            operation_result: operation,
            certificate: &certificate,
            ancestry: &[node],
        },
        |intent, result, _| {
            ensure!(
                intent.action == "ReadPage" && result.value == intent.parameters,
                "test ordinary schema differs"
            );
            proof::ActionValidation::new(Vec::new())
        },
    )
    .unwrap()
}
fn metadata(store: &Store, completion: V) -> Vec<u8> {
    let s = store.prefix().scope();
    let key = store.requester();
    encoded(vec![
        V::Uint(56),
        V::Uint(1),
        s.value(),
        b(&key),
        V::Bool(true),
        V::Uint(1),
        b(&proof::initial_generation_id(s.network, s.incarnation, key).unwrap()),
        V::Uint(0),
        completion,
        V::Null,
    ])
}
fn status(store: &mut Store, session: &mut Session, sample: ClockHealth, metadata: &[u8]) {
    let s = store.prefix().scope();
    let signed = wire::sign_envelope(
        &encoded(vec![
            V::Uint(55),
            V::Uint(1),
            b(&s.network),
            b(&s.incarnation),
            b(&store.requester()),
            b(&[99; 32]),
            V::Uint(s.epoch),
            V::Uint(store.prefix().height()),
        ]),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    let operation = encoded(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityStreamStatus".into()),
        V::Uint(0),
        V::Uint(0),
        b(metadata),
    ]);
    let result = certified(store, session, sample, &signed, &operation, None);
    store
        .accept(result, session, sample, 0)
        .unwrap()
        .perform(store, session, sample, 1, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
}
pub(crate) fn setup() -> (Directory, ClockHealth, Session, Store) {
    let directory = Directory::new();
    let sample = health();
    let mut session = Session::new().unwrap();
    let f = Fixture::new(sample.observe().unwrap().wall_ms);
    let mut store = Store::initialise(
        &directory.0,
        f.descriptor,
        SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        sample,
    )
    .unwrap();
    let m = metadata(&store, V::Null);
    status(&mut store, &mut session, sample, &m);
    (directory, sample, session, store)
}
pub(crate) fn prepare(store: &mut Store, sample: ClockHealth) -> (PreparedRequest, Vec<u8>) {
    let f = Fixture::new(sample.observe().unwrap().wall_ms);
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
        unreachable!()
    };
    let slot = store.ordinary_slot().unwrap();
    fields[4] = V::Uint(slot.generation());
    fields[5] = b(&slot.generation_id());
    fields[6] = V::Uint(slot.sequence());
    fields[7] = V::Uint(slot.acknowledged_through());
    fields[13] = V::Uint(slot.minimum_policy_epoch());
    fields[14] = V::Uint(slot.minimum_policy_height());
    let signed = wire::sign_envelope(
        &wire::encode(&V::Array(fields)).unwrap(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    (store.prepare_ordinary(slot, &signed).unwrap(), f.operation)
}
#[test]
fn saved_body_and_exact_request_survive_failed_workflow_then_allow_successor() {
    let (directory, sample, mut session, mut store) = setup();
    assert!(store.needs_stream_status().unwrap());
    let (pending, operation) = prepare(&mut store, sample);
    assert!(!store.needs_stream_status().unwrap());
    let prepared_floor = store.prefix().height();
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    let permit = store.accept(result, &mut session, sample, 0).unwrap();
    assert!(!store.stored.tracker.ordinary.as_ref().unwrap().body_saved);
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { anyhow::bail!("external context cache failed") }
            )
            .is_err()
    );
    assert!(store.stored.tracker.ordinary.as_ref().unwrap().body_saved);
    assert!(store.ordinary_slot().is_err());
    assert!(!store.needs_stream_status().unwrap());
    let retained = store.prefix().height();
    assert!(retained > prepared_floor);
    let descriptor = store.descriptor.clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    assert_eq!(store.prefix().height(), retained);
    assert!(!store.needs_stream_status().unwrap());
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        pending.signed()
    );
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    store
        .accept(result, &mut session, sample, 0)
        .unwrap()
        .perform(
            &mut store,
            &mut session,
            sample,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(!store.needs_stream_status().unwrap());
    let slot = store.ordinary_slot().unwrap();
    assert_eq!(slot.sequence(), 2);
    assert_eq!(slot.acknowledged_through(), 1);
    assert_eq!(
        files::read_at(&store.directory, OsStr::new(BODY), wire::MAXIMUM, true).unwrap(),
        operation
    );
    // A damaged completed body is a local integrity error, not a reason to query status.
    files::atomic_at(&store.directory, OsStr::new(BODY), b"Damaged", true).unwrap();
    assert!(store.needs_stream_status().is_err());
}
#[test]
fn body_write_failure_preserves_higher_floor_and_irreversible_claim_never_repeats() {
    let (directory, sample, mut session, mut store) = setup();
    let (pending, operation) = prepare(&mut store, sample);
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    let permit = store.accept(result, &mut session, sample, 0).unwrap();
    let height = store.prefix().height();
    std::fs::create_dir(directory.0.join(BODY)).unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("missing body released") }
            )
            .is_err()
    );
    assert_eq!(store.prefix().height(), height);
    assert!(!store.stored.tracker.ordinary.as_ref().unwrap().body_saved);
    std::fs::remove_dir(directory.0.join(BODY)).unwrap();
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    assert!(
        store
            .accept(result, &mut session, sample, 0)
            .unwrap()
            .perform_once(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { anyhow::bail!("handler interrupted") }
            )
            .is_err()
    );
    assert_eq!(
        store.stored.tracker.ordinary.as_ref().unwrap().effect,
        tracker::Effect::Claimed
    );
    let descriptor = store.descriptor.clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    assert!(
        store
            .accept(result, &mut session, sample, 0)
            .unwrap()
            .perform_once(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { panic!("claim repeated") }
            )
            .is_err()
    );
    assert!(store.ordinary_slot().is_err());
}
#[test]
fn fresh_refusal_does_not_erase_original_success_or_acknowledge_missing_body() {
    let (_directory, sample, mut session, mut store) = setup();
    let (pending, operation) = prepare(&mut store, sample);
    let V::Array(mut refused) = wire::decode(&operation).unwrap() else {
        unreachable!()
    };
    refused[3] = V::Uint(1);
    refused[4] = V::Uint(3);
    let refused = wire::encode(&V::Array(refused)).unwrap();
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &refused,
        None,
    );
    store.observe(result).unwrap();
    assert!(
        store
            .stored
            .tracker
            .ordinary
            .as_ref()
            .unwrap()
            .original
            .is_none()
    );
    assert!(store.ordinary_slot().is_err());
    let c = V::Array(vec![
        V::Uint(1),
        b(&pending.digest()),
        V::Uint(0),
        V::Uint(0),
        b(&wire::digest(&operation)),
    ]);
    let m = metadata(&store, c);
    status(&mut store, &mut session, sample, &m);
    let ordinary = store.stored.tracker.ordinary.as_ref().unwrap();
    assert_eq!(ordinary.original.as_ref().unwrap().disposition, 0);
    assert_eq!(ordinary.latest.as_ref().unwrap().disposition, 1);
    assert!(!ordinary.body_saved);
    assert!(store.ordinary_slot().is_err());
}
#[test]
fn requester_binding_and_stale_slot_cannot_replace_a_pending_request() {
    let (_directory, sample, _session, mut store) = setup();
    assert!(
        store
            .require_requester(SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes())
            .is_err()
    );
    let stale = store.ordinary_slot().unwrap();
    let (pending, _) = prepare(&mut store, sample);
    assert!(store.prepare_ordinary(stale, pending.signed()).is_err());
    assert!(store.ordinary_slot().is_err());
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        pending.signed()
    );
}

#[path = "AuthorityFloorRecoveryTests.rs"]
mod recovery;

#[test]
fn epoch_adoption_preserves_pending_request_and_recovers_witness_interruption() {
    let (directory, sample, mut session, mut store) = setup();
    let initial = store.initial_descriptor().clone();
    let old_scope = initial.scope().clone();
    let (pending, operation) = prepare(&mut store, sample);
    let first_node = *store.prefix().node();
    let result = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    let second_node = *result.point().prefix().node();
    let permit = store.accept(result, &mut session, sample, 0).unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { anyhow::bail!("Interrupted effect") }
            )
            .is_err()
    );
    let tracker = store.stored.tracker.clone();
    let generations = store.stored.generations.clone();
    let wall = store.stored.wall_floor_ms;
    let transition = crate::authority_epoch::tests::fixture(
        &initial,
        store.prefix(),
        store.tree_head(),
        &[first_node, second_node],
        &proof::tests::signers(),
    );
    store.seal_epoch(&transition.terminal).unwrap();
    assert!(store.ordinary_slot().is_err());
    assert!(store.epoch_sealed());
    let old = serde_json::to_vec(&store.stored).unwrap();
    let old_witness: serde_json::Value = serde_json::from_slice(
        &files::read_at(store.profile_directory(), OsStr::new(WITNESS), 1024, true).unwrap(),
    )
    .unwrap();
    store.activate_epoch(&transition.activation).unwrap();
    assert_eq!(store.descriptor().scope().epoch, 1);
    assert!(store.needs_stream_status().unwrap());
    assert_eq!(store.prefix().height(), 0);
    assert_eq!(store.stored.tracker, tracker);
    assert_eq!(store.stored.generations, generations);
    assert_eq!(store.stored.wall_floor_ms, wall);
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        pending.signed()
    );
    assert!(store.ordinary_slot().is_err());
    assert_eq!(
        store.descriptor_for_scope(&old_scope).unwrap().canonical(),
        initial.canonical()
    );
    let next = serde_json::to_vec(&store.stored).unwrap();
    let next_witness: serde_json::Value = serde_json::from_slice(
        &files::read_at(store.profile_directory(), OsStr::new(WITNESS), 1024, true).unwrap(),
    )
    .unwrap();
    let transaction = serde_json::to_vec(&serde_json::json!({
        "format":"HyperNetAuthorityPending/1", "network":store.stored.network,
        "incarnation":store.stored.incarnation, "requester":store.stored.requester,
        "descriptor":store.stored.descriptor,"oldWitness":old_witness,"nextWitness":next_witness,
        "nextFloorBytes":hex::encode(next),"transition":"activateEpoch",
        "continuity":{"ancestry":[],"history":null}
    }))
    .unwrap();
    // Publication writes the witness first; the old floor must recover forward exactly once.
    files::atomic_at(store.profile_directory(), OsStr::new(FLOOR), &old, true).unwrap();
    files::atomic_at(
        store.profile_directory(),
        OsStr::new(transaction::PENDING),
        &transaction,
        false,
    )
    .unwrap();
    drop(store);
    let mut store = Store::open(&directory.0, initial).unwrap();
    assert_eq!(store.stored.tracker, tracker);
    assert_eq!(store.stored.generations, generations);
    assert_eq!(store.stored.wall_floor_ms, wall);
    assert_eq!(store.prefix().height(), 0);
    let terminal = store
        .verify_epoch_terminal(&transition.evidence, &transition.history)
        .unwrap();
    let activation =
        crate::authority_epoch::verify_activation(terminal, transition.activation.ready()).unwrap();
    let sequence = store.stored.sequence;
    store.activate_epoch(&activation).unwrap();
    assert_eq!(store.stored.sequence, sequence);
    assert_eq!(store.stored.epochs.len(), 1);
    assert!(!transaction::exists(store.profile_directory(), transaction::PENDING).unwrap());
    let mut stored = serde_json::to_value(&store.stored).unwrap();
    stored.as_object_mut().unwrap().remove("sealed");
    assert!(serde_json::from_value::<Stored>(stored).is_err());
}
