// SPDX-License-Identifier: MIT
use super::{
    tests::{Fixture, result_bytes},
    *,
};
use ed25519_dalek::SigningKey;

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}
fn code(value: &Execution) -> u64 {
    crate::authority_proof::OperationResult::parse(result_bytes(value))
        .unwrap()
        .code
}
fn value(execution: &Execution) -> V {
    let parsed = crate::authority_proof::OperationResult::parse(result_bytes(execution)).unwrap();
    wire::decode(&parsed.value).unwrap()
}
fn scope(f: &Fixture) -> crate::authority_proof::Scope {
    let s = &f.app.config.scope;
    crate::authority_proof::Scope {
        network: s.network,
        incarnation: s.incarnation,
        configuration: s.configuration,
        epoch: s.epoch,
    }
}
fn change(bytes: &[u8], key: &SigningKey, changes: &[(usize, V)]) -> Vec<u8> {
    let (payload, _) = wire::envelope(bytes, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    for (index, value) in changes {
        fields[*index] = value.clone();
    }
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), key).unwrap()
}
fn status(f: &Fixture, key: &SigningKey, epoch: u64, height: u64) -> Vec<u8> {
    wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(55),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            b(&public(key)),
            b(&[81; 32]),
            V::Uint(epoch),
            V::Uint(height),
        ]))
        .unwrap(),
        key,
    )
    .unwrap()
}
fn fence(f: &Fixture, state: &State, nonce: u8) -> Vec<u8> {
    let metadata = state
        .streams
        .metadata(&public(&f.requester))
        .unwrap()
        .unwrap();
    wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(57),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            b(&public(&f.requester)),
            b(&[nonce; 32]),
            V::Uint(f.app.config.scope.epoch),
            V::Uint(state.height),
            V::Uint(metadata.generation),
            b(&metadata.generation_id),
            b(&wire::digest(
                &state
                    .streams
                    .metadata_bytes(&scope(f), &public(&f.requester))
                    .unwrap(),
            )),
        ]))
        .unwrap(),
        &f.requester,
    )
    .unwrap()
}

/// Fill admitted signers through the real per-result and aggregate receipt limits.
/// The target signer keeps its permanent finite-refusal reserve.
pub(super) fn saturated(f: &Fixture, prior: &[u8]) -> Vec<u8> {
    let mut state = State::parse(&f.app.config, prior).unwrap();
    let proposal = |size| {
        result(
            "AuthorityInspect",
            0,
            &wire::encode(&b(&vec![1; size])).unwrap(),
        )
        .unwrap()
    };
    let fallback = refusal("AuthorityInspect", 2).unwrap();
    let (mut low, mut high) = (0, crate::consensus::MAX_RESULT_BYTES);
    while low < high {
        let size = (low + high).div_ceil(2);
        if proposal(size).len() <= crate::consensus::MAX_RESULT_BYTES {
            low = size;
        } else {
            high = size - 1;
        }
    }
    let maximum = low;
    let target = public(&f.requester);
    let mut capacity_reached = false;
    for key in state
        .streams
        .keys()
        .into_iter()
        .filter(|key| *key != target)
    {
        let request = streams::Request {
            requester: key,
            generation: 1,
            generation_id: streams::initial_id(
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
                key,
            )
            .unwrap(),
            sequence: 1,
            acknowledged_through: 0,
            intent: [91; 32],
        };
        let original = state.streams.clone();
        let mut next = original.clone();
        if next
            .record(&request, &proposal(maximum), &fallback)
            .unwrap()
            .proposed_result_retained
        {
            state.streams = next;
            continue;
        }
        // This legal individual result was refused by the aggregate capacity.
        let (mut low, mut high) = (0, maximum);
        let mut best = original.clone();
        assert!(
            best.record(&request, &proposal(0), &fallback)
                .unwrap()
                .proposed_result_retained
        );
        while low < high {
            let size = (low + high).div_ceil(2);
            let mut next = original.clone();
            if next
                .record(&request, &proposal(size), &fallback)
                .unwrap()
                .proposed_result_retained
            {
                low = size;
                best = next;
            } else {
                high = size - 1;
            }
        }
        state.streams = best;
        capacity_reached = true;
        break;
    }
    assert!(
        capacity_reached,
        "fixture must fill the configured receipt store"
    );
    state.encode(&f.app.config).unwrap()
}

#[test]
fn genesis_admits_only_root_subjects_and_unknown_status_never_allocates() {
    let f = Fixture::new();
    let initial = State::parse(&f.app.config, &f.initial).unwrap();
    assert_eq!(initial.streams.value().list(64).unwrap().len(), 1);
    assert!(
        initial
            .streams
            .metadata(&public(&f.requester))
            .unwrap()
            .is_some()
    );
    let stranger = signer(78);
    let request = status(&f, &stranger, 0, 0);
    let applied = f
        .app
        .execute(
            &f.initial,
            &f.with_recipient(&request, 10000, 11251, 1, &stranger),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&applied), 0);
    let metadata = value(&applied);
    let metadata = metadata.array(10).unwrap();
    assert_eq!(metadata[0], V::Uint(56));
    assert_eq!(metadata[4], V::Bool(false));
    let after = State::parse(&f.app.config, &applied.state).unwrap();
    assert_eq!(initial.streams.value(), after.streams.value());
    let ordinary = change(
        &f.intent(1, &f.expected, 1),
        &stranger,
        &[
            (
                5,
                b(&streams::initial_id(
                    f.app.config.scope.network,
                    f.app.config.scope.incarnation,
                    public(&stranger),
                )
                .unwrap()),
            ),
            (8, b(&public(&stranger))),
        ],
    );
    let committed = f.with_recipient(&ordinary, 15000, 16251, 2, &stranger);
    assert!(
        f.app
            .validate(
                &applied.state,
                &committed.command,
                committed.evaluated_at,
                &crate::authority_objects::Resolved::default()
            )
            .is_err()
    );
    let refused = f
        .app
        .execute(
            &applied.state,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&refused), 3);
    assert_eq!(
        State::parse(&f.app.config, &refused.state)
            .unwrap()
            .streams
            .value(),
        initial.streams.value()
    );
}

#[test]
fn committed_pre_fence_request_refuses_without_stalling_or_rewriting_the_stream() {
    let f = Fixture::new();
    let stale = f.intent(1, &f.expected, 1);
    let pending = f.committed(&stale, 10000, 11251, 2);
    f.app
        .validate(
            &f.initial,
            &pending.command,
            pending.evaluated_at,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let initial = State::parse(&f.app.config, &f.initial).unwrap();
    let request = fence(&f, &initial, 82);
    let fenced = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&fenced), 0);
    assert_eq!(value(&fenced).array(7).unwrap()[5], V::Uint(0));
    let before = State::parse(&f.app.config, &fenced.state).unwrap();
    assert!(
        f.app
            .validate(
                &fenced.state,
                &pending.command,
                pending.evaluated_at,
                &crate::authority_objects::Resolved::default()
            )
            .is_err()
    );
    let late = f
        .app
        .execute(
            &fenced.state,
            &pending,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&late), 28);
    let after = State::parse(&f.app.config, &late.state).unwrap();
    assert_eq!(after.height, 2);
    assert_eq!(before.records, after.records);
    assert_eq!(before.streams.value(), after.streams.value());
    let current = before
        .streams
        .metadata(&public(&f.requester))
        .unwrap()
        .unwrap();
    let next = change(
        &stale,
        &f.requester,
        &[
            (4, V::Uint(current.generation)),
            (5, b(&current.generation_id)),
        ],
    );
    let fresh = f
        .app
        .execute(
            &late.state,
            &f.committed(&next, 15000, 16251, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&fresh), 0);
    let retry = f
        .app
        .execute(
            &fresh.state,
            &f.committed(&request, 20000, 21251, 4),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&retry), 0);
    assert_eq!(value(&retry).array(7).unwrap()[5], V::Uint(1));
    let before_retry = State::parse(&f.app.config, &fresh.state).unwrap();
    let after_retry = State::parse(&f.app.config, &retry.state).unwrap();
    assert_eq!(before_retry.streams.value(), after_retry.streams.value());
    assert_eq!(
        after_retry
            .streams
            .metadata(&public(&f.requester))
            .unwrap()
            .unwrap()
            .completion
            .unwrap()
            .intent,
        SignedRequest::from_signed(&next).unwrap().digest()
    );
}

#[test]
fn invalid_sequence_classes_are_finite_and_never_change_stream_or_domain() {
    let f = Fixture::new();
    let first = f.intent(1, &f.expected, 1);
    let one = f
        .app
        .execute(
            &f.initial,
            &f.committed(&first, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let conflict = change(&first, &f.requester, &[(14, V::Uint(1))]);
    let gap = change(&first, &f.requester, &[(6, V::Uint(3)), (7, V::Uint(1))]);
    let wrong_generation = change(&first, &f.requester, &[(4, V::Uint(2)), (5, b(&[84; 32]))]);
    for (request, expected) in [(&conflict, 28), (&gap, 12), (&wrong_generation, 28)] {
        let result = f
            .app
            .execute(
                &one.state,
                &f.committed(request, 15000, 16251, 2),
                &crate::authority_objects::Resolved::default(),
            )
            .unwrap();
        assert_eq!(code(&result), expected);
        let before = State::parse(&f.app.config, &one.state).unwrap();
        let after = State::parse(&f.app.config, &result.state).unwrap();
        assert_eq!(before.streams.value(), after.streams.value());
        assert_eq!(before.records, after.records);
    }
    let second = f.intent(2, &f.expected, 1);
    let two = f
        .app
        .execute(
            &one.state,
            &f.committed(&second, 15000, 16251, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&two), 0);
    let retired = f
        .app
        .execute(
            &two.state,
            &f.committed(&first, 20000, 21251, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&retired), 21);
    assert_eq!(
        State::parse(&f.app.config, &two.state)
            .unwrap()
            .streams
            .value(),
        State::parse(&f.app.config, &retired.state)
            .unwrap()
            .streams
            .value()
    );
    let expired = f
        .app
        .execute(
            &one.state,
            &f.committed(&wrong_generation, 10000, 13750, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&expired), 7);
}

#[test]
fn own_status_always_carries_exact_metadata_and_uses_preceding_policy_floor() {
    let f = Fixture::new();
    let initial = State::parse(&f.app.config, &f.initial).unwrap();
    for (epoch, height, evaluated, expected) in [
        (0, 0, 11251, 0),
        (0, 1, 11251, 21),
        (1, 0, 11251, 21),
        (0, 0, 13750, 7),
    ] {
        let request = status(&f, &f.requester, epoch, height);
        let response = f
            .app
            .execute(
                &f.initial,
                &f.committed(&request, 10000, evaluated, 1),
                &crate::authority_objects::Resolved::default(),
            )
            .unwrap();
        assert_eq!(code(&response), expected);
        assert_eq!(
            wire::encode(&value(&response)).unwrap(),
            initial
                .streams
                .metadata_bytes(&scope(&f), &public(&f.requester))
                .unwrap()
        );
        assert_eq!(
            State::parse(&f.app.config, &response.state)
                .unwrap()
                .streams
                .value(),
            initial.streams.value()
        );
    }
}

#[test]
fn receipt_capacity_refusal_is_atomic_and_acknowledgement_can_continue() {
    let f = Fixture::with_receipt_capacity_administrators(1000, vec![25]);
    let prior = saturated(&f, &f.initial);
    let request = f.intent(1, &f.expected, 1);
    let denied = f
        .app
        .execute(
            &prior,
            &f.committed(&request, 10000, 11251, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&denied), 2);
    let retried = f
        .app
        .execute(
            &denied.state,
            &f.committed(&request, 15000, 16251, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&retried), 2);
    assert_eq!(result_bytes(&denied), result_bytes(&retried));
    let next = f.intent(2, &[], 1);
    let refused = f
        .app
        .execute(
            &retried.state,
            &f.committed(&next, 20000, 21251, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(code(&refused), 3);
    let stream = State::parse(&f.app.config, &refused.state)
        .unwrap()
        .streams
        .metadata(&public(&f.requester))
        .unwrap()
        .unwrap();
    assert_eq!(stream.retired_through, 1);
    assert_eq!(stream.completion.unwrap().sequence, 2);
}
