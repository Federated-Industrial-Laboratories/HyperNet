// SPDX-License-Identifier: MIT
// Explicit fences preserve prior uncertain effects without retaining recursive request history.
use super::*;

#[test]
fn expired_challenge_reopens_only_the_exact_unconsumed_request() {
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
    let now = sample.observe().unwrap();
    let later = ClockHealth::new(
        now.wall_ms + 5000,
        now.boot_ms + 5000,
        now.boot_ms + 10000,
        0,
    )
    .unwrap()
    .frozen();
    let failed = store.accept(result, &mut session, later, 0);
    assert!(
        failed
            .err()
            .unwrap()
            .is::<crate::authority_challenge::ChallengeExpired>()
    );
    let descriptor = store.descriptor.clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    assert!(store.ordinary_slot().is_err());
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        pending.signed()
    );
    let mut session = Session::new().unwrap();
    let result = certified(
        &store,
        &mut session,
        later,
        pending.signed(),
        &operation,
        None,
    );
    let mut effects = 0;
    store
        .accept(result, &mut session, later, 0)
        .unwrap()
        .perform_once(
            &mut store,
            &mut session,
            later,
            1,
            |_| Ok(()),
            |_, _| {
                effects += 1;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(effects, 1);
    assert!(store.resume_ordinary().unwrap().is_none());
    assert_eq!(store.ordinary_slot().unwrap().sequence(), 2);
    let result = certified(
        &store,
        &mut session,
        later,
        pending.signed(),
        &operation,
        None,
    );
    assert!(
        store
            .accept(result, &mut session, later, 0)
            .unwrap()
            .perform_once(
                &mut store,
                &mut session,
                later,
                1,
                |_| Ok(()),
                |_, _| {
                    effects += 1;
                    Ok(())
                }
            )
            .is_err()
    );
    assert_eq!(effects, 1);
}

fn fence(store: &mut Store, session: &mut Session, sample: ClockHealth) {
    let old = store.stream_metadata().unwrap().unwrap();
    let prior = old.state().unwrap();
    let scope = store.prefix().scope();
    let signed = wire::sign_envelope(
        &encoded(vec![
            V::Uint(57),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&store.requester()),
            b(&wire::digest(old.canonical())),
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
            V::Uint(prior.generation),
            b(&prior.generation_id),
            b(&wire::digest(old.canonical())),
        ]),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    let pending = store.prepare_fence(&signed, old.canonical()).unwrap();
    let V::Array(old_fields) = wire::decode(old.canonical()).unwrap() else {
        unreachable!()
    };
    let f = V::Array(vec![
        b(&pending.digest()),
        b(&wire::digest(old.canonical())),
        V::Uint(prior.generation),
        b(&prior.generation_id),
        V::Uint(prior.retired_through),
        old_fields[8].clone(),
    ]);
    let current = encoded(vec![
        V::Uint(56),
        V::Uint(1),
        store.prefix().scope().value(),
        b(&store.requester()),
        V::Bool(true),
        V::Uint(prior.generation + 1),
        b(&pending.digest()),
        V::Uint(0),
        V::Null,
        f,
    ]);
    let value = encoded(vec![
        V::Uint(58),
        V::Uint(1),
        store.prefix().scope().value(),
        b(&store.requester()),
        b(&pending.digest()),
        V::Uint(0),
        b(&current),
    ]);
    let operation = encoded(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityStreamFence".into()),
        V::Uint(0),
        V::Uint(0),
        b(&value),
    ]);
    let result = certified(
        store,
        session,
        sample,
        pending.signed(),
        &operation,
        pending.expected_metadata(),
    );
    store
        .accept(result, session, sample, 0)
        .unwrap()
        .perform(store, session, sample, 1, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
}
#[test]
fn multiple_fences_keep_unknown_prior_effects_and_restart_with_fresh_generation() {
    let (directory, sample, mut session, mut store) = setup();
    let (first, _) = prepare(&mut store, sample);
    fence(&mut store, &mut session, sample);
    assert_eq!(store.ordinary_slot().unwrap().generation(), 2);
    let (second, _) = prepare(&mut store, sample);
    fence(&mut store, &mut session, sample);
    assert_eq!(store.stored.tracker.outstanding_unknown.len(), 2);
    assert_eq!(
        store.stored.tracker.outstanding_unknown[0].request,
        first.digest()
    );
    assert_eq!(
        store.stored.tracker.outstanding_unknown[1].request,
        second.digest()
    );
    assert!(store.resume_ordinary().unwrap().is_none());
    assert!(store.resume_fence().unwrap().is_none());
    let descriptor = store.descriptor.clone();
    drop(store);
    let store = Store::open(&directory.0, descriptor).unwrap();
    assert_eq!(store.ordinary_slot().unwrap().generation(), 3);
    assert_eq!(store.stored.tracker.outstanding_unknown.len(), 2);
    assert!(!directory.0.join(BODY).exists());
}
#[test]
fn certified_changed_comparison_releases_only_the_stale_fence_request() {
    let (_directory, sample, mut session, mut store) = setup();
    let (ordinary, operation) = prepare(&mut store, sample);
    let old = store.stream_metadata().unwrap().unwrap();
    let prior = old.state().unwrap();
    let scope = store.prefix().scope();
    let signed = wire::sign_envelope(
        &encoded(vec![
            V::Uint(57),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&store.requester()),
            b(&[8; 32]),
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
            V::Uint(prior.generation),
            b(&prior.generation_id),
            b(&wire::digest(old.canonical())),
        ]),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    store.prepare_fence(&signed, old.canonical()).unwrap();
    let completion = V::Array(vec![
        V::Uint(1),
        b(&ordinary.digest()),
        V::Uint(0),
        V::Uint(0),
        b(&wire::digest(&operation)),
    ]);
    let current = metadata(&store, completion);
    status(&mut store, &mut session, sample, &current);
    assert!(store.resume_fence().unwrap().is_none());
    assert_eq!(store.stored.tracker.outstanding_unknown.len(), 1);
    assert!(store.stored.tracker.outstanding_unknown[0].fence);
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        ordinary.signed()
    );
    assert!(store.ordinary_slot().is_err());
}

#[test]
fn final_return_guard_drops_bytes_after_completion_without_repeating_an_effect() {
    use std::{cell::Cell, rc::Rc};
    struct Protected(Rc<Cell<bool>>);
    impl Drop for Protected {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    for once in [false, true] {
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
        let checks = Cell::new(0);
        let callback_sequence = Cell::new(0);
        let dropped = Rc::new(Cell::new(false));
        let check = |_: &proof::Restrictions| {
            checks.set(checks.get() + 1);
            ensure!(
                checks.get() != 3,
                "restrictions changed before returning protected bytes"
            );
            Ok(())
        };
        let effect = |_: &OperationResult, store: &Store| {
            callback_sequence.set(store.stored.sequence);
            Ok(Protected(dropped.clone()))
        };
        let outcome = if once {
            permit.perform_once(&mut store, &mut session, sample, 1, check, effect)
        } else {
            permit.perform(&mut store, &mut session, sample, 1, check, effect)
        };
        assert!(outcome.is_err());
        assert!(dropped.get());
        assert_eq!(checks.get(), 3);
        assert!(store.stored.sequence > callback_sequence.get());
        let ordinary = store.stored.tracker.ordinary.as_ref().unwrap();
        assert!(ordinary.complete && ordinary.body_saved);
        assert_eq!(
            ordinary.effect,
            if once {
                tracker::Effect::Complete
            } else {
                tracker::Effect::Unclaimed
            }
        );
        let descriptor = store.descriptor.clone();
        drop(store);
        let mut store = Store::open(&directory.0, descriptor).unwrap();
        assert!(store.resume_ordinary().unwrap().is_none());
        // The explicit read retry uses the exact bytes retained before completion.
        let result = certified(
            &store,
            &mut session,
            sample,
            pending.signed(),
            &operation,
            None,
        );
        let permit = store.accept(result, &mut session, sample, 0).unwrap();
        let sequence = store.stored.sequence;
        if once {
            assert!(
                permit
                    .perform_once(
                        &mut store,
                        &mut session,
                        sample,
                        1,
                        |_| Ok(()),
                        |_, _| -> Result<()> { panic!("completed irreversible effect repeated") }
                    )
                    .is_err()
            );
        } else {
            permit
                .perform(
                    &mut store,
                    &mut session,
                    sample,
                    1,
                    |_| Ok(()),
                    |_, _| Ok(()),
                )
                .unwrap();
            assert_eq!(store.stored.sequence, sequence);
        }
    }
}

fn observed_refusal(
    store: &mut Store,
    session: &mut Session,
    sample: ClockHealth,
    pending: &PreparedRequest,
    permit: &[u8],
) -> Vec<u8> {
    let V::Array(mut fields) = wire::decode(permit).unwrap() else {
        unreachable!()
    };
    fields[3] = V::Uint(1);
    fields[4] = V::Uint(3);
    let refusal = wire::encode(&V::Array(fields)).unwrap();
    let result = certified(store, session, sample, pending.signed(), &refusal, None);
    store.observe(result).unwrap();
    refusal
}

#[test]
fn certified_original_refusal_after_reopen_allows_next_sequence_without_fencing() {
    let (directory, sample, mut session, mut store) = setup();
    let (pending, permit) = prepare(&mut store, sample);
    assert!(!store.refusal_needs_status().unwrap());
    assert!(!store.needs_stream_status().unwrap());
    let refusal = observed_refusal(&mut store, &mut session, sample, &pending, &permit);
    assert!(store.refusal_needs_status().unwrap());
    assert!(store.needs_stream_status().unwrap());
    assert!(store.ordinary_slot().is_err());
    let descriptor = store.descriptor.clone();
    drop(store);
    let mut store = Store::open(&directory.0, descriptor).unwrap();
    assert!(store.refusal_needs_status().unwrap());
    assert!(store.needs_stream_status().unwrap());
    assert_eq!(
        store.resume_ordinary().unwrap().unwrap().signed(),
        pending.signed()
    );
    let completion = V::Array(vec![
        V::Uint(1),
        b(&pending.digest()),
        V::Uint(1),
        V::Uint(3),
        b(&wire::digest(&refusal)),
    ]);
    let current = metadata(&store, completion);
    status(&mut store, &mut session, sample, &current);
    assert!(!store.refusal_needs_status().unwrap());
    assert!(!store.needs_stream_status().unwrap());
    assert!(store.resume_ordinary().unwrap().is_none());
    assert!(store.resume_fence().unwrap().is_none());
    let slot = store.ordinary_slot().unwrap();
    assert_eq!(slot.generation(), 1);
    assert_eq!(slot.sequence(), 2);
    assert_eq!(slot.acknowledged_through(), 1);
    let (successor, _) = prepare(&mut store, sample);
    assert_ne!(successor.digest(), pending.digest());
    assert_eq!(
        proof::Intent::from_signed(successor.signed())
            .unwrap()
            .sequence,
        2
    );
    assert!(store.stored.tracker.outstanding_unknown.is_empty());
}

#[test]
fn status_cannot_release_unknown_or_unconsumed_permit_after_disclosure_refusal() {
    for original_permit in [false, true] {
        let (directory, sample, mut session, mut store) = setup();
        let (pending, permit) = prepare(&mut store, sample);
        observed_refusal(&mut store, &mut session, sample, &pending, &permit);
        assert!(store.refusal_needs_status().unwrap());
        let completion = if original_permit {
            V::Array(vec![
                V::Uint(1),
                b(&pending.digest()),
                V::Uint(0),
                V::Uint(0),
                b(&wire::digest(&permit)),
            ])
        } else {
            V::Null
        };
        let current = metadata(&store, completion);
        status(&mut store, &mut session, sample, &current);
        assert_eq!(store.refusal_needs_status().unwrap(), !original_permit);
        assert!(store.ordinary_slot().is_err());
        assert_eq!(
            store.resume_ordinary().unwrap().unwrap().signed(),
            pending.signed()
        );
        assert!(store.resume_fence().unwrap().is_none());
        assert!(store.stored.tracker.outstanding_unknown.is_empty());
        let descriptor = store.descriptor.clone();
        drop(store);
        let store = Store::open(&directory.0, descriptor).unwrap();
        assert_eq!(store.refusal_needs_status().unwrap(), !original_permit);
        assert!(store.ordinary_slot().is_err());
        assert_eq!(
            store.resume_ordinary().unwrap().unwrap().signed(),
            pending.signed()
        );
    }
}
