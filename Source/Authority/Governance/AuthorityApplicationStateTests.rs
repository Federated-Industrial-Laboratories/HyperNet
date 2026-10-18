// SPDX-License-Identifier: MIT
// Exact state reuse cannot replace request authorization or cross configurations.
use super::{tests::Fixture, *};
use crate::authority_objects::Resolved;
use std::{sync::atomic::Ordering, time::Instant};

fn parses(app: &PolicyApplication) -> usize {
    app.state_parses.load(Ordering::Relaxed)
}

#[test]
fn verified_state_reuses_only_exact_successful_bytes_in_one_configuration() {
    let f = Fixture::new();
    let first = f.app.verified_state(&f.initial).unwrap();
    f.app.validate_checkpoint(&f.initial, 0).unwrap();
    assert!(f.app.retained_inputs(&f.initial).unwrap().is_empty());
    assert!(Arc::ptr_eq(
        &first,
        &f.app.verified_state(&f.initial).unwrap()
    ));
    assert_eq!(parses(&f.app), 1);
    let intent = f.intent(1, &f.expected, 1);
    let applied = f
        .app
        .execute(
            &f.initial,
            &f.committed(&intent, 10000, 11251, 1),
            &Resolved::default(),
        )
        .unwrap();
    let next = f.app.verified_state(&applied.state).unwrap();
    assert_eq!(next.height, 1);
    assert_eq!(first.height, 0);
    assert!(!Arc::ptr_eq(&first, &next));
    assert_eq!(parses(&f.app), 2);

    let mut invalid = wire::decode_state(&applied.state).unwrap();
    let V::Array(fields) = &mut invalid else {
        unreachable!()
    };
    fields[2] = b(&[99; 32]);
    let invalid = wire::encode_state(&invalid).unwrap();
    for _ in 0..2 {
        assert!(f.app.verified_state(&invalid).is_err());
    }
    assert_eq!(parses(&f.app), 4);
    assert!(Arc::ptr_eq(
        &next,
        &f.app.verified_state(&applied.state).unwrap()
    ));
    assert!(
        f.app
            .verified_state(&vec![0; crate::authority_capacity::MAX_STATE_BYTES + 1])
            .is_err()
    );
    assert_eq!(parses(&f.app), 4);
    let reloaded = f.app.verified_state(&f.initial).unwrap();
    assert!(!Arc::ptr_eq(&first, &reloaded));
    assert_eq!(parses(&f.app), 5);

    let separate = PolicyApplication::new(f.app.config.clone());
    assert!(!Arc::ptr_eq(
        &reloaded,
        &separate.verified_state(&f.initial).unwrap()
    ));
    assert_eq!(parses(&separate), 1);
    let mut foreign = f.app.config.clone();
    foreign.scope.incarnation = [99; 32];
    let foreign = PolicyApplication::new(foreign);
    assert!(foreign.verified_state(&f.initial).is_err());
    assert!(foreign.verified.lock().unwrap().is_none());
}

#[test]
fn verified_state_keeps_execution_isolated_and_rechecks_authority_and_expiry() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let prior = f.app.verified_state(&f.initial).unwrap();
    let unchanged = prior.encode(&f.app.config).unwrap();
    let intent = f.intent(1, &f.expected, 1);
    let inspect = f
        .app
        .execute(
            &f.initial,
            &f.committed(&intent, 10000, 11251, 1),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(membership_tests::code(&inspect), 0);
    let expired = f
        .app
        .execute(
            &f.initial,
            &f.committed(&intent, 10000, 13750, 1),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(membership_tests::code(&expired), 7);
    assert_eq!(prior.encode(&f.app.config).unwrap(), unchanged);
    assert!(Arc::ptr_eq(
        &prior,
        &f.app.verified_state(&f.initial).unwrap()
    ));
    assert_eq!(parses(&f.app), 1);

    let request = transaction_tests::revoke(&f, &f.initial, f.grant, 1);
    let revoked = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 3500, 5000, 1),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(membership_tests::code(&revoked), 0);
    let current = f.app.verified_state(&revoked.state).unwrap();
    let fresh = f.intent(2, &f.expected, 1);
    let denied = f
        .app
        .execute(
            &revoked.state,
            &f.committed(&fresh, 10000, 11251, 2),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(membership_tests::code(&denied), 6);
    assert!(Arc::ptr_eq(
        &current,
        &f.app.verified_state(&revoked.state).unwrap()
    ));
    assert_eq!(parses(&f.app), 2);
}

#[test]
fn verified_state_revalidates_signed_provenance_and_reports_reuse_cost() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let request = transaction_tests::revoke(&f, &f.initial, f.grant, 1);
    let revoked = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 3500, 5000, 1),
            &Resolved::default(),
        )
        .unwrap();
    assert_eq!(membership_tests::code(&revoked), 0);
    let current = f.app.verified_state(&revoked.state).unwrap();
    let mut invalid = wire::decode_state(&revoked.state).unwrap();
    let V::Array(fields) = &mut invalid else {
        unreachable!()
    };
    let V::Array(evidence) = &mut fields[9] else {
        unreachable!()
    };
    let V::Array(entry) = &mut evidence[0] else {
        unreachable!()
    };
    let V::Bytes(signed) = &mut entry[1] else {
        unreachable!()
    };
    *signed.last_mut().unwrap() ^= 1;
    assert!(
        f.app
            .verified_state(&wire::encode_state(&invalid).unwrap())
            .is_err()
    );
    assert!(Arc::ptr_eq(
        &current,
        &f.app.verified_state(&revoked.state).unwrap()
    ));

    const REPEATS: usize = 8;
    let cold = Instant::now();
    for _ in 0..REPEATS {
        assert_eq!(
            State::parse(&f.app.config, &revoked.state).unwrap().height,
            1
        );
    }
    let cold_ns = cold.elapsed().as_nanos();
    let before = parses(&f.app);
    let reused = Instant::now();
    for _ in 0..REPEATS {
        f.app.validate_checkpoint(&revoked.state, 1).unwrap();
    }
    let reused_ns = reused.elapsed().as_nanos();
    assert_eq!(parses(&f.app), before);
    eprintln!(
        "AuthorityStateValidation bytes={} repeats={REPEATS} coldParses={REPEATS} reusedParses=0 coldNs={cold_ns} reusedNs={reused_ns}",
        revoked.state.len()
    );
}

#[test]
fn verified_state_mutex_failure_refuses_a_previously_valid_entry() {
    let f = Fixture::new();
    f.app.verified_state(&f.initial).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = f.app.verified.lock().unwrap();
            panic!("Interrupted state validation");
        }))
        .is_err()
    );
    assert!(f.app.verified_state(&f.initial).is_err());
    assert!(f.app.retained_inputs(&f.initial).is_err());
    assert_eq!(parses(&f.app), 1);
}
