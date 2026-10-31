// SPDX-License-Identifier: MIT
// Clock advancement across durable writes cannot renew a certified effect.
use super::*;
use std::cell::Cell;

fn at(sample: ClockHealth, elapsed: u64, validity: u64) -> ClockHealth {
    let start = sample.observe().unwrap();
    ClockHealth::new(
        start.wall_ms + elapsed,
        start.boot_ms + elapsed,
        start.boot_ms + elapsed + validity,
        100,
    )
    .unwrap()
    .frozen()
}

fn stored(directory: &Directory) -> Stored {
    serde_json::from_slice(&std::fs::read(directory.0.join(FLOOR)).unwrap()).unwrap()
}

fn outcome_clock(sample: ClockHealth, case: &str) -> Result<ClockHealth> {
    match case {
        "Unavailable" => anyhow::bail!("monitor unavailable"),
        "Stale" => Ok(at(sample, 1600, 0)),
        "Expired" => Ok(at(sample, 4600, 1000)),
        "Current" => Ok(at(sample, 1600, 1000)),
        _ => unreachable!(),
    }
}

fn expected_failure(case: &str) -> &'static str {
    match case {
        "Unavailable" => "monitor unavailable",
        "Stale" => "clock health is stale or invalid",
        "Expired" => "authority effect is outside its conservative absolute validity interval",
        _ => unreachable!(),
    }
}

#[test]
fn durable_acceptance_resamples_health_without_renewing_authority_or_intent() {
    for case in ["Current", "Stale", "Expired", "Unavailable"] {
        let directory = Directory::new();
        let sample = at(health(), 0, 1000);
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
        let sequence = store.stored.sequence;
        let calls = Cell::new(0);
        let result = store.accept_with_clock(
            f.verify().unwrap(),
            &mut session,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    return Ok(sample);
                }
                let published = stored(&directory);
                assert!(published.sequence > sequence && published.certificate.is_some());
                // Simulate persistence crossing the first observation's validity.
                outcome_clock(sample, case)
            },
            0,
        );
        assert_eq!(calls.get(), 2);
        if case == "Current" {
            assert!(result.is_ok());
        } else {
            assert!(
                format!("{:#}", result.err().unwrap()).contains(expected_failure(case)),
                "{case}"
            );
        }
        assert_eq!(store.prefix().height(), 1);
        assert_eq!(store.resume_ordinary().unwrap().unwrap().signed(), f.intent);
        assert!(!store.stored.tracker.ordinary.as_ref().unwrap().complete);
    }
}

#[test]
fn durable_completion_resamples_health_and_keeps_completed_effect_after_expiry() {
    for once in [false, true] {
        for case in ["Current", "Stale", "Expired", "Unavailable"] {
            let directory = Directory::new();
            let sample = at(health(), 0, 1000);
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
                .accept_with_clock(f.verify().unwrap(), &mut session, &mut || Ok(sample), 0)
                .unwrap();
            let calls = Cell::new(0);
            let effects = Cell::new(0);
            let mut clock = || {
                calls.set(calls.get() + 1);
                if calls.get() <= 2 {
                    return Ok(sample);
                }
                let published = stored(&directory);
                let ordinary = published.tracker.ordinary.unwrap();
                assert!(ordinary.body_saved);
                if calls.get() < 5 {
                    assert!(!ordinary.complete);
                    return Ok(at(sample, 1500, 1000));
                }
                assert!(ordinary.complete);
                assert_eq!(effects.get(), 1);
                outcome_clock(sample, case)
            };
            let effect = |_: &OperationResult, _: &Store| {
                effects.set(effects.get() + 1);
                files::write_new(&directory.0.join("Effect"), b"Verified")?;
                Ok("Verified")
            };
            let result = if once {
                permit.perform_once_with_clock(
                    &mut store,
                    &mut session,
                    &mut clock,
                    1,
                    |_| Ok(()),
                    effect,
                )
            } else {
                permit.perform_with_clock(
                    &mut store,
                    &mut session,
                    &mut clock,
                    1,
                    |_| Ok(()),
                    effect,
                )
            };
            assert_eq!((calls.get(), effects.get()), (5, 1));
            if case == "Current" {
                assert_eq!(result.unwrap(), "Verified");
            } else {
                assert!(
                    format!("{:#}", result.unwrap_err()).contains(expected_failure(case)),
                    "{case}"
                );
            }
            assert!(store.stored.tracker.ordinary.as_ref().unwrap().complete);
            assert!(
                session
                    .check(&f.verify().unwrap(), 0, at(sample, 4700, 1000))
                    .is_err(),
                "completed challenge was restored"
            );
            drop(store);
            let reopened = Store::open(&directory.0, f.descriptor).unwrap();
            let retained = reopened.stored.tracker.ordinary.as_ref().unwrap();
            assert!(retained.complete);
            assert_eq!(retained.signed, hex::encode(&f.intent));
        }
    }
}
