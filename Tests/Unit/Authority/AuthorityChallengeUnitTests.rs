// SPDX-License-Identifier: MIT
// Unit tests for AuthorityChallenge.
use super::*;
#[test]
fn authenticated_clock_expiry_does_not_hide_invalid_progression() {
    let health = ClockHealth::new(1000, 100, 1100, 20).unwrap();
    assert!(
        !health
            .observe_at(2000, 1100)
            .unwrap_err()
            .is::<crate::consensus_clock::ObservationExpired>()
    );
    let authenticated = health.authenticated_observation();
    assert!(
        authenticated
            .observe_at(2000, 1100)
            .unwrap_err()
            .is::<crate::consensus_clock::ObservationExpired>()
    );
    for (wall, boot) in [(2000, 99), (3000, 1100)] {
        assert!(
            !authenticated
                .observe_at(wall, boot)
                .unwrap_err()
                .is::<crate::consensus_clock::ObservationExpired>()
        );
    }
}
#[test]
fn validity_expiry_never_hides_context_not_before_or_clock_mismatch() {
    let session = Session::new().unwrap();
    let challenge = Challenge {
        client_nonce: [7; 32],
        network: [1; 32],
        incarnation: [2; 32],
        recipient: [3; 32],
        boot_id: session.boot_id,
        nonce: [4; 32],
        intent: [5; 32],
        created_at_ms: 10000,
        expires_at_ms: 15000,
        maximum_duration_ms: 5000,
        digest: [7; 32],
    };
    let live = Live {
        digest: challenge.digest,
        intent: challenge.intent,
        issue_boot_ms: 100,
        deadline_boot_ms: 5100,
    };
    let now = Observation {
        wall_ms: 14900,
        boot_ms: 5000,
    };
    assert!(
        session
            .check_live_at(&challenge, &live, 15000, 10000, now)
            .unwrap_err()
            .is::<ValidityExpired>()
    );
    for (not_before, boot, intent) in [
        (15000, 5000, challenge.intent),
        (15000, 5100, challenge.intent),
        (10000, 99, challenge.intent),
        (10000, 5000, [8; 32]),
    ] {
        let mut invalid = challenge.clone();
        invalid.intent = intent;
        let error = session
            .check_live_at(
                &invalid,
                &live,
                15000,
                not_before,
                Observation {
                    wall_ms: 14900,
                    boot_ms: boot,
                },
            )
            .unwrap_err();
        assert!(!error.is::<ValidityExpired>() && !error.is::<ChallengeExpired>());
    }
}
#[test]
fn elapsed_challenge_never_hides_context_or_clock_mismatch() {
    let mut session = Session::new().unwrap();
    let challenge = Challenge {
        client_nonce: [7; 32],
        network: [1; 32],
        incarnation: [2; 32],
        recipient: [3; 32],
        boot_id: session.boot_id,
        nonce: [4; 32],
        intent: [5; 32],
        created_at_ms: 10000,
        expires_at_ms: 15000,
        maximum_duration_ms: 5000,
        digest: [7; 32],
    };
    let mut live = Live {
        digest: challenge.digest,
        intent: challenge.intent,
        issue_boot_ms: 100,
        deadline_boot_ms: 5100,
    };
    let now = Observation {
        wall_ms: 15000,
        boot_ms: 5100,
    };
    assert!(
        session
            .check_live_at(&challenge, &live, 15000, 10000, now)
            .unwrap_err()
            .is::<ChallengeExpired>()
    );
    for field in 0..5 {
        let mut invalid = challenge.clone();
        match field {
            0 => invalid.boot_id = [99; 32],
            1 => invalid.digest = [99; 32],
            2 => invalid.intent = [99; 32],
            3 => invalid.maximum_duration_ms = 4999,
            _ => live.issue_boot_ms = 5101,
        }
        assert!(
            !session
                .check_live_at(&invalid, &live, 15000, 10000, now)
                .unwrap_err()
                .is::<ChallengeExpired>()
        );
    }
    live.issue_boot_ms = 100;
    session.challenges.insert(challenge.nonce, live);
    assert!(
        session
            .check_at(&challenge, 15000, 10000, now)
            .unwrap_err()
            .is::<ChallengeExpired>()
    );
    assert_eq!(session.challenges.len(), 1);
    session.challenges.clear();
    assert!(
        !session
            .check_at(&challenge, 15000, 10000, now)
            .unwrap_err()
            .is::<ChallengeExpired>()
    );
}
#[test]
fn clock_error_budget_does_not_add_another_uncertainty_allowance() {
    let health = ClockHealth::new(1000, 20, 100, 250).unwrap();
    assert!(health.observe_at(1001, 21).is_ok());
    assert!(health.observe_at(1002, 21).is_err());
    assert!(health.observe_at(1000, 21).is_err());
    assert!(health.observe_at(1080, 100).is_err());
    assert!(ClockHealth::new(1000, 20, 100, 251).is_err());
}
#[test]
fn challenges_expire_at_original_boot_deadline_and_strict_absolute_boundary() {
    let mut session = Session::new().unwrap();
    let challenge = Challenge {
        client_nonce: [7; 32],
        network: [1; 32],
        incarnation: [2; 32],
        recipient: [3; 32],
        boot_id: session.boot_id,
        nonce: [4; 32],
        intent: [5; 32],
        created_at_ms: 10000,
        expires_at_ms: 15000,
        maximum_duration_ms: 5000,
        digest: [7; 32],
    };
    session.challenges.insert(
        challenge.nonce,
        Live {
            digest: challenge.digest,
            intent: challenge.intent,
            issue_boot_ms: 100,
            deadline_boot_ms: 5100,
        },
    );
    assert!(
        session
            .check_at(
                &challenge,
                15000,
                10000,
                Observation {
                    wall_ms: 10250,
                    boot_ms: 350
                }
            )
            .is_ok()
    );
    assert!(
        session
            .check_at(
                &challenge,
                15000,
                10000,
                Observation {
                    wall_ms: 14750,
                    boot_ms: 4850
                }
            )
            .is_err()
    );
    assert!(
        session
            .check_at(
                &challenge,
                15000,
                10000,
                Observation {
                    wall_ms: 10250,
                    boot_ms: 5100
                }
            )
            .is_err()
    );
    assert!(
        Session::new()
            .unwrap()
            .check_at(
                &challenge,
                15000,
                10000,
                Observation {
                    wall_ms: 10250,
                    boot_ms: 350
                }
            )
            .is_err()
    );
}
#[test]
fn immediate_results_preserve_independent_credential_start_and_original_deadline() {
    let mut session = Session::new().unwrap();
    let issued = ClockHealth::new(10000, 100, 6000, 0).unwrap().frozen();
    let mut fixture = crate::authority_proof::tests::Fixture::new(10000);
    fixture.challenge = session
        .issue(&fixture.intent, &fixture.recipient, [92; 32], 5000, issued)
        .unwrap();
    fixture.rebuild();
    let result = fixture.verify().unwrap();
    let current = ClockHealth::new(10100, 200, 6000, 0).unwrap().frozen();
    assert!(session.check(&result, 0, current).is_ok());
    assert!(session.check(&result, 9850, current).is_ok());
    assert!(session.check(&result, 9851, current).is_err());
    let expired = ClockHealth::new(10100, 5100, 7000, 0).unwrap().frozen();
    assert!(session.check(&result, 0, expired).is_err());
}
fn consumed() -> (Session, Consumption) {
    let mut session = Session::new().unwrap();
    let health = ClockHealth::new(10000, 100, 6000, 0).unwrap().frozen();
    let mut fixture = crate::authority_proof::tests::Fixture::new(10000);
    fixture.challenge = session
        .issue(&fixture.intent, &fixture.recipient, [91; 32], 5000, health)
        .unwrap();
    fixture.rebuild();
    let result = fixture.verify().unwrap();
    let consumed = session.consume(&result, 9750, health).unwrap();
    assert!(session.check(&result, 9750, health).is_err());
    (session, consumed)
}
#[test]
fn consumed_return_keeps_original_deadlines_and_cannot_restore_the_challenge() {
    let (mut session, token) = consumed();
    let nonce = token.challenge.nonce;
    let now = ClockHealth::new(13499, 3599, 7000, 0).unwrap().frozen();
    session.finish_consumption(token, now).unwrap();
    assert!(!session.challenges.contains_key(&nonce));
    let (mut session, token) = consumed();
    let absolute_boundary = ClockHealth::new(13500, 3600, 7000, 0).unwrap().frozen();
    assert!(
        session
            .finish_consumption(token, absolute_boundary)
            .is_err()
    );
    let (mut session, token) = consumed();
    let boot_boundary = ClockHealth::new(13000, 5100, 7000, 0).unwrap().frozen();
    assert!(session.finish_consumption(token, boot_boundary).is_err());
    let (_session, token) = consumed();
    assert!(
        Session::new()
            .unwrap()
            .finish_consumption(token, now)
            .is_err()
    );
}
