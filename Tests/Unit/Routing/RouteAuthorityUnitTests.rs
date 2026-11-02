// SPDX-License-Identifier: MIT
// Unit tests for RouteAuthority.
use super::*;

#[test]
fn check_readiness_challenges_keep_original_window_through_authority_uncertainty() {
    let fixture = proof::tests::Fixture::new(1_000_000);
    let started = 1000;
    let wait_end = started + 1000;
    let ceiling = started + authority_challenge::MAXIMUM_DURATION_MS;
    let service = [3; 32];
    let session_ref = VersionRef {
        kind: 173,
        id: [4; 32],
        generation: 1,
        digest: [5; 32],
    };
    for command in [
        DomainCommand::Route(routes::Command::Lookup { service }),
        DomainCommand::Stream(streams::Command::Permit {
            session: session_ref,
        }),
    ] {
        let operation = Operation {
            grant: None,
            command,
            snapshot: domains::snapshot(&a(vec![
                a(vec![V::Uint(0), V::Uint(0), b(&[6; 32])]),
                a(vec![]),
            ]))
            .unwrap(),
        };
        let nonce = [7; 32];
        let request = crate::authority_read::Request::sign(
            fixture.descriptor.scope(),
            &fixture.recipient,
            fixture.recipient.verifying_key().to_bytes(),
            nonce,
            0,
            crate::authority_read::Query::Domain(operation),
        )
        .unwrap();
        let mut session = Session::new().unwrap();
        let health = |boot| {
            authority_challenge::ClockHealth::new(1_000_000 + boot, boot, boot + 1000, 0)
                .unwrap()
                .frozen()
        };
        let issue = |session: &mut Session, boot, ceiling| {
            let bytes = read::issue_challenge(
                session,
                &request,
                &fixture.recipient,
                nonce,
                wait_end,
                ceiling,
                health(boot),
            )?;
            Challenge::from_signed(&bytes)
        };

        // The old short-wait path cannot pass the authority's conservative interval.
        let old = issue(&mut session, 1800, None).unwrap();
        assert_eq!(old.maximum_duration_ms, 200);
        assert!(
            old.evaluation_expiry(old.created_at_ms, old.expires_at_ms)
                .is_err()
        );

        // Both readiness reads use the original check window, including queue time.
        let fresh = issue(&mut session, 1800, Some(ceiling)).unwrap();
        assert_eq!(fresh.maximum_duration_ms, 4200);
        assert_eq!(fresh.expires_at_ms, 1_000_000 + ceiling);
        assert!(
            fresh
                .evaluation_expiry(fresh.created_at_ms, fresh.expires_at_ms)
                .is_ok()
        );
        let later = issue(&mut session, 1900, Some(ceiling)).unwrap();
        assert_eq!(later.maximum_duration_ms, 4100);
        assert_eq!(later.expires_at_ms, fresh.expires_at_ms);
        assert!(
            later
                .evaluation_expiry(later.created_at_ms, later.expires_at_ms)
                .is_ok()
        );

        // A fresh transport opportunity cannot restart an exhausted original window.
        let error = read::issue_challenge(
            &mut session,
            &request,
            &fixture.recipient,
            nonce,
            ceiling + 1000,
            Some(ceiling),
            health(ceiling),
        )
        .unwrap_err();
        assert!(error.is::<authority_challenge::ChallengeExpired>());
    }
}

#[test]
fn private_route_recurring_cost_replaces_outliers_and_excludes_other_actions() {
    let own = [3; 32];
    let lookup = DomainCommand::Route(routes::Command::Lookup { service: own });
    let voucher = DomainCommand::Route(routes::Command::VoucherContext {
        voucher: VersionRef {
            kind: 166,
            id: [4; 32],
            generation: 1,
            digest: [5; 32],
        },
    });
    let unrelated = DomainCommand::Route(routes::Command::Lookup { service: [6; 32] });
    let mut costs = OperationCosts::default();
    costs.observe(&lookup, own, 1800);
    costs.observe(&voucher, own, 1700);
    costs.observe(&unrelated, own, 4500);
    assert_eq!(costs.own_ms, Some(1800));
    assert_eq!(costs.voucher_ms(), 1700);
    assert_eq!(costs.action_ms, 4500);
    costs.observe(&lookup, own, 650);
    costs.observe(&voucher, own, 700);
    assert_eq!(costs.own_ms, Some(650));
    assert_eq!(costs.voucher_ms(), 700);
    assert_eq!(costs.action_ms, 700);
}
