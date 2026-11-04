// SPDX-License-Identifier: MIT
// Unit tests for RouteAuthority.
use super::*;

#[test]
fn durable_acceptance_timing_closes_on_success_and_failure_without_repeating_work() {
    use std::cell::RefCell;
    let order = RefCell::new(Vec::new());
    for fail in [false, true] {
        order.borrow_mut().clear();
        let result = read::observe_acceptance(
            |stage| {
                order.borrow_mut().push(match stage {
                    ReadStage::PublishStart => "start",
                    ReadStage::PublishComplete => "complete",
                })
            },
            || {
                order.borrow_mut().push("accept");
                if fail {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
                } else {
                    Ok(17)
                }
            },
        );
        assert_eq!(*order.borrow(), ["start", "accept", "complete"]);
        if fail {
            assert_eq!(
                result
                    .unwrap_err()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        } else {
            assert_eq!(result.unwrap(), 17);
        }
    }
}

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
    costs.observe(&lookup, own, 1800, true);
    costs.observe(&voucher, own, 1700, true);
    costs.observe(&unrelated, own, 4500, true);
    assert_eq!(costs.own_ms, Some(1800));
    assert_eq!(costs.voucher_ms(), 1700);
    assert_eq!(costs.action_ms, 4500);
    costs.observe(&lookup, own, 650, true);
    costs.observe(&voucher, own, 700, true);
    assert_eq!(costs.own_ms, Some(650));
    assert_eq!(costs.voucher_ms(), 700);
    assert_eq!(costs.action_ms, 700);
}

#[test]
fn stream_renewal_estimate_excludes_unrelated_work_and_refusals() {
    let own = [3; 32];
    let session = VersionRef {
        kind: 173,
        id: [4; 32],
        generation: 1,
        digest: [5; 32],
    };
    let permit = DomainCommand::Stream(streams::Command::Permit {
        session: session.clone(),
    });
    let cleanup = DomainCommand::Stream(streams::Command::RetirementContext { session });
    let lookup = DomainCommand::Route(routes::Command::Lookup { service: own });
    let mut costs = OperationCosts::default();
    costs.observe(&cleanup, own, 4500, true);
    assert_eq!(costs.stream_ms(), 4500);
    costs.observe(&permit, own, 180, false);
    assert!(costs.stream_ms.is_none());
    costs.observe(&permit, own, 170, true);
    costs.observe(&cleanup, own, 4600, true);
    assert_eq!(costs.stream_ms(), 170);
    assert_eq!(costs.action_ms, 4600);
    costs.observe(&lookup, own, 80, true);
    assert_eq!(costs.own_ms, Some(80));
    assert_eq!(costs.stream_ms(), 170);
    costs.observe(&permit, own, 4900, false);
    assert_eq!(costs.stream_ms(), 170);
    costs.observe(&permit, own, 120, true);
    assert_eq!(costs.stream_ms(), 120);
}

#[test]
fn certified_endpoint_binding_rejects_another_route_or_local_profile() {
    let route = VersionRef {
        kind: 165,
        id: [7; 32],
        generation: 1,
        digest: [8; 32],
    };
    let profile = b"Exact endpoint profile";
    let binding = EndpointBinding::checked(&route, route.id, profile, profile).unwrap();
    assert_eq!(
        CertifiedEndpointPermit {
            binding,
            expires: 7000
        }
        .expiry_for(profile)
        .unwrap(),
        7000
    );
    assert!(
        CertifiedEndpointPermit {
            binding,
            expires: 7000
        }
        .expiry_for(b"Other profile")
        .is_err()
    );
    assert!(EndpointBinding::checked(&route, [9; 32], profile, profile).is_err());
    assert!(
        EndpointBinding::checked(&route, route.id, b"Other registered envelope", profile).is_err()
    );
    let mut wrong_kind = route.clone();
    wrong_kind.kind = 172;
    assert!(EndpointBinding::checked(&wrong_kind, route.id, profile, profile).is_err());
}

#[test]
fn certified_stream_renewal_uses_exact_result_expiry_and_never_a_refusal() {
    let session = VersionRef {
        kind: 173,
        id: [1; 32],
        generation: 1,
        digest: [2; 32],
    };
    let observation = |disposition, expires| read::Observation {
        value: None,
        disposition,
        code: 0,
        statement: crate::authority_read::Statement {
            scope: proof::Scope {
                network: [3; 32],
                incarnation: [4; 32],
                configuration: [5; 32],
                epoch: 1,
            },
            request: [6; 32],
            challenge: [7; 32],
            requester: [8; 32],
            recipient: [8; 32],
            height: 1,
            node: [9; 32],
            state: [10; 32],
            evaluated_at_ms: 1_000_000,
            expires_at_ms: expires,
            result: [11; 32],
        },
    };
    let health = || {
        authority_challenge::ClockHealth::new(
            1_000_000,
            1000,
            1000 + crate::consensus_clock::SAMPLE_LIFETIME_MS,
            0,
        )
        .unwrap()
        .frozen()
    };
    let certified = |original_deadline| {
        StreamCheck::certified(
            &session,
            Some(EndpointBinding(wire::digest(b"Exact endpoint profile"))),
            observation(Disposition::Permit, 1_005_000),
            original_deadline,
            health(),
        )
        .unwrap()
    };
    // The real one-second clock observation bounds this action, not the
    // independently certified permission used by ordinary stream maintenance.
    let checked = certified(4000);
    assert_eq!(checked.deadline, 2000);
    assert_eq!(
        checked
            .endpoint_renewal
            .unwrap()
            .expiry_for(b"Exact endpoint profile")
            .unwrap(),
        6000 - authority_challenge::DELTA_MS
    );
    assert_eq!(
        checked.renewal.unwrap().expiry_for(&session).unwrap(),
        6000 - authority_challenge::DELTA_MS
    );
    let shorter_call = certified(1500);
    assert_eq!(shorter_call.deadline, 1500);
    assert_eq!(
        shorter_call.renewal.unwrap().expiry_for(&session).unwrap(),
        6000 - authority_challenge::DELTA_MS
    );
    for field in 0..4 {
        let mut wrong = session.clone();
        match field {
            0 => wrong.kind += 1,
            1 => wrong.id[0] ^= 1,
            2 => wrong.generation += 1,
            3 => wrong.digest[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(certified(4000).renewal.unwrap().expiry_for(&wrong).is_err());
    }
    let denied = StreamCheck::certified(
        &session,
        None,
        observation(Disposition::Refuse, 1_005_000),
        2000,
        health(),
    )
    .unwrap();
    assert!(denied.renewal.is_none());
    assert!(denied.endpoint_renewal.is_none());
    assert_eq!(denied.deadline, 2000);
    assert!(
        StreamCheck::certified(
            &session,
            None,
            observation(Disposition::Permit, 1_005_000),
            2000,
            health()
        )
        .is_err()
    );
    assert!(
        StreamCheck::certified(
            &session,
            Some(EndpointBinding(wire::digest(b"Exact endpoint profile"))),
            observation(Disposition::Pending, 1_005_000),
            2000,
            health()
        )
        .is_err()
    );
    assert!(
        StreamCheck::certified(
            &session,
            Some(EndpointBinding(wire::digest(b"Exact endpoint profile"))),
            observation(Disposition::Permit, 999_999),
            2000,
            health()
        )
        .is_err()
    );
}
