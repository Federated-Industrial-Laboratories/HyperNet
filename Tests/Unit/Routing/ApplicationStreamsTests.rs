// SPDX-License-Identifier: MIT
// Admission, cancellation and slot retirement preserve identity and quota across restart.
use super::*;
use crate::authority_domains::streams::{self, Command as StreamCommand};
use ed25519_dalek::Signer;
fn signed_twice(payload: &[u8], seeds: &[u8]) -> Vec<u8> {
    let mut signatures = seeds
        .iter()
        .map(|seed| {
            let key = deployment::key(*seed);
            let public = key.verifying_key().to_bytes();
            (
                public,
                key.sign(&wire::signature_message(payload, &public))
                    .to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|s| s.0);
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .iter()
            .map(|(key, sig)| a(vec![b(key), b(sig)]))
            .collect()),
    ]))
    .unwrap()
}
fn execute(
    f: &mut Fixture,
    command: impl Into<crate::authority_domains::Command>,
    signer: u8,
    grant: Option<VersionRef>,
    at: u64,
    apply: bool,
) -> (Intent, Operation, Decision) {
    let mut op = Operation {
        grant,
        command: command.into(),
        snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
    };
    let sign = |op: &Operation, refs| {
        Intent::from_signed(&deployment::signed(
            &deployment::key(signer),
            "AuthorityDomain",
            op.command.resource(),
            u64::from(op.mutation()),
            wire::decode(&op.parameters().unwrap()).unwrap(),
            refs,
        ))
        .unwrap()
    };
    let mut intent = sign(&op, vec![]);
    let mut d = op
        .prepare(&f.state, &f.records, &f.reserved, &intent, at, false, false)
        .unwrap();
    if d.code == 0 {
        op.snapshot = snapshot(&deployment::snapshot(&d.dependencies)).unwrap();
        intent = sign(&op, d.dependencies);
        d = op
            .prepare(&f.state, &f.records, &f.reserved, &intent, at, false, true)
            .unwrap();
    }
    if apply {
        assert_eq!(d.code, 0);
        if let Some(state) = &d.state {
            f.state = state.clone();
        }
        f.state = State::parse(&f.state.value(), N, I).unwrap();
    }
    (intent, op, d)
}
fn setup() -> (Fixture, streams::Registration) {
    let mut f = Fixture::new();
    f.profiles[1].protocol = streams::PROTOCOL;
    seal(&mut f.profiles[1], 92);
    f.register();
    let p = &f.profiles[1];
    let mut registration = streams::Registration {
        id: [221; 32],
        route: f.state.record(165, DESTINATION).unwrap().reference.clone(),
        owner: public(5),
        operator: public(92),
        protocol: "example.events/1".into(),
        binding: [222; 32],
        limits: p.limits,
        validity: p.validity,
        envelope: vec![],
    };
    registration.envelope = signed_twice(&registration.payload(N, I).unwrap(), &[5, 92]);
    registration = streams::Registration::parse(&registration.envelope, N, I).unwrap();
    let grant =
        deployment::scoped_grant(&mut f.records, &f.root, [232; 32], &[(3, registration.id)]);
    execute(
        &mut f,
        StreamCommand::Register {
            registration: registration.clone(),
        },
        5,
        Some(grant),
        5000,
        true,
    );
    (f, registration)
}
fn proof(
    f: &Fixture,
    registration: &streams::Registration,
    generation: u64,
    nonce: u8,
) -> streams::Proof {
    let mut p = streams::Proof {
        service: f
            .state
            .record(172, registration.id)
            .unwrap()
            .reference
            .clone(),
        principal: public(5),
        grant: Governance::parse(N, I, &f.records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [232; 32])
            .unwrap(),
        protocol: registration.protocol.clone(),
        slot: 0,
        generation,
        nonce: [nonce; 32],
        challenge: [nonce.wrapping_add(1); 32],
        exporter: [200; 32],
        limits: registration.limits,
        expires: 5000 + registration.limits.duration_ms,
        envelope: vec![],
    };
    p.envelope = wire::sign_envelope(&p.payload(N, I).unwrap(), &deployment::key(5)).unwrap();
    streams::Proof::parse(&p.envelope, N, I).unwrap()
}
fn retirement_context(
    f: &mut Fixture,
    original: &VersionRef,
    at: u64,
) -> crate::authority_domains::result::Candidate {
    use crate::authority_read::{self as read, Query, Request, Statement};
    let (_, mut operation, decision) = execute(
        f,
        StreamCommand::RetirementContext {
            session: original.clone(),
        },
        161,
        None,
        at,
        false,
    );
    assert_eq!(decision.code, 0);
    assert!(decision.state.is_none());
    assert_eq!(
        decision.versions.iter().map(|r| r.kind).collect::<Vec<_>>(),
        [165, 172, 173]
    );
    operation.snapshot = snapshot(&deployment::snapshot(&[])).unwrap();
    let bootstrap = crate::trust_bootstrap::check(&f.bootstrap, true, 5000).unwrap();
    let signed = Request::sign(
        bootstrap.descriptor().scope(),
        &deployment::key(161),
        public(161),
        [77; 32],
        operation.snapshot.height,
        Query::Domain(operation),
    )
    .unwrap();
    let request = Request::from_signed(&signed).unwrap();
    let bytes = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        V::Uint(0),
        V::Uint(0),
        b(&wire::encode(&decision.value).unwrap()),
    ]))
    .unwrap();
    let result = crate::authority_proof::OperationResult::parse(&bytes).unwrap();
    let statement = Statement {
        scope: request.scope.clone(),
        request: request.digest,
        challenge: [78; 32],
        requester: public(161),
        recipient: public(161),
        height: request.minimum_height,
        node: [79; 32],
        state: [80; 32],
        evaluated_at_ms: at,
        expires_at_ms: at + 5000,
        result: wire::digest(&bytes),
    };
    // Exercise the same independent typed-context consumer as RouteAuthority.
    read::verify_domain(
        &bootstrap,
        &f.state,
        &f.records,
        &request,
        &result,
        &statement,
        &[],
    )
    .unwrap()
}

#[test]
fn pending_cleanup_classification_requires_exact_session_proof_and_unfenced_ordinary() {
    let (mut f, registration) = setup();
    let admitted = proof(&f, &registration, 1, 81);
    let proof_digest = wire::digest(&admitted.envelope);
    execute(
        &mut f,
        StreamCommand::Admit {
            proof: admitted.clone(),
        },
        161,
        None,
        5000,
        true,
    );
    let original = f
        .state
        .record(173, admitted.id().unwrap())
        .unwrap()
        .reference
        .clone();
    for mode in 0..6 {
        let (directory, clock, _, mut store) = crate::authority_floor::tests::setup();
        assert!(crate::route_authority::pending_stream_close(
            &store, &f.state, &original, proof_digest,
        ).unwrap().is_none());
        let slot = store.ordinary_slot().unwrap();
        let fixture = crate::authority_proof::tests::Fixture::new(clock.observe().unwrap().wall_ms);
        let (payload, _) = wire::envelope(&fixture.intent, 1).unwrap();
        let V::Array(mut fields) = wire::decode(&payload).unwrap() else {
            unreachable!()
        };
        let mut target = original.clone();
        if mode == 1 {
            target.digest = [97; 32];
        }
        let command = if mode == 2 {
            StreamCommand::Permit { session: target }
        } else {
            StreamCommand::Close { session: target }
        };
        let operation = Operation {
            command: command.into(),
            grant: (mode == 3).then(|| admitted.grant.clone()),
            snapshot: snapshot(&a(vec![
                a(vec![
                    V::Uint(slot.minimum_policy_epoch()),
                    V::Uint(slot.minimum_policy_height()),
                    b(store.prefix().policy_state()),
                ]),
                a(vec![]),
            ]))
            .unwrap(),
        };
        fields[4] = V::Uint(slot.generation());
        fields[5] = b(&slot.generation_id());
        fields[6] = V::Uint(slot.sequence());
        fields[7] = V::Uint(slot.acknowledged_through());
        fields[9] = V::Text("AuthorityDomain".into());
        fields[10] = b(&operation.command.resource());
        fields[11] = V::Uint(u64::from(operation.command.mutation()));
        fields[12] = V::Uint(0);
        fields[13] = V::Uint(slot.minimum_policy_epoch());
        fields[14] = V::Uint(slot.minimum_policy_height());
        fields[15] = a(vec![]);
        fields[16] = b(&operation.parameters().unwrap());
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let signed = wire::sign_envelope(&wire::encode(&a(fields)).unwrap(), &key).unwrap();
        store.prepare_ordinary(slot, &signed).unwrap();
        if mode == 4 {
            let old = store.stream_metadata().unwrap().unwrap();
            let prior = old.state().unwrap();
            let scope = store.descriptor().scope();
            let fence = wire::sign_envelope(
                &wire::encode(&a(vec![
                    V::Uint(57),
                    V::Uint(1),
                    b(&scope.network),
                    b(&scope.incarnation),
                    b(&store.requester()),
                    b(&[96; 32]),
                    V::Uint(scope.epoch),
                    V::Uint(store.prefix().height()),
                    V::Uint(prior.generation),
                    b(&prior.generation_id),
                    b(&wire::digest(old.canonical())),
                ]))
                .unwrap(),
                &key,
            )
            .unwrap();
            store.prepare_fence(&fence, old.canonical()).unwrap();
        }
        let bound = crate::route_authority::pending_stream_close(
            &store,
            &f.state,
            &original,
            if mode == 5 { [98; 32] } else { proof_digest },
        )
        .unwrap();
        assert_eq!(bound, (mode == 0).then(|| wire::digest(&signed)));
        assert_eq!(store.resume_ordinary().unwrap().unwrap().signed(), signed);
        assert_eq!(store.resume_fence().unwrap().is_some(), mode == 4);
        if mode == 0 {
            let mut reused = original.clone();
            reused.generation += 1;
            assert!(
                crate::route_authority::pending_stream_close(
                    &store,
                    &f.state,
                    &reused,
                    proof_digest,
                )
                .unwrap()
                .is_none()
            );
            std::fs::remove_file(directory.0.join("AuthorityFloor.json")).unwrap();
            assert!(
                crate::route_authority::pending_stream_close(
                    &store,
                    &f.state,
                    &original,
                    proof_digest,
                )
                .is_err(),
                "unreadable requester state cannot authorize waiting"
            );
        }
    }
}

#[test]
fn caller_close_race_refreshes_only_the_same_proof_before_endpoint_retirement() {
    let (mut f, registration) = setup();
    let p = proof(&f, &registration, 1, 30);
    let digest = wire::digest(&p.envelope);
    execute(
        &mut f,
        StreamCommand::Admit { proof: p.clone() },
        161,
        None,
        5000,
        true,
    );
    let original = f
        .state
        .record(173, p.id().unwrap())
        .unwrap()
        .reference
        .clone();
    let (intent, pending, _) = execute(
        &mut f,
        StreamCommand::Close {
            session: original.clone(),
        },
        161,
        None,
        5000,
        false,
    );
    execute(
        &mut f,
        StreamCommand::Close {
            session: original.clone(),
        },
        5,
        None,
        5000,
        true,
    );
    assert_eq!(
        pending
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &intent,
                5000,
                false,
                true
            )
            .unwrap()
            .code,
        3
    );
    let cancelled = f.state.record(173, original.id).unwrap().reference.clone();
    let next = proof(&f, &registration, cancelled.generation + 1, 40);
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: next },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );

    let context = retirement_context(&mut f, &original, 5000);
    let target = crate::route_authority::retirement_target(&context.state, &original, digest)
        .unwrap()
        .unwrap();
    assert_eq!(target, cancelled);
    assert!(
        crate::route_authority::retirement_target(&context.state, &original, [99; 32])
            .unwrap()
            .is_none()
    );
    execute(
        &mut f,
        StreamCommand::Close { session: target },
        161,
        None,
        5000,
        true,
    );
    let context = retirement_context(&mut f, &original, 5000);
    assert!(
        crate::route_authority::retirement_target(&context.state, &original, digest)
            .unwrap()
            .is_none()
    );
    let generation = f
        .state
        .record(173, original.id)
        .unwrap()
        .reference
        .generation
        + 1;
    let next = proof(&f, &registration, generation, 41);
    execute(
        &mut f,
        StreamCommand::Admit { proof: next },
        161,
        None,
        5000,
        true,
    );
    let context = retirement_context(&mut f, &original, 5000);
    assert!(
        crate::route_authority::retirement_target(&context.state, &original, digest)
            .unwrap()
            .is_none(),
        "old cleanup cannot close a reused slot"
    );
}

#[test]
fn retirement_context_is_endpoint_only_and_survives_revocation_and_expiry() {
    for invalidation in ["withdrawn", "revoked", "expired"] {
        let (mut f, registration) = setup();
        let p = proof(&f, &registration, 1, 50);
        execute(
            &mut f,
            StreamCommand::Admit { proof: p.clone() },
            161,
            None,
            5000,
            true,
        );
        let original = f
            .state
            .record(173, p.id().unwrap())
            .unwrap()
            .reference
            .clone();
        execute(
            &mut f,
            StreamCommand::Close {
                session: original.clone(),
            },
            5,
            None,
            5000,
            true,
        );
        let at = match invalidation {
            "expired" => p.expires + 1,
            "revoked" => {
                f.records.push(
                    wire::encode(&a(vec![
                        V::Uint(126),
                        V::Uint(1),
                        b(&N),
                        b(&I),
                        V::Uint(1),
                        V::Null,
                        reference(&p.grant),
                        b(&public(5)),
                        deployment::snapshot(&[]),
                    ]))
                    .unwrap(),
                );
                members::sort_records(&mut f.records).unwrap();
                Governance::parse(N, I, &f.records).unwrap();
                5000
            }
            _ => {
                f.withdraw_deployment();
                5000
            }
        };
        assert_eq!(
            execute(
                &mut f,
                StreamCommand::Inspect { proof: p.clone() },
                161,
                None,
                at,
                false
            )
            .2
            .code,
            3
        );
        for signer in [5, 160] {
            assert_eq!(
                execute(
                    &mut f,
                    StreamCommand::RetirementContext {
                        session: original.clone()
                    },
                    signer,
                    None,
                    at,
                    false
                )
                .2
                .code,
                3
            );
        }
        let context = retirement_context(&mut f, &original, at);
        let target = crate::route_authority::retirement_target(
            &context.state,
            &original,
            wire::digest(&p.envelope),
        )
        .unwrap()
        .unwrap();
        execute(
            &mut f,
            StreamCommand::Close { session: target },
            161,
            None,
            at,
            true,
        );
        let current =
            streams::Session::parse(&f.state.record(173, original.id).unwrap().payload, N, I)
                .unwrap();
        assert!(current.closed && current.retired);
    }
}
#[test]
fn application_stream_principal_retirement_and_restart_are_independent_of_relay_access() {
    let (mut f, registration) = setup();
    let p = proof(&f, &registration, 1, 30);
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: p.clone() },
            160,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
    let (intent, op, d) = execute(
        &mut f,
        StreamCommand::Admit { proof: p.clone() },
        161,
        None,
        5000,
        true,
    );
    let first = f
        .state
        .record(173, p.id().unwrap())
        .unwrap()
        .reference
        .clone();
    let replay = op
        .prepare(&f.state, &f.records, &f.reserved, &intent, 5000, true, true)
        .unwrap();
    assert_eq!(replay.code, 0);
    assert_eq!(replay.value, d.value);
    assert!(replay.state.is_none());
    execute(
        &mut f,
        StreamCommand::Close {
            session: first.clone(),
        },
        5,
        None,
        5000,
        true,
    );
    let cancelled = f.state.record(173, first.id).unwrap().reference.clone();
    let next = proof(&f, &registration, 3, 40);
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: next },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
    execute(
        &mut f,
        StreamCommand::Close { session: cancelled },
        161,
        None,
        5000,
        true,
    );
    let stable_count = f.state.records.len();
    for nonce in 50..82 {
        let generation = f.state.record(173, first.id).unwrap().reference.generation + 1;
        let p = proof(&f, &registration, generation, nonce);
        execute(
            &mut f,
            StreamCommand::Admit { proof: p },
            161,
            None,
            5000,
            true,
        );
        assert_eq!(
            execute(
                &mut f,
                StreamCommand::Permit {
                    session: first.clone()
                },
                161,
                None,
                5000,
                false
            )
            .2
            .code,
            3
        );
        let current = f.state.record(173, first.id).unwrap().reference.clone();
        execute(
            &mut f,
            StreamCommand::Permit {
                session: current.clone(),
            },
            161,
            None,
            5000,
            true,
        );
        execute(
            &mut f,
            StreamCommand::Close { session: current },
            161,
            None,
            5000,
            true,
        );
        assert_eq!(f.state.records.len(), stable_count);
    }
    let generation = f.state.record(173, first.id).unwrap().reference.generation + 1;
    let p = proof(&f, &registration, generation, 100);
    execute(
        &mut f,
        StreamCommand::Admit { proof: p },
        161,
        None,
        5000,
        true,
    );
    let current = f.state.record(173, first.id).unwrap().reference.clone();
    f.withdraw_deployment();
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Permit { session: current },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
}
#[test]
fn application_stream_requires_current_grant_exact_service_and_local_context_nonce() {
    let (mut f, registration) = setup();
    let mut p = proof(&f, &registration, 1, 30);
    p.principal = public(200);
    p.envelope = wire::sign_envelope(&p.payload(N, I).unwrap(), &deployment::key(200)).unwrap();
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: p },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
    let mut p = proof(&f, &registration, 1, 31);
    p.protocol = "example.other/1".into();
    p.envelope = wire::sign_envelope(&p.payload(N, I).unwrap(), &deployment::key(5)).unwrap();
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: p },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
    let p = proof(&f, &registration, 1, 32);
    execute(
        &mut f,
        StreamCommand::Admit { proof: p.clone() },
        161,
        None,
        5000,
        true,
    );
    let session = f
        .state
        .record(173, p.id().unwrap())
        .unwrap()
        .reference
        .clone();
    let binding = streams::local::Binding {
        version: 1,
        id: [8; 32],
        network: N,
        incarnation: I,
        service: registration.id,
        owner: public(5),
        endpoint: public(161),
        protocol: registration.protocol,
    };
    let context =
        streams::local::context(&binding, &session, &p, [9; 32], &deployment::key(161)).unwrap();
    assert_eq!(
        streams::local::verify_context(&context, &binding, [9; 32])
            .unwrap()
            .principal,
        hex::encode(public(5))
    );
    assert!(streams::local::verify_context(&context, &binding, [10; 32]).is_err());
    let mut substituted = binding;
    substituted.endpoint = public(160);
    assert!(streams::local::verify_context(&context, &substituted, [9; 32]).is_err());
}

#[test]
fn application_stream_refuses_broad_mixed_and_sealed_grants() {
    let (mut f, registration) = setup();
    let precise = proof(&f, &registration, 1, 120).grant;
    let mixed = deployment::scoped_grant(
        &mut f.records,
        &f.root,
        [233; 32],
        &[(2, registration.id), (3, registration.id)],
    );
    let sealed =
        deployment::scoped_grant(&mut f.records, &f.root, [234; 32], &[(2, registration.id)]);
    for grant in [f.root.clone(), mixed, sealed] {
        for action in [streams::MANAGE, streams::CONNECT] {
            let result = execute(
                &mut f,
                StreamCommand::Context {
                    service: registration.id,
                    action,
                },
                5,
                Some(grant.clone()),
                5000,
                false,
            )
            .2;
            assert_eq!(result.code, 3);
        }
        let mut p = proof(&f, &registration, 1, 120);
        p.grant = grant;
        p.envelope = wire::sign_envelope(&p.payload(N, I).unwrap(), &deployment::key(5)).unwrap();
        assert_eq!(
            execute(
                &mut f,
                StreamCommand::Admit { proof: p },
                161,
                None,
                5000,
                false
            )
            .2
            .code,
            3
        );
    }
    for action in [streams::MANAGE, streams::CONNECT] {
        assert_eq!(
            execute(
                &mut f,
                StreamCommand::Context {
                    service: registration.id,
                    action
                },
                5,
                Some(precise.clone()),
                5000,
                false
            )
            .2
            .code,
            0
        );
    }
    // Historical service records still parse, but their broad management grant
    // cannot authorise a new connection after the upgrade.
    let mut legacy =
        streams::Service::parse(&f.state.record(172, registration.id).unwrap().payload, N, I)
            .unwrap();
    legacy.grant = f.root.clone();
    let next = Record::next(&f.state, 172, registration.id, legacy.value()).unwrap();
    f.state.records.insert(next.reference.index(), next);
    f.state = State::parse(&f.state.value(), N, I).unwrap();
    let p = proof(&f, &registration, 1, 121);
    assert_eq!(
        execute(
            &mut f,
            StreamCommand::Admit { proof: p },
            161,
            None,
            5000,
            false
        )
        .2
        .code,
        3
    );
}

#[test]
fn expired_voucher_renews_one_identifier_without_resetting_live_or_old_usage() {
    let mut f = Fixture::new();
    f.register();
    let voucher = f.issue(1, CHARGE);
    f.apply(Fixture::permit(&voucher, 210), 160, None);
    let records = f.state.records.len();
    let mut issue = f.issue_command(1, CHARGE);
    if let Command::Issue { expires, .. } = &mut issue {
        *expires = 19000;
    }
    let reader = f.reader.clone();
    assert_eq!(
        execute(&mut f, issue.clone(), 5, Some(reader.clone()), 5000, false)
            .2
            .code,
        3
    );
    execute(
        &mut f,
        Command::RenewContext {
            voucher: voucher.clone(),
        },
        5,
        Some(reader.clone()),
        16000,
        true,
    );
    execute(&mut f, issue, 5, Some(reader), 16000, true);
    let next = f.state.record(166, voucher.id).unwrap().reference.clone();
    assert_eq!(next.generation, 2);
    let renewed = Voucher::parse(&f.state.record(166, voucher.id).unwrap().payload).unwrap();
    assert_eq!(renewed.baseline, Some((1, CHARGE)));
    assert_eq!(
        execute(
            &mut f,
            Fixture::permit(&voucher, 220),
            160,
            None,
            16000,
            false
        )
        .2
        .code,
        3
    );
    execute(&mut f, Fixture::permit(&next, 221), 160, None, 16000, true);
    assert_eq!(
        execute(&mut f, Fixture::permit(&next, 223), 160, None, 16000, false)
            .2
            .code,
        3
    );
    assert_eq!(f.state.records.len(), records);
    assert_eq!(
        Usage::parse(&f.state.record(167, voucher.id).unwrap().payload)
            .unwrap()
            .connections,
        2
    );
}

#[test]
fn expired_service_owner_can_read_exact_metadata_and_withdraw_without_connect_rights() {
    let (mut f, registration) = setup();
    let lookup = StreamCommand::Lookup {
        service: registration.id,
        slot: 0,
    };
    assert_eq!(
        execute(&mut f, lookup.clone(), 200, None, 1000000, false)
            .2
            .code,
        3
    );
    execute(&mut f, lookup.clone(), 5, None, 1000000, true);
    let service = f
        .state
        .record(172, registration.id)
        .unwrap()
        .reference
        .clone();
    execute(
        &mut f,
        StreamCommand::Withdraw { service },
        5,
        None,
        1000000,
        true,
    );
    execute(&mut f, lookup, 5, None, 1000000, true);
    assert!(
        streams::Service::parse(&f.state.record(172, registration.id).unwrap().payload, N, I)
            .unwrap()
            .withdrawn
    );
}
