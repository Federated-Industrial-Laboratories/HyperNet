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
