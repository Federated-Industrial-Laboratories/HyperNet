// SPDX-License-Identifier: MIT
// Activation refresh changes only the challenge and stays inside its initial deadline.
use super::*;
use crate::authority_proof::{Intent, VersionRef};
use std::cell::Cell;

fn health(elapsed: u64) -> ClockHealth {
    ClockHealth::new(10000 + elapsed, 100 + elapsed, 20000, 0)
        .unwrap()
        .frozen()
}
fn fixture() -> (Scope, Vec<u8>, SigningKey) {
    let f = crate::authority_proof::tests::Fixture::new(10000);
    let grant = VersionRef {
        kind: 102,
        id: [10; 32],
        generation: 1,
        digest: [11; 32],
    };
    let admission = VersionRef {
        kind: 129,
        id: [4; 32],
        generation: 1,
        digest: [12; 32],
    };
    let refs = V::Array(
        [&grant, &admission]
            .into_iter()
            .map(crate::authority_membership::reference)
            .collect(),
    );
    let snapshot = V::Array(vec![
        V::Array(vec![V::Uint(0), V::Uint(0), V::Bytes([13; 32].to_vec())]),
        refs.clone(),
    ]);
    let parameters = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(crate::authority_runtime_activation::ACTION.into()),
        crate::authority_membership::reference(&grant),
        crate::authority_membership::reference(&admission),
        V::Uint(7),
        V::Bytes(f.recipient.verifying_key().to_bytes().to_vec()),
        V::Uint(1),
        snapshot,
    ]))
    .unwrap();
    let (payload, _) = wire::envelope(&f.intent, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[9] = V::Text(crate::authority_runtime_activation::ACTION.into());
    fields[15] = refs;
    fields[16] = V::Bytes(parameters);
    let signed = wire::sign_envelope(
        &wire::encode(&V::Array(fields)).unwrap(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    crate::authority_runtime_activation::Operation::parse(&Intent::from_signed(&signed).unwrap())
        .unwrap();
    (f.descriptor.scope().clone(), signed, f.recipient)
}

#[test]
fn activation_refresh_keeps_intent_and_original_deadline() {
    let (scope, signed, key) = fixture();
    let mut session = Session::new().unwrap();
    let elapsed = Cell::new(0);
    let mut attempts = Vec::new();
    let result = exchange_fresh(
        &scope,
        &signed,
        &key,
        &mut session,
        &mut || Ok(health(elapsed.get())),
        &mut |ordered, deadline| {
            let value = wire::decode(ordered)?;
            let fields = value.array(6)?;
            assert_eq!(fields[3].bytes()?, signed);
            assert_eq!(deadline, 5100);
            let challenge = Challenge::from_signed(fields[4].bytes()?)?;
            assert_eq!(challenge.expires_at_ms, 15000);
            attempts.push((ordered.to_vec(), challenge));
            if attempts.len() == 1 {
                elapsed.set(1000);
                Err(transport::HistoryOvertaken.into())
            } else {
                Ok(())
            }
        },
    )
    .unwrap();
    assert_eq!(attempts.len(), 2);
    assert_ne!(attempts[0].0, attempts[1].0);
    assert_ne!(attempts[0].1.nonce, attempts[1].1.nonce);
    assert_eq!(attempts[0].1.intent, attempts[1].1.intent);
    assert_eq!(attempts[0].1.maximum_duration_ms, 5000);
    assert_eq!(attempts[1].1.maximum_duration_ms, 4000);
    assert_eq!(result.deadline, 5100);
    assert_eq!(result.ordered, attempts[1].0);
    assert_eq!(
        Challenge::from_signed(&result.challenge).unwrap().digest,
        attempts[1].1.digest
    );
}

#[test]
fn activation_refresh_stops_on_malformed_history_or_original_deadline() {
    let (scope, signed, key) = fixture();
    for overtaken in [false, true] {
        let mut session = Session::new().unwrap();
        let elapsed = Cell::new(0);
        let mut calls = 0;
        let outcome = exchange_fresh::<()>(
            &scope,
            &signed,
            &key,
            &mut session,
            &mut || Ok(health(elapsed.get())),
            &mut |_, _| {
                calls += 1;
                if overtaken {
                    elapsed.set(MAXIMUM_DURATION_MS);
                    Err(transport::HistoryOvertaken.into())
                } else {
                    anyhow::bail!("malformed checkpoint proof")
                }
            },
        );
        let error = outcome
            .err()
            .expect("failed history cannot authorise activation");
        assert_eq!(calls, 1);
        assert!(error.to_string().contains(if overtaken {
            "original activation deadline expired"
        } else {
            "malformed checkpoint proof"
        }));
    }
}
