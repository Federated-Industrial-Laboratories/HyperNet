// SPDX-License-Identifier: MIT
// Stream responses preserve exact predecessor metadata and distinguish old effects from fresh disclosure.
use super::*;
use ed25519_dalek::SigningKey;
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[91; 32])
}
fn scope() -> Scope {
    Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 0,
    }
}
fn original() -> V {
    a(vec![
        V::Uint(1),
        b(&[8; 32]),
        V::Uint(0),
        V::Uint(0),
        b(&[9; 32]),
    ])
}
fn initial(present: bool) -> V {
    let scope = scope();
    let requester = key().verifying_key().to_bytes();
    a(vec![
        V::Uint(56),
        V::Uint(1),
        scope.value(),
        b(&requester),
        V::Bool(present),
        if present { V::Uint(1) } else { V::Null },
        if present {
            b(&initial_generation_id(scope.network, scope.incarnation, requester).unwrap())
        } else {
            V::Null
        },
        V::Uint(0),
        if present { original() } else { V::Null },
        V::Null,
    ])
}
fn signed(fields: V) -> SignedRequest {
    SignedRequest::from_signed(
        &wire::sign_envelope(&wire::encode(&fields).unwrap(), &key()).unwrap(),
    )
    .unwrap()
}
fn status() -> SignedRequest {
    signed(a(vec![
        V::Uint(55),
        V::Uint(1),
        b(&scope().network),
        b(&scope().incarnation),
        b(&key().verifying_key().to_bytes()),
        b(&[4; 32]),
        V::Uint(0),
        V::Uint(0),
    ]))
}
fn fence(prior: &[u8]) -> SignedRequest {
    let metadata = OwnStreamMetadata::parse(prior).unwrap();
    let state = metadata.state().unwrap();
    signed(a(vec![
        V::Uint(57),
        V::Uint(1),
        b(&scope().network),
        b(&scope().incarnation),
        b(&key().verifying_key().to_bytes()),
        b(&[5; 32]),
        V::Uint(0),
        V::Uint(0),
        V::Uint(state.generation),
        b(&state.generation_id),
        b(&wire::digest(prior)),
    ]))
}
fn point(request: &SignedRequest) -> ExecutedResult {
    ExecutedResult {
        scope: scope(),
        height: 1,
        committed_node: [10; 32],
        ordered_request: [11; 32],
        intent: request.digest(),
        challenge: [12; 32],
        requester: request.requester(),
        recipient: request.requester(),
        action: request.action().into(),
        resource: request.resource(),
        revision: request.revision(),
        profile_generation: 0,
        maximum_effect: 1,
        result: [13; 32],
        policy_state: [14; 32],
        minimum_policy_height: 0,
        evaluated_at_ms: 1000,
        expires_at_ms: 5000,
        restrictions: super::super::Restrictions::default(),
    }
}
fn result(request: &SignedRequest, value: V) -> OperationResult {
    OperationResult {
        action: request.action().into(),
        disposition: Disposition::Permit,
        code: 0,
        value: wire::encode(&value).unwrap(),
    }
}
fn fenced(request: &SignedRequest, prior: &[u8], later: bool) -> V {
    let metadata = OwnStreamMetadata::parse(prior).unwrap();
    let state = metadata.state().unwrap();
    a(vec![
        V::Uint(56),
        V::Uint(1),
        scope().value(),
        b(&request.requester()),
        V::Bool(true),
        V::Uint(2),
        b(&request.digest()),
        V::Uint(u64::from(later)),
        if later {
            a(vec![
                V::Uint(2),
                b(&[15; 32]),
                V::Uint(1),
                V::Uint(6),
                b(&[16; 32]),
            ])
        } else {
            V::Null
        },
        a(vec![
            b(&request.digest()),
            b(&wire::digest(prior)),
            V::Uint(1),
            b(&state.generation_id),
            V::Uint(0),
            original(),
        ]),
    ])
}
fn response(request: &SignedRequest, outcome: u64, metadata: V) -> V {
    a(vec![
        V::Uint(58),
        V::Uint(1),
        scope().value(),
        b(&request.requester()),
        b(&request.digest()),
        V::Uint(outcome),
        b(&wire::encode(&metadata).unwrap()),
    ])
}
#[test]
fn absent_status_is_finite_and_cannot_smuggle_state_or_payload() {
    let request = status();
    let value = initial(false);
    let accepted = validate(
        &request,
        &result(&request, value.clone()),
        &point(&request),
        None,
    )
    .unwrap();
    assert!(accepted.metadata().state().is_none());
    let V::Array(mut fields) = value else {
        unreachable!()
    };
    fields[8] = original();
    assert!(OwnStreamMetadata::parse(&wire::encode(&a(fields)).unwrap()).is_err());
    let mut refused = result(&request, initial(false));
    refused.disposition = Disposition::Pending;
    refused.code = 30;
    let mut executed = point(&request);
    executed.maximum_effect = 0;
    assert!(validate(&request, &refused, &executed, None).is_err());
    refused.disposition = Disposition::Refuse;
    refused.code = 7;
    assert!(validate(&request, &refused, &executed, None).is_ok());
    executed.recipient = SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes();
    assert!(validate(&request, &refused, &executed, None).is_err());
}
#[test]
fn metadata_enforces_initial_identity_and_completion_retirement() {
    let value = initial(true);
    assert!(OwnStreamMetadata::parse(&wire::encode(&value).unwrap()).is_ok());
    let V::Array(fields) = value else {
        unreachable!()
    };
    for (index, changed) in [
        (5, V::Uint(2)),
        (6, b(&[17; 32])),
        (7, V::Uint(1)),
        (7, V::Uint(u64::MAX)),
    ] {
        let mut bad = fields.clone();
        bad[index] = changed;
        assert!(OwnStreamMetadata::parse(&wire::encode(&a(bad)).unwrap()).is_err());
    }
    let mut extra = fields;
    extra.push(V::Null);
    assert!(OwnStreamMetadata::parse(&wire::encode(&a(extra)).unwrap()).is_err());
}
#[test]
fn exact_fence_retry_preserves_later_work_and_original_completion() {
    let prior = wire::encode(&initial(true)).unwrap();
    let request = fence(&prior);
    let metadata = fenced(&request, &prior, false);
    let accepted = validate(
        &request,
        &result(&request, response(&request, 0, metadata)),
        &point(&request),
        Some(&prior),
    )
    .unwrap();
    assert_eq!(
        accepted
            .metadata()
            .state()
            .unwrap()
            .last_fence
            .as_ref()
            .unwrap()
            .previous_completion
            .as_ref()
            .unwrap()
            .disposition,
        Disposition::Permit
    );
    let later = fenced(&request, &prior, true);
    let retry = validate(
        &request,
        &result(&request, response(&request, 1, later.clone())),
        &point(&request),
        Some(&prior),
    )
    .unwrap();
    assert_eq!(
        retry
            .metadata()
            .state()
            .unwrap()
            .completion
            .as_ref()
            .unwrap()
            .reason,
        6
    );
    assert!(
        validate(
            &request,
            &result(&request, response(&request, 0, later)),
            &point(&request),
            Some(&prior)
        )
        .is_err()
    );
}
#[test]
fn fence_requires_exact_prepared_metadata_and_matching_prior_fields() {
    let prior = wire::encode(&initial(true)).unwrap();
    let request = fence(&prior);
    let valid = result(
        &request,
        response(&request, 0, fenced(&request, &prior, false)),
    );
    assert!(validate(&request, &valid, &point(&request), None).is_err());
    let V::Array(mut altered) = initial(true) else {
        unreachable!()
    };
    altered[8] = V::Null;
    assert!(
        validate(
            &request,
            &valid,
            &point(&request),
            Some(&wire::encode(&a(altered)).unwrap())
        )
        .is_err()
    );
    let V::Array(mut current) = fenced(&request, &prior, false) else {
        unreachable!()
    };
    let V::Array(last) = &mut current[9] else {
        unreachable!()
    };
    last[5] = V::Null;
    assert!(
        validate(
            &request,
            &result(&request, response(&request, 0, a(current))),
            &point(&request),
            Some(&prior)
        )
        .is_err()
    );
}
#[test]
fn superseded_requires_a_strictly_later_generation_and_refusal() {
    let prior = wire::encode(&initial(true)).unwrap();
    let request = fence(&prior);
    let mut result = result(
        &request,
        response(&request, 3, fenced(&request, &prior, false)),
    );
    result.disposition = Disposition::Refuse;
    result.code = 28;
    let mut executed = point(&request);
    executed.maximum_effect = 0;
    assert!(validate(&request, &result, &executed, Some(&prior)).is_err());
    result.value = wire::encode(&response(&request, 2, fenced(&request, &prior, false))).unwrap();
    assert!(validate(&request, &result, &executed, Some(&prior)).is_ok());
    result.code = 30;
    assert!(validate(&request, &result, &executed, Some(&prior)).is_err());
}
