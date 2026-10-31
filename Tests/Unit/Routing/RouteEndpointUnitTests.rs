// SPDX-License-Identifier: MIT
// Unit tests for RouteEndpoint.
use super::*;
#[test]
fn private_authority_reads_keep_their_own_pending_identity_and_closed_protocol() {
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 1,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public = V::Bytes(key.verifying_key().to_bytes().to_vec());
    let fields = vec![
        V::Uint(60),
        V::Uint(1),
        scope.value(),
        public.clone(),
        public.clone(),
        V::Bytes(vec![6; 32]),
        V::Uint(0),
        V::Array(vec![V::Uint(0)]),
    ];
    let payload = wire::encode(&V::Array(fields.clone())).unwrap();
    let signed = wire::sign_envelope(&payload, &key).unwrap();
    let challenge = wire::sign_envelope(
        &wire::encode(&V::Array(vec![
            V::Uint(21),
            V::Uint(1),
            V::Bytes(scope.network.to_vec()),
            V::Bytes(scope.incarnation.to_vec()),
            public,
            V::Bytes(vec![4; 32]),
            V::Bytes(vec![5; 32]),
            V::Bytes(wire::digest(&payload).to_vec()),
            V::Bytes(vec![6; 32]),
            V::Uint(10_000),
            V::Uint(15_000),
            V::Uint(5000),
        ]))
        .unwrap(),
        &key,
    )
    .unwrap();
    let frame = |operation, bytes| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            scope.value(),
            V::Uint(operation),
            V::Bytes(bytes),
        ]))
        .unwrap()
    };
    let submit = |request: Vec<u8>| {
        frame(
            6,
            wire::encode(&V::Array(vec![
                V::Bytes(request),
                V::Bytes(challenge.clone()),
            ]))
            .unwrap(),
        )
    };
    let request = submit(signed.clone());
    let id = crate::authority_read::read_id(&signed, &challenge).unwrap();
    let poll = frame(7, id.to_vec());
    let fields = vec![
        V::Uint(62),
        V::Uint(1),
        scope.value(),
        V::Uint(0),
        V::Uint(0),
        V::Bytes(id.to_vec()),
        V::Null,
        V::Null,
        V::Null,
        V::Array(vec![]),
    ];
    let reply = wire::encode(&V::Array(fields.clone())).unwrap();
    for packet in [&request, &poll] {
        assert!(validate_packet(1, scope.network, scope.incarnation, packet).is_ok());
        assert!(authority_request_pending(packet, &reply));
        assert!(validate_packet(2, scope.network, scope.incarnation, packet).is_err());
    }
    for (index, value) in [
        (0, V::Uint(42)),
        (3, V::Uint(1)),
        (3, V::Uint(2)),
        (3, V::Uint(3)),
        (4, V::Uint(1)),
        (5, V::Bytes(vec![9; 32])),
        (6, V::Bytes(vec![])),
        (9, V::Array(vec![V::Null])),
    ] {
        let mut changed = fields.clone();
        changed[index] = value;
        let reply = wire::encode(&V::Array(changed)).unwrap();
        assert!(!authority_request_pending(&request, &reply));
        assert!(!authority_request_pending(&poll, &reply));
    }
    assert!(!authority_request_pending(&frame(1, id.to_vec()), &reply));
    let mut invalid = wire::decode(&payload).unwrap().array(8).unwrap().to_vec();
    invalid[7] = V::Array(vec![V::Uint(9)]);
    let invalid = wire::sign_envelope(&wire::encode(&V::Array(invalid)).unwrap(), &key).unwrap();
    assert!(validate_packet(1, scope.network, scope.incarnation, &submit(invalid)).is_err());
    assert!(validate_packet(1, [9; 32], scope.incarnation, &request).is_err());
    assert!(validate_packet(1, scope.network, scope.incarnation, &frame(5, vec![])).is_err());
}

#[test]
fn only_matching_pending_authority_replies_keep_poll_demand() {
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 1,
    }
    .value();
    let command = vec![7; 32];
    let digest = wire::digest(&command);
    let request = |operation, payload| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            scope.clone(),
            V::Uint(operation),
            V::Bytes(payload),
        ]))
        .unwrap()
    };
    let submitted = request(
        0,
        wire::encode(&V::Array(vec![V::Bytes(command), V::Array(vec![])])).unwrap(),
    );
    let poll = request(1, digest.to_vec());
    let fields = vec![
        V::Uint(42),
        V::Uint(1),
        scope.clone(),
        V::Uint(0),
        V::Uint(0),
        V::Bytes(digest.to_vec()),
        V::Null,
        V::Null,
        V::Null,
        V::Array(vec![]),
    ];
    let reply = wire::encode(&V::Array(fields.clone())).unwrap();
    assert!(authority_request_pending(&submitted, &reply));
    assert!(authority_request_pending(&poll, &reply));
    assert!(!authority_request_pending(
        &request(2, wire::encode(&V::Array(vec![])).unwrap()),
        &reply
    ));
    assert!(!authority_request_pending(b"malformed", &reply));
    assert!(!authority_request_pending(&poll, b"malformed"));
    let mut foreign = scope.array(4).unwrap().to_vec();
    foreign[0] = V::Bytes(vec![9; 32]);
    for (index, value) in [
        (0, V::Uint(41)),
        (1, V::Uint(2)),
        (2, V::Array(foreign)),
        (3, V::Uint(1)),
        (3, V::Uint(2)),
        (4, V::Uint(1)),
        (5, V::Bytes(vec![8; 32])),
        (6, V::Bytes(vec![])),
        (7, V::Bytes(vec![])),
        (8, V::Bytes(vec![])),
        (9, V::Array(vec![V::Null])),
    ] {
        let mut changed = fields.clone();
        changed[index] = value;
        assert!(!authority_request_pending(
            &poll,
            &wire::encode(&V::Array(changed)).unwrap()
        ));
    }
}

#[test]
fn private_endpoint_refuses_management_and_foreign_scope() {
    let frame = |operation, network| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            Scope {
                network,
                incarnation: [2; 32],
                configuration: [3; 32],
                epoch: 1,
            }
            .value(),
            V::Uint(operation),
            V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
        ]))
        .unwrap()
    };
    assert!(validate_packet(1, [1; 32], [2; 32], &frame(2, [1; 32])).is_ok());
    assert!(validate_packet(1, [1; 32], [2; 32], &frame(5, [1; 32])).is_err());
    assert!(validate_packet(1, [1; 32], [2; 32], &frame(2, [3; 32])).is_err());
    let sync = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("BridgeSync".into()),
        V::Bytes(vec![9; 32]),
        V::Null,
    ]))
    .unwrap();
    assert!(validate_packet(6, [1; 32], [2; 32], &sync).is_err());
}

#[test]
fn private_endpoint_allows_unspecified_target_only_for_checkpoint_preparation() {
    let scope = Scope {
        network: [1; 32],
        incarnation: [2; 32],
        configuration: [3; 32],
        epoch: 1,
    };
    let packet = |operation, body| {
        wire::encode(&V::Array(vec![
            V::Uint(41),
            V::Uint(1),
            scope.value(),
            V::Uint(operation),
            V::Bytes(wire::encode(&V::Array(body)).unwrap()),
        ]))
        .unwrap()
    };
    let body = vec![
        V::Uint(0),
        V::Bytes(vec![4; 32]),
        V::Null,
        V::Uint(0),
        V::Null,
    ];
    assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, body.clone())).is_ok());
    assert!(validate_packet(1, [1; 32], [2; 32], &packet(3, body[..3].to_vec())).is_err());
    assert!(validate_packet(1, [1; 32], [2; 32], &packet(5, body.clone())).is_err());
    assert!(validate_packet(1, [9; 32], [2; 32], &packet(4, body.clone())).is_err());
    let mut wrong = body.clone();
    wrong[2] = V::Bytes(vec![4; 31]);
    assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, wrong)).is_err());
    let mut exact = body;
    exact[2] = V::Bytes(vec![5; 32]);
    assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, exact)).is_ok());
}
