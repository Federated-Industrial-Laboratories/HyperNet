// SPDX-License-Identifier: MIT
// Ticket retirement distinguishes an authenticated original refusal from an unresolved effect.
use super::*;

fn request() -> (Scope, Intent) {
    let scope = Scope {
        network: [20; 32],
        incarnation: [21; 32],
        configuration: [22; 32],
        epoch: 0,
    };
    let requester = SigningKey::from_bytes(&[100; 32])
        .verifying_key()
        .to_bytes();
    let operation = Operation {
        grant: None,
        command: page::Command::ReplicaDeliver {
            ticket: VersionRef {
                kind: 146,
                id: [23; 32],
                generation: 1,
                digest: [24; 32],
            },
            bundle: crate::authority_objects::Reference::for_bytes(
                crate::authority_objects::Class::PageBundle,
                b"retained bundle reference",
            )
            .unwrap(),
        }
        .into(),
        snapshot: domains::snapshot(&a(vec![
            a(vec![V::Uint(scope.epoch), V::Uint(1), b(&[25; 32])]),
            a(vec![]),
        ]))
        .unwrap(),
    };
    let intent = Intent {
        network: scope.network,
        incarnation: scope.incarnation,
        generation: 1,
        generation_id: proof::initial_generation_id(scope.network, scope.incarnation, requester)
            .unwrap(),
        sequence: 1,
        acknowledged_through: 0,
        requester,
        action: "AuthorityDomain".into(),
        resource: operation.command.resource(),
        revision: 1,
        profile_generation: 0,
        minimum_policy_epoch: 0,
        minimum_policy_height: 1,
        expected: vec![],
        parameters: operation.parameters().unwrap(),
        digest: [26; 32],
    };
    (scope, intent)
}
fn metadata(scope: &Scope, intent: &Intent, completion: V, retired: u64) -> OwnStreamMetadata {
    OwnStreamMetadata::parse(
        &wire::encode(&a(vec![
            V::Uint(56),
            V::Uint(1),
            scope.value(),
            b(&intent.requester),
            V::Bool(true),
            V::Uint(intent.generation),
            b(&intent.generation_id),
            V::Uint(retired),
            completion,
            V::Null,
        ]))
        .unwrap(),
    )
    .unwrap()
}
fn completion(intent: &Intent, disposition: u64, reason: u64) -> V {
    a(vec![
        V::Uint(intent.sequence),
        b(&intent.digest),
        V::Uint(disposition),
        V::Uint(reason),
        b(&[27; 32]),
    ])
}

#[test]
fn delivery_retirement_requires_the_exact_original_refusal() {
    let (scope, intent) = request();
    let refused = metadata(&scope, &intent, completion(&intent, 1, 3), 0);
    assert!(original_delivery_refused(&refused, &scope, &intent).unwrap());
    for value in [
        V::Null,
        completion(&intent, 0, 0),
        completion(&intent, 2, 25),
    ] {
        assert!(
            !original_delivery_refused(&metadata(&scope, &intent, value, 0), &scope, &intent)
                .unwrap()
        );
    }
    let mut other = intent.clone();
    other.digest = [28; 32];
    assert!(
        !original_delivery_refused(
            &metadata(&scope, &intent, completion(&other, 1, 3), 0),
            &scope,
            &intent
        )
        .unwrap()
    );
    other = intent.clone();
    other.sequence = 2;
    assert!(
        !original_delivery_refused(
            &metadata(&scope, &intent, completion(&other, 1, 3), 1),
            &scope,
            &intent
        )
        .unwrap()
    );
    other = intent.clone();
    other.generation = 2;
    other.generation_id = [29; 32];
    assert!(!original_delivery_refused(&refused, &scope, &other).unwrap());
    let mut next_epoch = scope.clone();
    next_epoch.epoch += 1;
    assert!(!original_delivery_refused(&refused, &next_epoch, &intent).unwrap());
    let mut operation = Operation::parse(&intent).unwrap();
    operation.command = page::Command::ReplicaQueue {
        host: intent.requester,
        namespace: "Books".into(),
        after: None,
    }
    .into();
    other = intent.clone();
    other.resource = operation.command.resource();
    other.revision = 0;
    other.parameters = operation.parameters().unwrap();
    assert!(!original_delivery_refused(&refused, &scope, &other).unwrap());
}
