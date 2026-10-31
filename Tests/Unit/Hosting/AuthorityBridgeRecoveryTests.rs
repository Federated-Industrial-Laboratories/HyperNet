// SPDX-License-Identifier: MIT
use super::*;
use crate::{authority_challenge::ClockHealth, authority_floor::tests as fixture};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}
fn snapshot(store: &Store) -> Vec<u8> {
    store
        .stream_metadata()
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec()
}
fn operation(name: &str, value: &[u8]) -> Vec<u8> {
    wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(name.into()),
        V::Uint(0),
        V::Uint(0),
        b(value),
    ]))
    .unwrap()
}
fn learn_status(store: &mut Store, session: &mut Session, health: ClockHealth, metadata: &[u8]) {
    learn_status_with_versions(store, session, health, metadata, &[])
}
fn learn_status_with_versions(
    store: &mut Store,
    session: &mut Session,
    health: ClockHealth,
    metadata: &[u8],
    versions: &[VersionRef],
) {
    let scope = store.descriptor().scope();
    let request = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(55),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&store.requester()),
            b(&[76; 32]),
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
        ]))
        .unwrap(),
        &signer(),
    )
    .unwrap();
    let mut result = fixture::certified(
        store,
        session,
        health,
        &request,
        &operation("AuthorityStreamStatus", metadata),
        None,
    );
    // Model already-validated record versions; cryptographic record evaluation has separate tests.
    result.generations = versions.to_vec();
    store
        .accept(result, session, health, 0)
        .unwrap()
        .perform(store, session, health, 1, |_| Ok(()), |_, _| Ok(()))
        .unwrap();
}

#[test]
fn bridge_recovery_fence_retains_predecessor_cache_after_floor_advance_and_rejects_tampered_archive()
 {
    let (directory, health, mut session, mut store) = fixture::setup();
    let predecessor = VersionRef {
        kind: 157,
        id: [31; 32],
        generation: 1,
        digest: [32; 32],
    };
    let successor = VersionRef {
        generation: 2,
        digest: [33; 32],
        ..predecessor.clone()
    };
    let scope = store.descriptor().scope().clone();
    let slot = store.ordinary_slot().unwrap();
    let request = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(20),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            V::Uint(slot.generation()),
            b(&slot.generation_id()),
            V::Uint(slot.sequence()),
            V::Uint(slot.acknowledged_through()),
            b(&store.requester()),
            V::Text("AuthorityDomain".into()),
            b(&[34; 32]),
            V::Uint(1),
            V::Uint(0),
            V::Uint(slot.minimum_policy_epoch()),
            V::Uint(slot.minimum_policy_height()),
            a(vec![crate::authority_membership::reference(&predecessor)]),
            b(&wire::encode(&a(vec![V::Uint(200), V::Uint(1)])).unwrap()),
        ]))
        .unwrap(),
        &signer(),
    )
    .unwrap();
    store.prepare_ordinary(slot, &request).unwrap();
    assert!(store.historical_cache_references().unwrap().is_empty());
    let intent = proof::Intent::from_signed(&request).unwrap();
    let value = wire::decode(&snapshot(&store)).unwrap();
    let mut metadata = value.array(10).unwrap().to_vec();
    metadata[8] = a(vec![
        V::Uint(intent.sequence),
        b(&intent.digest),
        V::Uint(0),
        V::Uint(0),
        b(&[35; 32]),
    ]);
    learn_status_with_versions(
        &mut store,
        &mut session,
        health,
        &wire::encode(&a(metadata)).unwrap(),
        std::slice::from_ref(&successor),
    );
    // A crash leaves old cached bytes after the exact Permit advanced the restrictive floor.
    assert_eq!(store.generations(), std::slice::from_ref(&successor));
    assert_eq!(
        store.historical_cache_references().unwrap(),
        std::slice::from_ref(&predecessor)
    );
    let expected = snapshot(&store);
    let fence = prepare(&mut store, &signer(), &expected).unwrap();
    let metadata = fence_metadata(&store, &fence, &expected);
    let signed = proof::SignedRequest::from_signed(fence.signed()).unwrap();
    let response = wire::encode(&a(vec![
        V::Uint(58),
        V::Uint(1),
        scope.value(),
        b(&store.requester()),
        b(&signed.digest()),
        V::Uint(0),
        b(&metadata),
    ]))
    .unwrap();
    let result = fixture::certified(
        &store,
        &mut session,
        health,
        fence.signed(),
        &operation("AuthorityStreamFence", &response),
        Some(&expected),
    );
    store
        .accept(result, &mut session, health, 0)
        .unwrap()
        .perform(
            &mut store,
            &mut session,
            health,
            1,
            |_| Ok(()),
            |_, _| Ok(()),
        )
        .unwrap();
    let descriptor = store.initial_descriptor().clone();
    drop(store);
    let reopened = Store::open(&directory.0, descriptor.clone()).unwrap();
    assert!(reopened.resume_ordinary().unwrap().is_none());
    assert_eq!(reopened.ordinary_slot().unwrap().generation(), 2);
    assert_eq!(reopened.generations(), std::slice::from_ref(&successor));
    let historical = reopened.historical_cache_references().unwrap();
    assert_eq!(historical, std::slice::from_ref(&predecessor));
    assert!(
        cache_authenticated(
            std::slice::from_ref(&predecessor),
            reopened.generations(),
            &historical
        )
        .is_ok()
    );
    assert!(
        domains::result::minimum(std::slice::from_ref(&predecessor), reopened.generations())
            .is_err()
    );
    drop(reopened);
    let floor = directory.0.join("AuthorityFloor.json");
    let witness = directory.0.join("AuthorityWitness.json");
    let mut stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&floor).unwrap()).unwrap();
    let original = stored["tracker"]["outstandingUnknown"][0]["signed"]
        .as_str()
        .unwrap();
    let mut corrupted = hex::decode(original).unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    stored["tracker"]["outstandingUnknown"][0]["signed"] =
        serde_json::json!(hex::encode(corrupted));
    let bytes = serde_json::to_vec(&stored).unwrap();
    let mut link: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&witness).unwrap()).unwrap();
    link["digest"] = serde_json::json!(hex::encode(wire::digest(&bytes)));
    std::fs::write(floor, bytes).unwrap();
    std::fs::write(witness, serde_json::to_vec(&link).unwrap()).unwrap();
    assert!(Store::open(&directory.0, descriptor).is_err());
}
fn fence_metadata(store: &Store, fence: &PreparedRequest, expected: &[u8]) -> Vec<u8> {
    let request = proof::SignedRequest::from_signed(fence.signed()).unwrap();
    let metadata = OwnStreamMetadata::parse(expected).unwrap();
    let before = metadata.state().unwrap();
    let value = wire::decode(expected).unwrap();
    let completion = value.array(10).unwrap()[8].clone();
    wire::encode(&a(vec![
        V::Uint(56),
        V::Uint(1),
        store.descriptor().scope().value(),
        b(&store.requester()),
        V::Bool(true),
        V::Uint(before.generation + 1),
        b(&request.digest()),
        V::Uint(0),
        V::Null,
        a(vec![
            b(&request.digest()),
            b(&wire::digest(expected)),
            V::Uint(before.generation),
            b(&before.generation_id),
            V::Uint(before.retired_through),
            completion,
        ]),
    ]))
    .unwrap()
}

#[test]
fn bridge_recovery_requires_exact_metadata_and_resumes_identical_fence_after_reopen() {
    let (directory, _, _, mut store) = fixture::setup();
    let expected = snapshot(&store);
    let value = wire::decode(&expected).unwrap();
    let mut changed = value.array(10).unwrap().to_vec();
    changed[8] = a(vec![
        V::Uint(1),
        b(&[44; 32]),
        V::Uint(0),
        V::Uint(0),
        b(&[45; 32]),
    ]);
    let changed = wire::encode(&a(changed)).unwrap();
    assert_eq!(
        OwnStreamMetadata::parse(&changed)
            .unwrap()
            .state()
            .unwrap()
            .generation,
        OwnStreamMetadata::parse(&expected)
            .unwrap()
            .state()
            .unwrap()
            .generation
    );
    assert!(prepare(&mut store, &signer(), &changed).is_err());
    assert!(store.resume_fence().unwrap().is_none());
    let fence = prepare(&mut store, &signer(), &expected).unwrap();
    let descriptor = store.initial_descriptor().clone();
    drop(store);
    let mut reopened = Store::open(&directory.0, descriptor).unwrap();
    assert!(prepare(&mut reopened, &signer(), &changed).is_err());
    let resumed = prepare(&mut reopened, &signer(), &expected).unwrap();
    assert_eq!(resumed.signed(), fence.signed());
    assert_eq!(resumed.expected_metadata(), Some(expected.as_slice()));
}

#[test]
fn bridge_recovery_fence_preserves_unknown_and_original_permit_without_replaying_effect() {
    for known_permit in [false, true] {
        let (directory, health, mut session, mut store) = fixture::setup();
        let (ordinary, operation_bytes) = fixture::prepare(&mut store, health);
        let intent = proof::Intent::from_signed(ordinary.signed()).unwrap();
        if known_permit {
            let result = fixture::certified(
                &store,
                &mut session,
                health,
                ordinary.signed(),
                &operation_bytes,
                None,
            );
            // Certified authority permission was recorded; the local effect never ran.
            let _permit = store.accept(result, &mut session, health, 0).unwrap();
            let value = wire::decode(&snapshot(&store)).unwrap();
            let mut metadata = value.array(10).unwrap().to_vec();
            metadata[8] = a(vec![
                V::Uint(intent.sequence),
                b(&intent.digest),
                V::Uint(0),
                V::Uint(0),
                b(&wire::digest(&operation_bytes)),
            ]);
            learn_status(
                &mut store,
                &mut session,
                health,
                &wire::encode(&a(metadata)).unwrap(),
            );
        }
        let expected = snapshot(&store);
        let fence = prepare(&mut store, &signer(), &expected).unwrap();
        let metadata = fence_metadata(&store, &fence, &expected);
        let request = proof::SignedRequest::from_signed(fence.signed()).unwrap();
        let response = wire::encode(&a(vec![
            V::Uint(58),
            V::Uint(1),
            store.descriptor().scope().value(),
            b(&store.requester()),
            b(&request.digest()),
            V::Uint(0),
            b(&metadata),
        ]))
        .unwrap();
        let result = fixture::certified(
            &store,
            &mut session,
            health,
            fence.signed(),
            &operation("AuthorityStreamFence", &response),
            Some(&expected),
        );
        store
            .accept(result, &mut session, health, 0)
            .unwrap()
            .perform(
                &mut store,
                &mut session,
                health,
                1,
                |_| Ok(()),
                |_, _| Ok(()),
            )
            .unwrap();
        assert!(store.resume_ordinary().unwrap().is_none());
        assert!(store.resume_fence().unwrap().is_none());
        assert_eq!(store.ordinary_slot().unwrap().generation(), 2);
        assert!(completed(
            &OwnStreamMetadata::parse(&expected).unwrap(),
            &OwnStreamMetadata::parse(&metadata).unwrap()
        ));
        let descriptor = store.initial_descriptor().clone();
        drop(store);
        let reopened = Store::open(&directory.0, descriptor).unwrap();
        assert_eq!(reopened.ordinary_slot().unwrap().generation(), 2);
        let retained: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.0.join("AuthorityFloor.json")).unwrap(),
        )
        .unwrap();
        let unknown = retained["tracker"]["outstandingUnknown"]
            .as_array()
            .unwrap();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0]["request"], serde_json::json!(intent.digest));
        assert_eq!(unknown[0]["effect"], "unclaimed");
        assert_eq!(unknown[0]["original"].is_null(), !known_permit);
        if known_permit {
            assert_eq!(unknown[0]["original"]["disposition"], 0);
        }
    }
}

#[test]
fn bridge_recovery_refuses_cache_losing_pending_authentication() {
    let reference = VersionRef {
        kind: 157,
        id: [1; 32],
        generation: 2,
        digest: [2; 32],
    };
    assert!(cache_authenticated(std::slice::from_ref(&reference), &[], &[]).is_err());
    let mut predecessor = reference.clone();
    predecessor.generation = 1;
    assert!(cache_authenticated(std::slice::from_ref(&reference), &[predecessor], &[]).is_err());
    assert!(
        cache_authenticated(
            std::slice::from_ref(&reference),
            std::slice::from_ref(&reference),
            &[]
        )
        .is_ok()
    );
}
