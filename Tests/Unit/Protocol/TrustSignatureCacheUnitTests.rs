// SPDX-License-Identifier: MIT
// Unit tests for TrustSignatureCache.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn fixed_signature_cache_evicts_collisions_without_growing_or_reusing_the_wrong_proof() {
    let cache = Cache::new();
    let key = SigningKey::from_bytes(&[54; 32]);
    let mut slots = BTreeMap::new();
    let (first, second) = (0..=SLOTS)
        .find_map(|value| {
            let message = value.to_be_bytes().to_vec();
            let hash: [u8; 32] = Sha256::digest(&message).into();
            let slot = usize::from(u16::from_be_bytes([hash[0], hash[1]])) % SLOTS;
            slots
                .insert(slot, message.clone())
                .map(|old| (old, message))
        })
        .expect("More messages than slots must collide");
    let public = key.verifying_key();
    let verify = |message: &[u8]| {
        cache
            .verify(&public, message, key.sign(message).to_bytes())
            .unwrap()
    };
    take_signature_statistics();
    verify(&first);
    verify(&first);
    verify(&second);
    verify(&first);
    let stats = take_signature_statistics();
    assert_eq!(
        (
            stats.lookups,
            stats.hits,
            stats.strict_verifications,
            stats.evictions
        ),
        (4, 1, 3, 2)
    );
    let slots = cache.slots.lock().unwrap();
    assert_eq!(slots.len(), SLOTS);
    assert_eq!(slots.iter().filter(|slot| slot.is_some()).count(), 1);
    assert_eq!(size_of::<Verified>(), 32 + 32 + 64);
    assert!(size_of::<Option<Verified>>() <= 129);
    assert!(size_of_val(slots.as_ref()) <= 528384);
    assert_eq!(
        size_of_val(slots.as_ref()),
        SLOTS * size_of::<Option<Verified>>()
    );
}

#[test]
fn shared_signature_cache_keeps_numeric_counters_thread_local() {
    let cache = Arc::new(Cache::new());
    let key = SigningKey::from_bytes(&[55; 32]);
    let message = b"Shared strict verification";
    let signature = key.sign(message).to_bytes();
    let public = key.verifying_key();
    take_signature_statistics();
    cache.verify(&public, message, signature).unwrap();
    let shared = cache.clone();
    let child = std::thread::spawn(move || {
        assert_eq!(take_signature_statistics().lookups, 0);
        shared.verify(&public, message, signature).unwrap();
        let stats = take_signature_statistics();
        assert_eq!(
            (stats.lookups, stats.hits, stats.strict_verifications),
            (1, 1, 0)
        );
        assert_eq!(take_signature_statistics().lookups, 0);
    });
    child.join().unwrap();
    let stats = take_signature_statistics();
    assert_eq!(
        (stats.lookups, stats.hits, stats.strict_verifications),
        (1, 0, 1)
    );
    cache.verify(&public, message, signature).unwrap();
    assert_eq!(
        take_signature_statistics().hits,
        1,
        "Taking counters must not clear cached proofs"
    );
}

#[test]
fn poisoned_signature_cache_falls_back_to_strict_verification() {
    let cache = Arc::new(Cache::new());
    let broken = cache.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = broken.slots.lock().unwrap();
            panic!("Poison isolated cache");
        })
        .join()
        .is_err()
    );
    let key = SigningKey::from_bytes(&[56; 32]);
    let public = key.verifying_key();
    let message = b"Strict verification remains required";
    let signature = key.sign(message).to_bytes();
    take_signature_statistics();
    cache.verify(&public, message, signature).unwrap();
    cache.verify(&public, message, signature).unwrap();
    let mut altered = signature;
    altered[0] ^= 1;
    assert!(cache.verify(&public, message, altered).is_err());
    let stats = take_signature_statistics();
    assert_eq!(
        (stats.lookups, stats.hits, stats.strict_verifications),
        (3, 0, 3)
    );
}
