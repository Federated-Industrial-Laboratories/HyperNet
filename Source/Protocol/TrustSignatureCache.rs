// SPDX-License-Identifier: MIT
//! Bounded reuse of successful strict signature arithmetic, never authorization.
use anyhow::Result;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    sync::{Mutex, OnceLock},
    time::Instant,
};

const SLOTS: usize = 4096;
#[derive(Clone, Copy, PartialEq, Eq)]
struct Verified {
    message: [u8; 32],
    public: [u8; 32],
    signature: [u8; 64],
}
impl Verified {
    fn slot(&self) -> usize {
        usize::from(u16::from_be_bytes([self.message[0], self.message[1]])) % SLOTS
    }
}
// No entry owns payload bytes. Slot storage is exactly
// SLOTS * size_of::<Option<Verified>>(), including the Option representation.
pub(super) struct Cache {
    slots: Mutex<Box<[Option<Verified>]>>,
}
impl Cache {
    pub(super) fn new() -> Self {
        Self {
            slots: Mutex::new(vec![None; SLOTS].into_boxed_slice()),
        }
    }
    pub(super) fn verify(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: [u8; 64],
    ) -> Result<()> {
        let entry = Verified {
            message: Sha256::digest(message).into(),
            public: key.to_bytes(),
            signature,
        };
        record(|stats| stats.lookups = stats.lookups.saturating_add(1));
        let hit = self
            .slots
            .lock()
            .ok()
            .is_some_and(|slots| slots[entry.slot()] == Some(entry));
        if hit {
            record(|stats| stats.hits = stats.hits.saturating_add(1));
            return Ok(());
        }
        // Neither hashing nor signature arithmetic holds the shared cache lock.
        // A poisoned cache is unavailable; strict verification remains mandatory.
        let started = Instant::now();
        let outcome = key.verify_strict(message, &Signature::from_bytes(&signature));
        let elapsed = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        record(|stats| {
            stats.strict_verifications = stats.strict_verifications.saturating_add(1);
            stats.strict_verification_ns = stats.strict_verification_ns.saturating_add(elapsed);
        });
        outcome?;
        if let Ok(mut slots) = self.slots.lock() {
            let slot = &mut slots[entry.slot()];
            if slot.is_some_and(|old| old != entry) {
                record(|stats| stats.evictions = stats.evictions.saturating_add(1));
            }
            *slot = Some(entry);
        }
        Ok(())
    }
}
pub(super) fn global() -> &'static Cache {
    static VERIFIED: OnceLock<Cache> = OnceLock::new();
    VERIFIED.get_or_init(Cache::new)
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SignatureStatistics {
    pub lookups: u64,
    pub hits: u64,
    pub strict_verifications: u64,
    pub strict_verification_ns: u64,
    pub evictions: u64,
}
thread_local! {
    static STATISTICS: Cell<SignatureStatistics> = const { Cell::new(SignatureStatistics {
        lookups: 0, hits: 0, strict_verifications: 0, strict_verification_ns: 0, evictions: 0,
    }) };
}
fn record(update: impl FnOnce(&mut SignatureStatistics)) {
    STATISTICS.with(|cell| {
        let mut stats = cell.get();
        update(&mut stats);
        cell.set(stats);
    });
}
pub(super) fn take_signature_statistics() -> SignatureStatistics {
    STATISTICS.with(|cell| cell.replace(SignatureStatistics::default()))
}

#[cfg(test)]
mod tests {
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
}
