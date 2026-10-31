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
#[path = "../../Tests/Unit/Protocol/TrustSignatureCacheUnitTests.rs"]
mod tests;
