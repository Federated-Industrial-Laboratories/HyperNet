// SPDX-License-Identifier: MIT
//! Exact successful proof bytes permit reuse of signature arithmetic only.
use std::{cell::RefCell, collections::VecDeque};

const MAX_ENTRIES: usize = 256;
const MAX_BYTES: usize = 256 * 1024;

#[derive(Default)]
struct Cache {
    proofs: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl Cache {
    fn contains(&self, proof: &[u8]) -> bool {
        self.proofs.iter().any(|known| known == proof)
    }
    fn remember(&mut self, proof: &[u8]) {
        if proof.len() > MAX_BYTES || self.contains(proof) {
            return;
        }
        while self.proofs.len() >= MAX_ENTRIES || self.bytes > MAX_BYTES - proof.len() {
            let oldest = self.proofs.pop_front().expect("retained proof above bound");
            self.bytes -= oldest.len();
        }
        self.bytes += proof.len();
        self.proofs.push_back(proof.to_vec());
    }
}

thread_local! {
    static VERIFIED: RefCell<Cache> = RefCell::new(Cache::default());
}

pub(super) fn contains(proof: &[u8]) -> bool {
    VERIFIED.with(|cache| cache.borrow().contains(proof))
}
pub(super) fn remember(proof: &[u8]) {
    VERIFIED.with(|cache| cache.borrow_mut().remember(proof));
}
#[cfg(test)]
pub(super) fn clear() {
    VERIFIED.with(|cache| *cache.borrow_mut() = Cache::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_proofs_obey_both_bounds_and_do_not_admit_oversized_values() {
        let mut cache = Cache::default();
        for id in 0..=MAX_ENTRIES {
            cache.remember(&id.to_be_bytes());
        }
        assert_eq!(cache.proofs.len(), MAX_ENTRIES);
        assert_eq!(cache.bytes, MAX_ENTRIES * size_of::<usize>());
        assert!(!cache.contains(&0usize.to_be_bytes()));
        assert!(cache.contains(&MAX_ENTRIES.to_be_bytes()));
        cache.remember(&MAX_ENTRIES.to_be_bytes());
        assert_eq!(cache.proofs.len(), MAX_ENTRIES);

        let first = vec![1; MAX_BYTES / 2];
        let second = vec![2; MAX_BYTES / 2];
        cache.remember(&first);
        cache.remember(&second);
        assert_eq!(cache.proofs.len(), 2);
        assert_eq!(cache.bytes, MAX_BYTES);
        cache.remember(&[3]);
        assert!(!cache.contains(&first));
        assert!(cache.contains(&second));
        assert_eq!(cache.bytes, MAX_BYTES / 2 + 1);
        cache.remember(&vec![4; MAX_BYTES + 1]);
        assert_eq!(cache.proofs.len(), 2);
        assert_eq!(cache.bytes, MAX_BYTES / 2 + 1);
        assert!(cache.contains(&second));
    }
}
