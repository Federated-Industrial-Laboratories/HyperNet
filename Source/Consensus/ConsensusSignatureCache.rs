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
#[path = "../../Tests/Unit/Consensus/ConsensusSignatureCacheUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusSignatureCache.rs");
