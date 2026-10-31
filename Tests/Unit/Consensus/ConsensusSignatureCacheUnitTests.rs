// SPDX-License-Identifier: MIT
// Unit tests for ConsensusSignatureCache.
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
