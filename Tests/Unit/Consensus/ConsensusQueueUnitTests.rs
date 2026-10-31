// SPDX-License-Identifier: MIT
// Unit tests for ConsensusQueue.
use super::*;
use std::time::Duration;
#[tokio::test]
async fn offline_backlog_is_pruned_and_recovery_uses_its_own_wakeup() {
    let q = Mailbox::new();
    for serial in 0..GENERAL_COUNT {
        q.push_class(
            (serial as u64).to_be_bytes().to_vec(),
            Class::Broadcast { recovery: false },
        )
        .unwrap();
    }
    assert!(q.push(vec![200; 16]).is_err());
    // A stalled general request does not hold the recovery sender's queue.
    let general = q.pop(Lane::General).await.unwrap();
    assert_eq!(general, 0u64.to_be_bytes());
    let recovery_wait = q.pop(Lane::Recovery);
    tokio::pin!(recovery_wait);
    assert!(
        tokio::time::timeout(Duration::from_millis(5), &mut recovery_wait)
            .await
            .is_err()
    );
    let proof = vec![250; 64];
    q.push_class(proof.clone(), Class::Broadcast { recovery: true })
        .unwrap();
    let live = BTreeSet::from([trust_wire::digest(&proof)]);
    q.retain_live(&live, &BTreeSet::new(), &BTreeSet::new())
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), recovery_wait)
            .await
            .unwrap()
            .unwrap(),
        proof
    );
    assert!(q.try_pop().unwrap().is_none());
}
#[test]
fn slots_and_expiry_preserve_distinct_requested_response_families() {
    let q = Mailbox::new();
    let now = Instant::now();
    for family in [6, 14, 16] {
        q.push_at(vec![family; 16], Class::Response { family }, now)
            .unwrap();
    }
    q.push_at(vec![17; 16], Class::Response { family: 16 }, now)
        .unwrap();
    let mut inner = q.queue.lock().unwrap();
    assert_eq!(inner.messages.len(), 3);
    assert_eq!(inner.pop(Lane::Recovery, now).unwrap(), vec![6; 16]);
    assert_eq!(inner.pop(Lane::Recovery, now).unwrap(), vec![14; 16]);
    assert!(
        inner
            .pop(Lane::Recovery, now + peer::HTTP_TIMEOUT)
            .is_none()
    );
    drop(inner);
    // Repeating the exact request regenerates the same response after expiry.
    q.push_at(
        vec![17; 16],
        Class::Response { family: 16 },
        now + peer::HTTP_TIMEOUT,
    )
    .unwrap();
    assert_eq!(q.try_pop().unwrap().unwrap(), vec![17; 16]);
    let token = [3; 32];
    q.push_class(vec![4; 16], Class::Request { family: 13, token })
        .unwrap();
    q.retain_live(&BTreeSet::new(), &BTreeSet::new(), &BTreeSet::new())
        .unwrap();
    assert!(q.try_pop().unwrap().is_none());
}
#[test]
fn aggregate_byte_reservation_is_shared_across_lanes() {
    let q = Mailbox::new();
    for serial in 0..8 {
        q.push_class(vec![serial; trust_wire::MAXIMUM], Class::Transient)
            .unwrap();
    }
    assert!(q.push(vec![9; 1]).is_err());
    for serial in 8..16 {
        q.push_class(
            vec![serial; trust_wire::MAXIMUM],
            Class::Broadcast { recovery: true },
        )
        .unwrap();
    }
    assert!(
        q.push_class(vec![17; 1], Class::Broadcast { recovery: true })
            .is_err()
    );
    let inner = q.queue.lock().unwrap();
    assert_eq!(inner.bytes, MAX_BYTES);
    assert_eq!(inner.messages.len(), 16);
}
