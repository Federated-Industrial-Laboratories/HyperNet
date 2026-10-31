// SPDX-License-Identifier: MIT
// Unit tests for ConsensusSync.
use super::*;
#[test]
fn one_byzantine_jump_and_two_way_partition_cannot_enter() {
    let mut s = State::default();
    assert_eq!(s.receive(3, u64::MAX).unwrap(), Effects::default());
    assert_eq!(s.entered, 0);
    let mut partition = State::default();
    partition.receive(0, 1).unwrap();
    assert_eq!(partition.receive(1, 1).unwrap().entered, None);
    assert_eq!(partition.entered, 0);
}
#[test]
fn three_matching_wishes_enter_and_loss_is_retransmitted() {
    let mut replicas = [State::default(), State::default(), State::default()];
    for replica in &mut replicas {
        assert_eq!(replica.advance().unwrap().wish, Some(1));
        assert_eq!(replica.periodic().unwrap().wish, Some(1));
    }
    for replica in &mut replicas {
        for member in 0..3 {
            replica.receive(member, 1).unwrap();
        }
        assert_eq!(replica.entered, 1);
        assert!(!replica.advanced);
        assert_eq!(replica.periodic().unwrap().wish, Some(1));
        assert_eq!(replica.receive(1, 1).unwrap(), Effects::default());
        assert_eq!(replica.advance().unwrap().wish, Some(2));
        replica.validate().unwrap();
    }
}
#[test]
fn order_statistic_progress_is_not_protocol_entry() {
    let mut s = State::default();
    s.receive(0, 5).unwrap();
    s.receive(1, 4).unwrap();
    s.receive(2, 3).unwrap();
    assert_eq!((s.view, s.view_plus, s.entered), (3, 4, 0));
    assert_eq!(s.receive(2, 4).unwrap().entered, Some(4));
    assert_eq!(s.receive(3, 2).unwrap().entered, None);
}
