// SPDX-License-Identifier: MIT
use super::super::{records::tests::fixture, tests as fixtures};
use super::*;
use crate::authority_read::Statement;
fn statement(engine: &Engine) -> Statement {
    let anchor = engine.applied().unwrap();
    Statement {
        scope: engine.configuration.descriptor().scope().clone(),
        request: [31; 32],
        challenge: [32; 32],
        requester: SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes(),
        recipient: SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes(),
        height: anchor.height,
        node: anchor.digest().unwrap(),
        state: wire::digest(engine.application()),
        evaluated_at_ms: 10000,
        expires_at_ms: 14000,
        result: [34; 32],
    }
}
#[test]
fn fresh_read_commit_quorum_cannot_sign_stale_applied_state() {
    let (config, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&config, &keys);
    fixtures::enter(&config, &keys, &mut engines, 1);
    let command = fixtures::request(&config, 79);
    let commit = fixtures::phases(&config, &mut engines, &command);
    // Even before CommitQC delivery, the precommit lock bars the old applied state.
    assert!(engines.iter().all(|e| e.read_anchor().is_err()));
    for e in &mut engines {
        e.decide(&commit.bytes).unwrap();
        assert!(e.read_anchor().is_err());
    }
    for index in 0..3 {
        engines[index]
            .apply_committed(|_, position| Ok(fixtures::execution(&config, position)))
            .unwrap();
        let ready = engines.iter().filter(|e| e.read_anchor().is_ok()).count();
        assert_eq!(ready, index + 1);
    }
    let before: Vec<_> = engines
        .iter()
        .map(|e| (e.generation(), e.application().to_vec()))
        .collect();
    let signed: Vec<_> = engines
        .iter()
        .filter_map(|e| e.sign_read(&statement(e), 10000).ok())
        .collect();
    assert_eq!(signed.len(), 3);
    for (e, (generation, application)) in engines.iter().zip(before) {
        assert_eq!(e.generation(), generation);
        assert_eq!(e.application(), application);
    }
    let mut altered = statement(&engines[0]);
    altered.state = [99; 32];
    assert!(engines[0].sign_read(&altered, 10000).is_err());
    let altered = statement(&engines[0]);
    assert!(engines[0].sign_read(&altered, 10300).is_ok());
    assert!(engines[0].sign_read(&altered, 11000).is_ok());
    assert!(engines[0].sign_read(&altered, 11001).is_err());
    assert!(engines[0].sign_read(&altered, 8999).is_err());
}
#[test]
fn fresh_read_requires_full_voting_and_verified_lock_ancestry() {
    let (config, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&config, &keys);
    let e = &mut engines[0];
    assert!(e.read_anchor().is_ok());
    e.faulted = true;
    assert!(e.read_anchor().is_err());
    e.faulted = false;
    e.snapshot.quarantined = true;
    assert!(e.read_anchor().is_err());
    e.snapshot.quarantined = false;
    e.snapshot.prepared = Some(
        serde_json::from_value(
            serde_json::json!({"evidence":[],"history":[],"ready":[],"activation":null}),
        )
        .unwrap(),
    );
    assert!(e.read_anchor().is_err());
    e.snapshot.prepared = None;
    e.snapshot.terminal=Some(serde_json::from_value(serde_json::json!({"node":vec![0u8;32],"ordered":[],"checkpoint_share":[],"deciding":vec![0u8;32],"suffix":[]})).unwrap());
    assert!(e.read_anchor().is_err());
    e.snapshot.terminal = None;
    let locked = e.snapshot.locked;
    e.snapshot.locked = [254; 32];
    assert!(e.read_anchor().is_err());
    e.snapshot.locked = locked;
    let anchor = e.snapshot.applied;
    let removed = e.snapshot.nodes.remove(&id(&anchor)).unwrap();
    assert!(e.read_anchor().is_err());
    e.snapshot.nodes.insert(id(&anchor), removed);
    assert!(e.read_anchor().is_ok());
}
