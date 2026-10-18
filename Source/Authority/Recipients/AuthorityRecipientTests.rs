// SPDX-License-Identifier: MIT
// Durable effect claims separate serving recipients from caller request ownership.
use super::*;
use crate::{authority_proof::tests::Fixture, trust_wire::Value as V};
use ed25519_dalek::Signer;
use std::path::PathBuf;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("HyperNetRecipient{}", crate::random_hex::<16>()));
        files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn health() -> ClockHealth {
    ClockHealth::new(10000, 100, 30100, 100).unwrap().frozen()
}
fn fixture(session: &mut Session) -> Fixture {
    let mut f = Fixture::new(10000);
    f.challenge = session
        .issue(&f.intent, &f.recipient, [91; 32], 5000, health())
        .unwrap();
    f.rebuild();
    f
}
fn successor(first: &Fixture, session: &mut Session) -> Fixture {
    let mut f = fixture(session);
    let mut n = wire::decode(&f.ancestry[0])
        .unwrap()
        .array(9)
        .unwrap()
        .to_vec();
    n[3] = V::Uint(2);
    n[4] = V::Uint(2);
    n[5] = V::Bytes(wire::digest(&first.ancestry[0]).to_vec());
    let n = wire::encode(&V::Array(n)).unwrap();
    f.ancestry = vec![first.ancestry[0].clone(), n.clone()];
    let (p, _) = wire::envelope(&f.certificate, 4).unwrap();
    let mut p = wire::decode(&p).unwrap().array(23).unwrap().to_vec();
    p[3] = V::Uint(2);
    p[4] = V::Bytes(wire::digest(&n).to_vec());
    let p = wire::encode(&V::Array(p)).unwrap();
    let signatures = proof::tests::signers()[..3]
        .iter()
        .map(|k| {
            let key = k.verifying_key().to_bytes();
            V::Array(vec![
                V::Bytes(key.to_vec()),
                V::Bytes(
                    k.sign(&wire::signature_message(&p, &key))
                        .to_bytes()
                        .to_vec(),
                ),
            ])
        })
        .collect();
    f.certificate = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        V::Bytes(p),
        V::Array(signatures),
    ]))
    .unwrap();
    f
}
fn store(d: &Directory, f: &Fixture) -> Store {
    Store::initialise(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
        health(),
    )
    .unwrap()
}
#[test]
fn recipient_does_not_own_caller_and_completed_effect_cannot_repeat() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let mut s = store(&d, &f);
    assert_ne!(
        Intent::from_signed(&f.intent).unwrap().requester,
        s.recipient()
    );
    let p = s
        .accept(f.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    assert_eq!(
        p.perform(
            &mut s,
            &mut session,
            &mut || Ok(health()),
            64,
            |_| Ok(()),
            |r, _| Ok(r.action.clone())
        )
        .unwrap(),
        "ReadPage"
    );
    let intent = Intent::from_signed(&f.intent).unwrap().digest;
    assert_eq!(s.claim_state(intent), Some(ClaimState::Complete));
    drop(s);
    let mut s = Store::open(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(s.prefix().height(), 1);
    let mut session = Session::new().unwrap();
    let next = successor(&f, &mut session);
    let p = s
        .accept(next.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    assert!(
        p.perform(
            &mut s,
            &mut session,
            &mut || Ok(health()),
            64,
            |_| Ok(()),
            |_, _| -> Result<()> { panic!("duplicate effect") }
        )
        .is_err()
    );
    assert_eq!(s.claim_state(intent), Some(ClaimState::Complete));
    assert!(std::fs::read_dir(&d.0).unwrap().all(|p| {
        !p.unwrap()
            .file_name()
            .to_string_lossy()
            .contains("Requester")
    }));
}
#[test]
fn uncertain_effect_survives_restart_and_needs_explicit_exact_reconciliation() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let mut s = store(&d, &f);
    let intent = Intent::from_signed(&f.intent).unwrap().digest;
    let p = s
        .accept(f.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    assert!(
        p.perform(
            &mut s,
            &mut session,
            &mut || Ok(health()),
            1,
            |_| Ok(()),
            |_, _| -> Result<()> { anyhow::bail!("interrupted after claim") }
        )
        .is_err()
    );
    assert_eq!(s.claim_state(intent), Some(ClaimState::Claimed));
    drop(s);
    let mut s = Store::open(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    let mut session = Session::new().unwrap();
    let next = successor(&f, &mut session);
    let p = s
        .accept(next.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    assert!(
        p.reconcile(
            &mut s,
            &mut session,
            &mut || Ok(health()),
            2,
            |_| Ok(()),
            |_, _, _| -> Result<()> { panic!("changed effect") }
        )
        .is_err()
    );
    let p = s
        .accept(next.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    p.reconcile(
        &mut s,
        &mut session,
        &mut || Ok(health()),
        1,
        |_| Ok(()),
        |_, _, state| {
            assert_eq!(state, ClaimState::Claimed);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(s.claim_state(intent), Some(ClaimState::Complete));
}
#[test]
fn local_restriction_change_suppresses_output_without_erasing_effect() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let mut s = store(&d, &f);
    let p = s
        .accept(f.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    let mut checks = 0;
    assert!(
        p.perform(
            &mut s,
            &mut session,
            &mut || Ok(health()),
            1,
            |_| {
                checks += 1;
                ensure!(checks < 3, "local consent withdrawn");
                Ok(())
            },
            |_, _| Ok("sensitive output")
        )
        .is_err()
    );
    assert_eq!(
        s.claim_state(Intent::from_signed(&f.intent).unwrap().digest),
        Some(ClaimState::Complete)
    );
}
#[test]
fn partial_floor_restore_and_changed_recipient_are_refused() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let mut s = store(&d, &f);
    let initial = std::fs::read(d.0.join(FLOOR)).unwrap();
    s.accept(f.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    drop(s);
    assert!(
        Store::open(
            &d.0,
            f.descriptor.clone(),
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes()
        )
        .is_err()
    );
    std::fs::write(d.0.join(FLOOR), initial).unwrap();
    assert!(
        Store::open(
            &d.0,
            f.descriptor.clone(),
            f.recipient.verifying_key().to_bytes()
        )
        .is_err()
    );
}
#[test]
fn interrupted_initialisation_completes_forward_without_reset() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let s = store(&d, &f);
    let next = std::fs::read(d.0.join(FLOOR)).unwrap();
    drop(s);
    let dir = files::private_directory(&d.0).unwrap();
    files::atomic_at(
        &dir,
        OsStr::new(transaction::PENDING),
        &serde_json::to_vec(
            &serde_json::json!({"old":"","next":hex::encode(&next),"continuity":null}),
        )
        .unwrap(),
        false,
    )
    .unwrap();
    files::remove_private_at(&dir, OsStr::new(WITNESS)).unwrap();
    assert!(
        Store::initialise(
            &d.0,
            f.descriptor.clone(),
            f.recipient.verifying_key().to_bytes(),
            health()
        )
        .is_err()
    );
    let s = Store::open(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(s.prefix(), &f.descriptor.genesis().unwrap());
    assert!(!d.0.join(transaction::PENDING).exists());
}

#[test]
fn epoch_activation_keeps_uncertain_effects_and_recovers_interrupted_publication() {
    let d = Directory::new();
    let mut session = Session::new().unwrap();
    let f = fixture(&mut session);
    let mut s = store(&d, &f);
    let intent = Intent::from_signed(&f.intent).unwrap().digest;
    let permit = s
        .accept(f.verify().unwrap(), &mut session, health(), 0)
        .unwrap();
    assert!(
        permit
            .perform(
                &mut s,
                &mut session,
                &mut || Ok(health()),
                1,
                |_| Ok(()),
                |_, _| -> Result<()> { anyhow::bail!("interrupted effect") }
            )
            .is_err()
    );
    let callers = s.stored.callers.clone();
    let claims = s.stored.claims.clone();
    let versions = s.stored.versions.clone();
    let wall = s.stored.wall_floor_ms;
    let transition = crate::authority_epoch::tests::fixture(
        &f.descriptor,
        s.prefix(),
        s.tree_head(),
        &[wire::digest(&f.ancestry[0])],
        &proof::tests::signers(),
    );
    s.seal_epoch(&transition.terminal).unwrap();
    assert!(s.epoch_sealed());
    let old = files::read_at(s.profile_directory(), OsStr::new(FLOOR), LIMIT, true).unwrap();
    let witness = files::read_at(s.profile_directory(), OsStr::new(WITNESS), 1024, true).unwrap();
    drop(s);
    let mut s = Store::open(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(s.epoch_sealed());
    let mut fresh = Session::new().unwrap();
    let retry = successor(&f, &mut fresh);
    assert!(
        s.accept(retry.verify().unwrap(), &mut fresh, health(), 0)
            .is_err()
    );
    s.activate_epoch(&transition.activation).unwrap();
    assert!(!s.epoch_sealed());
    assert_eq!(s.descriptor().scope().epoch, 1);
    assert_eq!(s.prefix().height(), 0);
    assert_eq!(s.stored.callers, callers);
    assert_eq!(s.stored.claims, claims);
    assert_eq!(s.stored.versions, versions);
    assert_eq!(s.stored.wall_floor_ms, wall);
    assert_eq!(s.claim_state(intent), Some(ClaimState::Claimed));
    let next = files::read_at(s.profile_directory(), OsStr::new(FLOOR), LIMIT, true).unwrap();
    let pending = serde_json::to_vec(
        &serde_json::json!({"old":hex::encode(old),"next":hex::encode(next),"continuity":null}),
    )
    .unwrap();
    files::atomic_at(s.profile_directory(), OsStr::new(WITNESS), &witness, true).unwrap();
    files::atomic_at(
        s.profile_directory(),
        OsStr::new(transaction::PENDING),
        &pending,
        true,
    )
    .unwrap();
    drop(s);
    let mut s = Store::open(
        &d.0,
        f.descriptor.clone(),
        f.recipient.verifying_key().to_bytes(),
    )
    .unwrap();
    assert_eq!(s.descriptor().scope().epoch, 1);
    assert_eq!(s.claim_state(intent), Some(ClaimState::Claimed));
    assert_eq!(s.stored.callers, callers);
    assert_eq!(s.stored.versions, versions);
    assert!(!transaction::exists(s.profile_directory(), transaction::PENDING).unwrap());
    s.activate_epoch(&transition.activation).unwrap();
    assert_eq!(s.stored.epochs.len(), 1);
    assert!(
        s.accept(retry.verify().unwrap(), &mut fresh, health(), 0)
            .is_err()
    );
}
