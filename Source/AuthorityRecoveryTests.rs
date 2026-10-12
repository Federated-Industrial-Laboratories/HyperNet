// SPDX-License-Identifier: MIT
use super::*;
use crate::trust_bootstrap::{Assurance, DraftSpec, RecoveryKey, RecoverySpec, RouteSpec};
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
pub(crate) fn fixture(scope: u8, now: u64) -> (Vec<u8>, Vec<SigningKey>) {
    let mut voters = (1..=4).map(public).collect::<Vec<_>>();
    voters.sort();
    let mut recovery = (6..=8)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    recovery.sort_by_key(|k| k.verifying_key().to_bytes());
    let spec = DraftSpec {
        authority_transports: voters
            .iter()
            .enumerate()
            .map(|(i, v)| (v.clone(), public(30 + i as u8)))
            .collect(),
        voters,
        clock_monitors: vec![public(40)],
        administrator: public(5),
        administrator_actions: vec![9, 10, 11, 12],
        enrolment: "InvitationOnly".into(),
        public_reading: false,
        minimum_route: Assurance::Independent,
        publication_modes: vec!["HostReadable".into(), "Sealed".into()],
        default_publication_mode: "HostReadable".into(),
        limits: [100, 100, 10, 10],
        recovery: RecoverySpec {
            custody: "SharedThreshold".into(),
            keys: recovery
                .iter()
                .enumerate()
                .map(|(i, k)| RecoveryKey {
                    principal: hex::encode([50 + i as u8; 32]),
                    public_key: hex::encode(k.verifying_key().to_bytes()),
                })
                .collect(),
            accepted_keys: recovery[..2]
                .iter()
                .map(|k| hex::encode(k.verifying_key().to_bytes()))
                .collect(),
            immutable_shared: true,
        },
        route: RouteSpec {
            relay_service: hex::encode([12; 32]),
            relay_origin: "https://relay.invalid/".into(),
            relay_transport_key: public(9),
            relay_domain: hex::encode([13; 32]),
            admission_service: hex::encode([14; 32]),
            admission_origin: "https://admission.invalid/".into(),
            admission_transport_key: public(10),
            admission_domain: hex::encode([15; 32]),
            assurance: Assurance::Independent,
            not_before_ms: now - 1,
            expires_ms: now + 3600000,
        },
    };
    let draft = trust::draft(
        spec,
        [
            [scope; 32],
            [scope + 1; 32],
            [scope + 2; 32],
            [scope + 3; 32],
        ],
        now,
    )
    .unwrap();
    let shares = recovery[..2]
        .iter()
        .map(|k| trust::accept(&draft, k, now).unwrap())
        .collect::<Vec<_>>();
    (trust::assemble(&draft, &shares, now).unwrap(), recovery)
}
pub(crate) fn prior(bytes: &[u8]) -> Predecessor {
    let checked = trust::inspect(bytes, true).unwrap();
    Predecessor::new(&checked, &checked.descriptor().genesis().unwrap()).unwrap()
}
pub(crate) fn completed(
    old: &[u8],
    new: &[u8],
    keys: &[SigningKey],
    nonce: u8,
) -> ValidatedDeclaration {
    let p = prior(old);
    let draft = draft(&p, new, [90; 32], [nonce; 32], None).unwrap();
    let shares = keys[..2]
        .iter()
        .map(|k| sign(&p, draft.payload(), k).unwrap())
        .collect::<Vec<_>>();
    assemble(&p, draft.payload(), &shares).unwrap()
}
#[test]
fn recovery_requires_exact_threshold_and_new_identity_without_inherited_authority() {
    let (old, keys) = fixture(20, 1000);
    let (new, _) = fixture(24, 1000);
    let p = prior(&old);
    assert!(draft(&p, &old, [90; 32], [91; 32], None).is_err());
    let unsigned = draft(&p, &new, [90; 32], [91; 32], None).unwrap();
    let first = sign(&p, unsigned.payload(), &keys[0]).unwrap();
    assert!(verify(&p, &first).is_err());
    assert!(assemble(&p, unsigned.payload(), &[first.clone(), first.clone()]).is_err());
    assert!(sign(&p, unsigned.payload(), &SigningKey::from_bytes(&[99; 32])).is_err());
    let second = sign(&p, unsigned.payload(), &keys[1]).unwrap();
    let combined = assemble(&p, unsigned.payload(), &[first, second]).unwrap();
    assert!(!combined.summary().current_authority);
    assert_eq!(combined.summary().state, "AwaitingIndependentAcceptance");
    assert!(combined.declaration().verify_successor(&old).is_err());
    let mut changed = wire::decode(unsigned.payload())
        .unwrap()
        .array(16)
        .unwrap()
        .to_vec();
    changed[9] = a(vec![V::Uint(0), V::Uint(1), b(&[1; 32])]);
    assert!(inspect_draft(&p, &wire::encode(&a(changed)).unwrap()).is_err());
    let policy = trust::inspect(&old, true).unwrap().recovery_payload;
    assert!(verify(&p, &wire::sign_envelope(&policy, &keys[0]).unwrap()).is_err());
}
#[test]
fn competing_valid_custody_quorums_do_not_establish_unique_succession() {
    let (old, keys) = fixture(20, 1000);
    let (one, _) = fixture(24, 1000);
    let (two, _) = fixture(28, 1000);
    let first = completed(&old, &one, &keys, 80);
    let second = completed(&old, &two, &[keys[0].clone(), keys[2].clone()], 81);
    assert_ne!(first.declaration().digest(), second.declaration().digest());
    let client = SigningKey::from_bytes(&[90; 32]);
    assert!(
        accept(
            &first,
            &one,
            wire::digest(&one),
            &client,
            &[second.declaration().digest()]
        )
        .is_err()
    );
    assert!(accept(&first, &one, [8; 32], &client, &[]).is_err());
    let accepted = accept(&first, &one, wire::digest(&one), &client, &[]).unwrap();
    verify_acceptance(&first, &one, &accepted, client.verifying_key().to_bytes()).unwrap();
    assert!(
        verify_acceptance(&second, &two, &accepted, client.verifying_key().to_bytes()).is_err()
    );
    assert!(
        verify_acceptance(&first, &one, &accepted, keys[0].verifying_key().to_bytes()).is_err()
    );
}
