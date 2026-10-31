// SPDX-License-Identifier: MIT
use super::*;
use ed25519_dalek::{Signer, SigningKey};
fn signatures(payload: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    let mut shares = keys
        .iter()
        .map(|k| {
            let p = k.verifying_key().to_bytes();
            (p, k.sign(&wire::signature_message(payload, &p)).to_bytes())
        })
        .collect::<Vec<_>>();
    shares.sort_by_key(|(k, _)| *k);
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(shares.iter().map(|(k, s)| a(vec![b(k), b(s)])).collect()),
    ]))
    .unwrap()
}
pub(crate) fn fixture() -> (
    crate::trust_bootstrap::Verified,
    Operation,
    Intent,
    Vec<SigningKey>,
) {
    let (bytes, keys) = crate::authority_recovery::tests::fixture(20, 10000);
    let boot = crate::trust_bootstrap::inspect(&bytes, true).unwrap();
    let s = boot.descriptor().scope();
    let g = Governance::parse(s.network, s.incarnation, boot.governance_records()).unwrap();
    let p = g.record_bytes(100, s.network).unwrap().to_vec();
    let r = g.record_bytes(114, s.network).unwrap().to_vec();
    let grant = g.versions().into_iter().find(|r| r.kind == 102).unwrap();
    let requester = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
    let cap = g
        .current_capability(
            grant.id,
            &Requirement {
                subject: requester,
                actions: &[9],
                scope: (0, s.network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 20000,
                expected: &[],
            },
        )
        .unwrap();
    let mut refs = cap.dependencies;
    refs.push(record_reference(&r, s.network, s.incarnation, 114).unwrap());
    refs.sort_by_key(VersionRef::index);
    refs.dedup();
    let prefix = boot.descriptor().genesis().unwrap();
    let snapshot = Snapshot::parse(&a(vec![
        a(vec![V::Uint(0), V::Uint(0), b(prefix.policy_state())]),
        a(refs.iter().map(reference).collect()),
    ]))
    .unwrap();
    let mut fields = wire::decode(&p).unwrap().array(17).unwrap().to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(&p));
    fields[7] = V::Bool(true);
    fields[16] = snapshot.value.clone();
    let op = Operation {
        grant: grant.id,
        previous_policy: p,
        previous_recovery: r.clone(),
        policy: wire::encode(&a(fields)).unwrap(),
        recovery: r,
        old_authorisation: None,
        new_acceptance: None,
        snapshot,
    };
    let intent = Intent {
        network: s.network,
        incarnation: s.incarnation,
        generation: 1,
        generation_id: [71; 32],
        sequence: 1,
        acknowledged_through: 0,
        requester,
        action: "AuthorityPolicyApply".into(),
        resource: s.network,
        revision: 2,
        profile_generation: 0,
        minimum_policy_epoch: 0,
        minimum_policy_height: 0,
        expected: refs,
        parameters: op.parameters().unwrap(),
        digest: [72; 32],
    };
    (boot, op, intent, keys)
}
#[test]
fn policy_apply_requires_exact_current_predecessor_and_preserves_unrelated_records() {
    let (boot, op, intent, _) = fixture();
    Operation::parse(&intent).unwrap();
    let reserved = crate::authority_membership::Reservations(boot.reservations().to_vec());
    let d = authorise(
        &op,
        boot.governance_records(),
        &reserved,
        &intent,
        20000,
        false,
    )
    .unwrap();
    assert_eq!(d.code, 0);
    let updated = d.records.unwrap();
    assert_eq!(updated.len(), boot.governance_records().len());
    let current = Governance::parse(intent.network, intent.incarnation, &updated).unwrap();
    assert_eq!(
        current.record_bytes(100, intent.network).unwrap(),
        op.policy
    );
    assert_eq!(
        current.record_bytes(114, intent.network).unwrap(),
        op.previous_recovery
    );
    assert_eq!(
        authorise(&op, &updated, &reserved, &intent, 20000, false)
            .unwrap()
            .code,
        12
    );
    assert_eq!(
        authorise(&op, &updated, &reserved, &intent, 20000, true)
            .unwrap()
            .code,
        0
    );
    let mut stale = intent.clone();
    stale.expected.pop();
    assert!(Operation::parse(&stale).is_err());
}
#[test]
fn custody_rotation_has_separate_thresholds_and_never_revives_revoked_keys() {
    let (boot, mut op, mut intent, old_keys) = fixture();
    let s = boot.descriptor().scope();
    let new_keys = (80..=82)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let mut fields = wire::decode(&op.previous_recovery)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    fields[4] = V::Uint(2);
    fields[5] = b(&wire::digest(&op.previous_recovery));
    let principals = fields[8].list(3).unwrap().to_vec();
    fields[9] = a(principals
        .into_iter()
        .zip(&new_keys)
        .map(|(p, k)| a(vec![p, b(&k.verifying_key().to_bytes())]))
        .collect());
    let mut fingerprints = new_keys[..2]
        .iter()
        .map(|k| key_fingerprint(&k.verifying_key().to_bytes()))
        .collect::<Vec<_>>();
    fingerprints.sort();
    fields[11] = a(fingerprints.iter().map(|k| b(k)).collect());
    fields[12] = op.snapshot.value.clone();
    op.recovery = wire::encode(&a(fields)).unwrap();
    let r = Custody::parse(&op.recovery, s.network, s.incarnation).unwrap();
    let mut p = wire::decode(&op.policy)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    p[12] = reference(&r.reference);
    op.policy = wire::encode(&a(p)).unwrap();
    op.old_authorisation = Some(signatures(&op.recovery, &old_keys[..2]));
    op.new_acceptance = Some(signatures(&op.recovery, &new_keys[..2]));
    op.validate(s.network, s.incarnation).unwrap();
    intent.parameters = op.parameters().unwrap();
    let reserved = crate::authority_membership::Reservations(boot.reservations().to_vec());
    assert_eq!(
        authorise(
            &op,
            boot.governance_records(),
            &reserved,
            &intent,
            20000,
            false
        )
        .unwrap()
        .code,
        0
    );
    let prior = crate::authority_recovery::Predecessor::retained(
        &boot,
        &boot.descriptor().genesis().unwrap(),
        &op.recovery,
        &r.reference,
    )
    .unwrap();
    let (successor, _) = crate::authority_recovery::tests::fixture(30, 10000);
    let draft =
        crate::authority_recovery::draft(&prior, &successor, [90; 32], [91; 32], None).unwrap();
    assert!(crate::authority_recovery::sign(&prior, draft.payload(), &old_keys[0]).is_err());
    assert!(crate::authority_recovery::sign(&prior, draft.payload(), &new_keys[0]).is_ok());
    op.old_authorisation = op.new_acceptance.clone();
    assert!(op.validate(s.network, s.incarnation).is_err());
    op.old_authorisation = Some(signatures(&op.recovery, &old_keys[..1]));
    assert!(op.validate(s.network, s.incarnation).is_err());
}
#[test]
fn immutable_shared_custody_and_client_minima_refuse_weaker_trust() {
    let (boot, op, _, _) = fixture();
    let s = boot.descriptor().scope();
    let old = Custody::parse(&op.recovery, s.network, s.incarnation).unwrap();
    let mut f = wire::decode(&op.recovery)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    let key = old.keys[0];
    f[6] = V::Uint(0);
    f[7] = V::Uint(1);
    f[8] = a(vec![b(&key.0)]);
    f[9] = a(vec![a(vec![b(&key.0), b(&key.1)])]);
    f[10] = V::Bool(false);
    f[11] = a(vec![b(&key_fingerprint(&key.1))]);
    let weaker = wire::encode(&a(f)).unwrap();
    assert!(
        check_minima(
            &op.policy,
            &weaker,
            &op.previous_policy,
            &op.previous_recovery,
            s.network,
            s.incarnation
        )
        .is_err()
    );
    let mut immutable_change = op.clone();
    let mut f = wire::decode(&weaker).unwrap().array(13).unwrap().to_vec();
    f[4] = V::Uint(2);
    f[5] = b(&wire::digest(&op.previous_recovery));
    f[12] = op.snapshot.value.clone();
    immutable_change.recovery = wire::encode(&a(f)).unwrap();
    let r = Custody::parse(&immutable_change.recovery, s.network, s.incarnation).unwrap();
    let mut p = wire::decode(&op.policy)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    p[12] = reference(&r.reference);
    immutable_change.policy = wire::encode(&a(p)).unwrap();
    assert!(
        immutable_change
            .validate_unsigned(s.network, s.incarnation)
            .is_err()
    );
    let mut p = wire::decode(&op.policy)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    p[8] = V::Uint(0);
    assert!(
        check_minima(
            &wire::encode(&a(p)).unwrap(),
            &op.recovery,
            &op.previous_policy,
            &op.previous_recovery,
            s.network,
            s.incarnation
        )
        .is_err()
    );
}
