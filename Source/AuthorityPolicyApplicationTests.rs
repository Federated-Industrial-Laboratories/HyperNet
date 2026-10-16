// SPDX-License-Identifier: MIT
// Ordered policy changes retain bootstrap provenance, custody history and requester journals.
use super::{
    membership_tests::{code, execute, snapshot},
    tests::Fixture,
    *,
};
use crate::{
    authority_governance::Requirement,
    authority_policies::{self as policies, Operation},
};
use ed25519_dalek::{Signer, SigningKey};
fn signed_payload(payload: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    let mut pairs = keys
        .iter()
        .map(|k| {
            let p = k.verifying_key().to_bytes();
            (p, k.sign(&wire::signature_message(payload, &p)).to_bytes())
        })
        .collect::<Vec<_>>();
    pairs.sort_by_key(|(k, _)| *k);
    wire::encode(&array(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        array(pairs.iter().map(|(k, s)| array(vec![b(k), b(s)])).collect()),
    ]))
    .unwrap()
}
fn proposal(f: &Fixture, prior: &[u8], keys: Option<&[SigningKey]>) -> Vec<u8> {
    let old_keys = (6..=8)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    proposal_signed(f, prior, keys, &old_keys)
}
fn proposal_signed(
    f: &Fixture,
    prior: &[u8],
    keys: Option<&[SigningKey]>,
    authorisers: &[SigningKey],
) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let n = f.app.config.scope.network;
    let i = f.app.config.scope.incarnation;
    let g = Governance::parse(n, i, &state.records).unwrap();
    let previous_policy = g.record_bytes(100, n).unwrap().to_vec();
    let previous_recovery = g.record_bytes(114, n).unwrap().to_vec();
    let old = policies::Custody::parse(&previous_recovery, n, i).unwrap();
    let mut refs = g
        .current_capability(
            f.grant,
            &Requirement {
                subject: f.requester.verifying_key().to_bytes(),
                actions: &[9],
                scope: (0, n),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 6000,
                expected: &[],
            },
        )
        .unwrap()
        .dependencies;
    refs.push(old.reference.clone());
    refs.sort_by_key(VersionRef::index);
    refs.dedup();
    let snapshot =
        crate::authority_membership::Snapshot::parse(&snapshot(f, prior, &refs)).unwrap();
    let mut op = Operation {
        grant: f.grant,
        previous_policy: previous_policy.clone(),
        previous_recovery: previous_recovery.clone(),
        policy: Vec::new(),
        recovery: previous_recovery.clone(),
        old_authorisation: None,
        new_acceptance: None,
        snapshot,
    };
    if let Some(keys) = keys {
        let mut recovery = wire::decode(&previous_recovery)
            .unwrap()
            .array(13)
            .unwrap()
            .to_vec();
        recovery[4] = V::Uint(old.reference.generation + 1);
        recovery[5] = b(&old.reference.digest);
        recovery[9] = array(
            keys.iter()
                .map(|k| array(vec![b(&[0x11; 32]), b(&k.verifying_key().to_bytes())]))
                .collect(),
        );
        let mut fingerprints = keys[..2]
            .iter()
            .map(|k| crate::authority_policies::key_fingerprint(&k.verifying_key().to_bytes()))
            .collect::<Vec<_>>();
        fingerprints.sort();
        recovery[11] = array(fingerprints.iter().map(|k| b(k)).collect());
        recovery[12] = op.snapshot.value.clone();
        op.recovery = wire::encode(&array(recovery)).unwrap();
        op.old_authorisation = Some(signed_payload(&op.recovery, &authorisers[..2]));
        op.new_acceptance = Some(signed_payload(&op.recovery, &keys[..2]));
    }
    let mut policy = wire::decode(&previous_policy)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    let generation = policy[4].uint().unwrap() + 1;
    policy[4] = V::Uint(generation);
    policy[5] = b(&wire::digest(&previous_policy));
    policy[7] = V::Bool(true);
    policy[12] = reference(
        &policies::Custody::parse(&op.recovery, n, i)
            .unwrap()
            .reference,
    );
    policy[15] = array(vec![b(&f.grant)]);
    policy[16] = op.snapshot.value.clone();
    op.policy = wire::encode(&array(policy)).unwrap();
    op.validate(n, i).unwrap();
    let bytes = membership_tests::signed(
        f,
        prior,
        &f.requester,
        "AuthorityPolicyApply",
        n,
        wire::decode(&op.parameters().unwrap()).unwrap(),
        refs,
    );
    let (payload, _) = wire::envelope(&bytes, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[11] = V::Uint(generation);
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), &f.requester).unwrap()
}
#[test]
fn ordered_policy_and_custody_replacement_survive_state_reload() {
    let f = Fixture::with_extra_administrator(1000, vec![9, 25]);
    let request = proposal(&f, &f.initial, None);
    let first = execute(&f, &f.initial, &request, &f.requester, 6000);
    assert_eq!(code(&first), 0);
    let state = State::parse(&f.app.config, &first.state).unwrap();
    let removed = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    assert!(state.streams.keys().contains(&removed));
    let mut keys = (80..=82)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let request = proposal(&f, &first.state, Some(&keys));
    let next = execute(&f, &first.state, &request, &f.requester, 6000);
    assert_eq!(code(&next), 0);
    let reloaded = State::parse(&f.app.config, &next.state).unwrap();
    let g = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &reloaded.records,
    )
    .unwrap();
    assert_eq!(
        policies::record_reference(
            g.record_bytes(100, [20; 32]).unwrap(),
            [20; 32],
            [21; 32],
            100
        )
        .unwrap()
        .generation,
        3
    );
    assert_eq!(
        policies::Custody::parse(g.record_bytes(114, [20; 32]).unwrap(), [20; 32], [21; 32])
            .unwrap()
            .reference
            .generation,
        2
    );
    let reservations = reloaded.effective_reservations().unwrap();
    for key in keys.iter().chain([SigningKey::from_bytes(&[6; 32])].iter()) {
        assert!(reservations.contains(&key.verifying_key().to_bytes()));
    }
    let mut damaged = wire::decode_state(&next.state)
        .unwrap()
        .array(13)
        .unwrap()
        .to_vec();
    damaged[9] = array(vec![]);
    assert!(State::parse(&f.app.config, &wire::encode_state(&array(damaged)).unwrap()).is_err());
}

#[test]
fn committed_custody_rotation_replays_exactly_but_a_new_proposal_cannot_restore_retired_keys() {
    let f = Fixture::with_actions(1000, vec![9, 25]);
    let mut keys = (80..=82)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let request = proposal(&f, &f.initial, Some(&keys));
    let committed = execute(&f, &f.initial, &request, &f.requester, 6000);
    assert_eq!(code(&committed), 0);
    let reloaded = State::parse(&f.app.config, &committed.state).unwrap();
    let reserved = reloaded.effective_reservations().unwrap();
    assert!(
        keys.iter()
            .all(|k| reserved.contains(&k.verifying_key().to_bytes()))
    );

    let replay = execute(&f, &committed.state, &request, &f.requester, 6100);
    assert_eq!(code(&replay), 0);
    assert_eq!(
        tests::result_bytes(&replay),
        tests::result_bytes(&committed)
    );
    assert_eq!(
        State::parse(&f.app.config, &replay.state).unwrap().records,
        reloaded.records
    );

    let mut retired = (6..=8)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    retired.sort_by_key(|k| k.verifying_key().to_bytes());
    let reuse = proposal_signed(&f, &replay.state, Some(&retired), &keys);
    let refused = execute(&f, &replay.state, &reuse, &f.requester, 6200);
    assert_eq!(code(&refused), 3);
    assert_eq!(
        State::parse(&f.app.config, &refused.state).unwrap().records,
        reloaded.records
    );
}
