// SPDX-License-Identifier: MIT
// Unit tests for TrustBootstrap.
use super::*;
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn fixture() -> (Vec<u8>, Vec<SigningKey>) {
    let mut voters = (1..=4).map(public).collect::<Vec<_>>();
    voters.sort();
    let mut recovery = (6..=8)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect::<Vec<_>>();
    recovery.sort_by_key(|key| key.verifying_key().to_bytes());
    let authority_transports = voters
        .iter()
        .enumerate()
        .map(|(index, voter)| (voter.clone(), public(30 + index as u8)))
        .collect();
    let spec = DraftSpec {
        voters,
        authority_transports,
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
            custody: "OwnerThreshold".into(),
            keys: recovery
                .iter()
                .map(|key| RecoveryKey {
                    principal: "11".repeat(32),
                    public_key: hex::encode(key.verifying_key().to_bytes()),
                })
                .collect(),
            accepted_keys: recovery[..2]
                .iter()
                .map(|key| hex::encode(key.verifying_key().to_bytes()))
                .collect(),
            immutable_shared: false,
        },
        route: RouteSpec {
            relay_service: "12".repeat(32),
            relay_origin: "https://relay.invalid/".into(),
            relay_transport_key: public(9),
            relay_domain: "13".repeat(32),
            admission_service: "14".repeat(32),
            admission_origin: "https://admission.invalid/".into(),
            admission_transport_key: public(10),
            admission_domain: "15".repeat(32),
            assurance: Assurance::Independent,
            not_before_ms: 50,
            expires_ms: 1000,
        },
    };
    (
        draft(spec, [[20; 32], [21; 32], [22; 32], [23; 32]], 100).unwrap(),
        recovery,
    )
}
#[test]
fn custody_requires_authorised_signatures_over_exact_policy() {
    let (draft, keys) = fixture();
    let first = accept(&draft, &keys[0], 100).unwrap();
    let second = accept(&draft, &keys[1], 100).unwrap();
    let complete = assemble(&draft, &[first.clone(), second], 100).unwrap();
    assert!(check(&complete, true, 100).is_ok());
    assert!(assemble(&draft, &[first], 100).is_err());
    let checked = check(&draft, false, 100).unwrap();
    let outsider = SigningKey::from_bytes(&[99; 32]);
    let mut signatures = BTreeMap::new();
    for key in [&keys[0], &outsider] {
        let signed = wire::sign_envelope(&checked.recovery_payload, key).unwrap();
        let (_, pairs) = wire::envelope(&signed, 1).unwrap();
        signatures.extend(pairs);
    }
    let forged = wire::encode(&array([
        u(0),
        u(1),
        b(&checked.recovery_payload),
        array(signatures.iter().map(|(key, sig)| array([b(key), b(sig)]))),
    ]))
    .unwrap();
    // Every signature is valid cryptographically, but an outsider has no custody vote.
    assert!(wire::envelope(&forged, 3).is_ok());
    let mut bundle = wire::decode(&complete).unwrap().array(6).unwrap().to_vec();
    bundle[4] = b(&forged);
    assert!(check(&wire::encode(&array(bundle)).unwrap(), true, 100).is_err());
    assert!(accept(&draft, &outsider, 100).is_err());
    assert!(accept(&draft, &keys[2], 100).is_err());
}
#[test]
fn bootstrap_file_pin_and_protocol_fingerprint_remain_distinct() {
    let (draft, keys) = fixture();
    let complete = assemble(
        &draft,
        &[
            accept(&draft, &keys[0], 100).unwrap(),
            accept(&draft, &keys[1], 100).unwrap(),
        ],
        100,
    )
    .unwrap();
    let verified = inspect(&complete, true).unwrap();
    let file_pin: [u8; 32] = Sha256::digest(&complete).into();
    assert_eq!(verified.file_digest(), file_pin);
    assert_eq!(verified.fingerprint(), wire::digest(&complete));
    assert_ne!(verified.file_digest(), verified.fingerprint());
}
#[test]
fn reservations_are_exact_and_committed_by_the_genesis_digest() {
    let (draft, _) = fixture();
    let bundle = wire::decode(&draft).unwrap().array(6).unwrap().to_vec();
    let genesis = wire::decode(bundle[3].bytes().unwrap())
        .unwrap()
        .array(6)
        .unwrap()
        .to_vec();
    assert_eq!(genesis[5].list(64).unwrap().len(), 15);
    for variant in 0..4 {
        let mut changed = genesis.clone();
        match variant {
            0 => {
                changed.pop();
            }
            1 => {
                let V::Array(roles) = &mut changed[5] else {
                    unreachable!()
                };
                roles.pop();
            }
            2 => {
                let V::Array(roles) = &mut changed[5] else {
                    unreachable!()
                };
                roles.swap(0, 1);
            }
            _ => {
                let V::Array(roles) = &mut changed[5] else {
                    unreachable!()
                };
                let V::Array(role) = &mut roles[0] else {
                    unreachable!()
                };
                role[0] = u(5);
            }
        }
        let changed = wire::encode(&array(changed)).unwrap();
        let mut bundle = bundle.clone();
        let mut descriptor = wire::decode(bundle[2].bytes().unwrap())
            .unwrap()
            .array(11)
            .unwrap()
            .to_vec();
        descriptor[8] = b(&wire::digest(&changed));
        bundle[2] = b(&wire::encode(&array(descriptor)).unwrap());
        bundle[3] = b(&changed);
        assert!(check(&wire::encode(&array(bundle)).unwrap(), false, 100).is_err());
    }
}
#[test]
fn expired_bootstrap_remains_inspectable_without_authority() {
    let (draft, keys) = fixture();
    let complete = assemble(
        &draft,
        &[
            accept(&draft, &keys[0], 100).unwrap(),
            accept(&draft, &keys[1], 100).unwrap(),
        ],
        100,
    )
    .unwrap();
    assert!(check(&complete, true, 1000).is_err());
    assert!(inspect(&complete, true).is_ok());
    assert!(check(&complete, true, 49).is_err());
}
