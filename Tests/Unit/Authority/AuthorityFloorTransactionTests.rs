// SPDX-License-Identifier: MIT
// Forward recovery preserves the newer floor across every published transaction boundary.
use super::super::tests::{Directory, prepare, setup};
use super::*;
use crate::trust_wire::Value as V;
use std::os::unix::fs::PermissionsExt;

fn capture() -> (Directory, TrustDescriptor, Pending, Vec<u8>, Vec<u8>) {
    let (directory, sample, _session, mut store) = setup();
    let old = files::read_at(&store.directory, OsStr::new(FLOOR), LIMIT, true).unwrap();
    let old_state: Stored = serde_json::from_slice(&old).unwrap();
    let (request, _) = prepare(&mut store, sample);
    let next = files::read_at(&store.directory, OsStr::new(FLOOR), LIMIT, true).unwrap();
    let pending = Pending {
        format: "HyperNetAuthorityPending/1".into(),
        network: store.stored.network.clone(),
        incarnation: store.stored.incarnation.clone(),
        requester: store.stored.requester.clone(),
        descriptor: store.stored.descriptor.clone(),
        old_witness: Witness {
            sequence: old_state.sequence,
            digest: hex::encode(digest(&old)),
        },
        next_witness: Witness {
            sequence: store.stored.sequence,
            digest: hex::encode(digest(&next)),
        },
        next_floor_bytes: hex::encode(&next),
        transition: Transition::PrepareOrdinary {
            signed: hex::encode(request.signed()),
        },
        continuity: Continuity::default(),
    };
    let descriptor = store.descriptor.clone();
    drop(store);
    (directory, descriptor, pending, old, next)
}
fn stage(directory: &Directory, pending: &Pending, floor: &[u8], witness: &Witness) {
    std::fs::write(directory.0.join(FLOOR), floor).unwrap();
    std::fs::write(
        directory.0.join(WITNESS),
        serde_json::to_vec(witness).unwrap(),
    )
    .unwrap();
    let path = directory.0.join(PENDING);
    std::fs::write(&path, serde_json::to_vec(pending).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
#[test]
fn each_ordered_crash_boundary_recovers_forward_without_changing_request_bytes() {
    for boundary in 0..3 {
        let (directory, descriptor, pending, old, next) = capture();
        let floor = if boundary == 2 { &next } else { &old };
        let witness = if boundary == 0 {
            &pending.old_witness
        } else {
            &pending.next_witness
        };
        stage(&directory, &pending, floor, witness);
        let store = Store::open(&directory.0, descriptor).unwrap();
        assert_eq!(store.stored.sequence, pending.next_witness.sequence);
        assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), next);
        let Transition::PrepareOrdinary { signed } = pending.transition else {
            unreachable!()
        };
        assert_eq!(
            store.resume_ordinary().unwrap().unwrap().signed(),
            hex::decode(signed).unwrap()
        );
        assert!(!directory.0.join(PENDING).exists());
    }
}
#[test]
fn impossible_order_missing_state_and_higher_witness_never_roll_back() {
    for case in 0..4 {
        let (directory, descriptor, pending, old, next) = capture();
        stage(
            &directory,
            &pending,
            if case == 0 { &next } else { &old },
            &pending.old_witness,
        );
        match case {
            0 => (),
            1 => std::fs::remove_file(directory.0.join(FLOOR)).unwrap(),
            2 => std::fs::write(directory.0.join(FLOOR), b"corrupt").unwrap(),
            _ => std::fs::write(
                directory.0.join(WITNESS),
                serde_json::to_vec(&Witness {
                    sequence: pending.next_witness.sequence + 1,
                    digest: hex::encode([7; 32]),
                })
                .unwrap(),
            )
            .unwrap(),
        }
        let witness = std::fs::read(directory.0.join(WITNESS)).unwrap();
        assert!(Store::open(&directory.0, descriptor).is_err());
        assert_eq!(std::fs::read(directory.0.join(WITNESS)).unwrap(), witness);
        assert!(directory.0.join(PENDING).exists());
        if case == 1 {
            assert!(!directory.0.join(FLOOR).exists());
        }
    }
}
#[test]
fn old_state_recovery_rejects_rehashed_rollback_and_wrong_typed_successor() {
    for case in 0..3 {
        let (directory, descriptor, mut pending, old, next) = capture();
        let mut state: Stored = serde_json::from_slice(&next).unwrap();
        match case {
            0 => state.wall_floor_ms -= 1,
            1 => state.tracker.ordinary = None,
            _ => state.tracker.outstanding_unknown.push(tracker::Unknown {
                signed: String::new(),
                generation: 1,
                generation_id: [8; 32],
                sequence: 1,
                request: [9; 32],
                original: None,
                effect: tracker::Effect::Unclaimed,
                fence: false,
            }),
        }
        let bytes = serde_json::to_vec(&state).unwrap();
        pending.next_floor_bytes = hex::encode(&bytes);
        pending.next_witness.digest = hex::encode(digest(&bytes));
        stage(&directory, &pending, &old, &pending.old_witness);
        assert!(Store::open(&directory.0, descriptor).is_err());
        assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), old);
    }
}

#[test]
fn interrupted_saved_body_transaction_requires_exact_cache_and_preserves_newer_authority() {
    for missing in [false, true] {
        let (directory, sample, mut session, mut store) = setup();
        let (request, operation) = prepare(&mut store, sample);
        let result = super::super::tests::certified(
            &store,
            &mut session,
            sample,
            request.signed(),
            &operation,
            None,
        );
        let permit = store.accept(result, &mut session, sample, 0).unwrap();
        let old = files::read_at(&store.directory, OsStr::new(FLOOR), LIMIT, true).unwrap();
        let old_state = store.stored.clone();
        assert!(
            permit
                .perform(
                    &mut store,
                    &mut session,
                    sample,
                    1,
                    |_| Ok(()),
                    |_, _| -> Result<()> { anyhow::bail!("external cache failure") }
                )
                .is_err()
        );
        let next = files::read_at(&store.directory, OsStr::new(FLOOR), LIMIT, true).unwrap();
        let pending = Pending {
            format: "HyperNetAuthorityPending/1".into(),
            network: store.stored.network.clone(),
            incarnation: store.stored.incarnation.clone(),
            requester: store.stored.requester.clone(),
            descriptor: store.stored.descriptor.clone(),
            old_witness: Witness {
                sequence: old_state.sequence,
                digest: hex::encode(digest(&old)),
            },
            next_witness: Witness {
                sequence: store.stored.sequence,
                digest: hex::encode(digest(&next)),
            },
            next_floor_bytes: hex::encode(&next),
            transition: Transition::SaveBody {
                request: request.digest(),
                result: wire::digest(&operation),
            },
            continuity: Continuity::default(),
        };
        let height = store.prefix().height();
        let descriptor = store.descriptor.clone();
        drop(store);
        stage(&directory, &pending, &old, &pending.next_witness);
        if missing {
            std::fs::remove_file(directory.0.join(BODY)).unwrap();
        }
        let opened = Store::open(&directory.0, descriptor);
        if missing {
            assert!(opened.is_err());
            assert_eq!(std::fs::read(directory.0.join(FLOOR)).unwrap(), old);
            let witness: Witness =
                serde_json::from_slice(&std::fs::read(directory.0.join(WITNESS)).unwrap()).unwrap();
            assert_eq!(witness, pending.next_witness);
        } else {
            let store = opened.unwrap();
            assert_eq!(store.prefix().height(), height);
            assert!(store.stored.tracker.ordinary.as_ref().unwrap().body_saved);
            assert!(!store.stored.tracker.ordinary.as_ref().unwrap().complete);
        }
    }
}

#[test]
fn remote_media_context_retains_only_exact_certified_versions_without_releasing_effect() {
    use crate::{authority_domains as domains, authority_proof::tests::Fixture};
    use ed25519_dalek::{Signer, SigningKey};
    let (_directory, sample, _session, store) = setup();
    let mut fixture = Fixture::new(sample.observe().unwrap().wall_ms);
    let version = |kind, seed| VersionRef {
        kind,
        id: [seed; 32],
        generation: 1,
        digest: [seed + 1; 32],
    };
    let selected = version(157, 62);
    let command = domains::page::Command::MediaAuthorise {
        asset: version(144, 40),
        host: version(143, 42),
        effect: domains::page::MediaEffect::Read,
        offset: 0,
        bytes: 16,
        digest: None,
    };
    let operation = domains::Operation {
        grant: Some(version(102, 44)),
        command: command.into(),
        snapshot: domains::snapshot(&V::Array(vec![
            V::Array(vec![
                V::Uint(0),
                V::Uint(store.prefix().height()),
                V::Bytes(store.prefix().policy_state().to_vec()),
            ]),
            V::Array(vec![]),
        ]))
        .unwrap(),
    };
    let (payload, _) = wire::envelope(&fixture.intent, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[9] = V::Text("AuthorityDomain".into());
    fields[10] = V::Bytes(operation.command.resource().to_vec());
    fields[11] = V::Uint(0);
    fields[12] = V::Uint(0);
    fields[13] = V::Uint(operation.snapshot.epoch);
    fields[14] = V::Uint(operation.snapshot.height);
    fields[15] = V::Array(
        operation
            .snapshot
            .references
            .iter()
            .map(crate::authority_membership::reference)
            .collect(),
    );
    fields[16] = V::Bytes(operation.parameters().unwrap());
    fixture.intent = wire::sign_envelope(
        &wire::encode(&V::Array(fields)).unwrap(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    let intent = proof::Intent::from_signed(&fixture.intent).unwrap();
    let value = wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        V::Array(vec![crate::authority_membership::reference(&selected)]),
        V::Array(vec![
            V::Text(operation.command.name().into()),
            V::Array(vec![]),
            V::Array(vec![]),
            V::Null,
        ]),
    ]))
    .unwrap();
    fixture.operation = wire::encode(&V::Array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        V::Uint(0),
        V::Uint(0),
        V::Bytes(value),
    ]))
    .unwrap();
    fixture.rebuild();
    let (payload, _) = wire::envelope(&fixture.certificate, 4).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(23).unwrap().to_vec();
    fields[14] = V::Uint(1);
    let payload = wire::encode(&V::Array(fields)).unwrap();
    fixture.certificate = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        V::Bytes(payload.clone()),
        V::Array(
            proof::tests::signers()[..3]
                .iter()
                .map(|k| {
                    let public = k.verifying_key().to_bytes();
                    V::Array(vec![
                        V::Bytes(public.to_vec()),
                        V::Bytes(
                            k.sign(&wire::signature_message(&payload, &public))
                                .to_bytes()
                                .to_vec(),
                        ),
                    ])
                })
                .collect(),
        ),
    ]))
    .unwrap();
    let mut old = store.stored.clone();
    old.tracker.ordinary = Some(tracker::Ordinary {
        signed: hex::encode(&fixture.intent),
        original: Some(tracker::Completion {
            sequence: intent.sequence,
            intent: intent.digest,
            disposition: 0,
            reason: 0,
            result_digest: wire::digest(&fixture.operation),
        }),
        latest: None,
        body_saved: false,
        complete: false,
        effect: tracker::Effect::Unclaimed,
    });
    let transition = Transition::RetainMediaContext {
        scope: hex::encode(wire::encode(&fixture.descriptor.scope().value()).unwrap()),
        certificate: hex::encode(&fixture.certificate),
        result: hex::encode(&fixture.operation),
    };
    let mut next = old.clone();
    next.sequence += 1;
    next.generations = vec![selected.clone()];
    delta(&fixture.descriptor, &old, &next, &transition).unwrap();
    assert_eq!(next.tracker, old.tracker);
    assert_eq!(next.certificate, old.certificate);
    let mut forged = next.clone();
    forged.generations[0].digest = [90; 32];
    assert!(delta(&fixture.descriptor, &old, &forged, &transition).is_err());
    forged = next.clone();
    forged.tracker.ordinary.as_mut().unwrap().complete = true;
    assert!(delta(&fixture.descriptor, &old, &forged, &transition).is_err());
    let mut missing = old.clone();
    missing.tracker.ordinary.as_mut().unwrap().original = None;
    assert!(delta(&fixture.descriptor, &missing, &next, &transition).is_err());
    let mut later = old.clone();
    let mut newer = selected;
    newer.generation = 2;
    later.generations = vec![newer];
    assert!(delta(&fixture.descriptor, &later, &next, &transition).is_err());
}
