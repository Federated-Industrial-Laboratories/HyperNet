// SPDX-License-Identifier: MIT
use super::*;
use crate::{
    authority_history::{self as history, TreeHead},
    authority_proof::{Prefix, TrustDescriptor},
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest as _, Sha256};
pub(crate) struct Fixture {
    pub terminal: ValidatedTerminal,
    pub activation: ValidatedActivation,
    pub evidence: Vec<u8>,
    pub history: Vec<u8>,
    pub new_keys: Vec<SigningKey>,
}
fn hash_leaf(v: Digest) -> Digest {
    let mut h = Sha256::new();
    h.update([0]);
    h.update(v);
    h.finalize().into()
}
fn hash_branch(l: Digest, r: Digest) -> Digest {
    let mut h = Sha256::new();
    h.update([1]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}
fn root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return Sha256::digest([]).into();
    }
    if leaves.len() == 1 {
        return hash_leaf(leaves[0]);
    }
    let k = split(leaves.len());
    hash_branch(root(&leaves[..k]), root(&leaves[k..]))
}
fn inclusion(leaves: &[Digest], i: usize) -> Vec<Digest> {
    if leaves.len() == 1 {
        return vec![];
    }
    let k = split(leaves.len());
    if i < k {
        let mut p = inclusion(&leaves[..k], i);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion(&leaves[k..], i - k);
        p.push(root(&leaves[..k]));
        p
    }
}
fn consistency(leaves: &[Digest], m: usize, complete: bool) -> Vec<Digest> {
    if m == leaves.len() {
        return if complete { vec![] } else { vec![root(leaves)] };
    }
    let k = split(leaves.len());
    if m <= k {
        let mut p = consistency(&leaves[..k], m, complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = consistency(&leaves[k..], m - k, false);
        p.push(root(&leaves[..k]));
        p
    }
}
fn quorum(payload: &[u8], keys: &[SigningKey]) -> Vec<u8> {
    let mut signatures = keys
        .iter()
        .map(|key| {
            let public = key.verifying_key().to_bytes();
            (
                public,
                key.sign(&wire::signature_message(payload, &public))
                    .to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|s| s.0);
    wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(payload),
        a(signatures
            .iter()
            .map(|(key, sig)| a(vec![b(key), b(sig)]))
            .collect()),
    ]))
    .unwrap()
}
/// Signing fixtures exercise consumer proof obligations; production nomination evaluation has separate application tests.
pub(crate) fn fixture(
    old: &TrustDescriptor,
    from: &Prefix,
    head: Option<&TreeHead>,
    leaves: &[Digest],
    keys: &[SigningKey],
) -> Fixture {
    assert_eq!(leaves.len() as u64, from.height());
    let requester = SigningKey::from_bytes(&[71; 32]);
    let mut new_keys = (61..=64)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    new_keys.sort_by_key(|k| k.verifying_key().to_bytes());
    let descriptor_value = wire::decode(old.canonical()).unwrap();
    let d = descriptor_value.array(11).unwrap();
    let mut refs = vec![
        VersionRef {
            kind: 100,
            id: old.scope().network,
            generation: 1,
            digest: d[6].fixed().unwrap(),
        },
        VersionRef {
            kind: 114,
            id: old.scope().network,
            generation: 1,
            digest: d[7].fixed().unwrap(),
        },
    ];
    let nominations = new_keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let profile = VersionRef {
                kind: 117,
                id: [120 + i as u8; 32],
                generation: 1,
                digest: [130 + i as u8; 32],
            };
            let consent = VersionRef {
                kind: 105,
                id: profile.id,
                generation: 1,
                digest: [140 + i as u8; 32],
            };
            refs.extend([profile.clone(), consent.clone()]);
            Nomination {
                voter: k.verifying_key().to_bytes(),
                profile,
                consent,
            }
        })
        .collect();
    refs.sort_by_key(VersionRef::index);
    let snapshot = Snapshot::parse(&a(vec![
        a(vec![
            V::Uint(old.scope().epoch),
            V::Uint(from.height()),
            b(from.policy_state()),
        ]),
        a(refs.iter().map(reference).collect()),
    ]))
    .unwrap();
    let declaration = Declaration::create(
        old.scope().clone(),
        requester.verifying_key().to_bytes(),
        [150; 32],
        snapshot,
        nominations,
    )
    .unwrap();
    let intent = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(20),
            V::Uint(1),
            b(&old.scope().network),
            b(&old.scope().incarnation),
            V::Uint(1),
            b(&[151; 32]),
            V::Uint(1),
            V::Uint(0),
            b(&requester.verifying_key().to_bytes()),
            V::Text("Reconfigure".into()),
            b(&old.scope().network),
            V::Uint(from.height()),
            V::Uint(0),
            V::Uint(old.scope().epoch),
            V::Uint(from.height()),
            a(refs.iter().map(reference).collect()),
            b(&declaration.parameters().unwrap()),
        ]))
        .unwrap(),
        &requester,
    )
    .unwrap();
    let intent_digest = Intent::from_signed(&intent).unwrap().digest;
    let at = from.evaluated_at_ms() + 10000;
    let challenge = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(21),
            V::Uint(1),
            b(&old.scope().network),
            b(&old.scope().incarnation),
            b(&requester.verifying_key().to_bytes()),
            b(&[152; 32]),
            b(&[153; 32]),
            b(&intent_digest),
            b(&[154; 32]),
            V::Uint(at - 2000),
            V::Uint(at + 3000),
            V::Uint(5000),
        ]))
        .unwrap(),
        &requester,
    )
    .unwrap();
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        old.scope().value(),
        b(&intent),
        b(&challenge),
        V::Uint(at + 3000),
    ]))
    .unwrap();
    let anchor = wire::encode(&a(vec![
        V::Uint(14),
        V::Uint(1),
        old.scope().value(),
        V::Uint(from.view() + 1),
        V::Uint(from.height() + 1),
        b(from.node()),
        b(&wire::digest(&ordered)),
        V::Uint(at),
        b(&[155; 32]),
    ]))
    .unwrap();
    let node = wire::digest(&anchor);
    let mut next_leaves = leaves.to_vec();
    next_leaves.push(node);
    let statement = wire::encode(&a(vec![
        V::Uint(45),
        V::Uint(1),
        old.scope().value(),
        V::Uint(from.height() + 1),
        b(&node),
        V::Uint(at),
        b(&[156; 32]),
        V::Uint(from.height() + 1),
        b(&root(&next_leaves)),
        V::Bool(true),
    ]))
    .unwrap();
    let checkpoint = wire::encode(&a(vec![
        V::Uint(46),
        V::Uint(1),
        b(&quorum(&statement, &keys[..3])),
        b(&anchor),
    ]))
    .unwrap();
    let checkpoint = history::verify_checkpoint(old, &checkpoint).unwrap();
    let next_state = [157; 32];
    let next_descriptor = descriptor(&declaration, &checkpoint, next_state).unwrap();
    let scope = Scope {
        network: old.scope().network,
        incarnation: old.scope().incarnation,
        configuration: wire::digest(&next_descriptor),
        epoch: declaration.next_epoch,
    };
    let handoff = wire::encode(&a(vec![
        V::Uint(50),
        V::Uint(1),
        old.scope().value(),
        b(checkpoint.digest()),
        b(&declaration.digest()),
        b(&next_descriptor),
        b(&wire::digest(&genesis(&scope, at).unwrap())),
        b(&next_state),
    ]))
    .unwrap();
    let vote = wire::encode(&a(vec![
        V::Uint(11),
        V::Uint(1),
        old.scope().value(),
        V::Uint(from.view() + 1),
        V::Uint(2),
        b(&node),
    ]))
    .unwrap();
    let envelope = wire::decode(&quorum(&vote, &keys[..3])).unwrap();
    let f = envelope.array(4).unwrap();
    let qc = wire::encode(&a(vec![
        V::Uint(12),
        V::Uint(1),
        old.scope().value(),
        f[2].clone(),
        f[3].clone(),
    ]))
    .unwrap();
    let evidence = wire::encode(&a(vec![
        V::Uint(52),
        V::Uint(1),
        b(&ordered),
        b(checkpoint.canonical_proof()),
        b(&quorum(&handoff, &keys[..3])),
        V::Null,
        b(&qc),
        a(vec![]),
    ]))
    .unwrap();
    let path = if from.height() == 0 {
        vec![]
    } else {
        inclusion(&next_leaves, from.height() as usize - 1)
    };
    let (size, prior, consistency) = head.map_or((0, V::Null, vec![]), |h| {
        (
            h.size(),
            b(h.root()),
            consistency(&next_leaves, h.size() as usize, true),
        )
    });
    let history = wire::encode(&a(vec![
        V::Uint(47),
        V::Uint(1),
        old.scope().value(),
        V::Uint(from.height()),
        b(from.node()),
        b(checkpoint.digest()),
        a(path.iter().map(|p| b(p)).collect()),
        V::Uint(size),
        prior,
        a(consistency.iter().map(|p| b(p)).collect()),
    ]))
    .unwrap();
    let terminal = verify_terminal(old, from, head, &evidence, &history).unwrap();
    let ready = quorum(&ready_statement(&terminal).unwrap(), &new_keys[..3]);
    let activation = verify_activation(terminal.clone(), &ready).unwrap();
    Fixture {
        terminal,
        activation,
        evidence,
        history,
        new_keys,
    }
}
#[test]
fn activation_requires_both_quorums_and_exact_retained_history() {
    let base = crate::authority_proof::tests::Fixture::new(10000);
    let from = base.descriptor.genesis().unwrap();
    let keys = crate::authority_proof::tests::signers();
    let f = fixture(&base.descriptor, &from, None, &[], &keys);
    assert_eq!(f.activation.descriptor().unwrap().scope().epoch, 1);
    assert!(
        verify_activation(
            f.terminal.clone(),
            &quorum(&ready_statement(&f.terminal).unwrap(), &f.new_keys[..2])
        )
        .is_err()
    );
    let seal = archive::Seal::new(
        &f.terminal,
        archive::Retained {
            certificate: None,
            node: None,
            checkpoint: None,
        },
    )
    .unwrap();
    let activated = seal.activate(&f.activation).unwrap();
    let resolved = archive::resolve(&base.descriptor, &[activated]).unwrap();
    assert_eq!(resolved.descriptor.scope().epoch, 1);
    let mut bad = wire::decode(&f.evidence)
        .unwrap()
        .array(8)
        .unwrap()
        .to_vec();
    bad[6] = b(&[0; 32]);
    assert!(
        verify_terminal(
            &base.descriptor,
            &from,
            None,
            &wire::encode(&a(bad)).unwrap(),
            &f.history
        )
        .is_err()
    );
}

#[test]
fn terminal_collector_accepts_equivalent_commit_quorums_and_rejects_bad_decisions() {
    let base = crate::authority_proof::tests::Fixture::new(10000);
    let keys = crate::authority_proof::tests::signers();
    let f = fixture(
        &base.descriptor,
        &base.descriptor.genesis().unwrap(),
        None,
        &[],
        &keys,
    );
    let value = wire::decode(&f.evidence).unwrap();
    let fields = value.array(8).unwrap();
    let checkpoint = wire::decode(fields[3].bytes().unwrap()).unwrap();
    let checkpoint = checkpoint.array(4).unwrap();
    let (statement, _) = wire::envelope(checkpoint[2].bytes().unwrap(), 4).unwrap();
    let deciding = wire::decode(fields[6].bytes().unwrap()).unwrap();
    let deciding = deciding.array(5).unwrap();
    let mut shares = Vec::new();
    for (i, key) in keys.iter().take(3).enumerate() {
        let participants = if i == 1 { &keys[1..4] } else { &keys[..3] };
        let signed = quorum(deciding[3].bytes().unwrap(), participants);
        let signed = wire::decode(&signed).unwrap();
        let signed = signed.array(4).unwrap();
        let decision = wire::encode(&a(vec![
            V::Uint(12),
            V::Uint(1),
            base.descriptor.scope().value(),
            signed[2].clone(),
            signed[3].clone(),
        ]))
        .unwrap();
        shares.push(
            wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("EpochTerminalShare".into()),
                fields[2].clone(),
                b(&wire::sign_envelope(&statement, key).unwrap()),
                checkpoint[3].clone(),
                b(&decision),
                a(vec![]),
            ]))
            .unwrap(),
        );
    }
    let collected = assemble_checkpoint(&base.descriptor, &shares).unwrap();
    assert_eq!(
        terminal_checkpoint(&base.descriptor, &collected)
            .unwrap()
            .1
            .digest(),
        f.terminal.checkpoint().digest()
    );
    let mut bad = wire::decode(&shares[1]).unwrap().array(8).unwrap().to_vec();
    bad[6] = b(&[0; 32]);
    shares[1] = wire::encode(&a(bad)).unwrap();
    assert!(assemble_checkpoint(&base.descriptor, &shares).is_err());
    assert!(
        serde_json::from_str::<archive::Retained>(r#"{"node":null,"checkpoint":null}"#).is_err()
    );
}
