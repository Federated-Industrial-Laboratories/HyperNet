// SPDX-License-Identifier: MIT
// History preparation returns only a durable certified anchor and exact continuity.
use super::*;
use crate::authority_history;
use crate::consensus::{
    archive,
    records::{Vote, bytes as b},
};

fn query(
    config: &Configuration,
    height: u64,
    from: Digest,
    target: Option<Digest>,
    size: u64,
    root: Option<Digest>,
) -> Vec<u8> {
    wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        config.scope.value(),
        V::Uint(4),
        b(&wire::encode(&V::Array(vec![
            V::Uint(height),
            b(&from),
            target.as_ref().map_or(V::Null, |value| b(value)),
            V::Uint(size),
            root.as_ref().map_or(V::Null, |value| b(value)),
        ]))
        .unwrap()),
    ]))
    .unwrap()
}

fn checkpoint(
    config: &Configuration,
    keys: &[SigningKey; 4],
    leaves: &[Digest],
    anchor: &Node,
) -> (Vec<u8>, Vec<u8>) {
    let state = wire::encode(&V::Array(vec![V::Uint(anchor.height)])).unwrap();
    let statement = wire::encode(&V::Array(vec![
        V::Uint(45),
        V::Uint(1),
        config.scope.value(),
        V::Uint(anchor.height),
        b(&anchor.digest().unwrap()),
        V::Uint(anchor.evaluated_at),
        b(&wire::digest(&state)),
        V::Uint(leaves.len() as u64),
        b(&archive::root(leaves)),
        V::Bool(false),
    ]))
    .unwrap();
    let signatures = keys[..3]
        .iter()
        .map(|key| {
            let signed = wire::sign_envelope(&statement, key).unwrap();
            let signature = wire::envelope(&signed, 1).unwrap().1[0];
            V::Array(vec![b(&signature.0), b(&signature.1)])
        })
        .collect();
    let signed = wire::encode(&V::Array(vec![
        V::Uint(0),
        V::Uint(1),
        b(&statement),
        V::Array(signatures),
    ]))
    .unwrap();
    let proof = wire::encode(&V::Array(vec![
        V::Uint(46),
        V::Uint(1),
        b(&signed),
        b(&anchor.encode().unwrap()),
    ]))
    .unwrap();
    (proof, state)
}

fn refused(response: &[u8], code: u64) {
    let response = wire::decode(response).unwrap();
    let fields = response.array(10).unwrap();
    assert_eq!(fields[0], V::Uint(42));
    assert_eq!(fields[3], V::Uint(2));
    assert_eq!(fields[4], V::Uint(code));
    assert!(fields[5..9].iter().all(|field| *field == V::Null));
    assert_eq!(fields[9], V::Array(vec![]));
}

#[test]
fn latest_checkpoint_preparation_is_certified_consistent_and_read_only() {
    let (configuration, keys) = fixture();
    let directory = Directory::new();
    let engine = Engine::create(
        &directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    let mut driver = repair_driver(
        engine,
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let genesis = configuration.genesis().digest().unwrap();
    let generation = driver.engine.generation();
    refused(
        &driver.local_request(&query(&configuration, 0, genesis, None, 0, None)),
        1,
    );
    refused(
        &driver.local_request(&query(&configuration, 0, genesis, Some(genesis), 0, None)),
        2,
    );
    assert_eq!(driver.engine.generation(), generation);

    // Construct signed checkpoint inputs directly; no consensus progression is needed.
    let mut leaves = Vec::new();
    let mut parent = genesis;
    let mut prior = None;
    for height in 1..=64 {
        let justify = if height == 1 {
            configuration.genesis_qc().unwrap().digest()
        } else {
            Certificate::vote_digest(&Vote {
                scope: configuration.scope.clone(),
                view: height - 1,
                phase: Phase::Prepare,
                node: parent,
            })
            .unwrap()
        };
        let node = Node {
            scope: configuration.scope.clone(),
            view: height,
            height,
            parent: Some(parent),
            command: Some(wire::digest(&height.to_be_bytes())),
            evaluated_at: 10000,
            justify: Some(justify),
        };
        parent = node.digest().unwrap();
        leaves.push(parent);
        if height % 32 != 0 {
            continue;
        }
        let (proof, state) = checkpoint(&configuration, &keys, &leaves, &node);
        driver
            .engine
            .install_checkpoint(
                &proof,
                &state,
                &leaves,
                |state, height| {
                    ensure!(
                        wire::decode(state)?.array(1)?[0].uint()? == height,
                        "Checkpoint application height differs"
                    );
                    Ok(())
                },
                None,
            )
            .unwrap();
        let generation = driver.engine.generation();
        let (floor, from, size, root) = prior.as_ref().map_or(
            (0, genesis, 0, None),
            |old: &authority_history::ValidatedCheckpoint| {
                (
                    old.height(),
                    *old.node(),
                    old.head().size(),
                    Some(*old.head().root()),
                )
            },
        );
        let response = driver.local_request(&query(&configuration, floor, from, None, size, root));
        let decoded = wire::decode(&response).unwrap();
        let fields = decoded.array(7).unwrap();
        assert_eq!(fields[0], V::Uint(54));
        assert_eq!(fields[2], configuration.scope.value());
        assert_eq!(fields[3], b(&parent));
        assert_eq!(fields[4], b(&proof));
        assert_eq!(fields[6], V::Array(vec![]));
        let certified = authority_history::verify_checkpoint(
            configuration.descriptor(),
            fields[4].bytes().unwrap(),
        )
        .unwrap();
        let prefix = prior.as_ref().map_or_else(
            || configuration.descriptor().genesis().unwrap(),
            authority_history::ValidatedCheckpoint::prefix,
        );
        authority_history::verify_history(
            &certified,
            &prefix,
            prior.as_ref().map(|old| old.head()),
            fields[5].bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            driver.local_request(&query(
                &configuration,
                floor,
                from,
                Some(parent),
                size,
                root
            )),
            response
        );
        refused(
            &driver.local_request(&query(&configuration, height + 1, [99; 32], None, 0, None)),
            1,
        );
        assert_eq!(driver.engine.generation(), generation);
        assert_eq!(driver.engine.application(), state);
        assert!(driver.requests.is_empty() && driver.outbox.is_empty() && driver.local.is_empty());
        prior = Some(certified);
    }
    let generation = driver.engine.generation();
    refused(
        &driver.local_request(&query(
            &configuration,
            0,
            genesis,
            Some(leaves[31]),
            0,
            None,
        )),
        5,
    );
    for request in [
        query(&configuration, 0, [99; 32], None, 0, None),
        query(&configuration, 32, [99; 32], None, 0, None),
        query(&configuration, 32, leaves[31], None, 32, Some([99; 32])),
        query(&configuration, 32, leaves[31], None, 33, Some([99; 32])),
        query(&configuration, 32, leaves[31], None, 0, Some([99; 32])),
        query(&configuration, u64::MAX, leaves[31], None, 0, None),
    ] {
        refused(&driver.local_request(&request), 2);
    }
    let mut foreign = configuration.clone();
    foreign.scope.incarnation = [98; 32];
    refused(
        &driver.local_request(&query(&foreign, 0, genesis, None, 0, None)),
        2,
    );
    assert_eq!(driver.engine.generation(), generation);
}
