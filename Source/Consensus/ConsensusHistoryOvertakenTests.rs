// SPDX-License-Identifier: MIT
// A newer checkpoint cannot serve as ancestry for an older already-returned result.
use super::*;
use crate::consensus::checkpoint::tests::{certify, step};
use crate::{authority_history, authority_local_transport as transport};

fn query(
    config: &Configuration,
    height: u64,
    from: Digest,
    target: Digest,
    size: u64,
    root: Option<Digest>,
) -> Vec<u8> {
    wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        config.scope.value(),
        V::Uint(4),
        V::Bytes(
            wire::encode(&V::Array(vec![
                V::Uint(height),
                V::Bytes(from.to_vec()),
                V::Bytes(target.to_vec()),
                V::Uint(size),
                root.map_or(V::Null, |r| V::Bytes(r.to_vec())),
            ]))
            .unwrap(),
        ),
    ]))
    .unwrap()
}

#[test]
fn result159_checkpoint160_overtaking_is_distinct_from_malformed_history() {
    let (configuration, keys) = fixture();
    let directory = Directory::new();
    let mut engine = Engine::create(
        &directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    let mut floor = None;
    let mut target = None;
    for height in 1..=160 {
        step(&mut engine, &keys, height);
        if height == 36 {
            floor = Some(engine.applied().unwrap().digest().unwrap());
        }
        if height == 159 {
            let node = engine.applied().unwrap();
            let before = engine
                .history_reply(36, floor.unwrap(), node.digest().unwrap(), 0, None)
                .unwrap();
            assert_eq!(
                wire::decode(&before).unwrap().array(7).unwrap()[0],
                V::Uint(54)
            );
            target = Some(node.encode().unwrap());
        }
        if height % 32 == 0 {
            certify(&mut engine, &keys);
        }
    }
    let target = target.unwrap();
    let digest = wire::digest(&target);
    let floor = floor.unwrap();
    let runtime = Directory::new();
    let mut driver = repair_driver(
        engine,
        &runtime.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let generation = driver.engine.generation();
    let prefix = configuration.descriptor().genesis().unwrap();
    let response = driver.local_request(&query(&configuration, 36, floor, digest, 0, None));
    let value = wire::decode(&response).unwrap();
    let fields = value.array(10).unwrap();
    assert_eq!(
        (fields[3].uint().unwrap(), fields[4].uint().unwrap()),
        (2, 5)
    );
    assert!(
        transport::HistoryEvidence::checkpoint_reply(&prefix, &target, &response)
            .err()
            .unwrap()
            .is::<transport::HistoryOvertaken>()
    );
    for request in [
        query(&configuration, 36, [99; 32], digest, 0, None),
        query(&configuration, 36, floor, digest, 32, Some([99; 32])),
        query(&configuration, 36, floor, [99; 32], 0, None),
        query(&configuration, 161, floor, digest, 0, None),
    ] {
        let response = driver.local_request(&request);
        let value = wire::decode(&response).unwrap();
        let fields = value.array(10).unwrap();
        assert_eq!(
            (fields[3].uint().unwrap(), fields[4].uint().unwrap()),
            (2, 2)
        );
        assert!(
            !transport::HistoryEvidence::checkpoint_reply(&prefix, &target, &response)
                .err()
                .unwrap()
                .is::<transport::HistoryOvertaken>()
        );
    }
    assert_eq!(driver.engine.generation(), generation);

    step(&mut driver.engine, &keys, 161);
    let fresh = driver.engine.applied().unwrap().encode().unwrap();
    let response = driver.local_request(&query(
        &configuration,
        0,
        *prefix.node(),
        wire::digest(&fresh),
        0,
        None,
    ));
    let parsed = transport::HistoryEvidence::checkpoint_reply(&prefix, &fresh, &response).unwrap();
    assert_eq!(parsed.nodes, vec![fresh]);
    let value = wire::decode(&response).unwrap();
    let fields = value.array(7).unwrap();
    let checkpoint = authority_history::verify_checkpoint(
        configuration.descriptor(),
        fields[4].bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(checkpoint.height(), 160);
    authority_history::verify_history(&checkpoint, &prefix, None, fields[5].bytes().unwrap())
        .unwrap();
    let mut substituted = fields.to_vec();
    substituted[3] = V::Bytes(digest.to_vec());
    substituted[6] = V::Array(vec![]);
    let error = transport::HistoryEvidence::checkpoint_reply(
        &prefix,
        &target,
        &wire::encode(&V::Array(substituted)).unwrap(),
    )
    .err()
    .unwrap();
    assert!(!error.is::<transport::HistoryOvertaken>());
    assert!(
        error
            .to_string()
            .contains("checkpoint suffix scope or height differs")
    );
}
