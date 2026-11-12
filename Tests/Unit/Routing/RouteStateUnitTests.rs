// SPDX-License-Identifier: MIT
// Unit tests for RouteState.
use super::*;
use std::os::unix::fs::MetadataExt;

fn directory() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "HyperNetRouteState{}",
        hex::encode(crate::route_protocol::random().unwrap())
    ));
    files::create_directory(&path).unwrap();
    path
}
#[test]
fn private_route_spent_connection_survives_restart() {
    let path = directory();
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    disk.consume([3; 32], 100, 120000).unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    // Restart cannot resurrect a stream after its short proof has expired.
    assert!(disk.consume([3; 32], 6000, 120000).is_err());
    disk.consume([4; 32], 6000, 120000).unwrap();
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn private_route_identical_publication_reuses_only_durable_bytes() {
    let path = directory();
    let target = path.join("RouteState.cbor");
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    let initial = File::open(&target).unwrap();
    disk.publish(disk.snapshot.state.clone(), disk.snapshot.records.clone())
        .unwrap();
    assert_eq!(
        initial.metadata().unwrap().ino(),
        target.metadata().unwrap().ino()
    );

    disk.consume([3; 32], 100, 120000).unwrap();
    let consumed = File::open(&target).unwrap();
    assert_ne!(
        initial.metadata().unwrap().ino(),
        consumed.metadata().unwrap().ino()
    );
    disk.publish(disk.snapshot.state.clone(), disk.snapshot.records.clone())
        .unwrap();
    assert_eq!(
        consumed.metadata().unwrap().ino(),
        target.metadata().unwrap().ino()
    );
    drop(disk);

    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    disk.publish(disk.snapshot.state.clone(), disk.snapshot.records.clone())
        .unwrap();
    assert_eq!(
        consumed.metadata().unwrap().ino(),
        target.metadata().unwrap().ino()
    );
    assert!(disk.consume([3; 32], 6000, 120000).is_err());
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn private_route_failed_publication_cannot_be_elided_as_an_identical_retry() {
    let path = directory();
    let target = path.join("RouteState.cbor");
    let saved = path.join("Retained.cbor");
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    std::fs::rename(&target, &saved).unwrap();
    std::fs::create_dir(&target).unwrap();
    assert!(disk.consume([3; 32], 100, 120000).is_err());
    // The in-memory update is identical, but neither attempted publication reached storage.
    assert!(
        disk.publish(disk.snapshot.state.clone(), disk.snapshot.records.clone())
            .is_err()
    );
    std::fs::remove_dir(&target).unwrap();
    std::fs::rename(&saved, &target).unwrap();
    disk.publish(disk.snapshot.state.clone(), disk.snapshot.records.clone())
        .unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    assert!(disk.consume([3; 32], 6000, 120000).is_err());
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

fn connection(index: usize) -> Digest {
    let mut id = [9; 32];
    id[..8].copy_from_slice(&(index as u64).to_be_bytes());
    id
}

#[test]
fn route_replay_chunks_cover_capacity_without_expanding_wire_arrays() {
    for count in [4095, 4096, 4097, MAX_SPENT] {
        let path = directory();
        let maximum = domains::MAXIMUM_BYTES * 4;
        let mut disk = Disk::open(&path, [1; 32], [2; 32], maximum).unwrap();
        disk.snapshot.spent = (0..count).map(|i| (connection(i), 120000)).collect();
        disk.save().unwrap();
        drop(disk);
        let mut disk = Disk::open(&path, [1; 32], [2; 32], maximum).unwrap();
        assert_eq!(disk.snapshot.spent.len(), count);
        assert!(disk.consume(connection(0), 100, 120000).is_err());
        let next = disk.consume(connection(count), 100, 120000);
        assert_eq!(next.is_ok(), count < MAX_SPENT);
        assert_eq!(
            disk.snapshot.spent.len(),
            count + usize::from(count < MAX_SPENT)
        );
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
    assert!(wire::encode(&V::Array(vec![V::Uint(0); CHUNK + 1])).is_err());
    // The network decoder retains the same bound even for otherwise valid CBOR.
    let mut oversized = vec![0x99, 0x10, 0x01];
    oversized.extend(vec![0; CHUNK + 1]);
    assert!(wire::decode(&oversized).is_err());
}

#[test]
fn legacy_route_cache_migrates_without_losing_live_replay_identifiers() {
    let path = directory();
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    disk.snapshot.spent.insert([3; 32], 10);
    disk.snapshot.spent.insert([4; 32], 120000);
    let legacy = disk.snapshot.encode(1).unwrap();
    files::atomic_at(&disk.directory, OsStr::new(FILE), &legacy, true).unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    assert_eq!(disk.persisted.as_ref().unwrap(), &legacy);
    disk.consume([5; 32], 100, 120000).unwrap();
    assert!(!disk.snapshot.spent.contains_key(&[3; 32]));
    let v = wire::decode_state(disk.persisted.as_ref().unwrap()).unwrap();
    assert_eq!(v.array(6).unwrap()[1].uint().unwrap(), 2);
    drop(disk);
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    assert!(disk.consume([4; 32], 100, 120000).is_err());
    assert!(disk.consume([5; 32], 100, 120000).is_err());
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn route_cache_rejects_noncanonical_chunks_and_independent_byte_exhaustion() {
    let path = directory();
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    disk.snapshot.spent.insert(connection(1), 120000);
    let mut value = wire::decode_state(&disk.snapshot.encode(2).unwrap()).unwrap();
    let V::Array(f) = &mut value else {
        unreachable!()
    };
    let V::Array(chunks) = &mut f[5] else {
        unreachable!()
    };
    chunks.push(V::Array(vec![]));
    assert!(Snapshot::decode(&wire::encode_state(&value).unwrap(), [1; 32], [2; 32]).is_err());
    let saved = std::fs::read(path.join(FILE)).unwrap();
    disk.snapshot.spent = (0..4096).map(|i| (connection(i), 120000)).collect();
    assert!(
        disk.save()
            .unwrap_err()
            .to_string()
            .contains("storage admission")
    );
    assert_eq!(std::fs::read(path.join(FILE)).unwrap(), saved);
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

fn usage(state: &State, generation: u64) -> domains::Record {
    domains::Record::next(
        state,
        167,
        [7; 32],
        V::Array(vec![
            V::Uint(generation),
            V::Uint(500),
            V::Bytes([8; 32].to_vec()),
            V::Bytes([9; 32].to_vec()),
            V::Bytes([10; 32].to_vec()),
        ]),
    )
    .unwrap()
}

#[test]
fn route_cache_candidate_recovers_only_after_fresh_floor_authentication() {
    use crate::authority_floor::tests::{read::Read, setup};
    for stop in 0..3 {
        let (requester, sample, mut session, mut store) = setup();
        let scope = store.descriptor().scope().clone();
        let path = directory();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        let wall = store.cache_wall_floor().unwrap();
        disk.snapshot.spent.insert([3; 32], wall);
        disk.snapshot.spent.insert([4; 32], wall + 120000);
        disk.save().unwrap();
        let old = std::fs::read(path.join(FILE)).unwrap();
        let record = usage(&disk.snapshot.state, 1);
        let mut next = disk.snapshot.state.clone();
        next.records
            .insert(record.reference.index(), record.clone());
        disk.stage(next, vec![], &store).unwrap();
        assert!(disk.consume([5; 32], wall, wall + 100).is_err());
        if stop > 0 {
            let query =
                Read::with_versions(&store, &mut session, sample, vec![record.reference.clone()]);
            let verified = query.verify(&store);
            store
                .accept_read(verified, &mut session, sample, 0, |_, _| Ok(()))
                .unwrap();
            if stop == 2 {
                // Simulate cache rename followed by process loss before journal removal.
                let value = wire::decode_state(disk.pending.as_ref().unwrap()).unwrap();
                let bytes = value.array(7).unwrap()[6].bytes().unwrap();
                files::atomic_at(&disk.directory, OsStr::new(FILE), bytes, true).unwrap();
            }
        }
        let descriptor = store.descriptor().clone();
        drop(disk);
        drop(store);
        let store = Store::open(&requester.0, descriptor).unwrap();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        disk.recover(&store).unwrap();
        disk.check(&store).unwrap();
        assert!(!path.join(transaction::FILE).exists());
        if stop == 0 {
            assert_eq!(std::fs::read(path.join(FILE)).unwrap(), old);
            assert!(disk.snapshot.state.records.is_empty());
            assert!(disk.snapshot.spent.contains_key(&[3; 32]));
        } else {
            assert_eq!(
                disk.snapshot.state.records[&record.reference.index()].bytes,
                record.bytes
            );
            assert!(!disk.snapshot.spent.contains_key(&[3; 32]));
        }
        assert!(disk.consume([4; 32], wall + 100, wall + 120000).is_err());
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn route_cache_failed_replace_retains_forward_recovery_and_spent_entries() {
    use crate::authority_floor::tests::{certified, prepare, setup};
    let (_requester, sample, mut session, mut store) = setup();
    let scope = store.descriptor().scope().clone();
    let path = directory();
    let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
    let wall = store.cache_wall_floor().unwrap();
    disk.consume([4; 32], wall, wall + 120000).unwrap();
    // Expired replay pruning changes the cache even when this result has no domain records.
    disk.snapshot.spent.insert([3; 32], wall);
    disk.save().unwrap();
    let (pending, operation) = prepare(&mut store, sample);
    let verified = certified(
        &store,
        &mut session,
        sample,
        pending.signed(),
        &operation,
        None,
    );
    disk.stage(disk.snapshot.state.clone(), vec![], &store)
        .unwrap();
    let permit = store.accept(verified, &mut session, sample, 0).unwrap();
    let saved = path.join("Old.cbor");
    std::fs::rename(path.join(FILE), &saved).unwrap();
    std::fs::create_dir(path.join(FILE)).unwrap();
    assert!(
        permit
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, store| disk.recover(store)
            )
            .is_err()
    );
    assert!(path.join(transaction::FILE).is_file());
    std::fs::remove_dir(path.join(FILE)).unwrap();
    std::fs::rename(&saved, path.join(FILE)).unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
    disk.recover(&store).unwrap();
    assert!(disk.consume([4; 32], wall + 100, wall + 120000).is_err());
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn route_cache_recovery_refuses_unlearned_bytes_and_replay_deletion() {
    use crate::authority_floor::tests::{read::Read, setup};
    for tamper in 0..3 {
        let (_requester, sample, mut session, mut store) = setup();
        let scope = store.descriptor().scope().clone();
        let path = directory();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        let wall = store.cache_wall_floor().unwrap();
        disk.consume([4; 32], wall, wall + 120000).unwrap();
        let before = std::fs::read(path.join(FILE)).unwrap();
        let record = usage(&disk.snapshot.state, 1);
        let mut next = disk.snapshot.state.clone();
        next.records
            .insert(record.reference.index(), record.clone());
        disk.stage(next, vec![], &store).unwrap();
        let versions = if tamper == 0 {
            vec![]
        } else {
            vec![record.reference]
        };
        let query = Read::with_versions(&store, &mut session, sample, versions);
        let verified = query.verify(&store);
        store
            .accept_read(verified, &mut session, sample, 0, |_, _| Ok(()))
            .unwrap();
        if tamper > 0 {
            let mut value = wire::decode_state(disk.pending.as_ref().unwrap()).unwrap();
            let V::Array(f) = &mut value else {
                unreachable!()
            };
            if tamper == 1 {
                let mut candidate =
                    Snapshot::decode(f[6].bytes().unwrap(), scope.network, scope.incarnation)
                        .unwrap();
                candidate.spent.clear();
                f[6] = V::Bytes(candidate.encode(2).unwrap());
            } else {
                f[5] = V::Uint(wall + 120001);
            }
            let bytes = wire::encode_state(&value).unwrap();
            files::atomic_at(&disk.directory, OsStr::new(transaction::FILE), &bytes, true).unwrap();
        }
        drop(disk);
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        assert!(disk.recover(&store).is_err());
        assert_eq!(std::fs::read(path.join(FILE)).unwrap(), before);
        assert!(path.join(transaction::FILE).is_file());
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
}

fn repair_result(records: &[domains::Record]) -> crate::authority_proof::OperationResult {
    let value = wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        V::Array(
            records
                .iter()
                .map(|r| crate::authority_membership::reference(&r.reference))
                .collect(),
        ),
        V::Array(vec![
            V::Text("RouteLookup".into()),
            V::Array(records.iter().map(|r| V::Bytes(r.bytes.clone())).collect()),
            V::Array(vec![]),
            V::Array(vec![]),
        ]),
    ]))
    .unwrap();
    crate::authority_proof::OperationResult::parse(
        &wire::encode(&V::Array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text("AuthorityDomain".into()),
            V::Uint(0),
            V::Uint(0),
            V::Bytes(value),
        ]))
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn legacy_cache_repair_requires_exact_forward_bytes_and_preserves_live_replays() {
    let path = directory();
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    let first = usage(&disk.snapshot.state, 1);
    disk.snapshot
        .state
        .records
        .insert(first.reference.index(), first.clone());
    disk.snapshot.spent.insert([3; 32], 10);
    disk.snapshot.spent.insert([4; 32], 120000);
    let next = usage(&disk.snapshot.state, 2);
    let result = repair_result(std::slice::from_ref(&next));
    let candidate = disk
        .snapshot
        .repaired(&result, std::slice::from_ref(&next.reference), 10)
        .unwrap();
    assert_eq!(
        candidate.state.records[&first.reference.index()].bytes,
        next.bytes
    );
    assert_eq!(candidate.spent.len(), 1);
    assert_eq!(candidate.spent[&[4; 32]], 120000);
    assert_eq!(candidate.state.keys, disk.snapshot.state.keys);
    assert!(
        disk.snapshot
            .repaired(
                &repair_result(std::slice::from_ref(&first)),
                std::slice::from_ref(&next.reference),
                10
            )
            .is_err()
    );
    let mut conflict = next.reference.clone();
    conflict.digest = [99; 32];
    assert!(disk.snapshot.repaired(&result, &[conflict], 10).is_err());
    assert!(
        candidate
            .repaired(
                &repair_result(std::slice::from_ref(&first)),
                &[first.reference],
                10
            )
            .is_err()
    );
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn stopped_cache_repair_uses_retained_certificate_and_keeps_private_backup() {
    use crate::authority_floor::tests::{certified, prepare_domain, setup};
    for corrupt_body in [false, true] {
        let (_requester, sample, mut session, mut store) = setup();
        let scope = store.descriptor().scope().clone();
        let path = directory();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        let first = usage(&disk.snapshot.state, 1);
        disk.snapshot
            .state
            .records
            .insert(first.reference.index(), first.clone());
        let wall = store.cache_wall_floor().unwrap();
        disk.consume([4; 32], wall, wall + 120000).unwrap();
        let prior = std::fs::read(path.join(FILE)).unwrap();
        let next = usage(&disk.snapshot.state, 2);
        let result = repair_result(std::slice::from_ref(&next));
        let operation = wire::encode(&V::Array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text(result.action),
            V::Uint(0),
            V::Uint(0),
            V::Bytes(result.value),
        ]))
        .unwrap();
        let pending = prepare_domain(&mut store, sample);
        let verified = certified(
            &store,
            &mut session,
            sample,
            pending.signed(),
            &operation,
            None,
        );
        store
            .accept(verified, &mut session, sample, 0)
            .unwrap()
            .perform(
                &mut store,
                &mut session,
                sample,
                1,
                |_| Ok(()),
                |_, _| Ok(()),
            )
            .unwrap();
        // Emulate a pre-journal cache publication lost after the authentic original body was saved.
        if corrupt_body {
            let body = _requester.0.join("AuthorityBody.cbor");
            let bytes = std::fs::read(&body).unwrap();
            let mut altered = bytes.clone();
            let last = altered.len() - 1;
            altered[last] ^= 1;
            std::fs::write(&body, altered).unwrap();
            assert!(disk.repair(&store).is_err());
            assert_eq!(std::fs::read(path.join(FILE)).unwrap(), prior);
            assert!(!path.join("RouteState.before-repair.cbor").exists());
            std::fs::write(&body, bytes).unwrap();
        }
        let report = disk.inspect(&store).unwrap();
        assert_eq!(report["staleRecords"], 1);
        assert_eq!(report["retainedBodyRepairAvailable"], true);
        assert_eq!(std::fs::read(path.join(FILE)).unwrap(), prior);
        let checkpoint = store.cache_checkpoint().unwrap();
        disk.repair(&store).unwrap();
        assert_eq!(store.cache_checkpoint().unwrap(), checkpoint);
        assert_eq!(
            std::fs::read(path.join("RouteState.before-repair.cbor")).unwrap(),
            prior
        );
        assert_eq!(
            std::fs::metadata(path.join("RouteState.before-repair.cbor"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            disk.snapshot.state.records[&next.reference.index()].bytes,
            next.bytes
        );
        disk.repair(&store).unwrap();
        assert!(disk.consume([4; 32], wall + 100, wall + 120000).is_err());
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn reader_storage_pressure_keeps_metadata_publication_reserve() {
    use crate::authority_floor::tests::{read::Read, setup};
    let (_requester, sample, mut session, mut store) = setup();
    let scope = store.descriptor().scope().clone();
    let path = directory();
    let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
    let wall = store.cache_wall_floor().unwrap();
    // Fill the reader allowance directly; the next durable reader must refuse.
    disk.snapshot.spent = (0..1400).map(|i| (connection(i), wall + 120000)).collect();
    disk.save().unwrap();
    let saved = std::fs::read(path.join(FILE)).unwrap();
    assert!(
        disk.consume(connection(1500), wall, wall + 120000)
            .unwrap_err()
            .to_string()
            .contains("metadata reserve")
    );
    assert_eq!(std::fs::read(path.join(FILE)).unwrap(), saved);
    assert_eq!(disk.snapshot.spent.len(), 1400);
    assert!(!disk.snapshot.spent.contains_key(&connection(1500)));
    // Maintenance remains available in the same process after reader capacity refusal.
    let record = usage(&disk.snapshot.state, 1);
    let mut next = disk.snapshot.state.clone();
    next.records
        .insert(record.reference.index(), record.clone());
    disk.stage(next, vec![], &store).unwrap();
    let read = Read::with_versions(&store, &mut session, sample, vec![record.reference]);
    store
        .accept_read(read.verify(&store), &mut session, sample, 0, |_, store| {
            disk.recover(store)
        })
        .unwrap();
    assert_eq!(disk.snapshot.spent.len(), 1400);
    assert!(
        disk.consume(connection(0), wall + 1, wall + 120000)
            .is_err()
    );
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn ordinary_domain_candidate_recovers_after_floor_before_body_or_cache() {
    use crate::authority_floor::tests::{certified, prepare_domain, setup};
    for save_body in [false, true] {
        let (requester, sample, mut session, mut store) = setup();
        let scope = store.descriptor().scope().clone();
        let path = directory();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        let wall = store.cache_wall_floor().unwrap();
        disk.consume([4; 32], wall, wall + 120000).unwrap();
        let record = usage(&disk.snapshot.state, 1);
        let result = repair_result(std::slice::from_ref(&record));
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text(result.action),
            V::Uint(0),
            V::Uint(0),
            V::Bytes(result.value),
        ]))
        .unwrap();
        let pending = prepare_domain(&mut store, sample);
        let verified = certified(&store, &mut session, sample, pending.signed(), &bytes, None);
        let mut next = disk.snapshot.state.clone();
        next.records
            .insert(record.reference.index(), record.clone());
        disk.stage(next, vec![], &store).unwrap();
        let permit = store.accept(verified, &mut session, sample, 0).unwrap();
        if save_body {
            permit
                .perform(
                    &mut store,
                    &mut session,
                    sample,
                    1,
                    |_| Ok(()),
                    |_, _| Ok(()),
                )
                .unwrap();
        }
        let checkpoint = store.cache_checkpoint().unwrap();
        let descriptor = store.descriptor().clone();
        drop(disk);
        drop(store);
        let store = Store::open(&requester.0, descriptor).unwrap();
        let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
        disk.recover(&store).unwrap();
        assert_eq!(store.cache_checkpoint().unwrap(), checkpoint);
        assert_eq!(
            disk.snapshot.state.records[&record.reference.index()].bytes,
            record.bytes
        );
        assert!(disk.consume([4; 32], wall + 1, wall + 120000).is_err());
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[test]
fn unchanged_certified_cache_does_not_write_a_publication_journal() {
    use crate::authority_floor::tests::setup;
    let (_requester, _sample, _session, store) = setup();
    let scope = store.descriptor().scope().clone();
    let path = directory();
    let mut disk = Disk::open(&path, scope.network, scope.incarnation, 65536).unwrap();
    let inode = std::fs::metadata(path.join(FILE)).unwrap().ino();
    disk.stage(
        disk.snapshot.state.clone(),
        disk.snapshot.records.clone(),
        &store,
    )
    .unwrap();
    assert!(disk.pending.is_none());
    assert!(!path.join(transaction::FILE).exists());
    assert_eq!(std::fs::metadata(path.join(FILE)).unwrap().ino(), inode);
    disk.check(&store).unwrap();
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}
