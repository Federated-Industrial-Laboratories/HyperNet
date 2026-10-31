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
    disk.publish(disk.state.clone(), disk.records.clone())
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
    disk.publish(disk.state.clone(), disk.records.clone())
        .unwrap();
    assert_eq!(
        consumed.metadata().unwrap().ino(),
        target.metadata().unwrap().ino()
    );
    drop(disk);

    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    disk.publish(disk.state.clone(), disk.records.clone())
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
        disk.publish(disk.state.clone(), disk.records.clone())
            .is_err()
    );
    std::fs::remove_dir(&target).unwrap();
    std::fs::rename(&saved, &target).unwrap();
    disk.publish(disk.state.clone(), disk.records.clone())
        .unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
    assert!(disk.consume([3; 32], 6000, 120000).is_err());
    drop(disk);
    std::fs::remove_dir_all(path).unwrap();
}
