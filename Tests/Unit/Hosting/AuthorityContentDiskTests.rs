// SPDX-License-Identifier: MIT
// Complete-copy acknowledgement, reserved staging and restore reconciliation survive interruption.
use super::*;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
struct Fixture {
    root: PathBuf,
    path: PathBuf,
    limits: Limits,
    key: SigningKey,
    object: Object,
    payload: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("HyperNetContent{}", crate::random_hex::<16>()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("Content");
        let key = SigningKey::from_bytes(&[55; 32]);
        let payload = vec![91; CHUNK_BYTES + 19];
        let limits = Limits {
            network: [1; 32],
            incarnation: [2; 32],
            service: key.verifying_key().to_bytes(),
            profile: [3; 32],
            metadata_bytes: 65536,
            data_bytes: 4 * 1024 * 1024,
            staging_bytes: 2 * 1024 * 1024,
            quarantine_bytes: 1024 * 1024,
            maximum_object_bytes: 1024 * 1024,
            maximum_objects: 128,
            opaque: true,
        };
        let object = Object {
            placement: [4; 32],
            digest: Sha256::digest(&payload).into(),
            bytes: payload.len() as u64,
            expires_ms: 100000,
            opaque: true,
        };
        Disk::initialise(&path, &limits).unwrap();
        Self {
            root,
            path,
            limits,
            key,
            object,
            payload,
        }
    }
    fn open(&self) -> Disk {
        Disk::open(&self.path, &self.limits, 1000).unwrap()
    }
    fn upload(&self, disk: &mut Disk) {
        disk.reserve(&self.object, 1000).unwrap();
        for (offset, chunk) in self.payload.chunks(CHUNK_BYTES).enumerate() {
            disk.write(&self.object, (offset * CHUNK_BYTES) as u64, chunk, 1000)
                .unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn content_acknowledgement_survives_restart_but_serving_requires_reconciliation() {
    let f = Fixture::new();
    let mut disk = f.open();
    disk.reserve(&f.object, 1000).unwrap();
    disk.write(&f.object, 0, &f.payload[..CHUNK_BYTES], 1000)
        .unwrap();
    assert!(
        disk.complete(&f.object, [8; 32], &f.key, 1000, |_| Ok(()))
            .is_err()
    );
    drop(disk);
    let mut disk = f.open();
    assert_eq!(disk.reserve(&f.object, 1000).unwrap(), CHUNK_BYTES as u64);
    assert_eq!(
        disk.write(&f.object, 0, &f.payload[..CHUNK_BYTES], 1000)
            .unwrap(),
        CHUNK_BYTES as u64
    );
    assert!(disk.write(&f.object, 0, &[92; CHUNK_BYTES], 1000).is_err());
    disk.write(
        &f.object,
        CHUNK_BYTES as u64,
        &f.payload[CHUNK_BYTES..],
        1000,
    )
    .unwrap();
    assert!(
        disk.complete(&f.object, [8; 32], &f.key, 1000, |_| anyhow::bail!(
            "format rejected"
        ))
        .is_err()
    );
    let receipt = disk
        .complete(&f.object, [8; 32], &f.key, 1000, |_| Ok(()))
        .unwrap();
    assert!(disk.read(&f.object, 0, 19, 1000).is_err());
    drop(disk);
    let mut disk = f.open();
    assert!(disk.read(&f.object, 0, 19, 1000).is_err());
    assert_eq!(
        disk.complete(&f.object, [8; 32], &f.key, 1000, |_| Ok(()))
            .unwrap(),
        receipt
    );
    disk.reconcile(&f.object, 1000).unwrap();
    assert_eq!(disk.read(&f.object, 0, 19, 1000).unwrap(), f.payload[..19]);
    let file = open_file(&disk.directory, &f.object.name(), false).unwrap();
    file.write_all_at(&[1], 0).unwrap();
    file.sync_all().unwrap();
    assert!(disk.read(&f.object, 0, 19, 1000).is_err());
    assert!(disk.reconcile(&f.object, 1000).is_err());
    assert_eq!(disk.inventory()[0].1, Status::Quarantined);
    assert!(disk.reconcile(&f.object, 1000).is_err());
    disk.purge(f.object.placement, 1000).unwrap();
    assert!(disk.inventory().is_empty());
    assert!(!f.path.join(f.object.name()).exists());
}
#[test]
fn content_staging_reserves_complete_extent_and_rejects_aliases() {
    let mut f = Fixture::new();
    f.limits.staging_bytes = f.object.bytes;
    f.limits.maximum_object_bytes = f.object.bytes;
    let mut disk = f.open();
    disk.reserve(&f.object, 1000).unwrap();
    assert_eq!(
        f.path.join(f.object.name()).metadata().unwrap().len(),
        f.object.bytes
    );
    let mut other = f.object.clone();
    other.placement = [5; 32];
    assert!(disk.reserve(&other, 1000).is_err());
    assert_eq!(disk.inventory().len(), 1);
    disk.purge(f.object.placement, 1000).unwrap();
    disk.reserve(&other, 1000).unwrap();
    drop(disk);
    std::fs::remove_file(f.path.join(other.name())).unwrap();
    symlink(f.path.join("Store.bin"), f.path.join(other.name())).unwrap();
    assert!(Disk::open(&f.path, &f.limits, 1000).is_err());
}
#[test]
fn content_torn_metadata_keeps_prior_progress_and_purge_is_retryable() {
    let f = Fixture::new();
    let mut disk = f.open();
    f.upload(&mut disk);
    let inactive = (1 - disk.active) as u64 * (f.limits.metadata_bytes / 2);
    disk.file
        .write_all_at(b"TornSuccessor", inactive + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = f.open();
    assert_eq!(disk.inventory()[0].2, f.object.bytes);
    disk.complete(&f.object, [8; 32], &f.key, 1000, |_| Ok(()))
        .unwrap();
    let mut next = disk.state.clone();
    next.entries.get_mut(&f.object.placement).unwrap().status = Status::Purging;
    disk.commit(next).unwrap();
    drop(disk);
    let mut disk = f.open();
    assert!(disk.reconcile(&f.object, 1000).is_err());
    disk.purge(f.object.placement, 1000).unwrap();
    disk.purge(f.object.placement, 1000).unwrap();
    drop(disk);
    assert!(f.open().inventory().is_empty());
}
#[test]
fn content_unaccounted_files_and_missing_receipt_never_become_serving() {
    let f = Fixture::new();
    let mut disk = f.open();
    f.upload(&mut disk);
    assert!(disk.reconcile(&f.object, 1000).is_err());
    drop(disk);
    files::write_new(&f.path.join("Unexpected.bin"), b"unaccounted").unwrap();
    assert!(Disk::open(&f.path, &f.limits, 1000).is_err());
}

#[test]
fn content_repair_reserves_staging_before_discarding_corruption() {
    let f = Fixture::new();
    let mut disk = f.open();
    f.upload(&mut disk);
    let old = disk
        .complete(&f.object, [8; 32], &f.key, 1000, |_| Ok(()))
        .unwrap();
    assert_eq!(disk.repair(&f.object, 1000).unwrap(), f.object.bytes);
    let file = open_file(&disk.directory, &f.object.name(), false).unwrap();
    file.write_all_at(&[4], 0).unwrap();
    file.sync_all().unwrap();
    assert_eq!(disk.repair(&f.object, 1000).unwrap(), 0);
    assert!(disk.reconcile(&f.object, 1000).is_err());
    disk.write(&f.object, 0, &f.payload[..CHUNK_BYTES], 1000)
        .unwrap();
    drop(disk);
    let mut disk = f.open();
    assert_eq!(disk.repair(&f.object, 1000).unwrap(), CHUNK_BYTES as u64);
    disk.write(
        &f.object,
        CHUNK_BYTES as u64,
        &f.payload[CHUNK_BYTES..],
        1000,
    )
    .unwrap();
    let repaired = disk
        .complete(&f.object, [9; 32], &f.key, 1001, |_| Ok(()))
        .unwrap();
    assert_ne!(old, repaired);
    disk.reconcile(&f.object, 1001).unwrap();
    assert_eq!(disk.read(&f.object, 0, 19, 1001).unwrap(), f.payload[..19]);
}
