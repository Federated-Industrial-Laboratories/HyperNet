// SPDX-License-Identifier: MIT
// Unit tests for ConsensusArchive.
use super::*;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "HyperNetHistory{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        directory(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn indexed_segments_preserve_old_floor_proofs_beyond_legacy_capacity() {
    let dir = Directory::new();
    let configuration = [7; 32];
    let mut a = Archive::open(&dir.0, configuration, 0, empty_root()).unwrap();
    let mut leaves = Vec::new();
    for start in (0..131073usize).step_by(512) {
        let values = (start..(start + 512).min(131073))
            .map(|n| Sha256::digest((n as u64).to_be_bytes()).into())
            .collect::<Vec<Digest>>();
        a.append(a.len() as u64, a.tree_root(), &values).unwrap();
        leaves.extend(values);
    }
    assert!(a.frontier.len() <= 18);
    assert_eq!(a.tree_root(), root(&leaves));
    for size in [4095, 4096, 4097, 8193, 131073] {
        assert_eq!(a.root_at(size).unwrap(), root(&leaves[..size]));
        for old in [1, 31, 2048, size] {
            assert_eq!(
                consistency_at(&a, size, old).unwrap(),
                consistency(&leaves[..size], old).unwrap()
            );
        }
        for index in [0, size / 2, size - 1] {
            assert_eq!(
                inclusion_at(&a, size, index).unwrap(),
                inclusion(&leaves[..size], index).unwrap()
            );
        }
    }
    let expected = a.tree_root();
    drop(a);
    let mut a = Archive::open(&dir.0, configuration, 131073, expected).unwrap();
    let path = inclusion_at(&a, a.len(), 31).unwrap();
    assert!(path.len() <= 64);
    assert_eq!(a.get(31).unwrap(), leaves[31]);
    a.append(131073, expected, &[[99; 32]]).unwrap();
    drop(a);
    let a = Archive::open(&dir.0, configuration, 131073, expected).unwrap();
    assert_eq!(a.len(), 131073);
    let (used, quota) = a.capacity().unwrap();
    assert!(used < quota);
}
#[test]
fn legacy_migration_staging_and_quota_refusal_preserve_committed_prefix() {
    let dir = Directory::new();
    let configuration = [8; 32];
    let values = (0..4100u64)
        .map(|n| Sha256::digest(n.to_be_bytes()).into())
        .collect::<Vec<Digest>>();
    let mut legacy = options()
        .create_new(true)
        .mode(0o600)
        .open(dir.0.join("History.bin"))
        .unwrap();
    legacy.write_all(LEGACY).unwrap();
    legacy.write_all(&configuration).unwrap();
    for value in &values {
        legacy.write_all(value).unwrap();
    }
    legacy.sync_all().unwrap();
    drop(legacy);
    let mut a = Archive::open(&dir.0, configuration, values.len() as u64, root(&values)).unwrap();
    assert_eq!(a.tree_root(), root(&values));
    let mut stage = a.stage().unwrap();
    let path = stage.archive.directory.clone();
    stage
        .archive
        .append(a.len() as u64, a.tree_root(), &[[3; 32]])
        .unwrap();
    a.append_history(&stage.archive).unwrap();
    assert_eq!(a.tree_root(), stage.archive.tree_root());
    drop(stage);
    assert!(!path.exists());
    let size = a.len();
    let expected = a.tree_root();
    a.quota = 0;
    assert!(a.append(size as u64, expected, &[[4; 32]]).is_err());
    assert_eq!(a.len(), size);
    assert_eq!(a.tree_root(), expected);
    drop(a);
    let restored = Archive::open(&dir.0, configuration, size as u64, expected).unwrap();
    assert_eq!(restored.len(), size);
}
