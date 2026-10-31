// SPDX-License-Identifier: MIT
// Unit tests for ConsensusJournal.
use super::*;
pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("S{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn exclusive_restart_torn_state_and_retained_floor() {
    let path = Directory::new();
    let mut writer = Journal::create(&path.0, &vec![1u64]).unwrap();
    assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
    writer.commit(&vec![2u64]).unwrap();
    drop(writer);
    assert!(Journal::open::<Vec<u64>>(&path.0, 3).is_err());
    let (writer, value) = Journal::open::<Vec<u64>>(&path.0, 2).unwrap();
    assert_eq!(value, vec![2]);
    drop(writer);
    OpenOptions::new()
        .write(true)
        .open(path.0.join("Signer.bin"))
        .unwrap()
        .set_len(70)
        .unwrap();
    assert!(Journal::open::<Vec<u64>>(&path.0, 0).is_err());
}
#[test]
fn owner_drop_releases_inherited_description_without_weakening_exclusion() {
    let path = Directory::new();
    let writer = Journal::create(&path.0, &vec![1u64]).unwrap();
    let inherited = writer._lock.try_clone().unwrap();
    assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
    drop(writer);
    let (mut resumed, value) = Journal::open::<Vec<u64>>(&path.0, 1).unwrap();
    assert_eq!(value, vec![1]);
    drop(inherited);
    assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
    let child_description = resumed._lock.try_clone().unwrap();
    resumed.owner_pid = 0;
    assert!(resumed.commit(&vec![2u64]).is_err());
    drop(resumed);
    assert!(Journal::open::<Vec<u64>>(&path.0, 1).is_err());
    drop(child_description);
    assert_eq!(Journal::open::<Vec<u64>>(&path.0, 1).unwrap().1, vec![1]);
}
#[test]
fn failed_sync_path_poisoning_prevents_later_signer_progress() {
    let path = Directory::new();
    let mut writer = Journal::create(&path.0, &vec![1u64]).unwrap();
    std::os::unix::fs::symlink("Signer.bin", path.0.join("SignerPending.bin")).unwrap();
    assert!(writer.commit(&vec![2u64]).is_err());
    fs::remove_file(path.0.join("SignerPending.bin")).unwrap();
    assert!(writer.commit(&vec![3u64]).is_err());
}
