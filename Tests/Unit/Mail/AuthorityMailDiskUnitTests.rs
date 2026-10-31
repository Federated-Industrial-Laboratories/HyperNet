// SPDX-License-Identifier: MIT
// Unit tests for AuthorityMailDisk.
use super::*;
#[test]
fn mail_storage_reopen_retains_ciphertext_deletion_and_clock_floor() {
    let (profile, mailbox, claim, mut command) = mail::tests::storage_fixture();
    let path = std::env::temp_dir().join(format!(
        "HyperNetMailStorage{}{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(path.clone());
    Disk::initialise(&path, &profile).unwrap();
    let mut disk = Disk::open(&path, &profile, 5_000).unwrap();
    let ciphertext = b"retained ciphertext";
    disk.execute(&mailbox, Some(&claim), &command, ciphertext, 5_000, false)
        .unwrap();
    assert!(
        disk.execute(&mailbox, Some(&claim), &command, b"different", 5_001, true)
            .is_err()
    );
    // A torn unpublished bank must not replace the committed ciphertext.
    disk.file
        .write_all_at(b"incomplete", (1 - disk.active) as u64 * disk.bank + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, &profile, 5_010).unwrap();
    if let Command::Execute {
        effect,
        bytes,
        digest,
        claim,
        ..
    } = &mut command
    {
        *effect = Effect::Fetch;
        *bytes = 0;
        *digest = None;
        *claim = None;
    }
    let response = disk
        .execute(&mailbox, Some(&claim), &command, &[], 5_020, false)
        .unwrap();
    assert_eq!(
        wire::decode(&response).unwrap().array(9).unwrap()[8]
            .bytes()
            .unwrap(),
        ciphertext
    );
    drop(disk);
    assert!(Disk::open(&path, &profile, 5_019).is_err());
    let mut disk = Disk::open(&path, &profile, 5_020).unwrap();
    if let Command::Execute { effect, .. } = &mut command {
        *effect = Effect::Delete;
    }
    disk.execute(&mailbox, Some(&claim), &command, &[], 5_030, false)
        .unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, &profile, 5_030).unwrap();
    if let Command::Execute {
        effect,
        bytes,
        digest,
        claim,
        ..
    } = &mut command
    {
        *effect = Effect::Put;
        *bytes = ciphertext.len() as u64;
        *digest = Some(wire::digest(ciphertext));
        *claim = Some([192; 32]);
    }
    assert!(
        disk.execute(&mailbox, Some(&claim), &command, ciphertext, 5_040, true)
            .is_err()
    );
}
