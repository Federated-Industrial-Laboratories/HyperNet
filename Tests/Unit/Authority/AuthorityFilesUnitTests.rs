// SPDX-License-Identifier: MIT
// Unit tests for AuthorityFiles.
use super::*;
use std::os::unix::fs::symlink;
#[test]
fn profile_lock_owner_releases_inherited_description_without_child_unlock() {
    let root = std::env::temp_dir().join(format!("ProfileLock{}", crate::random_hex::<8>()));
    let directory = create_directory(&root).unwrap();
    let name = OsStr::new("Profile");
    let owner = profile_lock(&directory, name).unwrap();
    let inherited = owner.file.try_clone().unwrap();
    assert!(profile_lock(&directory, name).is_err());
    drop(owner);
    let mut resumed = profile_lock(&directory, name).unwrap();
    drop(inherited);
    assert!(profile_lock(&directory, name).is_err());
    let child_description = resumed.file.try_clone().unwrap();
    resumed.owner_pid = 0;
    drop(resumed);
    assert!(profile_lock(&directory, name).is_err());
    drop(child_description);
    drop(profile_lock(&directory, name).unwrap());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn publication_rejects_symlinks_traversal_and_destination_races() {
    let root = std::env::temp_dir().join(format!(
        "HyperNetTransferFiles{}",
        crate::random_hex::<16>()
    ));
    create_directory(&root).unwrap();
    let output = root.join("Output");
    let destination = Destination::open(&output).unwrap();
    write_new(&output, b"existing").unwrap();
    assert!(destination.publish(b"replacement").is_err());
    assert_eq!(read(&output, 64, true).unwrap(), b"existing");
    symlink(&root, root.join("Link")).unwrap();
    assert!(Destination::open(&root.join("Link/Bad")).is_err());
    assert!(read(&root.join("Link/Output"), 64, false).is_err());
    assert!(Destination::open(&root.join("../Escape")).is_err());
    assert!(read(Path::new("/dev/zero"), 64, false).is_err());
    Destination::open(&root.join("Good"))
        .unwrap()
        .publish(b"complete")
        .unwrap();
    assert_eq!(read(&root.join("Good"), 64, true).unwrap(), b"complete");
    std::fs::remove_dir_all(root).unwrap();
}
