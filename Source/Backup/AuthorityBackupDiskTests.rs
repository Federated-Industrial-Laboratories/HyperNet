// SPDX-License-Identifier: MIT
// Cold custody survives interruption and refuses moved destinations and expired archives.
use super::*;
use crate::authority_domains::backup::tests::{archive, profile};
use std::os::unix::fs::PermissionsExt;
#[test]
fn cold_archive_import_reopens_without_serving_and_expiry_removes_bytes() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("BackupStore{}", crate::random_hex::<16>()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let p = profile();
    let path = Disk::initialise(&root, &p, p.bytes).unwrap();
    let data = b"age-encryption.org/v1\nCiphertext";
    let a = archive(&p, data);
    let package = Package {
        profile: p.clone(),
        archive: a.clone(),
        ciphertext: data.to_vec(),
    }
    .encode()
    .unwrap();
    {
        let mut d = Disk::open(&root, p.id, &p.manifest, 10000).unwrap();
        d.import(&package, 10000).unwrap();
        assert_eq!(d.export(a.id, 10000).unwrap(), package);
        d.import(&package, 10000).unwrap();
    }
    {
        let mut d = Disk::open(&root, p.id, &p.manifest, 15000).unwrap();
        assert_eq!(d.export(a.id, 15000).unwrap(), package);
        assert!(d.export(a.id, 20000).is_err());
        assert!(d.import(&package, 20000).is_err());
    }
    assert!(
        !path
            .join(format!("Archive{}.cbor", hex::encode_upper(a.id)))
            .exists()
    );
    assert!(!path.join("ContentMetadata.cbor").exists());
    let moved = root.join("Moved");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(moved.join("Catalogue.json"), path.join("Catalogue.json")).unwrap();
    assert!(Disk::open(&root, p.id, &p.manifest, 20000).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
