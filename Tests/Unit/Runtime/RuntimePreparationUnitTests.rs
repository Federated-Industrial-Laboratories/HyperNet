// SPDX-License-Identifier: MIT
// Unit tests for RuntimePreparation.
use super::*;
#[test]
fn preparation_publish_resumes_exact_inode_without_replacing_data() {
    let root = std::env::temp_dir().join(format!("HyperNetPreparation{}", random_id()));
    directory(&root).unwrap();
    let pending = root.join("LaunchPending");
    directory(&pending).unwrap();
    create(&pending.join("Retained"), b"retained authority data").unwrap();
    let metadata = fs::symlink_metadata(&pending).unwrap();
    let preparation = Preparation {
        configuration: "digest".into(),
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
    };
    publish_preparation(&root, &preparation).unwrap();
    publish_preparation(&root, &preparation).unwrap();
    assert_eq!(
        read(&root.join("Launch/Retained"), 64).unwrap(),
        b"retained authority data"
    );
    fs::rename(root.join("Launch"), root.join("Saved")).unwrap();
    directory(&root.join("Launch")).unwrap();
    assert!(publish_preparation(&root, &preparation).is_err());
    assert_eq!(
        read(&root.join("Saved/Retained"), 64).unwrap(),
        b"retained authority data"
    );
    fs::remove_dir_all(root).unwrap();
}
