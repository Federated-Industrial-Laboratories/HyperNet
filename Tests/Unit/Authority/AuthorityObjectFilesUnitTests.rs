// SPDX-License-Identifier: MIT
// Unit tests for AuthorityObjectFiles.
use super::*;
use crate::{
    authority_objects::Class,
    trust_wire::{self as wire, Value as V},
};
use std::os::unix::fs::symlink;

#[test]
fn epoch_directory_rejects_extra_files_symlinks_and_different_bytes() {
    let root = crate::consensus::journal::tests::Directory::new();
    let state = wire::encode(&V::Array(vec![V::Uint(1)])).unwrap();
    let reference = Reference::for_bytes(Class::PageSource, b"exact publication").unwrap();
    let index = EpochIndex::new(&state, std::slice::from_ref(&reference)).unwrap();
    let path = root.0.join("Export");
    let directory =
        Directory::create(&path, &index, |_| Ok(b"exact publication".to_vec())).unwrap();
    directory.validate().unwrap();
    files::write_new(&path.join("Unlisted.bin"), b"unlisted").unwrap();
    assert!(Directory::open(&path, &index).is_err());
    std::fs::remove_file(path.join("Unlisted.bin")).unwrap();
    let body = path.join(reference.file_name());
    std::fs::remove_file(&body).unwrap();
    symlink(path.join(INDEX), &body).unwrap();
    assert!(Directory::open(&path, &index).unwrap().validate().is_err());
    std::fs::remove_file(&body).unwrap();
    files::write_new(&body, b"other publication").unwrap();
    assert!(Directory::open(&path, &index).unwrap().validate().is_err());
}
