// SPDX-License-Identifier: MIT
// Unit tests for RuntimeEpochObjects.
use super::*;
use crate::authority_objects::{Class, Reference};

#[test]
fn installed_epoch_objects_copy_exactly_and_reject_another_terminal() {
    let root = crate::consensus::journal::tests::Directory::new();
    let terminal = trust_wire::encode(&trust_wire::Value::Array(vec![trust_wire::Value::Text(
        "ExactTerminalState".into(),
    )]))
    .unwrap();
    let body = b"pending page source";
    let reference = Reference::for_bytes(Class::PageSource, body).unwrap();
    let index = EpochIndex::new(&terminal, std::slice::from_ref(&reference)).unwrap();
    let source = root.0.join("Source");
    Directory::create(&source, &index, |_| Ok(body.to_vec())).unwrap();
    assert!(open(&source, b"another terminal state").is_err());
    let source = open(&source, &terminal).unwrap();
    let output = root.0.join("Output");
    copy(&source, &output).unwrap();
    copy(&source, &output).unwrap();
    assert_eq!(
        open(&output, &terminal).unwrap().read(&reference).unwrap(),
        body
    );
    authority_files::write_new(&output.join("Unlisted.bin"), b"unlisted").unwrap();
    assert!(copy(&source, &output).is_err());
}
