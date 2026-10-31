// SPDX-License-Identifier: MIT
// Unit tests for ConsensusInputs.
use super::super::journal::tests::Directory;
use super::*;
use crate::authority_objects::Class;

#[test]
fn checkpoint_inputs_survive_restart_retirement_and_active_transfer() {
    let directory = Directory::new();
    let store = storage::Store::open(&directory.0, true).unwrap();
    let reference = Reference::for_bytes(Class::PageSource, b"retained publication").unwrap();
    let object = Object::verify(reference.clone(), b"retained publication".to_vec()).unwrap();
    let resolved = Resolved::exact(std::slice::from_ref(&reference), vec![object]).unwrap();
    let mut state = State::default();
    state.stage_command(&store, [1; 32], &resolved).unwrap();
    state
        .set_application(std::slice::from_ref(&reference))
        .unwrap();
    state
        .checkpoint([2; 32], std::slice::from_ref(&reference))
        .unwrap();
    for object in state.objects() {
        store.publish(object).unwrap();
    }
    store.sync().unwrap();
    state.unstage();
    let mut reopened: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    let reopened_store = storage::Store::open(&directory.0, false).unwrap();
    assert_eq!(
        reopened
            .reader(reopened_store.clone())
            .resolve(std::slice::from_ref(&reference))
            .unwrap()
            .get(&reference)
            .unwrap(),
        b"retained publication"
    );
    reopened.set_application(&[]).unwrap();
    reopened.retain(&BTreeSet::new(), &BTreeSet::from([hex::encode([2; 32])]));
    assert_eq!(reopened.objects().count(), 1);
    reopened
        .pin([3; 32], std::slice::from_ref(&reference))
        .unwrap();
    reopened.retain(&BTreeSet::new(), &BTreeSet::new());
    let retained = reopened.objects().map(storage::Object::key).collect();
    reopened_store.collect(&retained).unwrap();
    assert!(
        reopened
            .reader(reopened_store.clone())
            .resolve(std::slice::from_ref(&reference))
            .is_ok()
    );
    reopened.unpin(&[3; 32]);
    reopened.retain(&BTreeSet::new(), &BTreeSet::new());
    reopened_store.collect(&BTreeSet::new()).unwrap();
    assert_eq!(
        std::fs::read_dir(directory.0.join("Objects"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn learned_command_without_input_is_unavailable_until_exact_object_arrives() {
    let directory = Directory::new();
    let store = storage::Store::open(&directory.0, true).unwrap();
    let reference = Reference::for_bytes(Class::PageSource, b"exact body").unwrap();
    let mut state = State::default();
    state
        .bind_command([4; 32], std::slice::from_ref(&reference))
        .unwrap();
    let error = state
        .reader(store.clone())
        .resolve(std::slice::from_ref(&reference))
        .unwrap_err();
    assert!(error.downcast_ref::<inputs::Unavailable>().is_some());
    assert!(
        state
            .set_application(std::slice::from_ref(&reference))
            .is_err()
    );
    assert!(Object::verify(reference.clone(), b"other body".to_vec()).is_err());
    let exact = Object::verify(reference.clone(), b"exact body".to_vec()).unwrap();
    state.insert(&store, &exact).unwrap();
    assert_eq!(
        state
            .reader(store.clone())
            .resolve(std::slice::from_ref(&reference))
            .unwrap()
            .get(&reference)
            .unwrap(),
        b"exact body"
    );
    state.set_application(&[reference]).unwrap();
}
