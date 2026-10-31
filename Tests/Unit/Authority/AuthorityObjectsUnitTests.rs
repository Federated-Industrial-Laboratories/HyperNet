// SPDX-License-Identifier: MIT
// Unit tests for AuthorityObjects.
use super::*;

#[test]
fn staged_inputs_bind_raw_digest_length_and_class() {
    let bytes = b"@HyperNetPage/2\nA page";
    let source = Reference::for_bytes(Class::PageSource, bytes).unwrap();
    assert_eq!(
        source.content_sha256(),
        <Digest>::from(Sha256::digest(bytes))
    );
    assert_ne!(source.content_sha256(), wire::digest(bytes));
    assert!(source.verify(&bytes[..bytes.len() - 1]).is_err());
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    assert!(source.verify(&changed).is_err());
    let bundle = Reference::for_bytes(Class::PageBundle, bytes).unwrap();
    assert_ne!(source.identity(), bundle.identity());
    let substitution = Object::verify(bundle, bytes.to_vec()).unwrap();
    assert!(Resolved::exact(&[source], vec![substitution]).is_err());
    assert!(Reference::for_bytes(Class::PageSource, &vec![0; PAGE_SOURCE_BYTES + 1]).is_err());
    assert!(Reference::for_bytes(Class::PageBundle, &[]).is_err());
}

#[test]
fn evaluation_inputs_require_the_exact_declared_closure() {
    let first = Object::verify(
        Reference::for_bytes(Class::PageSource, b"first").unwrap(),
        b"first".to_vec(),
    )
    .unwrap();
    let second = Object::verify(
        Reference::for_bytes(Class::PageSource, b"second").unwrap(),
        b"second".to_vec(),
    )
    .unwrap();
    assert!(validate_required(std::slice::from_ref(&first.reference), &[], &[]).is_err());
    validate_required(
        std::slice::from_ref(&first.reference),
        std::slice::from_ref(&first.reference),
        &[],
    )
    .unwrap();
    validate_required(
        std::slice::from_ref(&second.reference),
        &[],
        std::slice::from_ref(&second.reference),
    )
    .unwrap();
    assert!(Resolved::exact(std::slice::from_ref(&first.reference), vec![second.clone()]).is_err());
    let exact =
        Resolved::exact(std::slice::from_ref(&first.reference), vec![first.clone()]).unwrap();
    assert!(exact.get(&second.reference).is_err());
    let value = exact.value();
    let decoded = Resolved::parse(std::slice::from_ref(&first.reference), &value).unwrap();
    assert_eq!(decoded.get(&first.reference).unwrap(), b"first");
    assert!(Resolved::parse(&[], &value).is_err());
    let mut references = vec![first.reference.clone(), second.reference.clone()];
    references.sort();
    assert!(Resolved::exact(&references, vec![first.clone(), first]).is_err());
}

#[test]
fn epoch_index_requires_the_full_exact_terminal_closure() {
    let state = wire::encode(&V::Array(vec![V::Uint(1)])).unwrap();
    let reference = Reference::for_bytes(Class::PageSource, b"pending page").unwrap();
    let index = EpochIndex::new(&state, std::slice::from_ref(&reference)).unwrap();
    let parsed = EpochIndex::parse(&index.canonical().unwrap()).unwrap();
    parsed
        .verify(&state, std::slice::from_ref(&reference))
        .unwrap();
    assert!(parsed.verify(&state, &[]).is_err());
    assert!(
        parsed
            .verify(
                &wire::encode(&V::Array(vec![V::Uint(2)])).unwrap(),
                &[reference]
            )
            .is_err()
    );
    assert!(
        EpochIndex::new(&state, &[])
            .unwrap()
            .verify(&state, parsed.references())
            .is_err()
    );
}
