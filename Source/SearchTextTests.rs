// SPDX-License-Identifier: MIT
// Search results remain literal, independently reproducible and bound to their exact request.
use super::*;
fn request(terms: &[&str]) -> Request {
    Request {
        network: [1; 32],
        incarnation: [2; 32],
        operation: [3; 32],
        scope: 1,
        terms: terms.iter().map(|s| (*s).into()).collect(),
        combination: 0,
        namespaces: vec![],
        limit: 10,
        cursor: None,
        historical: false,
        snapshot: V::Array(vec![
            V::Array(vec![V::Uint(1), V::Uint(1), bytes(&[4; 32])]),
            V::Array(vec![]),
        ]),
    }
}
const PAGE: &[u8] = b"HyperNetPage/2\n# Botanical Books\n@Tags {\"values\":[\"Gardening\",\"Fiction\"]}\n## Winter reading\n: Plants and stories.\n";
#[test]
fn exact_source_defines_literal_results_and_per_document_ranking() {
    let q = request(&["BOOKS", "Gardening"]);
    let found = matching(&q, PAGE).unwrap().unwrap();
    assert_eq!(found.score, 14);
    assert_eq!(found.title, "Botanical Books");
    assert!(
        matching(&request(&["plants OR stories"]), PAGE)
            .unwrap()
            .is_none()
    );
    let mut any = request(&["absent", "plants"]);
    assert!(matching(&any, PAGE).unwrap().is_none());
    any.combination = 1;
    assert!(matching(&any, PAGE).unwrap().is_some());
    let first = response(&q, PAGE).unwrap();
    assert_eq!(verify_response(&q, &first).unwrap().1, Some(found));
    assert!(verify_response(&request(&["Winter"]), &first).is_err());
    let mut forged = wire::decode(&first).unwrap().array(6).unwrap().to_vec();
    let mut result = forged[5].array(4).unwrap().to_vec();
    result[1] = V::Text("Unapproved injected snippet".into());
    forged[5] = V::Array(result);
    assert!(verify_response(&q, &wire::encode(&V::Array(forged)).unwrap()).is_err());
}
#[test]
fn request_rejects_scope_confusion_and_unbounded_or_control_terms() {
    let q = request(&[]);
    assert!(matching(&q, PAGE).unwrap().is_some());
    assert!(Request::parse(&q.encode().unwrap()).is_ok());
    let mut invalid = q.clone();
    invalid.historical = true;
    assert!(invalid.encode().is_err());
    invalid.scope = 0;
    assert!(invalid.encode().is_ok());
    assert!(invalid.network_scope([1; 32], [2; 32], [3; 32]).is_err());
    for terms in [
        vec!["\u{1b}[2J".to_owned()],
        vec!["a".repeat(129)],
        vec!["BOOK".into(), "book".into()],
        vec!["x".repeat(128); 9],
    ] {
        invalid.terms = terms;
        assert!(invalid.validate().is_err());
    }
}
#[test]
fn snippets_preserve_graphemes_and_remove_terminal_controls() {
    let s = format!("{}\u{1b}[31m\n  end", "e\u{301}".repeat(190));
    let result = snippet(&s);
    assert_eq!(result.graphemes(true).count(), 180);
    assert!(result.ends_with("e\u{301}"));
    assert!(snippet("a\u{1b}b\n\tc").chars().all(safe));
}
