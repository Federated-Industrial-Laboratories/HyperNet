// SPDX-License-Identifier: MIT
// Unit tests for AuthorityMailEvaluation.
#[cfg(test)]
#[test]
fn mail_oversized_response_closure_is_a_refusal_without_candidate_state() {
    let mut closure = State::empty([1; 32], [2; 32]);
    closure
        .reserve(
            3,
            crate::authority_deployment_tests::key(75)
                .verifying_key()
                .to_bytes(),
            crate::authority_deployment_tests::key(76)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(vec![]),
        a(vec![
            V::Text("MailClaim".into()),
            a(vec![b(&vec![17; wire::MAXIMUM])]),
            a(vec![]),
            V::Null,
        ]),
    ]);
    let refused = bounded_result(Some(closure), value, vec![], vec![], 10_000);
    assert_eq!(refused.code, 2);
    assert!(refused.state.is_none());
    assert_eq!(refused.value, a(vec![]));
}
