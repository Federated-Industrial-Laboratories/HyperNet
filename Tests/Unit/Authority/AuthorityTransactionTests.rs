// SPDX-License-Identifier: MIT
use super::{
    tests::{Fixture, result_bytes},
    *,
};
use crate::authority_governance::Requirement;

fn result_code(result: &Execution) -> u64 {
    wire::decode(result_bytes(result))
        .unwrap()
        .array(6)
        .unwrap()[4]
        .uint()
        .unwrap()
}
fn intent(
    f: &Fixture,
    sequence: u8,
    action: &str,
    target: ([u8; 32], u64, u64),
    expected: &[VersionRef],
    parameters: V,
) -> Vec<u8> {
    let (resource, revision, height) = target;
    wire::sign_envelope(
        &wire::encode(&array(vec![
            V::Uint(20),
            V::Uint(1),
            b(&f.app.config.scope.network),
            b(&f.app.config.scope.incarnation),
            V::Uint(1),
            b(&streams::initial_id(
                f.app.config.scope.network,
                f.app.config.scope.incarnation,
                f.requester.verifying_key().to_bytes(),
            )
            .unwrap()),
            V::Uint(u64::from(sequence)),
            V::Uint(u64::from(sequence) - 1),
            b(&f.requester.verifying_key().to_bytes()),
            V::Text(action.into()),
            b(&resource),
            V::Uint(revision),
            V::Uint(0),
            V::Uint(f.app.config.scope.epoch),
            V::Uint(height),
            array(expected.iter().map(reference).collect()),
            b(&wire::encode(&parameters).unwrap()),
        ]))
        .unwrap(),
        &f.requester,
    )
    .unwrap()
}
fn point(f: &Fixture, prior: &[u8]) -> V {
    let state = State::parse(&f.app.config, prior).unwrap();
    array(vec![
        V::Uint(f.app.config.scope.epoch),
        V::Uint(state.height),
        b(&wire::digest(prior)),
    ])
}
fn context(f: &Fixture, prior: &[u8], _minimum: &[VersionRef], operation: u8) -> Vec<u8> {
    context_cursor(f, prior, operation, V::Null)
}
fn context_cursor(f: &Fixture, prior: &[u8], operation: u8, cursor: V) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    intent(
        f,
        operation,
        "AuthorityContext",
        (f.app.config.scope.network, 0, state.height),
        &[],
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityContext".into()),
            b(&f.grant),
            point(f, prior),
            cursor,
        ]),
    )
}
fn page(result: &Execution) -> V {
    let outer = wire::decode(result_bytes(result)).unwrap();
    wire::decode(outer.array(6).unwrap()[5].bytes().unwrap()).unwrap()
}
#[test]
fn context_cursor_refuses_a_changed_view_and_rechecks_authority() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let prior = f.initial.clone();
    let request = context_cursor(&f, &prior, 1, V::Null);
    let first = f
        .app
        .execute(
            &prior,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let value = page(&first);
    let body = value.array(5).unwrap()[4].array(5).unwrap();
    let cursor = array(vec![body[0].clone(), body[1].clone(), V::Uint(1)]);
    let revoked = f
        .app
        .execute(
            &first.state,
            &f.committed(&revoke(&f, &first.state, [92; 32], 2), 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    let next = context_cursor(&f, &revoked.state, 3, cursor);
    let refused = f
        .app
        .execute(
            &revoked.state,
            &f.committed(&next, 3500, 5000, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&refused), 12);
    assert_eq!(page(&refused).array(4).unwrap()[3], array(vec![]));
}
pub(super) fn revoke(f: &Fixture, prior: &[u8], target_id: [u8; 32], operation: u8) -> Vec<u8> {
    let state = State::parse(&f.app.config, prior).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    let target = governance
        .versions()
        .into_iter()
        .find(|v| v.kind == 102 && v.id == target_id)
        .unwrap();
    let mut dependencies = governance
        .current_capability(
            f.grant,
            &Requirement {
                subject: f.requester.verifying_key().to_bytes(),
                actions: &[12],
                scope: (0, f.app.config.scope.network),
                namespace: None,
                usage: [0, 1, 0, 1],
                evaluated_at_ms: 5000,
                expected: &[],
            },
        )
        .unwrap()
        .dependencies;
    dependencies.push(target.clone());
    dependencies.sort_by_key(VersionRef::index);
    dependencies.dedup();
    let snapshot = array(vec![
        point(f, prior),
        array(dependencies.iter().map(reference).collect()),
    ]);
    intent(
        f,
        operation,
        "AuthorityRevokeGrant",
        (target.id, target.generation, state.height),
        &dependencies,
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityRevokeGrant".into()),
            b(&f.grant),
            reference(&target),
            snapshot,
        ]),
    )
}
fn extra_grant(f: &Fixture) -> (Vec<u8>, [u8; 32]) {
    // The target is a separately authenticated genesis administrator's root.
    (f.initial.clone(), [92; 32])
}
#[test]
fn exact_revoke_is_atomic_and_an_existing_tombstone_never_reactivates() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let (prior, target) = extra_grant(&f);
    let request = revoke(&f, &prior, target, 1);
    let committed = f.committed(&request, 3500, 5000, 1);
    let result = f
        .app
        .execute(
            &prior,
            &committed,
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&result), 0);
    let state = State::parse(&f.app.config, &result.state).unwrap();
    let governance = Governance::parse(
        f.app.config.scope.network,
        f.app.config.scope.incarnation,
        &state.records,
    )
    .unwrap();
    assert!(governance.revoked_chain(target).unwrap());
    assert!(!governance.revoked_chain(f.grant).unwrap());
    assert_eq!(
        state
            .streams
            .metadata(&f.requester.verifying_key().to_bytes())
            .unwrap()
            .unwrap()
            .completion
            .unwrap()
            .sequence,
        1
    );
    let replay = f
        .app
        .execute(
            &result.state,
            &f.committed(&request, 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&replay), 0);
    assert_eq!(result_bytes(&result), result_bytes(&replay));
    let state2 = State::parse(&f.app.config, &replay.state).unwrap();
    assert_eq!(state.records, state2.records);
    assert_eq!(state.streams.value(), state2.streams.value());
    let request2 = revoke(&f, &replay.state, target, 2);
    let denied = f
        .app
        .execute(
            &replay.state,
            &f.committed(&request2, 3500, 5000, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&denied), 6);
    assert_eq!(
        State::parse(&f.app.config, &denied.state).unwrap().records,
        state.records
    );
}
#[test]
fn revocation_floor_allows_unrelated_discovery_and_replays_exactly() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let (prior, target) = extra_grant(&f);
    let request = revoke(&f, &prior, target, 2);
    let discovery = context(&f, &prior, &f.expected, 1);
    let advanced = f
        .app
        .execute(
            &prior,
            &f.committed(&discovery, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&advanced), 0);
    let applied = f
        .app
        .execute(
            &advanced.state,
            &f.committed(&request, 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&applied), 0);
    let original_records = State::parse(&f.app.config, &prior).unwrap().records;
    assert_eq!(
        State::parse(&f.app.config, &applied.state)
            .unwrap()
            .records
            .len(),
        original_records.len() + 1
    );
    let replayed =
        super::membership_tests::execute(&f, &applied.state, &request, &f.requester, 6000);
    assert_eq!(result_code(&replayed), 0);
    assert_eq!(result_bytes(&applied), result_bytes(&replayed));
    f.app.validate_checkpoint(&replayed.state, 3).unwrap();
}
#[test]
fn discovery_returns_current_tombstones_but_never_relabels_a_cached_result() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let (prior, target) = extra_grant(&f);
    let request = context(&f, &prior, &f.expected, 1);
    let discovery = f
        .app
        .execute(
            &prior,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&discovery), 0);
    let revocation = revoke(&f, &discovery.state, target, 2);
    let revoked = f
        .app
        .execute(
            &discovery.state,
            &f.committed(&revocation, 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&revoked), 0);
    let replay = f
        .app
        .execute(
            &revoked.state,
            &f.committed(&request, 3500, 5000, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&replay), 21);
    let fresh = context(&f, &prior, &f.expected, 3);
    let refreshed = f
        .app
        .execute(
            &replay.state,
            &f.committed(&fresh, 3500, 5000, 4),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&refreshed), 0);
    let result = wire::decode(result_bytes(&refreshed)).unwrap();
    let value = wire::decode(result.array(6).unwrap()[5].bytes().unwrap()).unwrap();
    assert!(
        value.array(5).unwrap()[3]
            .list(512)
            .unwrap()
            .iter()
            .any(|r| r.array(4).unwrap()[0] == V::Uint(126))
    );
}
#[test]
fn self_revocation_succeeds_once_then_denies_discovery() {
    let f = Fixture::with_extra_administrator(1000, vec![12, 25]);
    let request = revoke(&f, &f.initial, f.grant, 1);
    let revoked = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&revoked), 0);
    let fresh = context(&f, &revoked.state, &f.expected, 2);
    let denied = f
        .app
        .execute(
            &revoked.state,
            &f.committed(&fresh, 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&denied), 6);
    let replay = f
        .app
        .execute(
            &denied.state,
            &f.committed(&request, 3500, 5000, 3),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&replay), 6);
}

#[test]
fn receipt_reservation_precedes_revocation_and_preserves_original_completion_metadata() {
    let f = Fixture::with_receipt_capacity_administrators(1000, vec![12, 25]);
    let (prior, target) = extra_grant(&f);
    let prior = super::stream_tests::saturated(&f, &prior);
    let request = revoke(&f, &prior, target, 1);
    let denied = f
        .app
        .execute(
            &prior,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&denied), 2);
    assert_eq!(
        State::parse(&f.app.config, &prior).unwrap().records,
        State::parse(&f.app.config, &denied.state).unwrap().records
    );

    let request = revoke(&f, &f.initial, f.grant, 1);
    let revoked = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&revoked), 0);
    let before = State::parse(&f.app.config, &revoked.state).unwrap();
    let replay = f
        .app
        .execute(
            &revoked.state,
            &f.committed(&request, 3500, 5000, 2),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&replay), 6);
    let after = State::parse(&f.app.config, &replay.state).unwrap();
    assert_eq!(before.streams.value(), after.streams.value());
    let completion = after
        .streams
        .metadata(&f.requester.verifying_key().to_bytes())
        .unwrap()
        .unwrap()
        .completion
        .unwrap();
    assert_eq!(
        completion.result_digest,
        wire::digest(result_bytes(&revoked))
    );
    assert_eq!(completion.reason, 0);
}

#[test]
fn policy_discovery_exposes_only_the_network_contract_without_admin_inspection() {
    let f = Fixture::with_extra_administrator(1000, vec![0]);
    let request = intent(
        &f,
        1,
        "AuthorityPolicyContext",
        (f.app.config.scope.network, 0, 0),
        &[],
        array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityPolicyContext".into()),
            b(&f.app.config.scope.network),
        ]),
    );
    let result = f
        .app
        .execute(
            &f.initial,
            &f.committed(&request, 3500, 5000, 1),
            &crate::authority_objects::Resolved::default(),
        )
        .unwrap();
    assert_eq!(result_code(&result), 0);
    let v = page(&result);
    let f = v.array(5).unwrap();
    assert_eq!(f[2].text().unwrap(), "AuthorityPolicyContext");
    let records = f[4].array(2).unwrap();
    assert_eq!(
        wire::decode(records[0].bytes().unwrap())
            .unwrap()
            .array(17)
            .unwrap()[0],
        V::Uint(100)
    );
    assert_eq!(
        wire::decode(records[1].bytes().unwrap())
            .unwrap()
            .array(13)
            .unwrap()[0],
        V::Uint(114)
    );
    assert_eq!(f[3].array(2).unwrap().len(), 2);
}
