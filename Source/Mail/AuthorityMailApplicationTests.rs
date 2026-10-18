// SPDX-License-Identifier: MIT
// A committed request for an absent service is a retained denial, not an application failure.
use super::*;
use super::{membership_tests as m, tests::Fixture};
use crate::authority_domains::{self as domain, mail};
fn request(f: &Fixture, prior: &[u8]) -> Vec<u8> {
    let command = mail::Command::Execute {
        address: [88; 32],
        service: m::public(&m::key(89)),
        effect: mail::Effect::List,
        message: None,
        claim: None,
        bytes: 0,
        digest: None,
        after: None,
    };
    let op = domain::Operation {
        grant: None,
        command: command.into(),
        snapshot: domain::snapshot(&m::snapshot(f, prior, &[])).unwrap(),
    };
    let request = m::signed(
        f,
        prior,
        &f.requester,
        "AuthorityDomain",
        op.command.resource(),
        wire::decode(&op.parameters().unwrap()).unwrap(),
        vec![],
    );
    let (payload, _) = wire::envelope(&request, 1).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(17).unwrap().to_vec();
    fields[11] = V::Uint(0);
    wire::sign_envelope(&wire::encode(&array(fields)).unwrap(), &f.requester).unwrap()
}
#[test]
fn absent_mail_recipient_commits_refusal_and_preserves_requester_progress() {
    let f = Fixture::with_actions(1000, vec![0, 15, 16, 25]);
    let before = State::parse(&f.app.config, &f.initial).unwrap();
    let recipient = m::key(89);
    let first = request(&f, &f.initial);
    let refused = m::execute(&f, &f.initial, &first, &recipient, 5000);
    assert_eq!(m::code(&refused), 3);
    let state = State::parse(&f.app.config, &refused.state).unwrap();
    assert_eq!(state.records, before.records);
    assert_eq!(state.domains.value(), before.domains.value());
    assert_eq!(state.streams.keys(), before.streams.keys());
    assert_eq!(state.height, 1);
    let completion = state
        .streams
        .metadata(&m::public(&f.requester))
        .unwrap()
        .unwrap()
        .completion
        .unwrap();
    assert_eq!(completion.sequence, 1);
    assert_eq!(completion.reason, 3);
    assert_eq!(
        completion.intent,
        Intent::from_signed(&first).unwrap().digest
    );
    let second = request(&f, &refused.state);
    let second = m::execute(&f, &refused.state, &second, &recipient, 5100);
    assert_eq!(m::code(&second), 3);
    let state = State::parse(&f.app.config, &second.state).unwrap();
    let metadata = state
        .streams
        .metadata(&m::public(&f.requester))
        .unwrap()
        .unwrap();
    assert_eq!(metadata.retired_through, 1);
    assert_eq!(metadata.completion.unwrap().sequence, 2);
    assert_eq!(state.height, 2);
    f.app.validate_checkpoint(&second.state, 2).unwrap();
}
