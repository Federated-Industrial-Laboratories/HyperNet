// SPDX-License-Identifier: MIT
// Server search requires explicit indexing consent; local leases carry no query material.
use super::*;
fn publish(f: &mut Fixture, raw: [u8; 16], body: &[u8]) -> (VersionRef, VersionRef) {
    let author = f.author_for(raw, body, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![],
        5000,
    );
    let review = f.reviewer(&author, true, 10000);
    let bundle = objects::Bundle::encode(body, &author.bytes, &review.bytes).unwrap();
    f.apply(
        Command::Review {
            review,
            bundle: Some(Reference::for_bytes(Class::PageBundle, &bundle).unwrap()),
        },
        vec![],
        5000,
    );
    let revision = f
        .state
        .record(141, revision_id(author.intent.resource, 1).unwrap())
        .unwrap()
        .reference
        .clone();
    let publication = f.state.record(142, revision.id).unwrap().reference.clone();
    let placement = f
        .state
        .records
        .values()
        .find(|r| {
            r.reference.kind == 159
                && content::Placement::parse(&r.payload).unwrap().revision == revision
        })
        .unwrap()
        .reference
        .clone();
    (publication, placement)
}
#[test]
fn search_requires_indexing_consent_and_current_exact_publication() {
    for consent in [false, true] {
        let mut f = Fixture::new_search();
        f.search = consent;
        let hosts = f.hosts();
        let body = b"HyperNetPage/2\n# Library\n: The winter catalogue.\n";
        let (_, placement) = publish(&mut f, [71; 16], body);
        let host = f
            .state
            .record(147, hosts[0].service)
            .unwrap()
            .reference
            .clone();
        let command = Command::Content(content::Command::Authorise {
            placement,
            host,
            effect: content::Effect::Search,
            offset: 0,
            bytes: body.len() as u64,
            digest: None,
        });
        assert_eq!(
            f.evaluate(command.clone(), vec![], 5000).2.code == 0,
            consent
        );
        f.apply(
            Command::Withdraw {
                page: [71; 16],
                as_reviewer: false,
            },
            vec![],
            5000,
        );
        assert_ne!(f.evaluate(command, vec![], 5000).2.code, 0);
    }
}
#[test]
fn local_search_lease_checks_every_exact_publication_before_disclosure() {
    let mut f = Fixture::new_search();
    f.search = false;
    f.hosts();
    let first = publish(
        &mut f,
        [71; 16],
        b"HyperNetPage/2\n# First\n: Retained only.\n",
    )
    .0;
    let second = publish(
        &mut f,
        [72; 16],
        b"HyperNetPage/2\n# Second\n: Also retained.\n",
    )
    .0;
    let mut items = vec![(first, None), (second, None)];
    items.sort_by_key(|r| r.0.index());
    let command = Command::LocalSearchLease { items };
    let result = f.evaluate(command.clone(), vec![], 5000).2;
    assert_eq!(result.code, 0);
    assert!(result.dependencies.len() <= 64);
    f.apply(
        Command::Withdraw {
            page: [72; 16],
            as_reviewer: false,
        },
        vec![],
        5000,
    );
    let result = f.evaluate(command, vec![], 5000).2;
    assert_ne!(result.code, 0);
    assert!(result.state.is_none());
}
