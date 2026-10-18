// SPDX-License-Identifier: MIT
// One current device lease may cover retained native and sealed content without network queries.
use super::*;
#[test]
fn device_owned_search_lease_covers_native_and_sealed_then_denies_revoked_device() {
    let mut f = Fixture::new();
    f.policy();
    assert_eq!(f.stage().code, 0);
    f.copy();
    let outer = f.outer();
    assert_eq!(
        f.run(
            |_| Command::Commit {
                outer: outer.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    let source = b"HyperNetPage/2\n# Native archive\n: Retained with sealed notes.\n";
    let raw = [92; 16];
    let params =
        page::objects::Author::parameters(raw, "Books", source, &f.grant, None, 18000).unwrap();
    let author = page::objects::Author::parse(
        &deployment::signed(
            &deployment::key(5),
            "PageAuthorStatement",
            page::page_id(&raw).unwrap(),
            1,
            wire::decode(&params).unwrap(),
            vec![],
        ),
        [20; 32],
        [21; 32],
    )
    .unwrap();
    assert_eq!(
        f.run(
            |_| page::Command::Submit {
                author: author.clone()
            }
            .into(),
            5
        )
        .code,
        0
    );
    let revision = f
        .state
        .record(141, page::revision_id(author.intent.resource, 1).unwrap())
        .unwrap()
        .reference
        .clone();
    let host = page::Host::parse(
        &f.state.record(147, public(100)).unwrap().payload,
        [20; 32],
        [21; 32],
    )
    .unwrap();
    page::complete_content(
        &mut f.state,
        &f.records,
        &f.reserved,
        &f.grant,
        &host.profile.manifest,
        &revision,
    );
    let params = page::objects::Reviewer::parameters(
        &revision,
        &author.source,
        author.intent.requester,
        author.intent.digest,
        &f.grant,
        None,
        true,
        0,
        None,
        10000,
    )
    .unwrap();
    let review = page::objects::Reviewer::parse(
        &deployment::signed(
            &deployment::key(5),
            "PageReviewStatement",
            author.intent.resource,
            1,
            wire::decode(&params).unwrap(),
            vec![],
        ),
        [20; 32],
        [21; 32],
    )
    .unwrap();
    let bundle = page::objects::Bundle::encode(source, &author.bytes, &review.bytes).unwrap();
    let reference = crate::authority_objects::Reference::for_bytes(
        crate::authority_objects::Class::PageBundle,
        &bundle,
    )
    .unwrap();
    assert_eq!(
        f.run(
            |_| page::Command::Review {
                review: review.clone(),
                bundle: Some(reference.clone())
            }
            .into(),
            5
        )
        .code,
        0
    );
    let native = f.state.record(142, revision.id).unwrap().reference.clone();
    let device = f.state.record(108, [83; 32]).unwrap().reference.clone();
    let items = vec![(outer, Some(device)), (native, None)];
    let result = f.run(
        |_| {
            page::Command::LocalSearchLease {
                items: items.clone(),
            }
            .into()
        },
        73,
    );
    assert_eq!(result.code, 0);
    assert!(result.dependencies.len() <= 64);
    assert_eq!(
        f.run(|_| page::Command::Read { page: raw }.into(), 73).code,
        0
    );
    f.revoke();
    assert_ne!(
        f.run(
            |_| page::Command::LocalSearchLease {
                items: items.clone()
            }
            .into(),
            73
        )
        .code,
        0
    );
    assert_ne!(
        f.run(|_| page::Command::Read { page: raw }.into(), 73).code,
        0
    );
}
