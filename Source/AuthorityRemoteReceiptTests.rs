// SPDX-License-Identifier: MIT
// Durable content reports use the same retained requester completion boundary as media reports.
use super::*;
use crate::{authority_deployment_tests as fixture, authority_domains as domains};
fn reference(kind: u64, seed: u8) -> VersionRef {
    VersionRef {
        kind,
        id: [seed; 32],
        generation: 1,
        digest: [seed + 1; 32],
    }
}
#[test]
fn content_receipt_completion_accepts_exact_effect_and_refuses_metadata_action() {
    let placement = reference(159, 31);
    let host = reference(147, 41);
    let signed = |command: domains::page::Command| {
        let operation = domains::Operation {
            grant: Some(reference(102, 51)),
            command: command.into(),
            snapshot: domains::snapshot(&fixture::snapshot(&[])).unwrap(),
        };
        fixture::signed(
            &fixture::key(5),
            "AuthorityDomain",
            operation.command.resource(),
            u64::from(operation.mutation()),
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            vec![],
        )
    };
    for effect in [
        domains::page::content::Effect::Read,
        domains::page::content::Effect::Upload,
    ] {
        let bytes = signed(domains::page::Command::Content(
            domains::page::content::Command::Authorise {
                placement: placement.clone(),
                host: host.clone(),
                effect,
                offset: 0,
                bytes: 16,
                digest: (effect == domains::page::content::Effect::Upload).then_some([61; 32]),
            },
        ));
        let request = domains::page::MediaRequest::parse(&bytes).unwrap();
        assert_eq!(request.receipt_tag(), "PageContentEffectReceipt");
        media_operation(request.intent()).unwrap();
    }
    let bytes = signed(domains::page::Command::Content(
        domains::page::content::Command::Get { placement },
    ));
    assert!(media_operation(&proof::Intent::from_signed(&bytes).unwrap()).is_err());
    assert!(domains::page::MediaRequest::parse(&bytes).is_err());
}
