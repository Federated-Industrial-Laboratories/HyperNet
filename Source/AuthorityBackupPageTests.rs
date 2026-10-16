// SPDX-License-Identifier: MIT
// A cold copy never grants permission to restore withdrawn content or widen its destination.
use super::*;
use crate::authority_domains::backup;
fn action(f: &mut Fixture, command: backup::Command, at: u64) -> Decision {
    let (mut intent, mut op) =
        f.request_as(Command::Read { page: [71; 16] }, Some(f.grant.clone()), 5);
    op.command = command.into();
    intent.resource = op.command.resource();
    intent.revision = u64::from(op.mutation());
    intent.parameters = op.parameters().unwrap();
    let preview = op
        .prepare(&f.state, &f.records, &f.reserved, &intent, at, false, false)
        .unwrap();
    if preview.code != 0 {
        return preview;
    }
    intent.expected = preview.dependencies;
    op.snapshot = snapshot(&deployment::snapshot(&intent.expected)).unwrap();
    intent.parameters = op.parameters().unwrap();
    let d = op
        .prepare(&f.state, &f.records, &f.reserved, &intent, at, false, true)
        .unwrap();
    if let Some(next) = &d.state {
        f.state = next.clone();
    }
    f.sequence += 1;
    d
}
#[test]
fn current_owner_can_archive_and_restore_but_withdrawal_and_destination_changes_refuse() {
    let mut f = Fixture::new();
    let mut hosts = f.hosts();
    let p = backup::tests::profile();
    let base = deployment::Fixture::with_actions(vec![0, 2, 3, 5, 10, 11, 12, 13, 21, 26]);
    (f.records, _, _, _) = deployment::admitted(&base, &deployment::offer(p.manifest.clone()));
    f.state = State::empty(f.state.network, f.state.incarnation);
    for h in &mut hosts {
        h.manifest = p.manifest.clone();
        h.envelope = wire::sign_envelope(&h.payload().unwrap(), &deployment::key(90)).unwrap();
        f.apply(
            Command::HostRegister {
                profile: Box::new(h.clone()),
            },
            vec![],
            5000,
        );
    }
    assert_eq!(
        action(
            &mut f,
            backup::Command::Register { profile: p.clone() },
            5000
        )
        .code,
        0
    );
    let body = b"HyperNetPage/2\n# Archive\n: A current publication.\n";
    let author = f.author(body, 1);
    f.apply(
        Command::Submit {
            author: author.clone(),
        },
        vec![],
        5000,
    );
    let review = f.reviewer(&author, true, 7000);
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
    let placement = f.content(&revision, 5000, true);
    let destination = f
        .state
        .record(backup::DESTINATION, p.id)
        .unwrap()
        .reference
        .clone();
    assert_eq!(
        action(
            &mut f,
            backup::Command::Prepare {
                placement: placement.clone(),
                destination: destination.clone()
            },
            6000
        )
        .code,
        0
    );
    let mut archive = backup::tests::archive(&p, b"age-encryption.org/v1\nCiphertext");
    archive.created_ms = 5000;
    archive.placement = placement;
    archive.destination = destination.clone();
    archive.envelope = wire::sign_envelope(
        &archive
            .payload(f.state.network, f.state.incarnation)
            .unwrap(),
        &deployment::key(5),
    )
    .unwrap();
    assert_eq!(
        action(
            &mut f,
            backup::Command::Create {
                archive: archive.clone()
            },
            6000
        )
        .code,
        0
    );
    let r = f
        .state
        .record(backup::ARCHIVE, archive.id)
        .unwrap()
        .reference
        .clone();
    assert_eq!(
        action(
            &mut f,
            backup::Command::Restore { archive: r.clone() },
            6000
        )
        .code,
        0
    );
    let before = f.state.clone();
    assert_eq!(
        action(
            &mut f,
            backup::Command::WithdrawDestination { destination },
            6000
        )
        .code,
        0
    );
    assert_ne!(
        action(
            &mut f,
            backup::Command::Restore { archive: r.clone() },
            6000
        )
        .code,
        0
    );
    f.state = before;
    f.apply(
        Command::Withdraw {
            page: [71; 16],
            as_reviewer: false,
        },
        vec![],
        7000,
    );
    assert_ne!(
        action(&mut f, backup::Command::Restore { archive: r }, 8000).code,
        0
    );
    assert_eq!(
        action(
            &mut f,
            backup::Command::Get {
                archive: archive.id
            },
            8000
        )
        .code,
        0,
        "owner still has cleanup metadata"
    );
}
