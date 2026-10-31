// SPDX-License-Identifier: MIT
// Finite content commands fail closed for invalid ranges, payload classes and host identities.
use super::*;
fn command(effect: Effect, offset: u64, bytes: u64, digest: Option<Digest>) -> Command {
    Command::Authorise {
        placement: VersionRef {
            kind: 159,
            id: [1; 32],
            generation: 1,
            digest: [2; 32],
        },
        host: VersionRef {
            kind: 147,
            id: [3; 32],
            generation: 1,
            digest: [4; 32],
        },
        effect,
        offset,
        bytes,
        digest,
    }
}
#[test]
fn content_effects_require_finite_exact_payload_and_purge_ranges() {
    for effect in [Effect::Upload, Effect::Repair] {
        assert!(
            Command::parse(
                &command(effect, 0, 32768, Some([5; 32])).value(),
                [6; 32],
                [7; 32]
            )
            .is_ok()
        );
        assert!(
            Command::parse(&command(effect, 0, 32768, None).value(), [6; 32], [7; 32]).is_err()
        );
    }
    for effect in [Effect::Read, Effect::Inspect] {
        assert!(Command::parse(&command(effect, 0, 32768, None).value(), [6; 32], [7; 32]).is_ok());
        assert!(
            Command::parse(
                &command(effect, 0, 32768, Some([5; 32])).value(),
                [6; 32],
                [7; 32]
            )
            .is_err()
        );
    }
    for (offset, bytes) in [(0, 0), (0, 32769), (u64::MAX, 1)] {
        assert!(
            Command::parse(
                &command(Effect::Read, offset, bytes, None).value(),
                [6; 32],
                [7; 32]
            )
            .is_err()
        );
    }
    assert!(
        Command::parse(
            &command(Effect::Purge, 0, 0, None).value(),
            [6; 32],
            [7; 32]
        )
        .is_ok()
    );
    assert!(
        Command::parse(
            &command(Effect::Purge, 0, 1, None).value(),
            [6; 32],
            [7; 32]
        )
        .is_err()
    );
    assert!(Command::parse(&V::Array(vec![]), [6; 32], [7; 32]).is_err());
    let mut invalid = command(Effect::Read, 0, 1, None);
    let Command::Authorise { host, .. } = &mut invalid else {
        unreachable!()
    };
    host.kind = 143;
    assert!(Command::parse(&invalid.value(), [6; 32], [7; 32]).is_err());
}
