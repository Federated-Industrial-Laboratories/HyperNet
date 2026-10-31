// SPDX-License-Identifier: MIT
// Shared action codes require one explicit terminal-grant resource family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionPurpose {
    ApplicationStream,
    SealedPublication,
}

pub fn collides(action: u64) -> bool {
    matches!(action, 29 | 30)
}

pub fn classify(kinds: impl IntoIterator<Item = u64>) -> Option<ActionPurpose> {
    let mut purpose = None;
    for kind in kinds {
        let current = match kind {
            3 => ActionPurpose::ApplicationStream,
            1 | 2 => ActionPurpose::SealedPublication,
            _ => return None,
        };
        if purpose.is_some_and(|previous| previous != current) {
            return None;
        }
        purpose = Some(current);
    }
    purpose
}
