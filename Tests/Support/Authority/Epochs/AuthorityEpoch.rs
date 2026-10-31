// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use crate::authority_membership::reference;

#[cfg(test)]
pub(crate) use proof::noop;

#[cfg(test)]
pub use assembly::{assemble_checkpoint, assemble_handoff, assemble_ready};

impl Declaration {
    #[cfg(test)]
    pub fn parameters(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("Reconfigure".into()),
            b(&self.bytes),
        ]))
    }

    #[cfg(test)]
    pub fn create(
        scope: Scope,
        requester: Key,
        grant: Digest,
        snapshot: Snapshot,
        nominations: Vec<Nomination>,
    ) -> Result<Self> {
        let bytes = wire::encode(&a(vec![
            V::Uint(49),
            V::Uint(1),
            scope.value(),
            V::Uint(scope.epoch.checked_add(1).context("epoch overflow")?),
            b(&requester),
            b(&grant),
            snapshot.value,
            a(nominations
                .iter()
                .map(|n| {
                    a(vec![
                        b(&n.voter),
                        reference(&n.profile),
                        reference(&n.consent),
                    ])
                })
                .collect()),
        ]))?;
        Self::parse(&bytes)
    }
}
