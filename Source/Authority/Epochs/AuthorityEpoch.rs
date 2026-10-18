// SPDX-License-Identifier: MIT
//! Committee succession has one exact declaration and preserves prior application history.
#[cfg(test)]
use crate::authority_membership::reference;
use crate::{
    authority_membership::{Snapshot, version},
    authority_proof::{Digest, Intent, Key, Scope, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
pub const MAX_DECLARATION: usize = 16384;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let id = v.fixed()?;
    ensure!(id != [0; 32], "zero epoch identifier");
    Ok(id)
}
#[derive(Clone, Debug)]
pub struct Nomination {
    pub voter: Key,
    pub profile: VersionRef,
    pub consent: VersionRef,
}
#[derive(Clone, Debug)]
pub struct Declaration {
    pub bytes: Vec<u8>,
    pub old_scope: Scope,
    pub next_epoch: u64,
    pub requester: Key,
    pub grant: Digest,
    pub snapshot: Snapshot,
    pub nominations: Vec<Nomination>,
}
impl Declaration {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DECLARATION,
            "epoch declaration exceeds bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(8)?;
        ensure!(
            f[0].uint()? == 49 && f[1].uint()? == 1,
            "epoch declaration kind differs"
        );
        let scope = Scope::parse(&f[2])?;
        let next = f[3].uint()?;
        ensure!(
            scope.epoch.checked_add(1) == Some(next),
            "epoch successor is not consecutive"
        );
        let requester = id(&f[4])?;
        wire::valid_key(&requester)?;
        let snapshot = Snapshot::parse(&f[6])?;
        ensure!(
            snapshot.epoch == scope.epoch,
            "epoch declaration snapshot scope differs"
        );
        let mut previous = None;
        let mut deployments = BTreeSet::new();
        let mut nominations = Vec::new();
        for row in f[7].array(4)? {
            let n = row.array(3)?;
            let voter = id(&n[0])?;
            wire::valid_key(&voter)?;
            let profile = version(&n[1])?;
            let consent = version(&n[2])?;
            ensure!(
                previous.is_none_or(|p| p < voter)
                    && profile.kind == 117
                    && consent.kind == 105
                    && profile.id == consent.id
                    && deployments.insert(profile.id),
                "committee nomination is repeated or has inconsistent consent"
            );
            previous = Some(voter);
            nominations.push(Nomination {
                voter,
                profile,
                consent,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            old_scope: scope,
            next_epoch: next,
            requester,
            grant: id(&f[5])?,
            snapshot,
            nominations,
        })
    }
    pub fn from_intent(intent: &Intent) -> Result<Self> {
        let decoded = wire::decode(&intent.parameters)?;
        let f = decoded.array(4)?;
        ensure!(
            intent.action == "Reconfigure"
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "Reconfigure",
            "reconfiguration parameters differ from action"
        );
        let declaration = Self::parse(f[3].bytes()?)?;
        ensure!(
            intent.network == declaration.old_scope.network
                && intent.incarnation == declaration.old_scope.incarnation
                && intent.requester == declaration.requester
                && intent.resource == intent.network
                && intent.profile_generation == 0
                && intent.revision == declaration.snapshot.height
                && intent.minimum_policy_epoch == declaration.snapshot.epoch
                && intent.minimum_policy_height == declaration.snapshot.height
                && intent.expected == declaration.snapshot.references,
            "reconfiguration request differs from the exact declaration"
        );
        Ok(declaration)
    }
    pub fn digest(&self) -> Digest {
        wire::digest(&self.bytes)
    }
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
#[derive(Clone, Debug)]
pub struct Terminal {
    pub declaration: Declaration,
    pub intent: Digest,
}
impl Terminal {
    pub fn parse(value: &V, scope: &Scope) -> Result<Option<Self>> {
        if *value == V::Null {
            return Ok(None);
        }
        let f = value.array(2)?;
        let declaration = Declaration::parse(f[0].bytes()?)?;
        ensure!(
            declaration.old_scope == *scope,
            "terminal declaration has another scope"
        );
        Ok(Some(Self {
            declaration,
            intent: id(&f[1])?,
        }))
    }
    pub fn value(&self) -> V {
        a(vec![b(&self.declaration.bytes), b(&self.intent)])
    }
}
#[derive(Clone, Debug)]
pub struct Origin {
    pub old_scope: Scope,
    pub height: u64,
    pub node: Digest,
    pub state: Digest,
    pub checkpoint: Digest,
    pub declaration: Digest,
}
impl Origin {
    pub fn parse(value: &V, scope: &Scope) -> Result<Option<Self>> {
        if *value == V::Null {
            ensure!(scope.epoch == 0, "successor state lacks its epoch origin");
            return Ok(None);
        }
        let f = value.array(6)?;
        let old_scope = Scope::parse(&f[0])?;
        let height = f[1].uint()?;
        ensure!(
            old_scope.network == scope.network
                && old_scope.incarnation == scope.incarnation
                && old_scope.epoch.checked_add(1) == Some(scope.epoch)
                && height > 0,
            "epoch origin differs from its predecessor"
        );
        Ok(Some(Self {
            old_scope,
            height,
            node: id(&f[2])?,
            state: id(&f[3])?,
            checkpoint: id(&f[4])?,
            declaration: id(&f[5])?,
        }))
    }
    pub fn value(&self) -> V {
        a(vec![
            self.old_scope.value(),
            V::Uint(self.height),
            b(&self.node),
            b(&self.state),
            b(&self.checkpoint),
            b(&self.declaration),
        ])
    }
}

#[path = "AuthorityEpochProof.rs"]
mod proof;
#[cfg(test)]
pub(crate) use proof::noop;
pub use proof::{ValidatedActivation, ValidatedTerminal, verify_activation, verify_terminal};
pub(crate) use proof::{descriptor, genesis, ready_statement};

#[path = "AuthorityEpochAssembly.rs"]
mod assembly;
pub use assembly::terminal_checkpoint;
#[cfg(test)]
pub use assembly::{assemble_checkpoint, assemble_handoff, assemble_ready};

#[path = "AuthorityEpochArchive.rs"]
pub mod archive;

#[cfg(test)]
#[path = "AuthorityEpochTests.rs"]
pub(crate) mod tests;
