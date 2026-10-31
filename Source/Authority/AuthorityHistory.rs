// SPDX-License-Identifier: MIT
// Certified checkpoints preserve exact retained history using RFC 9162 section 2.1.
use crate::{
    authority_proof::{Digest, Node, Prefix, Scope, TrustDescriptor},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};

// Proof arithmetic bounds; replica byte quotas govern actual retention.
pub const MAX_LEAVES: u64 = (1u64 << 63) - 1;
const MAX_PATH: usize = 64;
fn record(value: &V, kind: u64, size: usize) -> Result<&[V]> {
    let fields = value.array(size)?;
    ensure!(
        fields[0].uint()? == kind && fields[1].uint()? == 1,
        "history record kind or version differs"
    );
    Ok(fields)
}
fn hashes(value: &V) -> Result<Vec<Digest>> {
    value.list(MAX_PATH)?.iter().map(V::fixed).collect()
}
fn leaf(value: &Digest) -> Digest {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash.update(value);
    hash.finalize().into()
}
fn branch(left: &Digest, right: &Digest) -> Digest {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}
/// Leaf data is the canonical Node digest, not an already domain-prefixed leaf hash.
pub fn verify_inclusion(
    node: &Digest,
    index: u64,
    size: u64,
    root: &Digest,
    path: &[Digest],
) -> Result<()> {
    ensure!(
        (1..=MAX_LEAVES).contains(&size) && index < size && path.len() <= MAX_PATH,
        "inclusion position or path exceeds its bound"
    );
    let (mut position, mut right_edge) = (index, size - 1);
    let mut computed = leaf(node);
    for sibling in path {
        ensure!(right_edge != 0, "inclusion proof has extra hashes");
        if position & 1 != 0 || position == right_edge {
            computed = branch(sibling, &computed);
            while position != 0 && position & 1 == 0 {
                position >>= 1;
                right_edge >>= 1;
            }
        } else {
            computed = branch(&computed, sibling);
        }
        position >>= 1;
        right_edge >>= 1;
    }
    ensure!(
        right_edge == 0 && computed == *root,
        "inclusion proof is incomplete or has a different root"
    );
    Ok(())
}
/// Same-size trees require the exact same root and an empty proof. Empty prior trees are not retained heads.
pub fn verify_consistency(
    old_size: u64,
    old_root: &Digest,
    size: u64,
    root: &Digest,
    path: &[Digest],
) -> Result<()> {
    ensure!(
        old_size > 0 && old_size <= size && size <= MAX_LEAVES && path.len() <= MAX_PATH,
        "consistency sizes or path exceed their bounds"
    );
    if old_size == size {
        ensure!(
            old_root == root && path.is_empty(),
            "same-size history equivocation or extra proof hashes"
        );
        return Ok(());
    }
    ensure!(!path.is_empty(), "consistency proof is missing");
    let (mut left_position, mut right_position) = (old_size - 1, size - 1);
    while left_position & 1 != 0 {
        left_position >>= 1;
        right_position >>= 1;
    }
    let (initial, remaining) = if old_size.is_power_of_two() {
        (*old_root, path)
    } else {
        (path[0], &path[1..])
    };
    let (mut old, mut new) = (initial, initial);
    for sibling in remaining {
        ensure!(right_position != 0, "consistency proof has extra hashes");
        if left_position & 1 != 0 || left_position == right_position {
            old = branch(sibling, &old);
            new = branch(sibling, &new);
            while left_position != 0 && left_position & 1 == 0 {
                left_position >>= 1;
                right_position >>= 1;
            }
        } else {
            new = branch(&new, sibling);
        }
        left_position >>= 1;
        right_position >>= 1;
    }
    ensure!(
        right_position == 0 && old == *old_root && new == *root,
        "consistency proof is incomplete or changes retained history"
    );
    Ok(())
}

/// A head is obtained from a verified checkpoint. A caller must supply its durably retained head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeHead {
    scope: Scope,
    size: u64,
    root: Digest,
    terminal: bool,
}
impl TreeHead {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn root(&self) -> &Digest {
        &self.root
    }
}
/// The applied-state quorum statement and its exact anchor have been independently verified.
#[derive(Clone)]
pub struct ValidatedCheckpoint {
    proof: Vec<u8>,
    statement: Vec<u8>,
    digest: Digest,
    anchor: Node,
    state: Digest,
    head: TreeHead,
    terminal: bool,
}
impl ValidatedCheckpoint {
    pub(crate) fn prefix(&self) -> Prefix {
        Prefix::checkpoint(&self.anchor, self.state)
    }
    pub fn canonical_proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn height(&self) -> u64 {
        self.anchor.height()
    }
    pub fn node(&self) -> &Digest {
        self.anchor.digest()
    }
    pub fn state(&self) -> &Digest {
        &self.state
    }
    pub fn head(&self) -> &TreeHead {
        &self.head
    }
    pub fn terminal(&self) -> bool {
        self.terminal
    }
}
pub fn verify_checkpoint(
    descriptor: &TrustDescriptor,
    bytes: &[u8],
) -> Result<ValidatedCheckpoint> {
    let decoded = wire::decode(bytes)?;
    let fields = record(&decoded, 46, 4)?;
    let statement = descriptor.quorum(fields[2].bytes()?)?;
    let value = wire::decode(&statement)?;
    let checkpoint = record(&value, 45, 10)?;
    let scope = Scope::parse(&checkpoint[2])?;
    let height = checkpoint[3].uint()?;
    let node = checkpoint[4].fixed::<32>()?;
    let time = checkpoint[5].uint()?;
    let state = checkpoint[6].fixed::<32>()?;
    let size = checkpoint[7].uint()?;
    let root = checkpoint[8].fixed::<32>()?;
    let terminal = checkpoint[9].boolean()?;
    ensure!(
        scope == *descriptor.scope()
            && (1..=MAX_LEAVES).contains(&height)
            && size == height
            && (terminal || height.is_multiple_of(32)),
        "checkpoint scope, schedule or tree size differs"
    );
    let anchor = Node::parse(fields[3].bytes()?)?;
    ensure!(
        anchor.scope() == &scope
            && anchor.height() == height
            && *anchor.digest() == node
            && anchor.evaluated_at_ms() == time,
        "checkpoint does not bind its exact applied anchor"
    );
    Ok(ValidatedCheckpoint {
        proof: bytes.to_vec(),
        digest: wire::digest(&statement),
        statement,
        anchor,
        state,
        head: TreeHead {
            scope,
            size,
            root,
            terminal,
        },
        terminal,
    })
}

/// This relation authenticates a checkpoint from one exact retained node and optional prior tree head.
/// It confers no operation permission and does not activate terminal checkpoints.
#[derive(Clone)]
pub struct ValidatedHistory {
    from: Prefix,
    prior: Option<TreeHead>,
    checkpoint: ValidatedCheckpoint,
    canonical: Vec<u8>,
}
impl ValidatedHistory {
    pub fn checkpoint(&self) -> &ValidatedCheckpoint {
        &self.checkpoint
    }
    pub fn from(&self) -> &Prefix {
        &self.from
    }
    pub fn prior(&self) -> Option<&TreeHead> {
        self.prior.as_ref()
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    /// Ordinary old-scope effects cannot pass a terminal checkpoint before epoch activation is qualified.
    pub fn ordinary_checkpoint(&self) -> Result<&ValidatedCheckpoint> {
        ensure!(
            !self.checkpoint.terminal,
            "terminal checkpoint requires qualified epoch activation"
        );
        Ok(&self.checkpoint)
    }
}
pub fn verify_history(
    checkpoint: &ValidatedCheckpoint,
    retained: &Prefix,
    prior: Option<&TreeHead>,
    bytes: &[u8],
) -> Result<ValidatedHistory> {
    let decoded = wire::decode(bytes)?;
    let fields = record(&decoded, 47, 10)?;
    let scope = Scope::parse(&fields[2])?;
    ensure!(
        scope == checkpoint.head.scope
            && &scope == retained.scope()
            && fields[3].uint()? == retained.height()
            && fields[4].fixed::<32>()? == *retained.node()
            && fields[5].fixed::<32>()? == checkpoint.digest,
        "history proof differs from the exact retained node or requested checkpoint"
    );
    ensure!(
        retained.height() <= checkpoint.height()
            && retained.view() <= checkpoint.anchor.view()
            && retained.evaluated_at_ms() <= checkpoint.anchor.evaluated_at_ms(),
        "checkpoint is below the retained committed position"
    );
    let inclusion = hashes(&fields[6])?;
    let old_size = fields[7].uint()?;
    let consistency = hashes(&fields[9])?;
    if retained.height() == 0 {
        // Prefix can only originate from a verified descriptor or certified executed result.
        ensure!(inclusion.is_empty(), "genesis has no history-tree leaf");
    } else {
        verify_inclusion(
            retained.node(),
            retained.height() - 1,
            checkpoint.head.size,
            &checkpoint.head.root,
            &inclusion,
        )?;
        if retained.height() == checkpoint.height() {
            ensure!(
                retained.node() == checkpoint.node()
                    && retained.policy_state() == checkpoint.state()
                    && retained.view() == checkpoint.anchor.view()
                    && retained.evaluated_at_ms() == checkpoint.anchor.evaluated_at_ms(),
                "same-position checkpoint differs from the retained applied state"
            );
        }
    }
    match prior {
        None => ensure!(
            old_size == 0 && fields[8] == V::Null && consistency.is_empty(),
            "first checkpoint cannot select an earlier tree head"
        ),
        Some(head) => {
            ensure!(
                !head.terminal || checkpoint.terminal && checkpoint.head.size == head.size,
                "retained terminal history cannot advance within its old scope"
            );
            ensure!(
                head.scope == scope
                    && head.size <= retained.height()
                    && head.size == old_size
                    && fields[8].fixed::<32>()? == head.root,
                "history proof substitutes the retained tree head"
            );
            verify_consistency(
                head.size,
                &head.root,
                checkpoint.head.size,
                &checkpoint.head.root,
                &consistency,
            )?;
        }
    }
    Ok(ValidatedHistory {
        from: retained.clone(),
        prior: prior.cloned(),
        checkpoint: checkpoint.clone(),
        canonical: bytes.to_vec(),
    })
}

#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityHistoryTests.rs"]
mod tests;
