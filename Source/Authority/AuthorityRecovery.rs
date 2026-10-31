// SPDX-License-Identifier: MIT
//! Offline recovery proposes a new trust identity; custody never proves unique succession.
use crate::{
    authority_proof::{Digest, Key, Prefix, VersionRef},
    trust_bootstrap::{self as trust, Verified},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_DECLARATION: usize = 16384;
pub const MAX_CONFLICTS: usize = 16;
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn id(v: &V) -> Result<Digest> {
    let out = v.fixed()?;
    ensure!(out != [0; 32], "zero recovery identifier");
    Ok(out)
}
fn reference(v: &VersionRef) -> V {
    a(vec![
        V::Uint(v.kind),
        b(&v.id),
        V::Uint(v.generation),
        b(&v.digest),
    ])
}
/// The bootstrap and historical prefix have already been authenticated independently.
pub struct Predecessor {
    network: Digest,
    incarnation: Digest,
    point: V,
    policy: VersionRef,
    threshold: usize,
    keys: BTreeMap<Key, Digest>,
    shared: bool,
}
impl Predecessor {
    pub fn new(bootstrap: &Verified, prefix: &Prefix) -> Result<Self> {
        let scope = bootstrap.descriptor().scope();
        let reference = VersionRef {
            kind: 114,
            id: scope.network,
            generation: 1,
            digest: wire::digest(&bootstrap.recovery_payload),
        };
        Self::retained(bootstrap, prefix, &bootstrap.recovery_payload, &reference)
    }
    /// The caller authenticates the exact current policy reference from its durable certified floor.
    pub fn retained(
        bootstrap: &Verified,
        prefix: &Prefix,
        bytes: &[u8],
        minimum: &VersionRef,
    ) -> Result<Self> {
        let scope = bootstrap.descriptor().scope();
        ensure!(
            !bootstrap.summary.draft
                && prefix.scope().network == scope.network
                && prefix.scope().incarnation == scope.incarnation,
            "recovery predecessor differs from accepted bootstrap"
        );
        let custody =
            crate::authority_policies::Custody::parse(bytes, scope.network, scope.incarnation)?;
        ensure!(
            custody.reference == *minimum,
            "retained recovery policy is stale or conflicts with the authenticated floor"
        );
        Ok(Self {
            network: scope.network,
            incarnation: scope.incarnation,
            point: a(vec![
                V::Uint(prefix.scope().epoch),
                V::Uint(prefix.height()),
                b(prefix.policy_state()),
            ]),
            policy: custody.reference,
            threshold: custody.threshold,
            keys: custody.keys.into_iter().map(|(p, k)| (k, p)).collect(),
            shared: custody.mode == 2,
        })
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub declaration_digest: String,
    pub predecessor_network: String,
    pub predecessor_incarnation: String,
    pub successor_network: String,
    pub successor_incarnation: String,
    pub successor_descriptor: String,
    pub signers: Vec<String>,
    pub state: &'static str,
    pub current_authority: bool,
    pub historical_import_requested: bool,
}
#[derive(Clone)]
pub struct Declaration {
    payload: Vec<u8>,
    operation: Digest,
    old_network: Digest,
    old_incarnation: Digest,
    new_network: Digest,
    new_incarnation: Digest,
    descriptor: Digest,
    historical: Option<Digest>,
}
impl Declaration {
    fn parse(predecessor: &Predecessor, bytes: &[u8], exact_point: bool) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DECLARATION,
            "recovery declaration exceeds size bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(16)?;
        ensure!(
            f[0].uint()? == 115
                && f[1].uint()? == 1
                && f[2].fixed::<32>()? == predecessor.network
                && f[3].fixed::<32>()? == predecessor.incarnation
                && f[4].uint()? == 1
                && f[5] == V::Null
                && f[7] == f[2]
                && f[8] == f[3]
                && (!exact_point || f[9] == predecessor.point)
                && f[10] == reference(&predecessor.policy),
            "recovery declaration differs from the authenticated predecessor"
        );
        let point = f[9].array(3)?;
        point[0].uint()?;
        point[1].uint()?;
        id(&point[2])?;
        let new_network = id(&f[11])?;
        let new_incarnation = id(&f[12])?;
        ensure!(
            new_network != new_incarnation
                && ![predecessor.network, predecessor.incarnation].contains(&new_network)
                && ![predecessor.network, predecessor.incarnation].contains(&new_incarnation),
            "NewNetworkRequired: successor identifiers must be distinct and new"
        );
        id(&f[15])?;
        Ok(Self {
            payload: bytes.to_vec(),
            operation: id(&f[6])?,
            old_network: predecessor.network,
            old_incarnation: predecessor.incarnation,
            new_network,
            new_incarnation,
            descriptor: id(&f[13])?,
            historical: if f[14] == V::Null {
                None
            } else {
                Some(id(&f[14])?)
            },
        })
    }
    pub fn digest(&self) -> Digest {
        wire::digest(&self.payload)
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn verify_successor(&self, bootstrap: &[u8]) -> Result<Verified> {
        let verified = trust::inspect(bootstrap, true)?;
        let scope = verified.descriptor().scope();
        ensure!(
            scope.network == self.new_network
                && scope.incarnation == self.new_incarnation
                && scope.configuration == self.descriptor
                && scope.epoch == 0,
            "successor bootstrap differs from the exact recovery declaration"
        );
        Ok(verified)
    }
    fn summary(&self, signers: Vec<String>) -> Summary {
        Summary {
            declaration_digest: hex::encode(self.digest()),
            predecessor_network: hex::encode(self.old_network),
            predecessor_incarnation: hex::encode(self.old_incarnation),
            successor_network: hex::encode(self.new_network),
            successor_incarnation: hex::encode(self.new_incarnation),
            successor_descriptor: hex::encode(self.descriptor),
            state: if signers.is_empty() {
                "UnsignedRecoveryProposal"
            } else {
                "AwaitingIndependentAcceptance"
            },
            current_authority: false,
            historical_import_requested: self.historical.is_some(),
            signers,
        }
    }
}
pub struct ValidatedDeclaration {
    declaration: Declaration,
    signers: Vec<String>,
}
impl ValidatedDeclaration {
    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }
    pub fn summary(&self) -> Summary {
        self.declaration.summary(self.signers.clone())
    }
}
pub fn draft(
    predecessor: &Predecessor,
    successor: &[u8],
    operation: Digest,
    nonce: Digest,
    historical: Option<Digest>,
) -> Result<Declaration> {
    let next = trust::inspect(successor, true)?;
    let scope = next.descriptor().scope();
    let bytes = wire::encode(&a(vec![
        V::Uint(115),
        V::Uint(1),
        b(&predecessor.network),
        b(&predecessor.incarnation),
        V::Uint(1),
        V::Null,
        b(&operation),
        b(&predecessor.network),
        b(&predecessor.incarnation),
        predecessor.point.clone(),
        reference(&predecessor.policy),
        b(&scope.network),
        b(&scope.incarnation),
        b(&scope.configuration),
        historical.as_ref().map_or(V::Null, |v| b(v)),
        b(&nonce),
    ]))?;
    Declaration::parse(predecessor, &bytes, true)
}
pub fn inspect_draft(predecessor: &Predecessor, bytes: &[u8]) -> Result<Declaration> {
    Declaration::parse(predecessor, bytes, true)
}
pub fn sign(predecessor: &Predecessor, bytes: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    Declaration::parse(predecessor, bytes, true)?;
    ensure!(
        predecessor
            .keys
            .contains_key(&key.verifying_key().to_bytes()),
        "key is outside the predecessor recovery policy"
    );
    wire::sign_envelope(bytes, key)
}
fn eligible(
    predecessor: &Predecessor,
    signatures: &[(Key, [u8; 64])],
    threshold: bool,
) -> Result<()> {
    let mut principals = BTreeSet::new();
    for (key, _) in signatures {
        principals.insert(
            *predecessor
                .keys
                .get(key)
                .context("unknown recovery signer")?,
        );
    }
    ensure!(
        !threshold
            || (signatures.len() >= predecessor.threshold
                && (!predecessor.shared || principals.len() >= predecessor.threshold)),
        "RecoveryThreshold: distinct authorised custody signatures are required"
    );
    Ok(())
}
pub fn verify(predecessor: &Predecessor, envelope: &[u8]) -> Result<ValidatedDeclaration> {
    ensure!(
        envelope.len() <= MAX_DECLARATION,
        "recovery envelope exceeds size bound"
    );
    let (payload, signatures) = wire::envelope(envelope, 3)?;
    eligible(predecessor, &signatures, true)?;
    Ok(ValidatedDeclaration {
        declaration: Declaration::parse(predecessor, &payload, false)?,
        signers: signatures.iter().map(|(k, _)| hex::encode(k)).collect(),
    })
}
pub fn assemble(
    predecessor: &Predecessor,
    draft: &[u8],
    shares: &[Vec<u8>],
) -> Result<ValidatedDeclaration> {
    Declaration::parse(predecessor, draft, true)?;
    ensure!(
        (1..=3).contains(&shares.len()),
        "one to three independent recovery shares are required"
    );
    let mut signatures = BTreeMap::new();
    for share in shares {
        let (payload, pairs) = wire::envelope(share, 1)?;
        ensure!(
            payload == draft,
            "recovery shares name different declarations"
        );
        eligible(predecessor, &pairs, false)?;
        for (key, sig) in pairs {
            ensure!(
                signatures.insert(key, sig).is_none(),
                "duplicate recovery signer"
            );
        }
    }
    let bytes = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(draft),
        a(signatures
            .iter()
            .map(|(k, s)| a(vec![b(k), b(s)]))
            .collect()),
    ]))?;
    verify(predecessor, &bytes)
}
/// An explicit offline decision never restores the predecessor's grants or private content.
pub fn accept(
    declaration: &ValidatedDeclaration,
    successor: &[u8],
    fingerprint: Digest,
    key: &SigningKey,
    conflicts: &[Digest],
) -> Result<Vec<u8>> {
    ensure!(
        conflicts.len() <= MAX_CONFLICTS && conflicts.is_empty(),
        "RecoveryConflict: observed conflicting declarations prevent acceptance"
    );
    ensure!(
        fingerprint == wire::digest(successor),
        "IndependentAcceptance: successor bootstrap fingerprint differs"
    );
    let d = &declaration.declaration;
    d.verify_successor(successor)?;
    let bytes = wire::encode(&a(vec![
        V::Uint(116),
        V::Uint(1),
        b(&d.old_network),
        b(&d.old_incarnation),
        V::Uint(1),
        V::Null,
        b(&d.operation),
        b(&key.verifying_key().to_bytes()),
        b(&d.digest()),
        b(&d.descriptor),
        b(&fingerprint),
        a(Vec::new()),
    ]))?;
    wire::sign_envelope(&bytes, key)
}
pub fn verify_acceptance(
    declaration: &ValidatedDeclaration,
    successor: &[u8],
    acceptance: &[u8],
    client: Key,
) -> Result<()> {
    let (payload, signers) = wire::envelope(acceptance, 1)?;
    let d = &declaration.declaration;
    let value = wire::decode(&payload)?;
    let f = value.array(12)?;
    ensure!(
        signers[0].0 == client
            && f[0].uint()? == 116
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == d.old_network
            && f[3].fixed::<32>()? == d.old_incarnation
            && f[4].uint()? == 1
            && f[5] == V::Null
            && f[6].fixed::<32>()? == d.operation
            && f[7].fixed::<32>()? == client
            && f[8].fixed::<32>()? == d.digest()
            && f[9].fixed::<32>()? == d.descriptor
            && f[10].fixed::<32>()? == wire::digest(successor)
            && f[11].list(MAX_CONFLICTS)?.is_empty(),
        "recovery acceptance differs from the explicit independent decision"
    );
    d.verify_successor(successor)?;
    Ok(())
}
#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityRecoveryTests.rs"]
pub(crate) mod tests;
