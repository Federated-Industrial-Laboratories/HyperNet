// SPDX-License-Identifier: MIT
// Recipient authority is separate from network membership and serving-recipient floors.
use super::*;
use crate::{
    authority_governance::{Governance, Requirement},
    authority_membership::{Reservations, Snapshot, current},
};
use std::collections::BTreeSet;

#[path = "AuthoritySealedIdentityRecords.rs"]
mod records;
pub use records::*;
#[path = "AuthoritySealedIdentityCommands.rs"]
mod commands;
pub use commands::Command;
#[path = "AuthoritySealedIdentityEvaluation.rs"]
mod evaluation;
pub use evaluation::{evaluate, validate_state, verify_directory_result};
#[path = "AuthoritySealedIdentityRoster.rs"]
mod roster;
pub use roster::{CurrentRoster, admitted_device, current_member, member_evidence, roster};

pub const ROOT_KEY: u64 = 5;
pub const SIGNING_KEY: u64 = 6;
pub const ENCRYPTION_KEY: u64 = 7;
/// Permanent ownership uses one canonical little-endian X25519 field encoding.
/// The endpoint separately checks contributory ECDH before issuing encrypted possession evidence.
pub fn validate_encryption_key(public: Digest) -> Result<()> {
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    ensure!(
        public != [0; 32] && public.iter().rev().cmp(prime.iter().rev()).is_lt(),
        "noncanonical recipient encryption key"
    );
    Ok(())
}
pub fn persistent_kind(kind: u64) -> bool {
    matches!(kind, 107..=111 | 158)
}
fn point(value: &V) -> Result<(u64, u64, Digest)> {
    let f = value.array(3)?;
    Ok((f[0].uint()?, f[1].uint()?, id(&f[2])?))
}
fn validity(value: &V) -> Result<(u64, u64)> {
    let f = value.array(2)?;
    let value = (f[0].uint()?, f[1].uint()?);
    ensure!(value.0 < value.1, "invalid recipient validity");
    Ok(value)
}
fn ids(value: &V, maximum: usize) -> Result<Vec<Digest>> {
    let values = value
        .list(maximum)?
        .iter()
        .map(id)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.windows(2).all(|w| w[0] < w[1]),
        "recipient identifiers are not sorted and unique"
    );
    Ok(values)
}
fn typed_ref(value: &V, kind: u64) -> Result<VersionRef> {
    let r = version(value)?;
    ensure!(r.kind == kind, "recipient reference kind differs");
    Ok(r)
}
fn prefix(bytes: &[u8], n: Digest, i: Digest, kind: u64, arity: usize) -> Result<Vec<V>> {
    let value = wire::decode(bytes)?;
    let f = value.array(arity)?;
    ensure!(
        f[0].uint()? == kind && f[1].uint()? == 1 && id(&f[2])? == n && id(&f[3])? == i,
        "recipient record context differs"
    );
    let generation = f[4].uint()?;
    if matches!(kind, 120..=123) {
        ensure!(
            generation == 0 && f[5] == V::Null,
            "recipient transient predecessor differs"
        );
    } else {
        ensure!(
            generation > 0 && (generation == 1) == (f[5] == V::Null),
            "recipient predecessor differs"
        );
        if f[5] != V::Null {
            id(&f[5])?;
        }
    }
    Ok(f.to_vec())
}
fn record_ref(f: &[V], lookup: Digest, bytes: &[u8]) -> Result<VersionRef> {
    Ok(VersionRef {
        kind: f[0].uint()?,
        id: lookup,
        generation: f[4].uint()?,
        digest: wire::digest(bytes),
    })
}
pub fn signed_record(bytes: &[u8], n: Digest, i: Digest) -> Result<Record> {
    let (payload, _) = wire::envelope(bytes, 4)?;
    let value = wire::decode(&payload)?;
    let f = value.list(32)?;
    let kind = f.first().context("empty recipient record")?.uint()?;
    let reference = match kind {
        107 => Root::parse(&payload, n, i)?.reference,
        108 => Binding::parse(&payload, n, i)?.reference,
        109 => Admission::parse(&payload, n, i)?.reference,
        110 => Audience::parse(&payload, n, i)?.reference,
        111 => Roster::parse(&payload, n, i)?.reference,
        158 => Revocation::parse(&payload, n, i)?.reference,
        _ => anyhow::bail!("unsupported signed recipient record"),
    };
    Ok(Record {
        reference,
        predecessor: if f[5] == V::Null {
            None
        } else {
            Some(id(&f[5])?)
        },
        payload: a(f[6..].to_vec()),
        bytes: bytes.to_vec(),
    })
}
pub fn payload(record: &Record) -> Result<Vec<u8>> {
    Ok(wire::envelope(&record.bytes, 4)?.0)
}
pub fn signer(record: &Record, expected: Key) -> Result<()> {
    let (_, signatures) = wire::envelope(&record.bytes, 4)?;
    ensure!(
        signatures.iter().any(|(key, _)| *key == expected),
        "recipient record lacks its required signer"
    );
    Ok(())
}
pub fn revoked(state: &State, reference: &VersionRef) -> bool {
    state.records.contains_key(&(158, reference.digest))
}
pub fn reserve_record(state: &mut State, record: &Record) -> Result<()> {
    match record.reference.kind {
        107 => {
            let root = Root::parse(&payload(record)?, state.network, state.incarnation)?;
            state.reserve(ROOT_KEY, root.key, root.member)?;
        }
        108 => {
            let binding = Binding::parse(&payload(record)?, state.network, state.incarnation)?;
            state.reserve(SIGNING_KEY, binding.signing_key, binding.member)?;
            state.reserve(ENCRYPTION_KEY, binding.encryption_key, binding.member)?;
        }
        _ => (),
    }
    Ok(())
}

pub fn verify_successor(
    old: &Root,
    new: &Root,
    envelope: &[u8],
    recovery: Option<&[u8]>,
    custody: Option<&[u8]>,
    n: Digest,
    i: Digest,
) -> Result<()> {
    let record = signed_record(envelope, n, i)?;
    ensure!(
        record.reference == new.reference
            && old.member == new.member
            && old.reference.generation.checked_add(1) == Some(new.reference.generation)
            && record.predecessor == Some(old.reference.digest)
            && new.key != old.key
            && new.recovery_policy == old.recovery_policy,
        "recipient root successor differs from accepted continuity"
    );
    signer(&record, new.key)?;
    if signer(&record, old.key).is_ok() {
        ensure!(
            recovery.is_none() && custody.is_none(),
            "continuous root update includes recovery material"
        );
        return Ok(());
    }
    let custody = Custody::parse(
        custody.context("accepted recipient custody is absent")?,
        n,
        i,
    )?;
    let (bytes, signatures) = wire::envelope(
        recovery.context("recipient recovery declaration is absent")?,
        3,
    )?;
    let declaration = Recovery::parse(&bytes, n, i)?;
    ensure!(
        custody.member == old.member
            && custody.digest == old.recovery_policy
            && declaration.member == old.member
            && declaration.prior_root == old.reference
            && declaration.replacement_root == new.reference
            && declaration.accepted_policy == old.recovery_policy
            && signatures
                .iter()
                .filter(|(key, _)| custody.keys.iter().any(|(_, k)| k == key))
                .count()
                >= custody.threshold,
        "recipient recovery does not satisfy independently accepted custody"
    );
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Sealed/AuthoritySealedIdentityTests.rs"]
mod tests;
