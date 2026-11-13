// SPDX-License-Identifier: MIT
// Scoped admission owns bounded member slots, exact templates and descriptor-key purpose.
use crate::{
    authority_governance::{Governance, Limits, Requirement},
    authority_membership::{Snapshot, reference},
    authority_proof::{Digest, Key, VersionRef},
    trust_validity::Validity,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[path = "AuthorityAdmissionRecords.rs"]
mod records;
pub use records::{Policy, Role, Slot, Template};
#[path = "AuthorityAdmissionOperation.rs"]
mod operation;
pub use operation::{Operation, Transition};
#[path = "AuthorityAdmissionMaterial.rs"]
mod material;
pub use material::enrol_material;
#[path = "AuthorityAdmissionContext.rs"]
mod context;
#[path = "AuthorityAdmissionEvaluation.rs"]
mod evaluation;
pub use context::disclose;

pub const POLICY: u64 = 180;
pub const SLOT: u64 = 181;
pub const MAX_SLOTS: u64 = 64;
pub const MAX_ROLES: usize = 2;
pub const CHALLENGE_MS: u64 = 60_000;
pub const MAX_VOUCHER_MS: u64 = 86_400_000;
pub const MAX_POLICIES: usize = 4;

pub(crate) fn a(v: Vec<V>) -> V {
    V::Array(v)
}
pub(crate) fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
pub(crate) fn id(v: &V) -> Result<Digest> {
    let id = v.fixed()?;
    ensure!(id != [0; 32], "zero admission identifier");
    Ok(id)
}
pub(crate) fn key(v: &V) -> Result<Key> {
    let k = id(v)?;
    wire::valid_key(&k)?;
    Ok(k)
}
pub(crate) fn limits(v: &V) -> Result<Limits> {
    let f = v.array(4)?;
    let x = [f[0].uint()?, f[1].uint()?, f[2].uint()?, f[3].uint()?];
    ensure!(x.iter().all(|x| *x > 0), "zero admission limit");
    Ok(x)
}
pub fn identifier(policy: Digest, slot: u64, role: u64, purpose: u64) -> Result<Digest> {
    ensure!(
        policy != [0; 32] && slot < MAX_SLOTS && role < 2 && purpose < 8,
        "admission identifier scope differs"
    );
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Text("HyperNet/AdmissionSlot".into()),
        V::Uint(1),
        b(&policy),
        V::Uint(slot),
        V::Uint(role),
        V::Uint(purpose),
    ]))?))
}
pub fn claim_ordinal(claim: &Digest) -> Result<u64> {
    let ordinal = u64::from_be_bytes(claim[..8].try_into().expect("fixed claim"));
    ensure!(
        ordinal > 0 && claim[8..].iter().any(|b| *b != 0),
        "invalid admission claim ordinal"
    );
    Ok(ordinal)
}
pub fn record_reference(bytes: &[u8], n: Digest, i: Digest) -> Result<VersionRef> {
    let v = wire::decode(bytes)?;
    let f = v.array(9)?;
    let kind = f[0].uint()?;
    ensure!(
        matches!(kind, POLICY | SLOT)
            && f[1].uint()? == 1
            && id(&f[2])? == n
            && id(&f[3])? == i
            && f[4].uint()? > 0,
        "admission record context differs"
    );
    if f[4].uint()? == 1 {
        f[5].null()?;
    } else {
        id(&f[5])?;
    }
    Snapshot::parse(&f[8])?;
    Ok(VersionRef {
        kind,
        id: id(&f[6])?,
        generation: f[4].uint()?,
        digest: wire::digest(bytes),
    })
}
pub fn validate_record(bytes: &[u8], n: Digest, i: Digest) -> Result<()> {
    match record_reference(bytes, n, i)?.kind {
        POLICY => {
            Policy::parse(bytes, n, i)?;
        }
        SLOT => {
            Slot::parse(bytes, n, i)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
#[derive(Clone, Default)]
pub struct Index {
    pub policies: BTreeMap<Digest, Policy>,
    pub slots: BTreeMap<Digest, Slot>,
}
impl Index {
    pub fn parse(bytes: &[Vec<u8>], n: Digest, i: Digest) -> Result<Self> {
        let mut out = Self::default();
        for bytes in bytes {
            let v = wire::decode(bytes)?;
            match v.list(32)?[0].uint()? {
                POLICY => {
                    let p = Policy::parse(bytes, n, i)?;
                    ensure!(
                        out.policies.insert(p.reference.id, p).is_none(),
                        "duplicate admission policy"
                    );
                }
                SLOT => {
                    let s = Slot::parse(bytes, n, i)?;
                    ensure!(
                        out.slots.insert(s.reference.id, s).is_none(),
                        "duplicate admission slot"
                    );
                }
                _ => (),
            }
        }
        ensure!(
            out.policies.len() <= MAX_POLICIES,
            "admission policy capacity exceeded"
        );
        let mut keys = BTreeSet::new();
        for p in out.policies.values() {
            ensure!(
                keys.insert(p.registrar) && keys.insert(p.descriptor),
                "admission policy keys overlap"
            );
        }
        for s in out.slots.values() {
            let p = out
                .policies
                .get(&s.policy)
                .context("admission slot has no policy")?;
            ensure!(
                s.slot < p.maximum_slots,
                "admission slot exceeds policy capacity"
            );
            material::validate_material(p, s, bytes, n)?;
            for r in &s.roles {
                ensure!(
                    p.templates.iter().any(|t| t.role == r.role),
                    "admission role is outside policy"
                );
                if s.active() {
                    ensure!(
                        keys.insert(r.member) && keys.insert(r.relay),
                        "admission identities overlap"
                    );
                }
            }
        }
        Ok(out)
    }
    pub fn claim_floor(&self, _policy: Digest) -> u64 {
        self.slots.values().map(|s| s.ordinal).max().unwrap_or(0)
    }
    pub fn active_member(&self, member: Key) -> Option<(&Policy, &Slot, &Role)> {
        self.slots.values().filter(|s| s.active()).find_map(|s| {
            s.roles
                .iter()
                .find(|r| r.member == member)
                .map(|r| (&self.policies[&s.policy], s, r))
        })
    }
    pub fn owns_grant(&self, grant: Digest) -> bool {
        self.slots
            .values()
            .any(|s| s.owned().is_ok_and(|v| v.contains(&(102, grant))))
    }
    pub fn requester_keys(&self) -> Vec<Key> {
        let mut keys: Vec<_> = self.policies.values().map(|p| p.registrar).collect();
        keys.extend(
            self.slots
                .values()
                .filter(|s| s.active())
                .flat_map(|s| s.roles.iter().map(|r| r.member)),
        );
        keys.sort();
        keys.dedup();
        keys
    }
}

impl Index {
    #[allow(
        clippy::too_many_arguments,
        reason = "Compare every independently authenticated voucher field to the fixed native policy."
    )]
    pub fn route_template(
        &self,
        member: Key,
        grant: Digest,
        voucher: Digest,
        relay: Digest,
        destination: Digest,
        action: u64,
        scope: (u64, Digest),
        connections: u64,
        bytes: u64,
        expires: u64,
        at: u64,
    ) -> Result<()> {
        if let Some((policy, slot, role)) = self.active_member(member) {
            let template = policy.template(role.role)?;
            let purpose = if destination == policy.authority {
                4
            } else {
                5
            };
            ensure!(
                grant == identifier(slot.policy, slot.slot, role.role, 2)?
                    && voucher == identifier(slot.policy, slot.slot, role.role, purpose)?
                    && relay == policy.relay
                    && (destination == policy.authority || destination == template.destination)
                    && action == 0
                    && scope == (3, destination)
                    && connections == template.connections
                    && bytes == template.bytes
                    && expires <= at.saturating_add(template.voucher_ms),
                "scoped route exceeds the exact fixed admission template"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Admission/AuthorityAdmissionTests.rs"]
pub(crate) mod tests;
