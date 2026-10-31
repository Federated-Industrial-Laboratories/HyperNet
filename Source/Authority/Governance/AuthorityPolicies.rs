// SPDX-License-Identifier: MIT
// Network policy successors bind exact predecessors and separate old and new custody approval.
use crate::{
    authority_governance::{Governance, Requirement},
    authority_membership::{Snapshot, reference},
    authority_proof::{Digest, Intent, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
pub fn key_fingerprint(key: &Key) -> Digest {
    Sha256::digest(key).into()
}
use std::collections::{BTreeMap, BTreeSet};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let x = v.fixed()?;
    ensure!(x != [0; 32], "zero policy identifier");
    Ok(x)
}
fn ids(v: &V, max: usize) -> Result<Vec<Digest>> {
    let x = v.list(max)?.iter().map(id).collect::<Result<Vec<_>>>()?;
    ensure!(
        !x.is_empty() && x.windows(2).all(|p| p[0] < p[1]),
        "policy identifiers must be sorted and distinct"
    );
    Ok(x)
}
pub fn record_reference(
    bytes: &[u8],
    network: Digest,
    incarnation: Digest,
    kind: u64,
) -> Result<VersionRef> {
    let value = wire::decode(bytes)?;
    let f = value.array(if kind == 100 { 17 } else { 13 })?;
    ensure!(
        matches!(kind, 100 | 114)
            && f[0].uint()? == kind
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == network
            && f[3].fixed::<32>()? == incarnation
            && f[4].uint()? > 0,
        "policy record context differs"
    );
    if f[4].uint()? == 1 {
        f[5].null()?;
    } else {
        id(&f[5])?;
    }
    Ok(VersionRef {
        kind,
        id: network,
        generation: f[4].uint()?,
        digest: wire::digest(bytes),
    })
}
#[derive(Clone, Debug)]
pub struct Custody {
    pub reference: VersionRef,
    pub mode: u64,
    pub threshold: usize,
    pub keys: Vec<(Digest, Key)>,
    pub immutable: bool,
    pub accepted: Vec<Digest>,
}
impl Custody {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let reference = record_reference(bytes, n, i, 114)?;
        let v = wire::decode(bytes)?;
        let f = v.array(13)?;
        let mode = f[6].uint()?;
        let threshold = usize::try_from(f[7].uint()?)?;
        let principals = ids(&f[8], 3)?;
        let keys = f[9]
            .list(3)?
            .iter()
            .map(|v| {
                let p = v.array(2)?;
                let k = p[1].fixed()?;
                wire::valid_key(&k)?;
                Ok((id(&p[0])?, k))
            })
            .collect::<Result<Vec<_>>>()?;
        let immutable = f[10].boolean()?;
        let accepted = ids(&f[11], 3)?;
        ensure!(
            mode <= 2
                && threshold == if mode == 0 { 1 } else { 2 }
                && keys.len() == if mode == 0 { 1 } else { 3 }
                && principals.len() == if mode == 2 { 3 } else { 1 }
                && keys.windows(2).all(|p| p[0] < p[1])
                && keys.iter().map(|(_, k)| *k).collect::<BTreeSet<_>>().len() == keys.len()
                && keys.iter().map(|(p, _)| *p).collect::<BTreeSet<_>>()
                    == principals.into_iter().collect()
                && (!immutable || mode == 2)
                && accepted.len() >= threshold
                && accepted
                    .iter()
                    .all(|x| keys.iter().any(|(_, k)| key_fingerprint(k) == *x)),
            "invalid recovery custody or acceptance set"
        );
        if f[12] != V::Null {
            Snapshot::parse(&f[12])?;
        } else {
            ensure!(
                reference.generation == 1,
                "updated recovery policy lacks snapshot"
            );
        }
        Ok(Self {
            reference,
            mode,
            threshold,
            keys,
            immutable,
            accepted,
        })
    }
    pub fn verify(&self, payload: &[u8], envelope: &[u8], accepting: bool) -> Result<()> {
        let (p, signatures) = wire::envelope(envelope, 3)?;
        ensure!(
            p == payload
                && signatures.len() >= self.threshold
                && signatures
                    .iter()
                    .all(|(key, _)| self.keys.iter().any(|(_, k)| k == key)),
            "recovery threshold requires distinct authorised signatures over the exact proposal"
        );
        if accepting {
            ensure!(
                signatures
                    .iter()
                    .map(|(k, _)| key_fingerprint(k))
                    .collect::<BTreeSet<_>>()
                    == self.accepted.iter().copied().collect(),
                "new custody signatures differ from declared acceptance"
            );
        }
        Ok(())
    }
    pub fn weaker_than(&self, old: &Self) -> bool {
        self.threshold < old.threshold || old.mode == 2 && self.mode != 2
    }
}

#[derive(Clone)]
pub struct Operation {
    pub grant: Digest,
    pub previous_policy: Vec<u8>,
    pub previous_recovery: Vec<u8>,
    pub policy: Vec<u8>,
    pub recovery: Vec<u8>,
    pub old_authorisation: Option<Vec<u8>>,
    pub new_acceptance: Option<Vec<u8>>,
    pub snapshot: Snapshot,
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        action == "AuthorityPolicyApply"
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        let v = wire::decode(&intent.parameters)?;
        let f = v.array(11)?;
        ensure!(
            Self::handles(&intent.action)
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == intent.action
                && intent.profile_generation == 0,
            "policy action context differs"
        );
        let optional = |v: &V| {
            if *v == V::Null {
                Ok(None)
            } else {
                Ok::<_, anyhow::Error>(Some(v.bytes()?.to_vec()))
            }
        };
        let out = Self {
            grant: id(&f[3])?,
            previous_policy: f[4].bytes()?.to_vec(),
            previous_recovery: f[5].bytes()?.to_vec(),
            policy: f[6].bytes()?.to_vec(),
            recovery: f[7].bytes()?.to_vec(),
            old_authorisation: optional(&f[8])?,
            new_acceptance: optional(&f[9])?,
            snapshot: Snapshot::parse(&f[10])?,
        };
        let old = record_reference(
            &out.previous_policy,
            intent.network,
            intent.incarnation,
            100,
        )?;
        let new = record_reference(&out.policy, intent.network, intent.incarnation, 100)?;
        ensure!(
            intent.resource == intent.network
                && intent.revision == new.generation
                && old.generation.checked_add(1) == Some(new.generation)
                && intent.expected == out.snapshot.references
                && intent.minimum_policy_epoch == out.snapshot.epoch
                && intent.minimum_policy_height == out.snapshot.height,
            "policy proposal differs from signed predecessor snapshot"
        );
        out.validate(intent.network, intent.incarnation)?;
        Ok(out)
    }
    #[allow(
        dead_code,
        reason = "The Suite imports inspected proposals through the shared decoder."
    )]
    pub fn decode(bytes: &[u8], n: Digest, i: Digest, signed: bool) -> Result<Self> {
        let v = wire::decode(bytes)?;
        let f = v.array(11)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityPolicyApply",
            "invalid policy proposal"
        );
        let optional = |v: &V| {
            if *v == V::Null {
                Ok(None)
            } else {
                Ok::<_, anyhow::Error>(Some(v.bytes()?.to_vec()))
            }
        };
        let out = Self {
            grant: id(&f[3])?,
            previous_policy: f[4].bytes()?.to_vec(),
            previous_recovery: f[5].bytes()?.to_vec(),
            policy: f[6].bytes()?.to_vec(),
            recovery: f[7].bytes()?.to_vec(),
            old_authorisation: optional(&f[8])?,
            new_acceptance: optional(&f[9])?,
            snapshot: Snapshot::parse(&f[10])?,
        };
        out.validate_inner(n, i, signed)?;
        Ok(out)
    }

    pub fn validate(&self, n: Digest, i: Digest) -> Result<()> {
        self.validate_inner(n, i, true)
    }

    fn validate_inner(&self, n: Digest, i: Digest, signatures: bool) -> Result<()> {
        let old = record_reference(&self.previous_policy, n, i, 100)?;
        let new = record_reference(&self.policy, n, i, 100)?;
        let old_c = Custody::parse(&self.previous_recovery, n, i)?;
        let new_c = Custody::parse(&self.recovery, n, i)?;
        let p = wire::decode(&self.policy)?;
        let p = p.array(17)?;
        ensure!(
            old.generation.checked_add(1) == Some(new.generation)
                && p[5].fixed::<32>()? == old.digest
                && p[12] == reference(&new_c.reference)
                && p[16] == self.snapshot.value
                && self.snapshot.references.contains(&old)
                && self.snapshot.references.contains(&old_c.reference),
            "policy predecessor, recovery reference or snapshot differs"
        );
        // Existing root grants remain authoritative only when the exact resulting governance validates.
        let refs = Governance::record_versions(n, i, std::slice::from_ref(&self.policy))?;
        ensure!(refs == vec![new], "invalid network policy");
        if self.previous_recovery == self.recovery {
            ensure!(
                self.old_authorisation.is_none() && self.new_acceptance.is_none(),
                "unchanged custody cannot carry replacement approval"
            );
        } else {
            let c = wire::decode(&self.recovery)?;
            let c = c.array(13)?;
            ensure!(
                old_c.reference.generation.checked_add(1) == Some(new_c.reference.generation)
                    && c[5].fixed::<32>()? == old_c.reference.digest
                    && c[12] == self.snapshot.value,
                "recovery successor differs from exact predecessor"
            );
            ensure!(
                !old_c.immutable
                    || new_c.mode == 2 && new_c.immutable && !new_c.weaker_than(&old_c),
                "NewNetworkRequired: immutable shared recovery cannot weaken"
            );
            if signatures {
                old_c.verify(
                    &self.recovery,
                    self.old_authorisation
                        .as_deref()
                        .context("current custody approval missing")?,
                    false,
                )?;
                new_c.verify(
                    &self.recovery,
                    self.new_acceptance
                        .as_deref()
                        .context("new custody acceptance missing")?,
                    true,
                )?;
            }
        }
        Ok(())
    }
    pub fn replacements(&self, n: Digest, i: Digest) -> Result<Vec<(VersionRef, VersionRef)>> {
        let mut result = vec![(
            record_reference(&self.previous_policy, n, i, 100)?,
            record_reference(&self.policy, n, i, 100)?,
        )];
        if self.previous_recovery != self.recovery {
            result.push((
                record_reference(&self.previous_recovery, n, i, 114)?,
                record_reference(&self.recovery, n, i, 114)?,
            ));
        }
        Ok(result)
    }
    pub fn apply_records(&self, records: &[Vec<u8>], n: Digest, i: Digest) -> Result<Vec<Vec<u8>>> {
        let mut selected = Governance::record_versions(n, i, records)?
            .into_iter()
            .zip(records.iter().cloned())
            .map(|(r, v)| (r.index(), v))
            .collect::<BTreeMap<_, _>>();
        selected.insert((100, n), self.policy.clone());
        selected.insert((114, n), self.recovery.clone());
        let out = selected.into_values().collect::<Vec<_>>();
        Governance::parse(n, i, &out)?;
        Ok(out)
    }
}
pub fn custody_dependencies(
    governance: &Governance,
    old: &Custody,
    principals: &[Digest],
    at: u64,
) -> Result<Vec<VersionRef>> {
    let mut dependencies = Vec::new();
    for principal in principals {
        if old.keys.iter().any(|(p, _)| p == principal) {
            continue;
        }
        let bytes = governance
            .record_bytes(125, *principal)
            .context("new recovery custodian must be an enrolled principal")?;
        let value = wire::decode(bytes)?;
        let f = value.array(12)?;
        let span = f[8].array(2)?;
        ensure!(
            !f[9].boolean()?
                && at
                    .checked_sub(crate::authority_governance::UNCERTAINTY_MS)
                    .is_some_and(|t| span[0].uint().is_ok_and(|start| t >= start))
                && at
                    .checked_add(crate::authority_governance::UNCERTAINTY_MS)
                    .is_some_and(|t| span[1].uint().is_ok_and(|end| t < end)),
            "new recovery custodian membership is expired or revoked"
        );
        dependencies.push(
            governance
                .versions()
                .into_iter()
                .find(|r| r.kind == 125 && r.id == *principal)
                .context("custodian membership reference absent")?,
        );
    }
    dependencies.sort_by_key(VersionRef::index);
    dependencies.dedup();
    Ok(dependencies)
}
pub struct Decision {
    pub code: u64,
    pub expires_ms: u64,
    pub not_before_ms: u64,
    pub versions: Vec<VersionRef>,
    pub records: Option<Vec<Vec<u8>>>,
    pub value: V,
}
pub fn authorise(
    operation: &Operation,
    records: &[Vec<u8>],
    reserved: &crate::authority_membership::Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
) -> Result<Decision> {
    operation.validate(intent.network, intent.incarnation)?;
    let governance = Governance::parse(intent.network, intent.incarnation, records)?;
    let mut decision = Decision {
        code: 0,
        expires_ms: u64::MAX,
        not_before_ms: 0,
        versions: vec![],
        records: None,
        value: V::Null,
    };
    let replacements = operation.replacements(intent.network, intent.incarnation)?;
    if replacements.iter().any(|(old, new)| {
        !governance
            .versions()
            .contains(if replay { new } else { old })
    }) || governance.record_bytes(127, intent.requester).is_ok()
    {
        decision.code = 12;
        return Ok(decision);
    }
    let mut permission_records = records.to_vec();
    if replay {
        for bytes in &mut permission_records {
            let f = wire::decode(bytes)?;
            let kind = f.list(32)?[0].uint()?;
            if kind == 100 {
                *bytes = operation.previous_policy.clone();
            } else if kind == 114 {
                *bytes = operation.previous_recovery.clone();
            }
        }
    }
    let permission = Governance::parse(intent.network, intent.incarnation, &permission_records)?;
    let cap = permission.capability(
        operation.grant,
        &Requirement {
            subject: intent.requester,
            actions: &[9],
            scope: (0, intent.network),
            namespace: None,
            usage: [0, 1, 0, 1],
            evaluated_at_ms: at,
            expected: &intent.expected,
        },
    );
    let cap = match cap {
        Ok(c) => c,
        Err(_) => {
            decision.code = 3;
            return Ok(decision);
        }
    };
    let mut expected = cap.dependencies.clone();
    expected.push(record_reference(
        &operation.previous_recovery,
        intent.network,
        intent.incarnation,
        114,
    )?);
    let old_custody = Custody::parse(
        &operation.previous_recovery,
        intent.network,
        intent.incarnation,
    )?;
    let new_custody = Custody::parse(&operation.recovery, intent.network, intent.incarnation)?;
    let principals = new_custody.keys.iter().map(|(p, _)| *p).collect::<Vec<_>>();
    match custody_dependencies(&permission, &old_custody, &principals, at) {
        Ok(extra) => expected.extend(extra),
        Err(_) => {
            decision.code = 3;
            return Ok(decision);
        }
    }
    expected.sort_by_key(VersionRef::index);
    expected.dedup();
    if expected != intent.expected {
        decision.code = 12;
        return Ok(decision);
    }
    if !replay && operation.previous_recovery != operation.recovery {
        let old = Custody::parse(
            &operation.previous_recovery,
            intent.network,
            intent.incarnation,
        )?;
        let new = Custody::parse(&operation.recovery, intent.network, intent.incarnation)?;
        // Exact replay already proved both committed successors above. Their keys
        // are now reserved by this same change; fresh proposals cannot reuse them.
        if new.keys.iter().any(|(_, key)| {
            !old.keys.iter().any(|(_, k)| k == key) && reserved.0.iter().any(|(_, k)| k == key)
        }) {
            decision.code = 3;
            return Ok(decision);
        }
    }
    let updated = operation.apply_records(records, intent.network, intent.incarnation)?;
    for (old, new) in replacements {
        expected.retain(|r| r.index() != old.index());
        expected.push(new);
    }
    expected.sort_by_key(VersionRef::index);
    decision.expires_ms = cap.expires_ms;
    decision.not_before_ms = cap.not_before_ms;
    decision.versions = expected;
    decision.records = (!replay).then_some(updated);
    decision.value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityPolicyApply".into()),
        a(decision.versions.iter().map(reference).collect()),
        a(vec![b(&operation.policy), b(&operation.recovery)]),
    ]);
    Ok(decision)
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Governance/AuthorityPoliciesTests.rs"]
pub(crate) mod tests;

#[cfg(test)]
include!("../../../Tests/Support/Authority/Governance/AuthorityPolicies.rs");
