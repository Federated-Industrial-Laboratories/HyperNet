// SPDX-License-Identifier: MIT
// Provenance survives stream acknowledgement without re-evaluating historical authority.
use super::{array, b, reference, transactions};
use crate::{
    authority_membership::{Mutation, current, version},
    authority_proof::{Intent, VersionRef},
    consensus::records::Configuration,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};

#[derive(Clone, Default)]
pub(super) struct Evidence(Vec<Entry>);
#[derive(Clone)]
struct Entry {
    created: VersionRef,
    signed: Vec<u8>,
    height: u64,
    at: u64,
}
impl Entry {
    fn value(&self) -> V {
        array(vec![
            reference(&self.created),
            b(&self.signed),
            V::Uint(self.height),
            V::Uint(self.at),
        ])
    }
    fn validate(&self, config: &Configuration, height: u64) -> Result<Vec<Vec<u8>>> {
        ensure!(
            wire::encode(&self.value())?.len() <= self.maximum()
                && self.height > 0
                && self.at >= config.bootstrap_origin_time,
            "mutation provenance bounds differ"
        );
        let intent = Intent::from_signed(&self.signed)?;
        let intent = if crate::authority_grant_review::Operation::handles(&intent.action) {
            let reviewed = crate::authority_grant_review::Operation::parse(&intent)?;
            ensure!(reviewed.apply, "grant evidence names a preview");
            reviewed.inner
        } else {
            intent
        };
        let historical =
            config.evidence_context(intent.minimum_policy_epoch, self.height, self.at, height)?;
        let operation = transactions::Operation::parse(&intent, &historical)?;
        let (records, snapshot) = match operation {
            transactions::Operation::Policy(policy) => {
                let mut records = Vec::new();
                if policy.recovery != policy.previous_recovery {
                    records.push(policy.recovery.clone());
                }
                records.push(policy.policy.clone());
                (records, policy.snapshot.clone())
            }
            transactions::Operation::Tier(tier) => (
                vec![
                    tier.derive(&intent)?
                        .context("tier evidence names a read")?,
                ],
                tier.snapshot().clone(),
            ),
            transactions::Operation::Deployment(deployment) => {
                if let crate::authority_deployments::Operation::Register {
                    offer, historical, ..
                } = &deployment
                {
                    ensure!(
                        if *historical {
                            offer.manifest.generation > 1 && self.at >= offer.manifest.validity.1
                        } else {
                            offer.current(self.at)?
                        },
                        "deployment offer differs from its committed current or historical validity"
                    );
                }
                let snapshot = deployment
                    .snapshot()
                    .context("deployment audit names a read")?
                    .clone();
                (deployment.derive(&intent)?, snapshot)
            }
            transactions::Operation::Application(application) => {
                if let crate::authority_applications::Operation::Register { acceptance, .. } =
                    &application
                {
                    ensure!(
                        current(self.at, acceptance.validity)
                            && current(self.at, acceptance.acceptance_validity),
                        "historical application acceptance was not current"
                    );
                }
                if let crate::authority_applications::Operation::Renew { consent, .. } =
                    &application
                {
                    ensure!(
                        current(self.at, consent.validity)
                            && current(self.at, consent.acceptance_validity),
                        "historical application renewal was not current"
                    );
                }
                (
                    vec![
                        application
                            .derive(&intent)?
                            .context("application audit names a read")?,
                    ],
                    application
                        .snapshot()
                        .context("application audit has no snapshot")?
                        .clone(),
                )
            }
            transactions::Operation::Mutation(mutation) => {
                if let Mutation::Admit { acceptance, .. } = &mutation {
                    ensure!(
                        current(self.at, acceptance.validity)
                            && current(self.at, acceptance.acceptance_validity),
                        "historical acceptance was not current"
                    );
                }
                if let Mutation::Delegate { child, .. } = &mutation {
                    ensure!(
                        current(self.at, child.validity),
                        "historical delegation was not current"
                    );
                }
                (vec![mutation.derive(&intent)?], mutation.snapshot().clone())
            }
            transactions::Operation::Revoke {
                target, snapshot, ..
            } => {
                let record = wire::encode(&array(vec![
                    V::Uint(126),
                    V::Uint(1),
                    b(&intent.network),
                    b(&intent.incarnation),
                    V::Uint(1),
                    V::Null,
                    reference(&target),
                    b(&intent.requester),
                    snapshot.clone(),
                ]))?;
                (
                    vec![record],
                    crate::authority_membership::Snapshot::parse(&snapshot)?,
                )
            }
            _ => anyhow::bail!("mutation evidence names a non-creation action"),
        };
        let record = records.last().context("mutation audit derives no record")?;
        ensure!(
            snapshot.epoch == historical.scope.epoch
                && snapshot.height < self.height
                && intent.minimum_policy_epoch == snapshot.epoch
                && intent.minimum_policy_height == snapshot.height
                && wire::digest(record) == self.created.digest
                && (matches!(self.created.kind, 100 | 101 | 127 | 129)
                    || self.created.generation == 1),
            "mutation evidence derivation or position differs"
        );
        let fields = wire::decode(record)?;
        let fields = fields.list(32)?;
        let kind = fields[0].uint()?;
        let id = if matches!(kind, 100 | 114) {
            config.scope.network
        } else if matches!(kind, 126 | 128) {
            version(&fields[6])?.id
        } else {
            fields[6].fixed()?
        };
        ensure!(
            kind == self.created.kind && id == self.created.id,
            "mutation evidence target differs"
        );
        Ok(records)
    }
    fn maximum(&self) -> usize {
        if matches!(self.created.kind, 100 | 129) {
            crate::authority_capacity::MAX_DEPLOYMENT_EVIDENCE
        } else {
            crate::authority_capacity::MAX_OTHER_EVIDENCE
        }
    }
}
impl Evidence {
    pub fn genesis_tier(
        value: &V,
        id: [u8; 32],
        network: [u8; 32],
        incarnation: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        for item in value.list(crate::authority_capacity::MAX_RECORDS)? {
            let f = item.array(4)?;
            let reference = version(&f[0])?;
            if reference.kind != 101 || reference.id != id {
                continue;
            }
            let intent = Intent::from_signed(f[1].bytes()?)?;
            let operation = crate::authority_tiers::Operation::parse(&intent)?;
            if let Some(previous) = operation.previous() {
                let (_, old) =
                    crate::authority_tiers::Spec::from_record(previous, network, incarnation)?;
                let decoded = wire::decode(previous)?;
                if old.generation == 1 && decoded.array(14)?[13] == V::Null {
                    return Ok(Some(previous.to_vec()));
                }
            }
        }
        Ok(None)
    }
    pub fn genesis_policy(
        value: &V,
        kind: u64,
        network: [u8; 32],
        incarnation: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        ensure!(matches!(kind, 100 | 114), "unsupported genesis policy kind");
        for item in value.list(crate::authority_capacity::MAX_RECORDS)? {
            let f = item.array(4)?;
            let r = version(&f[0])?;
            if r.kind != 100 || r.id != network {
                continue;
            }
            let intent = Intent::from_signed(f[1].bytes()?)?;
            let operation = crate::authority_policies::Operation::parse(&intent)?;
            let bytes = if kind == 100 {
                &operation.previous_policy
            } else {
                &operation.previous_recovery
            };
            let old =
                crate::authority_policies::record_reference(bytes, network, incarnation, kind)?;
            let v = wire::decode(bytes)?;
            if old.generation == 1 && v.list(17)?.last() == Some(&V::Null) {
                return Ok(Some(bytes.clone()));
            }
        }
        Ok(None)
    }
    pub fn recovery_reservations(
        &self,
        base: &crate::authority_membership::Reservations,
    ) -> Result<crate::authority_membership::Reservations> {
        let mut keys = base
            .0
            .iter()
            .map(|(role, key)| (*key, *role))
            .collect::<std::collections::BTreeMap<_, _>>();
        for entry in self.0.iter().filter(|e| e.created.kind == 100) {
            let intent = Intent::from_signed(&entry.signed)?;
            let operation = crate::authority_policies::Operation::parse(&intent)?;
            for bytes in [&operation.previous_recovery, &operation.recovery] {
                let custody = crate::authority_policies::Custody::parse(
                    bytes,
                    intent.network,
                    intent.incarnation,
                )?;
                for (_, key) in custody.keys {
                    ensure!(
                        keys.get(&key).is_none_or(|role| *role == 1),
                        "recovery custody reuses another dedicated role key"
                    );
                    keys.insert(key, 1);
                }
            }
        }
        let mut entries = keys
            .into_iter()
            .map(|(key, role)| (role, key))
            .collect::<Vec<_>>();
        entries.sort();
        Ok(crate::authority_membership::Reservations(entries))
    }
    pub fn creation_height(&self, created: &VersionRef) -> Result<u64> {
        self.0
            .iter()
            .find(|entry| entry.created == *created)
            .map(|entry| entry.height)
            .context("creation provenance is absent")
    }

    pub fn value(&self) -> V {
        array(self.0.iter().map(Entry::value).collect())
    }
    pub fn charge(&self) -> Result<usize> {
        let bytes = wire::encode_state(&self.value())?.len();
        ensure!(
            self.0.len() <= crate::authority_capacity::MAX_RECORDS
                && bytes <= crate::authority_capacity::MAX_EVIDENCE_BYTES
                && self
                    .0
                    .iter()
                    .all(|e| wire::encode(&e.value()).is_ok_and(|v| v.len() <= e.maximum())),
            "mutation provenance capacity exceeded"
        );
        Ok(bytes)
    }
    pub fn parse(
        config: &Configuration,
        value: &V,
        height: u64,
        created: &[(VersionRef, Vec<u8>)],
    ) -> Result<Self> {
        let mut entries = Vec::new();
        for item in value.list(crate::authority_capacity::MAX_RECORDS)? {
            let f = item.array(4)?;
            entries.push(Entry {
                created: version(&f[0])?,
                signed: f[1].bytes()?.to_vec(),
                height: f[2].uint()?,
                at: f[3].uint()?,
            });
        }
        let result = Self(entries);
        result.charge()?;
        ensure!(
            result
                .0
                .windows(2)
                .all(|v| (v[0].created.index(), v[0].created.generation)
                    < (v[1].created.index(), v[1].created.generation)),
            "mutation provenance is duplicate or unsorted"
        );
        let mut derived: std::collections::BTreeMap<(u64, [u8; 32]), Vec<u8>> =
            std::collections::BTreeMap::new();
        for entry in &result.0 {
            for bytes in entry.validate(config, height)? {
                let value = wire::decode(&bytes)?;
                let f = value.list(32)?;
                let kind = f[0].uint()?;
                let id = match kind {
                    100 | 114 => config.scope.network,
                    105 => f[7].fixed()?,
                    126 | 128 => version(&f[6])?.id,
                    _ => f[6].fixed()?,
                };
                if kind == 101 {
                    let intent = Intent::from_signed(&entry.signed)?;
                    let tier = crate::authority_tiers::Operation::parse(&intent)?;
                    let prior = tier.previous();
                    if let Some(previous) = prior {
                        let (_, old) = crate::authority_tiers::Spec::from_record(
                            previous,
                            config.scope.network,
                            config.scope.incarnation,
                        )?;
                        ensure!(
                            old.generation.checked_add(1) == Some(entry.created.generation)
                                && f[5].fixed::<32>()? == old.digest,
                            "tier provenance does not extend its exact predecessor"
                        );
                        if let Some(retained) = derived.get(&(kind, id)) {
                            ensure!(
                                retained.as_slice() == previous,
                                "tier provenance history forked"
                            );
                        } else {
                            let old_value = wire::decode(previous)?;
                            ensure!(
                                old.generation == 1 && old_value.array(14)?[13] == V::Null,
                                "tier provenance begins outside authenticated genesis"
                            );
                        }
                    } else {
                        ensure!(
                            entry.created.generation == 1 && !derived.contains_key(&(kind, id)),
                            "tier provenance creation repeats"
                        );
                    }
                    derived.insert((kind, id), bytes);
                } else if matches!(kind, 100 | 114) {
                    let intent = Intent::from_signed(&entry.signed)?;
                    let policy = crate::authority_policies::Operation::parse(&intent)?;
                    let previous = if kind == 100 {
                        &policy.previous_policy
                    } else {
                        &policy.previous_recovery
                    };
                    let old = crate::authority_policies::record_reference(
                        previous,
                        config.scope.network,
                        config.scope.incarnation,
                        kind,
                    )?;
                    ensure!(
                        f[4].uint()?
                            == old
                                .generation
                                .checked_add(1)
                                .context("policy generation exhausted")?
                            && f[5].fixed::<32>()? == old.digest,
                        "policy provenance does not extend exact predecessor"
                    );
                    if let Some(retained) = derived.get(&(kind, id)) {
                        ensure!(retained == previous, "policy provenance history forked");
                    } else {
                        ensure!(
                            old.generation == 1
                                && wire::decode(previous)?.list(17)?.last() == Some(&V::Null),
                            "policy provenance begins outside authenticated genesis"
                        );
                    }
                    derived.insert((kind, id), bytes);
                } else if matches!(kind, 105 | 117 | 129) {
                    if let Some(previous) = derived.get(&(kind, id)) {
                        let previous_fields = wire::decode(previous)?;
                        let previous_fields = previous_fields.list(32)?;
                        ensure!(
                            previous_fields[4].uint()?.checked_add(1) == Some(f[4].uint()?)
                                && f[5].fixed::<32>()? == wire::digest(previous),
                            "deployment provenance does not extend exact predecessor"
                        );
                        if kind == 129 {
                            let prior = crate::runtime_manifest::Manifest::parse(
                                previous_fields[17].bytes()?,
                            )?;
                            let current = crate::runtime_manifest::Manifest::parse(f[17].bytes()?)?;
                            current.successor_of(&prior)?;
                        }
                    } else {
                        ensure!(
                            f[4].uint()? == 1 && f[5] == V::Null,
                            "deployment provenance begins without initial registration"
                        );
                    }
                    derived.insert((kind, id), bytes);
                } else {
                    ensure!(
                        derived.insert((kind, id), bytes).is_none(),
                        "duplicate mutation provenance output"
                    );
                }
            }
        }
        ensure!(
            derived.len() == created.len(),
            "mutation provenance is missing or extra"
        );
        for (reference, bytes) in created {
            ensure!(
                derived.get(&reference.index()) == Some(bytes),
                "mutation provenance differs from retained record"
            );
        }
        Ok(result)
    }
    pub fn deployment_offer(&self, deployment: [u8; 32]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let Some(entry) = self
            .0
            .iter()
            .rev()
            .find(|e| e.created.kind == 129 && e.created.id == deployment)
        else {
            return Ok(None);
        };
        let intent = Intent::from_signed(&entry.signed)?;
        let operation = crate::authority_deployments::Operation::parse(&intent)?;
        if let crate::authority_deployments::Operation::Register { offer, .. } = operation {
            Ok(Some((offer.manifest_bytes, offer.consent)))
        } else {
            anyhow::bail!("deployment provenance names another action")
        }
    }
    pub fn insert(
        &mut self,
        created: VersionRef,
        signed: &[u8],
        height: u64,
        at: u64,
    ) -> Result<()> {
        if created.kind == 127 && created.generation > 1 {
            let intent = Intent::from_signed(signed)?;
            let crate::authority_applications::Operation::Renew { consent, .. } =
                crate::authority_applications::Operation::parse(&intent)?
            else {
                anyhow::bail!("application evidence replacement is not a renewal");
            };
            ensure!(
                self.0.iter().any(|e| e.created == consent.admission)
                    && consent.admission.generation.checked_add(1) == Some(created.generation),
                "application evidence replacement skips its current predecessor"
            );
            self.0.retain(|e| e.created.index() != created.index());
        }
        ensure!(
            !self.0.iter().any(|e| e.created.index() == created.index()
                && (!matches!(created.kind, 100 | 101 | 129)
                    || e.created.generation == created.generation)),
            "mutation provenance already exists"
        );
        self.0.push(Entry {
            created,
            signed: signed.to_vec(),
            height,
            at,
        });
        self.0
            .sort_by_key(|e| (e.created.index(), e.created.generation));
        self.charge()?;
        Ok(())
    }
}

#[cfg(test)]
include!("../../Tests/Support/Authority/AuthorityMutationEvidence.rs");
