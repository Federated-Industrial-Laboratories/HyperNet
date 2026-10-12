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
        let historical =
            config.evidence_context(intent.minimum_policy_epoch, self.height, self.at, height)?;
        let operation = transactions::Operation::parse(&intent, &historical)?;
        let (records, snapshot) = match operation {
            transactions::Operation::Deployment(deployment) => {
                if let crate::authority_deployments::Operation::Register { offer, .. } = &deployment
                {
                    ensure!(
                        offer.current(self.at)?,
                        "historical deployment offer was not current"
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
                && snapshot.height.checked_add(1) == Some(self.height)
                && intent.minimum_policy_epoch == snapshot.epoch
                && intent.minimum_policy_height == snapshot.height
                && wire::digest(record) == self.created.digest
                && self.created.generation == 1,
            "mutation evidence derivation or position differs"
        );
        let fields = wire::decode(record)?;
        let fields = fields.list(32)?;
        let kind = fields[0].uint()?;
        let id = if matches!(kind, 126 | 128) {
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
        if self.created.kind == 129 {
            crate::authority_capacity::MAX_DEPLOYMENT_EVIDENCE
        } else {
            crate::authority_capacity::MAX_OTHER_EVIDENCE
        }
    }
}
impl Evidence {
    #[cfg(test)]
    pub(super) fn at_capacity() -> Self {
        // Synthetic bytes are only for capacity preflight. Historical evidence
        // validation still requires a signed mutation and its exact derivation.
        let maximum = crate::authority_capacity::MAX_OTHER_EVIDENCE;
        let total = crate::authority_capacity::MAX_EVIDENCE_BYTES;
        let mut entries = Vec::new();
        for seed in 0..total.div_ceil(maximum) {
            let mut entry = Entry {
                created: VersionRef {
                    kind: 102,
                    id: wire::digest(&(seed as u64).to_be_bytes()),
                    generation: 1,
                    digest: [1; 32],
                },
                signed: vec![0; maximum],
                height: 1,
                at: 1000,
            };
            let excess = wire::encode(&entry.value()).unwrap().len() - maximum;
            entry.signed.truncate(entry.signed.len() - excess);
            assert_eq!(wire::encode(&entry.value()).unwrap().len(), maximum);
            entries.push(entry);
        }
        entries.sort_by_key(|entry| entry.created.index());
        let mut evidence = Self(entries);
        let excess = wire::encode_state(&evidence.value()).unwrap().len() - total;
        let last = evidence.0.last_mut().unwrap();
        last.signed.truncate(last.signed.len() - excess);
        assert_eq!(evidence.charge().unwrap(), total);
        evidence
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
                .all(|v| v[0].created.index() < v[1].created.index()),
            "mutation provenance is duplicate or unsorted"
        );
        let mut derived = std::collections::BTreeMap::new();
        for entry in &result.0 {
            for bytes in entry.validate(config, height)? {
                let value = wire::decode(&bytes)?;
                let f = value.list(32)?;
                let kind = f[0].uint()?;
                let id = match kind {
                    105 => f[7].fixed()?,
                    126 | 128 => version(&f[6])?.id,
                    _ => f[6].fixed()?,
                };
                ensure!(
                    derived.insert((kind, id), bytes).is_none(),
                    "duplicate mutation provenance output"
                );
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
        ensure!(
            !self.0.iter().any(|e| e.created.index() == created.index()),
            "mutation provenance already exists"
        );
        self.0.push(Entry {
            created,
            signed: signed.to_vec(),
            height,
            at,
        });
        self.0.sort_by_key(|e| e.created.index());
        self.charge()?;
        Ok(())
    }
}
