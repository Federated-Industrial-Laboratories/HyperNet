// SPDX-License-Identifier: MIT
//! Bounded content-addressed repair; unknown snapshots never become trusted checkpoints.
use super::{
    Certificate, Configuration, Digest, Engine, Key, Node, Phase, id, insert_certificate,
    insert_command, insert_node, wire,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RECORDS: usize = 32;
pub const MAX_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub kind: u64,
    pub digest: Digest,
    pub signer: Option<Key>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub reference: Reference,
    pub bytes: Vec<u8>,
}
fn reference(config: &Configuration, kind: u64, bytes: &[u8]) -> Result<Reference> {
    if kind == 11 {
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        Ok(Reference {
            kind,
            digest: wire::digest(&payload),
            signer: Some(signatures[0].0),
        })
    } else {
        ensure!(
            matches!(kind, 12 | 14 | 22),
            "Unsupported repair record kind"
        );
        wire::decode(bytes)?;
        Ok(Reference {
            kind,
            digest: if kind == 12 {
                Certificate::parse(config, bytes)?.digest()
            } else {
                wire::digest(bytes)
            },
            signer: None,
        })
    }
}
impl Engine {
    /// Replica transport must authenticate the requester before exposing command references.
    pub fn repair_export(&self, requested: &[Reference]) -> Result<Vec<Item>> {
        self.active()?;
        ensure!(
            requested.len() <= MAX_RECORDS,
            "Repair request count exceeds bound"
        );
        let mut result = Vec::new();
        let mut total = 0usize;
        for wanted in requested {
            ensure!(
                wanted.signer.is_some() == (wanted.kind == 11),
                "Repair signer binding differs"
            );
            let value = match wanted.kind {
                12 | 14 | 22 => {
                    let objects = match wanted.kind {
                        12 => &self.snapshot.certificates,
                        14 => &self.snapshot.nodes,
                        _ => &self.snapshot.commands,
                    };
                    objects
                        .get(&id(&wanted.digest))
                        .map(|object| {
                            super::body(&self.snapshot, object).map(|b| b.as_ref().clone())
                        })
                        .transpose()?
                }
                11 => self
                    .snapshot
                    .votes
                    .values()
                    .find(|bytes| {
                        reference(&self.configuration, 11, bytes).is_ok_and(|r| r == *wanted)
                    })
                    .cloned(),
                _ => anyhow::bail!("Unsupported repair record kind"),
            };
            if let Some(value) = value {
                total = total
                    .checked_add(value.len())
                    .ok_or_else(|| anyhow::anyhow!("Repair size overflow"))?;
                ensure!(total <= MAX_BYTES, "Repair response exceeds byte bound");
                result.push(Item {
                    reference: wanted.clone(),
                    bytes: value.clone(),
                });
            }
        }
        Ok(result)
    }

    pub fn repair_import_with_inputs(
        &mut self,
        requested: &[Reference],
        items: &[Item],
        mut command_inputs: impl FnMut(&[u8]) -> Result<Vec<crate::authority_objects::Reference>>,
    ) -> Result<Vec<Vec<u8>>> {
        self.active()?;
        ensure!(
            requested.len() <= MAX_RECORDS,
            "Repair request count exceeds bound"
        );
        ensure!(
            items.len() <= MAX_RECORDS,
            "Repair response count exceeds bound"
        );
        let total = items.iter().try_fold(0usize, |n, item| {
            n.checked_add(item.bytes.len())
                .ok_or_else(|| anyhow::anyhow!("Repair size overflow"))
        })?;
        ensure!(total <= MAX_BYTES, "Repair response exceeds byte bound");
        let mut received = std::collections::BTreeSet::new();
        for item in items {
            ensure!(
                matches!(item.reference.kind, 12 | 14 | 22),
                "A single vote cannot authorise durable repair"
            );
            ensure!(
                requested.contains(&item.reference) && received.insert(item.reference.clone()),
                "Unrequested or repeated repair record"
            );
            ensure!(
                reference(&self.configuration, item.reference.kind, &item.bytes)? == item.reference,
                "Repair response identity differs"
            );
        }
        // A signature on a vote, execution share or proposed child does not certify
        // that child's ancestry. Validate the entire closure before any publication.
        let staged: BTreeMap<_, _> = items
            .iter()
            .map(|item| (item.reference.clone(), item.bytes.as_slice()))
            .collect();
        let mut pending = Vec::new();
        for item in items.iter().filter(|item| item.reference.kind == 12) {
            Certificate::parse(&self.configuration, &item.bytes)?;
            pending.push(item.reference.clone());
        }
        ensure!(
            !pending.is_empty(),
            "Repair requires quorum-certified roots"
        );
        let mut authorised = BTreeSet::new();
        while let Some(wanted) = pending.pop() {
            if !authorised.insert(wanted.clone()) {
                continue;
            }
            if !self
                .repair_export(std::slice::from_ref(&wanted))?
                .is_empty()
            {
                continue;
            }
            let bytes = staged
                .get(&wanted)
                .ok_or_else(|| anyhow::anyhow!("Certified repair dependency is missing"))?;
            let dependency = |kind, digest| Reference {
                kind,
                digest,
                signer: None,
            };
            match wanted.kind {
                12 => pending.push(dependency(
                    14,
                    Certificate::parse(&self.configuration, bytes)?.node,
                )),
                14 => {
                    let node = Node::parse(&self.configuration, bytes)?;
                    if let Some(parent) = node.parent {
                        pending.push(dependency(14, parent));
                    }
                    if let Some(justify) = node.justify {
                        pending.push(dependency(12, justify));
                    }
                    if let Some(command) = node.command {
                        pending.push(dependency(22, command));
                    }
                }
                22 => {}
                _ => anyhow::bail!("Unsupported certified repair dependency"),
            }
        }
        ensure!(
            items
                .iter()
                .all(|item| authorised.contains(&item.reference)),
            "Repair contains an object outside the certified dependency closure"
        );
        let mut next = self.snapshot.clone();
        for item in items.iter().filter(|item| item.reference.kind == 22) {
            let command = insert_command(&self.configuration, &mut next, &item.bytes)?;
            next.inputs
                .bind_command(command, &command_inputs(&item.bytes)?)?;
        }
        let mut pending: Vec<_> = items
            .iter()
            .filter(|item| matches!(item.reference.kind, 12 | 14))
            .collect();
        while !pending.is_empty() {
            let prior = pending.len();
            pending.retain(|item| {
                match item.reference.kind {
                    12 => {
                        insert_certificate(&self.configuration, &mut next, &item.bytes).map(|_| ())
                    }
                    14 => insert_node(&self.configuration, &mut next, &item.bytes).map(|_| ()),
                    _ => unreachable!(),
                }
                .is_err()
            });
            ensure!(
                pending.len() < prior,
                "Repair has invalid or missing verified dependencies"
            );
        }
        let mut high = super::certificate(&self.configuration, &next, &next.highest_prepare)?;
        for item in items.iter().filter(|item| item.reference.kind == 12) {
            let qc = Certificate::parse(&self.configuration, &item.bytes)?;
            if qc.phase == Phase::Prepare && qc.view > high.view {
                high = qc;
            }
        }
        next.highest_prepare = high.digest();
        if next.nodes.len() != self.snapshot.nodes.len()
            || next.commands.len() != self.snapshot.commands.len()
            || next.certificates.len() != self.snapshot.certificates.len()
            || next.highest_prepare != self.snapshot.highest_prepare
        {
            self.persist(next)?;
        }
        for item in items.iter().filter(|item| item.reference.kind == 12) {
            let qc = Certificate::parse(&self.configuration, &item.bytes)?;
            if qc.phase == Phase::Commit {
                self.decide(&item.bytes)?;
            }
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusRepair.rs");
