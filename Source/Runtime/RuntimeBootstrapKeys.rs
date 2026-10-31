// SPDX-License-Identifier: MIT
//! Immutable bootstrap reservations for authority transport and clock identities.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Keys {
    pub authority_transports: BTreeMap<[u8; 32], [u8; 32]>,
    pub clock_monitors: BTreeSet<[u8; 32]>,
    pub route_transports: BTreeMap<u64, ([u8; 32], [u8; 32])>,
}
impl Keys {
    pub fn parse(bytes: &[u8], network: [u8; 32], incarnation: [u8; 32]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let row = value.array(9)?;
        ensure!(
            row[0].uint()? == 131
                && row[1].uint()? == 1
                && row[2].fixed::<32>()? == network
                && row[3].fixed::<32>()? == incarnation
                && row[4].uint()? == 1
                && row[5] == V::Null,
            "Invalid immutable runtime bootstrap context"
        );
        let mut authority_transports = BTreeMap::new();
        let mut previous = None;
        let mut identities = BTreeSet::new();
        for entry in row[6].array(4)? {
            let pair = entry.array(2)?;
            let voter = pair[0].fixed::<32>()?;
            let transport = pair[1].fixed::<32>()?;
            wire::valid_key(&voter)?;
            wire::valid_key(&transport)?;
            ensure!(
                previous.is_none_or(|prior| prior < voter)
                    && identities.insert(voter)
                    && identities.insert(transport),
                "Repeated, overlapping or unsorted authority transport identity"
            );
            previous = Some(voter);
            authority_transports.insert(voter, transport);
        }
        let mut clock_monitors = BTreeSet::new();
        let mut previous = None;
        for entry in row[7].list(4)? {
            let monitor = entry.fixed::<32>()?;
            wire::valid_key(&monitor)?;
            ensure!(
                previous.is_none_or(|prior| prior < monitor) && identities.insert(monitor),
                "Repeated, overlapping or unsorted clock monitor identity"
            );
            previous = Some(monitor);
            clock_monitors.insert(monitor);
        }
        ensure!(
            !clock_monitors.is_empty(),
            "At least one bootstrap clock monitor is required"
        );
        let mut route_transports = BTreeMap::new();
        for (entry, expected) in row[8].array(2)?.iter().zip([2, 3]) {
            let fields = entry.array(3)?;
            let class = fields[0].uint()?;
            let id = fields[1].fixed::<32>()?;
            let key = fields[2].fixed::<32>()?;
            wire::valid_key(&key)?;
            ensure!(
                class == expected
                    && id != [0; 32]
                    && identities.insert(key)
                    && route_transports.values().all(|(old, _)| *old != id),
                "Repeated or invalid immutable route identity"
            );
            route_transports.insert(class, (id, key));
        }
        Ok(Self {
            authority_transports,
            clock_monitors,
            route_transports,
        })
    }

    pub fn reservations(&self) -> impl Iterator<Item = (u64, [u8; 32])> + '_ {
        self.authority_transports
            .values()
            .map(|key| (5, *key))
            .chain(self.clock_monitors.iter().map(|key| (6, *key)))
    }
    pub fn validate_voters(&self, voters: &[[u8; 32]]) -> Result<()> {
        ensure!(
            self.authority_transports
                .keys()
                .copied()
                .eq(voters.iter().copied()),
            "Runtime bootstrap transport mappings differ from the appointed voters"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeBootstrapKeysUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Runtime/RuntimeBootstrapKeys.rs");
