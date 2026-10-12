// SPDX-License-Identifier: MIT
//! Immutable bootstrap reservations for authority transport and clock identities.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Keys {
    pub authority_transports: BTreeMap<[u8; 32], [u8; 32]>,
    pub clock_monitors: BTreeSet<[u8; 32]>,
}
impl Keys {
    pub fn parse(bytes: &[u8], network: [u8; 32], incarnation: [u8; 32]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let row = value.array(8)?;
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
        Ok(Self {
            authority_transports,
            clock_monitors,
        })
    }
    #[cfg(test)]
    pub fn encode(&self, network: [u8; 32], incarnation: [u8; 32]) -> Result<Vec<u8>> {
        let b = |id: &[u8; 32]| V::Bytes(id.to_vec());
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(131),
            V::Uint(1),
            b(&network),
            b(&incarnation),
            V::Uint(1),
            V::Null,
            V::Array(
                self.authority_transports
                    .iter()
                    .map(|(voter, transport)| V::Array(vec![b(voter), b(transport)]))
                    .collect(),
            ),
            V::Array(self.clock_monitors.iter().map(b).collect()),
        ]))?;
        Self::parse(&bytes, network, incarnation)?;
        Ok(bytes)
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
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[test]
    fn immutable_reservations_bind_complete_committee_and_distinct_monitor() {
        let public = |seed| {
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes()
        };
        let mut voters = (1..=4).map(public).collect::<Vec<_>>();
        voters.sort();
        let keys = Keys {
            authority_transports: voters
                .iter()
                .enumerate()
                .map(|(i, voter)| (*voter, public(20 + i as u8)))
                .collect(),
            clock_monitors: [public(30)].into_iter().collect(),
        };
        let bytes = keys.encode([40; 32], [41; 32]).unwrap();
        let parsed = Keys::parse(&bytes, [40; 32], [41; 32]).unwrap();
        parsed.validate_voters(&voters).unwrap();
        assert_eq!(parsed.reservations().count(), 5);
        let mut wrong = voters.clone();
        wrong[0] = public(50);
        assert!(parsed.validate_voters(&wrong).is_err());
        let mut collision = keys.clone();
        collision.clock_monitors = [voters[0]].into_iter().collect();
        assert!(collision.encode([40; 32], [41; 32]).is_err());
        let mut value = wire::decode(&bytes).unwrap().array(8).unwrap().to_vec();
        value[4] = V::Uint(2);
        assert!(Keys::parse(&wire::encode(&V::Array(value)).unwrap(), [40; 32], [41; 32]).is_err());
    }
}
