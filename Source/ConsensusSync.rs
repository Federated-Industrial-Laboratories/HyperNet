// SPDX-License-Identifier: MIT
//! Authenticated bounded-space SMR synchronisation, separate from HotStuff voting.
use super::records::{Configuration, Key, Scope, record};
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub maxima: [u64; 4],
    pub view: u64,
    pub view_plus: u64,
    pub entered: u64,
    pub advanced: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    pub wish: Option<u64>,
    pub entered: Option<u64>,
}
impl State {
    pub fn validate(&self) -> Result<()> {
        let mut sorted = self.maxima;
        sorted.sort_unstable();
        ensure!(
            self.view == sorted[1] && self.view_plus == sorted[2] && self.entered <= self.view,
            "Invalid synchroniser snapshot"
        );
        Ok(())
    }
    pub fn advance(&mut self) -> Result<Effects> {
        let target = self
            .view
            .checked_add(1)
            .context("Synchroniser view overflow")?
            .max(self.view_plus);
        self.advanced = true;
        Ok(Effects {
            wish: Some(target),
            entered: None,
        })
    }
    pub fn periodic(&self) -> Result<Effects> {
        let wish = if self.advanced {
            Some(
                self.view
                    .checked_add(1)
                    .context("Synchroniser view overflow")?
                    .max(self.view_plus),
            )
        } else if self.view_plus > 0 {
            Some(self.view_plus)
        } else {
            None
        };
        Ok(Effects {
            wish,
            entered: None,
        })
    }
    pub fn receive(&mut self, member: usize, target: u64) -> Result<Effects> {
        ensure!(member < 4 && target > 0, "Invalid WISH identity or target");
        let previous = self.view;
        let previous_plus = self.view_plus;
        self.maxima[member] = self.maxima[member].max(target);
        let mut sorted = self.maxima;
        sorted.sort_unstable();
        self.view = sorted[1];
        self.view_plus = sorted[2];
        let entered = if self.view_plus == self.view && self.view > previous {
            self.entered = self.view;
            self.advanced = false;
            Some(self.view)
        } else {
            None
        };
        Ok(Effects {
            wish: (self.view_plus > previous_plus).then_some(self.view_plus),
            entered,
        })
    }
}
pub fn verify(config: &Configuration, envelope: &[u8]) -> Result<(Key, u64)> {
    let (payload, signatures) = wire::envelope(envelope, 1)?;
    let value = wire::decode(&payload)?;
    let a = record(&value, 16, 4)?;
    ensure!(
        Scope::parse(&a[2])? == config.scope && a[3].uint()? > 0,
        "WISH scope or target differs"
    );
    let signer = signatures.first().context("WISH signer missing")?.0;
    config.member(&signer)?;
    Ok((signer, a[3].uint()?))
}
pub fn sign(config: &Configuration, target: u64, key: &SigningKey) -> Result<Vec<u8>> {
    ensure!(target > 0, "Zero WISH target");
    config.member(&key.verifying_key().to_bytes())?;
    wire::sign_envelope(
        &wire::encode(&V::Array(vec![
            V::Uint(16),
            V::Uint(1),
            config.scope.value(),
            V::Uint(target),
        ]))?,
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_byzantine_jump_and_two_way_partition_cannot_enter() {
        let mut s = State::default();
        assert_eq!(s.receive(3, u64::MAX).unwrap(), Effects::default());
        assert_eq!(s.entered, 0);
        let mut partition = State::default();
        partition.receive(0, 1).unwrap();
        assert_eq!(partition.receive(1, 1).unwrap().entered, None);
        assert_eq!(partition.entered, 0);
    }
    #[test]
    fn three_matching_wishes_enter_and_loss_is_retransmitted() {
        let mut replicas = [State::default(), State::default(), State::default()];
        for replica in &mut replicas {
            assert_eq!(replica.advance().unwrap().wish, Some(1));
            assert_eq!(replica.periodic().unwrap().wish, Some(1));
        }
        for replica in &mut replicas {
            for member in 0..3 {
                replica.receive(member, 1).unwrap();
            }
            assert_eq!(replica.entered, 1);
            assert!(!replica.advanced);
            assert_eq!(replica.periodic().unwrap().wish, Some(1));
            assert_eq!(replica.receive(1, 1).unwrap(), Effects::default());
            assert_eq!(replica.advance().unwrap().wish, Some(2));
            replica.validate().unwrap();
        }
    }
    #[test]
    fn order_statistic_progress_is_not_protocol_entry() {
        let mut s = State::default();
        s.receive(0, 5).unwrap();
        s.receive(1, 4).unwrap();
        s.receive(2, 3).unwrap();
        assert_eq!((s.view, s.view_plus, s.entered), (3, 4, 0));
        assert_eq!(s.receive(2, 4).unwrap().entered, Some(4));
        assert_eq!(s.receive(3, 2).unwrap().entered, None);
    }
}
