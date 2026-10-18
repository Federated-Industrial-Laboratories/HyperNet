// SPDX-License-Identifier: MIT
//! Retained epoch evidence advances only from an independently pinned initial descriptor.
use super::*;
use crate::{
    authority_history::{self as history, ValidatedCheckpoint},
    authority_proof::{CertifiedPoint, Prefix, TrustDescriptor},
};
use serde::{Deserialize, Serialize};
/// This is a byte budget; retained epochs are never evicted to make room.
pub const MAX_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retained {
    #[serde(deserialize_with = "required_option")]
    pub certificate: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub node: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub checkpoint: Option<String>,
}
fn required_option<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
impl Retained {
    pub fn verify(
        &self,
        descriptor: &TrustDescriptor,
    ) -> Result<(Prefix, Option<ValidatedCheckpoint>)> {
        let floor = match (&self.certificate, &self.node) {
            (None, None) => descriptor.genesis()?,
            (Some(c), Some(n)) => {
                CertifiedPoint::from_evidence(descriptor, &hex::decode(c)?, &hex::decode(n)?)?
                    .prefix()
                    .clone()
            }
            _ => anyhow::bail!("Retained epoch floor evidence is incomplete"),
        };
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(|bytes| {
                let checkpoint = history::verify_checkpoint(descriptor, &hex::decode(bytes)?)?;
                ensure!(
                    !checkpoint.terminal()
                        && checkpoint.height() <= floor.height()
                        && checkpoint.prefix().view() <= floor.view()
                        && checkpoint.prefix().evaluated_at_ms() <= floor.evaluated_at_ms()
                        && (checkpoint.height() != floor.height() || checkpoint.prefix() == floor),
                    "Retained epoch checkpoint differs from the exact floor"
                );
                Ok::<_, anyhow::Error>(checkpoint)
            })
            .transpose()?;
        Ok((floor, checkpoint))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seal {
    retained: Retained,
    evidence: String,
    history: String,
}
impl Seal {
    pub fn new(terminal: &ValidatedTerminal, retained: Retained) -> Result<Self> {
        let (prefix, checkpoint) = retained.verify(terminal.old_descriptor())?;
        ensure!(
            &prefix == terminal.history().from()
                && checkpoint.as_ref().map(|c| c.head()) == terminal.history().prior(),
            "Epoch seal does not begin at the actual retained floor and tree head"
        );
        let seal = Self {
            retained,
            evidence: hex::encode(terminal.evidence()),
            history: hex::encode(terminal.history().canonical()),
        };
        seal.verify(terminal.old_descriptor())?;
        Ok(seal)
    }
    pub fn retained(&self) -> &Retained {
        &self.retained
    }
    pub fn evidence(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.evidence)?)
    }
    pub fn history(&self) -> Result<Vec<u8>> {
        Ok(hex::decode(&self.history)?)
    }
    pub fn verify(&self, descriptor: &TrustDescriptor) -> Result<ValidatedTerminal> {
        ensure!(
            self.evidence.len() <= 2 * proof::MAX_ACTIVATION
                && self.history.len() <= 2 * wire::MAXIMUM,
            "Epoch seal evidence exceeds its byte budget"
        );
        let (floor, checkpoint) = self.retained.verify(descriptor)?;
        verify_terminal(
            descriptor,
            &floor,
            checkpoint.as_ref().map(|c| c.head()),
            &self.evidence()?,
            &self.history()?,
        )
    }
    pub fn activate(&self, activation: &ValidatedActivation) -> Result<Activated> {
        let terminal = self.verify(activation.terminal().old_descriptor())?;
        ensure!(
            terminal.handoff() == activation.terminal().handoff()
                && terminal.checkpoint().digest() == activation.terminal().checkpoint().digest()
                && terminal.history().canonical() == activation.terminal().history().canonical(),
            "Readiness differs from the retained terminal seal"
        );
        let result = Activated {
            seal: self.clone(),
            ready: hex::encode(activation.ready()),
        };
        result.verify(activation.terminal().old_descriptor())?;
        Ok(result)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Activated {
    seal: Seal,
    ready: String,
}
impl Activated {
    pub fn seal(&self) -> &Seal {
        &self.seal
    }
    pub fn verify(&self, descriptor: &TrustDescriptor) -> Result<ValidatedActivation> {
        ensure!(
            self.ready.len() <= 4096,
            "Archived readiness exceeds its byte budget"
        );
        verify_activation(self.seal.verify(descriptor)?, &hex::decode(&self.ready)?)
    }
}
pub struct Resolution {
    pub descriptor: TrustDescriptor,
    pub previous_scopes: Vec<Scope>,
}
pub fn resolve(initial: &TrustDescriptor, epochs: &[Activated]) -> Result<Resolution> {
    ensure!(
        initial.scope().epoch == 0 && serde_json::to_vec(epochs)?.len() <= MAX_ARCHIVE_BYTES,
        "Epoch archive exceeds its byte budget or lacks initial independent trust"
    );
    let mut descriptor = initial.clone();
    let mut previous_scopes = Vec::new();
    for epoch in epochs {
        let activation = epoch.verify(&descriptor)?;
        previous_scopes.push(descriptor.scope().clone());
        descriptor = activation.descriptor()?;
    }
    Ok(Resolution {
        descriptor,
        previous_scopes,
    })
}

/// Authenticate a historical proof without advancing or authorizing a current recipient.
pub fn descriptor_for_scope(
    initial: &TrustDescriptor,
    epochs: &[Activated],
    scope: &Scope,
) -> Result<TrustDescriptor> {
    ensure!(
        initial.scope().epoch == 0 && serde_json::to_vec(epochs)?.len() <= MAX_ARCHIVE_BYTES,
        "Historical epoch archive exceeds its bound or lacks initial independent trust"
    );
    let mut descriptor = initial.clone();
    let mut selected = (descriptor.scope() == scope).then(|| descriptor.clone());
    for entry in epochs {
        descriptor = entry.verify(&descriptor)?.descriptor()?;
        if descriptor.scope() == scope {
            selected = Some(descriptor.clone());
        }
    }
    selected.context("Historical scope is absent from the complete verified epoch archive")
}
