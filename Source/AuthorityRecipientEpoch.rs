// SPDX-License-Identifier: MIT
// Epoch adoption keeps uncertain serving effects and caller history under the original independent trust pin.
use super::*;
use crate::authority_epoch::{
    ValidatedActivation, ValidatedTerminal,
    archive::{self, Retained},
};
impl Stored {
    pub(super) fn resolve(&self, initial: &TrustDescriptor) -> Result<archive::Resolution> {
        archive::resolve(initial, &self.epochs)
    }
    pub(super) fn retained(&self) -> Retained {
        Retained {
            certificate: self.certificate.clone(),
            node: self.node.clone(),
            checkpoint: self.checkpoint.clone(),
        }
    }
}
impl Store {
    pub fn epoch_retained(&self) -> Result<Retained> {
        self.unchanged()?;
        Ok(self.stored.retained())
    }
    /// Exact retries use the independently retained immediate predecessor and its real floor.
    pub fn verify_epoch_terminal(
        &self,
        evidence: &[u8],
        history: &[u8],
    ) -> Result<ValidatedTerminal> {
        self.unchanged()?;
        let value = wire::decode(evidence)?;
        let ordered = wire::decode(value.array(8)?[2].bytes()?)?;
        let scope = proof::Scope::parse(&ordered.array(6)?[2])?;
        if scope == *self.descriptor.scope() {
            return crate::authority_epoch::verify_terminal(
                &self.descriptor,
                &self.prefix,
                self.tree_head(),
                evidence,
                history,
            );
        }
        let mut descriptor = self.initial_descriptor.clone();
        for entry in &self.stored.epochs {
            let old = descriptor.clone();
            descriptor = entry.verify(&old)?.descriptor()?;
            if *old.scope() == scope && descriptor.scope() == self.descriptor.scope() {
                let retained = entry.seal().verify(&old)?;
                let (floor, checkpoint) = entry.seal().retained().verify(&old)?;
                let terminal = crate::authority_epoch::verify_terminal(
                    &old,
                    &floor,
                    checkpoint.as_ref().map(|c| c.head()),
                    evidence,
                    history,
                )?;
                ensure!(
                    terminal.handoff() == retained.handoff(),
                    "Recipient retry names another successor"
                );
                return Ok(terminal);
            }
        }
        anyhow::bail!("Recipient activation retry lacks its immediate retained predecessor")
    }
    pub(super) fn unsealed(&self) -> Result<()> {
        ensure!(
            self.stored.sealed.is_none(),
            "retained terminal evidence stops old recipient effects"
        );
        Ok(())
    }
    pub fn epoch_sealed(&self) -> bool {
        self.stored.sealed.is_some()
    }
    pub fn seal_epoch(&mut self, terminal: &ValidatedTerminal) -> Result<()> {
        self.unchanged()?;
        ensure!(
            terminal.old_descriptor().canonical() == self.descriptor.canonical(),
            "terminal evidence has another recipient predecessor"
        );
        let seal = archive::Seal::new(terminal, self.stored.retained())?;
        if let Some(old) = &self.stored.sealed {
            ensure!(*old == seal, "another terminal recipient seal is retained");
            return Ok(());
        }
        let mut next = self.stored.clone();
        next.sealed = Some(seal);
        transaction::publish(self, next, None)
    }
    pub fn activate_epoch(&mut self, activation: &ValidatedActivation) -> Result<()> {
        self.unchanged()?;
        if self.descriptor.scope() == activation.terminal().successor_scope() {
            let last = self
                .stored
                .epochs
                .last()
                .context("current recipient epoch has no archive")?;
            ensure!(
                last.seal()
                    .verify(activation.terminal().old_descriptor())?
                    .handoff()
                    == activation.terminal().handoff(),
                "recipient epoch retry names another transition"
            );
            return Ok(());
        }
        self.seal_epoch(activation.terminal())?;
        let mut next = self.stored.clone();
        next.epochs.push(
            next.sealed
                .as_ref()
                .context("durable recipient terminal seal required")?
                .activate(activation)?,
        );
        next.sealed = None;
        next.configuration = activation.terminal().successor_scope().configuration;
        next.certificate = None;
        next.node = None;
        next.checkpoint = None;
        transaction::publish(self, next, None)
    }
}
pub(super) fn forward(initial: &TrustDescriptor, old: &Stored, next: &Stored) -> Result<()> {
    let prior = old.resolve(initial)?;
    next.validate(initial)?;
    ensure!(
        old.sequence.checked_add(1) == Some(next.sequence),
        "recipient epoch transaction sequence differs"
    );
    if old.epochs == next.epochs {
        ensure!(old.sealed.is_none(), "recipient seal cannot be replaced");
        let seal = next
            .sealed
            .as_ref()
            .context("recipient terminal seal absent")?;
        ensure!(
            seal.retained() == &old.retained(),
            "recipient terminal seal lost actual retained floor"
        );
        seal.verify(&prior.descriptor)?;
        let mut expected = old.clone();
        expected.sequence = next.sequence;
        expected.sealed = Some(seal.clone());
        ensure!(
            *next == expected,
            "recipient seal changed preserved obligations"
        );
    } else {
        ensure!(
            next.epochs.len() == old.epochs.len() + 1 && next.epochs.starts_with(&old.epochs),
            "recipient activation rewrote archived epochs"
        );
        let added = next.epochs.last().context("recipient activation absent")?;
        ensure!(
            Some(added.seal()) == old.sealed.as_ref(),
            "recipient activation lacks its exact durable seal"
        );
        let activation = added.verify(&prior.descriptor)?;
        let mut expected = old.clone();
        expected.sequence = next.sequence;
        expected.epochs = next.epochs.clone();
        expected.sealed = None;
        expected.configuration = activation.terminal().successor_scope().configuration;
        expected.certificate = None;
        expected.node = None;
        expected.checkpoint = None;
        ensure!(
            *next == expected,
            "recipient activation changed callers, claims, restrictions or clock floor"
        );
    }
    Ok(())
}
