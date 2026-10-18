// SPDX-License-Identifier: MIT
//! Requester epoch adoption preserves pending intents, stream history and restrictive floors.
use super::*;
use crate::authority_epoch::{
    ValidatedActivation, ValidatedTerminal,
    archive::{self, Retained},
};
impl Stored {
    pub(super) fn resolve(&self, initial: &TrustDescriptor) -> Result<archive::Resolution> {
        archive::resolve(initial, &self.epochs)
    }
    fn retained(&self) -> Retained {
        Retained {
            certificate: self.certificate.clone(),
            node: self.node.clone(),
            checkpoint: self.checkpoint_proof.clone(),
        }
    }
}
impl Store {
    /// Historical descriptors authenticate receipts; they do not authorise new effects.
    pub fn descriptor_for_scope(
        &self,
        scope: &crate::authority_proof::Scope,
    ) -> Result<TrustDescriptor> {
        self.unchanged()?;
        let mut descriptor = self.initial_descriptor.clone();
        if descriptor.scope() == scope {
            return Ok(descriptor);
        }
        for epoch in &self.stored.epochs {
            descriptor = TrustDescriptor::from_activation(&epoch.verify(&descriptor)?)?;
            if descriptor.scope() == scope {
                return Ok(descriptor);
            }
        }
        anyhow::bail!("Scope has no retained, independently pinned epoch chain")
    }
    /// Retry validation uses the already retained predecessor, never a proof-selected floor.
    pub fn verify_epoch_terminal(
        &self,
        evidence: &[u8],
        history: &[u8],
    ) -> Result<ValidatedTerminal> {
        self.unchanged()?;
        let value = wire::decode(evidence)?;
        let fields = value.array(8)?;
        let ordered = wire::decode(fields[2].bytes()?)?;
        let old_scope = proof::Scope::parse(&ordered.array(6)?[2])?;
        if old_scope == *self.descriptor.scope() {
            return crate::authority_epoch::verify_terminal(
                &self.descriptor,
                &self.floor,
                self.tree_head(),
                evidence,
                history,
            );
        }
        let previous = self
            .stored
            .epochs
            .last()
            .context("No retained predecessor for activation retry")?;
        let old = self.descriptor_for_scope(&old_scope)?;
        let retained_terminal = previous.seal().verify(&old)?;
        ensure!(
            retained_terminal.successor_scope() == self.descriptor.scope(),
            "Activation retry is not the immediate retained predecessor"
        );
        let (floor, checkpoint) = previous.seal().retained().verify(&old)?;
        let terminal = crate::authority_epoch::verify_terminal(
            &old,
            &floor,
            checkpoint.as_ref().map(|c| c.head()),
            evidence,
            history,
        )?;
        ensure!(
            terminal.handoff() == retained_terminal.handoff(),
            "Activation retry names another successor"
        );
        Ok(terminal)
    }
    pub fn epoch_retained(&self) -> Result<Retained> {
        self.unchanged()?;
        Ok(self.stored.retained())
    }
    pub(super) fn unsealed(&self) -> Result<()> {
        ensure!(
            self.stored.sealed.is_none(),
            "Retained terminal evidence stops old-epoch effects until activation"
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
            "Terminal evidence has another predecessor"
        );
        let seal = archive::Seal::new(terminal, self.stored.retained())?;
        if let Some(previous) = &self.stored.sealed {
            ensure!(
                *previous == seal,
                "Another terminal transition is already retained"
            );
            return Ok(());
        }
        let mut next = self.next()?;
        next.sealed = Some(seal);
        transaction::publish(
            self,
            next,
            transaction::Transition::SealEpoch,
            proof::ContinuityEvidence {
                ancestry: vec![],
                history: None,
            },
        )
    }
    pub fn activate_epoch(&mut self, activation: &ValidatedActivation) -> Result<()> {
        self.unchanged()?;
        if self.descriptor.scope() == activation.terminal().successor_scope() {
            let last = self
                .stored
                .epochs
                .last()
                .context("Current successor lacks epoch evidence")?;
            ensure!(
                last.seal()
                    .verify(activation.terminal().old_descriptor())?
                    .handoff()
                    == activation.terminal().handoff(),
                "Epoch retry names another transition"
            );
            return Ok(());
        }
        self.seal_epoch(activation.terminal())?;
        let activated = self
            .stored
            .sealed
            .as_ref()
            .context("Durable seal required")?
            .activate(activation)?;
        let mut next = self.next()?;
        next.epochs.push(activated);
        next.sealed = None;
        next.descriptor = hex::encode(activation.terminal().successor_scope().configuration);
        next.certificate = None;
        next.node = None;
        next.checkpoint_proof = None;
        transaction::publish(
            self,
            next,
            transaction::Transition::ActivateEpoch,
            proof::ContinuityEvidence {
                ancestry: vec![],
                history: None,
            },
        )
    }
}
pub(super) fn forward(
    initial: &TrustDescriptor,
    old: &Stored,
    next: &Stored,
    transition: &transaction::Transition,
) -> Result<()> {
    let old_resolution = old.resolve(initial)?;
    next.validate(initial)?;
    ensure!(
        old.network == next.network
            && old.incarnation == next.incarnation
            && old.requester == next.requester
            && old.sequence.checked_add(1) == Some(next.sequence)
            && old.wall_floor_ms == next.wall_floor_ms
            && old.generations == next.generations
            && old.tracker == next.tracker,
        "Epoch transition changed preserved requester obligations"
    );
    match transition {
        transaction::Transition::SealEpoch => {
            ensure!(
                old.sealed.is_none()
                    && old.epochs == next.epochs
                    && old.descriptor == next.descriptor
                    && old.certificate == next.certificate
                    && old.node == next.node
                    && old.checkpoint_proof == next.checkpoint_proof,
                "Terminal seal changed retained authority"
            );
            let seal = next.sealed.as_ref().context("Terminal seal missing")?;
            ensure!(
                seal.retained() == &old.retained(),
                "Terminal seal does not bind actual old floor"
            );
            seal.verify(&old_resolution.descriptor)?;
        }
        transaction::Transition::ActivateEpoch => {
            ensure!(
                next.sealed.is_none()
                    && next.epochs.len() == old.epochs.len() + 1
                    && next.epochs.starts_with(&old.epochs)
                    && next.certificate.is_none()
                    && next.node.is_none()
                    && next.checkpoint_proof.is_none(),
                "Epoch activation changes history or invents a successor floor"
            );
            let activated = next.epochs.last().context("Activation missing")?;
            ensure!(
                Some(activated.seal()) == old.sealed.as_ref(),
                "Epoch activation does not use retained seal"
            );
            let activation = activated.verify(&old_resolution.descriptor)?;
            ensure!(
                next.descriptor
                    == hex::encode(activation.terminal().successor_scope().configuration),
                "Successor descriptor differs"
            );
        }
        _ => anyhow::bail!("Expected an epoch transaction"),
    }
    Ok(())
}
