// SPDX-License-Identifier: MIT
//! An old committee stops durably at its successful terminal application result.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminal {
    node: Digest,
    ordered: Vec<u8>,
    checkpoint_share: Vec<u8>,
    deciding: Vec<u8>,
    suffix: Vec<Vec<u8>>,
}
fn command(config: &Configuration, state: &Snapshot, n: &Node) -> Result<Command> {
    let object = state
        .commands
        .get(&id(&n.command.context("Epoch branch command missing")?))
        .context("Epoch branch command body missing")?;
    Command::parse(config, &body(state, object)?)
}
/// Only the exact target no-op may follow an unresolved declaration on a branch.
pub(super) fn branch(
    config: &Configuration,
    state: &Snapshot,
    tip: Digest,
) -> Result<Option<Digest>> {
    let mut reverse = Vec::new();
    let mut cursor = tip;
    let applied = node(config, state, &state.applied)?;
    while cursor != state.applied {
        ensure!(
            reverse.len() < MAX_NODES,
            "Epoch branch exceeds retained ancestry"
        );
        let n = node(config, state, &cursor)?;
        if n.height <= applied.height {
            break;
        }
        reverse.push((cursor, command(config, state, &n)?));
        cursor = n.parent.context("Epoch branch has no applied ancestor")?;
    }
    let mut terminal = None;
    let mut suffix = 0;
    for (digest, cmd) in reverse.into_iter().rev() {
        if let Some(target) = terminal {
            ensure!(
                matches!(cmd, Command::Noop(id) if id == target),
                "Only the exact terminal no-op can follow unresolved reconfiguration"
            );
            suffix += 1;
            ensure!(suffix <= 128, "Terminal deciding suffix exceeds its bound");
        } else {
            match cmd {
                Command::Ordered(request) if request.action == "Reconfigure" => {
                    terminal = Some(digest)
                }
                Command::Noop(target) => {
                    let n = node(config, state, &target)?;
                    ensure!(
                        n.height <= applied.height
                            && extends(config, state, state.applied, target)?
                            && matches!(command(config, state, &n)?, Command::Ordered(r) if r.action == "Reconfigure"),
                        "Terminal no-op lacks an exact retained resolved declaration"
                    );
                }
                _ => {}
            }
        }
    }
    Ok(terminal)
}
impl Engine {
    pub fn halted(&self) -> bool {
        self.snapshot.terminal.is_some()
    }
    pub(super) fn voting(&self) -> Result<()> {
        self.active()?;
        ensure!(
            self.can_vote(),
            "Replica is terminal or awaiting certified successor activation"
        );
        Ok(())
    }
    pub fn terminal_progress(&self) -> Result<Option<Vec<u8>>> {
        self.voting()?;
        let high = certificate(
            &self.configuration,
            &self.snapshot,
            &self.snapshot.highest_prepare,
        )?;
        let Some(target) = branch(&self.configuration, &self.snapshot, high.node)? else {
            return Ok(None);
        };
        Ok(Some(wire::encode(&V::Array(vec![
            V::Uint(53),
            V::Uint(1),
            self.configuration.scope.value(),
            records::bytes(&target),
        ]))?))
    }
    pub(super) fn halt_terminal(
        &self,
        next: &mut Snapshot,
        applied: &Node,
        deciding: Digest,
    ) -> Result<bool> {
        let Some(terminal) =
            crate::authority_application::terminal(&self.configuration, &next.application)?
        else {
            return Ok(false);
        };
        let digest = applied.digest()?;
        let ordered = self.command(&applied.command.context("Terminal command missing")?)?;
        let request = records::OrderedRequest::parse(&self.configuration, &ordered)?;
        ensure!(
            terminal.intent == request.intent
                && request.action == "Reconfigure"
                && crate::authority_epoch::Declaration::from_intent(
                    &crate::authority_proof::Intent::from_signed(
                        wire::decode(&ordered)?.array(6)?[3].bytes()?
                    )?
                )?
                .bytes
                    == terminal.declaration.bytes,
            "Terminal application differs from its committed reconfiguration"
        );
        let qc = certificate(&self.configuration, next, &deciding)?;
        ensure!(
            qc.phase == Phase::Commit,
            "Terminal decision is not a CommitQC"
        );
        let mut suffix = Vec::new();
        let mut cursor = qc.node;
        while cursor != digest {
            ensure!(
                suffix.len() < 128,
                "Terminal deciding suffix exceeds its bound"
            );
            let n = node(&self.configuration, next, &cursor)?;
            ensure!(
                matches!(command(&self.configuration, next, &n)?, Command::Noop(target) if target == digest),
                "Terminal decision suffix contains another command"
            );
            cursor = n
                .parent
                .context("Terminal decision does not include the applied declaration")?;
            suffix.push(n.encode()?);
        }
        suffix.reverse();
        let b = records::bytes;
        let statement = wire::encode(&V::Array(vec![
            V::Uint(45),
            V::Uint(1),
            self.configuration.scope.value(),
            V::Uint(applied.height),
            b(&digest),
            V::Uint(applied.evaluated_at),
            b(&wire::digest(&next.application)),
            V::Uint(next.archive_size),
            b(&next.archive_root),
            V::Bool(true),
        ]))?;
        let checkpoint_share = wire::sign_envelope(&statement, &self.key)?;
        next.terminal = Some(Terminal {
            node: digest,
            ordered,
            checkpoint_share,
            deciding: qc.bytes,
            suffix,
        });
        Ok(true)
    }
    pub(super) fn validate_terminal(&self) -> Result<()> {
        let terminal_state = crate::authority_application::terminal(
            &self.configuration,
            &self.snapshot.application,
        )?;
        let Some(saved) = &self.snapshot.terminal else {
            ensure!(
                terminal_state.is_none(),
                "Terminal application has lost its durable halt"
            );
            return Ok(());
        };
        ensure!(
            terminal_state.is_some()
                && saved.node == self.snapshot.applied
                && self.snapshot.apply_cursor.is_none(),
            "Durable terminal position differs"
        );
        let mut checked = self.snapshot.clone();
        let qc = Certificate::parse(&self.configuration, &saved.deciding)?;
        self.halt_terminal(&mut checked, &self.applied()?, qc.digest())?;
        let expected = checked.terminal.context("Terminal reconstruction failed")?;
        ensure!(
            serde_json::to_vec(&expected)? == serde_json::to_vec(saved)?,
            "Durable terminal proof differs from retained execution"
        );
        Ok(())
    }
    /// The share is observable only after its halt, archive and post-state are durable.
    pub fn terminal_share(&self) -> Result<Vec<u8>> {
        self.active()?;
        let terminal = self
            .snapshot
            .terminal
            .as_ref()
            .context("Replica has no terminal checkpoint")?;
        let b = records::bytes;
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("EpochTerminalShare".into()),
            b(&terminal.ordered),
            b(&terminal.checkpoint_share),
            b(&self.applied()?.encode()?),
            b(&terminal.deciding),
            V::Array(terminal.suffix.iter().map(|s| b(s)).collect()),
        ]))
    }
}

impl Engine {
    pub fn handoff_share(&self, package: &[u8]) -> Result<Vec<u8>> {
        self.active()?;
        let saved = self
            .snapshot
            .terminal
            .as_ref()
            .context("Old committee has not durably halted")?;
        let (ordered, checkpoint, _, _) =
            crate::authority_epoch::terminal_checkpoint(self.configuration.descriptor(), package)?;
        ensure!(
            ordered == saved.ordered
                && *checkpoint.node() == saved.node
                && *checkpoint.state() == wire::digest(&self.snapshot.application)
                && checkpoint.head().size() == self.snapshot.archive_size
                && *checkpoint.head().root() == self.snapshot.archive_root,
            "Handoff checkpoint differs from the durable halt"
        );
        let state = crate::authority_application::successor_state(
            &self.configuration,
            &self.snapshot.application,
            &checkpoint,
        )?;
        let terminal = crate::authority_application::terminal(
            &self.configuration,
            &self.snapshot.application,
        )?
        .context("Terminal declaration missing")?;
        let descriptor = crate::authority_epoch::descriptor(
            &terminal.declaration,
            &checkpoint,
            wire::digest(&state),
        )?;
        let scope = crate::authority_proof::Scope {
            network: self.configuration.scope.network,
            incarnation: self.configuration.scope.incarnation,
            configuration: wire::digest(&descriptor),
            epoch: terminal.declaration.next_epoch,
        };
        let genesis =
            crate::authority_epoch::genesis(&scope, checkpoint.prefix().evaluated_at_ms())?;
        let b = records::bytes;
        let statement = wire::encode(&V::Array(vec![
            V::Uint(50),
            V::Uint(1),
            self.configuration.scope.value(),
            b(checkpoint.digest()),
            b(&terminal.declaration.digest()),
            b(&descriptor),
            b(&wire::digest(&genesis)),
            b(&wire::digest(&state)),
        ]))?;
        wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("EpochHandoffShare".into()),
            b(package),
            b(&wire::sign_envelope(&statement, &self.key)?),
        ]))
    }
    pub fn terminal_history(
        &self,
        package: &[u8],
        retained: &crate::authority_proof::Prefix,
        head: Option<&crate::authority_history::TreeHead>,
    ) -> Result<Vec<u8>> {
        self.active()?;
        let (_, checkpoint, _, _) =
            crate::authority_epoch::terminal_checkpoint(self.configuration.descriptor(), package)?;
        ensure!(
            self.halted()
                && *checkpoint.node() == self.snapshot.applied
                && retained.scope() == self.configuration.descriptor().scope()
                && retained.height() <= checkpoint.height(),
            "Terminal history request scope differs"
        );
        let leaves = self.archive.leaves();
        let height = retained.height() as usize;
        ensure!(
            if height == 0 {
                *retained.node() == self.configuration.genesis().digest()?
            } else {
                leaves.get(height - 1) == Some(retained.node())
            },
            "Retained node is outside terminal history"
        );
        let (size, root, consistency) = if let Some(head) = head {
            ensure!(
                head.size() <= retained.height()
                    && archive::root(&leaves[..head.size() as usize]) == *head.root(),
                "Retained history root differs"
            );
            (
                head.size(),
                records::bytes(head.root()),
                archive::consistency(leaves, head.size() as usize)?,
            )
        } else {
            (0, V::Null, vec![])
        };
        let inclusion = if height == 0 {
            vec![]
        } else {
            archive::inclusion(leaves, height - 1)?
        };
        let b = records::bytes;
        wire::encode(&V::Array(vec![
            V::Uint(47),
            V::Uint(1),
            self.configuration.scope.value(),
            V::Uint(retained.height()),
            b(retained.node()),
            b(checkpoint.digest()),
            V::Array(inclusion.iter().map(|v| b(v)).collect()),
            V::Uint(size),
            root,
            V::Array(consistency.iter().map(|v| b(v)).collect()),
        ]))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    evidence: Vec<u8>,
    history: Vec<u8>,
    ready: Vec<u8>,
    activation: Option<Vec<u8>>,
}
impl Engine {
    pub fn can_vote(&self) -> bool {
        !self.halted()
            && self
                .snapshot
                .prepared
                .as_ref()
                .is_none_or(|p| p.activation.is_some())
    }
    fn prepared_terminal(&self) -> Result<crate::authority_epoch::ValidatedTerminal> {
        let prepared = self
            .snapshot
            .prepared
            .as_ref()
            .context("Replica is not a prepared successor")?;
        let old = self
            .configuration
            .predecessor
            .as_ref()
            .context("Successor predecessor trust is missing")?;
        crate::authority_epoch::verify_terminal(
            old.descriptor(),
            &old.descriptor().genesis()?,
            None,
            &prepared.evidence,
            &prepared.history,
        )
    }
    #[cfg(test)]
    pub fn prepare_epoch(
        directory: &Path,
        predecessor: Configuration,
        key: SigningKey,
        terminal_state: &[u8],
        terminal: &crate::authority_epoch::ValidatedTerminal,
    ) -> Result<Self> {
        Self::prepare_epoch_with_objects(
            directory,
            predecessor,
            key,
            terminal_state,
            terminal,
            None,
        )
    }
    pub fn prepare_epoch_with_objects(
        directory: &Path,
        predecessor: Configuration,
        key: SigningKey,
        terminal_state: &[u8],
        terminal: &crate::authority_epoch::ValidatedTerminal,
        objects: Option<&crate::authority_object_files::Directory>,
    ) -> Result<Self> {
        use super::runtime::Application;
        let refs = crate::authority_application::PolicyApplication::new(predecessor.clone())
            .retained_inputs(terminal_state)?;
        let index = crate::authority_objects::EpochIndex::new(terminal_state, &refs)?;
        if let Some(objects) = objects {
            ensure!(
                objects.index().canonical()? == index.canonical()?,
                "successor object index differs from terminal state"
            );
            objects.validate()?;
        } else {
            ensure!(
                refs.is_empty(),
                "successor immutable input closure is missing"
            );
        }
        ensure!(
            terminal.history().from() == &predecessor.descriptor().genesis()?
                && terminal.history().prior().is_none(),
            "New replica installation requires terminal history from its accepted predecessor genesis"
        );
        let configuration = predecessor.successor(terminal)?;
        configuration.member(&key.verifying_key().to_bytes())?;
        let initial = crate::authority_application::successor_state(
            &predecessor,
            terminal_state,
            terminal.checkpoint(),
        )?;
        ensure!(
            wire::digest(&initial) == terminal.successor_state(),
            "Installed successor state differs from old handoff"
        );
        ensure!(
            crate::authority_application::PolicyApplication::new(configuration.clone())
                .retained_inputs(&initial)?
                == refs,
            "successor changes immutable input closure"
        );
        let statement = crate::authority_epoch::ready_statement(terminal)?;
        let prepared = Prepared {
            evidence: terminal.evidence().to_vec(),
            history: terminal.history().canonical().to_vec(),
            ready: wire::sign_envelope(&statement, &key)?,
            activation: None,
        };
        Self::create_prepared_inputs(
            directory,
            configuration,
            key,
            initial,
            Some(prepared),
            &refs,
            |reference| {
                objects
                    .context("successor immutable inputs missing")?
                    .read(reference)
            },
        )
    }
    pub fn readiness_share(&self) -> Result<Vec<u8>> {
        self.active()?;
        self.validate_prepared()?;
        self.input_reader()?
            .verify(self.snapshot.inputs.application())?;
        Ok(self
            .snapshot
            .prepared
            .as_ref()
            .context("Replica is not prepared")?
            .ready
            .clone())
    }
    pub fn activate_epoch(
        &mut self,
        activation: &crate::authority_epoch::ValidatedActivation,
    ) -> Result<()> {
        self.active()?;
        let terminal = self.prepared_terminal()?;
        ensure!(
            terminal.handoff() == activation.terminal().handoff()
                && terminal.successor_scope() == activation.terminal().successor_scope(),
            "Readiness names another installed successor"
        );
        crate::authority_epoch::verify_activation(terminal, activation.ready())?;
        if let Some(previous) = self
            .snapshot
            .prepared
            .as_ref()
            .and_then(|p| p.activation.as_ref())
        {
            ensure!(
                wire::envelope(previous, 4)?.0 == wire::envelope(activation.ready(), 4)?.0,
                "Another successor activation is durable"
            );
            return Ok(());
        }
        let mut next = self.snapshot.clone();
        next.prepared
            .as_mut()
            .context("Prepared successor missing")?
            .activation = Some(activation.ready().to_vec());
        self.persist(next)
    }
    pub(super) fn validate_prepared(&self) -> Result<()> {
        let Some(prepared) = &self.snapshot.prepared else {
            ensure!(
                self.configuration.scope.epoch == 0,
                "Successor journal lost its preparation record"
            );
            return Ok(());
        };
        let terminal = self.prepared_terminal()?;
        ensure!(
            terminal.successor_scope() == self.configuration.descriptor().scope()
                && terminal.successor_state() == self.configuration.genesis_governance,
            "Prepared journal descriptor differs from certified handoff"
        );
        let (statement, signatures) = wire::envelope(&prepared.ready, 1)?;
        ensure!(
            statement == crate::authority_epoch::ready_statement(&terminal)?
                && signatures.len() == 1
                && signatures[0].0 == self.signer(),
            "Installed readiness share differs"
        );
        if let Some(ready) = &prepared.activation {
            crate::authority_epoch::verify_activation(terminal, ready)?;
        } else {
            ensure!(
                self.view() == 0
                    && self.snapshot.own_votes.is_empty()
                    && self.snapshot.proposals.is_empty()
                    && self.applied()?.height == 0
                    && self.committed()?.height == 0,
                "Unactivated successor has emitted consensus work"
            );
        }
        Ok(())
    }
}

impl Engine {
    pub fn current_activation(
        &self,
    ) -> Result<Option<crate::authority_epoch::ValidatedActivation>> {
        self.active()?;
        let Some(ready) = self
            .snapshot
            .prepared
            .as_ref()
            .and_then(|p| p.activation.as_ref())
        else {
            return Ok(None);
        };
        Ok(Some(crate::authority_epoch::verify_activation(
            self.prepared_terminal()?,
            ready,
        )?))
    }
}
