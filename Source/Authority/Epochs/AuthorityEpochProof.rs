// SPDX-License-Identifier: MIT
//! Terminal history and both quorums are verified before a client can change its pinned epoch.
use super::*;
use crate::{
    authority_history::{self as history, TreeHead, ValidatedCheckpoint, ValidatedHistory},
    authority_proof::{Challenge, Node, Prefix, TrustDescriptor},
};

pub const MAX_ACTIVATION: usize = 131072;
/// A verified old terminal statement seals the old scope without activating its successor.
#[derive(Clone)]
pub struct ValidatedTerminal {
    old_descriptor: TrustDescriptor,
    checkpoint: ValidatedCheckpoint,
    history: ValidatedHistory,
    declaration: Declaration,
    evidence: Vec<u8>,
    descriptor: Vec<u8>,
    scope: Scope,
    voters: [Key; 4],
    handoff: Vec<u8>,
    genesis: Digest,
    state: Digest,
}
impl ValidatedTerminal {
    pub fn old_descriptor(&self) -> &TrustDescriptor {
        &self.old_descriptor
    }
    pub fn checkpoint(&self) -> &ValidatedCheckpoint {
        &self.checkpoint
    }
    pub fn history(&self) -> &ValidatedHistory {
        &self.history
    }
    pub fn declaration(&self) -> &Declaration {
        &self.declaration
    }
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
    pub fn handoff(&self) -> &[u8] {
        &self.handoff
    }
    pub fn successor_bytes(&self) -> &[u8] {
        &self.descriptor
    }
    pub fn successor_scope(&self) -> &Scope {
        &self.scope
    }
    pub fn successor_state(&self) -> Digest {
        self.state
    }
}
#[derive(Clone)]
pub struct ValidatedActivation {
    terminal: ValidatedTerminal,
    ready: Vec<u8>,
}
impl ValidatedActivation {
    pub fn terminal(&self) -> &ValidatedTerminal {
        &self.terminal
    }
    pub fn ready(&self) -> &[u8] {
        &self.ready
    }
    pub fn descriptor(&self) -> Result<TrustDescriptor> {
        TrustDescriptor::from_activation(self)
    }
    pub(crate) fn descriptor_bytes(&self) -> &[u8] {
        &self.terminal.descriptor
    }
}
pub fn noop(scope: &Scope, target: Digest) -> Result<Vec<u8>> {
    ensure!(target != [0; 32], "zero transition candidate");
    wire::encode(&a(vec![V::Uint(53), V::Uint(1), scope.value(), b(&target)]))
}
pub fn descriptor(
    declaration: &Declaration,
    checkpoint: &ValidatedCheckpoint,
    state: Digest,
) -> Result<Vec<u8>> {
    let versions = &declaration.snapshot.references;
    let digest = |kind| -> Result<Digest> {
        Ok(versions
            .iter()
            .find(|v| v.kind == kind && v.id == declaration.old_scope.network)
            .context("transition policy dependency missing")?
            .digest)
    };
    wire::encode(&a(vec![
        V::Uint(10),
        V::Uint(1),
        b(&declaration.old_scope.network),
        b(&declaration.old_scope.incarnation),
        V::Uint(declaration.next_epoch),
        a(declaration
            .nominations
            .iter()
            .map(|n| b(&n.voter))
            .collect()),
        b(&digest(100)?),
        b(&digest(114)?),
        b(&state),
        V::Uint(checkpoint.prefix().evaluated_at_ms()),
        V::Text("BasicHotStuff".into()),
    ]))
}
pub fn genesis(scope: &Scope, time: u64) -> Result<Vec<u8>> {
    wire::encode(&a(vec![
        V::Uint(14),
        V::Uint(1),
        scope.value(),
        V::Uint(0),
        V::Uint(0),
        V::Null,
        V::Null,
        V::Uint(time),
        V::Null,
    ]))
}
pub(super) fn command(
    old: &TrustDescriptor,
    ordered: &[u8],
    checkpoint: &ValidatedCheckpoint,
) -> Result<Declaration> {
    ensure!(ordered.len() <= 32768, "transition command exceeds bound");
    let value = wire::decode(ordered)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 22 && f[1].uint()? == 1 && Scope::parse(&f[2])? == *old.scope(),
        "terminal ordered command scope differs"
    );
    let intent = Intent::from_signed(f[3].bytes()?)?;
    let challenge = Challenge::from_signed(f[4].bytes()?)?;
    challenge.validate_request(&crate::authority_proof::SignedRequest::Intent(
        intent.clone(),
    ))?;
    let declaration = Declaration::from_intent(&intent)?;
    let expires = f[5].uint()?;
    let time = checkpoint.prefix().evaluated_at_ms();
    ensure!(
        declaration.old_scope == *old.scope()
            && challenge.network == old.scope().network
            && challenge.incarnation == old.scope().incarnation
            && challenge.intent == intent.digest
            && challenge.recipient == intent.requester
            && challenge.evaluation_expiry(time, expires).is_ok()
            && declaration.snapshot.height.checked_add(1) == Some(checkpoint.height()),
        "terminal request or historical validity differs"
    );
    let proof = wire::decode(checkpoint.canonical_proof())?;
    let anchor = wire::decode(proof.array(4)?[3].bytes()?)?;
    ensure!(
        anchor.array(9)?[6].fixed::<32>()? == wire::digest(ordered),
        "terminal anchor names another ordered command"
    );
    Ok(declaration)
}
pub(super) fn decide(
    old: &TrustDescriptor,
    checkpoint: &ValidatedCheckpoint,
    certificate: &[u8],
    suffix: &V,
) -> Result<()> {
    let value = wire::decode(certificate)?;
    let qc = value.array(5)?;
    ensure!(
        qc[0].uint()? == 12 && qc[1].uint()? == 1 && Scope::parse(&qc[2])? == *old.scope(),
        "terminal deciding certificate scope differs"
    );
    let wrapped = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        qc[3].clone(),
        qc[4].clone(),
    ]))?;
    let payload = old.quorum(&wrapped)?;
    let value = wire::decode(&payload)?;
    let vote = value.array(6)?;
    ensure!(
        vote[0].uint()? == 11
            && vote[1].uint()? == 1
            && Scope::parse(&vote[2])? == *old.scope()
            && vote[4].uint()? == 2,
        "terminal decision requires an old-scope Commit quorum"
    );
    let mut previous = checkpoint.prefix();
    let expected = wire::digest(&noop(old.scope(), *checkpoint.node())?);
    for bytes in suffix.list(128)? {
        let node = Node::parse(bytes.bytes()?)?;
        let v = wire::decode(bytes.bytes()?)?;
        ensure!(
            node.scope() == old.scope()
                && *node.parent() == *previous.node()
                && node.height()
                    == previous
                        .height()
                        .checked_add(1)
                        .context("terminal suffix height overflow")?
                && node.view() > previous.view()
                && node.evaluated_at_ms() >= previous.evaluated_at_ms()
                && v.array(9)?[6].fixed::<32>()? == expected,
            "terminal deciding suffix contains an unrelated or non-noop command"
        );
        previous = Prefix::checkpoint(&node, [0; 32]);
    }
    ensure!(
        vote[5].fixed::<32>()? == *previous.node() && vote[3].uint()? == previous.view(),
        "terminal Commit quorum names another suffix"
    );
    Ok(())
}
/// The caller supplies its actual durable prefix and tree head, never a proof-selected predecessor.
pub fn verify_terminal(
    old: &TrustDescriptor,
    retained: &Prefix,
    head: Option<&TreeHead>,
    evidence: &[u8],
    history_bytes: &[u8],
) -> Result<ValidatedTerminal> {
    ensure!(
        evidence.len() <= MAX_ACTIVATION,
        "epoch activation exceeds bound"
    );
    let value = wire::decode(evidence)?;
    let f = value.array(8)?;
    ensure!(
        f[0].uint()? == 52 && f[1].uint()? == 1,
        "epoch activation kind differs"
    );
    if f[5] != V::Null {
        ensure!(
            f[5].bytes()?.len() <= 2048,
            "readiness envelope exceeds bound"
        );
    }
    let checkpoint = history::verify_checkpoint(old, f[3].bytes()?)?;
    ensure!(
        checkpoint.terminal(),
        "epoch activation requires a terminal checkpoint"
    );
    let history = history::verify_history(&checkpoint, retained, head, history_bytes)?;
    let declaration = command(old, f[2].bytes()?, &checkpoint)?;
    decide(old, &checkpoint, f[6].bytes()?, &f[7])?;
    let handoff = old.quorum(f[4].bytes()?)?;
    ensure!(handoff.len() <= 2048, "handoff exceeds bound");
    let handoff_value = wire::decode(&handoff)?;
    let h = handoff_value.array(8)?;
    let state = id(&h[7])?;
    let descriptor = descriptor(&declaration, &checkpoint, state)?;
    ensure!(
        h[0].uint()? == 50
            && h[1].uint()? == 1
            && Scope::parse(&h[2])? == *old.scope()
            && h[3].fixed::<32>()? == *checkpoint.digest()
            && h[4].fixed::<32>()? == declaration.digest()
            && h[5].bytes()? == descriptor,
        "old handoff differs from the unique declared successor"
    );
    let scope = Scope {
        network: old.scope().network,
        incarnation: old.scope().incarnation,
        configuration: wire::digest(&descriptor),
        epoch: declaration.next_epoch,
    };
    let genesis = wire::digest(&genesis(&scope, checkpoint.prefix().evaluated_at_ms())?);
    ensure!(
        h[6].fixed::<32>()? == genesis,
        "handoff genesis differs from the derived descriptor"
    );
    let voters = declaration
        .nominations
        .iter()
        .map(|n| n.voter)
        .collect::<Vec<_>>()
        .try_into()
        .expect("four nominations");
    Ok(ValidatedTerminal {
        old_descriptor: old.clone(),
        checkpoint,
        history,
        declaration,
        evidence: evidence.to_vec(),
        descriptor,
        scope,
        voters,
        handoff,
        genesis,
        state,
    })
}
pub fn ready_statement(terminal: &ValidatedTerminal) -> Result<Vec<u8>> {
    wire::encode(&a(vec![
        V::Uint(51),
        V::Uint(1),
        terminal.scope.value(),
        b(&wire::digest(&terminal.handoff)),
        b(&terminal.genesis),
        b(&terminal.state),
    ]))
}
pub fn verify_activation(terminal: ValidatedTerminal, ready: &[u8]) -> Result<ValidatedActivation> {
    let (payload, signatures) = wire::envelope(ready, 4)?;
    ensure!(
        payload == ready_statement(&terminal)?
            && signatures.len() >= 3
            && signatures.iter().all(|(k, _)| terminal.voters.contains(k)),
        "successor readiness requires three exact installed voter signatures"
    );
    Ok(ValidatedActivation {
        terminal,
        ready: ready.to_vec(),
    })
}
