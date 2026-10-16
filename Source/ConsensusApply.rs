// SPDX-License-Identifier: MIT
//! Applied progress is separate from voting and advances through a durable bounded cursor.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    target: Digest,
    certificate: Digest,
    base: Digest,
    state: Digest,
    scan: Digest,
    reverse: Vec<Digest>,
    verified: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredExecution {
    pub object: storage::Object,
    pub command: Digest,
    pub expires: u64,
    pub height: u64,
}
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded records are processed individually without an additional allocation."
)]
pub enum Turn {
    Idle,
    Progress,
    Blocked(&'static str),
    Unavailable(crate::authority_objects::Reference),
    Inert,
    Result(Node, ExecutionRecord),
}
impl Engine {
    pub(super) fn stage_direct_application(
        &self,
        next: &mut Snapshot,
        qc: &Certificate,
    ) -> Result<()> {
        if next.apply_cursor.is_some() {
            return Ok(());
        }
        let target = node(&self.configuration, next, &qc.node)?;
        if target.parent != Some(next.applied) {
            return Ok(());
        }
        let base = node(&self.configuration, next, &next.applied)?;
        ensure!(
            qc.phase == Phase::Commit && base.height.checked_add(1) == Some(target.height),
            "Direct application cursor lacks its exact deciding child"
        );
        // This verified suffix reaches disk in the same publication as its
        // deciding CommitQC. Execution still starts only from the durable cursor.
        next.apply_cursor = Some(Cursor {
            target: qc.node,
            certificate: qc.digest(),
            base: next.applied,
            state: wire::digest(&next.application),
            scan: next.applied,
            reverse: vec![qc.node],
            verified: true,
        });
        Ok(())
    }
    #[cfg(test)]
    pub fn apply_turn(
        &mut self,
        mut execute: impl FnMut(&[u8], &Committed) -> Result<Execution>,
    ) -> Result<Turn> {
        self.apply_turn_with_inputs(|prior, committed| Ok((execute(prior, committed)?, vec![])))
    }
    pub fn apply_turn_with_inputs(
        &mut self,
        mut execute: impl FnMut(
            &[u8],
            &Committed,
        )
            -> Result<(Execution, Vec<crate::authority_objects::Reference>)>,
    ) -> Result<Turn> {
        self.active()?;
        if self.halted()
            || self.snapshot.applied == self.snapshot.committed
                && self.snapshot.apply_cursor.is_none()
        {
            return Ok(Turn::Idle);
        }
        if self
            .snapshot
            .apply_cursor
            .as_ref()
            .is_none_or(|cursor| !cursor.verified)
        {
            let mut next = self.snapshot.clone();
            let mut cursor = if let Some(cursor) = next.apply_cursor.take() {
                cursor
            } else {
                let certificate = *next
                    .commit_certificates
                    .get(&id(&next.committed))
                    .context("Actual deciding certificate missing")?;
                Cursor {
                    target: next.committed,
                    certificate,
                    base: next.applied,
                    state: wire::digest(&next.application),
                    scan: next.committed,
                    reverse: Vec::new(),
                    verified: false,
                }
            };
            let qc = certificate(&self.configuration, &next, &cursor.certificate)?;
            ensure!(
                qc.phase == Phase::Commit && qc.node == cursor.target,
                "Application target lacks a CommitQC"
            );
            ensure!(
                cursor.base == next.applied && cursor.state == wire::digest(&next.application),
                "Application base changed during discovery"
            );
            let base_height = node(&self.configuration, &next, &cursor.base)?.height;
            for _ in 0..64 {
                if cursor.scan == cursor.base {
                    cursor.verified = true;
                    break;
                }
                ensure!(
                    cursor.reverse.len() < MAX_NODES,
                    "Committed discovery exceeds retained storage"
                );
                let n = node(&self.configuration, &next, &cursor.scan)?;
                ensure!(
                    n.height > base_height,
                    "Deciding branch does not extend applied state"
                );
                cursor.reverse.push(cursor.scan);
                cursor.scan = n
                    .parent
                    .context("Committed ancestry ended before the applied base")?;
            }
            if cursor.scan == cursor.base {
                cursor.verified = true;
            }
            next.apply_cursor = Some(cursor);
            // The committed/applied roots already survive a crash. Publish initial discovery
            // with its first bounded scan before any application callback or output.
            self.persist(next)?;
            return Ok(Turn::Progress);
        }
        let cursor = self
            .snapshot
            .apply_cursor
            .as_ref()
            .context("Application cursor missing")?;
        if cursor.reverse.is_empty() {
            let mut next = self.snapshot.clone();
            next.apply_cursor = None;
            self.persist(next)?;
            return Ok(Turn::Progress);
        }
        if self.snapshot.candidates.len() >= 2 {
            return Ok(Turn::Blocked("Checkpoint candidates require certification"));
        }
        let digest = *cursor.reverse.last().unwrap();
        let n = self.known_node(&digest)?;
        ensure!(
            n.parent == Some(self.snapshot.applied),
            "Application cursor lost its next exact parent"
        );
        let command = self.command(&n.command.context("Committed command missing")?)?;
        let inert = matches!(
            Command::parse(&self.configuration, &command)?,
            Command::Inert | Command::Noop(_)
        );
        if !inert && self.snapshot.executed.len() >= storage::MAX_RESULTS {
            return Ok(Turn::Blocked("Retained result capacity exhausted"));
        }
        // A candidate aliases this exact new application object. Reserve its
        // complete allocation while every old root remains durable.
        if !Self::state_reservation(&self.snapshot)? {
            return Ok(Turn::Blocked("Application state allocation exhausted"));
        }
        if !inert && !Self::result_reservation(&self.snapshot)? {
            return Ok(Turn::Blocked("Retained result allocation exhausted"));
        }
        // Retain the conservative metadata admission allowance as well as the
        // separate state-object reservation; descriptor storage does not raise
        // the existing journal or execution limits.
        let copies = if n.height.is_multiple_of(checkpoint::INTERVAL) {
            2
        } else {
            1
        };
        let current_metadata = serde_json::to_vec(&self.snapshot)?.len();
        if current_metadata
            .checked_add(checkpoint::MAX_STATE * 4 * copies + 4096)
            .is_none_or(|n| n > journal::MAXIMUM)
        {
            return Ok(Turn::Blocked("Application metadata reservation exhausted"));
        }
        let position = Committed {
            node: digest,
            height: n.height,

            evaluated_at: n.evaluated_at,
            command,
        };
        let (execution, retained) = match execute(&self.snapshot.application, &position) {
            Ok(execution) => execution,
            Err(error) => {
                if let Some(missing) = error.downcast_ref::<crate::authority_objects::Unavailable>()
                {
                    return Ok(Turn::Unavailable(missing.0.clone()));
                }
                return Err(error);
            }
        };
        validate_execution(&self.configuration, &position, &execution)?;
        let mut next = self.snapshot.clone();
        next.applied = digest;
        next.application = storage::StateObject::staged(objects(&next)?, execution.state)?;
        next.inputs.set_application(&retained)?;
        next.archive_size = next
            .archive_size
            .checked_add(1)
            .context("Archive height overflow")?;
        next.archive_root = self.archive.next_root(digest);
        let output = match execution.output {
            ExecutionOutput::Inert => Turn::Inert,
            ExecutionOutput::Result {
                result,
                attestation,
            } => {
                let envelope = wire::sign_envelope(&attestation, &self.key)?;
                ensure!(
                    envelope.len() <= 4096 && result.len() <= MAX_RESULT_BYTES,
                    "Executed output exceeds its declared budget"
                );
                let bundle = wire::encode(&V::Array(vec![
                    V::Bytes(n.encode()?),
                    V::Bytes(envelope.clone()),
                    V::Bytes(result.clone()),
                ]))?;
                ensure!(
                    bundle.len() <= peer::MAX_PAYLOAD,
                    "Executed output cannot fit the peer transport"
                );
                let value = wire::decode(&attestation)?;
                let expires = record(&value, 23, 23)?[19].uint()?;
                let object =
                    objects(&next)?.staged(storage::EXECUTION, wire::digest(&bundle), &bundle)?;
                next.executed.insert(
                    id(&digest),
                    StoredExecution {
                        object,
                        command: n.command.unwrap(),
                        expires,
                        height: n.height,
                    },
                );
                Turn::Result(
                    n.clone(),
                    ExecutionRecord {
                        result,
                        attestation: envelope,
                    },
                )
            }
        };
        let mut cursor = next.apply_cursor.take().unwrap();
        ensure!(
            cursor.reverse.pop() == Some(digest),
            "Application cursor changed"
        );
        cursor.base = digest;
        cursor.state = wire::digest(&next.application);
        let halted = self.halt_terminal(&mut next, &n, cursor.certificate)?;
        if !halted {
            if !cursor.reverse.is_empty() {
                next.apply_cursor = Some(cursor);
            }
            let candidate_state = next.application.clone();
            self.candidate(&mut next, &n, candidate_state)?;
        }
        // Every immutable dependency and reserved output reaches disk before the
        // journal and archive can expose this applied position or signature.
        self.publish_applied(next, &[digest])?;
        Ok(output)
    }
    pub fn execution(&self, digest: Digest) -> Result<Option<ExecutionRecord>> {
        let Some(saved) = self.snapshot.executed.get(&id(&digest)) else {
            return Ok(None);
        };
        ensure!(
            saved.object.kind == storage::EXECUTION,
            "Execution object kind differs"
        );
        let raw = body(&self.snapshot, &saved.object)?;
        ensure!(
            wire::digest(&raw) == saved.object.identity,
            "Execution object identity differs"
        );
        let v = wire::decode(&raw)?;
        let a = v.array(3)?;
        let n = Node::parse(&self.configuration, a[0].bytes()?)?;
        ensure!(
            n.digest()? == digest && n.command == Some(saved.command) && n.height == saved.height,
            "Stored execution index differs"
        );
        Ok(Some(ExecutionRecord {
            attestation: a[1].bytes()?.to_vec(),
            result: a[2].bytes()?.to_vec(),
        }))
    }
    pub(super) fn applied_candidate_commitment(&self, n: &Node) -> Result<(Digest, Digest)> {
        let c = self
            .snapshot
            .apply_cursor
            .as_ref()
            .context("Checkpoint requires local executed commit discovery")?;
        ensure!(
            c.verified && c.reverse.last() == Some(&n.digest()?),
            "Checkpoint lacks the exact applied cursor"
        );
        let qc = self.known_certificate(&c.certificate)?;
        ensure!(
            qc.phase == Phase::Commit && qc.node == c.target,
            "Checkpoint lacks actual deciding evidence"
        );
        Ok((c.certificate, c.target))
    }
    pub(super) fn cursor_roots(state: &Snapshot) -> Vec<Digest> {
        state
            .apply_cursor
            .as_ref()
            .map_or(Vec::new(), |c| vec![c.target, c.base, c.scan])
    }
    pub(super) fn cursor_certificate(state: &Snapshot) -> Option<Digest> {
        state.apply_cursor.as_ref().map(|c| c.certificate)
    }
    pub(super) fn validate_application_cursor(&self) -> Result<()> {
        let Some(c) = &self.snapshot.apply_cursor else {
            return Ok(());
        };
        let qc = self.known_certificate(&c.certificate)?;
        ensure!(
            qc.phase == Phase::Commit
                && qc.node == c.target
                && c.base == self.snapshot.applied
                && c.state == wire::digest(&self.snapshot.application)
                && c.reverse.len() <= MAX_NODES,
            "Durable application cursor binding differs"
        );
        let mut previous = c.target;
        for (index, digest) in c.reverse.iter().enumerate() {
            if index == 0 {
                ensure!(*digest == c.target, "Application cursor target differs");
            } else {
                ensure!(
                    self.known_node(&previous)?.parent == Some(*digest),
                    "Application cursor ancestry differs"
                );
            }
            previous = *digest;
        }
        let bottom = c
            .reverse
            .last()
            .map(|digest| self.known_node(digest))
            .transpose()?
            .and_then(|n| n.parent)
            .unwrap_or(c.target);
        if !c.verified {
            ensure!(bottom == c.scan, "Application discovery cursor differs");
        } else {
            ensure!(
                bottom == c.base,
                "Verified application suffix lost its base"
            );
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn apply_committed(
        &mut self,
        mut execute: impl FnMut(&[u8], &Committed) -> Result<Execution>,
    ) -> Result<Vec<ExecutionRecord>> {
        let mut result = Vec::new();
        for _ in 0..MAX_NODES * 2 {
            match self.apply_turn(&mut execute)? {
                Turn::Idle | Turn::Blocked(_) | Turn::Unavailable(_) => return Ok(result),
                Turn::Result(_, record) => result.push(record),
                Turn::Inert | Turn::Progress => {}
            }
        }
        anyhow::bail!("Test application turns exceeded retained capacity")
    }
}
