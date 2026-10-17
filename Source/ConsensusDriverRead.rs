// SPDX-License-Identifier: MIT
// Volatile fresh-query shares never enter consensus streams or the durable outbox.
use super::*;
use crate::{
    authority_proof::Challenge,
    authority_read::{self as read, Request, Statement},
};
const MAX_READ_BYTES: usize = 4 * peer::MAX_PAYLOAD;
pub(super) struct Collection {
    scope: crate::authority_proof::Scope,
    request: Vec<u8>,
    challenge: Vec<u8>,
    expires: Instant,
    attempted: Option<Instant>,
    candidates: VecDeque<Candidate>,
}
pub(super) struct Candidate {
    node: Vec<u8>,
    payload: Vec<u8>,
    result: Vec<u8>,
    signatures: BTreeMap<Key, [u8; 64]>,
    expires: Instant,
}
impl Collection {
    fn bytes(&self) -> usize {
        self.request.len()
            + self.challenge.len()
            + self.candidates.iter().map(Candidate::bytes).sum::<usize>()
    }
}
impl Candidate {
    fn bytes(&self) -> usize {
        self.node.len() + self.payload.len() + self.result.len() + self.signatures.len() * 96
    }
}
impl Driver {
    pub(super) fn expire_reads(&mut self) {
        self.expire_reads_at(Instant::now());
    }
    fn expire_reads_at(&mut self, now: Instant) {
        let scope = self.config().descriptor().scope().clone();
        self.reads
            .retain(|_, r| now < r.expires && r.scope == scope);
        for collection in self.reads.values_mut() {
            collection
                .candidates
                .retain(|candidate| now < candidate.expires);
        }
    }
    fn read_bytes(&self) -> usize {
        self.reads.values().map(Collection::bytes).sum()
    }
    fn read_evaluation(
        &self,
        request: &Request,
        challenge: &Challenge,
        at: u64,
        now: u64,
    ) -> Result<(Statement, Vec<u8>, Vec<u8>)> {
        let node = self.engine.read_anchor()?;
        ensure!(
            request.scope == *self.config().descriptor().scope()
                && node.height >= request.minimum_height,
            "fresh read floor not available"
        );
        request.validate_challenge(challenge)?;
        ensure!(
            at.abs_diff(now) <= super::super::read::READ_ADMISSION_MS && at >= node.evaluated_at,
            "fresh evaluation is outside clock window"
        );
        let expires = challenge.evaluation_expiry(at, challenge.expires_at_ms)?;
        let (result, expires) =
            self.application
                .read(self.engine.application(), request, at, expires)?;
        ensure!(
            result.len() <= super::super::MAX_RESULT_BYTES
                && challenge.evaluation_expiry(at, expires)? == expires,
            "fresh result exceeds its original bound"
        );
        let statement = Statement {
            scope: request.scope.clone(),
            request: request.digest,
            challenge: challenge.digest,
            requester: request.requester,
            recipient: request.recipient,
            height: node.height,
            node: node.digest()?,
            state: wire::digest(self.engine.application()),
            evaluated_at_ms: at,
            expires_at_ms: expires,
            result: wire::digest(&result),
        };
        Ok((statement, node.encode()?, result))
    }
    pub(super) fn read_probe(
        &mut self,
        sender: Key,
        request: Vec<u8>,
        challenge: Vec<u8>,
        proposed: Vec<u8>,
    ) -> Result<()> {
        let parsed = Request::from_signed(&request)?;
        let challenge_value = Challenge::from_signed(&challenge)?;
        let proposal = Statement::parse(&proposed)?;
        let Ok(now) = self.now() else {
            return Ok(());
        };
        // A moving or lagging peer contributes no share. It never evaluates a supplied snapshot.
        let Ok((statement, node, result)) =
            self.read_evaluation(&parsed, &challenge_value, proposal.evaluated_at_ms, now)
        else {
            return Ok(());
        };
        if statement.encode()? != proposed {
            return Ok(());
        }
        let share = self.engine.sign_read(&statement, self.now()?)?;
        let message = Message::ReadShare(read::read_id(&request, &challenge)?, node, share, result);
        ensure!(
            message.payload()?.len() <= peer::MAX_PAYLOAD,
            "fresh peer response exceeds bound"
        );
        self.send(sender, &message)
    }
    pub(super) fn read_share(
        &mut self,
        sender: Key,
        id: Digest,
        node: Vec<u8>,
        share: Vec<u8>,
        result: Vec<u8>,
    ) -> Result<()> {
        self.expire_reads();
        let (payload, signatures) = wire::envelope(&share, 1)?;
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == sender
                && self.config().voters.contains(&sender),
            "fresh peer signer differs"
        );
        let used = self.read_bytes();
        let Some(collection) = self.reads.get_mut(&id) else {
            return Ok(());
        };
        let Some(candidate) = collection
            .candidates
            .iter_mut()
            .find(|c| c.node == node && c.payload == payload && c.result == result)
        else {
            return Ok(());
        };
        if let std::collections::btree_map::Entry::Vacant(entry) =
            candidate.signatures.entry(sender)
        {
            ensure!(
                used + 96 <= MAX_READ_BYTES,
                "fresh collection byte bound reached"
            );
            entry.insert(signatures[0].1);
        }
        Ok(())
    }
    pub(super) fn read_start(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.expire_reads();
        let value = wire::decode(payload)?;
        let f = value.array(2)?;
        let request = f[0].bytes()?.to_vec();
        let challenge = f[1].bytes()?.to_vec();
        let id = read::read_id(&request, &challenge)?;
        let parsed = Request::from_signed(&request)?;
        ensure!(
            parsed.scope == *self.config().descriptor().scope(),
            "fresh local scope differs"
        );
        if let Some(old) = self.reads.get(&id) {
            ensure!(
                old.request == request && old.challenge == challenge,
                "fresh identifier collision"
            );
            return self.read_poll(id);
        }
        let challenge_value = Challenge::from_signed(&challenge)?;
        let Ok(now) = self.now() else {
            return self.read_reply(2, 1, id, None);
        };
        let upper = now
            .checked_add(crate::authority_challenge::DELTA_MS)
            .context("fresh clock overflow")?;
        if upper >= challenge_value.expires_at_ms {
            return self.read_reply(2, 1, id, None);
        }
        let remaining = challenge_value.expires_at_ms - upper;
        ensure!(
            remaining <= crate::authority_challenge::MAXIMUM_DURATION_MS,
            "fresh deadline exceeds original profile"
        );
        if self.reads.len() >= MAX_PENDING
            || self.read_bytes() + request.len() + challenge.len() > MAX_READ_BYTES
        {
            return self.read_reply(2, 2, id, None);
        }
        self.reads.insert(
            id,
            Collection {
                scope: parsed.scope,
                request,
                challenge,
                expires: Instant::now() + Duration::from_millis(remaining),
                attempted: None,
                candidates: VecDeque::new(),
            },
        );
        self.read_poll(id)
    }
    pub(super) fn read_poll(&mut self, id: Digest) -> Result<Vec<u8>> {
        let now = self.now();
        self.read_poll_at(id, Instant::now(), now)
    }
    pub(super) fn read_poll_at(
        &mut self,
        id: Digest,
        monotonic: Instant,
        now: Result<u64>,
    ) -> Result<Vec<u8>> {
        self.expire_reads_at(monotonic);
        let Some(collection) = self.reads.get_mut(&id) else {
            return self.read_reply(2, 1, id, None);
        };
        let Ok(now) = now else {
            return self.read_reply(0, 0, id, None);
        };
        let upper = now
            .checked_add(crate::authority_challenge::DELTA_MS)
            .context("fresh clock overflow")?;
        // Monotonic limits never extend, and a forward clock correction cannot expose an expired
        // retained statement as complete even if its original monotonic allowance remains.
        collection.candidates.retain(|candidate| {
            Statement::parse(&candidate.payload)
                .is_ok_and(|statement| upper < statement.expires_at_ms)
        });
        let collection = self.reads.get(&id).context("fresh collection absent")?;
        if let Some(candidate) = collection
            .candidates
            .iter()
            .find(|c| c.signatures.len() >= 3)
        {
            return self.read_reply(1, 0, id, Some(candidate));
        }
        if collection
            .attempted
            .is_some_and(|last| monotonic.saturating_duration_since(last) < RETRANSMIT)
        {
            return self.read_reply(0, 0, id, None);
        }
        let request = collection.request.clone();
        let challenge = collection.challenge.clone();
        self.reads
            .get_mut(&id)
            .context("fresh collection absent")?
            .attempted = Some(monotonic);
        let Ok(anchor) = self.engine.read_anchor() else {
            return self.read_reply(0, 0, id, None);
        };
        let anchor = anchor.digest()?;
        let state = wire::digest(self.engine.application());
        // Stable current state retransmits the exact statement and retains its in-flight shares.
        let retained = self
            .reads
            .get(&id)
            .context("fresh collection absent")?
            .candidates
            .iter()
            .rev()
            .find_map(|candidate| {
                let statement = Statement::parse(&candidate.payload).ok()?;
                (statement.node == anchor
                    && statement.state == state
                    && statement.evaluated_at_ms.abs_diff(now)
                        <= super::super::read::READ_ADMISSION_MS)
                    .then(|| candidate.payload.clone())
            });
        let payload = if let Some(payload) = retained {
            payload
        } else {
            let parsed = Request::from_signed(&request)?;
            let challenge_value = Challenge::from_signed(&challenge)?;
            let Ok((statement, node, result)) =
                self.read_evaluation(&parsed, &challenge_value, now, now)
            else {
                return self.read_reply(0, 0, id, None);
            };
            let share = self.engine.sign_read(&statement, now)?;
            let (payload, signatures) = wire::envelope(&share, 1)?;
            let upper = now
                .checked_add(crate::authority_challenge::DELTA_MS)
                .context("fresh clock overflow")?;
            let duration = statement
                .expires_at_ms
                .checked_sub(upper)
                .context("fresh statement expired")?;
            let expires = monotonic
                .checked_add(Duration::from_millis(duration))
                .context("fresh statement deadline overflow")?
                .min(
                    self.reads
                        .get(&id)
                        .context("fresh collection absent")?
                        .expires,
                );
            let candidate = Candidate {
                node,
                payload: payload.clone(),
                result,
                signatures: signatures.into_iter().collect(),
                expires,
            };
            // A new current anchor cannot erase still-valid delayed signatures for an earlier read.
            // Every candidate remains under the same aggregate allocation and original deadline.
            if self.read_bytes() + candidate.bytes() > MAX_READ_BYTES {
                return self.read_reply(2, 2, id, None);
            }
            self.reads
                .get_mut(&id)
                .context("fresh collection absent")?
                .candidates
                .push_back(candidate);
            payload
        };
        let message = Message::ReadProbe(request, challenge, payload);
        ensure!(
            message.payload()?.len() <= peer::MAX_PAYLOAD,
            "fresh probe exceeds bound"
        );
        for peer in self.senders.keys() {
            self.send(*peer, &message)?;
        }
        self.read_reply(0, 0, id, None)
    }
    pub(super) fn read_reply(
        &self,
        status: u64,
        code: u64,
        id: Digest,
        candidate: Option<&Candidate>,
    ) -> Result<Vec<u8>> {
        let (node, certificate, result) = if let Some(candidate) = candidate {
            let signatures = V::Array(
                candidate
                    .signatures
                    .iter()
                    .map(|(k, s)| V::Array(vec![V::Bytes(k.to_vec()), V::Bytes(s.to_vec())]))
                    .collect(),
            );
            let certificate = wire::encode(&V::Array(vec![
                V::Uint(0),
                V::Uint(1),
                V::Bytes(candidate.payload.clone()),
                signatures,
            ]))?;
            (
                V::Bytes(candidate.node.clone()),
                V::Bytes(certificate),
                V::Bytes(candidate.result.clone()),
            )
        } else {
            (V::Null, V::Null, V::Null)
        };
        wire::encode(&V::Array(vec![
            V::Uint(62),
            V::Uint(1),
            self.config().scope.value(),
            V::Uint(status),
            V::Uint(code),
            V::Bytes(id.to_vec()),
            node,
            certificate,
            result,
            V::Array(vec![]),
        ]))
    }
}
