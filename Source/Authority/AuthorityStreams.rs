// SPDX-License-Identifier: MIT
// Permanent signer generations retire receipts without making delayed requests executable.
use crate::{
    authority_proof::{Digest, Disposition, Key, OperationResult, Scope},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_STREAMS: usize = crate::authority_capacity::MAX_STREAMS;
const MAX_BYTES: usize = crate::authority_capacity::MAX_STREAM_BYTES;
const REFUSAL_RESERVE: usize = 512;
const FENCE_ACTION: &str = "AuthorityStreamFence";

#[derive(Clone)]
struct Completion {
    sequence: u64,
    intent: Digest,
    result: Vec<u8>,
}
#[derive(Clone)]
struct Stream {
    generation: u64,
    generation_id: Digest,
    retired: u64,
    last_fence: Option<LastFence>,
    completion: Option<Completion>,
}
#[derive(Clone, Default)]
pub(super) struct Streams {
    entries: BTreeMap<Key, Stream>,
}
pub(super) struct Request {
    pub requester: Key,
    pub generation: u64,
    pub generation_id: Digest,
    pub sequence: u64,
    pub acknowledged_through: u64,
    pub intent: Digest,
}
pub(super) enum Classification<'a> {
    Fresh,
    Replay(&'a [u8]),
    Retired,
    Conflict,
    Gap,
    GenerationConflict,
    Missing,
}
pub(super) struct Recorded {
    pub result: Vec<u8>,
    pub proposed_result_retained: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompletionMetadata {
    pub sequence: u64,
    pub intent: Digest,
    pub disposition: Disposition,
    pub reason: u64,
    pub result_digest: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LastFence {
    pub digest: Digest,
    pub expected_metadata_digest: Digest,
    pub previous_generation: u64,
    pub previous_generation_id: Digest,
    pub previous_retired_through: u64,
    pub previous_completion: Option<CompletionMetadata>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub generation: u64,
    pub generation_id: Digest,
    pub retired_through: u64,
    pub completion: Option<CompletionMetadata>,
    pub last_fence: Option<LastFence>,
}
pub(super) struct FenceRequest {
    pub requester: Key,
    pub digest: Digest,
    pub expected_generation: u64,
    pub expected_generation_id: Digest,
    pub expected_metadata_digest: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(super) enum FenceRefusal {
    LimitExceeded = 2,
    MissingAuthority = 3,
    Expired = 7,
    StaleSnapshot = 12,
    BelowPolicyFloor = 21,
    GenerationConflict = 28,
    WrongContext = 37,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(super) enum FenceOutcome {
    Applied = 0,
    AlreadyApplied = 1,
    AttemptRefused = 2,
    Superseded = 3,
}
pub(super) struct FenceResult {
    #[cfg(test)]
    pub outcome: FenceOutcome,
    pub code: u64,
    #[cfg(test)]
    pub metadata: Vec<u8>,
    pub value: Vec<u8>,
}
impl FenceResult {
    pub fn result(&self) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text(FENCE_ACTION.into()),
            V::Uint(u64::from(self.code != 0)),
            V::Uint(self.code),
            V::Bytes(self.value.clone()),
        ]))
    }
}
fn nonzero(value: &V) -> Result<Digest> {
    let digest = value.fixed()?;
    ensure!(digest != [0; 32], "zero stream identifier");
    Ok(digest)
}
fn disposition(value: Disposition) -> u64 {
    match value {
        Disposition::Permit => 0,
        Disposition::Refuse => 1,
        Disposition::Pending => 2,
    }
}
impl CompletionMetadata {
    fn parse(value: &V, retired: u64) -> Result<Self> {
        let f = value.array(5)?;
        let sequence = f[0].uint()?;
        let reason = f[3].uint()?;
        let disposition = match (f[2].uint()?, reason) {
            (0, 0) => Disposition::Permit,
            (1, 1..=38) => Disposition::Refuse,
            (2, 25 | 27 | 30) => Disposition::Pending,
            _ => anyhow::bail!("invalid completion disposition or reason"),
        };
        ensure!(
            retired.checked_add(1) == Some(sequence),
            "completion is not the next stream sequence"
        );
        Ok(Self {
            sequence,
            intent: nonzero(&f[1])?,
            disposition,
            reason,
            result_digest: nonzero(&f[4])?,
        })
    }
    fn value(&self) -> V {
        V::Array(vec![
            V::Uint(self.sequence),
            V::Bytes(self.intent.to_vec()),
            V::Uint(disposition(self.disposition)),
            V::Uint(self.reason),
            V::Bytes(self.result_digest.to_vec()),
        ])
    }
}
impl Completion {
    fn metadata(&self) -> Result<CompletionMetadata> {
        let result = OperationResult::parse(&self.result)?;
        Ok(CompletionMetadata {
            sequence: self.sequence,
            intent: self.intent,
            disposition: result.disposition,
            reason: result.code,
            result_digest: wire::digest(&self.result),
        })
    }
}
impl LastFence {
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(6)?;
        let previous_generation = f[2].uint()?;
        ensure!(previous_generation > 0, "zero previous stream generation");
        let previous_retired_through = f[4].uint()?;
        Ok(Self {
            digest: nonzero(&f[0])?,
            expected_metadata_digest: nonzero(&f[1])?,
            previous_generation,
            previous_generation_id: nonzero(&f[3])?,
            previous_retired_through,
            previous_completion: if f[5] == V::Null {
                None
            } else {
                Some(CompletionMetadata::parse(&f[5], previous_retired_through)?)
            },
        })
    }
    fn value(&self) -> V {
        V::Array(vec![
            V::Bytes(self.digest.to_vec()),
            V::Bytes(self.expected_metadata_digest.to_vec()),
            V::Uint(self.previous_generation),
            V::Bytes(self.previous_generation_id.to_vec()),
            V::Uint(self.previous_retired_through),
            self.previous_completion
                .as_ref()
                .map_or(V::Null, CompletionMetadata::value),
        ])
    }
    fn matches(&self, request: &FenceRequest) -> bool {
        self.digest == request.digest
            && self.expected_metadata_digest == request.expected_metadata_digest
            && self.previous_generation == request.expected_generation
            && self.previous_generation_id == request.expected_generation_id
    }
}
fn entry(key: &Key, stream: &Stream) -> V {
    V::Array(vec![
        V::Bytes(key.to_vec()),
        V::Uint(stream.generation),
        V::Bytes(stream.generation_id.to_vec()),
        V::Uint(stream.retired),
        stream.last_fence.as_ref().map_or(V::Null, LastFence::value),
        stream.completion.as_ref().map_or(V::Null, |c| {
            V::Array(vec![
                V::Uint(c.sequence),
                V::Bytes(c.intent.to_vec()),
                V::Bytes(c.result.clone()),
            ])
        }),
    ])
}
fn charge(key: &Key, stream: &Stream) -> Result<usize> {
    Ok(wire::encode(&entry(key, stream))?
        .len()
        .max(REFUSAL_RESERVE))
}
/// Initial identities survive healthy epochs and bind only the network, incarnation and signer.
pub(super) fn initial_id(network: Digest, incarnation: Digest, requester: Key) -> Result<Digest> {
    ensure!(
        network != [0; 32] && incarnation != [0; 32],
        "empty stream context"
    );
    wire::valid_key(&requester)?;
    Ok(wire::digest(&wire::encode(&V::Array(vec![
        V::Text("HyperNet/StreamInitial".into()),
        V::Uint(1),
        V::Bytes(network.to_vec()),
        V::Bytes(incarnation.to_vec()),
        V::Bytes(requester.to_vec()),
    ]))?))
}
impl Streams {
    pub fn keys(&self) -> Vec<Key> {
        self.entries.keys().copied().collect()
    }
    pub fn parse(network: Digest, incarnation: Digest, value: &V) -> Result<Self> {
        let mut entries = BTreeMap::new();
        let mut previous = None;
        for item in value.list(MAX_STREAMS)? {
            let f = item.array(6)?;
            let key = f[0].fixed::<32>()?;
            wire::valid_key(&key)?;
            ensure!(
                previous.is_none_or(|p| p < key),
                "stream keys are not sorted and unique"
            );
            previous = Some(key);
            let generation = f[1].uint()?;
            let generation_id = nonzero(&f[2])?;
            let retired = f[3].uint()?;
            let last_fence = if f[4] == V::Null {
                None
            } else {
                Some(LastFence::parse(&f[4])?)
            };
            ensure!(generation > 0, "zero stream generation");
            if generation == 1 {
                ensure!(last_fence.is_none(), "initial stream has a previous fence");
            } else {
                let fence = last_fence
                    .as_ref()
                    .context("later stream lacks its last fence")?;
                ensure!(
                    fence.previous_generation.checked_add(1) == Some(generation)
                        && fence.digest == generation_id,
                    "last fence does not establish the current generation"
                );
            }
            let completion = if f[5] == V::Null {
                None
            } else {
                let c = f[5].array(3)?;
                let sequence = c[0].uint()?;
                let intent = nonzero(&c[1])?;
                let result = c[2].bytes()?.to_vec();
                ensure!(
                    retired.checked_add(1) == Some(sequence),
                    "retained completion is not the next stream sequence"
                );
                OperationResult::parse(&result)?;
                Some(Completion {
                    sequence,
                    intent,
                    result,
                })
            };
            entries.insert(
                key,
                Stream {
                    generation,
                    generation_id,
                    retired,
                    last_fence,
                    completion,
                },
            );
        }
        let streams = Self { entries };
        streams.validate_context(network, incarnation)?;
        ensure!(
            streams.charged_bytes()? <= MAX_BYTES,
            "stream receipt capacity exceeded"
        );
        Ok(streams)
    }
    fn validate_context(&self, network: Digest, incarnation: Digest) -> Result<()> {
        ensure!(
            network != [0; 32] && incarnation != [0; 32],
            "empty stream context"
        );
        for (key, stream) in &self.entries {
            let initial = initial_id(network, incarnation, *key)?;
            ensure!(
                stream.generation != 1 || stream.generation_id == initial,
                "initial stream identity differs from its context"
            );
            if let Some(fence) = &stream.last_fence {
                ensure!(
                    fence.previous_generation != 1 || fence.previous_generation_id == initial,
                    "previous initial stream identity differs from its context"
                );
            }
        }
        Ok(())
    }
    pub fn value(&self) -> V {
        V::Array(
            self.entries
                .iter()
                .map(|(key, stream)| entry(key, stream))
                .collect(),
        )
    }
    /// Admission is committed with the authorised identity record, never inferred from a request.
    pub fn admit(&mut self, network: Digest, incarnation: Digest, key: Key) -> Result<()> {
        let generation_id = initial_id(network, incarnation, key)?;
        self.validate_context(network, incarnation)?;
        if self.entries.contains_key(&key) {
            return Ok(());
        }
        ensure!(
            self.entries.len() < MAX_STREAMS,
            "permanent signer stream capacity reached"
        );
        self.entries.insert(
            key,
            Stream {
                generation: 1,
                generation_id,
                retired: 0,
                last_fence: None,
                completion: None,
            },
        );
        Ok(())
    }
    fn charged_bytes(&self) -> Result<usize> {
        self.charged_with_reserve(&BTreeSet::new())
    }
    fn charged_with_reserve(&self, operators: &BTreeSet<Key>) -> Result<usize> {
        // Unused permanent slots reserve a finite refusal before any domain effect is evaluated.
        let mut bytes = 2 + (MAX_STREAMS - self.entries.len()) * REFUSAL_RESERVE;
        for (key, stream) in &self.entries {
            bytes = bytes
                .checked_add(reserved_charge(key, stream, operators)?)
                .context("stream size overflow")?;
        }
        Ok(bytes)
    }
    pub fn classify(&self, request: &Request) -> Result<Classification<'_>> {
        ensure!(
            request.generation > 0
                && request.generation_id != [0; 32]
                && request.sequence > 0
                && request.acknowledged_through < request.sequence
                && request.intent != [0; 32],
            "invalid stream generation, sequence, acknowledgement or intent"
        );
        wire::valid_key(&request.requester)?;
        let Some(stream) = self.entries.get(&request.requester) else {
            return Ok(Classification::Missing);
        };
        if stream.generation != request.generation || stream.generation_id != request.generation_id
        {
            return Ok(Classification::GenerationConflict);
        }
        if request.sequence <= stream.retired {
            return Ok(Classification::Retired);
        }
        let retired = stream.retired.max(request.acknowledged_through);
        if retired.checked_add(1) != Some(request.sequence) {
            return Ok(Classification::Gap);
        }
        Ok(match &stream.completion {
            Some(c) if c.sequence > retired => {
                if c.sequence != request.sequence {
                    Classification::Gap
                } else if c.intent == request.intent {
                    Classification::Replay(&c.result)
                } else {
                    Classification::Conflict
                }
            }
            _ => Classification::Fresh,
        })
    }
    /// The containing application commits this receipt and its permitted effect in one state.
    /// Authority and exact-snapshot checks use the original state before this retirement.
    #[cfg(test)]
    pub fn record(
        &mut self,
        request: &Request,
        proposed_result: &[u8],
        capacity_refusal: &[u8],
    ) -> Result<Recorded> {
        self.record_reserved(request, proposed_result, capacity_refusal, &BTreeSet::new())
    }
    pub fn validate_reserve(&self, operators: &BTreeSet<Key>) -> Result<()> {
        ensure!(
            operators.iter().all(|key| self.entries.contains_key(key))
                && self.charged_with_reserve(operators)? <= MAX_BYTES,
            "terminal withdrawal receipt reservation exceeds capacity"
        );
        Ok(())
    }
    pub fn record_reserved(
        &mut self,
        request: &Request,
        proposed_result: &[u8],
        capacity_refusal: &[u8],
        operators: &BTreeSet<Key>,
    ) -> Result<Recorded> {
        ensure!(
            matches!(self.classify(request)?, Classification::Fresh),
            "stream request is not fresh"
        );
        let proposed = OperationResult::parse(proposed_result)?;
        let refusal = OperationResult::parse(capacity_refusal)?;
        let refusal_value = wire::decode(&refusal.value)?;
        let f = refusal_value.array(4)?;
        ensure!(
            refusal.action == proposed.action
                && refusal.disposition == Disposition::Refuse
                && refusal.code == 2
                && f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == refusal.action
                && f[3].array(0)?.is_empty(),
            "capacity refusal does not match the finite operation schema"
        );
        let previous = self
            .entries
            .get(&request.requester)
            .context("stream missing")?;
        let retired = previous.retired.max(request.acknowledged_through);
        let make = |bytes: &[u8]| {
            let mut stream = previous.clone();
            stream.retired = retired;
            stream.completion = Some(Completion {
                sequence: request.sequence,
                intent: request.intent,
                result: bytes.to_vec(),
            });
            stream
        };
        let fallback = make(capacity_refusal);
        ensure!(
            charge(&request.requester, &fallback)? == REFUSAL_RESERVE,
            "capacity refusal exceeds its reserved space"
        );
        let candidate = make(proposed_result);
        let total = self.charged_with_reserve(operators)?
            - reserved_charge(&request.requester, previous, operators)?;
        let fits = proposed_result.len() <= crate::consensus::MAX_RESULT_BYTES
            && total
                .checked_add(reserved_charge(&request.requester, &candidate, operators)?)
                .is_some_and(|n| n <= MAX_BYTES);
        let next = if fits { candidate } else { fallback };
        let result = next
            .completion
            .as_ref()
            .context("completion missing")?
            .result
            .clone();
        self.entries.insert(request.requester, next);
        Ok(Recorded {
            result,
            proposed_result_retained: fits,
        })
    }
    /// Metadata refers to the original receipt; a later disclosure refusal must not replace it.
    pub fn metadata(&self, key: &Key) -> Result<Option<Metadata>> {
        let Some(stream) = self.entries.get(key) else {
            return Ok(None);
        };
        Ok(Some(Metadata {
            generation: stream.generation,
            generation_id: stream.generation_id,
            retired_through: stream.retired,
            completion: stream
                .completion
                .as_ref()
                .map(Completion::metadata)
                .transpose()?,
            last_fence: stream.last_fence.clone(),
        }))
    }
    pub fn metadata_bytes(&self, scope: &Scope, requester: &Key) -> Result<Vec<u8>> {
        self.validate_context(scope.network, scope.incarnation)?;
        wire::valid_key(requester)?;
        let metadata = self.metadata(requester)?;
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(56),
            V::Uint(1),
            scope.value(),
            V::Bytes(requester.to_vec()),
            V::Bool(metadata.is_some()),
            metadata.as_ref().map_or(V::Null, |m| V::Uint(m.generation)),
            metadata
                .as_ref()
                .map_or(V::Null, |m| V::Bytes(m.generation_id.to_vec())),
            V::Uint(metadata.as_ref().map_or(0, |m| m.retired_through)),
            metadata
                .as_ref()
                .and_then(|m| m.completion.as_ref())
                .map_or(V::Null, CompletionMetadata::value),
            metadata
                .as_ref()
                .and_then(|m| m.last_fence.as_ref())
                .map_or(V::Null, LastFence::value),
        ]))?;
        ensure!(bytes.len() <= 486, "stream metadata exceeds its bound");
        Ok(bytes)
    }
    /// The caller verifies canonical bytes, requester signature, context and fresh challenge first.
    /// Any finite context or freshness refusal participates in the smallest-applicable-code rule.
    pub fn fence(
        &mut self,
        scope: &Scope,
        request: &FenceRequest,
        refusal: Option<FenceRefusal>,
    ) -> Result<FenceResult> {
        wire::valid_key(&request.requester)?;
        ensure!(
            request.digest != [0; 32]
                && request.expected_generation > 0
                && request.expected_generation_id != [0; 32]
                && request.expected_metadata_digest != [0; 32],
            "invalid fence identity or expected state"
        );
        let metadata = self.metadata_bytes(scope, &request.requester)?;
        let stream = self.entries.get(&request.requester);
        let retry =
            stream.is_some_and(|s| s.last_fence.as_ref().is_some_and(|f| f.matches(request)));
        let next_generation = request.expected_generation.checked_add(1);
        let superseded =
            stream.is_some_and(|s| next_generation.is_some_and(|next| s.generation > next));
        let internal = match stream {
            None => Some(FenceRefusal::MissingAuthority),
            Some(_) if retry => None,
            Some(s)
                if s.generation != request.expected_generation
                    || s.generation_id != request.expected_generation_id =>
            {
                Some(FenceRefusal::GenerationConflict)
            }
            Some(_) if next_generation.is_none() => Some(FenceRefusal::LimitExceeded),
            Some(_) if wire::digest(&metadata) != request.expected_metadata_digest => {
                Some(FenceRefusal::StaleSnapshot)
            }
            Some(_) => None,
        };
        let code = [refusal, internal]
            .into_iter()
            .flatten()
            .map(|r| r as u64)
            .min()
            .unwrap_or(0);
        let outcome = if code != 0 {
            if superseded && code == 28 && refusal.is_none() {
                FenceOutcome::Superseded
            } else {
                FenceOutcome::AttemptRefused
            }
        } else if retry {
            FenceOutcome::AlreadyApplied
        } else {
            FenceOutcome::Applied
        };
        // Encode and check the complete replacement before exposing any mutation to the caller.
        let replacement = if outcome == FenceOutcome::Applied {
            let previous = stream.context("fence stream missing")?;
            let completion = previous
                .completion
                .as_ref()
                .map(Completion::metadata)
                .transpose()?;
            let next = Stream {
                generation: next_generation.context("stream generation overflow")?,
                generation_id: request.digest,
                retired: 0,
                last_fence: Some(LastFence {
                    digest: request.digest,
                    expected_metadata_digest: request.expected_metadata_digest,
                    previous_generation: previous.generation,
                    previous_generation_id: previous.generation_id,
                    previous_retired_through: previous.retired,
                    previous_completion: completion,
                }),
                completion: None,
            };
            ensure!(
                charge(&request.requester, &next)? == REFUSAL_RESERVE,
                "fenced stream exceeds its reserved space"
            );
            let total = self.charged_bytes()? - charge(&request.requester, previous)?;
            ensure!(
                total
                    .checked_add(charge(&request.requester, &next)?)
                    .is_some_and(|n| n <= MAX_BYTES),
                "fence exceeds receipt capacity"
            );
            Some(next)
        } else {
            None
        };
        let metadata = if let Some(next) = &replacement {
            let mut staged = self.clone();
            staged.entries.insert(request.requester, next.clone());
            staged.metadata_bytes(scope, &request.requester)?
        } else {
            metadata
        };
        let value = wire::encode(&V::Array(vec![
            V::Uint(58),
            V::Uint(1),
            scope.value(),
            V::Bytes(request.requester.to_vec()),
            V::Bytes(request.digest.to_vec()),
            V::Uint(outcome as u64),
            V::Bytes(metadata.clone()),
        ]))?;
        ensure!(value.len() <= 674, "fence result exceeds its bound");
        if let Some(next) = replacement {
            self.entries.insert(request.requester, next);
        }
        Ok(FenceResult {
            #[cfg(test)]
            outcome,
            code,
            #[cfg(test)]
            metadata,
            value,
        })
    }
}

#[cfg(test)]
#[path = "AuthorityStreamsTests.rs"]
mod tests;

fn reserved_charge(key: &Key, stream: &Stream, operators: &BTreeSet<Key>) -> Result<usize> {
    Ok(charge(key, stream)?.max(if operators.contains(key) {
        crate::authority_capacity::WITHDRAWAL_RESULT_RESERVE
    } else {
        0
    }))
}
