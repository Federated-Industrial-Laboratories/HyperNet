// SPDX-License-Identifier: MIT
// Own-stream metadata validates bounded status and exact generation-fence results.
use super::{Digest, Disposition, ExecutedResult, Key, OperationResult, Scope, SignedRequest};
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Context, Result, ensure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionMetadata {
    pub sequence: u64,
    pub intent: Digest,
    pub disposition: Disposition,
    pub reason: u64,
    pub result_digest: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastFenceMetadata {
    pub digest: Digest,
    pub expected_metadata_digest: Digest,
    pub previous_generation: u64,
    pub previous_generation_id: Digest,
    pub previous_retired_through: u64,
    pub previous_completion: Option<CompletionMetadata>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamState {
    pub generation: u64,
    pub generation_id: Digest,
    pub retired_through: u64,
    pub completion: Option<CompletionMetadata>,
    pub last_fence: Option<LastFenceMetadata>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnStreamMetadata {
    canonical: Vec<u8>,
    scope: Scope,
    requester: Key,
    state: Option<StreamState>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceOutcome {
    Applied,
    AlreadyApplied,
    AttemptRefused,
    Superseded,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamResponse {
    Status(OwnStreamMetadata),
    Fence {
        outcome: FenceOutcome,
        metadata: OwnStreamMetadata,
    },
}
impl StreamResponse {
    #[cfg(test)]
    pub fn metadata(&self) -> &OwnStreamMetadata {
        match self {
            Self::Status(metadata) | Self::Fence { metadata, .. } => metadata,
        }
    }
}
fn completion(value: &V, retired: u64) -> Result<Option<CompletionMetadata>> {
    if *value == V::Null {
        return Ok(None);
    }
    let f = value.array(5)?;
    let sequence = f[0].uint()?;
    ensure!(
        retired.checked_add(1) == Some(sequence),
        "completion sequence differs from retirement floor"
    );
    let reason = f[3].uint()?;
    let disposition = match (f[2].uint()?, reason) {
        (0, 0) => Disposition::Permit,
        (1, 1..=38) => Disposition::Refuse,
        (2, 25 | 27 | 30) => Disposition::Pending,
        _ => anyhow::bail!("invalid stream completion disposition or reason"),
    };
    Ok(Some(CompletionMetadata {
        sequence,
        intent: super::id(&f[1])?,
        disposition,
        reason,
        result_digest: super::id(&f[4])?,
    }))
}
pub fn initial_generation_id(
    network: Digest,
    incarnation: Digest,
    requester: Key,
) -> Result<Digest> {
    wire::valid_key(&requester)?;
    ensure!(
        network != [0; 32] && incarnation != [0; 32] && network != incarnation,
        "invalid initial stream context"
    );
    Ok(wire::digest(&wire::encode(&V::Array(vec![
        V::Text("HyperNet/StreamInitial".into()),
        V::Uint(1),
        V::Bytes(network.to_vec()),
        V::Bytes(incarnation.to_vec()),
        V::Bytes(requester.to_vec()),
    ]))?))
}
impl OwnStreamMetadata {
    /// Parsing establishes structure; only an exact certified response establishes current metadata.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 486, "stream metadata exceeds its bound");
        let value = wire::decode(bytes)?;
        let f = super::record(&value, 56, 10)?;
        let scope = Scope::parse(&f[2])?;
        let requester = super::key(&f[3])?;
        let present = f[4].boolean()?;
        let retired = f[7].uint()?;
        let state = if present {
            let generation = f[5].uint()?;
            let generation_id = super::id(&f[6])?;
            ensure!(generation > 0, "zero stream generation");
            let initial = initial_generation_id(scope.network, scope.incarnation, requester)?;
            let last_fence = if f[9] == V::Null {
                ensure!(
                    generation == 1 && generation_id == initial,
                    "initial stream identity differs"
                );
                None
            } else {
                let previous = f[9].array(6)?;
                let previous_generation = previous[2].uint()?;
                let previous_generation_id = super::id(&previous[3])?;
                let previous_retired = previous[4].uint()?;
                let digest = super::id(&previous[0])?;
                ensure!(
                    previous_generation > 0
                        && previous_generation.checked_add(1) == Some(generation)
                        && digest == generation_id
                        && (previous_generation != 1 || previous_generation_id == initial),
                    "last fence differs from the current stream generation"
                );
                Some(LastFenceMetadata {
                    digest,
                    expected_metadata_digest: super::id(&previous[1])?,
                    previous_generation,
                    previous_generation_id,
                    previous_retired_through: previous_retired,
                    previous_completion: completion(&previous[5], previous_retired)?,
                })
            };
            Some(StreamState {
                generation,
                generation_id,
                retired_through: retired,
                completion: completion(&f[8], retired)?,
                last_fence,
            })
        } else {
            ensure!(
                f[5] == V::Null
                    && f[6] == V::Null
                    && retired == 0
                    && f[8] == V::Null
                    && f[9] == V::Null,
                "absent stream contains retained state"
            );
            None
        };
        Ok(Self {
            canonical: bytes.to_vec(),
            scope,
            requester,
            state,
        })
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn requester(&self) -> Key {
        self.requester
    }
    pub fn state(&self) -> Option<&StreamState> {
        self.state.as_ref()
    }
}
fn bind(
    metadata: &OwnStreamMetadata,
    request: &SignedRequest,
    executed: &ExecutedResult,
) -> Result<()> {
    ensure!(
        metadata.scope() == &executed.scope
            && metadata.requester() == request.requester()
            && executed.requester == executed.recipient
            && executed.restrictions == super::Restrictions::default(),
        "stream response context or recipient differs"
    );
    Ok(())
}
pub(super) fn validate(
    request: &SignedRequest,
    result: &OperationResult,
    executed: &ExecutedResult,
    expected_stream: Option<&[u8]>,
) -> Result<StreamResponse> {
    ensure!(
        executed.maximum_effect == u64::from(result.disposition == Disposition::Permit),
        "stream result has an invalid effect bound"
    );
    match request {
        SignedRequest::Intent(_) => anyhow::bail!("ordinary intent is not a stream control"),
        SignedRequest::StreamStatus(_) => {
            ensure!(
                expected_stream.is_none(),
                "status cannot name expected fence metadata"
            );
            ensure!(
                matches!(
                    (result.disposition, result.code),
                    (Disposition::Permit, 0) | (Disposition::Refuse, 7 | 21 | 37)
                ),
                "invalid own-stream status disposition or reason"
            );
            let metadata = OwnStreamMetadata::parse(&result.value)?;
            bind(&metadata, request, executed)?;
            Ok(StreamResponse::Status(metadata))
        }
        SignedRequest::StreamFence(fence) => {
            let expected = OwnStreamMetadata::parse(
                expected_stream.context("exact prepared fence metadata is required")?,
            )?;
            let prior = expected
                .state()
                .context("a fence cannot be prepared from an absent stream")?;
            bind(&expected, request, executed)?;
            ensure!(
                prior.generation == fence.expected_generation
                    && prior.generation_id == fence.expected_generation_id
                    && wire::digest(expected.canonical()) == fence.expected_metadata_digest,
                "prepared metadata differs from the exact signed fence"
            );
            ensure!(result.value.len() <= 674, "fence result exceeds its bound");
            let value = wire::decode(&result.value)?;
            let f = super::record(&value, 58, 7)?;
            ensure!(
                Scope::parse(&f[2])? == executed.scope
                    && super::key(&f[3])? == fence.requester
                    && super::id(&f[4])? == fence.digest,
                "fence result identity differs"
            );
            let outcome = match f[5].uint()? {
                0 => FenceOutcome::Applied,
                1 => FenceOutcome::AlreadyApplied,
                2 => FenceOutcome::AttemptRefused,
                3 => FenceOutcome::Superseded,
                _ => anyhow::bail!("unknown fence outcome"),
            };
            let metadata = OwnStreamMetadata::parse(f[6].bytes()?)?;
            bind(&metadata, request, executed)?;
            match outcome {
                FenceOutcome::Applied | FenceOutcome::AlreadyApplied => {
                    ensure!(
                        result.disposition == Disposition::Permit && result.code == 0,
                        "successful fence has a non-permit result"
                    );
                    let current = metadata
                        .state()
                        .context("successful fence omitted the stream")?;
                    let last = current
                        .last_fence
                        .as_ref()
                        .context("successful fence omitted its retained outcome")?;
                    ensure!(
                        fence.expected_generation.checked_add(1) == Some(current.generation)
                            && current.generation_id == fence.digest
                            && last.digest == fence.digest
                            && last.expected_metadata_digest == fence.expected_metadata_digest
                            && last.previous_generation == prior.generation
                            && last.previous_generation_id == prior.generation_id
                            && last.previous_retired_through == prior.retired_through
                            && last.previous_completion == prior.completion,
                        "fence outcome changed its exact prepared predecessor"
                    );
                    if outcome == FenceOutcome::Applied {
                        ensure!(
                            current.retired_through == 0 && current.completion.is_none(),
                            "newly applied fence contains later ordinary work"
                        );
                    }
                }
                FenceOutcome::AttemptRefused => ensure!(
                    result.disposition == Disposition::Refuse
                        && matches!(result.code, 2 | 3 | 7 | 12 | 21 | 28 | 37),
                    "invalid fence refusal disposition or reason"
                ),
                FenceOutcome::Superseded => {
                    ensure!(
                        result.disposition == Disposition::Refuse
                            && result.code == 28
                            && fence
                                .expected_generation
                                .checked_add(1)
                                .is_some_and(|next| metadata
                                    .state()
                                    .is_some_and(|state| state.generation > next)),
                        "fence supersession is not established by the current generation"
                    );
                }
            }
            Ok(StreamResponse::Fence { outcome, metadata })
        }
    }
}

#[cfg(test)]
#[path = "AuthorityStreamProofTests.rs"]
mod tests;
