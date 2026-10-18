// SPDX-License-Identifier: MIT
// Exact signer requests survive uncertain replies and generation changes.
use super::*;
use proof::{CompletionMetadata, FenceOutcome, OwnStreamMetadata, SignedRequest, StreamResponse};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Completion {
    pub sequence: u64,
    pub intent: Digest,
    pub disposition: u64,
    pub reason: u64,
    pub result_digest: Digest,
}
impl From<&CompletionMetadata> for Completion {
    fn from(c: &CompletionMetadata) -> Self {
        Self {
            sequence: c.sequence,
            intent: c.intent,
            disposition: disposition(c.disposition),
            reason: c.reason,
            result_digest: c.result_digest,
        }
    }
}
fn disposition(value: Disposition) -> u64 {
    match value {
        Disposition::Permit => 0,
        Disposition::Refuse => 1,
        Disposition::Pending => 2,
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Reply {
    pub disposition: u64,
    pub reason: u64,
    pub digest: Digest,
}
impl Reply {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.digest != [0; 32]
                && matches!(
                    (self.disposition, self.reason),
                    (0, 0) | (1, 1..=38) | (2, 25 | 27 | 30)
                ),
            "invalid retained response"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum Effect {
    Unclaimed,
    Claimed,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Ordinary {
    pub signed: String,
    #[serde(deserialize_with = "required_option")]
    pub original: Option<Completion>,
    #[serde(deserialize_with = "required_option")]
    pub latest: Option<Reply>,
    pub body_saved: bool,
    pub complete: bool,
    pub effect: Effect,
}
impl Ordinary {
    pub fn request(&self) -> Result<proof::Intent> {
        proof::Intent::from_signed(&hex::decode(&self.signed)?)
    }
    fn original(&mut self, value: Completion) -> Result<()> {
        let request = self.request()?;
        ensure!(
            value.sequence == request.sequence && value.intent == request.digest,
            "original completion differs from pending intent"
        );
        if let Some(prior) = &self.original {
            ensure!(prior == &value, "conflicting original completion");
        }
        if value.disposition == 1 && self.effect == Effect::Unclaimed {
            self.complete = true;
        }
        self.original = Some(value);
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Fence {
    pub signed: String,
    pub expected_metadata: String,
    #[serde(deserialize_with = "required_option")]
    pub latest: Option<Reply>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Unknown {
    pub signed: String,
    pub generation: u64,
    pub generation_id: Digest,
    pub sequence: u64,
    pub request: Digest,
    #[serde(deserialize_with = "required_option")]
    pub original: Option<Completion>,
    pub effect: Effect,
    pub fence: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Tracker {
    #[serde(deserialize_with = "required_option")]
    pub metadata: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub ordinary: Option<Ordinary>,
    #[serde(deserialize_with = "required_option")]
    pub fence: Option<Fence>,
    pub outstanding_unknown: Vec<Unknown>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Learning {
    pub kind: u64,
    pub request: Digest,
    pub reply: Reply,
    #[serde(deserialize_with = "required_option")]
    pub metadata: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub outcome: Option<u64>,
}
impl Learning {
    pub fn from_result(result: &VerifiedResult) -> Result<Self> {
        let (kind, metadata, outcome) = match (result.request(), result.stream_response()) {
            (SignedRequest::Intent(_), None) => (20, None, None),
            (SignedRequest::StreamStatus(_), Some(StreamResponse::Status(m))) => {
                (55, Some(hex::encode(m.canonical())), None)
            }
            (SignedRequest::StreamFence(_), Some(StreamResponse::Fence { outcome, metadata })) => (
                57,
                Some(hex::encode(metadata.canonical())),
                Some(match outcome {
                    FenceOutcome::Applied => 0,
                    FenceOutcome::AlreadyApplied => 1,
                    FenceOutcome::AttemptRefused => 2,
                    FenceOutcome::Superseded => 3,
                }),
            ),
            _ => anyhow::bail!("request and validated stream result differ"),
        };
        Ok(Self {
            kind,
            request: result.request().digest(),
            reply: Reply {
                disposition: disposition(result.disposition()),
                reason: result.code(),
                digest: wire::digest(result.operation_result_bytes()),
            },
            metadata,
            outcome,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.reply.validate()?;
        ensure!(self.request != [0; 32], "zero learned request");
        match self.kind {
            20 => ensure!(
                self.metadata.is_none() && self.outcome.is_none(),
                "ordinary result contains stream metadata"
            ),
            55 => ensure!(
                self.metadata.is_some() && self.outcome.is_none(),
                "status result metadata missing"
            ),
            57 => ensure!(
                self.metadata.is_some()
                    && matches!(
                        (self.outcome, self.reply.disposition, self.reply.reason),
                        (Some(0 | 1), 0, 0)
                            | (Some(2), 1, 2 | 3 | 7 | 12 | 21 | 28 | 37)
                            | (Some(3), 1, 28)
                    ),
                "invalid finite fence result"
            ),
            _ => anyhow::bail!("unknown tracker request kind"),
        }
        Ok(())
    }
}
impl Tracker {
    pub fn metadata(&self) -> Result<Option<OwnStreamMetadata>> {
        self.metadata
            .as_ref()
            .map(|v| OwnStreamMetadata::parse(&hex::decode(v)?))
            .transpose()
    }
    pub fn validate_scopes(
        &self,
        scope: &proof::Scope,
        requester: Key,
        previous: &[proof::Scope],
    ) -> Result<()> {
        if let Some(m) = self.metadata()? {
            ensure!(
                (m.scope() == scope || previous.contains(m.scope())) && m.requester() == requester,
                "tracker metadata context differs"
            );
        }
        if let Some(o) = &self.ordinary {
            let i = o.request()?;
            ensure!(
                i.network == scope.network
                    && i.incarnation == scope.incarnation
                    && i.requester == requester,
                "tracker intent context differs"
            );
            if let Some(c) = &o.original {
                Reply {
                    disposition: c.disposition,
                    reason: c.reason,
                    digest: c.result_digest,
                }
                .validate()?;
                ensure!(
                    c.sequence == i.sequence && c.intent == i.digest,
                    "tracker original completion differs"
                );
            }
            if let Some(r) = &o.latest {
                r.validate()?;
            }
            ensure!(
                !o.body_saved || o.original.as_ref().is_some_and(|c| c.disposition == 0),
                "saved body lacks original permit"
            );
            ensure!(
                !o.complete
                    || o.original.as_ref().is_some_and(|c| c.disposition == 1
                        || (c.disposition == 0 && o.body_saved && o.effect != Effect::Claimed)),
                "unfinished ordinary workflow marked complete"
            );
            ensure!(
                o.effect == Effect::Unclaimed || o.body_saved,
                "effect claim lacks saved body"
            );
        }
        if let Some(f) = &self.fence {
            let SignedRequest::StreamFence(i) =
                SignedRequest::from_signed(&hex::decode(&f.signed)?)?
            else {
                anyhow::bail!("fence journal contains another request");
            };
            let m = OwnStreamMetadata::parse(&hex::decode(&f.expected_metadata)?)?;
            let s = m.state().context("fence expected an absent stream")?;
            ensure!(
                i.network == scope.network
                    && i.incarnation == scope.incarnation
                    && i.requester == requester
                    && m.requester() == requester
                    && m.scope().network == scope.network
                    && m.scope().incarnation == scope.incarnation
                    && s.generation == i.expected_generation
                    && s.generation_id == i.expected_generation_id
                    && wire::digest(m.canonical()) == i.expected_metadata_digest,
                "fence journal comparison differs"
            );
            if let Some(r) = &f.latest {
                r.validate()?;
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for u in &self.outstanding_unknown {
            let request = SignedRequest::from_signed(&hex::decode(&u.signed)?)?;
            ensure!(
                request.network() == scope.network
                    && request.incarnation() == scope.incarnation
                    && request.requester() == requester
                    && request.digest() == u.request,
                "archived request signature or identity differs"
            );
            match (&request, u.fence) {
                (SignedRequest::Intent(i), false) => ensure!(
                    i.generation == u.generation
                        && i.generation_id == u.generation_id
                        && i.sequence == u.sequence,
                    "archived ordinary request differs from its retained stream"
                ),
                (SignedRequest::StreamFence(f), true) => ensure!(
                    f.expected_generation == u.generation
                        && f.expected_generation_id == u.generation_id
                        && u.sequence == 0
                        && u.original.is_none()
                        && u.effect == Effect::Unclaimed,
                    "archived fence differs from its retained stream"
                ),
                _ => anyhow::bail!("archived request kind differs"),
            }
            ensure!(
                u.generation > 0
                    && u.generation_id != [0; 32]
                    && u.request != [0; 32]
                    && (u.fence || u.sequence > 0)
                    && seen.insert(u.request),
                "invalid or duplicate unresolved history"
            );
            if let Some(c) = &u.original {
                ensure!(
                    !u.fence && c.intent == u.request && c.sequence == u.sequence,
                    "unresolved completion identity differs"
                );
                Reply {
                    disposition: c.disposition,
                    reason: c.reason,
                    digest: c.result_digest,
                }
                .validate()?;
            }
        }
        Ok(())
    }
    pub fn slot(&self) -> Result<(u64, Digest, u64, u64)> {
        ensure!(
            self.fence.is_none(),
            "resume the outstanding fence before new ordinary work"
        );
        let m = self
            .metadata()?
            .context("verified own-stream status required")?;
        let s = m.state().context("requester has no admitted stream")?;
        let acknowledged = if let Some(o) = &self.ordinary {
            ensure!(
                o.complete && o.effect != Effect::Claimed,
                "ordinary workflow is outstanding; resume its exact request or explicitly fence"
            );
            let i = o.request()?;
            ensure!(
                i.generation == s.generation && i.generation_id == s.generation_id,
                "ordinary completion belongs to another generation"
            );
            ensure!(
                s.retired_through <= i.sequence
                    && s.completion
                        .as_ref()
                        .is_none_or(|c| c.sequence <= i.sequence),
                "untracked later completion requires explicit recovery"
            );
            s.retired_through.max(i.sequence)
        } else {
            ensure!(
                s.completion.is_none(),
                "untracked completion requires explicit recovery fencing"
            );
            s.retired_through
        };
        Ok((
            s.generation,
            s.generation_id,
            acknowledged
                .checked_add(1)
                .context("stream sequence exhausted")?,
            acknowledged,
        ))
    }
    pub fn prepare_ordinary(&self, signed: &[u8]) -> Result<Self> {
        let i = proof::Intent::from_signed(signed)?;
        let (generation, id, sequence, ack) = self.slot()?;
        ensure!(
            (
                i.generation,
                i.generation_id,
                i.sequence,
                i.acknowledged_through
            ) == (generation, id, sequence, ack),
            "ordinary intent differs from durable sequence slot"
        );
        let mut next = self.clone();
        next.ordinary = Some(Ordinary {
            signed: hex::encode(signed),
            original: None,
            latest: None,
            body_saved: false,
            complete: false,
            effect: Effect::Unclaimed,
        });
        Ok(next)
    }
    pub fn prepare_fence(&self, signed: &[u8], expected: &[u8]) -> Result<Self> {
        ensure!(self.fence.is_none(), "resume the exact outstanding fence");
        let m = self
            .metadata()?
            .context("verified own-stream status required before fencing")?;
        ensure!(
            m.canonical() == expected,
            "fence comparison differs from retained metadata"
        );
        let SignedRequest::StreamFence(i) = SignedRequest::from_signed(signed)? else {
            anyhow::bail!("expected a signed fence");
        };
        let s = m.state().context("cannot fence absent stream")?;
        ensure!(
            i.expected_generation == s.generation
                && i.expected_generation_id == s.generation_id
                && i.expected_metadata_digest == wire::digest(expected),
            "fence comparison differs from exact metadata"
        );
        let mut next = self.clone();
        next.fence = Some(Fence {
            signed: hex::encode(signed),
            expected_metadata: hex::encode(expected),
            latest: None,
        });
        Ok(next)
    }
    fn archive_ordinary(&mut self) -> Result<()> {
        if let Some(o) = self.ordinary.take()
            && (!o.complete || o.effect == Effect::Claimed)
        {
            let i = o.request()?;
            self.outstanding_unknown.push(Unknown {
                signed: o.signed,
                generation: i.generation,
                generation_id: i.generation_id,
                sequence: i.sequence,
                request: i.digest,
                original: o.original,
                effect: o.effect,
                fence: false,
            });
        }
        Ok(())
    }
    pub fn learn_current(
        &self,
        learn: &Learning,
        current: &proof::Scope,
        previous: &[proof::Scope],
    ) -> Result<Self> {
        self.learn_scopes(learn, Some((current, previous)))
    }
    fn learn_scopes(
        &self,
        learn: &Learning,
        scopes: Option<(&proof::Scope, &[proof::Scope])>,
    ) -> Result<Self> {
        learn.validate()?;
        let mut next = self.clone();
        if learn.kind == 20 {
            let o = next
                .ordinary
                .as_mut()
                .context("ordinary result lacks an exact prepared request")?;
            let i = o.request()?;
            ensure!(
                i.digest == learn.request,
                "ordinary response differs from prepared request"
            );
            if learn.reply.disposition == 0 {
                o.original(Completion {
                    sequence: i.sequence,
                    intent: i.digest,
                    disposition: 0,
                    reason: 0,
                    result_digest: learn.reply.digest,
                })?;
            }
            o.latest = Some(learn.reply.clone());
            return Ok(next);
        }
        let metadata = OwnStreamMetadata::parse(&hex::decode(
            learn.metadata.as_ref().context("missing metadata")?,
        )?)?;
        if let Some(old) = self.metadata()? {
            if let Some((current, previous)) = scopes {
                ensure!(
                    metadata.scope() == current
                        && (old.scope() == current || previous.contains(old.scope())),
                    "Stream metadata crosses an unauthenticated epoch"
                );
                monotonic_state(&old, &metadata)?;
            } else {
                monotonic_metadata(&old, &metadata)?;
            }
        }
        if learn.kind == 57 {
            let f = next
                .fence
                .as_mut()
                .context("fence result lacks exact prepared request")?;
            let i = SignedRequest::from_signed(&hex::decode(&f.signed)?)?;
            ensure!(
                i.digest() == learn.request,
                "fence response differs from prepared request"
            );
            f.latest = Some(learn.reply.clone());
        }
        if let Some(state) = metadata.state()
            && let Some(o) = next.ordinary.as_mut()
        {
            let i = o.request()?;
            let completion =
                if i.generation == state.generation && i.generation_id == state.generation_id {
                    state.completion.as_ref()
                } else {
                    state
                        .last_fence
                        .as_ref()
                        .filter(|f| {
                            f.previous_generation == i.generation
                                && f.previous_generation_id == i.generation_id
                        })
                        .and_then(|f| f.previous_completion.as_ref())
                };
            if i.generation == state.generation
                && i.sequence > state.retired_through
                && o.original.is_some()
            {
                ensure!(
                    completion.is_some_and(|c| c.sequence == i.sequence
                        && c.intent == i.digest
                        && o.original.as_ref() == Some(&Completion::from(c))),
                    "status lost an established original completion"
                );
            }
            if let Some(c) = completion.filter(|c| c.sequence == i.sequence && c.intent == i.digest)
            {
                o.original(c.into())?;
            }
            if state.generation > i.generation {
                next.archive_ordinary()?;
            }
        }
        if learn.kind == 57 && matches!(learn.outcome, Some(0 | 1)) {
            next.archive_ordinary()?;
            next.fence = None;
        } else if learn.kind == 57 && learn.outcome == Some(3) {
            let f = next.fence.take().context("missing superseded fence")?;
            let SignedRequest::StreamFence(i) =
                SignedRequest::from_signed(&hex::decode(&f.signed)?)?
            else {
                unreachable!()
            };
            next.outstanding_unknown.push(Unknown {
                signed: f.signed,
                generation: i.expected_generation,
                generation_id: i.expected_generation_id,
                sequence: 0,
                request: i.digest,
                original: None,
                effect: Effect::Unclaimed,
                fence: true,
            });
        }
        if learn.kind == 55
            && let (Some(fence), Some(state)) = (next.fence.as_ref(), metadata.state())
        {
            let SignedRequest::StreamFence(request) =
                SignedRequest::from_signed(&hex::decode(&fence.signed)?)?
            else {
                unreachable!()
            };
            let expected = OwnStreamMetadata::parse(&hex::decode(&fence.expected_metadata)?)?;
            let before = expected
                .state()
                .context("fence expected an absent stream")?;
            let exact = state
                .last_fence
                .as_ref()
                .is_some_and(|f| f.digest == request.digest);
            if exact {
                let f = state
                    .last_fence
                    .as_ref()
                    .context("missing exact last fence")?;
                ensure!(
                    f.expected_metadata_digest == request.expected_metadata_digest
                        && f.previous_generation == before.generation
                        && f.previous_generation_id == before.generation_id
                        && f.previous_retired_through == before.retired_through
                        && f.previous_completion == before.completion,
                    "status last-fence comparison differs from prepared request"
                );
                next.archive_ordinary()?;
                next.fence = None;
            } else if state.generation > request.expected_generation
                || (state.generation == request.expected_generation
                    && state.generation_id == request.expected_generation_id
                    && wire::digest(metadata.canonical()) != request.expected_metadata_digest)
            {
                // Closing a stale attempt does not assert its historical outcome.
                next.outstanding_unknown.push(Unknown {
                    signed: fence.signed.clone(),
                    generation: request.expected_generation,
                    generation_id: request.expected_generation_id,
                    sequence: 0,
                    request: request.digest,
                    original: None,
                    effect: Effect::Unclaimed,
                    fence: true,
                });
                next.fence = None;
            }
        }
        next.metadata = learn.metadata.clone();
        Ok(next)
    }
    pub fn body_saved(&self, request: Digest, result: Digest) -> Result<Self> {
        let mut next = self.clone();
        let o = next
            .ordinary
            .as_mut()
            .context("body has no ordinary request")?;
        ensure!(
            o.request()?.digest == request
                && o.original
                    .as_ref()
                    .is_some_and(|c| c.disposition == 0 && c.result_digest == result),
            "body differs from original permit"
        );
        o.body_saved = true;
        Ok(next)
    }
    pub fn effect(&self, request: Digest, claim: bool) -> Result<Self> {
        let mut next = self.clone();
        let o = next
            .ordinary
            .as_mut()
            .context("effect has no ordinary request")?;
        ensure!(
            o.request()?.digest == request && o.body_saved && !o.complete,
            "effect differs from unfinished saved workflow"
        );
        if claim {
            ensure!(
                o.effect == Effect::Unclaimed,
                "local effect may already have applied"
            );
            o.effect = Effect::Claimed;
        } else {
            o.effect = if o.effect == Effect::Claimed {
                Effect::Complete
            } else {
                Effect::Unclaimed
            };
            o.complete = true;
        }
        Ok(next)
    }
}
pub(super) fn monotonic_metadata(old: &OwnStreamMetadata, next: &OwnStreamMetadata) -> Result<()> {
    ensure!(
        old.scope() == next.scope() && old.requester() == next.requester(),
        "stream metadata context changed"
    );
    monotonic_state(old, next)
}
fn monotonic_state(old: &OwnStreamMetadata, next: &OwnStreamMetadata) -> Result<()> {
    ensure!(
        old.requester() == next.requester(),
        "Stream requester changed"
    );
    if let Some(a) = old.state() {
        let b = next.state().context("admitted stream disappeared")?;
        ensure!(
            b.generation >= a.generation,
            "stream generation moved backwards"
        );
        if b.generation == a.generation {
            ensure!(
                b.generation_id == a.generation_id
                    && b.retired_through >= a.retired_through
                    && b.last_fence == a.last_fence,
                "stream metadata lost retained generation state"
            );
            if b.retired_through == a.retired_through && a.completion.is_some() {
                ensure!(
                    b.completion == a.completion,
                    "stream original completion changed"
                );
            }
        }
    }
    Ok(())
}
