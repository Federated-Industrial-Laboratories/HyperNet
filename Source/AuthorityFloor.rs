// SPDX-License-Identifier: MIT
// Durable certified prefixes and exact signer journals precede protected effects.
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_files as files,
    authority_history::{self as history, TreeHead, ValidatedCheckpoint},
    authority_proof::{
        self as proof, CertifiedPoint, Digest, Disposition, Key, OperationResult, Prefix,
        TrustDescriptor, VerifiedResult, VersionRef,
    },
    trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
#[path = "AuthorityEpochFloor.rs"]
mod epoch;
#[path = "AuthorityTracker.rs"]
mod tracker;
#[path = "AuthorityFloorTransaction.rs"]
mod transaction;

const FLOOR: &str = "AuthorityFloor.json";
const WITNESS: &str = "AuthorityWitness.json";
const BODY: &str = "AuthorityBody.cbor";
const LIMIT: usize = 2 * 1024 * 1024 + crate::authority_epoch::archive::MAX_ARCHIVE_BYTES;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Stored {
    format: String,
    descriptor: String,
    network: String,
    incarnation: String,
    requester: String,
    sequence: u64,
    #[serde(deserialize_with = "required_option")]
    certificate: Option<String>,
    #[serde(deserialize_with = "required_option")]
    node: Option<String>,
    #[serde(deserialize_with = "required_option")]
    checkpoint_proof: Option<String>,
    generations: Vec<VersionRef>,
    wall_floor_ms: u64,
    tracker: tracker::Tracker,
    epochs: Vec<crate::authority_epoch::archive::Activated>,
    #[serde(deserialize_with = "required_option")]
    sealed: Option<crate::authority_epoch::archive::Seal>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Witness {
    sequence: u64,
    digest: String,
}
fn required_option<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}
impl Stored {
    fn requester(&self) -> Result<Key> {
        hex::decode(&self.requester)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid requester key length"))
    }
    fn validate(
        &self,
        descriptor: &TrustDescriptor,
    ) -> Result<(Prefix, Option<ValidatedCheckpoint>)> {
        let resolved = self.resolve(descriptor)?;
        let descriptor = &resolved.descriptor;
        let scope = descriptor.scope();
        ensure!(
            self.format == "HyperNetAuthorityFloor/1"
                && self.sequence > 0
                && self.descriptor == hex::encode(scope.configuration)
                && self.network == hex::encode(scope.network)
                && self.incarnation == hex::encode(scope.incarnation),
            "authority floor identity differs from pinned configuration"
        );
        let requester = self.requester()?;
        wire::valid_key(&requester)?;
        proof::validate_versions(&self.generations, crate::authority_capacity::MAX_RECORDS)?;
        self.tracker
            .validate_scopes(scope, requester, &resolved.previous_scopes)?;
        let floor = match (&self.certificate, &self.node) {
            (None, None) => {
                ensure!(
                    !self.epochs.is_empty()
                        || self.generations.is_empty()
                            && self.checkpoint_proof.is_none()
                            && self.tracker.metadata.is_none()
                            && self
                                .tracker
                                .ordinary
                                .as_ref()
                                .is_none_or(|o| o.original.is_none() && o.latest.is_none())
                            && self.tracker.outstanding_unknown.is_empty(),
                    "invalid genesis floor"
                );
                descriptor.genesis()?
            }
            (Some(c), Some(n)) => {
                CertifiedPoint::from_evidence(descriptor, &hex::decode(c)?, &hex::decode(n)?)?
                    .prefix()
                    .clone()
            }
            _ => anyhow::bail!("incomplete certified floor"),
        };
        let checkpoint = self
            .checkpoint_proof
            .as_ref()
            .map(|bytes| {
                let c = history::verify_checkpoint(descriptor, &hex::decode(bytes)?)?;
                ensure!(
                    !c.terminal()
                        && c.height() <= floor.height()
                        && c.prefix().view() <= floor.view()
                        && c.prefix().evaluated_at_ms() <= floor.evaluated_at_ms()
                        && (c.height() != floor.height() || c.prefix() == floor),
                    "stored checkpoint conflicts with retained floor"
                );
                Ok::<_, anyhow::Error>(c)
            })
            .transpose()?;
        if let Some(seal) = &self.sealed {
            let terminal = seal.verify(descriptor)?;
            ensure!(
                terminal.history().from() == &floor
                    && terminal.history().prior() == checkpoint.as_ref().map(|c| c.head()),
                "Retained seal differs from the current exact floor"
            );
        }
        Ok((floor, checkpoint))
    }
}
fn check_body(directory: &File, stored: &Stored) -> Result<()> {
    if let Some(o) = stored.tracker.ordinary.as_ref().filter(|o| o.body_saved) {
        let bytes = files::read_at(directory, OsStr::new(BODY), wire::MAXIMUM, true)?;
        let result = OperationResult::parse(&bytes)?;
        let request = o.request()?;
        ensure!(
            result.action == request.action
                && result.disposition == Disposition::Permit
                && o.original
                    .as_ref()
                    .is_some_and(|c| c.result_digest == wire::digest(&bytes)),
            "saved original result is missing or inconsistent"
        );
    }
    Ok(())
}
pub struct SequenceSlot {
    generation: u64,
    generation_id: Digest,
    sequence: u64,
    acknowledged_through: u64,
    epoch: u64,
    height: u64,
    witness: Digest,
}
impl SequenceSlot {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn generation_id(&self) -> Digest {
        self.generation_id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn acknowledged_through(&self) -> u64 {
        self.acknowledged_through
    }
    pub fn minimum_policy_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn minimum_policy_height(&self) -> u64 {
        self.height
    }
}
#[derive(Clone)]
pub struct PreparedRequest {
    signed: Vec<u8>,
    #[cfg(test)]
    request: proof::SignedRequest,
    expected: Option<Vec<u8>>,
}
impl PreparedRequest {
    fn new(signed: Vec<u8>, _expected: Option<Vec<u8>>) -> Result<Self> {
        #[cfg(test)]
        let request = proof::SignedRequest::from_signed(&signed)?;
        #[cfg(not(test))]
        proof::SignedRequest::from_signed(&signed)?;
        Ok(Self {
            signed,
            #[cfg(test)]
            request,
            expected: _expected,
        })
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    #[cfg(test)]
    pub fn digest(&self) -> Digest {
        self.request.digest()
    }
    pub fn expected_metadata(&self) -> Option<&[u8]> {
        self.expected.as_deref()
    }
}
pub struct Store {
    directory: File,
    _lock: File,
    descriptor: TrustDescriptor,
    initial_descriptor: TrustDescriptor,
    stored: Stored,
    floor: Prefix,
    checkpoint: Option<ValidatedCheckpoint>,
    digest: Digest,
    poisoned: bool,
}
impl Store {
    /// Explicit bootstrap initialisation only; ordinary opening never recreates private trust state.
    pub fn initialise(
        directory: &Path,
        descriptor: TrustDescriptor,
        requester: Key,
        health: ClockHealth,
    ) -> Result<Self> {
        wire::valid_key(&requester)?;
        let directory = files::private_directory(directory)?;
        let lock = files::profile_lock(&directory, OsStr::new(FLOOR))?;
        ensure!(
            !transaction::exists(&directory, transaction::PENDING)?
                && !transaction::exists(&directory, BODY)?,
            "existing private transaction or result requires recovery"
        );
        let stored = Stored {
            format: "HyperNetAuthorityFloor/1".into(),
            descriptor: hex::encode(descriptor.scope().configuration),
            network: hex::encode(descriptor.scope().network),
            incarnation: hex::encode(descriptor.scope().incarnation),
            requester: hex::encode(requester),
            sequence: 1,
            certificate: None,
            node: None,
            checkpoint_proof: None,
            generations: Vec::new(),
            wall_floor_ms: health.observe()?.wall_ms,
            tracker: tracker::Tracker::default(),
            epochs: Vec::new(),
            sealed: None,
        };
        let (floor, checkpoint) = stored.validate(&descriptor)?;
        let bytes = serde_json::to_vec(&stored)?;
        let hash = digest(&bytes);
        let witness = serde_json::to_vec(&Witness {
            sequence: 1,
            digest: hex::encode(hash),
        })?;
        files::atomic_at(&directory, OsStr::new(WITNESS), &witness, false)?;
        files::atomic_at(&directory, OsStr::new(FLOOR), &bytes, false)?;
        Ok(Self {
            directory,
            _lock: lock,
            initial_descriptor: descriptor.clone(),
            descriptor: stored.resolve(&descriptor)?.descriptor,
            stored,
            floor,
            checkpoint,
            digest: hash,
            poisoned: false,
        })
    }
    pub fn open(directory: &Path, descriptor: TrustDescriptor) -> Result<Self> {
        let directory = files::private_directory(directory)?;
        let lock = files::profile_lock(&directory, OsStr::new(FLOOR))?;
        transaction::recover(&directory, &descriptor)?;
        let bytes = files::read_at(&directory, OsStr::new(FLOOR), LIMIT, true)?;
        let stored: Stored = serde_json::from_slice(&bytes)?;
        let witness: Witness = serde_json::from_slice(&files::read_at(
            &directory,
            OsStr::new(WITNESS),
            1024,
            true,
        )?)?;
        let hash = digest(&bytes);
        ensure!(
            witness.sequence == stored.sequence && witness.digest == hex::encode(hash),
            "authority floor and witness differ"
        );
        let (floor, checkpoint) = stored.validate(&descriptor)?;
        check_body(&directory, &stored)?;
        Ok(Self {
            directory,
            _lock: lock,
            initial_descriptor: descriptor.clone(),
            descriptor: stored.resolve(&descriptor)?.descriptor,
            stored,
            floor,
            checkpoint,
            digest: hash,
            poisoned: false,
        })
    }
    #[cfg(test)]
    pub fn initial_descriptor(&self) -> &TrustDescriptor {
        &self.initial_descriptor
    }
    pub fn descriptor(&self) -> &TrustDescriptor {
        &self.descriptor
    }
    pub fn prefix(&self) -> &Prefix {
        &self.floor
    }
    pub fn generations(&self) -> &[VersionRef] {
        &self.stored.generations
    }
    /// Exact original Permits authenticate historical cache bytes only, never a current grant.
    pub fn historical_cache_references(&self) -> Result<Vec<VersionRef>> {
        self.unchanged()?;
        let signed = self
            .stored
            .tracker
            .ordinary
            .iter()
            .filter(|o| o.original.as_ref().is_some_and(|c| c.disposition == 0))
            .map(|o| &o.signed)
            .chain(
                self.stored
                    .tracker
                    .outstanding_unknown
                    .iter()
                    .filter(|o| !o.fence && o.original.as_ref().is_some_and(|c| c.disposition == 0))
                    .map(|o| &o.signed),
            );
        let mut references = Vec::new();
        for signed in signed {
            let request = proof::Intent::from_signed(&hex::decode(signed)?)?;
            if request.action == "AuthorityDomain" {
                for reference in request.expected {
                    if !references.contains(&reference) {
                        references.push(reference);
                    }
                }
            }
        }
        Ok(references)
    }
    pub fn tree_head(&self) -> Option<&TreeHead> {
        self.checkpoint.as_ref().map(ValidatedCheckpoint::head)
    }
    pub fn requester(&self) -> Key {
        self.stored.requester().expect("validated requester")
    }
    pub fn require_requester(&self, key: Key) -> Result<()> {
        ensure!(
            key == self.requester(),
            "signer differs from durable journal requester"
        );
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn profile_directory(&self) -> &File {
        &self.directory
    }
    pub fn stream_metadata(&self) -> Result<Option<proof::OwnStreamMetadata>> {
        self.stored.tracker.metadata()
    }
    /// Completed ordinary work supplies the next slot without another status query.
    /// This is stream bookkeeping only; every new operation still requires a fresh proof.
    pub fn needs_stream_status(&self) -> Result<bool> {
        self.unchanged()?;
        self.unsealed()?;
        if self
            .stream_metadata()?
            .is_none_or(|metadata| metadata.scope() != self.descriptor.scope())
            || self.refusal_needs_status()?
        {
            return Ok(true);
        }
        if self.resume_ordinary()?.is_some() {
            return Ok(false);
        }
        if self.stored.tracker.ordinary.is_none() {
            return Ok(true);
        }
        self.ordinary_slot()?;
        Ok(false)
    }
    pub fn ordinary_slot(&self) -> Result<SequenceSlot> {
        self.unchanged()?;
        self.unsealed()?;
        ensure!(
            self.stored
                .tracker
                .metadata()?
                .is_some_and(|m| m.scope() == self.descriptor.scope()),
            "Fresh current-epoch stream status is required after activation"
        );
        check_body(&self.directory, &self.stored)?;
        let (generation, generation_id, sequence, acknowledged_through) =
            self.stored.tracker.slot()?;
        Ok(SequenceSlot {
            generation,
            generation_id,
            sequence,
            acknowledged_through,
            epoch: self.floor.scope().epoch,
            height: self.floor.height(),
            witness: self.digest,
        })
    }
    pub fn prepare_ordinary(
        &mut self,
        slot: SequenceSlot,
        signed: &[u8],
    ) -> Result<PreparedRequest> {
        self.unchanged()?;
        ensure!(slot.witness == self.digest, "sequence slot is stale");
        let request = proof::SignedRequest::from_signed(signed)?;
        self.request_context(&request)?;
        let i = request.ordinary()?;
        ensure!(
            i.minimum_policy_epoch == slot.epoch && i.minimum_policy_height >= slot.height,
            "request causal floor differs from sequence slot"
        );
        let tracker = self.stored.tracker.prepare_ordinary(signed)?;
        self.local(
            tracker,
            transaction::Transition::PrepareOrdinary {
                signed: hex::encode(signed),
            },
            true,
        )?;
        PreparedRequest::new(signed.to_vec(), None)
    }
    pub fn prepare_fence(&mut self, signed: &[u8], expected: &[u8]) -> Result<PreparedRequest> {
        self.unchanged()?;
        ensure!(
            self.stream_metadata()?
                .is_some_and(|m| m.scope() == self.descriptor.scope()),
            "Fresh current-epoch metadata is required before a new fence"
        );
        let request = proof::SignedRequest::from_signed(signed)?;
        self.request_context(&request)?;
        let tracker = self.stored.tracker.prepare_fence(signed, expected)?;
        self.local(
            tracker,
            transaction::Transition::PrepareFence {
                signed: hex::encode(signed),
                expected: hex::encode(expected),
            },
            true,
        )?;
        PreparedRequest::new(signed.to_vec(), Some(expected.to_vec()))
    }
    pub fn resume_ordinary(&self) -> Result<Option<PreparedRequest>> {
        self.unchanged()?;
        self.stored
            .tracker
            .ordinary
            .as_ref()
            .filter(|o| !o.complete)
            .map(|o| PreparedRequest::new(hex::decode(&o.signed)?, None))
            .transpose()
    }
    /// A disclosure refusal alone cannot establish the original operation's outcome.
    pub fn refusal_needs_status(&self) -> Result<bool> {
        self.unchanged()?;
        Ok(self
            .stored
            .tracker
            .ordinary
            .as_ref()
            .is_some_and(|ordinary| {
                !ordinary.complete
                    && ordinary.original.is_none()
                    && ordinary
                        .latest
                        .as_ref()
                        .is_some_and(|reply| reply.disposition == 1)
            }))
    }
    pub fn resume_fence(&self) -> Result<Option<PreparedRequest>> {
        self.unchanged()?;
        self.stored
            .tracker
            .fence
            .as_ref()
            .map(|f| {
                PreparedRequest::new(
                    hex::decode(&f.signed)?,
                    Some(hex::decode(&f.expected_metadata)?),
                )
            })
            .transpose()
    }
    fn request_context(&self, request: &proof::SignedRequest) -> Result<()> {
        self.unsealed()?;
        self.require_requester(request.requester())?;
        ensure!(
            request.network() == self.floor.scope().network
                && request.incarnation() == self.floor.scope().incarnation
                && request.minimum_policy_epoch() == self.floor.scope().epoch
                && request.minimum_policy_height() >= self.floor.height(),
            "prepared request context or causal floor differs"
        );
        Ok(())
    }
    pub fn attach_history(
        &self,
        result: VerifiedResult,
        checkpoint_proof: &[u8],
        history_proof: &[u8],
    ) -> Result<VerifiedResult> {
        self.unchanged()?;
        let checkpoint = history::verify_checkpoint(&self.descriptor, checkpoint_proof)?;
        let transition =
            history::verify_history(&checkpoint, &self.floor, self.tree_head(), history_proof)?;
        result.attach_history(transition)
    }
    fn check_history(&self, result: &VerifiedResult) -> Result<()> {
        self.unsealed()?;
        if let Some(history) = result.history() {
            ensure!(
                history.from() == self.prefix() && history.prior() == self.tree_head(),
                "authority history differs from retained prefix or head"
            );
        }
        result.extends(&self.floor)
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            !self.poisoned && !transaction::exists(&self.directory, transaction::PENDING)?,
            "authority persistence requires reopening for recovery"
        );
        let bytes = files::read_at(&self.directory, OsStr::new(FLOOR), LIMIT, true)?;
        let witness: Witness = serde_json::from_slice(&files::read_at(
            &self.directory,
            OsStr::new(WITNESS),
            1024,
            true,
        )?)?;
        ensure!(
            digest(&bytes) == self.digest
                && witness.sequence == self.stored.sequence
                && witness.digest == hex::encode(self.digest),
            "authority floor changed outside its exclusive owner"
        );
        Ok(())
    }
    fn next_generations(&self, result: &VerifiedResult) -> Result<Vec<VersionRef>> {
        let mut known: BTreeMap<_, _> = self
            .stored
            .generations
            .iter()
            .map(|v| (v.index(), v.clone()))
            .collect();
        if result.disposition() == Disposition::Permit {
            for value in result.request().expected() {
                if let Some(prior) = known.get(&value.index()) {
                    ensure!(
                        value.generation >= prior.generation
                            && (value.generation != prior.generation
                                || value.digest == prior.digest)
                            || result.validates_update(value, prior)
                                && self.stored.tracker.ordinary.as_ref().is_some_and(|o| {
                                    o.request()
                                        .is_ok_and(|i| i.digest == result.request().digest())
                                        && o.original.as_ref().is_some_and(|c| {
                                            c.result_digest == result.executed.result
                                        })
                                }),
                        "request is below a known generation or conflicts with its digest"
                    );
                }
            }
        }
        for value in &result.generations {
            if let Some(prior) = known.get(&value.index()) {
                ensure!(
                    value.generation >= prior.generation
                        && (value.generation != prior.generation || value.digest == prior.digest),
                    "certified result is below a known generation or conflicts with its digest"
                );
            }
            known.insert(value.index(), value.clone());
        }
        ensure!(
            known.len() <= crate::authority_capacity::MAX_RECORDS,
            "certified generation floor capacity reached"
        );
        Ok(known.into_values().collect())
    }
    pub fn observe(&mut self, result: VerifiedResult) -> Result<()> {
        self.unchanged()?;
        ensure!(
            result.disposition() != Disposition::Permit
                && result.point().prefix().scope() == self.descriptor.scope(),
            "observation requires a non-permit in retained configuration"
        );
        self.check_history(&result)?;
        self.advance(&result, self.stored.wall_floor_ms)
    }
    /// The lower bound is an independent credential start, or zero when none applies.
    /// The original live challenge already establishes causal issuance through BOOTTIME.
    pub fn accept(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        health: ClockHealth,
        not_before_ms: u64,
    ) -> Result<DurablePermit> {
        self.unchanged()?;
        ensure!(
            result.disposition() == Disposition::Permit
                && result.point().prefix().scope() == self.descriptor.scope(),
            "non-permit result or wrong configuration"
        );
        self.check_history(&result)?;
        let now = session.check(&result, not_before_ms, health)?;
        ensure!(
            now.wall_ms >= self.stored.wall_floor_ms,
            "wall clock is below durable floor"
        );
        self.advance(&result, now.wall_ms)?;
        session.check(&result, not_before_ms, health)?;
        Ok(DurablePermit {
            result,
            not_before_ms,
            wall_floor_ms: now.wall_ms,
        })
    }
    fn next(&self) -> Result<Stored> {
        let mut next = self.stored.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .context("floor transaction sequence exhausted")?;
        Ok(next)
    }
    fn advance(&mut self, result: &VerifiedResult, wall_floor_ms: u64) -> Result<()> {
        self.require_requester(result.request().requester())?;
        let learning = tracker::Learning::from_result(result)?;
        let mut next = self.next()?;
        let resolved = self.stored.resolve(&self.initial_descriptor)?;
        next.tracker = self.stored.tracker.learn_current(
            &learning,
            self.descriptor.scope(),
            &resolved.previous_scopes,
        )?;
        next.generations = self.next_generations(result)?;
        next.certificate = Some(hex::encode(result.point().certificate()));
        next.node = Some(hex::encode(result.point().node()));
        next.checkpoint_proof = result
            .history()
            .map(|h| hex::encode(h.checkpoint().canonical_proof()))
            .or_else(|| self.stored.checkpoint_proof.clone());
        next.wall_floor_ms = wall_floor_ms;
        transaction::publish(
            self,
            next,
            transaction::Transition::Learn { learning },
            result.continuity(),
        )
    }
    fn local(
        &mut self,
        tracker: tracker::Tracker,
        transition: transaction::Transition,
        reserve: bool,
    ) -> Result<()> {
        self.unchanged()?;
        let mut next = self.next()?;
        next.tracker = tracker;
        if reserve {
            reserve_completion(&next)?;
        }
        transaction::publish(
            self,
            next,
            transition,
            proof::ContinuityEvidence {
                ancestry: Vec::new(),
                history: None,
            },
        )
    }
}
fn reserve_completion(next: &Stored) -> Result<()> {
    // Bound future metadata, original response and unresolved summaries using their actual JSON shapes.
    let mut projected = next.clone();
    projected.tracker.metadata = Some("f".repeat(2 * 486));
    if let Some(o) = projected.tracker.ordinary.as_mut() {
        let i = o.request()?;
        let c = tracker::Completion {
            sequence: i.sequence,
            intent: i.digest,
            disposition: 2,
            reason: 38,
            result_digest: [255; 32],
        };
        o.original = Some(c.clone());
        o.latest = Some(tracker::Reply {
            disposition: 2,
            reason: 38,
            digest: [255; 32],
        });
        projected
            .tracker
            .outstanding_unknown
            .push(tracker::Unknown {
                signed: o.signed.clone(),
                generation: i.generation,
                generation_id: i.generation_id,
                sequence: i.sequence,
                request: i.digest,
                original: Some(c),
                effect: tracker::Effect::Complete,
                fence: false,
            });
    }
    if let Some(f) = projected.tracker.fence.as_mut() {
        f.latest = Some(tracker::Reply {
            disposition: 1,
            reason: 38,
            digest: [255; 32],
        });
        if let proof::SignedRequest::StreamFence(i) =
            proof::SignedRequest::from_signed(&hex::decode(&f.signed)?)?
        {
            projected
                .tracker
                .outstanding_unknown
                .push(tracker::Unknown {
                    signed: f.signed.clone(),
                    generation: i.expected_generation,
                    generation_id: i.expected_generation_id,
                    sequence: 0,
                    request: i.digest,
                    original: None,
                    effect: tracker::Effect::Unclaimed,
                    fence: true,
                });
        }
    }
    ensure!(
        serde_json::to_vec(&projected)?.len() <= LIMIT,
        "journal capacity cannot retain the eventual completion and unresolved history"
    );
    Ok(())
}
pub struct DurablePermit {
    result: VerifiedResult,
    not_before_ms: u64,
    wall_floor_ms: u64,
}
impl DurablePermit {
    fn check_floor(&self, store: &Store, requested_effect: u64) -> Result<()> {
        store.unchanged()?;
        store.unsealed()?;
        self.result.extends(store.prefix())?;
        if let Some(h) = self.result.history() {
            ensure!(
                store.tree_head() == Some(h.checkpoint().head()),
                "permit lost accepted history head"
            );
        }
        store.next_generations(&self.result)?;
        ensure!(
            requested_effect <= self.result.executed.maximum_effect,
            "effect exceeds certified maximum"
        );
        Ok(())
    }
    fn check(
        &self,
        store: &Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
    ) -> Result<()> {
        self.check_floor(store, requested_effect)?;
        let now = session.check(&self.result, self.not_before_ms, health)?;
        ensure!(
            now.wall_ms >= self.wall_floor_ms.max(store.stored.wall_floor_ms),
            "wall clock fell below durable floor"
        );
        Ok(())
    }
    fn save_body(
        &self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
    ) -> Result<()> {
        if !matches!(self.result.request(), proof::SignedRequest::Intent(_)) {
            return Ok(());
        }
        self.check(store, session, health, requested_effect)?;
        let bytes = self.result.operation_result_bytes();
        ensure!(
            bytes.len() <= wire::MAXIMUM,
            "original body exceeds its bound"
        );
        let request = self.result.request().digest();
        let result = wire::digest(bytes);
        let next = store.stored.tracker.body_saved(request, result)?;
        if store
            .stored
            .tracker
            .ordinary
            .as_ref()
            .is_some_and(|o| o.body_saved)
        {
            check_body(&store.directory, &store.stored)?;
            return Ok(());
        }
        if transaction::exists(&store.directory, BODY)? {
            files::read_at(&store.directory, OsStr::new(BODY), wire::MAXIMUM, true)?;
        }
        files::atomic_at(&store.directory, OsStr::new(BODY), bytes, true)?;
        store.local(
            next,
            transaction::Transition::SaveBody { request, result },
            false,
        )
    }
    pub fn perform<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        self.run(
            store,
            session,
            health,
            requested_effect,
            check_current_restrictions,
            effect,
            false,
        )
    }
    pub fn perform_once<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            matches!(self.result.request(), proof::SignedRequest::Intent(_)),
            "stream controls cannot invoke irreversible handlers"
        );
        self.run(
            store,
            session,
            health,
            requested_effect,
            check_current_restrictions,
            effect,
            true,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn run<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        mut check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
        once: bool,
    ) -> Result<T> {
        self.check(store, session, health, requested_effect)?;
        check_current_restrictions(&self.result.executed.restrictions)?;
        self.save_body(store, session, health, requested_effect)?;
        let request = self.result.request().digest();
        let ordinary = matches!(self.result.request(), proof::SignedRequest::Intent(_));
        if ordinary {
            let o = store
                .stored
                .tracker
                .ordinary
                .as_ref()
                .context("ordinary workflow missing")?;
            ensure!(
                o.effect == tracker::Effect::Unclaimed,
                "local effect may already have applied"
            );
        }
        if once {
            let next = store.stored.tracker.effect(request, true)?;
            store.local(next, transaction::Transition::Claim { request }, false)?;
        }
        self.check(store, session, health, requested_effect)?;
        check_current_restrictions(&self.result.executed.restrictions)?;
        let consumption = session.consume(&self.result, self.not_before_ms, health)?;
        let value = effect(&self.result.result, store)?;
        if ordinary
            && !store
                .stored
                .tracker
                .ordinary
                .as_ref()
                .context("ordinary workflow missing")?
                .complete
        {
            let next = store.stored.tracker.effect(request, false)?;
            store.local(next, transaction::Transition::Complete { request }, false)?;
        }
        // The callback and final durable publication consume the original validity interval.
        self.check_floor(store, requested_effect)?;
        check_current_restrictions(&self.result.executed.restrictions)?;
        let now = session.finish_consumption(consumption, health)?;
        ensure!(
            now.wall_ms >= self.wall_floor_ms.max(store.stored.wall_floor_ms),
            "wall clock fell below durable floor before return"
        );
        Ok(value)
    }
}
// Whole, internally consistent local snapshot rollback requires an independently current anchor.
#[cfg(test)]
#[path = "AuthorityFloorTests.rs"]
pub(crate) mod tests;

#[path = "AuthorityRemoteReceipt.rs"]
mod remote_receipt;
