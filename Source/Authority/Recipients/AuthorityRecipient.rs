// SPDX-License-Identifier: MIT
//! Serving-recipient floors and effect claims never allocate or acknowledge a caller's request stream.
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_files as files,
    authority_history::{self as history, TreeHead, ValidatedCheckpoint},
    authority_proof::{
        self as proof, CertifiedPoint, Digest, Disposition, Intent, Key, OperationResult, Prefix,
        Restrictions, TrustDescriptor, VerifiedResult, VersionRef,
    },
    trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
#[path = "AuthorityRecipientEpoch.rs"]
mod epoch;
#[path = "AuthorityRecipientTransaction.rs"]
mod transaction;

const FLOOR: &str = "RecipientFloor.json";
const WITNESS: &str = "RecipientWitness.json";
const LIMIT: usize = 2 * 1024 * 1024 + crate::authority_epoch::archive::MAX_ARCHIVE_BYTES + 8192;
fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimState {
    Claimed,
    Complete,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Claim {
    requester: Key,
    generation: u64,
    generation_id: Digest,
    sequence: u64,
    intent: Digest,
    result: Digest,
    amount: u64,
    state: ClaimState,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Caller {
    key: Key,
    generation: u64,
    generation_id: Digest,
    acknowledged: u64,
    sequence: u64,
    intent: Digest,
    result: Digest,
}
impl Caller {
    fn learn(&mut self, i: &Intent, result: Digest) -> Result<()> {
        ensure!(
            i.requester == self.key && i.generation >= self.generation,
            "recipient has retained a later caller generation"
        );
        if i.generation == self.generation {
            ensure!(
                i.generation_id == self.generation_id
                    && i.sequence >= self.sequence
                    && i.acknowledged_through >= self.acknowledged
                    && (i.sequence != self.sequence
                        || i.digest == self.intent && result == self.result),
                "caller stream conflicts with the retained recipient floor"
            );
        }
        *self = Self::from(i);
        self.result = result;
        Ok(())
    }
}
impl From<&Intent> for Caller {
    fn from(i: &Intent) -> Self {
        Self {
            key: i.requester,
            generation: i.generation,
            generation_id: i.generation_id,
            acknowledged: i.acknowledged_through,
            sequence: i.sequence,
            intent: i.digest,
            result: [0; 32],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Stored {
    format: String,
    configuration: Digest,
    recipient: Key,
    sequence: u64,
    #[serde(deserialize_with = "required_option")]
    certificate: Option<String>,
    #[serde(deserialize_with = "required_option")]
    node: Option<String>,
    #[serde(deserialize_with = "required_option")]
    checkpoint: Option<String>,
    versions: Vec<VersionRef>,
    wall_floor_ms: u64,
    callers: Vec<Caller>,
    claims: Vec<Claim>,
    epochs: Vec<crate::authority_epoch::archive::Activated>,
    #[serde(deserialize_with = "required_option")]
    sealed: Option<crate::authority_epoch::archive::Seal>,
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
impl Stored {
    fn validate(
        &self,
        descriptor: &TrustDescriptor,
    ) -> Result<(Prefix, Option<ValidatedCheckpoint>)> {
        let resolved = self.resolve(descriptor)?;
        let descriptor = &resolved.descriptor;
        if let Some(seal) = &self.sealed {
            ensure!(
                seal.retained() == &self.retained(),
                "recipient seal changed retained authority"
            );
            seal.verify(descriptor)?;
        }
        ensure!(
            self.format == "HyperNetRecipientFloor/1"
                && self.sequence > 0
                && self.configuration == descriptor.scope().configuration,
            "recipient floor configuration differs"
        );
        wire::valid_key(&self.recipient)?;
        proof::validate_versions(&self.versions, crate::authority_capacity::MAX_RECORDS)?;
        ensure!(
            self.callers.len() <= crate::authority_capacity::MAX_STREAMS
                && self.callers.windows(2).all(|w| w[0].key < w[1].key),
            "recipient caller floors are repeated or exceed network admission capacity"
        );
        for c in &self.callers {
            wire::valid_key(&c.key)?;
            ensure!(
                c.generation > 0
                    && c.generation_id != [0; 32]
                    && c.sequence > c.acknowledged
                    && c.intent != [0; 32]
                    && c.result != [0; 32],
                "invalid recipient caller floor"
            );
        }
        ensure!(
            self.claims.windows(2).all(|w| w[0].intent < w[1].intent),
            "repeated recipient effect claim"
        );
        for c in &self.claims {
            let caller = self
                .callers
                .iter()
                .find(|a| a.key == c.requester)
                .context("effect has no caller floor")?;
            ensure!(
                c.generation > 0
                    && c.generation_id != [0; 32]
                    && c.sequence > 0
                    && c.intent != [0; 32]
                    && c.result != [0; 32]
                    && c.generation <= caller.generation
                    && (c.generation != caller.generation
                        || c.generation_id == caller.generation_id
                            && c.sequence <= caller.sequence),
                "invalid retained recipient claim"
            );
        }
        let prefix = match (&self.certificate, &self.node) {
            (None, None) => {
                ensure!(
                    self.checkpoint.is_none()
                        && (!self.epochs.is_empty()
                            || self.versions.is_empty()
                                && self.callers.is_empty()
                                && self.claims.is_empty()),
                    "invalid initial recipient floor"
                );
                descriptor.genesis()?
            }
            (Some(c), Some(n)) => {
                CertifiedPoint::from_evidence(descriptor, &hex::decode(c)?, &hex::decode(n)?)?
                    .prefix()
                    .clone()
            }
            _ => anyhow::bail!("incomplete recipient floor certificate"),
        };
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(|c| {
                let c = history::verify_checkpoint(descriptor, &hex::decode(c)?)?;
                ensure!(
                    !c.terminal()
                        && c.height() <= prefix.height()
                        && c.prefix().view() <= prefix.view()
                        && c.prefix().evaluated_at_ms() <= prefix.evaluated_at_ms()
                        && (c.height() != prefix.height() || c.prefix() == prefix),
                    "recipient checkpoint conflicts with floor"
                );
                Ok::<_, anyhow::Error>(c)
            })
            .transpose()?;
        ensure!(
            serde_json::to_vec(self)?.len() <= LIMIT,
            "recipient journal capacity reached"
        );
        Ok((prefix, checkpoint))
    }
}

pub struct Store {
    directory: File,
    _lock: files::ProfileLock,
    descriptor: TrustDescriptor,
    initial_descriptor: TrustDescriptor,
    stored: Stored,
    prefix: Prefix,
    checkpoint: Option<ValidatedCheckpoint>,
    digest: Digest,
    poisoned: bool,
}
impl Store {
    pub fn initialise(
        path: &Path,
        descriptor: TrustDescriptor,
        recipient: Key,
        health: ClockHealth,
    ) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::profile_lock(&directory, OsStr::new(FLOOR))?;
        ensure!(
            !transaction::exists(&directory, FLOOR)?
                && !transaction::exists(&directory, WITNESS)?
                && !transaction::exists(&directory, transaction::PENDING)?,
            "recipient state already exists; open it without resetting trust"
        );
        let stored = Stored {
            format: "HyperNetRecipientFloor/1".into(),
            configuration: descriptor.scope().configuration,
            recipient,
            sequence: 1,
            certificate: None,
            node: None,
            checkpoint: None,
            versions: vec![],
            wall_floor_ms: health.observe()?.wall_ms,
            callers: vec![],
            claims: vec![],
            epochs: vec![],
            sealed: None,
        };
        let (prefix, checkpoint) = stored.validate(&descriptor)?;
        let bytes = transaction::initialise(&directory, &descriptor, &stored)?;
        let hash = digest(&bytes);
        Ok(Self {
            directory,
            _lock: lock,
            initial_descriptor: descriptor.clone(),
            descriptor,
            stored,
            prefix,
            checkpoint,
            digest: hash,
            poisoned: false,
        })
    }
    pub fn open(path: &Path, descriptor: TrustDescriptor, recipient: Key) -> Result<Self> {
        let directory = files::private_directory(path)?;
        let lock = files::profile_lock(&directory, OsStr::new(FLOOR))?;
        transaction::recover(&directory, &descriptor, recipient)?;
        let bytes = files::read_at(&directory, OsStr::new(FLOOR), LIMIT, true)?;
        let stored: Stored = serde_json::from_slice(&bytes)?;
        ensure!(
            stored.recipient == recipient,
            "recipient journal belongs to another service"
        );
        let (prefix, checkpoint) = stored.validate(&descriptor)?;
        let result = Self {
            directory,
            _lock: lock,
            initial_descriptor: descriptor.clone(),
            descriptor: stored.resolve(&descriptor)?.descriptor,
            stored,
            prefix,
            checkpoint,
            digest: digest(&bytes),
            poisoned: false,
        };
        result.unchanged()?;
        Ok(result)
    }
    pub fn descriptor(&self) -> &TrustDescriptor {
        &self.descriptor
    }
    pub fn recipient(&self) -> Key {
        self.stored.recipient
    }
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
    pub fn tree_head(&self) -> Option<&TreeHead> {
        self.checkpoint.as_ref().map(ValidatedCheckpoint::head)
    }
    pub fn generations(&self) -> &[VersionRef] {
        &self.stored.versions
    }
    pub fn claim_state(&self, intent: Digest) -> Option<ClaimState> {
        self.stored
            .claims
            .iter()
            .find(|c| c.intent == intent)
            .map(|c| c.state)
    }
    pub fn profile_directory(&self) -> &File {
        &self.directory
    }
    pub fn attach_history(
        &self,
        result: VerifiedResult,
        checkpoint: &[u8],
        history: &[u8],
    ) -> Result<VerifiedResult> {
        self.unchanged()?;
        let checkpoint = history::verify_checkpoint(&self.descriptor, checkpoint)?;
        result.attach_history(history::verify_history(
            &checkpoint,
            self.prefix(),
            self.tree_head(),
            history,
        )?)
    }
    fn unchanged(&self) -> Result<()> {
        ensure!(
            !self.poisoned && !transaction::exists(&self.directory, transaction::PENDING)?,
            "recipient persistence requires reopening for recovery"
        );
        let bytes = files::read_at(&self.directory, OsStr::new(FLOOR), LIMIT, true)?;
        let witness: transaction::Witness = serde_json::from_slice(&files::read_at(
            &self.directory,
            OsStr::new(WITNESS),
            1024,
            true,
        )?)?;
        ensure!(
            digest(&bytes) == self.digest
                && witness.sequence == self.stored.sequence
                && witness.digest == self.digest,
            "recipient journal changed outside its exclusive owner"
        );
        Ok(())
    }
    fn check_result(&self, result: &VerifiedResult) -> Result<()> {
        self.unchanged()?;
        self.unsealed()?;
        ensure!(
            result.executed.recipient == self.recipient()
                && result.challenge.recipient == self.recipient()
                && result.point().prefix().scope() == self.descriptor.scope(),
            "proof belongs to another recipient or configuration"
        );
        result.request().ordinary()?;
        if let Some(h) = result.history() {
            ensure!(
                h.from() == self.prefix() && h.prior() == self.tree_head(),
                "recipient history starts from another retained floor"
            );
        }
        result.extends(self.prefix())
    }
    fn advance(&mut self, result: &VerifiedResult, wall: u64) -> Result<()> {
        self.check_result(result)?;
        let mut next = self.stored.clone();
        let mut versions: BTreeMap<_, _> = next
            .versions
            .iter()
            .map(|r| (r.index(), r.clone()))
            .collect();
        let expected = if result.disposition() == Disposition::Permit {
            result.request().expected()
        } else {
            &[]
        };
        for r in expected.iter().chain(&result.generations) {
            if let Some(old) = versions.get(&r.index()) {
                ensure!(
                    r.generation > old.generation
                        || r == old
                        || result.validates_update(r, old)
                            && self
                                .stored
                                .callers
                                .iter()
                                .any(|c| c.key == result.request().requester()
                                    && c.intent == result.request().digest()
                                    && c.result == result.executed.result),
                    "recipient proof is below a retained restriction or version"
                );
            }
        }
        for r in &result.generations {
            versions.insert(r.index(), r.clone());
        }
        next.versions = versions.into_values().collect();
        if result.disposition() == Disposition::Permit {
            let i = result.request().ordinary()?;
            if let Some(c) = next.callers.iter_mut().find(|c| c.key == i.requester) {
                c.learn(i, result.executed.result)?;
            } else {
                let mut c = Caller::from(i);
                c.result = result.executed.result;
                next.callers.push(c);
                next.callers.sort_by_key(|c| c.key);
            }
            // Only completed local effects may retire after a certified caller acknowledgement/fence.
            // Uncertain effects remain visible and cannot be silently retried or discarded.
            next.claims.retain(|c| {
                c.state != ClaimState::Complete
                    || c.requester != i.requester
                    || !(c.generation < i.generation
                        || c.generation == i.generation && c.sequence <= i.acknowledged_through)
            });
        }
        next.certificate = Some(hex::encode(result.point().certificate()));
        next.node = Some(hex::encode(result.point().node()));
        next.checkpoint = result
            .history()
            .map(|h| hex::encode(h.checkpoint().canonical_proof()))
            .or(next.checkpoint);
        next.wall_floor_ms = wall;
        transaction::publish(self, next, Some(result.continuity()))
    }
    pub fn observe(&mut self, result: VerifiedResult) -> Result<()> {
        ensure!(
            result.disposition() != Disposition::Permit,
            "recipient observation cannot release a permit"
        );
        self.advance(&result, self.stored.wall_floor_ms)
    }
    /// The lower bound is an independent credential start, or zero when none applies.
    /// The original live challenge already establishes causal issuance through BOOTTIME.
    #[cfg(test)]
    pub fn accept(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        health: ClockHealth,
        not_before_ms: u64,
    ) -> Result<Permit> {
        self.accept_with_clock(result, session, &mut || Ok(health), not_before_ms)
    }
    pub fn accept_with_clock(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
        not_before_ms: u64,
    ) -> Result<Permit> {
        ensure!(
            result.disposition() == Disposition::Permit,
            "recipient requires a successful certified result"
        );
        self.check_result(&result)?;
        let now = session.check(&result, not_before_ms, clock()?)?;
        ensure!(
            now.wall_ms >= self.stored.wall_floor_ms,
            "recipient clock is below its durable floor"
        );
        self.advance(&result, now.wall_ms)?;
        session.check(&result, not_before_ms, clock()?)?;
        Ok(Permit {
            result,
            not_before_ms,
        })
    }
    fn claim(&mut self, result: &VerifiedResult, amount: u64, state: ClaimState) -> Result<()> {
        let i = result.request().ordinary()?;
        let mut next = self.stored.clone();
        if let Some(c) = next.claims.iter_mut().find(|c| c.intent == i.digest) {
            ensure!(
                state == ClaimState::Complete
                    && c.amount == amount
                    && c.result == result.executed.result,
                "recipient effect was already claimed or changed"
            );
            c.state = state;
        } else {
            ensure!(
                state == ClaimState::Claimed,
                "recipient completion has no durable claim"
            );
            next.claims.push(Claim {
                requester: i.requester,
                generation: i.generation,
                generation_id: i.generation_id,
                sequence: i.sequence,
                intent: i.digest,
                result: result.executed.result,
                amount,
                state,
            });
            next.claims.sort_by_key(|c| c.intent);
        }
        transaction::publish(self, next, None)
    }
}

pub struct Permit {
    result: VerifiedResult,
    not_before_ms: u64,
}
impl Permit {
    fn check(
        &self,
        store: &Store,
        session: &mut Session,
        health: ClockHealth,
        amount: u64,
    ) -> Result<()> {
        store.unchanged()?;
        store.unsealed()?;
        ensure!(
            self.result.executed.recipient == store.recipient(),
            "permit belongs to another recipient"
        );
        self.result.extends(store.prefix())?;
        let i = self.result.request().ordinary()?;
        let mut caller = store
            .stored
            .callers
            .iter()
            .find(|c| c.key == i.requester)
            .context("caller floor is absent")?
            .clone();
        caller.learn(i, self.result.executed.result)?;
        ensure!(
            amount <= self.result.executed.maximum_effect,
            "recipient effect exceeds certified amount"
        );
        for r in &self.result.generations {
            ensure!(
                store.generations().contains(r),
                "recipient permit lost an exact certified version"
            );
        }
        let now = session.check(&self.result, self.not_before_ms, health)?;
        ensure!(
            now.wall_ms >= store.stored.wall_floor_ms,
            "recipient clock is below its durable floor"
        );
        Ok(())
    }
    pub fn perform<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
        amount: u64,
        restrictions: impl FnMut(&Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        self.run(
            store,
            session,
            clock,
            amount,
            restrictions,
            |r, s, _| effect(r, s),
            false,
        )
    }
    /// The callback reconciles an existing resource identity; it must never blindly repeat an uncertain effect.
    pub fn reconcile<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
        amount: u64,
        restrictions: impl FnMut(&Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store, ClaimState) -> Result<T>,
    ) -> Result<T> {
        self.run(store, session, clock, amount, restrictions, effect, true)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn run<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        clock: &mut impl FnMut() -> Result<ClockHealth>,
        amount: u64,
        mut restrictions: impl FnMut(&Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store, ClaimState) -> Result<T>,
        reconcile: bool,
    ) -> Result<T> {
        self.check(store, session, clock()?, amount)?;
        restrictions(&self.result.executed.restrictions)?;
        let prior = store
            .stored
            .claims
            .iter()
            .find(|c| c.intent == self.result.request().digest());
        let state = if reconcile {
            let prior = prior.context("no existing effect to reconcile")?;
            ensure!(
                prior.amount == amount && prior.result == self.result.executed.result,
                "reconciliation differs from the exact claimed effect"
            );
            prior.state
        } else {
            ensure!(
                prior.is_none(),
                "effect may already exist; explicit reconciliation is required"
            );
            store.claim(&self.result, amount, ClaimState::Claimed)?;
            ClaimState::Claimed
        };
        self.check(store, session, clock()?, amount)?;
        restrictions(&self.result.executed.restrictions)?;
        let consumption = session.consume(&self.result, self.not_before_ms, clock()?)?;
        let value = effect(&self.result.result, store, state)?;
        store.claim(&self.result, amount, ClaimState::Complete)?;
        store.unchanged()?;
        store.unsealed()?;
        self.result.extends(store.prefix())?;
        restrictions(&self.result.executed.restrictions)?;
        let now = session.finish_consumption(consumption, clock()?)?;
        ensure!(
            now.wall_ms >= store.stored.wall_floor_ms,
            "recipient clock regressed before return"
        );
        Ok(value)
    }
}

#[cfg(test)]
#[path = "AuthorityRecipientTests.rs"]
mod tests;
