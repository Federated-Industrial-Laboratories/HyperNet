// SPDX-License-Identifier: MIT
// A private write-ahead transaction completes witnessed floors forward after interruption.
use super::*;
use std::{ffi::CString, os::fd::AsRawFd};

pub(super) const PENDING: &str = "AuthorityPending.json";
const PENDING_LIMIT: usize = 2 * LIMIT + 6 * wire::MAXIMUM + 8192;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) enum Transition {
    SealEpoch,
    ActivateEpoch,
    PrepareOrdinary {
        signed: String,
    },
    PrepareFence {
        signed: String,
        expected: String,
    },
    Learn {
        learning: tracker::Learning,
    },
    LearnRead {
        result: String,
    },
    RetainMediaContext {
        scope: String,
        certificate: String,
        result: String,
    },
    SaveBody {
        request: Digest,
        result: Digest,
    },
    Claim {
        request: Digest,
    },
    Complete {
        request: Digest,
    },
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Continuity {
    ancestry: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    history: Option<String>,
}
impl Continuity {
    fn from_evidence(value: proof::ContinuityEvidence) -> Self {
        Self {
            ancestry: value.ancestry.iter().map(hex::encode).collect(),
            history: value.history.map(hex::encode),
        }
    }
    fn evidence(&self) -> Result<proof::ContinuityEvidence> {
        ensure!(
            self.ancestry.len() <= 128,
            "too many pending ancestry nodes"
        );
        let ancestry = self
            .ancestry
            .iter()
            .map(hex::decode)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            ancestry
                .iter()
                .try_fold(0usize, |sum, b| sum.checked_add(b.len()))
                .is_some_and(|n| n <= wire::MAXIMUM),
            "pending ancestry exceeds its bound"
        );
        let history = self.history.as_ref().map(hex::decode).transpose()?;
        ensure!(
            history.as_ref().is_none_or(|b| b.len() <= wire::MAXIMUM),
            "pending history exceeds its bound"
        );
        Ok(proof::ContinuityEvidence { ancestry, history })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    format: String,
    network: String,
    incarnation: String,
    requester: String,
    descriptor: String,
    old_witness: Witness,
    next_witness: Witness,
    next_floor_bytes: String,
    transition: Transition,
    continuity: Continuity,
}
pub(super) fn exists(directory: &File, name: &str) -> Result<bool> {
    let name = CString::new(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(libc::ENOENT),
        "cannot inspect private transaction: {error}"
    );
    Ok(false)
}
fn binding(stored: &Stored, pending: &Pending) -> Result<()> {
    ensure!(
        pending.format == "HyperNetAuthorityPending/1"
            && pending.network == stored.network
            && pending.incarnation == stored.incarnation
            && pending.requester == stored.requester
            && pending.descriptor == stored.descriptor
            && pending.old_witness.sequence.checked_add(1) == Some(pending.next_witness.sequence)
            && pending.next_witness.sequence == stored.sequence,
        "pending floor identity or sequence differs"
    );
    for value in [&pending.old_witness.digest, &pending.next_witness.digest] {
        ensure!(
            hex::decode(value)?.len() == 32,
            "invalid pending witness digest"
        );
    }
    Ok(())
}
fn shape(next: &Stored, transition: &Transition) -> Result<()> {
    match transition {
        Transition::SealEpoch => ensure!(next.sealed.is_some(), "Epoch seal missing"),
        Transition::ActivateEpoch => ensure!(
            next.sealed.is_none() && !next.epochs.is_empty(),
            "Epoch activation missing"
        ),
        Transition::PrepareOrdinary { signed } => {
            let o = next
                .tracker
                .ordinary
                .as_ref()
                .context("prepared ordinary missing")?;
            ensure!(
                &o.signed == signed
                    && o.original.is_none()
                    && o.latest.is_none()
                    && !o.body_saved
                    && !o.complete
                    && o.effect == tracker::Effect::Unclaimed,
                "invalid prepared ordinary state"
            );
        }
        Transition::PrepareFence { signed, expected } => {
            let f = next
                .tracker
                .fence
                .as_ref()
                .context("prepared fence missing")?;
            ensure!(
                &f.signed == signed && &f.expected_metadata == expected && f.latest.is_none(),
                "invalid prepared fence state"
            );
        }
        Transition::Learn { learning } => {
            learning.validate()?;
            if learning.kind == 20 {
                let o = next
                    .tracker
                    .ordinary
                    .as_ref()
                    .context("learned ordinary missing")?;
                ensure!(
                    o.request()?.digest == learning.request
                        && o.latest.as_ref() == Some(&learning.reply),
                    "learned ordinary state differs"
                );
            } else {
                ensure!(
                    next.tracker.metadata == learning.metadata,
                    "learned metadata differs"
                );
            }
        }
        Transition::LearnRead { result } => {
            OperationResult::parse(&hex::decode(result)?)?;
        }
        Transition::RetainMediaContext { .. } => {
            ensure!(
                next.tracker
                    .ordinary
                    .as_ref()
                    .is_some_and(|o| o.original.is_some()),
                "remote context lacks original completion"
            );
        }
        Transition::SaveBody { request, result } => {
            let o = next
                .tracker
                .ordinary
                .as_ref()
                .context("saved body request missing")?;
            ensure!(
                o.request()?.digest == *request
                    && o.body_saved
                    && o.original
                        .as_ref()
                        .is_some_and(|c| c.result_digest == *result && c.disposition == 0),
                "saved body transition differs"
            );
        }
        Transition::Claim { request } | Transition::Complete { request } => {
            let o = next
                .tracker
                .ordinary
                .as_ref()
                .context("effect request missing")?;
            ensure!(
                o.request()?.digest == *request && o.body_saved,
                "effect transition differs"
            );
            ensure!(
                match transition {
                    Transition::Claim { .. } => o.effect == tracker::Effect::Claimed && !o.complete,
                    _ => o.complete && o.effect != tracker::Effect::Claimed,
                },
                "effect transition is incomplete"
            );
        }
    }
    Ok(())
}
fn delta(
    initial: &TrustDescriptor,
    old: &Stored,
    next: &Stored,
    transition: &Transition,
) -> Result<()> {
    if matches!(
        transition,
        Transition::SealEpoch | Transition::ActivateEpoch
    ) {
        return epoch::forward(initial, old, next, transition);
    }
    ensure!(
        old.epochs == next.epochs && old.sealed == next.sealed && old.sealed.is_none(),
        "Ordinary transaction changes or passes a sealed epoch"
    );
    let resolved = old.resolve(initial)?;
    ensure!(
        old.network == next.network
            && old.incarnation == next.incarnation
            && old.requester == next.requester
            && old.descriptor == next.descriptor
            && old.sequence.checked_add(1) == Some(next.sequence)
            && next.wall_floor_ms >= old.wall_floor_ms,
        "pending transaction changed identity or moved backwards"
    );
    for before in &old.generations {
        let after = next
            .generations
            .iter()
            .find(|v| v.index() == before.index())
            .context("pending transaction omitted a restrictive floor")?;
        ensure!(
            after.generation >= before.generation
                && (after.generation != before.generation || after.digest == before.digest),
            "pending restrictive generation moved backwards"
        );
    }
    let expected = match transition {
        Transition::SealEpoch | Transition::ActivateEpoch => unreachable!(),
        Transition::PrepareOrdinary { signed } => {
            old.tracker.prepare_ordinary(&hex::decode(signed)?)?
        }
        Transition::PrepareFence { signed, expected } => old
            .tracker
            .prepare_fence(&hex::decode(signed)?, &hex::decode(expected)?)?,
        Transition::Learn { learning } => old.tracker.learn_current(
            learning,
            resolved.descriptor.scope(),
            &resolved.previous_scopes,
        )?,
        Transition::LearnRead { .. } | Transition::RetainMediaContext { .. } => old.tracker.clone(),
        Transition::SaveBody { request, result } => old.tracker.body_saved(*request, *result)?,
        Transition::Claim { request } => old.tracker.effect(*request, true)?,
        Transition::Complete { request } => old.tracker.effect(*request, false)?,
    };
    ensure!(
        expected == next.tracker,
        "pending tracker transition is not the exact typed successor"
    );
    if !matches!(
        transition,
        Transition::Learn { .. } | Transition::LearnRead { .. }
    ) {
        ensure!(
            old.certificate == next.certificate
                && old.node == next.node
                && old.checkpoint_proof == next.checkpoint_proof
                && (matches!(transition, Transition::RetainMediaContext { .. })
                    || old.generations == next.generations)
                && old.wall_floor_ms == next.wall_floor_ms,
            "local tracker transition changed authority"
        );
    }
    if let Transition::LearnRead { result } = transition {
        let result = OperationResult::parse(&hex::decode(result)?)?;
        let mut exact: BTreeMap<_, _> = old
            .generations
            .iter()
            .map(|r| (r.index(), r.clone()))
            .collect();
        for version in crate::authority_read::result_versions(&result)? {
            exact.insert(version.index(), version);
        }
        ensure!(
            next.generations == exact.into_values().collect::<Vec<_>>(),
            "fresh read added uncertified generations"
        );
    }
    if let Transition::RetainMediaContext {
        scope,
        certificate,
        result,
    } = transition
    {
        let versions = media_context_versions(initial, old, scope, certificate, result)?;
        let mut exact: BTreeMap<_, _> = old
            .generations
            .iter()
            .map(|v| (v.index(), v.clone()))
            .collect();
        for version in versions {
            exact.insert(version.index(), version);
        }
        ensure!(
            next.generations == exact.into_values().collect::<Vec<_>>(),
            "remote context added uncertified generations"
        );
    }
    Ok(())
}
fn media_context_versions(
    initial: &TrustDescriptor,
    old: &Stored,
    scope: &str,
    certificate: &str,
    result: &str,
) -> Result<Vec<VersionRef>> {
    let scope = proof::Scope::parse(&wire::decode(&hex::decode(scope)?)?)?;
    let descriptor =
        crate::authority_epoch::archive::descriptor_for_scope(initial, &old.epochs, &scope)?;
    let executed = proof::ExecutedResult::parse(&descriptor.quorum(&hex::decode(certificate)?)?)?;
    let bytes = hex::decode(result)?;
    let operation = proof::OperationResult::parse(&bytes)?;
    let pending = old
        .tracker
        .ordinary
        .as_ref()
        .context("remote context has no exact pending request")?;
    let request =
        crate::authority_domains::page::MediaRequest::parse(&hex::decode(&pending.signed)?)?;
    ensure!(
        executed.scope == scope
            && executed.intent == request.intent().digest
            && executed.requester == old.requester()?
            && executed.action == "AuthorityDomain"
            && executed.result == wire::digest(&bytes)
            && operation.action == "AuthorityDomain"
            && operation.disposition == Disposition::Permit
            && executed.maximum_effect == 1
            && pending.effect != tracker::Effect::Claimed
            && pending
                .original
                .as_ref()
                .is_some_and(|c| c.intent == executed.intent
                    && c.result_digest == executed.result
                    && c.disposition == 0
                    && c.reason == 0),
        "remote context differs from exact certified original completion"
    );
    let value = wire::decode(&operation.value)?;
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
        "remote domain context format differs"
    );
    let versions = f[3]
        .list(64)?
        .iter()
        .map(crate::authority_domains::version)
        .collect::<Result<Vec<_>>>()?;
    proof::validate_versions(&versions, 64)?;
    Ok(versions)
}
fn learning_certificate(
    descriptor: &TrustDescriptor,
    next: &Stored,
    transition: &Transition,
) -> Result<()> {
    let resolved = next.resolve(descriptor)?;
    let descriptor = &resolved.descriptor;
    if let Transition::LearnRead { result } = transition {
        let certificate = hex::decode(
            next.certificate
                .as_ref()
                .context("fresh read certificate missing")?,
        )?;
        let statement = crate::authority_read::Statement::parse(&descriptor.quorum(&certificate)?)?;
        let bytes = hex::decode(result)?;
        let result = OperationResult::parse(&bytes)?;
        ensure!(
            statement.requester == next.requester()?
                && statement.recipient == next.requester()?
                && statement.result == wire::digest(&bytes),
            "fresh read result differs from certified context"
        );
        let versions = crate::authority_read::result_versions(&result)?;
        ensure!(
            versions.iter().all(|v| next.generations.contains(v)),
            "fresh read versions missing from floor"
        );
    }
    if let Transition::Learn { learning } = transition {
        let bytes = hex::decode(
            next.certificate
                .as_ref()
                .context("learned result omitted certificate")?,
        )?;
        let executed = proof::ExecutedResult::parse(&descriptor.quorum(&bytes)?)?;
        ensure!(
            executed.intent == learning.request
                && executed.requester == next.requester()?
                && executed.result == learning.reply.digest,
            "learned tracker response differs from certified result"
        );
        if learning.kind != 20 {
            let m = proof::OwnStreamMetadata::parse(&hex::decode(
                learning
                    .metadata
                    .as_ref()
                    .context("control metadata missing")?,
            )?)?;
            let (action, value) = if learning.kind == 55 {
                ("AuthorityStreamStatus", m.canonical().to_vec())
            } else {
                (
                    "AuthorityStreamFence",
                    wire::encode(&wire::Value::Array(vec![
                        wire::Value::Uint(58),
                        wire::Value::Uint(1),
                        m.scope().value(),
                        wire::Value::Bytes(m.requester().to_vec()),
                        wire::Value::Bytes(learning.request.to_vec()),
                        wire::Value::Uint(learning.outcome.context("fence outcome missing")?),
                        wire::Value::Bytes(m.canonical().to_vec()),
                    ]))?,
                )
            };
            let bytes = wire::encode(&wire::Value::Array(vec![
                wire::Value::Uint(24),
                wire::Value::Uint(1),
                wire::Value::Text(action.into()),
                wire::Value::Uint(learning.reply.disposition),
                wire::Value::Uint(learning.reply.reason),
                wire::Value::Bytes(value),
            ]))?;
            ensure!(
                executed.action == action && wire::digest(&bytes) == executed.result,
                "control metadata differs from its certified result"
            );
        }
    }
    Ok(())
}
fn forward(
    descriptor: &TrustDescriptor,
    old: &Stored,
    next: &Stored,
    pending: &Pending,
) -> Result<()> {
    delta(descriptor, old, next, &pending.transition)?;
    if matches!(
        pending.transition,
        Transition::SealEpoch | Transition::ActivateEpoch
    ) {
        let evidence = pending.continuity.evidence()?;
        ensure!(
            evidence.ancestry.is_empty() && evidence.history.is_none(),
            "Epoch transaction carries unrelated continuity"
        );
        return Ok(());
    }
    let initial = descriptor;
    let resolved = old.resolve(initial)?;
    let descriptor = &resolved.descriptor;
    if let Transition::Learn { learning } = &pending.transition
        && learning.kind == 57
    {
        let old_fence = old
            .tracker
            .fence
            .as_ref()
            .context("fence transition lacks exact pending comparison")?;
        let request = proof::SignedRequest::from_signed(&hex::decode(&old_fence.signed)?)?;
        let expected = hex::decode(&old_fence.expected_metadata)?;
        let metadata = proof::OwnStreamMetadata::parse(&hex::decode(
            learning
                .metadata
                .as_ref()
                .context("missing fence metadata")?,
        )?)?;
        let value = wire::encode(&wire::Value::Array(vec![
            wire::Value::Uint(58),
            wire::Value::Uint(1),
            metadata.scope().value(),
            wire::Value::Bytes(metadata.requester().to_vec()),
            wire::Value::Bytes(learning.request.to_vec()),
            wire::Value::Uint(learning.outcome.context("fence outcome missing")?),
            wire::Value::Bytes(metadata.canonical().to_vec()),
        ]))?;
        let operation = OperationResult {
            action: "AuthorityStreamFence".into(),
            disposition: if learning.reply.disposition == 0 {
                Disposition::Permit
            } else {
                Disposition::Refuse
            },
            code: learning.reply.reason,
            value,
        };
        let certificate = hex::decode(
            next.certificate
                .as_ref()
                .context("missing fence certificate")?,
        )?;
        let executed = proof::ExecutedResult::parse(&descriptor.quorum(&certificate)?)?;
        proof::validate_stream_response(&request, &operation, &executed, Some(&expected))?;
    }
    let (old_prefix, old_checkpoint) = old.validate(initial)?;
    let (next_prefix, next_checkpoint) = next.validate(initial)?;
    let evidence = pending.continuity.evidence()?;
    if let (Some(c), Some(n)) = (&next.certificate, &next.node) {
        let point = CertifiedPoint::from_evidence(descriptor, &hex::decode(c)?, &hex::decode(n)?)?;
        proof::validate_continuity(
            descriptor,
            &old_prefix,
            old_checkpoint.as_ref().map(ValidatedCheckpoint::head),
            &point,
            next_checkpoint.as_ref(),
            &evidence,
        )?;
    } else {
        ensure!(
            old_prefix == next_prefix
                && old.certificate.is_none()
                && old.checkpoint_proof == next.checkpoint_proof
                && evidence.ancestry.is_empty()
                && evidence.history.is_none(),
            "pending genesis transition changed authority"
        );
    }
    Ok(())
}
pub(super) fn recover(directory: &File, descriptor: &TrustDescriptor) -> Result<()> {
    if !exists(directory, PENDING)? {
        return Ok(());
    }
    let pending: Pending = serde_json::from_slice(&files::read_at(
        directory,
        OsStr::new(PENDING),
        PENDING_LIMIT,
        true,
    )?)?;
    let next_bytes = hex::decode(&pending.next_floor_bytes)?;
    ensure!(
        next_bytes.len() <= LIMIT
            && hex::encode(digest(&next_bytes)) == pending.next_witness.digest,
        "pending next floor digest differs"
    );
    let next: Stored = serde_json::from_slice(&next_bytes)?;
    next.validate(descriptor)?;
    binding(&next, &pending)?;
    shape(&next, &pending.transition)?;
    learning_certificate(descriptor, &next, &pending.transition)?;
    pending.continuity.evidence()?;
    let bytes = files::read_at(directory, OsStr::new(FLOOR), LIMIT, true)?;
    let current: Stored = serde_json::from_slice(&bytes)?;
    let witness: Witness =
        serde_json::from_slice(&files::read_at(directory, OsStr::new(WITNESS), 1024, true)?)?;
    let current_witness = Witness {
        sequence: current.sequence,
        digest: hex::encode(digest(&bytes)),
    };
    if current_witness == pending.next_witness && witness == pending.next_witness {
        ensure!(bytes == next_bytes, "published next floor bytes differ");
        // The old state is no longer present. Validate the completed private publication, not an invented old-state proof.
        check_body(directory, &next)?;
        files::remove_private_at(directory, OsStr::new(PENDING))?;
        return Ok(());
    }
    ensure!(
        current_witness == pending.old_witness
            && (witness == pending.old_witness || witness == pending.next_witness),
        "pending transaction conflicts with floor or witness"
    );
    forward(descriptor, &current, &next, &pending)?;
    check_body(directory, &next)?;
    if witness == pending.old_witness {
        files::atomic_at(
            directory,
            OsStr::new(WITNESS),
            &serde_json::to_vec(&pending.next_witness)?,
            true,
        )?;
    }
    files::atomic_at(directory, OsStr::new(FLOOR), &next_bytes, true)?;
    files::remove_private_at(directory, OsStr::new(PENDING))?;
    Ok(())
}
pub(super) fn publish(
    store: &mut Store,
    next: Stored,
    transition: Transition,
    continuity: proof::ContinuityEvidence,
) -> Result<()> {
    let next_bytes = serde_json::to_vec(&next)?;
    ensure!(
        next_bytes.len() <= LIMIT,
        "authority floor capacity reached"
    );
    let pending = Pending {
        format: "HyperNetAuthorityPending/1".into(),
        network: next.network.clone(),
        incarnation: next.incarnation.clone(),
        requester: next.requester.clone(),
        descriptor: next.descriptor.clone(),
        old_witness: Witness {
            sequence: store.stored.sequence,
            digest: hex::encode(store.digest),
        },
        next_witness: Witness {
            sequence: next.sequence,
            digest: hex::encode(digest(&next_bytes)),
        },
        next_floor_bytes: hex::encode(&next_bytes),
        transition,
        continuity: Continuity::from_evidence(continuity),
    };
    binding(&next, &pending)?;
    shape(&next, &pending.transition)?;
    learning_certificate(&store.initial_descriptor, &next, &pending.transition)?;
    forward(&store.initial_descriptor, &store.stored, &next, &pending)?;
    let (prefix, checkpoint) = next.validate(&store.initial_descriptor)?;
    let bytes = serde_json::to_vec(&pending)?;
    ensure!(
        bytes.len() <= PENDING_LIMIT,
        "authority pending transaction exceeds its bound"
    );
    ensure!(
        !exists(&store.directory, PENDING)?,
        "pending publication already exists"
    );
    store.poisoned = true;
    files::atomic_at(&store.directory, OsStr::new(PENDING), &bytes, false)?;
    files::atomic_at(
        &store.directory,
        OsStr::new(WITNESS),
        &serde_json::to_vec(&pending.next_witness)?,
        true,
    )?;
    files::atomic_at(&store.directory, OsStr::new(FLOOR), &next_bytes, true)?;
    files::remove_private_at(&store.directory, OsStr::new(PENDING))?;
    store.descriptor = next.resolve(&store.initial_descriptor)?.descriptor;
    store.stored = next;
    store.floor = prefix;
    store.checkpoint = checkpoint;
    store.digest = digest(&next_bytes);
    store.poisoned = false;
    Ok(())
}

#[cfg(test)]
#[path = "AuthorityFloorTransactionTests.rs"]
mod tests;
