// SPDX-License-Identifier: MIT
// Interrupted recipient journals complete forward from an exact witnessed predecessor.
use super::*;
use std::{ffi::CString, os::fd::AsRawFd};
pub(super) const PENDING: &str = "RecipientPending.json";
const PENDING_LIMIT: usize = 4 * LIMIT + 4 * wire::MAXIMUM + 8192;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Witness {
    pub sequence: u64,
    pub digest: Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Continuity {
    ancestry: Vec<String>,
    history: Option<String>,
}
impl Continuity {
    fn evidence(&self) -> Result<proof::ContinuityEvidence> {
        ensure!(
            self.ancestry.len() <= 128,
            "recipient pending ancestry exceeds bound"
        );
        let ancestry = self
            .ancestry
            .iter()
            .map(hex::decode)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            ancestry.iter().map(Vec::len).sum::<usize>() <= wire::MAXIMUM,
            "recipient pending ancestry exceeds wire bound"
        );
        let history = self.history.as_ref().map(hex::decode).transpose()?;
        ensure!(
            history.as_ref().is_none_or(|h| h.len() <= wire::MAXIMUM),
            "recipient pending history exceeds wire bound"
        );
        Ok(proof::ContinuityEvidence { ancestry, history })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pending {
    old: String,
    next: String,
    continuity: Option<Continuity>,
}
pub(super) fn exists(directory: &File, name: &str) -> Result<bool> {
    let name = CString::new(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(libc::ENOENT),
        "cannot inspect recipient journal: {error}"
    );
    Ok(false)
}
fn transition(
    old: &Stored,
    next: &Stored,
    descriptor: &TrustDescriptor,
    evidence: Option<&Continuity>,
) -> Result<()> {
    let (prefix, checkpoint) = old.validate(descriptor)?;
    let (_, next_checkpoint) = next.validate(descriptor)?;
    if old.epochs != next.epochs || old.sealed != next.sealed {
        ensure!(
            evidence.is_none(),
            "epoch transition cannot mix ordinary authority evidence"
        );
        return epoch::forward(descriptor, old, next);
    }
    ensure!(
        old.sealed.is_none(),
        "sealed epoch cannot advance effects or ordinary floors"
    );
    let resolved = old.resolve(descriptor)?;
    let descriptor = &resolved.descriptor;
    ensure!(
        next.recipient == old.recipient
            && next.configuration == old.configuration
            && old.sequence.checked_add(1) == Some(next.sequence)
            && next.wall_floor_ms >= old.wall_floor_ms,
        "recipient transition changed identity or regressed"
    );
    for r in &old.versions {
        ensure!(
            next.versions
                .iter()
                .find(|v| v.index() == r.index())
                .is_some_and(|v| v.generation > r.generation || v == r),
            "recipient transition lost a certified version floor"
        );
    }
    if let Some(evidence) = evidence {
        let point = CertifiedPoint::from_evidence(
            descriptor,
            &hex::decode(
                next.certificate
                    .as_ref()
                    .context("recipient advance has no certificate")?,
            )?,
            &hex::decode(
                next.node
                    .as_ref()
                    .context("recipient advance has no node")?,
            )?,
        )?;
        proof::validate_continuity(
            descriptor,
            &prefix,
            checkpoint.as_ref().map(ValidatedCheckpoint::head),
            &point,
            next_checkpoint.as_ref(),
            &evidence.evidence()?,
        )?;
        // A floor advance cannot create or complete effects. Completed effects may retire
        // only below a monotonically certified caller acknowledgement or generation.
        for c in &next.claims {
            ensure!(
                old.claims.iter().any(|p| p == c),
                "recipient advance changed a local effect"
            );
        }
        for c in &old.callers {
            let n = next
                .callers
                .iter()
                .find(|n| n.key == c.key)
                .context("recipient advance lost a caller floor")?;
            ensure!(
                n.generation > c.generation
                    || n.generation == c.generation
                        && n.generation_id == c.generation_id
                        && n.sequence >= c.sequence
                        && n.acknowledged >= c.acknowledged
                        && (n.sequence != c.sequence
                            || n.intent == c.intent && n.result == c.result),
                "recipient advance reset caller history"
            );
        }
        for c in &old.claims {
            if !next.claims.contains(c) {
                let caller = next
                    .callers
                    .iter()
                    .find(|a| a.key == c.requester)
                    .context("retired effect has no caller floor")?;
                ensure!(
                    c.state == ClaimState::Complete
                        && (c.generation < caller.generation
                            || c.generation == caller.generation
                                && c.sequence <= caller.acknowledged),
                    "recipient advance erased an uncertain or unacknowledged effect"
                );
            }
        }
    } else {
        let mut fixed = next.clone();
        fixed.sequence = old.sequence;
        fixed.claims = old.claims.clone();
        ensure!(
            fixed == *old,
            "local effect transition changed authority or caller floors"
        );
        let mut changes = 0;
        for c in &old.claims {
            let n = next
                .claims
                .iter()
                .find(|n| n.intent == c.intent)
                .context("local transition erased an effect")?;
            if n != c {
                let mut completed = c.clone();
                completed.state = ClaimState::Complete;
                ensure!(
                    c.state == ClaimState::Claimed && *n == completed,
                    "local transition reset or changed a claim"
                );
                changes += 1;
            }
        }
        for c in next
            .claims
            .iter()
            .filter(|c| !old.claims.iter().any(|p| p.intent == c.intent))
        {
            ensure!(
                c.state == ClaimState::Claimed,
                "local transition completed an unclaimed effect"
            );
            let caller = old
                .callers
                .iter()
                .find(|a| a.key == c.requester)
                .context("claim has no certified caller")?;
            ensure!(
                c.generation == caller.generation
                    && c.generation_id == caller.generation_id
                    && c.sequence == caller.sequence
                    && c.intent == caller.intent
                    && c.result == caller.result,
                "claim differs from retained caller request"
            );
            changes += 1;
        }
        ensure!(
            changes <= 1,
            "local transition changes more than one effect"
        );
    }
    Ok(())
}
fn decode(
    pending: &Pending,
    descriptor: &TrustDescriptor,
    recipient: Key,
) -> Result<(Vec<u8>, Stored, Vec<u8>, Stored)> {
    ensure!(
        pending.old.len() <= 2 * LIMIT && pending.next.len() <= 2 * LIMIT,
        "recipient transaction exceeds journal bound"
    );
    let old_bytes = hex::decode(&pending.old)?;
    let next_bytes = hex::decode(&pending.next)?;
    let old: Stored = serde_json::from_slice(&old_bytes)?;
    let next: Stored = serde_json::from_slice(&next_bytes)?;
    ensure!(
        old.recipient == recipient,
        "recipient transaction belongs to another service"
    );
    transition(&old, &next, descriptor, pending.continuity.as_ref())?;
    Ok((old_bytes, old, next_bytes, next))
}
fn install_initial(
    directory: &File,
    pending: &Pending,
    descriptor: &TrustDescriptor,
    recipient: Key,
) -> Result<(Vec<u8>, Stored)> {
    ensure!(
        pending.continuity.is_none() && pending.next.len() <= 2 * LIMIT,
        "invalid recipient initialization transaction"
    );
    let bytes = hex::decode(&pending.next)?;
    let next: Stored = serde_json::from_slice(&bytes)?;
    let (prefix, _) = next.validate(descriptor)?;
    ensure!(
        next.recipient == recipient
            && next.sequence == 1
            && next.epochs.is_empty()
            && next.sealed.is_none()
            && prefix == descriptor.genesis()?,
        "initial recipient journal differs from pinned genesis"
    );
    let witness = serde_json::to_vec(&Witness {
        sequence: 1,
        digest: digest(&bytes),
    })?;
    for (name, expected, limit) in [
        (FLOOR, bytes.as_slice(), LIMIT),
        (WITNESS, witness.as_slice(), 1024),
    ] {
        if exists(directory, name)? {
            ensure!(
                files::read_at(directory, OsStr::new(name), limit, true)? == expected,
                "existing initialization artifact differs; no state replaced"
            );
        } else {
            files::atomic_at(directory, OsStr::new(name), expected, false)?;
        }
    }
    files::remove_private_at(directory, OsStr::new(PENDING))?;
    Ok((bytes, next))
}
fn install(
    directory: &File,
    pending: &Pending,
    descriptor: &TrustDescriptor,
    recipient: Key,
) -> Result<(Vec<u8>, Stored)> {
    if pending.old.is_empty() {
        return install_initial(directory, pending, descriptor, recipient);
    }
    let (old_bytes, old, next_bytes, next) = decode(pending, descriptor, recipient)?;
    let old_witness = Witness {
        sequence: old.sequence,
        digest: digest(&old_bytes),
    };
    let next_witness = Witness {
        sequence: next.sequence,
        digest: digest(&next_bytes),
    };
    let bytes = files::read_at(directory, OsStr::new(FLOOR), LIMIT, true)?;
    let witness: Witness =
        serde_json::from_slice(&files::read_at(directory, OsStr::new(WITNESS), 1024, true)?)?;
    ensure!(
        (bytes == old_bytes && witness == old_witness)
            || bytes == next_bytes && (witness == old_witness || witness == next_witness),
        "recipient pending transition does not extend the exact retained witness"
    );
    if bytes != next_bytes {
        files::atomic_at(directory, OsStr::new(FLOOR), &next_bytes, true)?;
    }
    if witness != next_witness {
        files::atomic_at(
            directory,
            OsStr::new(WITNESS),
            &serde_json::to_vec(&next_witness)?,
            true,
        )?;
    }
    files::remove_private_at(directory, OsStr::new(PENDING))?;
    Ok((next_bytes, next))
}
pub(super) fn initialise(
    directory: &File,
    descriptor: &TrustDescriptor,
    next: &Stored,
) -> Result<Vec<u8>> {
    let pending = Pending {
        old: String::new(),
        next: hex::encode(serde_json::to_vec(next)?),
        continuity: None,
    };
    files::atomic_at(
        directory,
        OsStr::new(PENDING),
        &serde_json::to_vec(&pending)?,
        false,
    )?;
    Ok(install_initial(directory, &pending, descriptor, next.recipient)?.0)
}
pub(super) fn recover(
    directory: &File,
    descriptor: &TrustDescriptor,
    recipient: Key,
) -> Result<()> {
    if exists(directory, PENDING)? {
        let p: Pending = serde_json::from_slice(&files::read_at(
            directory,
            OsStr::new(PENDING),
            PENDING_LIMIT,
            true,
        )?)?;
        install(directory, &p, descriptor, recipient)?;
    }
    Ok(())
}
pub(super) fn publish(
    store: &mut Store,
    mut next: Stored,
    continuity: Option<proof::ContinuityEvidence>,
) -> Result<()> {
    store.unchanged()?;
    next.sequence = store
        .stored
        .sequence
        .checked_add(1)
        .context("recipient journal sequence exhausted")?;
    let old = files::read_at(&store.directory, OsStr::new(FLOOR), LIMIT, true)?;
    let bytes = serde_json::to_vec(&next)?;
    ensure!(
        bytes.len() <= LIMIT,
        "recipient journal capacity reached before publication"
    );
    let pending = Pending {
        old: hex::encode(old),
        next: hex::encode(bytes),
        continuity: continuity.map(|c| Continuity {
            ancestry: c.ancestry.iter().map(hex::encode).collect(),
            history: c.history.map(hex::encode),
        }),
    };
    decode(&pending, &store.initial_descriptor, store.recipient())?;
    let bytes = serde_json::to_vec(&pending)?;
    ensure!(
        bytes.len() <= PENDING_LIMIT,
        "recipient transaction capacity reached"
    );
    store.poisoned = true;
    files::atomic_at(&store.directory, OsStr::new(PENDING), &bytes, false)?;
    let (bytes, next) = install(
        &store.directory,
        &pending,
        &store.initial_descriptor,
        store.recipient(),
    )?;
    let (prefix, checkpoint) = next.validate(&store.initial_descriptor)?;
    store.descriptor = next.resolve(&store.initial_descriptor)?.descriptor;
    store.stored = next;
    store.prefix = prefix;
    store.checkpoint = checkpoint;
    store.digest = digest(&bytes);
    store.poisoned = false;
    Ok(())
}
