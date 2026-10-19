// SPDX-License-Identifier: MIT
// Stopped bridges inspect and explicitly fence their own stream without serving another effect.
use super::*;
use crate::{
    authority_challenge::{MAXIMUM_DURATION_MS, Session},
    authority_floor::{PreparedRequest, Store},
    authority_proof::{
        self as proof, Challenge, Disposition, OwnStreamMetadata, Restrictions, StreamResponse,
    },
};
use rand::{RngCore, rngs::OsRng};

fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn random() -> Result<Digest> {
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "zero Bridge recovery nonce");
    Ok(nonce)
}

fn control(
    store: &mut Store,
    session: &mut Session,
    config: &Config,
    guard: &Guard,
    request: &[u8],
    expected: Option<&[u8]>,
) -> Result<StreamResponse> {
    guard.check()?;
    let health = guard.health()?;
    let now = health.observe()?;
    let descriptor = store.descriptor().clone();
    let challenge = session.issue(request, &config.key, random()?, MAXIMUM_DURATION_MS, health)?;
    let result = (|| {
        let parsed = Challenge::from_signed(&challenge)?;
        let ordered = wire::encode(&a(vec![
            V::Uint(22),
            V::Uint(1),
            descriptor.scope().value(),
            b(request),
            b(&challenge),
            V::Uint(parsed.expires_at_ms),
        ]))?;
        let deadline = now
            .boot_ms
            .checked_add(MAXIMUM_DURATION_MS)
            .context("Bridge recovery deadline overflow")?;
        let (reply, history) = transport::exchange(
            &descriptor,
            &ordered,
            deadline,
            Path::new("/Authority/Control.sock"),
            store.prefix(),
            store.tree_head(),
            &mut || {
                guard.check()?;
                guard.health()
            },
        )?;
        let verified = proof::verify_response(
            &descriptor,
            proof::ProofContext {
                intent: request,
                challenge: &challenge,
                restrictions: Restrictions::default(),
                minimum_height: store.prefix().height(),
                maximum_effect: 1,
                expected_stream: expected,
            },
            proof::Response {
                ordered_request: &ordered,
                operation_result: &reply.result,
                certificate: &reply.certificate,
                ancestry: &history.nodes,
            },
            |_, _, _| anyhow::bail!("ordinary effects cannot use Bridge requester recovery"),
        )?;
        let verified = history.attach(store, verified)?;
        let response = verified
            .stream_response()
            .context("Bridge stream response absent")?
            .clone();
        guard.check()?;
        if verified.disposition() != Disposition::Permit {
            let code = verified.code();
            store.observe(verified)?;
            anyhow::bail!(
                "Bridge requester control refused with code {code}; retain its exact expected metadata"
            );
        }
        transport::remaining(deadline)?;
        store
            .accept_with_clock(verified, session, &mut || guard.health(), 0)?
            .perform_with_clock(
                store,
                session,
                &mut || guard.health(),
                1,
                |restrictions| {
                    guard.check()?;
                    ensure!(
                        *restrictions == Restrictions::default(),
                        "Bridge recovery restrictions changed"
                    );
                    Ok(())
                },
                |_, _| Ok(response),
            )
    })();
    if result.is_err() {
        session.discard(&challenge)?;
    }
    result
}

fn status(
    store: &mut Store,
    session: &mut Session,
    config: &Config,
    guard: &Guard,
) -> Result<OwnStreamMetadata> {
    let scope = store.descriptor().scope();
    let signed = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(55),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&store.requester()),
            b(&random()?),
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
        ]))?,
        &config.key,
    )?;
    match control(store, session, config, guard, &signed, None)? {
        StreamResponse::Status(metadata) => Ok(metadata),
        _ => anyhow::bail!("Bridge status returned another control result"),
    }
}

fn expected(store: &Store, bytes: &[u8]) -> Result<OwnStreamMetadata> {
    let metadata = OwnStreamMetadata::parse(bytes)?;
    ensure!(
        metadata.scope() == store.descriptor().scope() && metadata.requester() == store.requester(),
        "expected Bridge metadata belongs to another requester or authority epoch"
    );
    ensure!(
        metadata.state().is_some(),
        "Bridge has no admitted requester stream"
    );
    Ok(metadata)
}

fn prepare(store: &mut Store, signer: &SigningKey, bytes: &[u8]) -> Result<PreparedRequest> {
    store.require_requester(signer.verifying_key().to_bytes())?;
    let metadata = expected(store, bytes)?;
    if let Some(pending) = store.resume_fence()? {
        ensure!(
            pending.expected_metadata() == Some(bytes),
            "pending Bridge fence requires its exact original expected metadata"
        );
        return Ok(pending);
    }
    let state = metadata.state().expect("checked admitted stream");
    let scope = store.descriptor().scope();
    let signed = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(57),
            V::Uint(1),
            b(&scope.network),
            b(&scope.incarnation),
            b(&store.requester()),
            b(&random()?),
            V::Uint(scope.epoch),
            V::Uint(store.prefix().height()),
            V::Uint(state.generation),
            b(&state.generation_id),
            b(&wire::digest(bytes)),
        ]))?,
        signer,
    )?;
    store.prepare_fence(&signed, bytes)
}

fn completed(expected: &OwnStreamMetadata, current: &OwnStreamMetadata) -> bool {
    let Some(before) = expected.state() else {
        return false;
    };
    let Some(after) = current.state() else {
        return false;
    };
    expected.scope() == current.scope()
        && expected.requester() == current.requester()
        && before.generation.checked_add(1) == Some(after.generation)
        && after.last_fence.as_ref().is_some_and(|last| {
            last.expected_metadata_digest == wire::digest(expected.canonical())
                && last.previous_generation == before.generation
                && last.previous_generation_id == before.generation_id
                && last.previous_retired_through == before.retired_through
                && last.previous_completion == before.completion
        })
}

fn cache_authenticated(
    references: &[VersionRef],
    retained: &[VersionRef],
    historical: &[VersionRef],
) -> Result<()> {
    ensure!(
        references
            .iter()
            .all(|r| retained.contains(r) || historical.contains(r)),
        "Bridge cache lacks retained current or original-Permit authentication; preserve its exact journals"
    );
    Ok(())
}

pub fn run(config: &Config, guard: &Guard, expected_bytes: Option<&[u8]>) -> Result<Vec<u8>> {
    ensure!(
        guard.role == 7
            && guard
                .manifest
                .permits_definition(&config.profile.manifest)
                .is_ok(),
        "Bridge requester recovery requires its own consented role"
    );
    guard.check()?;
    let mut store = Store::open(
        Path::new("/State/Requester"),
        guard.bootstrap.descriptor().clone(),
    )?;
    store.require_requester(config.profile.service)?;
    let mut session = Session::new()?;
    let Some(bytes) = expected_bytes else {
        return Ok(status(&mut store, &mut session, config, guard)?
            .canonical()
            .to_vec());
    };
    let comparison = expected(&store, bytes)?;
    // The exact original Permit preserves historical cache authentication across fencing. No cache is rewritten.
    let disk = disk::Disk::open_bridge(
        Path::new("/State/BridgeState.bin"),
        &config.profile,
        guard.health()?.observe()?.wall_ms,
    )?;
    let (state, records) = disk.context();
    let scope = store.descriptor().scope();
    let mut references = crate::authority_governance::Governance::record_versions(
        scope.network,
        scope.incarnation,
        records,
    )?;
    references.extend(state.records.values().map(|r| r.reference.clone()));
    if store.resume_fence()?.is_none() {
        let current = status(&mut store, &mut session, config, guard)?;
        if completed(&comparison, &current) {
            cache_authenticated(
                &references,
                store.generations(),
                &store.historical_cache_references()?,
            )?;
            return Ok(current.canonical().to_vec());
        }
        ensure!(
            current.canonical() == bytes,
            "Bridge stream metadata changed; inspect a new requester-status before explicitly fencing"
        );
    }
    cache_authenticated(
        &references,
        store.generations(),
        &store.historical_cache_references()?,
    )?;
    let pending = prepare(&mut store, &config.key, bytes)?;
    let response = control(
        &mut store,
        &mut session,
        config,
        guard,
        pending.signed(),
        pending.expected_metadata(),
    )?;
    guard.check()?;
    match response {
        StreamResponse::Fence { metadata, .. } => Ok(metadata.canonical().to_vec()),
        _ => anyhow::bail!("Bridge fence returned another control result"),
    }
}

#[cfg(test)]
#[path = "AuthorityBridgeRecoveryTests.rs"]
mod tests;
