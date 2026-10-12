// SPDX-License-Identifier: MIT
// A dedicated recipient retains activation claims before a confined service can start.
use crate::{
    authority_challenge::{MAXIMUM_DURATION_MS, Session},
    authority_files as files, authority_floor, authority_local_transport as transport,
    authority_proof::{Challenge, Disposition, Restrictions},
    authority_recipient::{ClaimState, Store},
    authority_runtime_activation::{Receipt, Request},
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use std::{ffi::OsStr, path::Path};

const RECIPIENT: &str = "/State/Recipient";
const MARKER: &str = "Activation.cbor";
pub struct Active {
    store: Store,
    marker: Vec<u8>,
}
fn signer(guard: &Guard) -> Result<SigningKey> {
    let bytes = zeroize::Zeroizing::new(files::read(Path::new("/Config/Service.key"), 32, true)?);
    let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .context("service identity requires a 32-byte seed")?,
    );
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        key.verifying_key().to_bytes() == guard.key(),
        "service identity differs from exact local consent"
    );
    Ok(key)
}
/// This explicit preparation command never runs as part of ordinary startup.
pub fn initialise(guard: &Guard) -> Result<()> {
    guard.check()?;
    let _ = signer(guard)?;
    let descriptor = guard.bootstrap.descriptor().clone();
    let requester = Path::new("/State/Requester");
    let recipient = Path::new(RECIPIENT);
    // An interrupted preparation may retain either complete journal; opening validates it.
    if requester.join("AuthorityFloor.json").try_exists()?
        || requester.join("AuthorityPending.json").try_exists()?
    {
        authority_floor::Store::open(requester, descriptor.clone())?
            .require_requester(guard.key())?;
    } else {
        authority_floor::Store::initialise(
            requester,
            descriptor.clone(),
            guard.key(),
            guard.health()?,
        )?;
    }
    if recipient.join("RecipientFloor.json").try_exists()?
        || recipient.join("RecipientPending.json").try_exists()?
    {
        Store::open(recipient, descriptor, guard.key())?;
    } else {
        Store::initialise(recipient, descriptor, guard.key(), guard.health()?)?;
    }
    guard.check()
}
impl Active {
    pub(crate) fn recipient_mut(&mut self) -> &mut Store {
        &mut self.store
    }
    pub fn check(&self, guard: &Guard) -> Result<()> {
        guard.check()?;
        ensure!(
            !self.store.epoch_sealed(),
            "service authority epoch is sealed"
        );
        ensure!(
            files::read_at(
                self.store.profile_directory(),
                OsStr::new(MARKER),
                4096,
                true
            )? == self.marker,
            "service activation identity changed"
        );
        Ok(())
    }
}
fn record(store: &Store, marker: &[u8], prior: Option<ClaimState>) -> Result<()> {
    let directory = store.profile_directory();
    if prior == Some(ClaimState::Complete) {
        ensure!(
            files::read_at(directory, OsStr::new(MARKER), 4096, true)? == marker,
            "completed activation marker is absent or replaced"
        );
    } else {
        // Replacing this exact marker is the entire idempotent effect. The recipient lock excludes another service process.
        files::atomic_at(directory, OsStr::new(MARKER), marker, true)?;
    }
    Ok(())
}
pub fn activate(guard: &Guard) -> Result<Active> {
    guard.check()?;
    let key = signer(guard)?;
    let requester_descriptor = {
        let requester = authority_floor::Store::open(
            Path::new("/State/Requester"),
            guard.bootstrap.descriptor().clone(),
        )?;
        requester.require_requester(guard.key())?;
        ensure!(
            !requester.epoch_sealed(),
            "Service requester authority epoch is sealed"
        );
        requester.descriptor().canonical().to_vec()
    };
    let mut store = Store::open(
        Path::new(RECIPIENT),
        guard.bootstrap.descriptor().clone(),
        guard.key(),
    )?;
    ensure!(
        !store.epoch_sealed() && store.descriptor().canonical() == requester_descriptor,
        "Service requester and recipient must finish the same epoch activation before startup"
    );
    let request = Request::parse(&crate::runtime_authorization::public_read(
        Path::new("/Authorization/ActivationRequest.cbor"),
        wire::MAXIMUM,
    )?)?;
    request.check_manifest(
        &guard.bootstrap,
        store.descriptor(),
        &guard.manifest,
        guard.role,
        guard.generation,
    )?;
    let mut session = Session::new()?;
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "activation nonce generation failed");
    let health = guard.health()?;
    let now = health.observe()?;
    let challenge = session.issue(request.signed(), &key, nonce, MAXIMUM_DURATION_MS, health)?;
    let parsed = Challenge::from_signed(&challenge)?;
    let ordered = wire::encode(&V::Array(vec![
        V::Uint(22),
        V::Uint(1),
        store.descriptor().scope().value(),
        V::Bytes(request.signed().to_vec()),
        V::Bytes(challenge.clone()),
        V::Uint(parsed.expires_at_ms),
    ]))?;
    let mut clock = || {
        guard.check()?;
        guard.health()
    };
    let (reply, evidence) = transport::exchange(
        store.descriptor(),
        &ordered,
        now.boot_ms
            .checked_add(MAXIMUM_DURATION_MS)
            .context("activation deadline overflow")?,
        Path::new("/Authority/Control.sock"),
        store.prefix(),
        store.tree_head(),
        &mut clock,
    )?;
    let verify = || {
        request.verify(
            &guard.bootstrap,
            store.descriptor(),
            &challenge,
            &ordered,
            &reply.result,
            &reply.certificate,
            &evidence.nodes,
        )
    };
    let result = evidence.attach_recipient(&store, verify()?)?;
    if result.disposition() != Disposition::Permit {
        let code = result.code();
        store.observe(result)?;
        anyhow::bail!("service activation refused with code {code}");
    }
    // Retain receipt inputs independently; producing a receipt follows the durable effect and final checks.
    let receipt_result = verify()?;
    let marker = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("RuntimeActivation".into()),
        V::Bytes(request.intent().digest.to_vec()),
        V::Bytes(result.executed.result.to_vec()),
        V::Uint(guard.generation),
        V::Bytes(wire::digest(&guard.manifest.encode()?).to_vec()),
    ]))?;
    let prior = store.claim_state(request.intent().digest);
    let restrictions = |r: &Restrictions| {
        guard.check()?;
        ensure!(
            *r == Restrictions {
                consent: Some(guard.consent()),
                placement: None,
                route: None
            },
            "service activation restrictions differ from exact local consent"
        );
        Ok(())
    };
    let permit = store.accept(result, &mut session, clock()?, 0)?;
    if let Some(prior) = prior {
        permit.reconcile(
            &mut store,
            &mut session,
            &mut clock,
            1,
            restrictions,
            |_, s, state| {
                ensure!(state == prior, "activation claim changed");
                record(s, &marker, Some(state))
            },
        )?;
    } else {
        permit.perform(
            &mut store,
            &mut session,
            &mut clock,
            1,
            restrictions,
            |_, s| record(s, &marker, None),
        )?;
    }
    let active = Active { store, marker };
    active.check(guard)?;
    let receipt = Receipt::create(
        &request,
        &challenge,
        &ordered,
        &receipt_result,
        &key,
        clock()?.observe()?.wall_ms,
    )?;
    receipt.verify(&guard.bootstrap, active.store.descriptor())?;
    // This report acknowledges an activation claim. It does not report service readiness or renew permission.
    files::atomic_at(
        active.store.profile_directory(),
        OsStr::new("ActivationReceipt.cbor"),
        receipt.canonical(),
        true,
    )?;
    active.check(guard)?;
    Ok(active)
}
