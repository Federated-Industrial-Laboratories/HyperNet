// SPDX-License-Identifier: MIT
// Exact certified content effects use the activated recipient stream and durable immutable store.
use crate::{
    authority_challenge::{self, Session},
    authority_content_disk as disk,
    authority_domains::page::{self, MediaReceipt as Receipt, MediaRequest as Request, content},
    authority_files as files, authority_local_transport as transport,
    authority_page_service::Config,
    authority_proof::{Challenge, Disposition, Restrictions, SignedRequest},
    authority_recipient::Store,
    runtime_service_activate::Active,
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use sha2::Digest as _;
use std::{
    os::unix::{
        fs::{FileExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::Duration,
};
#[path = "AuthorityContentEffect.rs"]
mod effect;
use effect::execute;
fn listener() -> Result<UnixListener> {
    let directory = files::private_directory(Path::new("/State/Control"))?;
    let path = Path::new("/State/Control/Control.sock");
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0,
                "content control path is not an owned private socket"
            );
            match UnixStream::connect(path) {
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    std::fs::remove_file(path)?
                }
                _ => anyhow::bail!("content control socket is already active"),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    directory.sync_all()?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn handle(
    config: &Config,
    guard: &Guard,
    store: &mut Store,
    disk: &mut disk::Disk,
    bytes: &[u8],
) -> Result<(Vec<u8>, u64)> {
    guard.check()?;
    let v = wire::decode(bytes)?;
    let f = v.array(6)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "ContentExchange",
        "invalid local content exchange"
    );
    let request = Request::parse(f[3].bytes()?)?;
    ensure!(
        request.is_content(),
        "content exchange requires a content action"
    );
    let payload = f[4].bytes()?;
    ensure!(payload.len() <= 32768, "content chunk exceeds its bound");
    match request.command() {
        page::Command::Content(content::Command::Authorise {
            effect: content::Effect::Upload | content::Effect::Repair,
            bytes,
            digest,
            ..
        }) => {
            ensure!(
                payload.len() as u64 == *bytes
                    && *digest == Some(sha2::Sha256::digest(payload).into()),
                "content payload differs from its signed extent or digest"
            );
        }
        _ => ensure!(payload.is_empty(), "this content effect has no payload"),
    }
    let reconcile = f[5].boolean()?;
    let mut session = Session::new()?;
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "content nonce generation failed");
    let issued = guard.health()?;
    let now = issued.observe()?;
    let duration =
        authority_challenge::maximum_duration_ms(&SignedRequest::Intent(request.intent().clone()));
    let challenge = session.issue(request.signed(), &config.key, nonce, duration, issued)?;
    let c = Challenge::from_signed(&challenge)?;
    let deadline = now
        .boot_ms
        .checked_add(duration)
        .context("content deadline overflow")?;
    let ordered = wire::encode(&V::Array(vec![
        V::Uint(22),
        V::Uint(1),
        store.descriptor().scope().value(),
        V::Bytes(request.signed().to_vec()),
        V::Bytes(challenge.clone()),
        V::Uint(c.expires_at_ms),
    ]))?;
    let mut clock = || {
        guard.check()?;
        guard.health()
    };
    let (reply, evidence) = transport::exchange(
        store.descriptor(),
        &ordered,
        deadline,
        Path::new("/Authority/Control.sock"),
        store.prefix(),
        store.tree_head(),
        &mut clock,
    )?;
    let result = request.verify(
        &guard.bootstrap,
        store.descriptor(),
        &challenge,
        &ordered,
        &reply.result,
        &reply.certificate,
        &evidence.nodes,
        store.generations(),
    )?;
    let result = evidence.attach_recipient(store, result)?;
    let receipt_result = request.verify(
        &guard.bootstrap,
        store.descriptor(),
        &challenge,
        &ordered,
        &reply.result,
        &reply.certificate,
        &evidence.nodes,
        store.generations(),
    )?;
    if result.disposition() != Disposition::Permit {
        let receipt = Receipt::refusal(&request, &challenge, &ordered, &receipt_result)?;
        store.observe(result)?;
        return Ok((receipt.canonical().to_vec(), deadline));
    }
    let (profile, placement, revision) = request.result_content(&result.result)?;
    ensure!(
        profile.envelope == config.profile.envelope,
        "content quorum selected another local storage profile"
    );
    let prior = store.claim_state(request.intent().digest);
    ensure!(
        prior.is_none() || reconcile,
        "content effect may already exist; retry with explicit reconciliation"
    );
    let restrictions = |r: &Restrictions| {
        guard.check()?;
        ensure!(*r == Restrictions::default(), "content restrictions differ");
        Ok(())
    };
    let permit = store.accept(result, &mut session, clock()?, 0)?;
    let response = if prior.is_some() {
        permit.reconcile(
            store,
            &mut session,
            &mut clock,
            1,
            restrictions,
            |_, _, _| {
                execute(
                    disk,
                    &request,
                    &placement,
                    revision.as_ref(),
                    &config.profile,
                    payload,
                    &config.key,
                    guard.health()?.observe()?.wall_ms,
                )
            },
        )?
    } else {
        permit.perform(store, &mut session, &mut clock, 1, restrictions, |_, _| {
            execute(
                disk,
                &request,
                &placement,
                revision.as_ref(),
                &config.profile,
                payload,
                &config.key,
                guard.health()?.observe()?.wall_ms,
            )
        })?
    };
    guard.check()?;
    let receipt = Receipt::create(
        &request,
        &challenge,
        &ordered,
        &receipt_result,
        &response,
        &config.key,
        clock()?.observe()?.wall_ms,
    )?;
    receipt.verify(&guard.bootstrap, store.descriptor())?;
    Ok((receipt.canonical().to_vec(), deadline))
}
pub async fn run(config: Config, guard: &Guard, active: &mut Active) -> Result<()> {
    active.check(guard)?;
    ensure!(
        guard.role == 1 && config.profile.manifest == guard.manifest,
        "content service differs from activated role"
    );
    let mut disk = disk::Disk::open(
        Path::new("/State/Content"),
        &disk::Limits::from_profile(&config.profile)?,
        guard.health()?.observe()?.wall_ms,
    )?;
    let listener = listener()?;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {_ = tokio::signal::ctrl_c()=>break,_ = terminate.recv()=>break,_ = tick.tick()=>{active.check(guard)?;match listener.accept(){Ok((mut stream,_))=>{let deadline=authority_challenge::boot_time_ms()?.checked_add(1000).context("content request deadline overflow")?;let result=(||->Result<()>{let bytes=transport::receive_frame(&mut stream,deadline,wire::MAXIMUM)?;active.check(guard)?;let(reply,deadline)=handle(&config,guard,active.recipient_mut(),&mut disk,&bytes)?;active.check(guard)?;transport::send_frame(&mut stream,&reply,deadline,page::MEDIA_RECEIPT_LIMIT)?;Ok(())})();if let Err(error)=result{eprintln!("Local content request refused: {error}");}},Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>{},Err(e)=>return Err(e.into())}}}
    }
    active.check(guard)?;
    Ok(())
}

/// The installed local operator forwards only a bounded signed participant packet.
pub fn exchange_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let value = wire::decode(packet)?;
    let fields = value.array(6)?;
    ensure!(
        fields[0].uint()? == 200
            && fields[1].uint()? == 1
            && fields[2].text()? == "ContentExchange",
        "invalid content exchange packet"
    );
    let request = Request::parse(fields[3].bytes()?)?;
    ensure!(
        request.is_content(),
        "content exchange requires a content action"
    );
    let duration =
        authority_challenge::maximum_duration_ms(&SignedRequest::Intent(request.intent().clone()));
    ensure!(
        fields[4].bytes()?.len() <= 32768,
        "content chunk exceeds bound"
    );
    fields[5].boolean()?;
    transport::LocalControl::open(Path::new("/State/Control/Control.sock"))?.exchange_limit(
        packet,
        authority_challenge::boot_time_ms()?
            .checked_add(
                duration
                    .checked_add(authority_challenge::MAXIMUM_DURATION_MS)
                    .context("content exchange duration overflow")?,
            )
            .context("content exchange deadline overflow")?,
        page::MEDIA_RECEIPT_LIMIT,
    )
}
