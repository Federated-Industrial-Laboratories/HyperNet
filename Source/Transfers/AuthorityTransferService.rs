// SPDX-License-Identifier: MIT
// A confined local transfer store claims each participant-authorized effect before touching ciphertext.
use crate::{
    authority_challenge::{self, Session},
    authority_domains::transfer::{self, Profile, Receipt, Request},
    authority_files as files, authority_local_transport as transport,
    authority_proof::{Challenge, Disposition, Restrictions},
    authority_recipient::Store,
    confinement,
    runtime_service_activate::{self, Active},
    runtime_service_authorization::Guard,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use std::{
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};
#[path = "AuthorityTransferDisk.rs"]
mod disk;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    bootstrap_file: PathBuf,
    manifest_file: PathBuf,
    profile_file: PathBuf,
    identity_file: PathBuf,
    state_file: PathBuf,
    control_socket: PathBuf,
    clock_witness_file: PathBuf,
    listen_socket: PathBuf,
}
pub struct Config {
    pub profile: Profile,
    key: SigningKey,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "transfer store must be PID1 under its dedicated service UID"
        );
        let raw: Configuration = serde_json::from_slice(&files::read(path, 16384, true)?)?;
        for (actual, expected) in [
            (&raw.bootstrap_file, "/Config/Bootstrap.cbor"),
            (&raw.manifest_file, "/Config/Manifest.cbor"),
            (&raw.profile_file, "/Config/TransferProfile.cbor"),
            (&raw.identity_file, "/Config/Service.key"),
            (&raw.state_file, "/State/TransferState.bin"),
            (&raw.control_socket, "/Authority/Control.sock"),
            (&raw.clock_witness_file, "/Clock/ClockHealth.cbor"),
            (&raw.listen_socket, "/State/Control/Control.sock"),
        ] {
            ensure!(
                actual == Path::new(expected),
                "transfer path differs from its confined profile"
            );
        }
        let manifest = crate::runtime_manifest::Manifest::parse(&files::read(
            &raw.manifest_file,
            crate::runtime_manifest::MAXIMUM,
            true,
        )?)?;
        let bootstrap = crate::trust_bootstrap::inspect(
            &files::read(&raw.bootstrap_file, wire::MAXIMUM, true)?,
            true,
        )?;
        ensure!(
            manifest.bootstrap_digest == bootstrap.file_digest()
                && bootstrap.descriptor().scope().network == manifest.network
                && bootstrap.descriptor().scope().incarnation == manifest.incarnation,
            "transfer manifest differs from accepted bootstrap"
        );
        let profile = Profile::parse(
            &files::read(
                &raw.profile_file,
                crate::runtime_manifest::MAXIMUM + 1024,
                true,
            )?,
            manifest.network,
            manifest.incarnation,
        )?;
        let role = manifest
            .roles
            .iter()
            .find(|r| r.role == 4)
            .context("transfer role absent")?;
        ensure!(
            manifest.permits_definition(&profile.manifest).is_ok()
                && profile.endpoint.is_none()
                && role.bind_endpoint_ids.is_empty()
                && role.outbound_endpoint_ids.is_empty(),
            "local transfer profile must have no direct network route"
        );
        let seed = zeroize::Zeroizing::new(files::read(&raw.identity_file, 32, true)?);
        let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            seed.as_slice()
                .try_into()
                .context("transfer service key must be a raw32-byte seed")?,
        );
        let key = SigningKey::from_bytes(&seed);
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "transfer signing identity differs from consent"
        );
        Ok(Self { profile, key })
    }
    pub fn resources(&self, actual: &confinement::Profile) -> Result<()> {
        let role = self
            .profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 4)
            .context("transfer role absent")?;
        let cpu = actual
            .cpu_max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            actual.memory_max <= role.memory_bytes
                && actual.pids_max <= role.pids
                && cpu.len() == 2
                && cpu[0] as u128 * role.cpu_period as u128
                    <= role.cpu_quota as u128 * cpu[1] as u128,
            "transfer cgroup exceeds consent"
        );
        Ok(())
    }
}
pub fn initialise(guard: &Guard) -> Result<()> {
    guard.check()?;
    ensure!(guard.role == 4, "transfer preparation has another role");
    let config = Config::load(Path::new("/Config/ServiceConfig.json"))?;
    ensure!(
        guard
            .manifest
            .permits_definition(&config.profile.manifest)
            .is_ok(),
        "transfer profile differs from local authorization"
    );
    runtime_service_activate::initialise(guard)?;
    let path = Path::new("/State/TransferState.bin");
    if !path.try_exists()? {
        disk::Disk::initialise(path, &config.profile)?;
    }
    disk::Disk::open(path, &config.profile, guard.health()?.observe()?.wall_ms)?;
    guard.check()
}
fn listener() -> Result<UnixListener> {
    let directory = files::private_directory(Path::new("/State/Control"))?;
    let path = Path::new("/State/Control/Control.sock");
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0,
                "transfer control path is not an owned private socket"
            );
            match UnixStream::connect(path) {
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    std::fs::remove_file(path)?
                }
                _ => anyhow::bail!("transfer control socket is already active"),
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
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "TransferExchange",
        "invalid local transfer exchange"
    );
    let request = Request::parse(f[3].bytes()?)?;
    let payload = f[4].bytes()?;
    ensure!(
        payload.len() <= transfer::CHUNK as usize,
        "transfer chunk exceeds its bound"
    );
    match request.command() {
        transfer::Command::Execute {
            effect: transfer::Effect::Put,
            bytes,
            digest,
            ..
        } => {
            ensure!(
                payload.len() as u64 == *bytes && *digest == Some(wire::digest(payload)),
                "transfer payload differs from its signed extent or digest"
            );
        }
        _ => ensure!(payload.is_empty(), "this transfer effect has no payload"),
    }
    let reconcile = f[5].boolean()?;
    let mut session = Session::new()?;
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "transfer nonce generation failed");
    let issued = guard.health()?;
    let now = issued.observe()?;
    let challenge = session.issue(
        request.signed(),
        &config.key,
        nonce,
        authority_challenge::MAXIMUM_DURATION_MS,
        issued,
    )?;
    let c = Challenge::from_signed(&challenge)?;
    let deadline = now
        .boot_ms
        .checked_add(authority_challenge::MAXIMUM_DURATION_MS)
        .context("transfer deadline overflow")?;
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
    let (profile, agreement) = request.result_agreement(&result.result)?;
    ensure!(
        profile.envelope == config.profile.envelope,
        "transfer quorum selected another local storage profile"
    );
    let prior = store.claim_state(request.intent().digest);
    ensure!(
        prior.is_none() || reconcile,
        "transfer effect may already exist; retry with explicit reconciliation"
    );
    let restrictions = |r: &Restrictions| {
        guard.check()?;
        ensure!(
            *r == Restrictions::default(),
            "transfer restrictions differ"
        );
        Ok(())
    };
    let permit = store.accept_with_clock(result, &mut session, &mut clock, 0)?;
    let response = if prior.is_some() {
        permit.reconcile(
            store,
            &mut session,
            &mut clock,
            1,
            restrictions,
            |_, _, _| {
                disk.execute(
                    &agreement,
                    request.command(),
                    payload,
                    guard.health()?.observe()?.wall_ms,
                    true,
                )
            },
        )?
    } else {
        permit.perform(store, &mut session, &mut clock, 1, restrictions, |_, _| {
            disk.execute(
                &agreement,
                request.command(),
                payload,
                guard.health()?.observe()?.wall_ms,
                false,
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
        guard.role == 4
            && guard
                .manifest
                .permits_definition(&config.profile.manifest)
                .is_ok(),
        "transfer service differs from activated role"
    );
    let mut disk = disk::Disk::open(
        Path::new("/State/TransferState.bin"),
        &config.profile,
        guard.health()?.observe()?.wall_ms,
    )?;
    let listener = listener()?;
    let mut clock = crate::runtime_service_activate::clock::Gate::default();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            _ = tick.tick() => {
                if !clock.accepting(active, guard, &listener)? { continue; }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let deadline = authority_challenge::boot_time_ms()?
                            .checked_add(1000).context("transfer request deadline overflow")?;
                        let result = (|| -> Result<()> {
                            let bytes = transport::receive_frame(&mut stream, deadline, wire::MAXIMUM)?;
                            active.check(guard)?;
                            let (reply, deadline) = handle(&config, guard, active.recipient_mut(), &mut disk, &bytes)?;
                            active.check(guard)?;
                            transport::send_frame(&mut stream, &reply, deadline, transfer::RECEIPT_LIMIT)?;
                            Ok(())
                        })();
                        if let Err(error) = result { eprintln!("Local transfer request refused: {error}"); }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    active.check_local(guard)?;
    Ok(())
}

/// The installed local operator forwards only a bounded signed participant packet.
pub fn exchange_packet(packet: &[u8]) -> Result<Vec<u8>> {
    let value = wire::decode(packet)?;
    let fields = value.array(6)?;
    ensure!(
        fields[0].uint()? == 200
            && fields[1].uint()? == 1
            && fields[2].text()? == "TransferExchange",
        "invalid transfer exchange packet"
    );
    Request::parse(fields[3].bytes()?)?;
    ensure!(
        fields[4].bytes()?.len() <= transfer::CHUNK as usize,
        "transfer chunk exceeds bound"
    );
    fields[5].boolean()?;
    transport::LocalControl::open(Path::new("/State/Control/Control.sock"))?.exchange_limit(
        packet,
        authority_challenge::boot_time_ms()?
            .checked_add(10_000)
            .context("transfer exchange deadline overflow")?,
        transfer::RECEIPT_LIMIT,
    )
}
