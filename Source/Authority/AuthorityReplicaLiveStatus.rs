// SPDX-License-Identifier: MIT
//! Bounded local diagnostics without opening the active signer journal.
use crate::{
    authority_files as files,
    consensus::records::{Key, Scope, record},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value as Json, json};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixStream,
    },
    path::Path,
};

// The fixed nine-field reply is below 256 bytes even with maximum-width integers.
const MAX_RESPONSE: usize = 4096;
const TIMEOUT_MS: u64 = 5000;

pub(super) fn query(directory: &Path, minimum_generation: u64) -> Result<Json> {
    ensure!(
        minimum_generation > 0,
        "An independently retained minimum generation is required"
    );
    let deployment = super::deployment(directory)?;
    let control = LocalControl::open(
        deployment
            .runtime
            .control_socket
            .parent()
            .context("Control socket parent is absent")?,
    )?;
    let request = wire::encode(&V::Array(vec![
        V::Uint(41),
        V::Uint(1),
        deployment.configuration.scope.value(),
        V::Uint(5),
        V::Bytes(wire::encode(&V::Array(vec![]))?),
    ]))?;
    let deadline = boot_ms()?
        .checked_add(TIMEOUT_MS)
        .context("Local status deadline overflow")?;
    let response = control.exchange(&request, deadline)?;
    let mut status = parse(
        &response,
        &deployment.configuration.scope,
        &deployment.key.verifying_key().to_bytes(),
        minimum_generation.max(deployment.record.minimum_generation),
    )?;
    // A concurrent offline configuration change must not relabel an earlier reply.
    let current = super::deployment(directory)?;
    ensure!(
        current.record.bootstrap_digest == deployment.record.bootstrap_digest
            && current.record.signer == deployment.record.signer
            && current.record.config_digest == deployment.record.config_digest
            && current.record.config_generation == deployment.record.config_generation
            && current.record.minimum_generation == deployment.record.minimum_generation
            && current.configuration.scope == deployment.configuration.scope,
        "Replica configuration changed during live status"
    );
    status["configDigest"] = json!(deployment.record.config_digest);
    status["configGeneration"] = json!(deployment.record.config_generation);
    Ok(status)
}

fn parse(bytes: &[u8], scope: &Scope, signer: &Key, minimum_generation: u64) -> Result<Json> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESPONSE,
        "Local status reply exceeds its bound"
    );
    let value = wire::decode(bytes)?;
    let a = record(&value, 59, 9)?;
    ensure!(Scope::parse(&a[2])? == *scope, "Local status scope differs");
    ensure!(
        a[3].fixed::<32>()? == *signer,
        "Local status signer differs"
    );
    let generation = a[4].uint()?;
    ensure!(
        generation >= minimum_generation && generation > 0,
        "Local status signer generation is below its retained floor"
    );
    let committed = a[6].uint()?;
    let applied = a[7].uint()?;
    ensure!(
        applied <= committed,
        "Local applied height exceeds committed height"
    );
    Ok(json!({
        "status": "Live",
        "network": hex::encode(scope.network),
        "incarnation": hex::encode(scope.incarnation),
        "authorityConfiguration": hex::encode(scope.configuration),
        "epoch": scope.epoch,
        "signer": hex::encode(signer),
        "generation": generation,
        "view": a[5].uint()?,
        "committedHeight": committed,
        "appliedHeight": applied,
        "clockReady": a[8].boolean()?,
        "quorum": "NotProbed",
    }))
}

fn boot_ms() -> Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr()) } == 0,
        "Local status clock unavailable"
    );
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec)?;
    let nanos = u64::try_from(time.tv_nsec)?;
    ensure!(nanos < 1_000_000_000, "Invalid local status clock");
    seconds
        .checked_mul(1000)
        .and_then(|v| v.checked_add(nanos / 1_000_000))
        .context("Local status clock overflow")
}
fn remaining(deadline: u64) -> Result<u64> {
    let now = boot_ms()?;
    ensure!(now < deadline, "Local status deadline expired");
    Ok(deadline - now)
}

struct LocalControl {
    directory: File,
    name: CString,
}
impl LocalControl {
    fn open(directory: &Path) -> Result<Self> {
        let this = Self {
            directory: files::private_directory(directory)?,
            name: CString::new("Control.sock")?,
        };
        this.socket_stat()?;
        Ok(this)
    }
    fn socket_stat(&self) -> Result<libc::stat> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        ensure!(
            unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0,
            "Cannot inspect local status socket"
        );
        let stat = unsafe { stat.assume_init() };
        ensure!(
            stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
                && stat.st_uid == unsafe { libc::geteuid() }
                && stat.st_mode & 0o077 == 0,
            "Local status endpoint must be an owned private Unix socket"
        );
        Ok(stat)
    }
    fn connect(&self, deadline: u64) -> Result<UnixStream> {
        remaining(deadline)?;
        let before = self.socket_stat()?;
        let descriptor = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        ensure!(descriptor >= 0, "Cannot create local status socket");
        let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
        let path = format!("/proc/self/fd/{}/Control.sock", self.directory.as_raw_fd());
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        ensure!(
            path.len() < address.sun_path.len(),
            "Local status socket path exceeds its bound"
        );
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
            *slot = byte as libc::c_char;
        }
        if unsafe {
            libc::connect(
                descriptor,
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            ensure!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
                ),
                "Local status connection failed: {error}"
            );
            ready(&stream, libc::POLLOUT, deadline)?;
            if let Some(error) = stream.take_error()? {
                return Err(error.into());
            }
        }
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    descriptor,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    credentials.as_mut_ptr().cast(),
                    &mut length,
                )
            } == 0
                && length as usize == std::mem::size_of::<libc::ucred>(),
            "Local status peer credentials unavailable"
        );
        ensure!(
            unsafe { credentials.assume_init() }.uid == unsafe { libc::geteuid() },
            "Local status peer has another owner"
        );
        let after = self.socket_stat()?;
        ensure!(
            before.st_dev == after.st_dev && before.st_ino == after.st_ino,
            "Local status socket changed during connect"
        );
        Ok(stream)
    }
    fn exchange(&self, request: &[u8], deadline: u64) -> Result<Vec<u8>> {
        ensure!(
            !request.is_empty() && request.len() <= MAX_RESPONSE,
            "Local status request exceeds its bound"
        );
        let mut stream = self.connect(deadline)?;
        write_all(&mut stream, &(request.len() as u32).to_be_bytes(), deadline)?;
        write_all(&mut stream, request, deadline)?;
        let mut length = [0; 4];
        read_all(&mut stream, &mut length, deadline)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            (1..=MAX_RESPONSE).contains(&length),
            "Local status response exceeds its bound"
        );
        let mut response = vec![0; length];
        read_all(&mut stream, &mut response, deadline)?;
        Ok(response)
    }
}
fn ready(stream: &UnixStream, event: libc::c_short, deadline: u64) -> Result<()> {
    loop {
        let remaining = remaining(deadline)?;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: event,
            revents: 0,
        };
        let status =
            unsafe { libc::poll(&mut descriptor, 1, remaining.min(i32::MAX as u64) as i32) };
        if status < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            status > 0
                && descriptor.revents & event != 0
                && descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "Local status readiness failed or timed out"
        );
        return Ok(());
    }
}
fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.write(bytes) {
            Ok(0) => bail!("Local status write closed"),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ready(stream, libc::POLLOUT, deadline)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn read_all(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.read(bytes) {
            Ok(0) => bail!("Local status read closed"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ready(stream, libc::POLLIN, deadline)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Authority/AuthorityReplicaLiveStatusUnitTests.rs"]
mod tests;
