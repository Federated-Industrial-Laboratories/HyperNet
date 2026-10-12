// SPDX-License-Identifier: MIT
// Private authority transport preserves socket ownership, peer identity and one monotonic deadline.
use crate::{authority_challenge::boot_time_ms, authority_files as files, trust_wire as wire};
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
};
pub fn remaining(deadline: u64) -> Result<u64> {
    let now = boot_time_ms()?;
    ensure!(now < deadline, "original inspection deadline expired");
    Ok(deadline - now)
}
pub struct LocalControl {
    directory: File,
    name: CString,
}
impl LocalControl {
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .context("private control directory required")?;
        let name = path
            .file_name()
            .context("control socket filename required")?;
        let directory = files::private_directory(parent)?;
        let name = CString::new(name.as_bytes())?;
        let this = Self { directory, name };
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
            "cannot inspect private control socket"
        );
        let stat = unsafe { stat.assume_init() };
        ensure!(
            stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
                && stat.st_uid == unsafe { libc::geteuid() }
                && stat.st_mode & 0o077 == 0,
            "control endpoint must be an owned private Unix socket"
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
        ensure!(descriptor >= 0, "cannot create local control socket");
        let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
        let path = Path::new("/proc/self/fd")
            .join(self.directory.as_raw_fd().to_string())
            .join(OsStr::from_bytes(self.name.as_bytes()));
        let bytes = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        ensure!(
            bytes.len() < address.sun_path.len(),
            "private control path exceeds Unix socket bound"
        );
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
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
                "private control connection failed: {error}"
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
            "private control credentials unavailable"
        );
        ensure!(
            unsafe { credentials.assume_init() }.uid == unsafe { libc::geteuid() },
            "private control peer has another owner"
        );
        let after = self.socket_stat()?;
        ensure!(
            before.st_dev == after.st_dev && before.st_ino == after.st_ino,
            "private control socket changed during connect"
        );
        Ok(stream)
    }
    pub fn exchange(&self, request: &[u8], deadline: u64) -> Result<Vec<u8>> {
        self.exchange_limit(request, deadline, wire::MAXIMUM)
    }
    pub(crate) fn exchange_limit(
        &self,
        request: &[u8],
        deadline: u64,
        maximum_response: usize,
    ) -> Result<Vec<u8>> {
        ensure!(
            (1..=4 * wire::MAXIMUM).contains(&maximum_response),
            "invalid private reply bound"
        );
        ensure!(
            !request.is_empty() && request.len() <= wire::MAXIMUM,
            "local control request exceeds bound"
        );
        let mut stream = self.connect(deadline)?;
        write_all(&mut stream, &(request.len() as u32).to_be_bytes(), deadline)?;
        write_all(&mut stream, request, deadline)?;
        let mut length = [0; 4];
        read_all(&mut stream, &mut length, deadline)?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            (1..=maximum_response).contains(&length),
            "local control response exceeds bound"
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
            "private control readiness failed or timed out"
        );
        return Ok(());
    }
}
fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: u64) -> Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.write(bytes) {
            Ok(0) => bail!("private control write closed"),
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
            Ok(0) => bail!("private control read closed"),
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

use crate::{
    authority_challenge::ClockHealth,
    authority_history::TreeHead,
    authority_proof::{self as proof, Prefix, TrustDescriptor},
    trust_wire::Value as V,
};
use std::time::Duration;
fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let fields = value.array(arity)?;
    ensure!(
        fields[0].uint()? == kind && fields[1].uint()? == 1,
        "unexpected private authority record"
    );
    Ok(fields)
}
pub struct CertifiedReply {
    pub node: Vec<u8>,
    pub certificate: Vec<u8>,
    pub result: Vec<u8>,
}

pub struct HistoryEvidence {
    pub nodes: Vec<Vec<u8>>,
    history: Option<(Vec<u8>, Vec<u8>)>,
}
impl HistoryEvidence {
    pub fn proofs(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        self.history
            .as_ref()
            .map_or((None, None), |(c, h)| (Some(c.clone()), Some(h.clone())))
    }
    pub fn direct(nodes: Vec<Vec<u8>>) -> Self {
        Self {
            nodes,
            history: None,
        }
    }
    pub fn attach(
        &self,
        store: &crate::authority_floor::Store,
        result: proof::VerifiedResult,
    ) -> Result<proof::VerifiedResult> {
        match &self.history {
            Some((checkpoint, history)) => store.attach_history(result, checkpoint, history),
            None => Ok(result),
        }
    }
    pub fn attach_recipient(
        &self,
        store: &crate::authority_recipient::Store,
        result: proof::VerifiedResult,
    ) -> Result<proof::VerifiedResult> {
        match &self.history {
            Some((checkpoint, history)) => store.attach_history(result, checkpoint, history),
            None => Ok(result),
        }
    }
    fn control(prefix: &Prefix, operation: u64, payload: &[u8]) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            prefix.scope().value(),
            V::Uint(operation),
            b(payload),
        ]))
    }
    pub fn fetch(
        control: &LocalControl,
        prefix: &Prefix,
        head: Option<&TreeHead>,
        target: &[u8],
        deadline: u64,
    ) -> Result<Self> {
        let node = proof::Node::parse(target)?;
        ensure!(
            node.scope() == prefix.scope() && node.height() >= prefix.height(),
            "catch-up target differs from retained authority"
        );
        let gap = node.height() - prefix.height();
        if gap <= 1 {
            return Ok(Self::direct(vec![target.to_vec()]));
        }
        if gap <= 128 {
            let query = wire::encode(&a(vec![
                V::Uint(prefix.height()),
                b(prefix.node()),
                b(node.digest()),
            ]))?;
            let bytes = control.exchange(&Self::control(prefix, 3, &query)?, deadline)?;
            let value = wire::decode(&bytes)?;
            if value.list(10)?.first() == Some(&V::Uint(43)) {
                let f = record(&value, 43, 4)?;
                ensure!(
                    proof::Scope::parse(&f[2])? == *prefix.scope(),
                    "ancestry scope differs"
                );
                let nodes = f[3]
                    .list(128)?
                    .iter()
                    .map(|v| Ok(v.bytes()?.to_vec()))
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    nodes.len() as u64 == gap && nodes.last().is_some_and(|v| v == target),
                    "short ancestry omits or substitutes the target"
                );
                return Ok(Self::direct(nodes));
            }
            // Only the finite unavailable reply permits a checkpoint query. Malformed proof data fails.
            let f = record(&value, 42, 10)?;
            ensure!(
                proof::Scope::parse(&f[2])? == *prefix.scope()
                    && f[3].uint()? == 2
                    && f[4].uint()? == 1,
                "short ancestry failed without an unavailable response"
            );
            for value in &f[5..9] {
                value.null()?;
            }
            f[9].array(0)?;
        }
        let query = wire::encode(&a(vec![
            V::Uint(prefix.height()),
            b(prefix.node()),
            b(node.digest()),
            V::Uint(head.map_or(0, |h| h.size())),
            head.map_or(V::Null, |h| b(h.root())),
        ]))?;
        let bytes = control.exchange(&Self::control(prefix, 4, &query)?, deadline)?;
        Self::checkpoint_reply(prefix, target, &bytes)
    }
    pub fn checkpoint_reply(prefix: &Prefix, target: &[u8], bytes: &[u8]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = record(&value, 54, 7)?;
        ensure!(
            proof::Scope::parse(&f[2])? == *prefix.scope()
                && f[3].fixed::<32>()? == wire::digest(target),
            "checkpoint response differs from requested target"
        );
        let checkpoint = f[4].bytes()?.to_vec();
        let history = f[5].bytes()?.to_vec();
        let package = wire::decode(&checkpoint)?;
        let package = record(&package, 46, 4)?;
        let anchor = proof::Node::parse(package[3].bytes()?)?;
        let target_node = proof::Node::parse(target)?;
        ensure!(
            anchor.scope() == prefix.scope()
                && target_node.scope() == prefix.scope()
                && anchor.height() <= target_node.height(),
            "checkpoint suffix scope or height differs"
        );
        let mut nodes = f[6]
            .list(128)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            nodes.len() as u64 == target_node.height() - anchor.height(),
            "checkpoint suffix must exclude anchor and include exact target"
        );
        if nodes.is_empty() {
            ensure!(
                package[3].bytes()? == target,
                "empty checkpoint suffix has another anchor"
            );
            nodes.push(target.to_vec());
        } else {
            ensure!(
                nodes.last().is_some_and(|v| v == target),
                "checkpoint suffix does not end at requested target"
            );
        }
        Ok(Self {
            nodes,
            history: Some((checkpoint, history)),
        })
    }
}

pub fn exchange(
    descriptor: &TrustDescriptor,
    ordered: &[u8],
    deadline: u64,
    path: &Path,
    retained: &Prefix,
    head: Option<&TreeHead>,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<(CertifiedReply, HistoryEvidence)> {
    exchange_with_inputs(
        descriptor,
        ordered,
        &crate::authority_objects::Resolved::default(),
        deadline,
        path,
        retained,
        head,
        clock,
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn exchange_with_inputs(
    descriptor: &TrustDescriptor,
    ordered: &[u8],
    inputs: &crate::authority_objects::Resolved,
    deadline: u64,
    path: &Path,
    retained: &Prefix,
    head: Option<&TreeHead>,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
) -> Result<(CertifiedReply, HistoryEvidence)> {
    let (reply, evidence, _) = exchange_objects(
        descriptor,
        ordered,
        inputs,
        deadline,
        path,
        retained,
        head,
        clock,
        &mut |_| Ok(vec![]),
    )?;
    Ok((reply, evidence))
}

// This callback selects a finite schema only. Quorum and retained-floor verification
// must complete before the caller exposes or acts on these inert object bytes.
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub fn exchange_objects(
    descriptor: &TrustDescriptor,
    ordered: &[u8],
    inputs: &crate::authority_objects::Resolved,
    deadline: u64,
    path: &Path,
    retained: &Prefix,
    head: Option<&TreeHead>,
    clock: &mut impl FnMut() -> Result<ClockHealth>,
    expected_outputs: &mut impl FnMut(&[u8]) -> Result<Vec<crate::authority_objects::Reference>>,
) -> Result<(
    CertifiedReply,
    HistoryEvidence,
    crate::authority_objects::Resolved,
)> {
    let request = |operation, payload: &[u8]| {
        wire::encode(&a(vec![
            V::Uint(41),
            V::Uint(1),
            descriptor.scope().value(),
            V::Uint(operation),
            b(payload),
        ]))
    };
    let control = LocalControl::open(path)?;
    let digest = wire::digest(ordered);
    let submission = wire::encode(&a(vec![b(ordered), inputs.value()]))?;
    let mut bytes = control.exchange(&request(0, &submission)?, deadline)?;
    let (reply, outputs) = loop {
        let decoded = wire::decode(&bytes)?;
        let f = record(&decoded, 42, 10)?;
        ensure!(
            proof::Scope::parse(&f[2])? == *descriptor.scope()
                && f[4].uint()? == 0
                && f[5].fixed::<32>()? == digest,
            "local control refused or returned another authority request"
        );
        match f[3].uint()? {
            0 => {
                f[6].null()?;
                f[7].null()?;
                f[8].null()?;
                f[9].array(0)?;
            }
            1 => {
                let result = f[8].bytes()?.to_vec();
                let outputs = output_objects(&result, &f[9], expected_outputs)?;
                remaining(deadline)?;
                break (
                    CertifiedReply {
                        node: f[6].bytes()?.to_vec(),
                        certificate: f[7].bytes()?.to_vec(),
                        result,
                    },
                    outputs,
                );
            }
            _ => bail!("invalid local authority status"),
        }
        clock()?.observe()?;
        std::thread::sleep(Duration::from_millis(remaining(deadline)?.min(25)));
        bytes = control.exchange(&request(1, &digest)?, deadline)?;
    };
    let evidence = HistoryEvidence::fetch(&control, retained, head, &reply.node, deadline)?;
    remaining(deadline)?;
    Ok((reply, evidence, outputs))
}
fn output_objects(
    result: &[u8],
    sidecar: &V,
    expected: &mut impl FnMut(&[u8]) -> Result<Vec<crate::authority_objects::Reference>>,
) -> Result<crate::authority_objects::Resolved> {
    let operation = proof::OperationResult::parse(result)?;
    let references = if operation.disposition == proof::Disposition::Permit {
        expected(result)?
    } else {
        vec![]
    };
    crate::authority_objects::Resolved::parse(&references, sidecar)
}

/// Local services use the same owned-peer and monotonic framed-I/O contracts as authority control.
pub(crate) fn receive_frame(
    stream: &mut UnixStream,
    deadline: u64,
    maximum: usize,
) -> Result<Vec<u8>> {
    ensure!(
        (1..=wire::MAXIMUM).contains(&maximum),
        "invalid private request bound"
    );
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                peer.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
            && length as usize == std::mem::size_of::<libc::ucred>(),
        "private service peer credentials unavailable"
    );
    ensure!(
        unsafe { peer.assume_init() }.uid == unsafe { libc::geteuid() },
        "private service peer has another owner"
    );
    stream.set_nonblocking(true)?;
    let mut size = [0; 4];
    read_all(stream, &mut size, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        (1..=maximum).contains(&size),
        "private service request exceeds bound"
    );
    let mut bytes = vec![0; size];
    read_all(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
pub(crate) fn send_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: u64,
    maximum: usize,
) -> Result<()> {
    ensure!(
        (1..=4 * wire::MAXIMUM).contains(&maximum) && !bytes.is_empty() && bytes.len() <= maximum,
        "private service reply exceeds bound"
    );
    stream.set_nonblocking(true)?;
    write_all(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_all(stream, bytes, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn output_sidecars_are_finite_and_absent_from_nonpermits() {
        use crate::authority_objects::{Class, Object, Reference, Resolved};
        let body = b"approved source".to_vec();
        let reference = Reference::for_bytes(Class::PageSource, &body).unwrap();
        let objects = Resolved::exact(
            std::slice::from_ref(&reference),
            vec![Object::verify(reference.clone(), body).unwrap()],
        )
        .unwrap();
        let result = |disposition, code| {
            wire::encode(&a(vec![
                V::Uint(24),
                V::Uint(1),
                V::Text("AuthorityDomain".into()),
                V::Uint(disposition),
                V::Uint(code),
                b(&wire::encode(&a(vec![])).unwrap()),
            ]))
            .unwrap()
        };
        assert_eq!(
            output_objects(&result(0, 0), &objects.value(), &mut |_| Ok(vec![
                reference.clone()
            ]))
            .unwrap()
            .references(),
            vec![reference]
        );
        assert!(output_objects(&result(0, 0), &objects.value(), &mut |_| Ok(vec![])).is_err());
        for (disposition, code) in [(1, 3), (2, 25)] {
            let mut called = false;
            let mut select = |_: &[u8]| {
                called = true;
                Ok(vec![])
            };
            assert!(
                output_objects(&result(disposition, code), &objects.value(), &mut select).is_err()
            );
            assert!(
                output_objects(&result(disposition, code), &a(vec![]), &mut select)
                    .unwrap()
                    .is_empty()
            );
            assert!(!called);
        }
    }
    #[test]
    fn drip_reads_do_not_extend_the_original_transport_deadline() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let sender = std::thread::spawn(move || {
            for byte in 0..10 {
                if server.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = boot_time_ms().unwrap();
        let mut bytes = [0; 10];
        assert!(read_all(&mut client, &mut bytes, start + 55).is_err());
        assert!(boot_time_ms().unwrap() - start < 500);
        drop(client);
        sender.join().unwrap();
    }
}
