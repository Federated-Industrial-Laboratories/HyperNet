// SPDX-License-Identifier: MIT
// A reader creates one fresh nested TLS stream; every socket wait shares its original deadline.
use crate::{
    authority_challenge::boot_time_ms, authority_domains as domains,
    authority_membership::reference, route_profile::Profile, route_protocol as protocol, route_tls,
    trust_wire,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rustls::{ClientConnection, StreamOwned, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::fd::{AsRawFd, FromRawFd},
};
#[path = "ApplicationStreamConnector.rs"]
mod application_streams;
struct Socket<'a> {
    opportunistic: bool,
    socket: TcpStream,
    deadline: u64,
    operation_deadline: Option<u64>,
    idle_deadline: u64,
    idle_ms: u64,
    remaining_bytes: u64,
    cancelled: &'a dyn Fn() -> bool,
}
impl Socket<'_> {
    fn admitted(&mut self, limits: crate::route_profile::Limits, received_at: u64) {
        // Readiness reports remaining admission time; the caller's original deadline stays fixed.
        self.deadline = self
            .deadline
            .min(received_at.saturating_add(limits.duration_ms));
        self.idle_deadline = self
            .idle_deadline
            .min(received_at.saturating_add(limits.idle_ms));
        self.idle_ms = limits.idle_ms;
        self.remaining_bytes = self.remaining_bytes.min(limits.bytes);
    }
    fn check(&self) -> io::Result<u64> {
        if (self.cancelled)() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "private route cancelled",
            ));
        }
        let now = boot_time_ms().map_err(io::Error::other)?;
        self.deadline
            .min(self.operation_deadline.unwrap_or(u64::MAX))
            .min(self.idle_deadline)
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "private route deadline expired")
            })
    }
    fn ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let wait = self.check()?.min(100);
            let mut fd = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut fd, 1, wait as i32) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if result > 0 {
                if fd.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "private route socket failed",
                    ));
                }
                if fd.revents & (events | libc::POLLHUP) != 0 {
                    return Ok(());
                }
            }
        }
    }
    fn used(&mut self, n: usize) -> io::Result<()> {
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(n as u64)
            .ok_or_else(|| io::Error::other("private route byte admission exhausted"))?;
        if n > 0 {
            self.idle_deadline = boot_time_ms()
                .map_err(io::Error::other)?
                .saturating_add(self.idle_ms);
        }
        self.check()?;
        Ok(())
    }
}
impl Read for Socket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let maximum = bytes
                .len()
                .min(usize::try_from(self.remaining_bytes).unwrap_or(usize::MAX));
            if maximum == 0 {
                return Err(io::Error::other("private route byte admission exhausted"));
            }
            match self.socket.read(&mut bytes[..maximum]) {
                Ok(n) => {
                    self.used(n)?;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.opportunistic {
                        return Err(e);
                    }
                    self.ready(libc::POLLIN)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}
impl Write for Socket<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let maximum = bytes
                .len()
                .min(usize::try_from(self.remaining_bytes).unwrap_or(usize::MAX));
            if maximum == 0 {
                return Err(io::Error::other("private route byte admission exhausted"));
            }
            match self.socket.write(&bytes[..maximum]) {
                Ok(n) => {
                    self.used(n)?;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.opportunistic {
                        return Err(e);
                    }
                    self.ready(libc::POLLOUT)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        Ok(())
    }
}
fn send(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= protocol::FRAME,
        "private route frame exceeds bound"
    );
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}
fn receive(stream: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(
        size > 0 && size <= maximum,
        "private route response exceeds bound"
    );
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn connect(address: SocketAddr, deadline: u64, cancelled: &dyn Fn() -> bool) -> Result<TcpStream> {
    ensure!(!cancelled(), "private route cancelled");
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    ensure!(fd >= 0, "cannot create private route socket");
    let socket = unsafe { TcpStream::from_raw_fd(fd) };
    let result = match address {
        SocketAddr::V4(address) => {
            let mut native: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            native.sin_family = libc::AF_INET as libc::sa_family_t;
            native.sin_port = address.port().to_be();
            native.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
            unsafe {
                libc::connect(
                    fd,
                    &native as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(address) => {
            ensure!(
                address.scope_id() == 0,
                "scoped interface addresses are not a private relay route"
            );
            let mut native: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            native.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            native.sin6_port = address.port().to_be();
            native.sin6_addr.s6_addr = address.ip().octets();
            unsafe {
                libc::connect(
                    fd,
                    &native as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&native) as libc::socklen_t,
                )
            }
        }
    };
    let pending = Socket {
        opportunistic: false,
        socket,
        deadline,
        operation_deadline: None,
        idle_deadline: deadline,
        idle_ms: u64::MAX,
        remaining_bytes: u64::MAX,
        cancelled,
    };
    if result != 0 {
        ensure!(
            io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS),
            "private relay connection refused"
        );
        pending.ready(libc::POLLOUT)?;
        if let Some(error) = pending.socket.take_error()? {
            return Err(error.into());
        }
    }
    pending.check()?;
    pending.socket.set_nodelay(true)?;
    Ok(pending.socket)
}

type Stream<'a> = StreamOwned<ClientConnection, StreamOwned<ClientConnection, Socket<'a>>>;
/// One admitted connection owns a fixed resource budget; failed exchanges cannot reconnect.
pub struct Session<'a> {
    stream: Option<Stream<'a>>,
}
impl<'a> Session<'a> {
    pub fn connect(
        profile: &Profile,
        possession: &SigningKey,
        deadline: u64,
        cancelled: &'a dyn Fn() -> bool,
    ) -> Result<Self> {
        profile.validate()?;
        let record =
            domains::Record::parse(&profile.voucher, profile.network, profile.incarnation)?;
        ensure!(
            record.reference.kind == 166,
            "private route profile requires a typed voucher record"
        );
        let voucher = domains::routes::Voucher::parse(&record.payload)?;
        ensure!(
            voucher.relay.id == profile.relay.service
                && voucher.destination.id == profile.destination.service
                && voucher.possession == possession.verifying_key().to_bytes(),
            "private route voucher differs from selected endpoints or possession key"
        );
        // Profiles retain the complete public voucher; relay admission selects its exact current record.
        let voucher = trust_wire::encode(&reference(&record.reference))?;
        let start = boot_time_ms()?;
        let deadline = deadline.min(
            start
                .checked_add(profile.limits.duration_ms)
                .context("private route deadline overflow")?,
        );
        let socket = Socket {
            opportunistic: false,
            socket: connect(profile.relay_address, deadline, cancelled)?,
            deadline,
            operation_deadline: None,
            idle_deadline: start.saturating_add(profile.limits.idle_ms),
            idle_ms: profile.limits.idle_ms,
            remaining_bytes: profile.limits.bytes,
            cancelled,
        };
        let connection = ClientConnection::new(
            route_tls::client(&profile.relay)?,
            ServerName::try_from(profile.relay.server_name.clone())?,
        )?;
        let mut outer = StreamOwned::new(connection, socket);
        outer
            .conn
            .complete_io(&mut outer.sock)
            .context("authenticate private relay")?;
        ensure!(
            outer.conn.alpn_protocol() == Some(route_tls::ALPN),
            "relay protocol differs"
        );
        let exporter = outer
            .conn
            .export_keying_material([0; 32], protocol::EXPORTER, None)?;
        let open = protocol::Open {
            network: profile.network,
            incarnation: profile.incarnation,
            relay: profile.relay.service,
            service: profile.destination.service,
            voucher,
            nonce: protocol::random()?,
            attachment: false,
        };
        send(&mut outer, &open.encode()?).context("send private route request")?;
        let challenge = protocol::parse_challenge(
            &receive(&mut outer, protocol::FRAME).context("wait for private relay challenge")?,
        )?;
        let signed = open.sign(challenge, exporter, possession)?;
        let binding = trust_wire::digest(&open.binding(challenge, exporter)?);
        send(&mut outer, &signed).context("send private route channel proof")?;
        let limits = protocol::parse_ready(
            &receive(&mut outer, protocol::FRAME).context("wait for private relay admission")?,
            binding,
            profile.limits,
        )?;
        outer.sock.admitted(limits, boot_time_ms()?);
        let connection = ClientConnection::new(
            route_tls::client(&profile.destination)?,
            ServerName::try_from(profile.destination.server_name.clone())?,
        )?;
        let mut inner = StreamOwned::new(connection, outer);
        inner
            .conn
            .complete_io(&mut inner.sock)
            .context("authenticate final private service")?;
        ensure!(
            inner.conn.alpn_protocol() == Some(route_tls::ALPN),
            "final service protocol differs"
        );
        protocol::parse_endpoint_ready(
            &receive(&mut inner, protocol::FRAME)
                .context("wait for final private service readiness")?,
            profile.network,
            profile.incarnation,
            profile.destination.service,
            profile.protocol,
        )?;
        inner.sock.sock.check()?;
        Ok(Self {
            stream: Some(inner),
        })
    }
    pub fn exchange(
        &mut self,
        request: &[u8],
        deadline: u64,
        maximum_response: usize,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            ensure!(
                !request.is_empty()
                    && request.len() <= trust_wire::MAXIMUM
                    && (1..=4 * trust_wire::MAXIMUM).contains(&maximum_response),
                "invalid private route application frame"
            );
            let inner = self
                .stream
                .as_mut()
                .context("private route session is closed")?;
            inner.sock.sock.operation_deadline = Some(deadline);
            inner.sock.sock.check()?;
            // Endpoint readiness and both authenticated TLS layers precede every application credential.
            send(inner, request).context("send private application request")?;
            let response =
                receive(inner, maximum_response).context("receive private application response")?;
            inner.sock.sock.check()?;
            inner.sock.sock.operation_deadline = None;
            Ok(response)
        })();
        if result.is_err() {
            self.stream.take();
        }
        result
    }
}
#[allow(dead_code)] // Shared one-shot entry point used by Core transport qualification.
pub fn exchange(
    profile: &Profile,
    possession: &SigningKey,
    request: &[u8],
    deadline: u64,
    maximum_response: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>> {
    Session::connect(profile, possession, deadline, cancelled)?.exchange(
        request,
        deadline,
        maximum_response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    #[test]
    fn private_route_operation_deadline_never_resets_session_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let now = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: now + 60000,
            operation_deadline: Some(now),
            idle_deadline: now + 30000,
            idle_ms: 30000,
            remaining_bytes: 12345,
            cancelled: &|| false,
        };
        assert!(stream.check().is_err());
        stream.operation_deadline = Some(now + 5000);
        assert!(stream.check().unwrap() <= 5000);
        stream.operation_deadline = None;
        assert!(stream.check().unwrap() > 5000);
        assert_eq!(stream.deadline, now + 60000);
        assert_eq!(stream.idle_deadline, now + 30000);
        assert_eq!(stream.remaining_bytes, 12345);
    }
    #[test]
    fn private_route_readiness_cannot_extend_original_socket_limits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: 5000,
            operation_deadline: None,
            idle_deadline: 4800,
            idle_ms: 1000,
            remaining_bytes: 12000,
            cancelled: &|| false,
        };
        let limits = crate::route_profile::Limits {
            bytes: 16384,
            duration_ms: 1000,
            idle_ms: 800,
        };
        stream.admitted(limits, 4500);
        assert_eq!(stream.deadline, 5000);
        assert_eq!(stream.idle_deadline, 4800);
        assert_eq!(stream.remaining_bytes, 12000);
        assert_eq!(stream.idle_ms, 800);
        // A stricter remaining allowance starts at readiness, not at the original connection start.
        stream.deadline = 9000;
        stream.idle_deadline = 9000;
        stream.remaining_bytes = 65536;
        stream.admitted(limits, 4500);
        assert_eq!(stream.deadline, 5500);
        assert_eq!(stream.idle_deadline, 5300);
        assert_eq!(stream.remaining_bytes, 16384);
    }
    #[test]
    fn private_route_cancellation_does_not_retry_as_interrupted_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let task = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            signal.store(true, Ordering::Release);
        });
        let check = || cancelled.load(Ordering::Acquire);
        let start = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: start + 5000,
            operation_deadline: None,
            idle_deadline: start + 5000,
            idle_ms: 5000,
            remaining_bytes: 1024,
            cancelled: &check,
        };
        let error = stream.read_exact(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(boot_time_ms().unwrap() - start < 1000);
        task.join().unwrap();
    }
    #[test]
    fn private_route_drip_traffic_cannot_extend_original_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let task = std::thread::spawn(move || {
            for _ in 0..20 {
                if peer.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = boot_time_ms().unwrap();
        let mut stream = Socket {
            opportunistic: false,
            socket,
            deadline: start + 75,
            operation_deadline: None,
            idle_deadline: start + 1000,
            idle_ms: 1000,
            remaining_bytes: 1024,
            cancelled: &|| false,
        };
        let error = stream.read_exact(&mut [0; 20]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(boot_time_ms().unwrap() - start < 1000);
        drop(stream);
        task.join().unwrap();
    }
}
