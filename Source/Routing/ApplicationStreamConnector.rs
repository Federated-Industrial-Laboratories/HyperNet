// SPDX-License-Identifier: MIT
// The application SDK authenticates inside nested TLS and pumps bounded duplex plaintext to one local socket.
use super::*;
use crate::{
    authority_domains::streams,
    authority_proof::{Digest, VersionRef},
};
use std::{net::Shutdown, os::unix::net::UnixStream};
impl Session<'_> {
    pub fn authenticate_application(
        &mut self,
        network: Digest,
        incarnation: Digest,
        proof: &mut streams::Proof,
        binding: Digest,
        key: &SigningKey,
    ) -> Result<VersionRef> {
        let result = (|| {
            let inner = self
                .stream
                .as_mut()
                .context("application stream is closed")?;
            let challenge = streams::protocol::parse_challenge(
                &receive(inner, protocol::FRAME)?,
                network,
                incarnation,
                proof.service.id,
            )?;
            ensure!(
                proof.principal == key.verifying_key().to_bytes(),
                "application stream key differs from its principal"
            );
            proof.challenge = challenge;
            proof.exporter =
                inner
                    .conn
                    .export_keying_material([0; 32], streams::protocol::EXPORTER, None)?;
            proof.nonce = protocol::random()?;
            proof.envelope = trust_wire::sign_envelope(&proof.payload(network, incarnation)?, key)?;
            streams::Proof::parse(&proof.envelope, network, incarnation)?;
            send(inner, &proof.envelope)?;
            streams::protocol::parse_accepted(&receive(inner, protocol::FRAME)?, proof, binding)
        })();
        if result.is_err() {
            self.stream.take();
        }
        result
    }
    /// Ownership of the local stream and its close signals belongs to this one finite session.
    pub fn forward_application(&mut self, mut local: UnixStream, maximum_bytes: u64) -> Result<()> {
        let result = (|| {
            ensure!(
                maximum_bytes > 0 && maximum_bytes <= 1024 * 1024 * 1024,
                "application stream byte limit is invalid"
            );
            let inner = self
                .stream
                .as_mut()
                .context("application stream is closed")?;
            inner.conn.set_buffer_limit(Some(16384));
            inner.sock.conn.set_buffer_limit(Some(16384));
            inner.sock.sock.opportunistic = true;
            local.set_nonblocking(true)?;
            let mut up = [0u8; 8192];
            let mut down = [0u8; 8192];
            let (mut up_start, mut up_end, mut down_start, mut down_end) = (0, 0, 0, 0);
            let (mut local_eof, mut remote_eof, mut close_sent, mut local_closed) =
                (false, false, false, false);
            let mut remaining = maximum_bytes;
            loop {
                inner.sock.sock.check()?;
                let mut progress = false;
                if !local_eof && up_start == up_end {
                    match local.read(&mut up) {
                        Ok(0) => {
                            local_eof = true;
                            progress = true;
                        }
                        Ok(n) => {
                            remaining = remaining
                                .checked_sub(n as u64)
                                .context("application stream byte allowance exhausted")?;
                            up_start = 0;
                            up_end = n;
                            progress = true;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if up_start < up_end {
                    match inner.write(&up[up_start..up_end]) {
                        Ok(0) => anyhow::bail!("application TLS write closed"),
                        Ok(n) => {
                            up_start += n;
                            progress = true;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if local_eof && up_start == up_end && !close_sent {
                    inner.conn.send_close_notify();
                    close_sent = true;
                    progress = true;
                }
                match inner.flush() {
                    Ok(()) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e.into()),
                }
                if !remote_eof && down_start == down_end {
                    match inner.read(&mut down) {
                        Ok(0) => {
                            remote_eof = true;
                            progress = true;
                        }
                        Ok(n) => {
                            remaining = remaining
                                .checked_sub(n as u64)
                                .context("application stream byte allowance exhausted")?;
                            down_start = 0;
                            down_end = n;
                            progress = true;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if down_start < down_end {
                    match local.write(&down[down_start..down_end]) {
                        Ok(0) => anyhow::bail!("local application write closed"),
                        Ok(n) => {
                            down_start += n;
                            progress = true;
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if remote_eof && down_start == down_end && !local_closed {
                    local.shutdown(Shutdown::Write)?;
                    local_closed = true;
                }
                if close_sent
                    && local_closed
                    && !inner.conn.wants_write()
                    && !inner.sock.conn.wants_write()
                {
                    return Ok(());
                }
                if !progress {
                    let mut descriptors = [
                        libc::pollfd {
                            fd: inner.sock.sock.socket.as_raw_fd(),
                            events: libc::POLLIN
                                | if inner.conn.wants_write()
                                    || inner.sock.conn.wants_write()
                                    || up_start < up_end
                                {
                                    libc::POLLOUT
                                } else {
                                    0
                                },
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: local.as_raw_fd(),
                            events: if !local_eof && up_start == up_end {
                                libc::POLLIN
                            } else {
                                0
                            } | if down_start < down_end {
                                libc::POLLOUT
                            } else {
                                0
                            },
                            revents: 0,
                        },
                    ];
                    let wait = inner.sock.sock.check()?.min(100) as i32;
                    let rc = unsafe {
                        libc::poll(
                            descriptors.as_mut_ptr(),
                            descriptors.len() as libc::nfds_t,
                            wait,
                        )
                    };
                    if rc < 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::Interrupted {
                            return Err(e.into());
                        }
                    }
                    ensure!(
                        !descriptors.iter().any(|d| d.revents & libc::POLLNVAL != 0),
                        "application stream descriptor closed"
                    );
                }
            }
        })();
        self.stream.take();
        result
    }
}
