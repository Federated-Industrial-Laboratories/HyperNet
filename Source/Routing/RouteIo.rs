// SPDX-License-Identifier: MIT
// Opaque route traffic has one shared byte allowance, finite idle time and a fixed total deadline.
use crate::{route_profile::Limits, route_protocol};
use anyhow::{Context, Result, ensure};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub async fn receive<S: AsyncRead + Unpin>(stream: &mut S, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        maximum > 0 && maximum <= 4 * route_protocol::FRAME,
        "invalid route frame bound"
    );
    let size = stream.read_u32().await? as usize;
    ensure!(size > 0 && size <= maximum, "route frame exceeds its bound");
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4 * route_protocol::FRAME,
        "route response exceeds its bound"
    );
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
#[derive(Clone, Copy)]
struct Permission {
    expires: u64,
    closed: bool,
    active: usize,
    requested: bool,
}
#[derive(Clone)]
pub struct Gate(
    tokio::sync::watch::Sender<Permission>,
    Arc<tokio::sync::Notify>,
);
pub(crate) struct Activity {
    gate: Gate,
}
impl Drop for Activity {
    fn drop(&mut self) {
        self.gate.0.send_modify(|permission| permission.active -= 1);
        self.gate.1.notify_one();
    }
}
impl Gate {
    pub fn new(expires: u64) -> Self {
        Self::with_signal(expires, Arc::new(tokio::sync::Notify::new()))
    }
    pub(crate) fn with_signal(expires: u64, signal: Arc<tokio::sync::Notify>) -> Self {
        Self(
            tokio::sync::watch::channel(Permission {
                expires,
                closed: false,
                active: 0,
                requested: false,
            })
            .0,
            signal,
        )
    }
    pub(crate) fn signal(&self) -> Arc<tokio::sync::Notify> {
        self.1.clone()
    }
    pub(crate) fn demanded(&self) -> bool {
        let permission = self.0.borrow();
        !permission.closed && (permission.active > 0 || permission.requested)
    }
    /// Retain through a pending exchange; end before waiting for new work.
    pub(crate) fn activity(&self) -> Result<Activity> {
        let mut acquired = false;
        self.0.send_if_modified(|permission| {
            if permission.closed {
                return false;
            }
            let Some(active) = permission.active.checked_add(1) else {
                return false;
            };
            permission.active = active;
            acquired = true;
            true
        });
        ensure!(acquired, "route permission activity is unavailable");
        self.1.notify_one();
        Ok(Activity { gate: self.clone() })
    }
    fn request_renewal(&self) -> std::io::Result<()> {
        let now = crate::authority_challenge::boot_time_ms().map_err(std::io::Error::other)?;
        if self.0.send_if_modified(|permission| {
            if permission.closed || permission.expires > now || permission.requested {
                return false;
            }
            permission.requested = true;
            true
        }) {
            self.1.notify_one();
        }
        Ok(())
    }
    pub fn expiry(&self) -> Result<u64> {
        let value = *self.0.borrow();
        ensure!(!value.closed, "route permission is closed");
        Ok(value.expires)
    }
    pub fn renew(&self, expires: u64) -> Result<()> {
        ensure!(
            expires > crate::authority_challenge::boot_time_ms()?,
            "fresh route permission expired"
        );
        let mut renewed = false;
        self.0.send_modify(|permission| {
            if !permission.closed {
                permission.expires = expires;
                // A cancelled raw TLS write can leave one request, never an activity lease.
                permission.requested = false;
                renewed = true;
            }
        });
        ensure!(renewed, "route permission is closed");
        Ok(())
    }
    pub fn close(&self) {
        self.0.send_modify(|value| value.closed = true);
        self.1.notify_one();
    }
    pub async fn closed(&self) {
        let mut updates = self.0.subscribe();
        loop {
            if updates.borrow_and_update().closed {
                return;
            }
            if updates.changed().await.is_err() {
                return;
            }
        }
    }
}
#[derive(Clone)]
struct Binding {
    permission: Option<Gate>,
    deadline: u64,
}
#[derive(Clone)]
pub struct Boundary(tokio::sync::watch::Sender<Binding>);
impl Boundary {
    pub fn arm(&self, permission: Gate, deadline: u64) -> Result<()> {
        ensure!(
            permission.expiry()? > crate::authority_challenge::boot_time_ms()?,
            "route permission expired before arming"
        );
        self.arm_renewable(permission, deadline)
    }
    /// An endpoint may bind while its proof is being renewed. Every raw write still
    /// waits for current permission, and the original transport deadline cannot grow.
    pub fn arm_renewable(&self, permission: Gate, deadline: u64) -> Result<()> {
        permission.expiry()?;
        crate::authority_local_transport::remaining(deadline)?;
        let mut armed = false;
        self.0.send_modify(|binding| {
            if binding.permission.is_none() {
                binding.permission = Some(permission);
                binding.deadline = binding.deadline.min(deadline);
                armed = true;
            }
        });
        ensure!(armed, "route transport is already armed");
        Ok(())
    }
    fn check(&self) -> std::io::Result<bool> {
        let binding = self.0.borrow();
        let now = crate::authority_challenge::boot_time_ms().map_err(std::io::Error::other)?;
        if now >= binding.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original route transport deadline expired",
            ));
        }
        let Some(permission) = &binding.permission else {
            return Ok(true);
        };
        Ok(permission.expiry().map_err(std::io::Error::other)? > now)
    }
    async fn changed(self) {
        let mut control = self.0.subscribe();
        let binding = control.borrow_and_update().clone();
        let mut permission = binding.permission.as_ref().map(|gate| gate.0.subscribe());
        let now = crate::authority_challenge::boot_time_ms().unwrap_or(binding.deadline);
        let deadline = permission
            .as_mut()
            .map(|updates| *updates.borrow_and_update())
            .filter(|value| !value.closed && value.expires > now)
            .map_or(binding.deadline, |value| {
                binding.deadline.min(value.expires)
            });
        let has_permission = permission.is_some();
        tokio::select! {
            _ = control.changed() => {},
            _ = async { permission.as_mut().expect("enabled permission watcher").changed().await }, if has_permission => {},
            _ = tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(now))) => {},
        }
    }
}
#[derive(Default)]
struct WakeBoth(std::sync::Mutex<Vec<std::task::Waker>>);
impl WakeBoth {
    fn register(&self, waker: &std::task::Waker) {
        let mut waiters = self.0.lock().expect("route wake lock poisoned");
        if waiters.iter().any(|old| old.will_wake(waker)) {
            return;
        }
        // A split duplex stream has two pollers. Wake an evicted poller so cancellation cannot lose a wake.
        let evicted = (waiters.len() == 2).then(|| waiters.remove(0));
        waiters.push(waker.clone());
        drop(waiters);
        if let Some(waker) = evicted {
            waker.wake();
        }
    }
}
impl std::task::Wake for WakeBoth {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.0.lock().expect("route wake lock poisoned"));
        for waker in waiters {
            waker.wake();
        }
    }
}
// TLS reads can emit alerts and flush queued application ciphertext. This boundary is below TLS.
pub struct Transport<S> {
    socket: S,
    boundary: Boundary,
    pollers: Arc<WakeBoth>,
    wake: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
}
impl<S> Transport<S> {
    pub fn new(socket: S, deadline: u64) -> (Self, Boundary) {
        let boundary = Boundary(
            tokio::sync::watch::channel(Binding {
                permission: None,
                deadline,
            })
            .0,
        );
        (
            Self {
                socket,
                boundary: boundary.clone(),
                pollers: Arc::new(WakeBoth::default()),
                wake: None,
            },
            boundary,
        )
    }
    fn poll_boundary(
        &mut self,
        cx: &mut std::task::Context<'_>,
        writing: bool,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        self.pollers.register(cx.waker());
        let wake = std::task::Waker::from(self.pollers.clone());
        let mut context = std::task::Context::from_waker(&wake);
        loop {
            if let Err(error) = self.boundary.check() {
                return Poll::Ready(Err(error));
            }
            if self.wake.is_none() {
                self.wake = Some(Box::pin(self.boundary.clone().changed()));
            }
            if self
                .wake
                .as_mut()
                .expect("boundary wake installed")
                .as_mut()
                .poll(&mut context)
                .is_ready()
            {
                self.wake = None;
                continue;
            }
            return match self.boundary.check() {
                Ok(true) => Poll::Ready(Ok(())),
                Ok(false) if !writing => Poll::Ready(Ok(())),
                Ok(false) => {
                    if let Some(permission) = self.boundary.0.borrow().permission.as_ref()
                        && let Err(error) = permission.request_renewal()
                    {
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            };
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Transport<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_boundary(cx, false))?;
        std::pin::Pin::new(&mut self.socket).poll_read(cx, bytes)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Transport<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::ready!(self.poll_boundary(cx, true))?;
        std::pin::Pin::new(&mut self.socket).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::ready!(self.poll_boundary(cx, true))?;
        std::pin::Pin::new(&mut self.socket).poll_write_vectored(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_boundary(cx, true))?;
        std::pin::Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_boundary(cx, true))?;
        std::pin::Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}
async fn permitted<T>(
    gate: &Gate,
    deadline: u64,
    mut operation: impl FnMut(&mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<T>>,
) -> Result<T> {
    use std::task::Poll;
    let mut updates = gate.0.subscribe();
    loop {
        let left = crate::authority_local_transport::remaining(deadline)?;
        let permission = *updates.borrow_and_update();
        ensure!(!permission.closed, "route permission is closed");
        let now = crate::authority_challenge::boot_time_ms()?;
        if permission.expires <= now {
            tokio::time::timeout(Duration::from_millis(left), updates.changed()).await??;
            continue;
        }
        let wait = left.min(permission.expires - now);
        let pending = tokio::time::timeout(
            Duration::from_millis(wait),
            std::future::poll_fn(|cx| {
                let now = match crate::authority_challenge::boot_time_ms() {
                    Ok(now) => now,
                    Err(error) => return Poll::Ready(Err(std::io::Error::other(error))),
                };
                let permission = *gate.0.borrow();
                if permission.closed || now >= deadline {
                    return Poll::Ready(Err(std::io::Error::other(
                        "route permission closed or original deadline expired",
                    )));
                }
                if now >= permission.expires {
                    return Poll::Ready(Ok(None));
                }
                operation(cx).map(|result| result.map(Some))
            }),
        );
        let result = tokio::select! {
            result = pending => result,
            changed = updates.changed() => { changed?; continue; },
        };
        match result {
            Ok(Ok(Some(value))) => return Ok(value),
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(None)) | Err(_) => {}
        }
    }
}
async fn guarded_write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    mut bytes: &[u8],
    gate: &Gate,
    deadline: u64,
    idle_ms: u64,
) -> Result<()> {
    use std::pin::Pin;
    let _activity = gate.activity()?;
    let mut idle_deadline = crate::authority_challenge::boot_time_ms()?
        .saturating_add(idle_ms)
        .min(deadline);
    while !bytes.is_empty() {
        let n = permitted(gate, idle_deadline, |cx| {
            Pin::new(&mut *stream).poll_write(cx, bytes)
        })
        .await?;
        ensure!(n > 0, "route write closed");
        bytes = &bytes[n..];
        idle_deadline = crate::authority_challenge::boot_time_ms()?
            .saturating_add(idle_ms)
            .min(deadline);
    }
    permitted(gate, idle_deadline, |cx| {
        Pin::new(&mut *stream).poll_flush(cx)
    })
    .await
}
pub async fn guarded_send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    gate: &Gate,
    deadline: u64,
    idle_ms: u64,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 4 * route_protocol::FRAME,
        "route response exceeds its bound"
    );
    guarded_write(
        stream,
        &(bytes.len() as u32).to_be_bytes(),
        gate,
        deadline,
        idle_ms,
    )
    .await?;
    guarded_write(stream, bytes, gate, deadline, idle_ms).await
}
async fn direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    bytes: Arc<AtomicU64>,
    gate: &Gate,
    deadline: u64,
    idle_ms: u64,
) -> Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let left = crate::authority_local_transport::remaining(deadline)?.min(idle_ms);
        let count =
            tokio::time::timeout(Duration::from_millis(left), reader.read(&mut buffer)).await??;
        if count == 0 {
            return Ok(());
        }
        ensure!(
            bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| remaining
                    .checked_sub(count as u64))
                .is_ok(),
            "route byte admission exhausted"
        );
        guarded_write(writer, &buffer[..count], gate, deadline, idle_ms).await?;
    }
}
pub async fn forward_guarded<
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
>(
    left: A,
    right: B,
    limits: Limits,
    gate: Gate,
    deadline: u64,
) -> Result<()> {
    limits.validate()?;
    let bytes = Arc::new(AtomicU64::new(limits.bytes));
    let (mut lr, mut lw) = tokio::io::split(left);
    let (mut rr, mut rw) = tokio::io::split(right);
    let left = crate::authority_local_transport::remaining(deadline)?;
    tokio::time::timeout(Duration::from_millis(left), async {
        tokio::select! {
            result = direction(&mut lr, &mut rw, bytes.clone(), &gate, deadline, limits.idle_ms) => result,
            result = direction(&mut rr, &mut lw, bytes, &gate, deadline, limits.idle_ms) => result,
            _ = gate.closed() => anyhow::bail!("route permission closed"),
        }
    }).await?
}
#[cfg(test)]
pub async fn forward<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    left: A,
    right: B,
    limits: Limits,
) -> Result<()> {
    let deadline = crate::authority_challenge::boot_time_ms()?.saturating_add(limits.duration_ms);
    forward_guarded(left, right, limits, Gate::new(deadline), deadline).await
}
pub async fn local(path: &std::path::Path) -> Result<tokio::net::UnixStream> {
    use std::{
        os::fd::AsRawFd,
        os::unix::fs::{FileTypeExt, MetadataExt},
        path::Path,
    };
    let directory = crate::authority_files::private_directory(
        path.parent().context("private route directory absent")?,
    )?;
    let name = path.file_name().context("private route socket absent")?;
    let path = Path::new("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(name);
    let check = || -> Result<std::fs::Metadata> {
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.file_type().is_socket()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "egress endpoint is not an owned private socket"
        );
        Ok(metadata)
    };
    let before = check()?;
    let stream = tokio::net::UnixStream::connect(&path).await?;
    ensure!(
        stream.peer_cred()?.uid() == unsafe { libc::geteuid() },
        "egress peer has another owner"
    );
    let after = check()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && directory.metadata()?.is_dir(),
        "egress socket changed during connection"
    );
    Ok(stream)
}
pub async fn dial(endpoint: crate::authority_proof::Digest) -> Result<tokio::net::UnixStream> {
    use crate::trust_wire::{self as wire, Value as V};
    let mut stream = local(std::path::Path::new("/Egress/Egress.sock")).await?;
    let frame = |kind| {
        wire::encode(&V::Array(vec![
            V::Uint(kind),
            V::Uint(1),
            V::Text("RouteDial".into()),
            V::Bytes(endpoint.to_vec()),
        ]))
    };
    send(&mut stream, &frame(200)?).await?;
    ensure!(
        receive(&mut stream, 256).await? == frame(201)?,
        "egress acknowledgement differs from the selected endpoint"
    );
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn private_route_raw_boundary_renews_both_pollers_and_cannot_rearm() {
        let (socket, mut peer) = tokio::io::duplex(128);
        let now = crate::authority_challenge::boot_time_ms().unwrap();
        let (socket, boundary) = Transport::new(socket, now + 2000);
        let gate = Gate::new(now + 50);
        boundary.arm(gate.clone(), now + 2000).unwrap();
        assert!(boundary.arm(Gate::new(now + 5000), now + 5000).is_err());
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (mut reader, mut writer) = tokio::io::split(socket);
        let write = tokio::spawn(async move { writer.write_all(b"Renewed").await });
        let read = tokio::spawn(async move { reader.read_exact(&mut [0; 1]).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(30), peer.read_exact(&mut [0; 1]))
                .await
                .is_err()
        );
        gate.renew(now + 2000).unwrap();
        tokio::time::timeout(Duration::from_millis(300), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        peer.read_exact(&mut [0; 7]).await.unwrap();
        gate.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), read)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    #[tokio::test]
    async fn private_route_raw_boundary_enforces_deadline_on_reads_flush_and_shutdown() {
        let (socket, _peer) = tokio::io::duplex(128);
        let now = crate::authority_challenge::boot_time_ms().unwrap();
        let (mut socket, boundary) = Transport::new(socket, now + 100);
        boundary.arm(Gate::new(now + 5000), now + 5000).unwrap();
        let error =
            tokio::time::timeout(Duration::from_millis(400), socket.read_exact(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(socket.flush().await.is_err());
        assert!(socket.shutdown().await.is_err());
        assert!(
            socket
                .write_vectored(&[std::io::IoSlice::new(b"Late")])
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn private_route_permission_pauses_then_renews_without_resetting_bytes() {
        let (mut reader, relay) = tokio::io::duplex(32768);
        let (service, mut destination) = tokio::io::duplex(32768);
        let start = crate::authority_challenge::boot_time_ms().unwrap();
        let gate = Gate::new(start);
        let task = tokio::spawn(forward_guarded(
            relay,
            service,
            Limits {
                bytes: 16384,
                duration_ms: 2000,
                idle_ms: 1000,
            },
            gate.clone(),
            start + 2000,
        ));
        tokio::task::yield_now().await;
        assert!(
            !gate.demanded(),
            "idle reads must not renew an expired proof"
        );
        reader.write_all(&[1; 10000]).await.unwrap();
        let mut first = [0; 1];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                destination.read_exact(&mut first)
            )
            .await
            .is_err()
        );
        assert!(
            gate.demanded(),
            "buffered forwarding must request fresh permission"
        );
        gate.renew(start + 2000).unwrap();
        let mut received = [0; 10000];
        destination.read_exact(&mut received).await.unwrap();
        assert_eq!(received, [1; 10000]);
        tokio::task::yield_now().await;
        assert!(!gate.demanded(), "completed writes must return to idle");
        gate.renew(start + 3000).unwrap();
        destination.write_all(&[2; 10000]).await.unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(!gate.demanded());
    }
    #[tokio::test]
    async fn private_route_cancelled_raw_write_requests_only_one_renewal() {
        let (socket, _peer) = tokio::io::duplex(128);
        let start = crate::authority_challenge::boot_time_ms().unwrap();
        let (mut socket, boundary) = Transport::new(socket, start + 2000);
        let gate = Gate::new(start);
        boundary.arm_renewable(gate.clone(), start + 2000).unwrap();
        let mut write = Box::pin(socket.write_all(b"Cancelled ciphertext"));
        std::future::poll_fn(|cx| {
            assert!(write.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(gate.demanded());
        // Demand predates the wait: Notify must retain the wake while the level remains set.
        tokio::time::timeout(Duration::from_millis(100), gate.signal().notified())
            .await
            .unwrap();
        drop(write);
        let expires = crate::authority_challenge::boot_time_ms().unwrap() + 50;
        gate.renew(expires).unwrap();
        assert!(!gate.demanded());
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            !gate.demanded(),
            "a cancelled TLS future must not retain activity"
        );
        for shutdown in [false, true] {
            let mut operation: std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<()>> + '_>,
            > = if shutdown {
                Box::pin(socket.shutdown())
            } else {
                Box::pin(socket.flush())
            };
            std::future::poll_fn(|cx| {
                assert!(operation.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert!(gate.demanded());
            drop(operation);
        }
        gate.close();
        assert!(!gate.demanded());
        assert!(socket.flush().await.is_err());
    }
    #[tokio::test]
    async fn private_route_permission_renewal_never_extends_original_deadline() {
        let (mut reader, relay) = tokio::io::duplex(128);
        let (service, mut destination) = tokio::io::duplex(128);
        let start = crate::authority_challenge::boot_time_ms().unwrap();
        let gate = Gate::new(start);
        let task = tokio::spawn(forward_guarded(
            relay,
            service,
            Limits {
                bytes: 16384,
                duration_ms: 1000,
                idle_ms: 1000,
            },
            gate.clone(),
            start + 150,
        ));
        reader.write_all(b"Bounded").await.unwrap();
        gate.renew(start + 5000).unwrap();
        destination.read_exact(&mut [0; 7]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(600), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(destination.read(&mut [0; 1]).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn private_route_permission_close_cancels_backpressured_write() {
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 5000;
        let gate = Gate::new(deadline);
        let permission = gate.clone();
        let task = tokio::spawn(async move {
            guarded_send(
                &mut writer,
                b"Buffered sensitive reply",
                &permission,
                deadline,
                5000,
            )
            .await
        });
        // A one-byte buffer proves the frame is still backpressured after its first byte.
        reader.read_exact(&mut [0; 1]).await.unwrap();
        assert!(gate.demanded());
        gate.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(gate.renew(deadline).is_err());
        assert!(!gate.demanded());
    }
    #[tokio::test]
    async fn closing_reader_cancels_both_opaque_directions() {
        let (mut reader, relay) = tokio::io::duplex(128);
        let (service, mut destination) = tokio::io::duplex(128);
        let task = tokio::spawn(forward(
            relay,
            service,
            Limits {
                bytes: 16384,
                duration_ms: 1000,
                idle_ms: 500,
            },
        ));
        reader.write_all(b"opaque").await.unwrap();
        let mut bytes = [0; 6];
        destination.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"opaque");
        drop(reader);
        tokio::time::timeout(Duration::from_millis(200), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(destination.read(&mut bytes).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn opaque_directions_share_one_byte_budget() {
        let (mut reader, relay) = tokio::io::duplex(32768);
        let (service, mut destination) = tokio::io::duplex(32768);
        let task = tokio::spawn(forward(
            relay,
            service,
            Limits {
                bytes: 16384,
                duration_ms: 1000,
                idle_ms: 500,
            },
        ));
        reader.write_all(&[1; 10000]).await.unwrap();
        destination.read_exact(&mut [0; 10000]).await.unwrap();
        destination.write_all(&[2; 10000]).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }
}
