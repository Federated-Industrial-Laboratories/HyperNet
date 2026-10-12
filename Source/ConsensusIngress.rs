// SPDX-License-Identifier: MIT
use super::diagnostics::{Code, Diagnostics, Stage};
pub(super) use super::queue::Mailbox;
use super::{Event, Key, peer, queue::Lane};
use crate::trust_wire;
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    sync::{Semaphore, mpsc, oneshot},
    time::{Instant, timeout},
};

pub(super) struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
    _lock: File,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.device && m.ino() == self.inode && m.file_type().is_socket()
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
pub(super) fn local_socket(path: &Path) -> Result<(UnixListener, SocketGuard)> {
    let parent = path.parent().context("Private socket directory required")?;
    crate::runtime_management::files::root(parent)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(parent.join("ConsensusSocket.lock"))?;
    let m = lock.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0
            && m.nlink() == 1,
        "Unsafe socket lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Replica socket is already active"
    );
    if let Ok(old) = std::fs::symlink_metadata(path) {
        ensure!(
            old.file_type().is_socket()
                && old.uid() == unsafe { libc::geteuid() }
                && old.mode() & 0o077 == 0,
            "Unsafe existing socket"
        );
        ensure!(
            std::os::unix::net::UnixStream::connect(path).is_err(),
            "Socket is already listening"
        );
        let actual = std::fs::symlink_metadata(path)?;
        ensure!(
            actual.ino() == old.ino() && actual.dev() == old.dev(),
            "Socket changed during reconciliation"
        );
        std::fs::remove_file(path)?;
    }
    let socket = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let m = std::fs::symlink_metadata(path)?;
    socket.set_nonblocking(true)?;
    Ok((
        UnixListener::from_std(socket)?,
        SocketGuard {
            path: path.to_path_buf(),
            device: m.dev(),
            inode: m.ino(),
            _lock: lock,
        },
    ))
}
pub(super) async fn accept_local(
    listener: UnixListener,
    events: mpsc::Sender<Event>,
    diagnostics: Diagnostics,
) -> Result<()> {
    let limit = Arc::new(Semaphore::new(4));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (mut stream, _) = connection?;
                if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } { continue; }
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    diagnostics.emit(Code::LocalCapacity, Stage::LocalIngress, std::time::Duration::ZERO, 0);
                    continue;
                };
                let events = events.clone();
                let diagnostics = diagnostics.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let started = Instant::now();
                    let result = timeout(peer::HTTP_TIMEOUT, async {
                        let length = stream.read_u32().await.map_err(|_| Code::LocalIo)? as usize;
                        if length == 0 || length > trust_wire::MAXIMUM { return Err(Code::LocalInvalid); }
                        let mut bytes = vec![0; length];
                        stream.read_exact(&mut bytes).await.map_err(|_| Code::LocalIo)?;
                        let (answer, response) = oneshot::channel();
                        events.try_send(Event::Local { body: bytes, answer, queued: Instant::now() })
                            .map_err(|error| match error {
                                mpsc::error::TrySendError::Full(_) => Code::LocalQueueFull,
                                mpsc::error::TrySendError::Closed(_) => Code::LocalDriverClosed,
                            })?;
                        let body = response.await.map_err(|_| Code::LocalResponseClosed)?;
                        let length = u32::try_from(body.len()).map_err(|_| Code::LocalInvalid)?;
                        stream.write_u32(length).await.map_err(|_| Code::LocalIo)?;
                        stream.write_all(&body).await.map_err(|_| Code::LocalIo)?;
                        Ok::<(), Code>(())
                    }).await;
                    let code = match result { Err(_) => Some(Code::LocalTimeout), Ok(Err(code)) => Some(code), Ok(Ok(())) => None };
                    if let Some(code) = code { diagnostics.emit(code, Stage::LocalIngress, started.elapsed(), 0); }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}
fn response(status: StatusCode, bytes: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/cbor".parse().unwrap());
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
async fn handle(
    request: Request<Incoming>,
    sender: Key,
    events: mpsc::Sender<Event>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != hyper::Method::POST
        || request.uri().path() != "/V1/Peer"
        || request.uri().query().is_some()
        || request
            .headers()
            .get("content-type")
            .is_none_or(|v| v != "application/cbor")
    {
        return Ok(response(StatusCode::BAD_REQUEST, Vec::new()));
    }
    let result = async {
        let body = Limited::new(request.into_body(), trust_wire::MAXIMUM)
            .collect()
            .await
            .map_err(|_| anyhow::anyhow!("Invalid bounded peer body"))?
            .to_bytes()
            .to_vec();
        let (answer, response) = oneshot::channel();
        events.try_send(Event::Peer {
            sender,
            body,
            answer,
            queued: Instant::now(),
        })?;
        anyhow::Ok(response.await?)
    }
    .await;
    Ok(match result {
        Ok(bytes) => response(StatusCode::OK, bytes),
        Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
    })
}
async fn serve_peer<S>(stream: S, key: Key, events: mpsc::Sender<Event>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let service = service_fn(move |request| handle(request, key, events.clone()));
    // Reuse the authenticated connection within its original total lifetime.
    http1::Builder::new()
        .keep_alive(true)
        .max_headers(16)
        .max_buf_size(16384)
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}
pub(super) async fn accept_peers(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    pins: Vec<([u8; 32], Key)>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let capacity = Arc::new(Semaphore::new(16));
    let pins = Arc::new(
        pins.into_iter()
            .map(|(pin, key)| (pin, key, Arc::new(Semaphore::new(2))))
            .collect::<Vec<_>>(),
    );
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (stream, _) = connection?;
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                let acceptor = acceptor.clone(); let events = events.clone(); let pins = pins.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(peer::HTTP_TIMEOUT, async {
                        stream.set_nodelay(true)?;
                        let stream = acceptor.accept(stream).await?;
                        let leaf = stream.get_ref().1.peer_certificates().and_then(|c| c.first()).context("Peer TLS identity absent")?;
                        let pin: [u8;32] = Sha256::digest(leaf.as_ref()).into();
                        let (_, key, capacity) = pins.iter().find(|(known, _, _)| *known == pin).context("Peer TLS leaf is not configured")?;
                        let _peer_permit = capacity.clone().try_acquire_owned()?;
                        let key = *key;
                        serve_peer(stream, key, events).await?;
                        anyhow::Ok(())
                    }).await;
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}
pub(super) async fn send_peer(
    key: Key,
    origin: String,
    client: reqwest::Client,
    mailbox: Mailbox,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    // Both lanes use the same pinned client and the existing two-connection
    // peer limit. Dropping this future cancels both in-flight requests.
    tokio::try_join!(
        send_lane(key, &origin, &client, &mailbox, &events, Lane::General),
        send_lane(key, &origin, &client, &mailbox, &events, Lane::Recovery)
    )?;
    Ok(())
}
async fn send_lane(
    key: Key,
    origin: &str,
    client: &reqwest::Client,
    mailbox: &Mailbox,
    events: &mpsc::Sender<Event>,
    lane: Lane,
) -> Result<()> {
    loop {
        let body = mailbox.pop(lane).await?;
        let result = async {
            let mut response = client
                .post(origin)
                .header("content-type", "application/cbor")
                .body(body)
                .send()
                .await?;
            ensure!(
                response.status() == reqwest::StatusCode::OK
                    && response
                        .headers()
                        .get("content-type")
                        .is_some_and(|v| v == "application/cbor"),
                "Invalid peer transport response"
            );
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    body.len() + chunk.len() <= trust_wire::MAXIMUM,
                    "Peer response exceeds bound"
                );
                body.extend(chunk);
            }
            let (answer, _) = oneshot::channel();
            let _ = events.try_send(Event::Peer {
                sender: key,
                body,
                answer,
                queued: Instant::now(),
            });
            anyhow::Ok(())
        }
        .await;
        // Refused or unavailable transport never supplies a synthetic consensus response.
        if let Err(error) = result {
            super::diagnostic("transport", 0, 0, &error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[tokio::test]
    async fn peer_connection_reuses_identity_without_extending_its_lifetime() {
        let (server, client) = tokio::io::duplex(4096);
        let (events, mut received) = mpsc::channel(2);
        let key = [7; 32];
        let serving = tokio::spawn(async move {
            timeout(peer::HTTP_TIMEOUT, serve_peer(server, key, events)).await
        });
        let replies = tokio::spawn(async move {
            for expected in [b"ab", b"cd"] {
                let Event::Peer {
                    sender,
                    body,
                    answer,
                    ..
                } = received.recv().await.unwrap()
                else {
                    panic!("Peer request required");
                };
                assert_eq!(sender, key);
                assert_eq!(body, expected);
                answer.send(body).unwrap();
            }
        });
        let mut client = BufReader::new(client);
        for body in [b"ab", b"cd"] {
            client.write_all(b"POST /V1/Peer HTTP/1.1\r\nHost: peer\r\nContent-Type: application/cbor\r\nContent-Length: 2\r\n\r\n").await.unwrap();
            client.write_all(body).await.unwrap();
            let mut line = String::new();
            client.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("HTTP/1.1 200 "));
            loop {
                line.clear();
                assert!(client.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                assert!(!line.to_ascii_lowercase().starts_with("connection: close"));
            }
            let mut response = [0; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, body);
        }
        replies.await.unwrap();
        assert!(serving.await.unwrap().is_err());
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
