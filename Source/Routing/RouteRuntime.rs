// SPDX-License-Identifier: MIT
// One-use relays and outbound attachments retain encrypted buffers only for the admitted connection.
use crate::{
    authority_domains::routes,
    authority_files as files,
    authority_proof::Digest,
    route_authority::{Client, Renewal},
    route_config::Config,
    route_endpoint, route_io,
    route_profile::{Identity, Limits},
    route_protocol::{self as protocol, Open},
    route_tls,
    runtime_service_activate::Active,
    runtime_service_authorization::Guard,
    trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub trait Channel: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Channel for T {}
type Stream = Box<dyn Channel>;
#[path = "ApplicationStreamRuntime.rs"]
mod application_streams;
static TIMING_SAMPLES: AtomicU64 = AtomicU64::new(0);
const DISPATCH_MS: u64 = 100;
const READ_RETRY_MS: u64 = 1000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadRetry {
    FreshQuorumUnavailable,
    HistoryOvertaken,
    ChallengeExpired,
    TransportClosed,
}
impl std::fmt::Display for ReadRetry {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "fresh route context requires another read: {self:?}")
    }
}
impl std::error::Error for ReadRetry {}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    AdmissionQueue,
    VoucherContextStart,
    VoucherContextComplete,
    PermitStart,
    PermitComplete,
    AdmissionComplete,
    AdmissionRefused,
    AdmissionExpired,
    DestinationRefused,
    PublicDialStart,
    PublicDialComplete,
    ReadyComplete,
    ForwardingComplete,
    ForwardingRefused,
    EndpointTlsStart,
    EndpointTlsComplete,
    EndpointRefused,
    EndpointReadyStart,
    EndpointReadyBindingRefused,
    EndpointReadyBudgetRefused,
    EndpointReadyWriteRefused,
    EndpointReadyComplete,
    RequestReceived,
    RequestDequeued,
    LocalReply,
    ResponseFlushed,
    RenewalStart,
    RenewalComplete,
    RenewalRefused,
    RelayGuardExpired,
    RelayGuardResumed,
    RelayCurrent,
    RelayClock,
    RenewalAuthority,
    RenewalCurrent,
    PairPermission,
    PairCurrent,
    PairClock,
    PairBinding,
    AttachmentAdmission,
    AttachmentRefused,
    AttachmentReady,
    ReaderReady,
    AdmissionAuthority,
    AdmissionCurrent,
    AdmissionClock,
    EndpointRenewalStart,
    EndpointRenewalComplete,
    EndpointRenewalRefused,
}
impl std::fmt::Display for Phase {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "private route stage {self:?}")
    }
}
impl std::error::Error for Phase {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureCode {
    ObservationExpired,
    ChallengeExpired,
    FreshQuorumUnavailable,
    HistoryOvertaken,
    LocalReadClosed,
    LocalWriteClosed,
    LocalReadiness,
    InspectionDeadline,
    Timeout,
    UnexpectedEof,
    ConnectionReset,
    ConnectionAborted,
    BrokenPipe,
    PermissionDenied,
    Io,
    Tls,
    Other,
}
fn failure_code(error: &anyhow::Error) -> FailureCode {
    if error.is::<crate::consensus_clock::ObservationExpired>() {
        return FailureCode::ObservationExpired;
    }
    if error.is::<crate::authority_challenge::ChallengeExpired>() {
        return FailureCode::ChallengeExpired;
    }
    if error.is::<crate::authority_local_transport::FreshReadUnavailable>() {
        return FailureCode::FreshQuorumUnavailable;
    }
    if error.is::<crate::authority_local_transport::HistoryOvertaken>() {
        return FailureCode::HistoryOvertaken;
    }
    if error.is::<tokio::time::error::Elapsed>() {
        return FailureCode::Timeout;
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return match error.kind() {
            std::io::ErrorKind::TimedOut => FailureCode::Timeout,
            std::io::ErrorKind::UnexpectedEof => FailureCode::UnexpectedEof,
            std::io::ErrorKind::ConnectionReset => FailureCode::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted => FailureCode::ConnectionAborted,
            std::io::ErrorKind::BrokenPipe => FailureCode::BrokenPipe,
            std::io::ErrorKind::PermissionDenied => FailureCode::PermissionDenied,
            _ => FailureCode::Io,
        };
    }
    if error.is::<rustls::Error>() {
        return FailureCode::Tls;
    }
    // Legacy transport errors are mapped only for diagnostics, never retry authority.
    for cause in error.chain() {
        match cause.to_string().as_str() {
            "private control read closed" => return FailureCode::LocalReadClosed,
            "private control write closed" => return FailureCode::LocalWriteClosed,
            "private control readiness failed or timed out" => return FailureCode::LocalReadiness,
            "original inspection deadline expired" => return FailureCode::InspectionDeadline,
            _ => {}
        }
    }
    FailureCode::Other
}
#[derive(Clone, Copy)]
pub(crate) struct Timing {
    started: u64,
    sample: Option<u64>,
}
impl Timing {
    fn begin(started: u64, enabled: bool) -> Self {
        let sample = if enabled {
            TIMING_SAMPLES
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < 64).then_some(n + 1)
                })
                .ok()
                .map(|n| n + 1)
        } else {
            None
        };
        Self { started, sample }
    }
    pub(crate) fn mark(self, stage: Phase) {
        if let Some(sample) = self.sample
            && let Ok(now) = crate::authority_challenge::boot_time_ms()
        {
            // Bounded samples cover sequential setup; only fixed stages and elapsed time are logged.
            eprintln!(
                "HyperNet private route timing: sample={sample} stage={stage:?} elapsedMs={} bootMs={now}",
                now.saturating_sub(self.started)
            );
        }
    }
    fn failure(self, stage: Phase, error: &anyhow::Error) {
        if let Some(sample) = self.sample {
            eprintln!(
                "HyperNet private route failure: sample={sample} stage={stage:?} cause={:?} reason={:?} freshReadCode={:?} bootMs={:?}",
                error.downcast_ref::<Phase>(),
                failure_code(error),
                error
                    .downcast_ref::<crate::authority_local_transport::FreshReadUnavailable>()
                    .map(|e| e.code),
                crate::authority_challenge::boot_time_ms().ok(),
            );
        }
    }
}
struct Opened {
    stream: Stream,
    boundary: route_io::Boundary,
    open: Open,
    signer: Digest,
    connection: Digest,
    binding: Digest,
    timing: Option<Timing>,
}
struct Attached {
    stream: Stream,
    boundary: route_io::Boundary,
    service: Digest,
    envelope: Vec<u8>,
    binding: Digest,
    expires: u64,
    deadline: u64,
    total_deadline: u64,
    slot: OwnedSemaphorePermit,
}
struct Queued<T> {
    request: T,
    slot: OwnedSemaphorePermit,
    started: u64,
    enqueued: u64,
    deadline: u64,
}
struct ListenerQueue<T> {
    tasks: JoinSet<Result<()>>,
    requests: mpsc::Receiver<Queued<T>>,
    attachments: mpsc::Receiver<Queued<T>>,
    diagnostics: Arc<IngressDiagnostics>,
    stop: tokio::sync::watch::Sender<bool>,
}
#[derive(Clone, Copy, Debug)]
enum Refusal {
    Capacity,
    AttachmentCapacity,
    Socket,
    Tls,
    Open,
    Proof,
    Deadline,
    Parser,
    Admission,
    AdmissionExpired,
    AttachmentUnavailable,
    Forwarding,
    Accept,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Capacity => "connection capacity",
            Self::AttachmentCapacity => "attachment capacity",
            Self::Socket => "socket configuration",
            Self::Tls => "TLS handshake",
            Self::Open => "request frame",
            Self::Proof => "channel proof",
            Self::Deadline => "admission deadline",
            Self::Parser => "request parsing",
            Self::Admission => "authority admission",
            Self::AdmissionExpired => "admitted permission expired",
            Self::AttachmentUnavailable => "matching attachment unavailable",
            Self::Forwarding => "forwarding",
            Self::Accept => "transient listener failure",
        })
    }
}
impl std::error::Error for Refusal {}
#[derive(Default)]
struct IngressDiagnostics {
    refused: [AtomicU64; 13],
    parsed: AtomicU64,
    reported: AtomicU64,
}
impl IngressDiagnostics {
    fn refuse(&self, reason: Refusal) {
        let first = self.refused[reason as usize].fetch_add(1, Ordering::Relaxed) == 0;
        let sampled = self
            .reported
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 64).then_some(n + 1)
            })
            .is_ok();
        if first || sampled {
            // Bounded fixed categories omit peer identity, frames and untrusted error text.
            eprintln!(
                "HyperNet private route refused: {reason} code={reason:?} bootMs={:?}",
                crate::authority_challenge::boot_time_ms().ok()
            );
        }
    }
}
impl<T> Drop for ListenerQueue<T> {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        eprintln!(
            "HyperNet private route ingress totals: parsed={} refused={:?} bootMs={:?}",
            self.diagnostics.parsed.load(Ordering::Relaxed),
            self.diagnostics
                .refused
                .each_ref()
                .map(|count| count.load(Ordering::Relaxed)),
            crate::authority_challenge::boot_time_ms().ok(),
        );
    }
}
impl<T> ListenerQueue<T> {
    async fn shutdown(&mut self) {
        self.stop.send_replace(true);
        self.requests.close();
        self.attachments.close();
        while self.tasks.join_next().await.is_some() {}
        while self.requests.try_recv().is_ok() {}
        while self.attachments.try_recv().is_ok() {}
    }
}
async fn drain<T: 'static>(tasks: &mut JoinSet<T>) {
    while tasks.join_next().await.is_some() {}
}
fn transient_accept(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::ECONNABORTED
                | libc::ECONNRESET
                | libc::EINTR
                | libc::EAGAIN
                | libc::ETIMEDOUT
                | libc::ENETDOWN
                | libc::EPROTO
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENONET
                | libc::EHOSTUNREACH
                | libc::EOPNOTSUPP
                | libc::ENETUNREACH
        )
    )
}
// TLS acceptance must remain responsive while the sole authority requester waits for quorum.
// Parsing, readers and attachments each have an independent, explicitly bounded allowance.
// Waiting readers cannot prevent replacement attachments from authenticating.
fn listen<T, F, Fut>(
    listener: TcpListener,
    capacity: usize,
    idle_ms: u64,
    attachment: Option<fn(&T) -> bool>,
    mut parse: F,
) -> ListenerQueue<T>
where
    T: Send + 'static,
    F: FnMut(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T>> + Send + 'static,
{
    let (sender, requests) = mpsc::channel(capacity);
    let (park_sender, attachments) = mpsc::channel(capacity);
    let slots = Arc::new(Semaphore::new(capacity));
    let parked_slots = Arc::new(Semaphore::new(capacity));
    let diagnostics = Arc::new(IngressDiagnostics::default());
    let observed = diagnostics.clone();
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut parsing = JoinSet::new();
        let mut accept_after = tokio::time::Instant::now();
        let outcome = async {
        loop {
            tokio::select! {
                biased;
                _ = stopping.changed() => break,
                _ = sender.closed() => break,
                accepted = async {
                    tokio::time::sleep_until(accept_after).await;
                    listener.accept().await
                }, if parsing.len() < capacity => {
                    let (socket, _) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) if transient_accept(&error) => {
                            observed.refuse(Refusal::Accept);
                            // An exhausted process must not spin or terminate its established streams.
                            // Waiting here never changes any accepted connection's original deadline.
                            accept_after = tokio::time::Instant::now() + Duration::from_millis(DISPATCH_MS);
                            continue;
                        },
                        Err(error) => return Err(error.into()),
                    };
                    {
                        let started = crate::authority_challenge::boot_time_ms()?;
                        let deadline = started
                            .checked_add(idle_ms).context("route admission deadline overflow")?;
                        let pending = parse(socket);
                        let sender = sender.clone();
                        let park_sender = park_sender.clone();
                        let parked_slots = parked_slots.clone();
                        let slots = slots.clone();
                        let observed = observed.clone();
                        parsing.spawn(async move {
                            let parsed = tokio::time::timeout(Duration::from_millis(idle_ms), pending).await;
                            let request = match parsed {
                                Ok(Ok(request)) => request,
                                Ok(Err(error)) => { observed.refuse(error.downcast_ref::<Refusal>().copied().unwrap_or(Refusal::Parser)); return; },
                                Err(_) => { observed.refuse(Refusal::Deadline); return; },
                            };
                            observed.parsed.fetch_add(1, Ordering::Relaxed);
                            let (sender, slot) = if attachment.is_some_and(|classify| classify(&request)) {
                                let Ok(parked) = parked_slots.try_acquire_owned() else { observed.refuse(Refusal::AttachmentCapacity); return; };
                                // Provisional and approved attachments share the existing inert pool.
                                // They do not reserve a reader/forwarding slot while awaiting authority.
                                (park_sender, parked)
                            } else {
                                let Ok(slot) = slots.try_acquire_owned() else { observed.refuse(Refusal::Capacity); return; };
                                (sender, slot)
                            };
                            let Ok(enqueued) = crate::authority_challenge::boot_time_ms() else { observed.refuse(Refusal::Parser); return; };
                            let _ = sender.send(Queued { request, slot, started, enqueued, deadline }).await;
                        });
                    }
                },
                _ = parsing.join_next(), if !parsing.is_empty() => {},
            }
        }
        Ok(())
        }.await;
        parsing.abort_all();
        drain(&mut parsing).await;
        outcome
    });
    ListenerQueue {
        tasks,
        requests,
        attachments,
        diagnostics,
        stop,
    }
}
async fn next_admission<T>(
    requests: &mut mpsc::Receiver<Queued<T>>,
    attachments: &mut mpsc::Receiver<Queued<T>>,
) -> Option<Queued<T>> {
    tokio::select! {
        biased;
        request = requests.recv() => request,
        attachment = attachments.recv() => attachment,
    }
}
fn parking_deadline(deadline: u64, expires: u64, wall_ms: u64, boot_ms: u64) -> Result<u64> {
    let consent = expires
        .checked_sub(wall_ms)
        .context("parked route consent expired")?;
    let deadline = deadline.min(boot_ms.saturating_add(consent));
    ensure!(boot_ms < deadline, "parked route deadline expired");
    Ok(deadline)
}
fn exact_attachment(parked: &[u8], target: &[u8], expiry: (u64, u64), now: (u64, u64)) -> bool {
    parked == target && now.0 < expiry.0 && now.1 < expiry.1
}
struct Session {
    stream: Stream,
    boundary: route_io::Boundary,
    deadline: u64,
    idle_ms: u64,
    bytes: u64,
    slot: Option<OwnedSemaphorePermit>,
    timing: Timing,
    frames: u8,
    exporter: Digest,
}
impl Session {
    fn mark(&self, phase: Phase) {
        if self.frames <= 32 {
            self.timing.mark(phase);
        }
    }
    fn charge(&mut self, size: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_sub(size as u64 + 4)
            .context("private endpoint byte budget exhausted")?;
        Ok(())
    }
    fn wait(&self) -> Result<Duration> {
        Ok(Duration::from_millis(
            crate::authority_local_transport::remaining(self.deadline)?.min(self.idle_ms),
        ))
    }
}
struct Request {
    session: Session,
    packet: Vec<u8>,
}
struct Live {
    renewal: Renewal,
    gate: route_io::Gate,
    accepted_at: u64,
    deadline: u64,
    timing: Timing,
    renewals: u8,
}
impl Drop for Live {
    fn drop(&mut self) {
        self.gate.close();
    }
}
fn live_renewal(live: &BTreeMap<Digest, Live>) -> Result<Option<(Digest, (u64, u64))>> {
    live.iter()
        .filter(|(_, session)| session.gate.demanded())
        .map(|(id, session)| Ok((*id, (session.gate.expiry()?, session.accepted_at))))
        .collect::<Result<Vec<_>>>()
        .map(|entries| entries.into_iter().min_by_key(|(_, (expires, _))| *expires))
}
struct Waiting {
    opened: Opened,
    slot: OwnedSemaphorePermit,
    setup_deadline: u64,
    limits: Limits,
    target: Digest,
    envelope: Vec<u8>,
    live: Live,
}
impl Waiting {
    fn current(&self, boot: u64) -> bool {
        boot < self.setup_deadline && boot < self.live.deadline
    }
    fn matches(&self, attachment: &Attached, wall: u64, boot: u64) -> bool {
        self.current(boot)
            && attachment.service == self.target
            && boot < attachment.total_deadline
            && exact_attachment(
                &attachment.envelope,
                &self.envelope,
                (attachment.expires, attachment.deadline),
                (wall, boot),
            )
    }
    fn permission(
        &mut self,
        attachment_deadline: u64,
        refresh: impl FnOnce(&Renewal, u64) -> Result<u64>,
    ) -> Result<()> {
        let deadline = self.live.deadline.min(attachment_deadline);
        let setup = self.setup_deadline.min(deadline);
        crate::authority_local_transport::remaining(setup)?;
        if self.live.gate.expiry()? <= crate::authority_challenge::boot_time_ms()? {
            // The original Permit remains spent. Only its exact current permission is renewed.
            let expires = refresh(&self.live.renewal, setup)?;
            crate::authority_local_transport::remaining(setup)?;
            let expires = expires.min(deadline);
            self.live.gate.renew(expires)?;
            self.live.accepted_at = crate::authority_challenge::boot_time_ms()?;
        }
        Ok(())
    }
}
fn waiting_pair(
    waiting: &VecDeque<Waiting>,
    attachments: &VecDeque<Attached>,
    wall: u64,
    boot: u64,
) -> Option<(usize, usize)> {
    waiting.iter().enumerate().find_map(|(reader, waiting)| {
        attachments
            .iter()
            .position(|attachment| waiting.matches(attachment, wall, boot))
            .map(|attachment| (reader, attachment))
    })
}
fn pending_admission(
    pending: &VecDeque<Queued<Opened>>,
    waiting: &VecDeque<Waiting>,
) -> Option<(usize, bool)> {
    // A replacement needed by a retained reader gets the same bounded fairness turn as that reader.
    pending
        .iter()
        .position(|job| {
            job.request.open.attachment
                && waiting
                    .iter()
                    .any(|reader| reader.target == job.request.open.service)
        })
        .map(|index| (index, false))
        .or_else(|| {
            pending
                .iter()
                .position(|job| !job.request.open.attachment)
                .map(|index| (index, false))
        })
        .or_else(|| (!pending.is_empty()).then_some((0, true)))
}
fn useful_until(now: u64, expires: u64) -> u64 {
    now.saturating_add(expires.saturating_sub(now) / 2)
        .min(expires)
}
fn refresh_at(expires: u64, operation_budget: u64, accepted_at: Option<u64>) -> u64 {
    let predicted = expires.saturating_sub(operation_budget.saturating_add(DISPATCH_MS));
    match accepted_at {
        // An overdrawn prediction must leave some of the new proof's actual tail for useful work.
        // Insufficient capacity can still pause I/O at expiry; no hard deadline changes.
        Some(accepted) if predicted <= accepted => useful_until(accepted, expires),
        _ => predicted,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    Refresh,
    Admit,
    Wait,
}
#[derive(Default)]
struct AdmissionSchedule {
    reader_turn: bool,
}
impl AdmissionSchedule {
    fn choose(
        &self,
        now: u64,
        expires: Option<(u64, u64)>,
        renewal_budget: u64,
        operation_budget: u64,
        job: Option<(Digest, bool)>,
    ) -> Work {
        // Parked attachments carry no traffic. Replenishment must not occupy the requester
        // while a live reader needs renewal; an attachment required by a waiting reader is eligible.
        let job = job.filter(|(_, background)| !background || expires.is_none());
        let reader = job.is_some_and(|(_, attachment)| !attachment);
        let threatened = expires.is_some_and(|(expiry, accepted_at)| {
            let budget =
                renewal_budget.saturating_add(if job.is_some() { operation_budget } else { 0 });
            now >= refresh_at(expiry, budget, Some(accepted_at))
        });
        if threatened && !(reader && self.reader_turn) {
            Work::Refresh
        } else if job.is_some() {
            Work::Admit
        } else {
            Work::Wait
        }
    }
    fn refreshed(&mut self) {
        // A reader arriving during renewal also receives the next bounded admission turn.
        // This affects scheduling only: the unchanged Gate still pauses bytes at proof expiry.
        self.reader_turn = true;
    }
    fn admitted(&mut self, job: Option<(Digest, bool)>) {
        if job.is_some_and(|(_, attachment)| !attachment) {
            self.reader_turn = false;
        }
    }
}
fn total_deadline(started: u64, limits: Limits, expires: u64, now: u64, boot: u64) -> Result<u64> {
    let deadline = started
        .saturating_add(limits.duration_ms)
        .min(boot.saturating_add(expires.checked_sub(now).context("route consent expired")?));
    crate::authority_local_transport::remaining(deadline)?;
    Ok(deadline)
}
async fn ingress(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    network: Digest,
    incarnation: Digest,
    relay: Digest,
    limits: Limits,
) -> Result<Opened> {
    tokio::time::timeout(Duration::from_millis(limits.idle_ms), async {
        socket.set_nodelay(true).context(Refusal::Socket)?;
        let (socket, boundary) = route_io::Transport::new(
            socket,
            crate::authority_challenge::boot_time_ms()?.saturating_add(limits.duration_ms),
        );
        let mut stream = acceptor.accept(socket).await.context(Refusal::Tls)?;
        ensure!(
            stream.get_ref().1.alpn_protocol() == Some(route_tls::ALPN),
            "route client protocol differs"
        );
        let exporter =
            stream
                .get_ref()
                .1
                .export_keying_material([0; 32], protocol::EXPORTER, None)?;
        let open = Open::parse(
            &route_io::receive(&mut stream, protocol::FRAME)
                .await
                .context(Refusal::Open)?,
        )
        .context(Refusal::Open)?;
        ensure!(
            open.network == network && open.incarnation == incarnation && open.relay == relay,
            "route open has another network or relay"
        );
        let challenge = protocol::random()?;
        route_io::send(&mut stream, &protocol::challenge(challenge)?).await?;
        let proof = route_io::receive(&mut stream, protocol::FRAME)
            .await
            .context(Refusal::Proof)?;
        let signer = open
            .verify(challenge, exporter, &proof)
            .context(Refusal::Proof)?;
        let binding = wire::digest(&open.binding(challenge, exporter)?);
        Ok(Opened {
            stream: Box::new(stream),
            boundary,
            open,
            signer,
            connection: binding,
            binding,
            timing: None,
        })
    })
    .await
    .context(Refusal::Deadline)?
}
fn forwarding_limits(limits: Limits, deadline: u64) -> Result<Limits> {
    let duration_ms = limits
        .duration_ms
        .min(crate::authority_local_transport::remaining(deadline)?);
    let limits = Limits {
        duration_ms,
        idle_ms: limits.idle_ms.min(duration_ms),
        ..limits
    };
    limits.validate()?;
    Ok(limits)
}
async fn public(
    opened: Opened,
    endpoint: Digest,
    limits: Limits,
    deadline: u64,
    permission: route_io::Gate,
    timing: Timing,
) -> Result<()> {
    let limits = forwarding_limits(limits, deadline)?;
    opened.boundary.arm(permission.clone(), deadline)?;
    tokio::time::timeout(Duration::from_millis(limits.duration_ms), async {
        timing.mark(Phase::PublicDialStart);
        let destination = tokio::time::timeout(
            Duration::from_millis(limits.idle_ms),
            route_io::dial(endpoint),
        )
        .await??;
        timing.mark(Phase::PublicDialComplete);
        let mut stream = opened.stream;
        let limits = forwarding_limits(limits, deadline)?;
        route_io::guarded_send(
            &mut stream,
            &protocol::ready(opened.binding, limits)?,
            &permission,
            deadline,
            limits.idle_ms,
        )
        .await?;
        timing.mark(Phase::ReadyComplete);
        route_io::forward_guarded(stream, destination, limits, permission, deadline).await
    })
    .await?
}
async fn pair(
    opened: Opened,
    mut attachment: Attached,
    setup_deadline: u64,
    limits: Limits,
    deadline: u64,
    permission: route_io::Gate,
) -> Result<()> {
    let timing = opened.timing.unwrap_or(Timing {
        started: 0,
        sample: None,
    });
    let limits = forwarding_limits(limits, deadline)?;
    opened
        .boundary
        .arm(permission.clone(), deadline)
        .context(Phase::PairBinding)?;
    attachment
        .boundary
        .arm(permission.clone(), deadline)
        .context(Phase::PairBinding)?;
    // Pairing consumes the inert pool reservation; the reader's slot covers forwarding.
    drop(attachment.slot);
    tokio::time::timeout(Duration::from_millis(limits.duration_ms), async {
        let mut stream = opened.stream;
        route_io::guarded_send(
            &mut attachment.stream,
            &protocol::ready(attachment.binding, limits)?,
            &permission,
            deadline.min(setup_deadline),
            limits.idle_ms,
        )
        .await
        .context(Phase::AttachmentReady)?;
        let limits = forwarding_limits(limits, deadline)?;
        route_io::guarded_send(
            &mut stream,
            &protocol::ready(opened.binding, limits)?,
            &permission,
            deadline.min(setup_deadline),
            limits.idle_ms,
        )
        .await
        .context(Phase::ReaderReady)?;
        timing.mark(Phase::ReadyComplete);
        route_io::forward_guarded(stream, attachment.stream, limits, permission, deadline).await
    })
    .await?
}
async fn relay(
    config: &Config,
    guard: &Guard,
    active: &Active,
    acceptor: TlsAcceptor,
    client: &mut Client<'_>,
) -> Result<()> {
    let own = &config.profile;
    let capacity = usize::try_from(own.maximum_connections)?;
    let listener = TcpListener::bind(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        own.address.context("relay listener absent")?.port(),
    ))
    .await?;
    let network = config.manifest.network;
    let incarnation = config.manifest.incarnation;
    let relay = own.identity.service;
    let admitted_limits = own.limits;
    let mut incoming = listen(
        listener,
        capacity,
        own.limits.idle_ms,
        Some(|opened: &Opened| opened.open.attachment),
        move |socket| {
            ingress(
                socket,
                acceptor.clone(),
                network,
                incarnation,
                relay,
                admitted_limits,
            )
        },
    );
    let mut forwarding: JoinSet<(Digest, Result<()>)> = JoinSet::new();
    let mut live: BTreeMap<Digest, Live> = BTreeMap::new();
    let mut attachments: VecDeque<Attached> = VecDeque::new();
    let mut pending: VecDeque<Queued<Opened>> = VecDeque::new();
    let mut waiting: VecDeque<Waiting> = VecDeque::new();
    let mut schedule = AdmissionSchedule::default();
    let demand = Arc::new(tokio::sync::Notify::new());
    let mut tick = tokio::time::interval(Duration::from_millis(DISPATCH_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let outcome = async {
    loop {
        active.check(guard).context(Phase::RelayCurrent)?;
        let now = client.now().context(Phase::RelayClock)?;
        let boot = crate::authority_challenge::boot_time_ms()?;
        attachments.retain(|a| a.expires > now && a.deadline > boot && a.total_deadline > boot);
        while let Ok(job) = incoming.requests.try_recv() {
            pending.push_back(job);
        }
        while let Ok(job) = incoming.attachments.try_recv() {
            pending.push_back(job);
        }
        // Every queued stage retains its original socket, slot, transcript and absolute deadline.
        pending.retain(|job| {
            if job.deadline <= boot {
                incoming.diagnostics.refuse(Refusal::Deadline);
                false
            } else {
                true
            }
        });
        waiting.retain(|reader| {
            if reader.current(boot) {
                true
            } else {
                incoming.diagnostics.refuse(Refusal::AttachmentUnavailable);
                false
            }
        });
        let pairing = waiting_pair(&waiting, &attachments, now, boot);
        let next = pending_admission(&pending, &waiting);
        let job = pairing
            .map(|(index, _)| (waiting[index].opened.connection, false))
            .or_else(|| {
                next.map(|(index, background)| (pending[index].request.connection, background))
            })
            // An idle retained reader still suppresses speculative pool replenishment.
            .filter(|(_, background)| !background || live.is_empty());
        let renewal = live_renewal(&live)?;
        let work = schedule.choose(
            boot,
            renewal.map(|(_, expires)| expires),
            client.voucher_renewal_budget_ms(),
            client.operation_budget_ms(),
            job,
        );
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            result = incoming.tasks.join_next() => {
                result.context("route listener stopped")???;
                anyhow::bail!("route listener stopped");
            },
            result = forwarding.join_next(), if !forwarding.is_empty() => {
                let (id, result) = result.context("route forwarding task absent")??;
                if result.is_err() { incoming.diagnostics.refuse(Refusal::Forwarding); }
                live.remove(&id);
            },
            _ = std::future::ready(()), if work == Work::Refresh => {
                // Predict one full authority action before it can cross the next renewal's latest start.
                if let Some((id, _)) = renewal {
                    let session = live.get_mut(&id).context("live route disappeared")?;
                    let expiry = session.gate.expiry()?;
                    let timing = if session.renewals < 4 { session.timing } else { Timing::begin(boot, false) };
                    session.renewals = session.renewals.saturating_add(1);
                    timing.mark(Phase::RenewalStart);
                    if expiry <= crate::authority_challenge::boot_time_ms()? { timing.mark(Phase::RelayGuardExpired); }
                    let result = clock_checked(client.refresh(&session.renewal, session.deadline))
                        .context(Phase::RenewalAuthority)?;
                    timing.mark(if result.is_ok() { Phase::RenewalComplete } else { Phase::RenewalRefused });
                    if let Err(error) = &result { timing.failure(Phase::RenewalRefused, error); }
                    active.check(guard).context(Phase::RenewalCurrent)?;
                    if result.and_then(|expires| {
                        let expires = expires.min(session.deadline);
                        session.gate.renew(expires)?;
                        session.accepted_at = crate::authority_challenge::boot_time_ms()?;
                        Ok(())
                    }).is_ok() {
                        let now = crate::authority_challenge::boot_time_ms()?;
                        if expiry <= now { timing.mark(Phase::RelayGuardResumed); }
                        schedule.refreshed();
                    } else { live.remove(&id); }
                }
            },
            _ = std::future::ready(()), if work == Work::Admit => {
                schedule.admitted(job);
                if let Some((reader, attachment)) = pairing {
                    let mut reader = waiting.remove(reader).context("waiting reader disappeared")?;
                    let attachment = attachments.remove(attachment).context("matching attachment disappeared")?;
                    let permission = clock_checked(reader.permission(attachment.total_deadline, |renewal, deadline| client.refresh(renewal, deadline)))
                        .context(Phase::PairPermission)?;
                    active.check(guard).context(Phase::PairCurrent)?;
                    if let Err(error) = permission {
                        reader.live.timing.failure(Phase::PairPermission, &error);
                        incoming.diagnostics.refuse(Refusal::AdmissionExpired);
                        continue;
                    }
                    let wall = client.now().context(Phase::PairClock)?;
                    let boot = crate::authority_challenge::boot_time_ms()?;
                    if !reader.current(boot) {
                        incoming.diagnostics.refuse(Refusal::AttachmentUnavailable);
                        continue;
                    }
                    // A replacement can itself expire during renewal. Keep the same spent Permit and slot.
                    if !reader.matches(&attachment, wall, boot) {
                        waiting.push_back(reader);
                        continue;
                    }
                    let Waiting { opened, slot, setup_deadline, limits, live: mut session, .. } = reader;
                    let deadline = session.deadline.min(attachment.total_deadline);
                    session.deadline = deadline;
                    let permission = session.gate.clone();
                    let timing = session.timing;
                    let id = opened.connection;
                    ensure!(live.insert(id, session).is_none(), "live route identity was reused");
                    forwarding.spawn(async move {
                        let _slot = slot;
                        let result = pair(opened, attachment, setup_deadline, limits, deadline, permission).await;
                        timing.mark(if result.is_ok() { Phase::ForwardingComplete } else { Phase::ForwardingRefused });
                        if let Err(error) = &result { timing.failure(Phase::ForwardingRefused, error); }
                        (id, result)
                    });
                    continue;
                }
                if let Some(Queued { request: mut opened, slot, started, enqueued, deadline }) = next.and_then(|(index, _)| pending.remove(index)) {
                    let timing = *opened.timing.get_or_insert_with(|| {
                        let timing = Timing::begin(enqueued, !opened.open.attachment);
                        timing.mark(Phase::AdmissionQueue);
                        timing
                    });
                    if crate::authority_local_transport::remaining(deadline).is_err() { incoming.diagnostics.refuse(Refusal::Deadline); timing.mark(Phase::AdmissionRefused); continue; }
                    let admitted = clock_checked(client.admit(&opened.open, opened.signer, opened.connection, opened.binding, (started, deadline), timing))
                        .context(Phase::AdmissionAuthority)?;
                    active.check(guard).context(Phase::AdmissionCurrent)?;
                    let admission = match admitted {
                        Ok(Some(admission)) => { timing.mark(Phase::AdmissionComplete); admission },
                        Ok(None) => {
                            pending.push_back(Queued { request: opened, slot, started, enqueued, deadline });
                            continue;
                        },
                        Err(error) => { incoming.diagnostics.refuse(Refusal::Admission); timing.mark(Phase::AdmissionRefused); timing.failure(Phase::AdmissionRefused, &error); continue; },
                    };
                    {
                        let now = client.now().context(Phase::AdmissionClock)?;
                        let boot = crate::authority_challenge::boot_time_ms()?;
                        if boot >= deadline || now >= admission.expires { incoming.diagnostics.refuse(Refusal::AdmissionExpired); timing.mark(Phase::AdmissionExpired); continue; }
                        if opened.open.attachment {
                            if attachments.len() < capacity && attachments.iter().filter(|a| a.service == admission.target.identity.service).count() < admission.target.maximum_connections as usize {
                                // This socket is inert. Only a later current reader Permit can release bytes.
                                let expires = own.validity.1.min(admission.target.validity.1);
                                let Ok(deadline) = parking_deadline(started.saturating_add(admission.limits.idle_ms), expires, now, boot) else {
                                    incoming.diagnostics.refuse(Refusal::Deadline);
                                    continue;
                                };
                                let Ok(total_deadline) = total_deadline(started, admission.limits, admission.total_expires, now, boot) else { continue; };
                                attachments.push_back(Attached { stream: opened.stream, boundary: opened.boundary, service: admission.target.identity.service, envelope: admission.target.envelope, binding: opened.binding, expires, deadline, total_deadline, slot });
                            }
                        } else {
                            let setup_deadline = deadline;
                            let Ok(deadline) = total_deadline(started, admission.limits, admission.total_expires, now, boot) else { incoming.diagnostics.refuse(Refusal::AdmissionExpired); timing.mark(Phase::AdmissionExpired); continue; };
                            let permission = route_io::Gate::with_signal(boot.saturating_add(admission.expires - now).min(deadline), demand.clone());
                            let id = opened.connection;
                            let session = Live {
                                renewal: admission.renewal.context("reader admission omitted its renewal binding")?,
                                accepted_at: boot,
                                gate: permission.clone(), deadline, timing, renewals: 0,
                            };
                            if admission.target.mode == 3 {
                                waiting.push_back(Waiting { opened, slot, setup_deadline, limits: admission.limits,
                                    target: admission.target.identity.service, envelope: admission.target.envelope, live: session });
                                continue;
                            }
                            let destination = match config.dial(&admission.target.identity, admission.target.address.context("public route endpoint absent")?) {
                                Ok(address) => address,
                                Err(_) => { timing.mark(Phase::DestinationRefused); continue; }
                            };
                            let Ok(limits) = forwarding_limits(admission.limits, deadline) else { incoming.diagnostics.refuse(Refusal::AdmissionExpired); continue; };
                            ensure!(live.insert(id, session).is_none(), "live route identity was reused");
                            forwarding.spawn(async move {
                                let _slot = slot;
                                let result = public(opened, destination, limits, deadline, permission, timing).await;
                                timing.mark(if result.is_ok() { Phase::ForwardingComplete } else { Phase::ForwardingRefused });
                                if let Err(error) = &result { timing.failure(Phase::ForwardingRefused, error); }
                                (id, result)
                            });
                        }
                    }
                }
            },
            _ = demand.notified() => {},
            result = next_admission(&mut incoming.requests, &mut incoming.attachments) => {
                if let Some(job) = result { pending.push_back(job); }
            },
            _ = tick.tick() => {},
        }
    }
    Ok(())
    }.await;
    if let Err(error) = &outcome {
        eprintln!(
            "HyperNet private relay termination: phase={:?} reason={:?} freshReadCode={:?} bootMs={:?}",
            error.downcast_ref::<Phase>(),
            failure_code(error),
            error
                .downcast_ref::<crate::authority_local_transport::FreshReadUnavailable>()
                .map(|e| e.code),
            crate::authority_challenge::boot_time_ms().ok()
        );
    }
    live.clear();
    waiting.clear();
    attachments.clear();
    pending.clear();
    forwarding.abort_all();
    incoming.shutdown().await;
    drain(&mut forwarding).await;
    outcome
}
async fn endpoint_incoming(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    limits: Limits,
) -> Result<Session> {
    let start = crate::authority_challenge::boot_time_ms()?;
    let timing = Timing::begin(start, true);
    let result = tokio::time::timeout(Duration::from_millis(limits.idle_ms), async {
        socket.set_nodelay(true).context(Refusal::Socket)?;
        timing.mark(Phase::EndpointTlsStart);
        let (socket, boundary) =
            route_io::Transport::new(socket, start.saturating_add(limits.duration_ms));
        let stream = acceptor.accept(socket).await.context(Refusal::Tls)?;
        timing.mark(Phase::EndpointTlsComplete);
        ensure!(
            stream.get_ref().1.alpn_protocol() == Some(route_tls::ALPN),
            "private endpoint protocol differs"
        );
        let exporter = stream.get_ref().1.export_keying_material(
            [0; 32],
            crate::authority_domains::streams::protocol::EXPORTER,
            None,
        )?;
        Ok(Session {
            exporter,
            stream: Box::new(stream),
            boundary,
            deadline: start.saturating_add(limits.duration_ms),
            idle_ms: limits.idle_ms,
            bytes: limits.bytes,
            slot: None,
            timing,
            frames: 0,
        })
    })
    .await
    .context(Refusal::Deadline)
    .and_then(|result| result);
    if result.is_err() {
        timing.mark(Phase::EndpointRefused);
    }
    result
}
async fn attach(
    endpoint: Digest,
    relay: Identity,
    acceptor: TlsAcceptor,
    key: ed25519_dalek::SigningKey,
    open: Open,
    limits: Limits,
) -> Result<Session> {
    let start = crate::authority_challenge::boot_time_ms()?;
    let timing = Timing::begin(start, true);
    let outcome = tokio::time::timeout(Duration::from_millis(limits.duration_ms), async {
        let socket = tokio::time::timeout(
            Duration::from_millis(limits.idle_ms),
            route_io::dial(endpoint),
        )
        .await??;
        let (socket, boundary) =
            route_io::Transport::new(socket, start.saturating_add(limits.duration_ms));
        let connector = TlsConnector::from(route_tls::client(&relay)?);
        let mut outer = connector
            .connect(
                rustls::pki_types::ServerName::try_from(relay.server_name.clone())?,
                socket,
            )
            .await?;
        ensure!(
            outer.get_ref().1.alpn_protocol() == Some(route_tls::ALPN),
            "attachment relay protocol differs"
        );
        let exporter =
            outer
                .get_ref()
                .1
                .export_keying_material([0; 32], protocol::EXPORTER, None)?;
        route_io::send(&mut outer, &open.encode()?).await?;
        let challenge =
            protocol::parse_challenge(&route_io::receive(&mut outer, protocol::FRAME).await?)?;
        route_io::send(&mut outer, &open.sign(challenge, exporter, &key)?).await?;
        let binding = wire::digest(&open.binding(challenge, exporter)?);
        let admitted = protocol::parse_ready(
            &route_io::receive(&mut outer, protocol::FRAME)
                .await
                .context(Phase::AttachmentAdmission)?,
            binding,
            limits,
        )?;
        let ready = crate::authority_challenge::boot_time_ms()?;
        let inner = tokio::time::timeout(
            Duration::from_millis(admitted.idle_ms),
            acceptor.accept(outer),
        )
        .await??;
        ensure!(
            inner.get_ref().1.alpn_protocol() == Some(route_tls::ALPN),
            "attached endpoint protocol differs"
        );
        let exporter = inner.get_ref().1.export_keying_material(
            [0; 32],
            crate::authority_domains::streams::protocol::EXPORTER,
            None,
        )?;
        Ok(Session {
            exporter,
            stream: Box::new(inner),
            boundary,
            deadline: start
                .saturating_add(limits.duration_ms)
                .min(ready.saturating_add(admitted.duration_ms)),
            idle_ms: limits.idle_ms.min(admitted.idle_ms),
            bytes: limits.bytes.min(admitted.bytes),
            slot: None,
            timing,
            frames: 0,
        })
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    if let Err(error) = &outcome {
        timing.failure(Phase::AttachmentRefused, error);
    }
    outcome
}
async fn next_packet(mut session: Session, permission: route_io::Gate) -> Result<Request> {
    let maximum = usize::try_from(session.bytes.saturating_sub(4))?.min(wire::MAXIMUM);
    let packet = tokio::select! {
        packet = tokio::time::timeout(session.wait()?, route_io::receive(&mut session.stream, maximum)) => packet??,
        _ = permission.closed() => anyhow::bail!("endpoint permission closed"),
    };
    session.charge(packet.len())?;
    session.frames = session.frames.saturating_add(1);
    session.mark(Phase::RequestReceived);
    Ok(Request { session, packet })
}
async fn ready_session(
    mut session: Session,
    ready: Vec<u8>,
    permission: route_io::Gate,
) -> Result<Request> {
    // A checked proof can expire before this task runs. Bind its renewable guard
    // before any readiness write; guarded_send waits within the original limits.
    session
        .boundary
        .arm_renewable(permission.clone(), session.deadline)
        .inspect_err(|_| session.mark(Phase::EndpointReadyBindingRefused))?;
    session
        .charge(ready.len())
        .inspect_err(|_| session.mark(Phase::EndpointReadyBudgetRefused))?;
    route_io::guarded_send(
        &mut session.stream,
        &ready,
        &permission,
        session.deadline,
        session.idle_ms,
    )
    .await
    .inspect_err(|_| session.mark(Phase::EndpointReadyWriteRefused))?;
    session.mark(Phase::EndpointReadyComplete);
    next_packet(session, permission).await
}
fn application_path(protocol: u64) -> &'static Path {
    Path::new(if protocol == 1 {
        "/Authority/Control.sock"
    } else {
        "/Application/Control.sock"
    })
}
async fn session_requests(
    session: Session,
    ready: Vec<u8>,
    scope: (u64, Digest, Digest),
    permission: route_io::Gate,
) -> Result<Request> {
    let request = ready_session(session, ready, permission.clone()).await?;
    if scope.0 == 6 {
        return Ok(request);
    }
    ordinary_requests(request, scope, permission, application_path(scope.0)).await
}
async fn ordinary_requests(
    mut request: Request,
    scope: (u64, Digest, Digest),
    permission: route_io::Gate,
    path: &Path,
) -> Result<Request> {
    loop {
        request.session.mark(Phase::RequestDequeued);
        route_endpoint::validate_packet(scope.0, scope.1, scope.2, &request.packet)?;
        let deadline = request.session.deadline;
        let packet = request.packet.clone();
        request = response_at(request, packet, scope.0, permission.clone(), deadline, path).await?;
    }
}
async fn response(
    request: Request,
    packet: Vec<u8>,
    protocol: u64,
    permission: route_io::Gate,
    effect_deadline: u64,
) -> Result<Request> {
    response_at(
        request,
        packet,
        protocol,
        permission,
        effect_deadline,
        application_path(protocol),
    )
    .await
}
async fn response_at(
    mut request: Request,
    packet: Vec<u8>,
    protocol: u64,
    permission: route_io::Gate,
    effect_deadline: u64,
    path: &Path,
) -> Result<Request> {
    let activity = permission.activity()?;
    let session = &mut request.session;
    let pending = tokio::time::timeout(
        Duration::from_millis(
            crate::authority_local_transport::remaining(effect_deadline)?.min(session.idle_ms),
        ),
        async {
            let mut local = route_io::local(path).await?;
            // Every local application write is subject to the same current role guard.
            route_io::guarded_send(
                &mut local,
                &packet,
                &permission,
                effect_deadline,
                session.idle_ms,
            )
            .await?;
            route_io::receive(&mut local, 4 * wire::MAXIMUM).await
        },
    );
    let reply = tokio::select! {
        result = pending => result??,
        _ = permission.closed() => anyhow::bail!("endpoint permission closed"),
    };
    session.mark(Phase::LocalReply);
    session.charge(reply.len())?;
    route_io::guarded_send(
        &mut session.stream,
        &reply,
        &permission,
        effect_deadline,
        session.idle_ms,
    )
    .await?;
    session.mark(Phase::ResponseFlushed);
    // A Pending result is still an active exchange while its next poll crosses
    // the relay. Keep renewal demand through this existing bounded read only.
    // Terminal replies release it before an idle session waits for new work.
    let pending = protocol == 1 && route_endpoint::authority_request_pending(&packet, &reply);
    let activity = pending.then_some(activity);
    let next = next_packet(request.session, permission).await;
    drop(activity);
    next
}
struct EndpointPermission {
    gate: route_io::Gate,
    accepted_at: Option<u64>,
    renewals: u64,
}
impl Drop for EndpointPermission {
    fn drop(&mut self) {
        self.gate.close();
    }
}
impl EndpointPermission {
    fn refresh_due(&self, now: u64, budget: u64) -> Result<bool> {
        Ok(
            self.gate.demanded()
                && now >= refresh_at(self.gate.expiry()?, budget, self.accepted_at),
        )
    }
    fn current(&mut self, client: &mut Client<'_>, deadline: u64) -> Result<()> {
        self.prepare(deadline, client.own_renewal_budget_ms(), |deadline| {
            client.before(deadline, |client| client.own())?;
            client.effect_deadline()
        })
    }
    fn prepare(
        &mut self,
        deadline: u64,
        budget: u64,
        refresh: impl FnOnce(u64) -> Result<u64>,
    ) -> Result<()> {
        crate::authority_local_transport::remaining(deadline)?;
        if crate::authority_challenge::boot_time_ms()?
            >= refresh_at(
                self.gate.expiry()?,
                budget.saturating_mul(2),
                self.accepted_at,
            )
        {
            // Readiness reserves one application action before the next renewal's latest start.
            self.renew(deadline, refresh)?;
        }
        Ok(())
    }
    fn before_action(&mut self, client: &mut Client<'_>, deadline: u64) -> Result<()> {
        // A bridge frame uses the same scheduling margin; its own Reader proof remains mandatory.
        self.current(client, deadline)
    }
    fn refresh(&mut self, client: &mut Client<'_>, deadline: u64) -> Result<()> {
        self.renew(deadline, |deadline| {
            client.before(deadline, |client| client.own())?;
            client.effect_deadline()
        })
    }
    fn renew(&mut self, deadline: u64, refresh: impl FnOnce(u64) -> Result<u64>) -> Result<()> {
        let old_expiry = self.gate.expiry()?;
        let sample = if self.renewals < 64 {
            Some(self.renewals + 1)
        } else {
            None
        };
        self.renewals = self.renewals.saturating_add(1);
        if let Some(sample) = sample {
            eprintln!(
                "HyperNet private route endpoint renewal: sample={sample} stage={:?} oldExpiryBootMs={old_expiry} bootMs={:?}",
                Phase::EndpointRenewalStart,
                crate::authority_challenge::boot_time_ms().ok()
            );
        }
        let outcome = (|| {
            let expiry = refresh(deadline)?;
            crate::authority_local_transport::remaining(deadline)?;
            self.gate.renew(expiry)?;
            self.accepted_at = Some(crate::authority_challenge::boot_time_ms()?);
            Ok(expiry)
        })();
        if let Some(sample) = sample {
            eprintln!(
                "HyperNet private route endpoint renewal: sample={sample} stage={:?} oldExpiryBootMs={old_expiry} newExpiryBootMs={:?} reason={:?} bootMs={:?}",
                if outcome.is_ok() {
                    Phase::EndpointRenewalComplete
                } else {
                    Phase::EndpointRenewalRefused
                },
                outcome.as_ref().ok(),
                outcome.as_ref().err().map(failure_code),
                crate::authority_challenge::boot_time_ms().ok()
            );
        }
        outcome.map(|_| ())
    }
}
fn endpoint_packet(
    client: &mut Client<'_>,
    own: &routes::RegisteredProfile,
    request: &Request,
) -> Result<(Vec<u8>, u64)> {
    ensure!(
        own.protocol == 6,
        "only bridge reads require per-frame route authority"
    );
    client.before(request.session.deadline, |client| {
        let packet = client.reader(&request.packet)?;
        Ok((
            packet,
            request.session.deadline.min(client.effect_deadline()?),
        ))
    })
}

async fn endpoint(
    config: &Config,
    guard: &Guard,
    active: &Active,
    acceptor: TlsAcceptor,
    client: &mut Client<'_>,
) -> Result<()> {
    if config.profile.protocol == crate::authority_domains::streams::PROTOCOL {
        return application_streams::endpoint(config, guard, active, acceptor, client).await;
    }
    let own = &config.profile;
    let capacity = usize::try_from(own.maximum_connections)?;
    let expiry = client.effect_deadline()?;
    let mut permission = EndpointPermission {
        gate: route_io::Gate::new(expiry),
        accepted_at: None,
        renewals: 0,
    };
    let demand = permission.gate.signal();
    let ready = protocol::endpoint_ready(
        config.manifest.network,
        config.manifest.incarnation,
        own.identity.service,
        own.protocol,
    )?;
    let relay = if let Some((identity, address)) = &config.relay {
        let current = client.lookup(identity.service)?;
        ensure!(
            current.mode == 1 && current.identity == *identity && current.address == Some(*address),
            "attachment relay registration differs from local consent"
        );
        Some((identity.clone(), config.dial(identity, *address)?))
    } else {
        None
    };
    let mut listener = if own.mode == 2 {
        let listener = TcpListener::bind(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            own.address.context("endpoint listener absent")?.port(),
        ))
        .await?;
        let acceptor = acceptor.clone();
        let limits = own.limits;
        Some(listen(
            listener,
            capacity,
            limits.idle_ms,
            None,
            move |socket| endpoint_incoming(socket, acceptor.clone(), limits),
        ))
    } else {
        None
    };
    let scope = (
        own.protocol,
        config.manifest.network,
        config.manifest.incarnation,
    );
    let mut incoming = JoinSet::new();
    let mut responses: JoinSet<Result<Request>> = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(DISPATCH_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut retry_after = tokio::time::Instant::now();
    let outcome = async {
    loop {
        active.check(guard)?;
        if let Some((identity, address)) = &relay {
            while incoming.len() + responses.len() < capacity
                && tokio::time::Instant::now() >= retry_after
            {
                let open = Open {
                    network: config.manifest.network,
                    incarnation: config.manifest.incarnation,
                    relay: identity.service,
                    service: own.identity.service,
                    voucher: vec![],
                    nonce: protocol::random()?,
                    attachment: true,
                };
                incoming.spawn(attach(
                    *address,
                    identity.clone(),
                    acceptor.clone(),
                    config.key.clone(),
                    open,
                    own.limits,
                ));
            }
        }
        let public = listener.is_some();
        let (listener_tasks, listener_requests) = listener
            .as_mut()
            .map(|listener| (&mut listener.tasks, &mut listener.requests))
            .unzip();
        let refresh_due = permission.refresh_due(
            crate::authority_challenge::boot_time_ms()?, client.own_renewal_budget_ms())?;
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            result = responses.join_next(), if !responses.is_empty() => {
                if let Some(Ok(Ok(request))) = result {
                    request.session.mark(Phase::RequestDequeued);
                    if crate::authority_local_transport::remaining(request.session.deadline).is_err() { continue; }
                    permission.before_action(client, request.session.deadline)?;
                    let packet = clock_checked(endpoint_packet(client, own, &request))?;
                    active.check(guard)?;
                    if let Ok((packet, deadline)) = packet {
                        responses.spawn(response(request, packet, own.protocol, permission.gate.clone(), deadline));
                    }
                }
            },
            stopped = async { listener_tasks.expect("enabled endpoint listener").join_next().await }, if public => {
                stopped.context("private endpoint listener stopped")???;
                anyhow::bail!("private endpoint listener stopped");
            },
            request = async { listener_requests.expect("enabled endpoint listener").recv().await }, if public => {
                if let Some(Queued { mut request, slot, deadline, started, .. }) = request {
                    if crate::authority_local_transport::remaining(deadline).is_err() { continue; }
                    request.deadline = request.deadline.min(started.saturating_add(own.limits.duration_ms));
                    request.mark(Phase::EndpointReadyStart);
                    permission.current(client, deadline)?;
                    active.check(guard)?;
                    request.slot = Some(slot);
                    responses.spawn(session_requests(request, ready.clone(), scope, permission.gate.clone()));
                }
            },
            result = incoming.join_next(), if !incoming.is_empty() => {
                if let Some(Ok(Ok(session))) = result {
                    session.mark(Phase::EndpointReadyStart);
                    permission.current(client, session.deadline)?;
                    active.check(guard)?;
                    responses.spawn(session_requests(session, ready.clone(), scope, permission.gate.clone()));
                } else { retry_after = tokio::time::Instant::now() + Duration::from_millis(own.limits.idle_ms.min(1000)); }
            },
            _ = std::future::ready(()), if refresh_due => {
                // Only this exact deployed endpoint role shares the proof; application checks remain separate.
                let deadline = crate::authority_challenge::boot_time_ms()?.saturating_add(own.limits.idle_ms);
                permission.refresh(client, deadline)?;
                active.check(guard)?;
            },
            _ = demand.notified() => {},
            _ = tick.tick() => {},
        }
    }
    Ok(())
    }.await;
    permission.gate.close();
    incoming.abort_all();
    responses.abort_all();
    if let Some(listener) = &mut listener {
        listener.shutdown().await;
    }
    drain(&mut incoming).await;
    drain(&mut responses).await;
    outcome
}
// A failed connection read closes only that connection. Other gates retain their
// exact expiry. An expired ordinary challenge requires exact requester recovery.
fn clock_checked<T>(outcome: Result<T>) -> Result<Result<T>> {
    match outcome {
        Err(error)
            if error.is::<crate::consensus_clock::ObservationExpired>()
                || (error.is::<crate::authority_challenge::ChallengeExpired>()
                    && !error.is::<ReadRetry>()) =>
        {
            Err(error)
        }
        outcome => Ok(outcome),
    }
}
async fn wait_for_clock(
    check: impl FnMut() -> Result<()>,
    stopping: impl Future<Output = ()>,
) -> Result<bool> {
    wait_for_retry(check, stopping, Duration::ZERO).await
}
async fn wait_for_retry(
    mut check: impl FnMut() -> Result<()>,
    stopping: impl Future<Output = ()>,
    delay: Duration,
) -> Result<bool> {
    tokio::pin!(stopping);
    let retry_at = tokio::time::Instant::now() + delay;
    loop {
        match check() {
            Ok(()) if tokio::time::Instant::now() >= retry_at => return Ok(true),
            Ok(()) => {}
            Err(error) if error.is::<crate::consensus_clock::ObservationExpired>() => {}
            Err(error) => return Err(error),
        }
        tokio::select! {
            biased;
            _ = &mut stopping => return Ok(false),
            _ = tokio::time::sleep(Duration::from_millis(DISPATCH_MS)) => {},
        }
    }
}
pub async fn run(config: Config, guard: &Guard, active: &Active) -> Result<()> {
    ensure!(
        guard.role == 5 && guard.manifest == config.manifest,
        "route activation differs from exact local consent"
    );
    let acceptor = TlsAcceptor::from(route_tls::server(
        &config.profile.identity,
        &files::read(Path::new("/Config/Certificate.pem"), 65536, true)?,
        &zeroize::Zeroizing::new(files::read(
            Path::new("/Config/Transport.key"),
            16384,
            true,
        )?),
    )?);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        let outcome = async {
            active.check(guard)?;
            let mut client = Client::open(&config, guard, active)?;
            client.own()?;
            if config.profile.mode == 1 {
                relay(&config, guard, active, acceptor.clone(), &mut client).await
            } else {
                endpoint(&config, guard, active, acceptor.clone(), &mut client).await
            }
        }
        .await;
        match outcome {
            Err(error) if error.is::<crate::consensus_clock::ObservationExpired>() => {
                // All previous sockets and tasks are gone. Only the original consent may resume.
                eprintln!(
                    "HyperNet private route clock: Suspended phase={:?} bootMs={:?}",
                    error.downcast_ref::<Phase>(),
                    crate::authority_challenge::boot_time_ms().ok()
                );
                let resumed = wait_for_clock(
                    || {
                        active.check_local(guard)?;
                        guard.check_configuration()?;
                        active.check(guard)
                    },
                    async {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {},
                            _ = terminate.recv() => {},
                        }
                    },
                )
                .await?;
                if !resumed {
                    return Ok(());
                }
                eprintln!(
                    "HyperNet private route clock: FreshObservation bootMs={:?}",
                    crate::authority_challenge::boot_time_ms().ok()
                );
            }
            Err(error)
                if error.is::<ReadRetry>()
                    || error.is::<crate::authority_challenge::ChallengeExpired>() =>
            {
                // No admission survives. Reopening retains the exact pending ordinary request;
                // a fresh challenge cannot replace its sequence or restore a consumed admission.
                eprintln!(
                    "HyperNet private route authority: Suspended reason={:?} failure={:?} bootMs={:?}",
                    error.downcast_ref::<ReadRetry>(),
                    failure_code(&error),
                    crate::authority_challenge::boot_time_ms().ok()
                );
                let resumed = wait_for_retry(
                    || {
                        active.check_local(guard)?;
                        guard.check_configuration()?;
                        active.check(guard)
                    },
                    async {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {},
                            _ = terminate.recv() => {},
                        }
                    },
                    Duration::from_millis(READ_RETRY_MS),
                )
                .await?;
                if !resumed {
                    return Ok(());
                }
                eprintln!(
                    "HyperNet private route authority: FreshAttempt bootMs={:?}",
                    crate::authority_challenge::boot_time_ms().ok()
                );
            }
            outcome => {
                if let Err(error) = &outcome {
                    eprintln!(
                        "HyperNet private route stopped: phase={:?} reason={:?} bootMs={:?}",
                        error.downcast_ref::<Phase>(),
                        failure_code(error),
                        crate::authority_challenge::boot_time_ms().ok()
                    );
                }
                return outcome;
            }
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteTests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteAcceptTests.rs"]
mod accept_tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteClockTests.rs"]
mod clock_tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteRuntimeDiagnosticTests.rs"]
mod diagnostic_tests;
