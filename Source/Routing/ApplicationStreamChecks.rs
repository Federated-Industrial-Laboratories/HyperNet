// SPDX-License-Identifier: MIT
// A separate bounded local connection carries checks, never application payload or authority mutation.
use super::*;
use crate::authority_domains::streams::control::{
    self, Cancel, Challenge, Disposition, Privacy, Ready, Receipt, Request,
};
use crate::route_authority::{PreparedRead, ReadCompletion, ReadStage};
use std::sync::atomic::AtomicBool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

static CHECK_SAMPLES: AtomicU64 = AtomicU64::new(0);
static NEXT_CHECK_SAMPLE: AtomicU64 = AtomicU64::new(0);
pub(super) fn sample_check(now: u64, samples: &AtomicU64, next: &AtomicU64) -> Timing {
    let sample = if samples.load(Ordering::Relaxed) < 256
        && next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |due| {
                if now >= due {
                    now.checked_add(1000)
                } else {
                    None
                }
            })
            .is_ok()
    {
        Timing::counted(now, samples, 256).sample
    } else {
        None
    };
    Timing {
        started: now,
        sample,
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    Enqueued,
    Dequeued,
    EndpointPreparation,
    StreamPreparation,
    FreshRead,
    ExchangeStart,
    ExchangeComplete,
    FinalizeStart,
    DomainStart,
    DomainComplete,
    PublishStart,
    PublishComplete,
    Outcome,
}
pub(super) struct ExchangeCompletion {
    pub result: Result<ReadCompletion>,
    pub started: Option<u64>,
    pub completed: Option<u64>,
}
impl ExchangeCompletion {
    pub(super) fn capture(
        sampled: bool,
        mut clock: impl FnMut() -> Result<u64>,
        exchange: impl FnOnce() -> Result<ReadCompletion>,
    ) -> Self {
        let started = sampled.then(|| clock().ok()).flatten();
        let result = exchange();
        let completed = sampled.then(|| clock().ok()).flatten();
        Self {
            result,
            started,
            completed,
        }
    }
}
pub(super) struct Check {
    pub request: Request,
    pub ready: Arc<Ready>,
    pub connected: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
    pub reply: oneshot::Sender<Receipt>,
    pub timing: Option<Timing>,
    pub _slot: OwnedSemaphorePermit,
}
pub(super) enum Preparation {
    Ready,
    Complete(Box<Receipt>),
}
pub(super) struct Pending {
    pub check: Check,
    pub read: PreparedRead,
}
struct Connection(Arc<AtomicBool>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct Reader(tokio::task::JoinHandle<()>);
impl Drop for Reader {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) fn unavailable(request: Request, privacy: Privacy, disposition: Disposition) -> Receipt {
    Receipt {
        not_after_boot_ms: request.caller_deadline_boot_ms,
        request,
        disposition,
        authority: None,
        privacy,
    }
}
pub(super) async fn run(
    binding: local::Binding,
    key: ed25519_dalek::SigningKey,
    boot: String,
    privacy: Privacy,
    queue: mpsc::Sender<Check>,
    endpoint_gate: route_io::Gate,
) {
    let Ok(instance) = protocol::random() else {
        return;
    };
    let mut previous: Option<Challenge> = None;
    // A permit follows a check from admission through finalization, including
    // cancelled workers left draining across control-generation changes.
    let slots = Arc::new(Semaphore::new(control::MAXIMUM_PENDING));
    loop {
        let attempt = link(
            &binding,
            &key,
            &boot,
            &privacy,
            instance,
            &queue,
            &slots,
            &mut previous,
        );
        tokio::select! {
            _ = endpoint_gate.closed() => return,
            _ = attempt => {},
        }
        // A missing optional socket leaves old companions' opaque payload workflows intact.
        tokio::select! {
            _ = endpoint_gate.closed() => return,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {},
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn link(
    binding: &local::Binding,
    key: &ed25519_dalek::SigningKey,
    boot: &str,
    privacy: &Privacy,
    instance: Digest,
    queue: &mpsc::Sender<Check>,
    slots: &Arc<Semaphore>,
    previous: &mut Option<Challenge>,
) -> Result<()> {
    let mut socket = tokio::time::timeout(
        Duration::from_millis(control::MAXIMUM_CHECK_MS),
        route_io::local(Path::new("/Application/Checks.sock")),
    )
    .await??;
    let challenge: Challenge = control::parse(
        &tokio::time::timeout(
            Duration::from_millis(control::MAXIMUM_CHECK_MS),
            route_io::receive(&mut socket, control::MAXIMUM_FRAME),
        )
        .await??,
    )?;
    ensure!(
        challenge.binding_digest == binding.digest()? && challenge.kernel_boot == boot,
        "application check binding or host boot differs"
    );
    if let Some(old) = previous.as_ref() {
        ensure!(
            old.companion_instance != challenge.companion_instance
                || (challenge.control_generation > old.control_generation
                    && challenge.nonce != old.nonce),
            "application check control generation did not advance"
        );
    }
    let ready = Arc::new(Ready {
        challenge: challenge.clone(),
        endpoint_instance: instance,
        monotonic_offset_ns: 0,
        boottime_offset_ns: 0,
        capabilities: vec![control::CAPABILITY.into()],
        privacy: privacy.clone(),
    });
    tokio::time::timeout(
        Duration::from_millis(control::MAXIMUM_CHECK_MS),
        route_io::send(&mut socket, &control::sign(ready.as_ref(), binding, key)?),
    )
    .await??;
    *previous = Some(challenge);
    exchange(socket, ready, binding, key, queue, slots).await
}
pub(super) async fn exchange(
    socket: tokio::net::UnixStream,
    ready: Arc<Ready>,
    binding: &local::Binding,
    key: &ed25519_dalek::SigningKey,
    queue: &mpsc::Sender<Check>,
    slots: &Arc<Semaphore>,
) -> Result<()> {
    let privacy = &ready.privacy;
    let connected = Connection(Arc::new(AtomicBool::new(true)));
    let (mut reader, mut writer) = socket.into_split();
    let (frames, mut input) = mpsc::channel(control::MAXIMUM_PENDING);
    let _reader = Reader(tokio::spawn(async move {
        while let Ok(frame) = route_io::receive(&mut reader, control::MAXIMUM_FRAME).await {
            if frames.send(frame).await.is_err() {
                break;
            }
        }
    }));
    let mut pending: BTreeMap<Digest, (Request, Arc<AtomicBool>)> = BTreeMap::new();
    let mut replies = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            frame = input.recv() => {
                let frame = frame.context("application check connection closed")?;
                if let Ok(cancel) = control::parse::<Cancel>(&frame) {
                    cancel.request.matches_ready(&ready)?;
                    if let Some((request, cancelled)) = pending.get(&cancel.request.nonce) {
                        ensure!(*request == cancel.request, "application check cancellation differs");
                        cancelled.store(true, Ordering::Release);
                    }
                    continue;
                }
                let request: Request = control::parse(&frame)?;
                request.matches_ready(&ready)?;
                ensure!(!pending.contains_key(&request.nonce), "duplicate pending application check nonce");
                if pending.len() >= control::MAXIMUM_PENDING || pending.values().any(|(old,_)| old.local_connection_id == request.local_connection_id || old.session.id == request.session.id) {
                    let receipt = unavailable(request, privacy.clone(), Disposition::Unavailable);
                    tokio::time::timeout(Duration::from_millis(1000), route_io::send(&mut writer, &control::sign(&receipt, binding, key)?)).await??;
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    let receipt = unavailable(request, privacy.clone(), Disposition::Unavailable);
                    tokio::time::timeout(Duration::from_millis(1000), route_io::send(&mut writer, &control::sign(&receipt, binding, key)?)).await??;
                    continue;
                };
                let Ok(slot) = queue.try_reserve() else {
                    let receipt = unavailable(request, privacy.clone(), Disposition::Unavailable);
                    tokio::time::timeout(Duration::from_millis(1000), route_io::send(&mut writer, &control::sign(&receipt, binding, key)?)).await??;
                    continue;
                };
                let cancelled = Arc::new(AtomicBool::new(false));
                let (reply, receiver) = oneshot::channel();
                let timing = DIAGNOSTICS.get().is_some_and(Option::is_some)
                    .then(|| crate::authority_challenge::boot_time_ms().ok())
                    .flatten()
                    .map(|now| sample_check(now, &CHECK_SAMPLES, &NEXT_CHECK_SAMPLE));
                let check = Check { request: request.clone(), ready: ready.clone(), connected: connected.0.clone(), cancelled: cancelled.clone(), reply, timing, _slot: permit };
                check.record(Stage::Enqueued, None, None);
                slot.send(check);
                pending.insert(request.nonce, (request.clone(), cancelled.clone()));
                replies.spawn(async move { (request.nonce, cancelled, receiver.await) });
            },
            result = replies.join_next(), if !replies.is_empty() => {
                let (nonce, cancelled, receipt) = result.context("application check worker stopped")??;
                pending.remove(&nonce);
                if !cancelled.load(Ordering::Acquire) && let Ok(receipt) = receipt {
                    let remaining = crate::authority_local_transport::remaining(receipt.request.caller_deadline_boot_ms);
                    if let Ok(remaining) = remaining {
                        tokio::time::timeout(Duration::from_millis(remaining), route_io::send(&mut writer, &control::sign(&receipt, binding, key)?)).await??;
                    }
                }
            },
        }
    }
}

pub(super) fn prepare(
    check: &Check,
    live: &mut BTreeMap<Digest, LiveStream>,
    permission: &mut EndpointPermission,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Result<Preparation> {
    let request = &check.request;
    let privacy = check.ready.privacy.clone();
    check.record(Stage::Dequeued, None, None);
    let now = crate::authority_challenge::boot_time_ms()?;
    if now >= request.caller_deadline_boot_ms || request.caller_started_boot_ms > now {
        return Ok(Preparation::Complete(Box::new(unavailable(
            request.clone(),
            privacy,
            Disposition::Expired,
        ))));
    }
    check.request.matches_ready(&check.ready)?;
    let stream = live
        .get_mut(&request.session.id)
        .ok_or(InactiveStream::Missing)?;
    ensure!(
        stream.reference == request.session,
        InactiveStream::ReferenceChanged
    );
    stream.preparation_deadline(now)?;
    check.current(guard, active)?;
    // Readiness maintenance precedes the separate fresh check. It never supplies
    // the check result or replaces its original caller/challenge deadline.
    let preparation_end = request
        .caller_deadline_boot_ms
        .min(stream.forwarding.deadline);
    permission.prepare(
        preparation_end,
        client.own_renewal_budget_ms(),
        |deadline| {
            check.current(guard, active)?;
            check.record(Stage::EndpointPreparation, None, None);
            client.before_check(deadline, request.caller_started_boot_ms, |client| {
                client.own()
            })?;
            check.current(guard, active)?;
            client.effect_deadline()
        },
    )?;
    let reference = stream.reference.clone();
    stream.prepare_check(
        preparation_end,
        client.stream_renewal_budget_ms(),
        || !check.connected.load(Ordering::Acquire) || check.cancelled.load(Ordering::Acquire),
        |deadline| {
            check.current(guard, active)?;
            check.record(Stage::StreamPreparation, None, None);
            let expiry =
                client.before_check(deadline, request.caller_started_boot_ms, |client| {
                    client.stream_permit(&reference)
                })?;
            check.current(guard, active)?;
            Ok(expiry)
        },
    )?;
    check.current(guard, active)?;
    Ok(Preparation::Ready)
}

// Capture the initial batch. Only issue-only slots may join before its first completion.
pub(super) fn cohort(first: Check, queue: &mut mpsc::Receiver<Check>) -> Vec<Check> {
    let mut checks = Vec::with_capacity(control::MAXIMUM_PENDING);
    checks.push(first);
    while checks.len() < control::MAXIMUM_PENDING {
        let Ok(check) = queue.try_recv() else { break };
        checks.push(check);
    }
    checks
}

#[derive(Debug)]
struct EndpointPermissionExpired;
impl std::fmt::Display for EndpointPermissionExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("application endpoint permission expired")
    }
}
impl std::error::Error for EndpointPermissionExpired {}

pub(super) fn needs_preparation(error: &anyhow::Error) -> bool {
    error.is::<EndpointPermissionExpired>()
        || error.downcast_ref::<InactiveStream>() == Some(&InactiveStream::GateExpired)
}

pub(super) fn issue_current(
    check: &Check,
    end: u64,
    live: &BTreeMap<Digest, LiveStream>,
    permission: &EndpointPermission,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Result<PreparedRead> {
    check.record(Stage::Dequeued, None, None);
    // This path may sign a new challenge, but never prepares gates or recovers
    // ordinary effects. All existing issue checks remain authoritative.
    client.before(end, |client| {
        issue(check, live, permission, client, guard, active)
    })
}

pub(super) fn issue(
    check: &Check,
    live: &BTreeMap<Digest, LiveStream>,
    permission: &EndpointPermission,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Result<PreparedRead> {
    // Captured members have finished readiness work. Later issue-only members
    // must use already-current gates; neither path can renew this call here.
    check.current(guard, active)?;
    let now = crate::authority_challenge::boot_time_ms()?;
    let stream = check.completion_stream(live, permission, now)?;
    let stream_deadline = stream.current_deadline(now)?;
    let clock = guard.application_clock()?;
    ensure!(
        clock.kernel_boot == check.ready.challenge.kernel_boot,
        "application check host boot changed"
    );
    active.check(guard)?;
    let request = &check.request;
    let deadline = clock.read_deadline(
        request
            .caller_deadline_boot_ms
            .min(stream_deadline)
            .min(permission.gate.expiry()?),
    );
    check.record(Stage::FreshRead, None, None);
    client.before(deadline, |client| {
        client.prepare_check_stream(&request.session, request.caller_started_boot_ms)
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish(
    check: &Check,
    read: PreparedRead,
    completion: Result<ReadCompletion>,
    live: &mut BTreeMap<Digest, LiveStream>,
    permission: &mut EndpointPermission,
    profile: &[u8],
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Receipt {
    check.record(Stage::FinalizeStart, None, None);
    // Revalidate before consuming the challenge or publishing learned state.
    let context = check.current(guard, active).and_then(|()| {
        check
            .completion_stream(
                live,
                permission,
                crate::authority_challenge::boot_time_ms()?,
            )
            .map(|_| ())
    });
    if let Err(error) = context {
        let discarded = client.discard_read(read);
        return check.complete(discarded.and(Err(error)));
    }
    let deadline = read.deadline();
    let result = (|| -> Result<Receipt> {
        let observation =
            client.finish_check_stream(read, completion, &check.request.session, |stage| {
                let stage = match stage {
                    ReadStage::DomainStart => Stage::DomainStart,
                    ReadStage::DomainComplete => Stage::DomainComplete,
                    ReadStage::PublishStart => Stage::PublishStart,
                    ReadStage::PublishComplete => Stage::PublishComplete,
                    ReadStage::Signatures(statistics) => {
                        check.record_signatures(statistics);
                        return;
                    }
                };
                check.record(stage, None, None);
            })?;
        check.current(guard, active)?;
        let clock = guard.application_clock()?;
        let now = crate::authority_challenge::boot_time_ms()?;
        check.finish_observation(
            observation,
            deadline,
            live,
            permission,
            profile,
            now,
            |end| clock.receipt_deadline(end),
        )
    })();
    check.complete(result)
}

impl Check {
    pub(super) fn sampled(&self) -> bool {
        self.timing.is_some_and(|timing| timing.sample.is_some())
    }

    fn record_signatures(&self, statistics: wire::SignatureStatistics) {
        if self.sampled()
            && let Ok(now) = crate::authority_challenge::boot_time_ms()
        {
            let mut line = DiagnosticLine::new();
            self.record_signatures_at(&mut line, now, statistics);
            diagnostic_line(line);
        }
    }

    pub(super) fn record_signatures_at(
        &self,
        output: &mut impl std::fmt::Write,
        now: u64,
        statistics: wire::SignatureStatistics,
    ) {
        if let Some(sample) = self.timing.and_then(|timing| timing.sample) {
            let _ = writeln!(
                output,
                "HyperNet application check: sample={sample} stage=Signatures lookups={} hits={} strictCalls={} strictNs={} evictions={} bootMs={now}",
                statistics.lookups,
                statistics.hits,
                statistics.strict_verifications,
                statistics.strict_verification_ns,
                statistics.evictions,
            );
        }
    }

    pub(super) fn record_exchange(&self, completion: &ExchangeCompletion) {
        for (stage, captured) in [
            (Stage::ExchangeStart, completion.started),
            (Stage::ExchangeComplete, completion.completed),
        ] {
            if let Some(now) = captured {
                let mut line = DiagnosticLine::new();
                self.record_at(&mut line, now, stage, None, None);
                diagnostic_line(line);
            }
        }
    }

    pub(super) fn completion_stream<'a>(
        &self,
        live: &'a BTreeMap<Digest, LiveStream>,
        permission: &EndpointPermission,
        now: u64,
    ) -> Result<&'a LiveStream> {
        self.request.matches_ready(&self.ready)?;
        ensure!(
            self.connected.load(Ordering::Acquire) && !self.cancelled.load(Ordering::Acquire),
            "application check cancelled"
        );
        ensure!(
            now >= self.request.caller_started_boot_ms
                && now < self.request.caller_deadline_boot_ms,
            "application check deadline expired"
        );
        ensure!(permission.gate.expiry()? > now, EndpointPermissionExpired);
        let stream = live
            .get(&self.request.session.id)
            .ok_or(InactiveStream::Missing)?;
        ensure!(
            stream.reference == self.request.session,
            InactiveStream::ReferenceChanged
        );
        stream.current_deadline(now)?;
        Ok(stream)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_observation(
        &self,
        observation: crate::route_authority::StreamCheck,
        original_deadline: u64,
        live: &mut BTreeMap<Digest, LiveStream>,
        permission: &mut EndpointPermission,
        profile: &[u8],
        now: u64,
        receipt_deadline: impl FnOnce(u64) -> u64,
    ) -> Result<Receipt> {
        let stream = self.completion_stream(live, permission, now)?;
        // Clip against the OLD gate before installing the separately certified
        // renewal. This action cannot borrow lifetime from its own gate renewal.
        let not_after = receipt_deadline(
            original_deadline
                .min(observation.deadline)
                .min(stream.current_deadline(now)?)
                .min(permission.gate.expiry()?),
        );
        if not_after <= now {
            return Ok(unavailable(
                self.request.clone(),
                self.ready.privacy.clone(),
                Disposition::Expired,
            ));
        }
        let permitted = observation.renewal.is_some();
        if let Some(renewal) = observation.renewal {
            let endpoint = observation
                .endpoint_renewal
                .context("fresh stream permit omitted endpoint renewal")?;
            live.get_mut(&self.request.session.id)
                .expect("checked live stream")
                .renew_checked(renewal, endpoint, profile, permission, not_after, || {
                    !self.connected.load(Ordering::Acquire)
                        || self.cancelled.load(Ordering::Acquire)
                })?;
        }
        Ok(Receipt {
            request: self.request.clone(),
            disposition: if permitted {
                Disposition::Permitted
            } else {
                Disposition::Denied
            },
            authority: Some(observation.authority),
            not_after_boot_ms: not_after,
            privacy: self.ready.privacy.clone(),
        })
    }
    pub(super) fn respond(self, receipt: Receipt) {
        if self.connected.load(Ordering::Acquire) && !self.cancelled.load(Ordering::Acquire) {
            let _ = self.reply.send(receipt);
        }
    }
    fn record(
        &self,
        stage: Stage,
        disposition: Option<&Disposition>,
        failure: Option<(FailureCode, Option<u64>, Option<InactiveStream>)>,
    ) {
        if let Some(timing) = self.timing
            && timing.sample.is_some()
            && let Ok(now) = crate::authority_challenge::boot_time_ms()
        {
            let mut line = DiagnosticLine::new();
            self.record_at(&mut line, now, stage, disposition, failure);
            diagnostic_line(line);
        }
    }
    pub(super) fn record_at(
        &self,
        output: &mut impl std::fmt::Write,
        now: u64,
        stage: Stage,
        disposition: Option<&Disposition>,
        failure: Option<(FailureCode, Option<u64>, Option<InactiveStream>)>,
    ) {
        if let Some(timing) = self.timing
            && let Some(sample) = timing.sample
        {
            let reason = failure.map(|f| f.0);
            let fresh_read_code = failure.and_then(|f| f.1);
            let inactive = failure.and_then(|f| f.2);
            let _ = writeln!(
                output,
                "HyperNet application check: sample={sample} stage={stage:?} elapsedMs={} callerStartedBootMs={} deadlineBootMs={} disposition={disposition:?} reason={reason:?} freshReadCode={fresh_read_code:?} inactive={inactive:?} bootMs={now}",
                now.saturating_sub(timing.started),
                self.request.caller_started_boot_ms,
                self.request.caller_deadline_boot_ms
            );
        }
    }
    pub(super) fn complete(&self, result: Result<Receipt>) -> Receipt {
        let pending_stage = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<crate::route_authority::ReadPending>())
            .map(|pending| pending.stage);
        let failure = result.as_ref().err().map(|error| {
            (
                failure_code(error),
                error
                    .downcast_ref::<crate::authority_local_transport::FreshReadUnavailable>()
                    .map(|e| e.code),
                error.downcast_ref::<InactiveStream>().copied(),
            )
        });
        let receipt = result.unwrap_or_else(|error| {
            unavailable(
                self.request.clone(),
                self.ready.privacy.clone(),
                if error.is::<InactiveStream>() {
                    Disposition::NotActive
                } else {
                    Disposition::Unavailable
                },
            )
        });
        if receipt.disposition != Disposition::Permitted
            && let Some((sample, now)) = failure_sample()
        {
            let mut line = DiagnosticLine::new();
            self.record_failure_at(
                &mut line,
                sample,
                now,
                &receipt.disposition,
                failure,
                pending_stage,
            );
            diagnostic_line(line);
        }
        self.record(Stage::Outcome, Some(&receipt.disposition), failure);
        receipt
    }
    pub(super) fn record_failure_at(
        &self,
        output: &mut impl std::fmt::Write,
        sample: u64,
        now: u64,
        disposition: &Disposition,
        failure: Option<(FailureCode, Option<u64>, Option<InactiveStream>)>,
        pending_stage: Option<crate::route_authority::ReadPendingStage>,
    ) {
        let _ = writeln!(
            output,
            "HyperNet application check failure: sample={sample} callerStartedBootMs={} deadlineBootMs={} disposition={disposition:?} reason={:?} pendingStage={pending_stage:?} freshReadCode={:?} inactive={:?} bootMs={now}",
            self.request.caller_started_boot_ms,
            self.request.caller_deadline_boot_ms,
            failure.map(|value| value.0),
            failure.and_then(|value| value.1),
            failure.and_then(|value| value.2),
        );
    }
    fn current(&self, guard: &Guard, active: &Active) -> Result<()> {
        crate::authority_local_transport::remaining(self.request.caller_deadline_boot_ms)?;
        self.request.matches_ready(&self.ready)?;
        ensure!(
            self.connected.load(Ordering::Acquire) && !self.cancelled.load(Ordering::Acquire),
            "application check cancelled"
        );
        ensure!(
            guard.application_clock()?.kernel_boot == self.ready.challenge.kernel_boot,
            "application check host boot changed"
        );
        active.check(guard)
    }
}
