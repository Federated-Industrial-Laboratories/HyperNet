// SPDX-License-Identifier: MIT
// A separate bounded local connection carries checks, never application payload or authority mutation.
use super::*;
use crate::authority_domains::streams::control::{
    self, Cancel, Challenge, Disposition, Privacy, Ready, Receipt, Request,
};
use crate::route_authority::{PreparedRead, ReadCompletion};
use std::sync::atomic::AtomicBool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

static CHECK_SAMPLES: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    Enqueued,
    Dequeued,
    EndpointPreparation,
    StreamPreparation,
    FreshRead,
    Outcome,
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
                let timing = crate::authority_challenge::boot_time_ms().ok().map(|now| Timing::counted(now, &CHECK_SAMPLES, 256));
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
        client.operation_budget_ms(),
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

// Capture once: a draining round never admits later arrivals or extends its end.
pub(super) fn cohort(first: Check, queue: &mut mpsc::Receiver<Check>) -> Vec<Check> {
    let mut checks = Vec::with_capacity(control::MAXIMUM_PENDING);
    checks.push(first);
    while checks.len() < control::MAXIMUM_PENDING {
        let Ok(check) = queue.try_recv() else { break };
        checks.push(check);
    }
    checks
}

pub(super) fn issue(
    check: &Check,
    live: &BTreeMap<Digest, LiveStream>,
    permission: &EndpointPermission,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Result<PreparedRead> {
    // Every member's readiness work has finished before any member issues a
    // challenge. Recheck validity now: other preparation cannot renew this call.
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
    permission: &EndpointPermission,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Receipt {
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
        let observation = client.finish_check_stream(read, completion, &check.request.session)?;
        check.current(guard, active)?;
        let clock = guard.application_clock()?;
        let now = crate::authority_challenge::boot_time_ms()?;
        check.finish_observation(observation, deadline, live, permission, now, |end| {
            clock.receipt_deadline(end)
        })
    })();
    check.complete(result)
}

impl Check {
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
        ensure!(
            permission.gate.expiry()? > now,
            "application endpoint permission expired"
        );
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
    pub(super) fn finish_observation(
        &self,
        observation: crate::route_authority::StreamCheck,
        original_deadline: u64,
        live: &mut BTreeMap<Digest, LiveStream>,
        permission: &EndpointPermission,
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
            live.get_mut(&self.request.session.id)
                .expect("checked live stream")
                .renew_checked(renewal, not_after)?;
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
        self.record(Stage::Outcome, Some(&receipt.disposition), failure);
        receipt
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
