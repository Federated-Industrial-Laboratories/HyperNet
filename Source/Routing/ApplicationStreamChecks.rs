// SPDX-License-Identifier: MIT
// A separate bounded local connection carries checks, never application payload or authority mutation.
use super::*;
use crate::authority_domains::streams::control::{
    self, Cancel, Challenge, Disposition, Privacy, Ready, Receipt, Request,
};
use std::sync::atomic::AtomicBool;
use tokio::sync::oneshot;

pub(super) struct Check {
    pub request: Request,
    pub ready: Arc<Ready>,
    pub connected: Arc<AtomicBool>,
    pub cancelled: Arc<AtomicBool>,
    pub reply: oneshot::Sender<Receipt>,
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
    loop {
        let attempt = link(
            &binding,
            &key,
            &boot,
            &privacy,
            instance,
            &queue,
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
async fn link(
    binding: &local::Binding,
    key: &ed25519_dalek::SigningKey,
    boot: &str,
    privacy: &Privacy,
    instance: Digest,
    queue: &mpsc::Sender<Check>,
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
    exchange(socket, ready, binding, key, queue).await
}
pub(super) async fn exchange(
    socket: tokio::net::UnixStream,
    ready: Arc<Ready>,
    binding: &local::Binding,
    key: &ed25519_dalek::SigningKey,
    queue: &mpsc::Sender<Check>,
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
                let cancelled = Arc::new(AtomicBool::new(false));
                let (reply, receiver) = oneshot::channel();
                let check = Check { request: request.clone(), ready: ready.clone(), connected: connected.0.clone(), cancelled: cancelled.clone(), reply };
                if queue.try_send(check).is_err() {
                    let receipt = unavailable(request, privacy.clone(), Disposition::Unavailable);
                    tokio::time::timeout(Duration::from_millis(1000), route_io::send(&mut writer, &control::sign(&receipt, binding, key)?)).await??;
                    continue;
                }
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

pub(super) fn evaluate(
    check: &Check,
    live: &BTreeMap<Digest, LiveStream>,
    gate: &route_io::Gate,
    client: &mut Client<'_>,
    guard: &Guard,
    active: &Active,
) -> Receipt {
    let request = &check.request;
    let privacy = check.ready.privacy.clone();
    let result = (|| -> Result<Receipt> {
        let now = crate::authority_challenge::boot_time_ms()?;
        if now >= request.caller_deadline_boot_ms || request.caller_started_boot_ms > now {
            return Ok(unavailable(request.clone(), privacy, Disposition::Expired));
        }
        check.request.matches_ready(&check.ready)?;
        let current = live
            .get(&request.session.id)
            .filter(|s| s.reference == request.session);
        let Some(stream) = current else {
            return Ok(unavailable(
                request.clone(),
                privacy,
                Disposition::NotActive,
            ));
        };
        let Some(stream_deadline) = stream.check_deadline(now) else {
            return Ok(unavailable(
                request.clone(),
                privacy,
                Disposition::NotActive,
            ));
        };
        ensure!(
            check.connected.load(Ordering::Acquire) && !check.cancelled.load(Ordering::Acquire),
            "application check cancelled"
        );
        let clock = guard.application_clock()?;
        ensure!(
            clock.kernel_boot == check.ready.challenge.kernel_boot,
            "application check host boot changed"
        );
        active.check(guard)?;
        let deadline = clock.read_deadline(
            request
                .caller_deadline_boot_ms
                .min(stream_deadline)
                .min(gate.expiry()?),
        );
        let (authority, permitted, observed_deadline) = client.before(deadline, |client| {
            client.check_stream(&request.session, request.caller_started_boot_ms)
        })?;
        let now = crate::authority_challenge::boot_time_ms()?;
        active.check(guard)?;
        let clock = guard.application_clock()?;
        ensure!(
            clock.kernel_boot == check.ready.challenge.kernel_boot
                && check.connected.load(Ordering::Acquire)
                && !check.cancelled.load(Ordering::Acquire),
            "application check context ended"
        );
        let Some(stream_deadline) = stream.check_deadline(now) else {
            return Ok(unavailable(
                request.clone(),
                privacy,
                Disposition::NotActive,
            ));
        };
        let not_after = clock.receipt_deadline(
            deadline
                .min(observed_deadline)
                .min(stream_deadline)
                .min(gate.expiry()?),
        );
        if not_after <= now {
            return Ok(unavailable(request.clone(), privacy, Disposition::Expired));
        }
        Ok(Receipt {
            request: request.clone(),
            disposition: if permitted {
                Disposition::Permitted
            } else {
                Disposition::Denied
            },
            authority: Some(authority),
            not_after_boot_ms: not_after,
            privacy,
        })
    })();
    result.unwrap_or_else(|error| {
        // Existing bounded, metadata-only diagnostics retain the failure category.
        Timing::begin(request.caller_started_boot_ms, true)
            .failure(Phase::ApplicationCheckRefused, &error);
        unavailable(
            request.clone(),
            check.ready.privacy.clone(),
            Disposition::Unavailable,
        )
    })
}
