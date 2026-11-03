// SPDX-License-Identifier: MIT
// One endpoint requester serializes admission while bounded duplex tasks obey separate renewable gates.
use super::*;
use crate::authority_domains::streams::{self, local, protocol as stream_protocol};
use crate::authority_proof::VersionRef;
use std::sync::atomic::AtomicBool;
#[path = "ApplicationStreamChecks.rs"]
mod checks;
#[derive(Clone, Copy, Debug)]
enum Activity {
    IncomingPermission,
    HandshakePermission,
    StreamAdmission,
    StreamPermit,
    Cleanup,
}
static ACTIVITY_SAMPLES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
fn observed<T>(
    activity: Activity,
    deadline: u64,
    session: Option<Timing>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let timing = crate::authority_challenge::boot_time_ms()
        .ok()
        .map(|now| Timing::counted(now, &ACTIVITY_SAMPLES[activity as usize], 64));
    let session_sample = session.and_then(|s| s.sample);
    if let Some(Timing {
        sample: Some(sample),
        started,
    }) = timing
    {
        diagnostic(format_args!(
            "HyperNet application actor: operation={activity:?} sample={sample} sessionSample={session_sample:?} stage=Start deadlineBootMs={deadline} bootMs={started}\n"
        ));
    }
    let result = action();
    if let Some(Timing {
        sample: Some(sample),
        started,
    }) = timing
        && let Ok(now) = crate::authority_challenge::boot_time_ms()
    {
        diagnostic(format_args!(
            "HyperNet application actor: operation={activity:?} sample={sample} sessionSample={session_sample:?} stage=Complete deadlineBootMs={deadline} elapsedMs={} reason={:?} bootMs={now}\n",
            now.saturating_sub(started),
            result.as_ref().err().map(failure_code)
        ));
    }
    result
}
struct Forwarding {
    deadline: u64,
    established: AtomicBool,
    finished: AtomicBool,
}
struct ForwardingCompletion(Arc<Forwarding>, Timing);
impl Drop for ForwardingCompletion {
    fn drop(&mut self) {
        self.0.finished.store(true, Ordering::Release);
        self.1.mark(Phase::ApplicationForwardComplete);
    }
}
struct OpenedStream {
    session: Session,
    proof: streams::Proof,
}
struct LiveStream {
    reference: VersionRef,
    proof_digest: Digest,
    gate: route_io::Gate,
    accepted_at: u64,
    retry_after: u64,
    renewal_turn: u64,
    forwarding: Arc<Forwarding>,
}
impl LiveStream {
    fn check_deadline(&self, now: u64) -> Option<u64> {
        let deadline = self.forwarding.deadline.min(self.gate.expiry().ok()?);
        (self.forwarding.established.load(Ordering::Acquire)
            && !self.forwarding.finished.load(Ordering::Acquire)
            && deadline > now)
            .then_some(deadline)
    }
    fn prepare_check(
        &mut self,
        deadline: u64,
        budget: u64,
        cancelled: impl Fn() -> bool,
        refresh: impl FnOnce(u64) -> Result<u64>,
    ) -> Result<()> {
        let deadline = deadline.min(self.forwarding.deadline);
        crate::authority_local_transport::remaining(deadline)?;
        let now = crate::authority_challenge::boot_time_ms()?;
        ensure!(!cancelled(), "application check cancelled");
        self.check_deadline(now)
            .context("application stream is no longer current")?;
        let expiry = self.gate.expiry()?;
        if now >= refresh_at(expiry, budget.saturating_mul(2), Some(self.accepted_at)) {
            let expiry = refresh(deadline)?;
            crate::authority_local_transport::remaining(deadline)?;
            ensure!(
                !cancelled()
                    && self.forwarding.established.load(Ordering::Acquire)
                    && !self.forwarding.finished.load(Ordering::Acquire),
                "application check context ended"
            );
            self.gate.renew(expiry.min(self.forwarding.deadline))?;
            self.accepted_at = crate::authority_challenge::boot_time_ms()?;
            self.retry_after = 0;
        }
        Ok(())
    }
}
impl Drop for LiveStream {
    fn drop(&mut self) {
        self.gate.close();
    }
}
struct PendingClose {
    reference: VersionRef,
    proof_digest: Digest,
    deadline: u64,
    retry_after: u64,
    own_renewals: u64,
    renewal_turn: u64,
}
impl PendingClose {
    fn completed(
        stream: LiveStream,
        now: u64,
        idle_ms: u64,
        own_renewals: u64,
        renewal_turn: u64,
    ) -> Self {
        stream.gate.close();
        Self {
            reference: stream.reference.clone(),
            proof_digest: stream.proof_digest,
            deadline: now.saturating_add(idle_ms),
            retry_after: now,
            own_renewals,
            renewal_turn,
        }
    }
    fn attempt(&mut self, client: &mut Client<'_>, diagnostics: &mut u8) -> bool {
        self.attempt_with(
            || crate::authority_challenge::boot_time_ms().unwrap_or(u64::MAX),
            diagnostics,
            |reference, proof_digest, deadline| {
                observed(Activity::Cleanup, deadline, None, || {
                    client.before(deadline, |client| {
                        client.stream_close(reference, proof_digest)
                    })
                })
            },
        )
    }
    fn attempt_with(
        &mut self,
        mut clock: impl FnMut() -> u64,
        diagnostics: &mut u8,
        close: impl FnOnce(&VersionRef, Digest, u64) -> Result<()>,
    ) -> bool {
        let now = clock();
        if now < self.retry_after {
            return false;
        }
        let expired = now >= self.deadline;
        if !expired && close(&self.reference, self.proof_digest, self.deadline).is_ok() {
            return true;
        }
        let finished = clock();
        let expired = expired || finished >= self.deadline;
        if *diagnostics < 16 {
            *diagnostics += 1;
            diagnostic(format_args!(
                "HyperNet application stream cleanup: sample={} category={}\n",
                diagnostics,
                if expired { "Expired" } else { "Failed" }
            ));
        }
        // Unknown effects stay in the requester's exact recovery slot. This one
        // held retirement retains its target and first deadline between attempts.
        self.retry_after = finished.saturating_add(READ_RETRY_MS).min(self.deadline);
        expired
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Maintenance {
    Own,
    Stream(Digest),
    Close,
    Wait,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dispatch {
    Own,
    Stream,
    Check,
    Handshake,
    Incoming,
    Public,
    Forwarding,
    Close,
}
const DISPATCH: [Dispatch; 7] = [
    Dispatch::Own,
    Dispatch::Stream,
    Dispatch::Handshake,
    Dispatch::Incoming,
    Dispatch::Public,
    Dispatch::Forwarding,
    Dispatch::Close,
];
#[derive(Default)]
struct Schedule {
    next: usize,
    check_turn: bool,
    renewal_turn: u64,
}
impl Schedule {
    async fn next<T>(
        &mut self,
        mut ready: impl FnMut(Dispatch, &mut std::task::Context<'_>) -> std::task::Poll<T>,
    ) -> T {
        tokio::task::consume_budget().await;
        // A ready queue must not look empty merely because another class spent
        // the task's cooperative budget. Only this finite selector is unbudgeted.
        tokio::task::unconstrained(std::future::poll_fn(|cx| {
            self.poll(|class| ready(class, cx))
        }))
        .await
    }
    // Interleave one queued check between non-check events. Other ready classes
    // retain their rotation; checks alone do not wait for an idle class.
    fn poll<T>(
        &mut self,
        mut ready: impl FnMut(Dispatch) -> std::task::Poll<T>,
    ) -> std::task::Poll<T> {
        let checked = self.check_turn;
        if checked && let std::task::Poll::Ready(event) = ready(Dispatch::Check) {
            self.check_turn = false;
            return std::task::Poll::Ready(event);
        }
        for offset in 0..DISPATCH.len() {
            let index = (self.next + offset) % DISPATCH.len();
            if let std::task::Poll::Ready(event) = ready(DISPATCH[index]) {
                self.next = (index + 1) % DISPATCH.len();
                self.check_turn = true;
                return std::task::Poll::Ready(event);
            }
        }
        if checked {
            std::task::Poll::Pending
        } else {
            ready(Dispatch::Check)
        }
    }
    fn renewed(&mut self) -> Result<u64> {
        self.renewal_turn = self
            .renewal_turn
            .checked_add(1)
            .context("application renewal turn exhausted")?;
        Ok(self.renewal_turn)
    }
}
enum Event {
    Maintenance(Maintenance),
    Forwarding(std::result::Result<(Digest, Result<()>), tokio::task::JoinError>),
    Handshake(std::result::Result<Result<OpenedStream>, tokio::task::JoinError>),
    Incoming(std::result::Result<Result<Session>, tokio::task::JoinError>),
    Public(Queued<Session>),
    Check(checks::Check),
    Checked(
        std::result::Result<
            (
                tokio::task::Id,
                Result<crate::route_authority::ReadCompletion>,
            ),
            tokio::task::JoinError,
        >,
    ),
}
fn event<T>(
    polled: std::task::Poll<Option<T>>,
    map: impl FnOnce(T) -> Event,
) -> std::task::Poll<Event> {
    match polled {
        std::task::Poll::Ready(Some(value)) => std::task::Poll::Ready(map(value)),
        _ => std::task::Poll::Pending,
    }
}
fn due_stream(
    live: &BTreeMap<Digest, LiveStream>,
    now: u64,
    budget: u64,
    through_turn: u64,
) -> Option<Digest> {
    live.iter()
        .filter(|(_, stream)| {
            !stream.forwarding.finished.load(Ordering::Acquire)
                && stream.renewal_turn <= through_turn
                && now >= stream.retry_after
                && now
                    >= refresh_at(
                        stream.gate.expiry().unwrap_or(0),
                        budget,
                        Some(stream.accepted_at),
                    )
        })
        // New arrivals and serviced streams join behind every older eligible stream.
        .min_by_key(|(id, stream)| (stream.renewal_turn, **id))
        .map(|(id, _)| *id)
}
fn occupied(
    incoming: usize,
    handshakes: usize,
    live: &BTreeMap<Digest, LiveStream>,
    close: Option<&PendingClose>,
) -> usize {
    incoming + handshakes + live.len() + usize::from(close.is_some())
}
fn maintenance(
    now: u64,
    permission: &EndpointPermission,
    live: &BTreeMap<Digest, LiveStream>,
    close: Option<&PendingClose>,
    own_budget: u64,
    action_budget: u64,
) -> Result<Maintenance> {
    // Cleanup prepares each existing gate at most once. The captured turn
    // excludes new arrivals and already serviced streams without another queue.
    // Repeatedly waiting for all gates to be fresh can starve cleanup under load.
    let close_budget = close
        .filter(|close| now < close.deadline)
        .map_or(0, |_| action_budget);
    if close.is_some_and(|close| now >= close.deadline) {
        return Ok(Maintenance::Close);
    }
    if close.is_none_or(|close| close.own_renewals == permission.renewals)
        && permission.refresh_due(now, own_budget.saturating_add(close_budget))?
    {
        return Ok(Maintenance::Own);
    }
    if let Some(id) = due_stream(
        live,
        now,
        action_budget.saturating_add(close_budget),
        close.map_or(u64::MAX, |close| close.renewal_turn),
    ) {
        return Ok(Maintenance::Stream(id));
    }
    Ok(if close.is_some() {
        Maintenance::Close
    } else {
        Maintenance::Wait
    })
}
async fn hello(
    mut session: Session,
    application: crate::route_config::Application,
    ready: Vec<u8>,
    permission: route_io::Gate,
) -> Result<OpenedStream> {
    session
        .boundary
        .arm_renewable(permission.clone(), session.deadline)?;
    session.charge(ready.len())?;
    route_io::guarded_send(
        &mut session.stream,
        &ready,
        &permission,
        session.deadline,
        session.idle_ms,
    )
    .await?;
    let nonce = protocol::random()?;
    let binding = &application.binding;
    let challenge =
        stream_protocol::challenge(binding.network, binding.incarnation, binding.service, nonce)?;
    session.charge(challenge.len())?;
    route_io::guarded_send(
        &mut session.stream,
        &challenge,
        &permission,
        session.deadline,
        session.idle_ms,
    )
    .await?;
    let request = next_packet(session, permission).await?;
    let proof = streams::Proof::parse(&request.packet, binding.network, binding.incarnation)?;
    ensure!(
        proof.service.id == binding.service
            && proof.protocol == binding.protocol
            && proof.challenge == nonce
            && proof.exporter == request.session.exporter,
        "application proof belongs to another endpoint or TLS channel"
    );
    Ok(OpenedStream {
        session: request.session,
        proof,
    })
}
async fn serve(
    mut opened: OpenedStream,
    reference: VersionRef,
    application: crate::route_config::Application,
    key: ed25519_dalek::SigningKey,
    permission: route_io::Gate,
    endpoint_permission: route_io::Gate,
    forwarding: Arc<Forwarding>,
) -> Result<()> {
    let deadline = forwarding.deadline;
    let _completion = ForwardingCompletion(forwarding.clone(), opened.session.timing);
    let session = &mut opened.session;
    let binding = &application.binding;
    let local = tokio::select! {
        local=tokio::time::timeout(session.wait()?,route_io::local(Path::new("/Application/Control.sock")))=>local??,
        _=permission.closed()=>anyhow::bail!("application permission closed"),
        _=endpoint_permission.closed()=>anyhow::bail!("endpoint permission closed"),
    };
    let (mut local, boundary) = route_io::Transport::new(local, deadline);
    boundary.arm_renewable(endpoint_permission.clone(), deadline)?;
    let challenge = tokio::select! {
        reply=tokio::time::timeout(session.wait()?,route_io::receive(&mut local,1024))=>reply??,
        _=permission.closed()=>anyhow::bail!("application permission closed"),
    };
    let nonce = local::parse_local_challenge(&challenge)?;
    let context = local::context(binding, &reference, &opened.proof, nonce, &key)?;
    route_io::guarded_send(&mut local, &context, &permission, deadline, session.idle_ms).await?;
    // The SDK acknowledges the authenticated context before the network receives acceptance.
    let acknowledgement =
        tokio::time::timeout(session.wait()?, route_io::receive(&mut local, 1024)).await??;
    ensure!(
        acknowledgement == local::local_challenge(nonce)?,
        "application broker rejected peer context"
    );
    let accepted = stream_protocol::accepted(&reference, &opened.proof, binding.digest()?)?;
    session.charge(accepted.len())?;
    route_io::guarded_send(
        &mut session.stream,
        &accepted,
        &permission,
        deadline,
        session.idle_ms,
    )
    .await?;
    forwarding.established.store(true, Ordering::Release);
    session.mark(Phase::ApplicationAccepted);
    let limits = Limits {
        bytes: session.bytes.min(opened.proof.limits.bytes),
        duration_ms: crate::authority_local_transport::remaining(deadline)?,
        idle_ms: session.idle_ms.min(opened.proof.limits.idle_ms),
    };
    let _endpoint_demand = endpoint_permission.activity()?;
    tokio::select! {
        result=route_io::forward_guarded(&mut session.stream,local,limits,permission.clone(),deadline)=>result,
        _=endpoint_permission.closed()=>anyhow::bail!("endpoint permission closed"),
    }
}
pub(super) async fn endpoint(
    config: &Config,
    guard: &Guard,
    active: &Active,
    acceptor: TlsAcceptor,
    client: &mut Client<'_>,
) -> Result<()> {
    let own = &config.profile;
    let application = config
        .application
        .as_ref()
        .context("application endpoint binding absent")?
        .clone();
    let capacity = usize::try_from(own.maximum_connections)?;
    let mut permission = EndpointPermission {
        gate: route_io::Gate::new(client.effect_deadline()?),
        accepted_at: None,
        renewals: 0,
    };
    let demand = permission.gate.signal();
    let ready = protocol::endpoint_ready(
        config.manifest.network,
        config.manifest.incarnation,
        own.identity.service,
        streams::PROTOCOL,
    )?;
    let mut attachment = None;
    let relay = if let Some((identity, address)) = &config.relay {
        let current = client.lookup(identity.service)?;
        ensure!(
            current.mode == 1 && current.identity == *identity && current.address == Some(*address),
            "application relay differs from local consent"
        );
        attachment = Some(streams::control::Attachment {
            relay_service: identity.service,
            profile_digest: wire::digest(&current.envelope),
        });
        Some((identity.clone(), config.dial(identity, *address)?))
    } else {
        None
    };
    let privacy = streams::control::Privacy {
        transport_protection: streams::control::TransportProtection::Tls13FinalService,
        endpoint_mode: own.mode,
        incoming_path: if relay.is_some() {
            streams::control::IncomingPath::ApprovedAttachment
        } else {
            streams::control::IncomingPath::PublicListener
        },
        attachment,
        physical_independence_verified: false,
        profile_currentness_asserted: false,
    };
    let (check_queue, mut check_requests) = mpsc::channel(streams::control::MAXIMUM_PENDING);
    let check_worker = guard.application_clock().ok().map(|clock| {
        tokio::spawn(checks::run(
            application.binding.clone(),
            config.key.clone(),
            clock.kernel_boot,
            privacy,
            check_queue,
            permission.gate.clone(),
        ))
    });
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
    let mut incoming: JoinSet<Result<Session>> = JoinSet::new();
    let mut handshakes: JoinSet<Result<OpenedStream>> = JoinSet::new();
    let mut forwarding: JoinSet<(Digest, Result<()>)> = JoinSet::new();
    let mut live: BTreeMap<Digest, LiveStream> = BTreeMap::new();
    let mut reads: JoinSet<Result<crate::route_authority::ReadCompletion>> = JoinSet::new();
    let mut pending: BTreeMap<tokio::task::Id, checks::Pending> = BTreeMap::new();
    let mut closing: Option<PendingClose> = None;
    let mut cleanup_diagnostics = 0;
    let mut schedule = Schedule::default();
    let mut tick = tokio::time::interval(Duration::from_millis(DISPATCH_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut retry_after = tokio::time::Instant::now();
    let outcome=async {loop {
        active.check(guard)?;
        if let Some((identity,address))=&relay {
            while occupied(incoming.len(),handshakes.len(),&live,closing.as_ref())<capacity && tokio::time::Instant::now()>=retry_after {
                let open=Open {network:config.manifest.network,incarnation:config.manifest.incarnation,relay:identity.service,service:own.identity.service,voucher:vec![],nonce:protocol::random()?,attachment:true};
                incoming.spawn(attach(*address,identity.clone(),acceptor.clone(),config.key.clone(),open,own.limits));
            }
        }
        let now=crate::authority_challenge::boot_time_ms()?;
        let close_budget=closing.as_ref().filter(|close|now<close.deadline).map_or(0,|_|client.operation_budget_ms());
        let own_due=permission.refresh_due(now,client.own_renewal_budget_ms().saturating_add(close_budget))?;
        let stream_due=due_stream(&live,now,client.operation_budget_ms().saturating_add(close_budget),u64::MAX);
        let close_work=closing.as_ref().filter(|close|now>=close.retry_after).map(|close|maintenance(now,&permission,&live,Some(close),client.own_renewal_budget_ms(),client.operation_budget_ms())).transpose()?;
        let public=listener.is_some();
        let (listener_tasks,mut listener_requests)=listener.as_mut().map(|l|(&mut l.tasks,&mut l.requests)).unzip();
        let next=tokio::select! {
            biased;
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            stopped=async {listener_tasks.expect("enabled listener").join_next().await},if public=>{stopped.context("application listener stopped")???;anyhow::bail!("application listener stopped");},
            next=schedule.next(|class,cx|match class {
                Dispatch::Own if own_due=>std::task::Poll::Ready(Event::Maintenance(Maintenance::Own)),
                Dispatch::Stream if stream_due.is_some()=>std::task::Poll::Ready(Event::Maintenance(Maintenance::Stream(stream_due.expect("due stream")))),
                Dispatch::Check=>{
                    let completed=event(reads.poll_join_next_with_id(cx),Event::Checked);
                    if completed.is_ready() {completed} else {event(check_requests.poll_recv(cx),Event::Check)}
                },
                Dispatch::Handshake if !handshakes.is_empty()=>event(handshakes.poll_join_next(cx),Event::Handshake),
                Dispatch::Incoming if !incoming.is_empty()=>event(incoming.poll_join_next(cx),Event::Incoming),
                Dispatch::Public if public=>event(listener_requests.as_mut().expect("enabled listener").poll_recv(cx),Event::Public),
                Dispatch::Forwarding if !forwarding.is_empty() && closing.is_none()=>event(forwarding.poll_join_next(cx),Event::Forwarding),
                Dispatch::Close if close_work.is_some()=>std::task::Poll::Ready(Event::Maintenance(close_work.expect("held cleanup"))),
                _=>std::task::Poll::Pending,
            })=>next,
            _=demand.notified()=>continue,
            _=tick.tick()=>continue,
        };
        match next {
            Event::Maintenance(Maintenance::Own)=>{
                permission.refresh(client,now.saturating_add(own.limits.idle_ms))?;active.check(guard)?;
            },
            Event::Maintenance(Maintenance::Stream(id))=>{
                let s=live.get_mut(&id).expect("selected live stream");
                s.renewal_turn=schedule.renewed()?;
                if now>=s.forwarding.deadline {s.gate.close();s.retry_after=u64::MAX;continue;}
                let deadline=s.forwarding.deadline.min(now.saturating_add(own.limits.idle_ms));
                match clock_checked(observed(Activity::StreamPermit,deadline,None,||client.before(deadline,|client|client.stream_permit(&s.reference))))? {
                    Ok(expiry)=>{s.gate.renew(expiry)?;s.accepted_at=crate::authority_challenge::boot_time_ms()?;s.retry_after=0;},
                    Err(error)=>{if error.is::<ReadRetry>() {s.retry_after=now.saturating_add(READ_RETRY_MS);} else {s.gate.close();s.retry_after=u64::MAX;}},
                }
            },
            Event::Maintenance(Maintenance::Close)=>{
                if closing.as_mut().expect("selected stream cleanup").attempt(client,&mut cleanup_diagnostics) {closing=None;}
            },
            Event::Maintenance(Maintenance::Wait)=>unreachable!("held cleanup always has work"),
            Event::Forwarding(result)=>{
                if let Ok((id,_result))=result && let Some(stream)=live.remove(&id) {
                    closing=Some(PendingClose::completed(stream,crate::authority_challenge::boot_time_ms()?,own.limits.idle_ms,permission.renewals,schedule.renewal_turn));
                }
            },
            Event::Handshake(result)=>{
                if let Ok(Ok(opened))=result {
                    let id=opened.proof.id()?;
                    if live.contains_key(&id) {continue;}
                    observed(Activity::HandshakePermission,opened.session.deadline,Some(opened.session.timing),||permission.current(client,opened.session.deadline))?;
                    let admitted=clock_checked(observed(Activity::StreamAdmission,opened.session.deadline,Some(opened.session.timing),||client.before(opened.session.deadline,|client|client.stream_admit(opened.proof.clone()))))?;
                    if let Ok(reference)=admitted {
                        active.check(guard)?;
                        let now=crate::authority_challenge::boot_time_ms()?;
                        let deadline=opened.session.deadline.min(now.saturating_add(opened.proof.expires.saturating_sub(client.now()?))).min(now.saturating_add(opened.proof.limits.duration_ms));
                        let gate=route_io::Gate::with_signal(client.effect_deadline()?,demand.clone());
                        let status=Arc::new(Forwarding {deadline,established:AtomicBool::new(false),finished:AtomicBool::new(false)});
                        live.insert(id,LiveStream {reference:reference.clone(),proof_digest:wire::digest(&opened.proof.envelope),gate:gate.clone(),accepted_at:now,retry_after:0,renewal_turn:schedule.renewed()?,forwarding:status.clone()});
                        let application=application.clone();let key=config.key.clone();let endpoint_gate=permission.gate.clone();
                        forwarding.spawn(async move {(id,serve(opened,reference,application,key,gate,endpoint_gate,status).await)});
                    }
                }
            },
            Event::Public(Queued {mut request,slot,deadline,started,..})=>{
                if crate::authority_local_transport::remaining(deadline).is_err(){continue;}
                request.deadline=request.deadline.min(started.saturating_add(own.limits.duration_ms));request.slot=Some(slot);
                observed(Activity::IncomingPermission,deadline,Some(request.timing),||permission.current(client,deadline))?;active.check(guard)?;
                handshakes.spawn(hello(request,application.clone(),ready.clone(),permission.gate.clone()));
            },
            Event::Incoming(result)=>{
                if let Ok(Ok(session))=result {
                    observed(Activity::IncomingPermission,session.deadline,Some(session.timing),||permission.current(client,session.deadline))?;active.check(guard)?;
                    handshakes.spawn(hello(session,application.clone(),ready.clone(),permission.gate.clone()));
                } else {retry_after=tokio::time::Instant::now()+Duration::from_millis(own.limits.idle_ms.min(1000));}
            },
            Event::Check(check)=>{
                match checks::prepare(&check,&mut live,&mut permission,client,guard,active) {
                    Ok(checks::Preparation::Ready(read))=>{
                        let read=*read;
                        let exchange=read.exchange();
                        let clock=guard.clock_source();
                        let connected=check.connected.clone();
                        let cancelled=check.cancelled.clone();
                        let stream=live.get(&check.request.session.id).expect("prepared live stream");
                        let forwarding=stream.forwarding.clone();
                        let stream_gate=stream.gate.clone();
                        let endpoint_gate=permission.gate.clone();
                        let task=reads.spawn_blocking(move || exchange.run(|| {
                            ensure!(connected.load(Ordering::Acquire) && !cancelled.load(Ordering::Acquire), "application check cancelled");
                            ensure!(forwarding.established.load(Ordering::Acquire) && !forwarding.finished.load(Ordering::Acquire), "application stream is no longer current");
                            crate::authority_local_transport::remaining(stream_gate.expiry()?.min(endpoint_gate.expiry()?))?;
                            clock.health()
                        }));
                        pending.insert(task.id(),checks::Pending {check,read});
                    },
                    Ok(checks::Preparation::Complete(receipt))=>{let receipt=check.complete(Ok(*receipt));check.respond(receipt);},
                    Err(error)=>{let receipt=check.complete(Err(error));check.respond(receipt);},
                }
            },
            Event::Checked(result)=>{
                let (id,completion)=match result {Ok(result)=>result,Err(error)=>(error.id(),Err(error.into()))};
                let checks::Pending {check,read}=pending.remove(&id).context("application check worker has no owner")?;
                let receipt=checks::finish(&check,read,completion,&live,&permission,client,guard,active);
                check.respond(receipt);
            },
        }
    }Ok(())}.await;
    permission.gate.close();
    if let Some(worker) = check_worker {
        worker.abort();
        let _ = worker.await;
    }
    for stream in live.values() {
        stream.gate.close();
    }
    check_requests.close();
    while check_requests.try_recv().is_ok() {}
    for check in pending.values() {
        check.check.cancelled.store(true, Ordering::Release);
    }
    incoming.abort_all();
    handshakes.abort_all();
    forwarding.abort_all();
    if let Some(listener) = &mut listener {
        listener.shutdown().await;
    }
    drain(&mut incoming).await;
    drain(&mut handshakes).await;
    drain(&mut forwarding).await;
    // Blocking exchanges keep their captured absolute end (at most five seconds).
    // Join them instead of detaching work, then discard each actor-owned challenge.
    while reads.join_next().await.is_some() {}
    let mut discard_error = None;
    for (_, check) in pending {
        if let Err(error) = client.discard_read(check.read) {
            discard_error.get_or_insert(error);
        }
    }
    if let Some(mut close) = closing {
        close.attempt(client, &mut cleanup_diagnostics);
    }
    // Failed closure retains a spent slot until its original wall-clock expiry.
    for stream in live.values() {
        let _ = client.before(
            crate::authority_challenge::boot_time_ms()?.saturating_add(1000),
            |client| client.stream_close(&stream.reference, stream.proof_digest),
        );
    }
    outcome?;
    if let Some(error) = discard_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/ApplicationStreamChecksTests.rs"]
mod check_tests;
