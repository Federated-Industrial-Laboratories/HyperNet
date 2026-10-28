// SPDX-License-Identifier: MIT
// One endpoint requester serializes admission while bounded duplex tasks obey separate renewable gates.
use super::*;
use crate::authority_domains::streams::{self, local, protocol as stream_protocol};
use crate::authority_proof::VersionRef;
struct OpenedStream {
    session: Session,
    proof: streams::Proof,
}
struct LiveStream {
    reference: VersionRef,
    gate: route_io::Gate,
    deadline: u64,
    accepted_at: u64,
    retry_after: u64,
}
impl Drop for LiveStream {
    fn drop(&mut self) {
        self.gate.close();
    }
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
    deadline: u64,
) -> Result<()> {
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
    let relay = if let Some((identity, address)) = &config.relay {
        let current = client.lookup(identity.service)?;
        ensure!(
            current.mode == 1 && current.identity == *identity && current.address == Some(*address),
            "application relay differs from local consent"
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
    let mut incoming: JoinSet<Result<Session>> = JoinSet::new();
    let mut handshakes: JoinSet<Result<OpenedStream>> = JoinSet::new();
    let mut forwarding: JoinSet<(Digest, Result<()>)> = JoinSet::new();
    let mut live: BTreeMap<Digest, LiveStream> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(DISPATCH_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut retry_after = tokio::time::Instant::now();
    let outcome=async {loop {
        active.check(guard)?;
        if let Some((identity,address))=&relay {
            while incoming.len()+handshakes.len()+live.len()<capacity && tokio::time::Instant::now()>=retry_after {
                let open=Open {network:config.manifest.network,incarnation:config.manifest.incarnation,relay:identity.service,service:own.identity.service,voucher:vec![],nonce:protocol::random()?,attachment:true};
                incoming.spawn(attach(*address,identity.clone(),acceptor.clone(),config.key.clone(),open,own.limits));
            }
        }
        let now=crate::authority_challenge::boot_time_ms()?;
        let renew=live.iter().find_map(|(id,s)| (now>=s.retry_after && now>=refresh_at(s.gate.expiry().unwrap_or(0),client.operation_budget_ms(),Some(s.accepted_at))).then_some(*id));
        let own_due=permission.refresh_due(now,client.own_renewal_budget_ms())?;
        let public=listener.is_some();
        let (listener_tasks,listener_requests)=listener.as_mut().map(|l|(&mut l.tasks,&mut l.requests)).unzip();
        tokio::select! {
            biased;
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            result=forwarding.join_next(),if !forwarding.is_empty()=>{
                if let Some(Ok((id,_result)))=result && let Some(s)=live.remove(&id) {
                    s.gate.close();let _=client.before(now.saturating_add(own.limits.idle_ms),|client|client.stream_close(&s.reference));
                }
            },
            _=std::future::ready(()),if own_due=>{
                permission.refresh(client,now.saturating_add(own.limits.idle_ms))?;active.check(guard)?;
            },
            _=std::future::ready(()),if renew.is_some()=>{
                let id=renew.expect("selected stream renewal");let s=live.get_mut(&id).expect("selected live stream");
                if now>=s.deadline {s.gate.close();s.retry_after=u64::MAX;continue;}
                match clock_checked(client.before(s.deadline.min(now.saturating_add(own.limits.idle_ms)),|client|client.stream_permit(&s.reference)))? {
                    Ok(expiry)=>{s.gate.renew(expiry)?;s.accepted_at=crate::authority_challenge::boot_time_ms()?;s.retry_after=0;},
                    Err(error)=>{if error.is::<ReadRetry>() {s.retry_after=now.saturating_add(READ_RETRY_MS);} else {s.gate.close();s.retry_after=u64::MAX;}},
                }
            },
            result=handshakes.join_next(),if !handshakes.is_empty()=>{
                if let Some(Ok(Ok(opened)))=result {
                    let id=opened.proof.id()?;
                    if live.contains_key(&id) {continue;}
                    permission.current(client,opened.session.deadline)?;
                    let admitted=clock_checked(client.before(opened.session.deadline,|client|client.stream_admit(opened.proof.clone())))?;
                    if let Ok(reference)=admitted {
                        active.check(guard)?;
                        let now=crate::authority_challenge::boot_time_ms()?;
                        let deadline=opened.session.deadline.min(now.saturating_add(opened.proof.expires.saturating_sub(client.now()?))).min(now.saturating_add(opened.proof.limits.duration_ms));
                        let gate=route_io::Gate::with_signal(client.effect_deadline()?,demand.clone());
                        live.insert(id,LiveStream {reference:reference.clone(),gate:gate.clone(),deadline,accepted_at:now,retry_after:0});
                        let application=application.clone();let key=config.key.clone();let endpoint_gate=permission.gate.clone();
                        forwarding.spawn(async move {(id,serve(opened,reference,application,key,gate,endpoint_gate,deadline).await)});
                    }
                }
            },
            stopped=async {listener_tasks.expect("enabled listener").join_next().await},if public=>{stopped.context("application listener stopped")???;anyhow::bail!("application listener stopped");},
            request=async {listener_requests.expect("enabled listener").recv().await},if public=>{
                if let Some(Queued {mut request,slot,deadline,started,..})=request {
                    if crate::authority_local_transport::remaining(deadline).is_err(){continue;}
                    request.deadline=request.deadline.min(started.saturating_add(own.limits.duration_ms));request.slot=Some(slot);
                    permission.current(client,deadline)?;active.check(guard)?;
                    handshakes.spawn(hello(request,application.clone(),ready.clone(),permission.gate.clone()));
                }
            },
            result=incoming.join_next(),if !incoming.is_empty()=>{
                if let Some(Ok(Ok(session)))=result {
                    permission.current(client,session.deadline)?;active.check(guard)?;
                    handshakes.spawn(hello(session,application.clone(),ready.clone(),permission.gate.clone()));
                } else {retry_after=tokio::time::Instant::now()+Duration::from_millis(own.limits.idle_ms.min(1000));}
            },
            _=demand.notified()=>{},
            _=tick.tick()=>{},
        }
    }Ok(())}.await;
    permission.gate.close();
    for stream in live.values() {
        stream.gate.close();
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
    // Failed closure retains a spent slot until its original wall-clock expiry.
    for stream in live.values() {
        let _ = client.before(
            crate::authority_challenge::boot_time_ms()?.saturating_add(1000),
            |client| client.stream_close(&stream.reference),
        );
    }
    outcome
}
