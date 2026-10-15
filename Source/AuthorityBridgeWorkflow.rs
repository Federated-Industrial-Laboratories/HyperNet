// SPDX-License-Identifier: MIT
// Destination admission and source export are separate certified operations over one exact treaty.
use super::*;
use rand::{RngCore, rngs::OsRng};
use std::os::unix::{
    fs::{FileTypeExt, MetadataExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn packet(label: &str, mut values: Vec<V>) -> Result<Vec<u8>> {
    let mut f = vec![V::Uint(200), V::Uint(1), V::Text(label.into())];
    f.append(&mut values);
    wire::encode_state(&a(f))
}
fn reply(label: &str, mut values: Vec<V>) -> Result<Vec<u8>> {
    let mut f = vec![V::Uint(201), V::Uint(1), V::Text(label.into())];
    f.append(&mut values);
    wire::encode_state(&a(f))
}
fn refresh(
    client: &client::Shared<'_>,
    id: Digest,
) -> Result<(Record, federation::Agreement, Record)> {
    client.action(federation::Command::Get { agreement: id })?;
    cached(client, id)
}
fn cached(
    client: &client::Shared<'_>,
    id: Digest,
) -> Result<(Record, federation::Agreement, Record)> {
    let state = client.context().0;
    let r = state.record(151, id)?.clone();
    let agreement = federation::Agreement::parse(&r.payload, state.network, state.incarnation)?;
    let bridge = state.record(152, client.service())?.clone();
    Ok((r, agreement, bridge))
}
fn anchors(state: &domains::State, agreement: &federation::Agreement) -> Result<(Record, Record)> {
    Ok((
        state.record(150, agreement.foreign.id)?.clone(),
        state.record(157, agreement.foreign.id)?.clone(),
    ))
}
fn parse_anchors(trust: &V, floor: &V, n: Digest, i: Digest) -> Result<(Record, Record)> {
    let trust = Record::parse(trust.bytes()?, n, i)?;
    let floor = Record::parse(floor.bytes()?, n, i)?;
    ensure!(
        trust.reference.kind == 150
            && floor.reference.kind == 157
            && trust.reference.id == floor.reference.id,
        "bridge anchors select different trust"
    );
    Ok((trust, floor))
}
type Admission = (
    federation::Treaty,
    federation::ForeignProof,
    Option<Vec<Digest>>,
);
async fn admission(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    id: Digest,
    page: Option<[u8; 16]>,
    revision: Option<VersionRef>,
    after: Option<Digest>,
) -> Result<Admission> {
    let (record, agreement, bridge) = refresh(client, id)?;
    let treaty = agreement.treaty;
    ensure!(
        !treaty.source_side(client.context().0.network, client.context().0.incarnation)?,
        "lease must originate at destination bridge"
    );
    let deadline = client.deadline()?;
    let bytes = network
        .exchange(
            treaty.source_bridge,
            &packet(
                "BridgeAnchor",
                vec![
                    b(&id),
                    page.as_ref().map_or(V::Null, |v| b(v)),
                    after.as_ref().map_or(V::Null, |v| b(v)),
                ],
            )?,
            deadline,
        )
        .await?;
    transport::remaining(deadline)?;
    let value = wire::decode_state(&bytes)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeAnchor",
        "counterpart anchor response differs"
    );
    let (trust, floor) = parse_anchors(
        &f[3],
        &f[4],
        treaty.source.network,
        treaty.source.incarnation,
    )?;
    let inventory = federation::Command::parse_inventory(&f[5], page, after)?;
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "bridge exchange nonce is zero");
    let completion = client.action(federation::Command::Admission {
        agreement: record.reference,
        bridge: bridge.reference,
        page,
        exchange: nonce,
        revision,
        after,
    })?;
    let proof = client.portable(&completion, &trust, &floor)?;
    Ok((treaty, proof, inventory))
}
#[allow(
    clippy::too_many_arguments,
    reason = "The lease binds the exact treaty, optional revision, continuation and recipient floor before transport."
)]
async fn lease(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    id: Digest,
    page: Option<[u8; 16]>,
    revision: Option<VersionRef>,
    after: Option<Digest>,
    target: Option<(Record, Record)>,
    include_bundle: bool,
) -> Result<(federation::ForeignProof, Resolved)> {
    let (treaty, proof, inventory) = admission(client, network, id, page, revision, after).await?;
    let agreement = federation::Agreement::parse(
        &client.context().0.record(151, id)?.payload,
        client.context().0.network,
        client.context().0.incarnation,
    )?;
    let (trust, floor) = target.unwrap_or(anchors(&client.context().0, &agreement)?);
    let deadline = client.deadline()?;
    let bytes = network
        .exchange(
            treaty.source_bridge,
            &packet(
                "BridgeExport",
                vec![
                    b(&id),
                    b(&proof.bytes),
                    b(&trust.bytes),
                    b(&floor.bytes),
                    V::Bool(include_bundle),
                    federation::Command::inventory_value(&inventory),
                ],
            )?,
            deadline,
        )
        .await?;
    let value = wire::decode_state(&bytes)?;
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeLease",
        "counterpart export response differs"
    );
    let proof = federation::ForeignProof::parse(f[3].bytes()?)?;
    let intent = proof.intent()?;
    let result = crate::authority_proof::OperationResult::parse(&proof.result)?;
    let refs = domains::response_inputs(&intent, &wire::decode(&result.value)?)?;
    let objects = Resolved::parse(&refs, &f[4])?;
    let verified = proof.verify(&client.context().0, &treaty, client.now()?, &objects, false)?;
    let objects = if include_bundle {
        content::fetch(client, network, &treaty, &proof, &verified).await?
    } else {
        objects
    };
    transport::remaining(deadline)?;
    Ok((proof, objects))
}
async fn local(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    input: &[u8],
) -> Result<Vec<u8>> {
    let v = wire::decode(input)?;
    let f = v.list(10)?;
    ensure!(
        f.len() >= 3 && f[0].uint()? == 200 && f[1].uint()? == 1,
        "bridge local packet differs"
    );
    match f[2].text()? {
        "BridgeSearch" => {
            let f = v.array(5)?;
            let query = crate::search_text::Request::parse(f[4].bytes()?)?;
            let packet = wire::decode(f[3].bytes()?)?;
            let p = packet.array(10)?;
            ensure!(
                p[0].uint()? == 200
                    && p[1].uint()? == 1
                    && p[2].text()? == "BridgeLease"
                    && p[6] == V::Null
                    && p[9].boolean()?,
                "search requires one exact imported body"
            );
            let agreement = p[3].fixed()?;
            let raw = p[4].fixed()?;
            let native = domains::version(&p[5])?;
            ensure!(native.kind == 141, "imported search revision differs");
            let context = client.context().0;
            let target = parse_anchors(&p[7], &p[8], context.network, context.incarnation)?;
            let (proof, _) = lease(
                client,
                network,
                agreement,
                Some(raw),
                Some(native.clone()),
                None,
                Some(target),
                false,
            )
            .await?;
            let context = client.context().0;
            let accepted = federation::Agreement::parse(
                &context.record(151, agreement)?.payload,
                context.network,
                context.incarnation,
            )?;
            query.network_scope(
                context.network,
                context.incarnation,
                page::namespace_id(&accepted.treaty.destination_namespace)?,
            )?;
            let (objects, source) = client.search_bundle(agreement, raw, &native)?;
            let result = crate::search_text::response(&query, &source)?;
            reply(
                "BridgeSearch",
                vec![b(&proof.bytes), objects.value(), b(&result)],
            )
        }
        "BridgeLease" => {
            let f = v.array(10)?;
            let id = f[3].fixed()?;
            let page = if f[4] == V::Null {
                None
            } else {
                Some(f[4].fixed()?)
            };
            let revision = if f[5] == V::Null {
                None
            } else {
                Some(domains::version(&f[5])?)
            };
            let after = if f[6] == V::Null {
                None
            } else {
                Some(f[6].fixed()?)
            };
            let target = parse_anchors(
                &f[7],
                &f[8],
                client.context().0.network,
                client.context().0.incarnation,
            )?;
            let (proof, objects) = lease(
                client,
                network,
                id,
                page,
                revision,
                after,
                Some(target),
                f[9].boolean()?,
            )
            .await?;
            reply("BridgeLease", vec![b(&proof.bytes), objects.value()])
        }
        "BridgeSync" => {
            let f = v.array(5)?;
            let id = f[3].fixed()?;
            let selected = if f[4] == V::Null {
                None
            } else {
                Some(f[4].fixed()?)
            };
            let mut imported = Vec::new();
            let mut after = None;
            loop {
                let pages = if let Some(page) = selected {
                    vec![page]
                } else {
                    let (proof, objects) =
                        lease(client, network, id, None, None, after, None, false).await?;
                    let treaty = federation::Agreement::parse(
                        &client.context().0.record(151, id)?.payload,
                        client.context().0.network,
                        client.context().0.incarnation,
                    )?
                    .treaty;
                    let verified = proof.verify(
                        &client.context().0,
                        &treaty,
                        client.now()?,
                        &objects,
                        false,
                    )?;
                    after = verified.cursor;
                    verified
                        .state
                        .records
                        .values()
                        .filter(|r| r.reference.kind == 153)
                        .map(|r| {
                            federation::Share::parse(
                                &r.payload,
                                verified.state.network,
                                verified.state.incarnation,
                            )
                            .map(|s| s.page)
                        })
                        .collect::<Result<Vec<_>>>()?
                };
                for raw in pages {
                    let (proof, objects) =
                        lease(client, network, id, Some(raw), None, None, None, true).await?;
                    let agreement = client.context().0.record(151, id)?.clone();
                    let bridge = client.context().0.record(152, client.service())?.clone();
                    let refs = objects.references();
                    ensure!(
                        refs.len() == 1,
                        "bridge import requires one exact approved bundle"
                    );
                    let completion = client.action(federation::Command::Import {
                        agreement: agreement.reference,
                        bridge: bridge.reference,
                        export: proof,
                        bundle: refs[0].clone(),
                    })?;
                    client.stage(&objects)?;
                    let body = completion.value.array(5)?[4].array(4)?;
                    let page = body[1]
                        .list(64)?
                        .iter()
                        .map(|v| {
                            Record::parse(
                                v.bytes()?,
                                client.context().0.network,
                                client.context().0.incarnation,
                            )
                        })
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .find(|r| r.reference.kind == 154)
                        .context("import omitted qualified Page")?;
                    media::replicate(client, network, id, raw).await?;
                    imported.push(b(&page.reference.id));
                }
                if selected.is_some() || after.is_none() {
                    break;
                }
            }
            reply("BridgeSync", vec![a(imported)])
        }
        _ => anyhow::bail!("unknown local bridge packet"),
    }
}
fn peer(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    sender: Digest,
    input: &[u8],
) -> Result<Vec<u8>> {
    let v = wire::decode_state(input)?;
    let f = v.list(12)?;
    ensure!(
        f.len() >= 4 && f[0].uint()? == 200 && f[1].uint()? == 1,
        "bridge peer packet differs"
    );
    let id = f[3].fixed()?;
    let label = f[2].text()?;
    let prepared = if label == "BridgeAnchor" {
        let f = v.array(6)?;
        let page = if f[4] == V::Null {
            None
        } else {
            Some(f[4].fixed()?)
        };
        let after = if f[5] == V::Null {
            None
        } else {
            Some(f[5].fixed()?)
        };
        ensure!(
            page.is_none() || after.is_none(),
            "bridge source context mixes Page and inventory"
        );
        Some((
            page,
            client.action(federation::Command::SourceContext {
                agreement: id,
                page,
                after,
            })?,
        ))
    } else {
        None
    };
    // Anchor already acquired the exact source context before this fresh Admission.
    // Export and media execution independently revalidate its signed dependencies.
    let (record, agreement, bridge) = cached(client, id)?;
    let source = agreement
        .treaty
        .source_side(client.context().0.network, client.context().0.incarnation)?;
    ensure!(
        source && sender == agreement.treaty.destination_bridge,
        "bridge request comes from another treaty endpoint"
    );
    match label {
        "BridgeAnchor" => {
            let (page, completion) = prepared.context("bridge source context absent")?;
            let inventory = if page.is_some() {
                None
            } else {
                let body = completion.value.array(5)?[4].array(4)?;
                let ids = body[1]
                    .list(federation::MAXIMUM_CONTEXT_RECORDS)?
                    .iter()
                    .map(|v| {
                        Record::parse(
                            v.bytes()?,
                            client.context().0.network,
                            client.context().0.incarnation,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|r| r.reference.kind == 153)
                    .map(|r| r.reference.id)
                    .collect();
                Some(ids)
            };
            let (trust, floor) = anchors(&client.context().0, &agreement)?;
            reply(
                "BridgeAnchor",
                vec![
                    b(&trust.bytes),
                    b(&floor.bytes),
                    federation::Command::inventory_value(&inventory),
                ],
            )
        }
        "BridgeExport" => {
            let f = v.array(9)?;
            let admission = federation::ForeignProof::parse(f[4].bytes()?)?;
            let federation::Command::Admission { page, after, .. } = admission.command()? else {
                anyhow::bail!("bridge export admission differs")
            };
            let inventory = federation::Command::parse_inventory(&f[8], page, after)?;
            let (trust, floor) = parse_anchors(
                &f[5],
                &f[6],
                agreement.treaty.destination.network,
                agreement.treaty.destination.incarnation,
            )?;
            let completion = client.action(federation::Command::Export {
                agreement: record.reference,
                bridge: bridge.reference,
                admission,
                include_bundle: f[7].boolean()?,
                inventory,
            })?;
            let proof = client.portable(&completion, &trust, &floor)?;
            reply(
                "BridgeLease",
                vec![b(&proof.bytes), completion.objects.value()],
            )
        }
        "BridgeMedia" => media::source(client, network, &v),
        "BridgeContent" => content::source(client, &v),
        _ => anyhow::bail!("unknown peer bridge operation"),
    }
}
fn listener() -> Result<UnixListener> {
    let directory = files::private_directory(Path::new("/State/Control"))?;
    let path = Path::new("/State/Control/Control.sock");
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0,
                "bridge control socket differs"
            );
            match UnixStream::connect(path) {
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    std::fs::remove_file(path)?
                }
                _ => anyhow::bail!("bridge socket already active"),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    directory.sync_all()?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
fn ingress_capacity(config: &Config) -> Result<usize> {
    let manifest = &config.profile.manifest;
    let role = manifest
        .roles
        .iter()
        .find(|r| r.role == 7)
        .context("bridge role absent")?;
    let cache = config
        .profile
        .state_bytes
        .checked_mul(3)
        .context("bridge working set overflow")?;
    // Each pending peer may hold a frame, decoded frame, reply and TLS buffers. The local
    // coordinator also retains its outbound frame and one complete bounded media asset.
    let local = 4 * tls::FRAME as u64 + 2 * crate::markup::media::MAX_PAGE_BYTES;
    let available = role
        .memory_bytes
        .saturating_sub(cache)
        .saturating_sub(local);
    let count = manifest.limits[2]
        .saturating_sub(2)
        .min(manifest.limits[3].saturating_sub(1))
        .min(available / (4 * tls::FRAME) as u64);
    ensure!(
        count > 0,
        "bridge consent has no capacity for a counterpart operation"
    );
    usize::try_from(count).context("bridge connection capacity exceeds platform")
}
pub async fn run(
    config: &Config,
    guard: &Guard,
    active: &Active,
    network: &tls::Transport,
    client: &client::Shared<'_>,
) -> Result<()> {
    client
        .recover()
        .context("recover pending Bridge operation")?;
    for (id, _) in &config.profile.agreements {
        refresh(client, *id).context("refresh Bridge agreement at startup")?;
    }
    let capacity = ingress_capacity(config)?;
    let tcp = tokio::net::TcpListener::bind(network.listen).await?;
    let local_listener = tokio::net::UnixListener::from_std(listener()?)?;
    let mut incoming = tokio::task::JoinSet::new();
    let mut responses = tokio::task::JoinSet::new();
    let mut local_operation: Option<
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + '_>>,
    > = None;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        active.check(guard)?;
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=tick.tick()=>{},
            result=async { local_operation.as_mut().expect("enabled local future").await }, if local_operation.is_some()=> {
                local_operation = None;
                if let Err(error) = result { eprintln!("Local bridge operation refused: {error}"); }
            },
            accepted=local_listener.accept(), if local_operation.is_none()=> {
                let (mut stream, _)=accepted?;
                if stream.peer_cred()?.uid()!=unsafe{libc::geteuid()} { continue; }
                let duration=Duration::from_millis(config.profile.manifest.validity.1.saturating_sub(client.now()?));
                local_operation=Some(Box::pin(async move {
                    tokio::time::timeout(duration, async {
                        let input=tls::receive(&mut stream).await?;
                        let reply=local(client,network,&input).await?;
                        active.check(guard)?;
                        tls::send(&mut stream,&reply).await
                    }).await.context("local bridge operation deadline expired")?
                }));
            },
            accepted=tcp.accept()=> {
                let (stream,_)=accepted?;
                if incoming.len()+responses.len() < capacity {
                    incoming.spawn(network.incoming(stream,client.deadline()?));
                }
            },
            accepted=incoming.join_next(), if !incoming.is_empty()=> {
                match accepted.context("bridge ingress task absent")? {
                    Ok(Ok((mut stream,sender,input,deadline)))=> {
                        let answer=(|| { transport::remaining(deadline)?; peer(client,network,sender,&input) })();
                        active.check(guard)?;
                        match answer {
                            Ok(reply)=> { responses.spawn(async move {
                                tokio::time::timeout(Duration::from_millis(transport::remaining(deadline)?),tls::send(&mut stream,&reply))
                                    .await.context("bridge peer response deadline expired")?
                            }); },
                            Err(error)=>eprintln!("Counterpart bridge operation refused: {error}"),
                        }
                    },
                    Ok(Err(error))=>eprintln!("Counterpart bridge ingress refused: {error}"),
                    Err(error)=>eprintln!("Counterpart bridge ingress failed: {error}"),
                }
            },
            response=responses.join_next(), if !responses.is_empty()=> {
                if let Some(Ok(Err(error)))=response { eprintln!("Counterpart bridge response failed: {error}"); }
            },
        }
    }
    incoming.abort_all();
    responses.abort_all();
    Ok(())
}
#[path = "AuthorityBridgeContent.rs"]
mod content;
#[path = "AuthorityBridgeMedia.rs"]
mod media;
