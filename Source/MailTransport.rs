// SPDX-License-Identifier: MIT
use crate::{
    mail_store::{Config, MailStore, StoreRequest},
    mail_types::MAX_STORE_REQUEST,
    store,
    types::Reply,
};
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{CACHE_CONTROL, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
type Body = Full<Bytes>;
fn response(reply: Reply, status: StatusCode) -> Response<Body> {
    let mut result = Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&reply).expect("Reply serialization"),
    )));
    *result.status_mut() = status;
    result
        .headers_mut()
        .insert(CONTENT_TYPE, "application/json".parse().unwrap());
    result
        .headers_mut()
        .insert(CACHE_CONTROL, "no-store".parse().unwrap());
    result
}
fn failure(error: &anyhow::Error) -> &'static str {
    // Never return nested TLS, file, or JSON parser details to remote clients.
    for code in [
        "MailQuotaExceeded",
        "MailGenerationConflict",
        "MailClaimConflict",
        "MailPlacementDenied",
        "MailMessageConflict",
        "MailUnavailable",
        "MailPermissionDenied",
        "MailConsentExpired",
        "MailInvalidObject",
        "MailStaleOperation",
        "MailStalePermission",
        "MailRollback",
    ] {
        if error.to_string() == code {
            return code;
        }
    }
    "MailUnavailable"
}
async fn handle(
    request: Request<Incoming>,
    store: Arc<Mutex<MailStore>>,
) -> Result<Response<Body>, Infallible> {
    if request.method() != hyper::Method::POST
        || request.uri().path() != "/V1/Mail"
        || request.uri().query().is_some()
    {
        return Ok(response(Reply::error("NotFound"), StatusCode::NOT_FOUND));
    }
    if request
        .headers()
        .get(CONTENT_TYPE)
        .is_none_or(|v| v != "application/json")
    {
        return Ok(response(
            Reply::error("InvalidContentType"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ));
    }
    let body = match timeout(
        Duration::from_secs(3),
        Limited::new(request.into_body(), MAX_STORE_REQUEST).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            return Ok(response(
                Reply::error("InvalidBody"),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    let request = match serde_json::from_slice::<StoreRequest>(&body) {
        Ok(request) => request,
        Err(_) => {
            return Ok(response(
                Reply::error("MailInvalidObject"),
                StatusCode::BAD_REQUEST,
            ));
        }
    };
    let operation = async { store.lock().await.execute(request).await };
    let reply = match timeout(Duration::from_secs(8), operation).await {
        Ok(Ok(result)) => Reply::success(0, result),
        Ok(Err(error)) => Reply::error(failure(&error)),
        Err(_) => Reply::error("MailUnavailable"),
    };
    let status = if reply.ok {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };
    Ok(response(reply, status))
}
pub async fn serve(config: Config) -> Result<()> {
    let expires = config.consent.expires;
    let listen = config.listen;
    let tls = config.tls.clone();
    let mut initial = MailStore::new(config)?;
    initial.policy().await?;
    let store = Arc::new(Mutex::new(initial));
    let listener = TcpListener::bind(listen).await?;
    let acceptor = TlsAcceptor::from(tls);
    let connections = Arc::new(Semaphore::new(8));
    let mut workers = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut last = store::now()?;
    println!("MailStore ready");
    loop {
        let current = store::now()?;
        ensure!(current >= last, "Mail clock moved backwards");
        last = current;
        if current >= expires {
            break;
        }
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            _=workers.join_next(),if !workers.is_empty()=>{},
            _=tick.tick()=>{
                if let Ok(mut store)=store.try_lock(){let _=store.policy().await;}
            },
            incoming=listener.accept()=>{
                let (stream,_)=incoming?;let permit=match connections.clone().try_acquire_owned(){Ok(permit)=>permit,Err(_)=>continue};
                let acceptor=acceptor.clone();let store=store.clone();
                workers.spawn(async move {
                    let _permit=permit;
                    if let Ok(Ok(stream))=timeout(Duration::from_secs(3),acceptor.accept(stream)).await {
                        let service=service_fn(move|request|handle(request,store.clone()));
                        let _=timeout(Duration::from_secs(12),http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(stream),service)).await;
                    }
                });
            }
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    Ok(())
}
