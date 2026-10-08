// SPDX-License-Identifier: MIT
use crate::{
    protocol,
    store::{self, read_bounded, read_private},
    types::*,
};
use anyhow::{Context, Result, bail};
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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

type Body = Full<Bytes>;

pub fn tls_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    // Tonic builds from the installed provider. Excluding legacy cipher suites
    // also prevents TLS 1.2 when transitive crates enable its Cargo feature.
    provider
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    provider
}

fn response(reply: Reply, status: StatusCode) -> Response<Body> {
    let mut result = Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&reply).expect("Reply serialisation"),
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

async fn handle(
    request: Request<Incoming>,
    store: Arc<Mutex<store::Store>>,
    network: Arc<String>,
    certificate: Option<String>,
) -> Result<Response<Body>, Infallible> {
    if request.method() != hyper::Method::POST
        || request.uri().path() != "/V1/Command"
        || request.uri().query().is_some()
    {
        return Ok(response(Reply::error("NotFound"), StatusCode::NOT_FOUND));
    }
    if request
        .headers()
        .get(CONTENT_TYPE)
        .is_none_or(|value| value != "application/json")
    {
        return Ok(response(
            Reply::error("InvalidContentType"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ));
    }
    let body = match timeout(
        Duration::from_secs(3),
        Limited::new(request.into_body(), MAX_ENVELOPE).collect(),
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
    let now = match store::now() {
        Ok(now) => now,
        Err(_) => {
            return Ok(response(
                Reply::error("ClockUnavailable"),
                StatusCode::SERVICE_UNAVAILABLE,
            ));
        }
    };
    let verified = match protocol::verify(&body, &network, now) {
        Ok(verified) => verified,
        Err(code) => return Ok(response(Reply::error(code), StatusCode::BAD_REQUEST)),
    };
    let operation = async {
        let mut store = store.lock().await;
        store.execute(&verified, certificate.as_deref()).await
    };
    let reply = timeout(Duration::from_secs(8), operation)
        .await
        .unwrap_or_else(|_| Reply::error("AuthorityUnavailable"));
    let status = if reply.ok {
        StatusCode::OK
    } else if reply.code == "AuthorityUnavailable" {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::FORBIDDEN
    };
    Ok(response(reply, status))
}

pub fn tls_config(config: &AuthorityConfig) -> Result<Arc<ServerConfig>> {
    let certificate_bytes = read_bounded(&config.certificate, 64 * 1024)?;
    let certificates =
        CertificateDer::pem_slice_iter(&certificate_bytes).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        bail!("Server certificate is missing");
    }
    let key_bytes = zeroize::Zeroizing::new(read_private(&config.private_key, 64 * 1024)?);
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .context("Server private key is missing or invalid")?;
    let mut roots = RootCertStore::empty();
    let root_bytes = read_bounded(&config.client_ca, 64 * 1024)?;
    for cert in CertificateDer::pem_slice_iter(&root_bytes) {
        roots.add(cert?)?;
    }
    if roots.is_empty() {
        bail!("Hosting certificate roots are missing");
    }
    let provider = Arc::new(tls_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()?;
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)?;
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

pub async fn serve(config: AuthorityConfig, tls: Arc<ServerConfig>) -> Result<()> {
    let mut store = store::Store::connect(&config).await?;
    store.health().await?;
    let store = Arc::new(Mutex::new(store));
    let listener = TcpListener::bind(config.listen)
        .await
        .context("Cannot bind authority endpoint")?;
    let network = Arc::new(config.network);
    let acceptor = TlsAcceptor::from(tls);
    let connections = Arc::new(Semaphore::new(32));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!("Authority ready");
    loop {
        let (stream, _) = tokio::select! {
            connection = listener.accept() => connection?,
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        };
        let permit = match connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(stream);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let store = store.clone();
        let network = network.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match timeout(Duration::from_secs(3), acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                _ => return,
            };
            let certificate = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|cert| hex::encode(Sha256::digest(cert.as_ref())));
            let service = service_fn(move |request| {
                handle(request, store.clone(), network.clone(), certificate.clone())
            });
            let mut http = http1::Builder::new();
            http.keep_alive(false)
                .max_buf_size(32 * 1024)
                .max_headers(32);
            let _ = timeout(
                Duration::from_secs(12),
                http.serve_connection(TokioIo::new(tls), service),
            )
            .await;
        });
    }
    println!("Authority stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_provider_cannot_negotiate_legacy_tls() {
        let provider = super::tls_provider();
        assert!(!provider.cipher_suites.is_empty());
        assert!(
            provider
                .cipher_suites
                .iter()
                .all(|suite| { suite.version().version == rustls::ProtocolVersion::TLSv1_3 })
        );
        assert!(
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_safe_default_protocol_versions()
                .is_ok()
        );
    }
}
