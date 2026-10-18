// SPDX-License-Identifier: MIT
// Bridge peers use exact consented literal endpoints, TLS1.3 and pinned mutually authenticated leaves.
use super::*;
use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use sha2::{Digest as _, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const FRAME: usize = 4 * wire::MAXIMUM;
#[derive(Debug)]
struct PinnedVerifier {
    standard: Arc<WebPkiServerVerifier>,
    pin: Digest,
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(leaf.as_ref()).as_slice() != self.pin.as_slice() {
            return Err(rustls::Error::General(
                "Peer certificate pin differs".into(),
            ));
        }
        self.standard
            .verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard
            .verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard
            .verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}

pub struct Route {
    pub endpoint: crate::runtime_manifest::Endpoint,
    connector: tokio_rustls::TlsConnector,
}
pub struct Transport {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub listen: SocketAddr,
    routes: BTreeMap<Digest, Route>,
}
impl Transport {
    pub fn load(config: &Config) -> Result<Self> {
        let provider = Arc::new(crate::transport::tls_provider());
        let certs = CertificateDer::pem_slice_iter(&files::read(
            Path::new("/Config/Certificate.pem"),
            65536,
            true,
        )?)
        .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(!certs.is_empty(), "bridge certificate absent");
        let key = PrivateKeyDer::from_pem_slice(&files::read(
            Path::new("/Config/Transport.key"),
            16384,
            true,
        )?)?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&files::read(
            Path::new("/Config/CertificateAuthority.pem"),
            65536,
            true,
        )?) {
            roots.add(cert?)?;
        }
        ensure!(!roots.is_empty(), "bridge trust roots absent");
        let roots = Arc::new(roots);
        let role = config
            .profile
            .manifest
            .roles
            .iter()
            .find(|r| r.role == 7)
            .context("bridge role absent")?;
        let own = config
            .profile
            .manifest
            .endpoints
            .iter()
            .find(|e| role.bind_endpoint_ids == [e.endpoint_id])
            .context("bridge listener absent")?;
        ensure!(
            own.service_key == config.profile.service && certs[0].as_ref() == own.leaf_der,
            "bridge TLS leaf differs from own consent"
        );
        let server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    roots.clone(),
                    provider.clone(),
                )
                .build()?,
            )
            .with_single_cert(certs.clone(), key.clone_key())?;
        let mut routes = BTreeMap::new();
        for id in &role.outbound_endpoint_ids {
            let e = config
                .profile
                .manifest
                .endpoints
                .iter()
                .find(|e| e.endpoint_id == *id)
                .context("bridge counterpart endpoint absent")?;
            let standard =
                WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                    .build()?;
            let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                    standard,
                    pin: Sha256::digest(&e.leaf_der).into(),
                }))
                .with_client_auth_cert(certs.clone(), key.clone_key())?;
            ensure!(
                e.service_key != config.profile.service
                    && routes
                        .insert(
                            e.service_key,
                            Route {
                                endpoint: e.clone(),
                                connector: tokio_rustls::TlsConnector::from(Arc::new(tls))
                            }
                        )
                        .is_none(),
                "bridge counterpart service repeats"
            );
        }
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
            listen: SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), own.port),
            routes,
        })
    }
    pub fn incoming(
        &self,
        socket: tokio::net::TcpStream,
        deadline: u64,
    ) -> impl std::future::Future<
        Output = Result<(
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            Digest,
            Vec<u8>,
            u64,
        )>,
    > + Send
    + 'static {
        let acceptor = self.acceptor.clone();
        let peers = self
            .routes
            .iter()
            .map(|(key, route)| (*key, route.endpoint.leaf_der.clone()))
            .collect::<Vec<_>>();
        async move {
            tokio::time::timeout(
                Duration::from_millis(transport::remaining(deadline)?),
                async move {
                    socket.set_nodelay(true)?;
                    let mut stream = acceptor.accept(socket).await?;
                    let leaf = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|v| v.first())
                        .context("bridge client certificate absent")?;
                    let sender = peers
                        .iter()
                        .find(|(_, pinned)| pinned.as_slice() == leaf.as_ref())
                        .map(|(key, _)| *key)
                        .context("bridge client leaf is not an exact consented counterpart")?;
                    let input = receive(&mut stream).await?;
                    Ok((stream, sender, input, deadline))
                },
            )
            .await
            .context("bridge peer ingress deadline expired")?
        }
    }
    pub async fn exchange(&self, peer: Digest, packet: &[u8], deadline: u64) -> Result<Vec<u8>> {
        let route = self
            .routes
            .get(&peer)
            .context("counterpart bridge has no consented TLS route")?;
        let future = async {
            let socket = tokio::net::TcpStream::connect(SocketAddr::new(
                route.endpoint.address,
                route.endpoint.port,
            ))
            .await?;
            socket.set_nodelay(true)?;
            let mut stream = route
                .connector
                .connect(ServerName::IpAddress(route.endpoint.address.into()), socket)
                .await?;
            send(&mut stream, packet).await?;
            receive(&mut stream).await
        };
        tokio::time::timeout(
            Duration::from_millis(transport::remaining(deadline)?),
            future,
        )
        .await
        .context("bridge TLS exchange deadline expired")?
    }
}
pub async fn receive<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let count = stream.read_u32().await? as usize;
    ensure!(count > 0 && count <= FRAME, "bridge frame exceeds bound");
    let mut bytes = vec![0; count];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= FRAME,
        "bridge response exceeds bound"
    );
    stream.write_u32(u32::try_from(bytes.len())?).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
