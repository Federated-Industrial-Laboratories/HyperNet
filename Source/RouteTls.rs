// SPDX-License-Identifier: MIT
// Exact Ed25519 leaves supplement ordinary WebPKI validation on fresh TLS1.3 sessions.
use crate::route_profile::Identity;
use anyhow::{Result, ensure};
use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use std::sync::Arc;

pub const ALPN: &[u8] = b"HyperNetRoute/1";
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|s| s.version().version == rustls::ProtocolVersion::TLSv1_3);
    Arc::new(provider)
}
#[derive(Debug)]
struct Pinned {
    standard: Arc<WebPkiServerVerifier>,
    leaf: Vec<u8>,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if leaf.as_ref() != self.leaf {
            return Err(rustls::Error::General(
                "route transport identity differs".into(),
            ));
        }
        self.standard
            .verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls12_signature(message, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls13_signature(message, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}
pub fn client(identity: &Identity) -> Result<Arc<rustls::ClientConfig>> {
    identity.validate()?;
    let provider = provider();
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(identity.certificate_authority_pem.as_bytes())
    {
        roots.add(certificate?)?;
    }
    ensure!(!roots.is_empty(), "route trust roots absent");
    let standard =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            standard,
            leaf: identity.leaf_der.clone(),
        }))
        .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}
#[allow(dead_code)] // Shared reader builds use only the client half of the same TLS contract.
pub fn server(
    identity: &Identity,
    certificate_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>> {
    identity.validate()?;
    let certificates =
        CertificateDer::pem_slice_iter(certificate_pem).collect::<Result<Vec<_>, _>>()?;
    ensure!(
        certificates
            .first()
            .is_some_and(|v| v.as_ref() == identity.leaf_der),
        "route server leaf differs from consent"
    );
    let key = PrivateKeyDer::from_pem_slice(key_pem)?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}
