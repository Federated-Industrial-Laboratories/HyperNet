// SPDX-License-Identifier: MIT
// Consent pins are enforced during certificate verification, before HTTP data is sent.
use anyhow::{Context, Result};
use rustls::{
    DigitallySignedStruct, Error, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use std::sync::Arc;
#[derive(Debug)]
struct Pinned {
    standard: Arc<WebPkiServerVerifier>,
    digest: String,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let result = self
            .standard
            .verify_server_cert(cert, intermediates, name, ocsp, now)?;
        if crate::mail_authority::hash(cert.as_ref()) != self.digest {
            return Err(Error::General(
                "media host certificate differs from consent".into(),
            ));
        }
        Ok(result)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.standard.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.standard.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}
pub fn config(pem: &[u8], digest: &str) -> Result<rustls::ClientConfig> {
    crate::protocol::fixed_hex::<32>(digest).map_err(anyhow::Error::msg)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        roots.add(cert?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "media CA file contains no certificates");
    let provider = Arc::new(crate::transport::tls_provider());
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3 unavailable")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            standard: verifier,
            digest: digest.into(),
        }))
        .with_no_client_auth();
    Ok(config)
}
