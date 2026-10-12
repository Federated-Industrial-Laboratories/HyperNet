// SPDX-License-Identifier: MIT
// All authenticated network transports share the TLS 1.3 cipher policy.
pub fn tls_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    // Transitive TLS features cannot enable older cipher suites in this provider.
    provider
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    provider
}
