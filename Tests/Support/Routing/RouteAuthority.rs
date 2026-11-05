// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
impl Renewal {
    pub(crate) fn fixture(voucher: VersionRef, target: Vec<u8>, total_expires: u64) -> Self {
        Self {
            voucher,
            target,
            relay: b"Exact relay envelope".to_vec(),
            total_expires,
        }
    }
}

#[cfg(test)]
impl StreamCheck {
    pub(crate) fn fixture(session: VersionRef, deadline: u64, expiry: Option<u64>) -> Self {
        Self {
            authority: streams::control::Authority {
                network: [1; 32],
                incarnation: [2; 32],
                configuration: [3; 32],
                epoch: 1,
                height: 1,
                state: [4; 32],
                statement_digest: [5; 32],
                evaluated_at_ms: 1_000_000,
                expires_at_ms: 1_005_000,
                code: 0,
            },
            deadline,
            renewal: expiry.map(|expires| CertifiedStreamPermit { session, expires }),
            endpoint_renewal: expiry.map(|expires| CertifiedEndpointPermit {
                binding: EndpointBinding(wire::digest(b"Exact endpoint profile")),
                expires,
            }),
        }
    }
}
