// SPDX-License-Identifier: MIT
// Inner-channel challenges prevent relay sponsors from impersonating application principals.
use super::*;
pub const EXPORTER: &[u8] = b"EXPORTER-HyperNet-Application-Stream-1";
pub fn challenge(n: Digest, i: Digest, service: Digest, nonce: Digest) -> Result<Vec<u8>> {
    ensure!(nonce != [0; 32], "stream challenge is zero");
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("ApplicationStreamChallenge".into()),
        b(&n),
        b(&i),
        b(&service),
        b(&nonce),
    ]))
}

pub fn accepted(session: &VersionRef, proof: &Proof, binding: Digest) -> Result<Vec<u8>> {
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("ApplicationStreamAccepted".into()),
        reference(session),
        b(&wire::digest(&proof.envelope)),
        b(&binding),
    ]))
}

#[cfg(test)]
include!("../../../Tests/Support/Authority/Domains/ApplicationStreamProtocol.rs");
