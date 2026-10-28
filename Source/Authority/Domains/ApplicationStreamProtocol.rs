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
#[cfg(test)]
pub fn parse_challenge(bytes: &[u8], n: Digest, i: Digest, service: Digest) -> Result<Digest> {
    let v = wire::decode(bytes)?;
    let f = v.array(7)?;
    let nonce = id(&f[6])?;
    ensure!(
        challenge(n, i, service, nonce)? == bytes,
        "stream challenge context differs"
    );
    Ok(nonce)
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
pub fn parse_accepted(bytes: &[u8], proof: &Proof, binding: Digest) -> Result<VersionRef> {
    let v = wire::decode(bytes)?;
    let f = v.array(6)?;
    let r = version(&f[3])?;
    ensure!(
        r.kind == 173
            && r.id == proof.id()?
            && r.generation == proof.generation
            && accepted(&r, proof, binding)? == bytes,
        "stream acceptance differs"
    );
    Ok(r)
}
