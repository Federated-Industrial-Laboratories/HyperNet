// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
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
