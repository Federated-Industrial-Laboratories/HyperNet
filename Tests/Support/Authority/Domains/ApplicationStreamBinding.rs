// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerContext {
    pub network: String,
    pub incarnation: String,
    pub service: String,
    pub protocol: String,
    pub principal: String,
    pub grant: String,
    pub grant_generation: u64,
    pub session: String,
    pub generation: u64,
    pub expires_ms: u64,
    pub maximum_bytes: u64,
    pub idle_ms: u64,
    pub duration_ms: u64,
}

#[cfg(test)]
pub fn verify_context(bytes: &[u8], binding: &Binding, nonce: Digest) -> Result<PeerContext> {
    let (payload, signatures) = wire::envelope(bytes, 1)?;
    let v = wire::decode(&payload)?;
    let f = v.array(7)?;
    ensure!(
        f[0].uint()? == 200
            && f[1].uint()? == 1
            && f[2].text()? == "ApplicationPeerContext"
            && id(&f[3])? == binding.digest()?
            && id(&f[6])? == nonce
            && signatures.len() == 1
            && signatures[0].0 == binding.endpoint,
        "local stream context signature or binding differs"
    );
    let r = version(&f[4])?;
    let p = Proof::parse(f[5].bytes()?, binding.network, binding.incarnation)?;
    ensure!(
        r.kind == 173
            && r.id == p.id()?
            && r.generation == p.generation
            && p.service.id == binding.service
            && p.protocol == binding.protocol,
        "local context names another stream"
    );
    Ok(PeerContext {
        network: hex::encode(binding.network),
        incarnation: hex::encode(binding.incarnation),
        service: hex::encode(binding.service),
        protocol: binding.protocol.clone(),
        principal: hex::encode(p.principal),
        grant: hex::encode(p.grant.id),
        grant_generation: p.grant.generation,
        session: hex::encode(r.id),
        generation: r.generation,
        expires_ms: p.expires,
        maximum_bytes: p.limits.bytes,
        idle_ms: p.limits.idle_ms,
        duration_ms: p.limits.duration_ms,
    })
}
