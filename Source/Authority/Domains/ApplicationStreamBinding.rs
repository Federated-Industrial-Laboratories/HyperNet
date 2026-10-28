// SPDX-License-Identifier: MIT
// A signed peer context is consumed by the SDK before any application payload is exposed.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub version: u64,
    pub id: Digest,
    pub network: Digest,
    pub incarnation: Digest,
    pub service: Digest,
    pub owner: Key,
    pub endpoint: Key,
    pub protocol: String,
}
impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.id != [0; 32]
                && self.network != [0; 32]
                && self.incarnation != [0; 32]
                && self.service != [0; 32],
            "invalid local application binding"
        );
        wire::valid_key(&self.owner)?;
        wire::valid_key(&self.endpoint)?;
        label(&V::Text(self.protocol.clone()), 96)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(wire::digest(&self.encode()?))
    }
    pub fn registration(&self, r: &Registration, route: &routes::RegisteredProfile) -> Result<()> {
        self.validate()?;
        ensure!(
            r.id == self.service
                && r.owner == self.owner
                && r.binding == self.digest()?
                && r.protocol == self.protocol
                && route.service == self.endpoint
                && r.route.id == route.identity.service
                && route.protocol == PROTOCOL
                && r.operator == route.operator,
            "application binding differs from consented service"
        );
        Ok(())
    }
}
pub fn local_challenge(nonce: Digest) -> Result<Vec<u8>> {
    ensure!(nonce != [0; 32], "local stream challenge is zero");
    wire::encode(&a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("ApplicationLocalChallenge".into()),
        b(&nonce),
    ]))
}
pub fn parse_local_challenge(bytes: &[u8]) -> Result<Digest> {
    let v = wire::decode(bytes)?;
    let f = v.array(4)?;
    let nonce = id(&f[3])?;
    ensure!(
        local_challenge(nonce)? == bytes,
        "invalid local stream challenge"
    );
    Ok(nonce)
}
pub fn context(
    binding: &Binding,
    session: &VersionRef,
    proof: &Proof,
    nonce: Digest,
    endpoint: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>> {
    ensure!(
        endpoint.verifying_key().to_bytes() == binding.endpoint
            && proof.service.id == binding.service
            && proof.protocol == binding.protocol
            && session.kind == 173
            && session.id == proof.id()?
            && session.generation == proof.generation
            && nonce != [0; 32],
        "local peer context differs from endpoint binding"
    );
    wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ApplicationPeerContext".into()),
            b(&binding.digest()?),
            reference(session),
            b(&proof.envelope),
            b(&nonce),
        ]))?,
        endpoint,
    )
}
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
