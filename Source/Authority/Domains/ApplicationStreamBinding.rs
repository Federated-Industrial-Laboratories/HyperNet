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
include!("../../../Tests/Support/Authority/Domains/ApplicationStreamBinding.rs");
