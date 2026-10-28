// SPDX-License-Identifier: MIT
// Relay admission binds a distinct proof key to the fresh TLS channel and one exact destination.
use crate::{
    authority_proof::Digest,
    route_profile::Limits,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
pub const FRAME: usize = wire::MAXIMUM;
pub const EXPORTER: &[u8] = b"EXPORTER-HyperNet-Route-1";
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn encode(label: &str, values: Vec<V>) -> Result<Vec<u8>> {
    let mut out = vec![V::Uint(200), V::Uint(1), V::Text(label.into())];
    out.extend(values);
    wire::encode(&V::Array(out))
}
fn fields<'a>(value: &'a V, label: &str, count: usize) -> Result<&'a [V]> {
    let fields = value.array(count)?;
    ensure!(
        fields[0].uint()? == 200 && fields[1].uint()? == 1 && fields[2].text()? == label,
        "route frame type differs"
    );
    Ok(fields)
}
pub fn random() -> Result<Digest> {
    let mut nonce = [0; 32];
    OsRng.try_fill_bytes(&mut nonce)?;
    ensure!(nonce != [0; 32], "route nonce is zero");
    Ok(nonce)
}
#[derive(Clone, Debug)]
pub struct Open {
    pub network: Digest,
    pub incarnation: Digest,
    pub relay: Digest,
    pub service: Digest,
    pub voucher: Vec<u8>,
    pub nonce: Digest,
    pub attachment: bool,
}
impl Open {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.network != [0; 32]
                && self.incarnation != [0; 32]
                && self.relay != [0; 32]
                && self.service != [0; 32]
                && self.nonce != [0; 32],
            "route open has zero identity"
        );
        ensure!(
            (self.attachment && self.voucher.is_empty())
                || (!self.attachment
                    && !self.voucher.is_empty()
                    && self.voucher.len() <= FRAME / 2),
            "route open voucher differs from its purpose"
        );
        encode(
            if self.attachment {
                "RouteAttach"
            } else {
                "RouteOpen"
            },
            vec![
                b(&self.network),
                b(&self.incarnation),
                b(&self.relay),
                b(&self.service),
                b(&self.voucher),
                b(&self.nonce),
            ],
        )
    }
    #[allow(dead_code)] // Shared server admission parser.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v = wire::decode(bytes)?;
        let f = v.array(9)?;
        let label = f[2].text()?;
        ensure!(
            matches!(label, "RouteOpen" | "RouteAttach"),
            "unsupported route open"
        );
        fields(&v, label, 9)?;
        let out = Self {
            network: f[3].fixed()?,
            incarnation: f[4].fixed()?,
            relay: f[5].fixed()?,
            service: f[6].fixed()?,
            voucher: f[7].bytes()?.to_vec(),
            nonce: f[8].fixed()?,
            attachment: label == "RouteAttach",
        };
        ensure!(out.encode()? == bytes, "noncanonical route open");
        Ok(out)
    }
    pub fn binding(&self, challenge: Digest, exporter: Digest) -> Result<Vec<u8>> {
        ensure!(
            challenge != [0; 32] && exporter != [0; 32],
            "route channel binding is absent"
        );
        encode(
            "RoutePossession",
            vec![
                b(&wire::digest(&self.encode()?)),
                b(&challenge),
                b(&exporter),
            ],
        )
    }
    pub fn sign(&self, challenge: Digest, exporter: Digest, key: &SigningKey) -> Result<Vec<u8>> {
        wire::sign_envelope(&self.binding(challenge, exporter)?, key)
    }
    #[allow(dead_code)] // Shared server possession verifier.
    pub fn verify(&self, challenge: Digest, exporter: Digest, signed: &[u8]) -> Result<Digest> {
        let (payload, signatures) = wire::envelope(signed, 1)?;
        ensure!(
            payload == self.binding(challenge, exporter)? && signatures.len() == 1,
            "route proof is not bound to this connection"
        );
        Ok(signatures[0].0)
    }
}
pub fn challenge(nonce: Digest) -> Result<Vec<u8>> {
    ensure!(nonce != [0; 32], "route challenge is zero");
    encode("RouteChallenge", vec![b(&nonce)])
}
pub fn parse_challenge(bytes: &[u8]) -> Result<Digest> {
    let value = wire::decode(bytes)?;
    let f = fields(&value, "RouteChallenge", 4)?;
    let nonce = f[3].fixed()?;
    ensure!(challenge(nonce)? == bytes, "noncanonical route challenge");
    Ok(nonce)
}
#[allow(dead_code)] // Shared server admission response constructor.
pub fn ready(binding: Digest, limits: Limits) -> Result<Vec<u8>> {
    limits.validate()?;
    encode(
        "RouteReady",
        vec![
            b(&binding),
            V::Uint(limits.bytes),
            V::Uint(limits.duration_ms),
            V::Uint(limits.idle_ms),
        ],
    )
}
pub fn parse_ready(bytes: &[u8], binding: Digest, limits: Limits) -> Result<Limits> {
    let value = wire::decode(bytes)?;
    let f = fields(&value, "RouteReady", 7)?;
    let actual = Limits {
        bytes: f[4].uint()?,
        duration_ms: f[5].uint()?,
        idle_ms: f[6].uint()?,
    };
    actual.validate()?;
    ensure!(
        f[3].fixed::<32>()? == binding
            && actual.bytes <= limits.bytes
            && actual.duration_ms <= limits.duration_ms
            && actual.idle_ms <= limits.idle_ms,
        "route admission differs from connection or exceeds selected limits"
    );
    Ok(actual)
}

#[allow(dead_code)] // Shared final-service readiness constructor.
pub fn endpoint_ready(
    network: Digest,
    incarnation: Digest,
    service: Digest,
    protocol: u64,
) -> Result<Vec<u8>> {
    ensure!(
        network != [0; 32]
            && incarnation != [0; 32]
            && service != [0; 32]
            && (1..=7).contains(&protocol),
        "invalid final service readiness identity"
    );
    encode(
        "EndpointReady",
        vec![b(&network), b(&incarnation), b(&service), V::Uint(protocol)],
    )
}
#[allow(dead_code)] // Shared client readiness verifier.
pub fn parse_endpoint_ready(
    bytes: &[u8],
    network: Digest,
    incarnation: Digest,
    service: Digest,
    protocol: u64,
) -> Result<()> {
    ensure!(
        bytes == endpoint_ready(network, incarnation, service, protocol)?,
        "final service readiness differs from selected endpoint"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_readiness_binds_exact_selected_service_and_protocol() {
        let bytes = endpoint_ready([1; 32], [2; 32], [3; 32], 1).unwrap();
        parse_endpoint_ready(&bytes, [1; 32], [2; 32], [3; 32], 1).unwrap();
        assert!(parse_endpoint_ready(&bytes, [4; 32], [2; 32], [3; 32], 1).is_err());
        assert!(parse_endpoint_ready(&bytes, [1; 32], [4; 32], [3; 32], 1).is_err());
        assert!(parse_endpoint_ready(&bytes, [1; 32], [2; 32], [4; 32], 1).is_err());
        assert!(parse_endpoint_ready(&bytes, [1; 32], [2; 32], [3; 32], 2).is_err());
        let mut extra = bytes;
        extra.push(0);
        assert!(parse_endpoint_ready(&extra, [1; 32], [2; 32], [3; 32], 1).is_err());
    }
    #[test]
    fn route_possession_cannot_move_between_channels_or_destinations() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let open = Open {
            network: [1; 32],
            incarnation: [2; 32],
            relay: [3; 32],
            service: [4; 32],
            voucher: vec![5],
            nonce: [6; 32],
            attachment: false,
        };
        let proof = open.sign([7; 32], [8; 32], &key).unwrap();
        assert_eq!(
            open.verify([7; 32], [8; 32], &proof).unwrap(),
            key.verifying_key().to_bytes()
        );
        assert!(open.verify([10; 32], [8; 32], &proof).is_err());
        assert!(open.verify([7; 32], [10; 32], &proof).is_err());
        let mut changed = open.clone();
        changed.service = [11; 32];
        assert!(changed.verify([7; 32], [8; 32], &proof).is_err());
        changed = open;
        changed.attachment = true;
        changed.voucher.clear();
        assert!(changed.verify([7; 32], [8; 32], &proof).is_err());
    }
}
