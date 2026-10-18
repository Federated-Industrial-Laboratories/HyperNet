// SPDX-License-Identifier: MIT
// Remote bridge reads bind one reader capability and exact inert request to the selected endpoint.
use crate::{
    authority_domains::{self as domain, federation},
    authority_proof::{Digest, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
#[derive(Clone, Debug)]
pub struct Reader {
    pub endpoint: Digest,
    pub reader: Key,
    pub grant: VersionRef,
    pub action: u64,
    pub expires: u64,
    pub packet: Vec<u8>,
    pub agreement: Digest,
    pub page: Option<[u8; 16]>,
    pub revision: Option<VersionRef>,
    pub trust: Vec<u8>,
    pub floor: Vec<u8>,
}
impl Reader {
    pub fn parse(envelope: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        ensure!(
            envelope.len() <= wire::MAXIMUM,
            "reader route envelope exceeds bound"
        );
        let (payload, signatures) = wire::envelope(envelope, 1)?;
        let value = wire::decode(&payload)?;
        let f = value.array(12)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "RouteBridgeRead"
                && f[3].fixed::<32>()? == network
                && f[4].fixed::<32>()? == incarnation,
            "bridge reader scope differs"
        );
        let reader = f[6].fixed()?;
        let grant = domain::version(&f[7])?;
        let action = f[8].uint()?;
        let endpoint = f[5].fixed()?;
        let nonce = f[10].fixed()?;
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == reader
                && grant.kind == 102
                && matches!(action, 0 | 1 | 3)
                && endpoint != [0; 32]
                && nonce != [0; 32]
                && f[9].uint()? > 0,
            "bridge reader signature, capability or purpose differs"
        );
        let packet = f[11].bytes()?.to_vec();
        let value = wire::decode(&packet)?;
        let p = value.array(10)?;
        ensure!(
            p[0].uint()? == 200 && p[1].uint()? == 1 && p[2].text()? == "BridgeLease",
            "only exact reader BridgeLease packets are permitted"
        );
        let agreement = p[3].fixed()?;
        let page = if p[4] == V::Null {
            None
        } else {
            Some(p[4].fixed()?)
        };
        let revision = if p[5] == V::Null {
            None
        } else {
            Some(domain::version(&p[5])?)
        };
        let after = if p[6] == V::Null {
            None
        } else {
            Some(p[6].fixed::<32>()?)
        };
        let include_body = p[9].boolean()?;
        ensure!(
            agreement != [0; 32]
                && match (page, revision.as_ref(), after, include_body) {
                    (None, None, _, false) => true,
                    (Some(_), Some(r), None, _) => r.kind == 141,
                    _ => false,
                },
            "bridge reader page, revision or catalogue shape differs"
        );
        let trust = p[7].bytes()?.to_vec();
        let floor = p[8].bytes()?.to_vec();
        let trust_record = domain::Record::parse(&trust, network, incarnation)?;
        let floor_record = domain::Record::parse(&floor, network, incarnation)?;
        ensure!(
            trust_record.reference.kind == 150
                && floor_record.reference.kind == 157
                && trust_record.reference.id == floor_record.reference.id,
            "bridge reader foreign trust closure differs"
        );
        Ok(Self {
            endpoint,
            reader,
            grant,
            action,
            expires: f[9].uint()?,
            packet,
            agreement,
            page,
            revision,
            trust,
            floor,
        })
    }
    pub fn command(&self) -> federation::Command {
        self.page.map_or(
            federation::Command::InventoryContext {
                agreement: self.agreement,
                action: self.action,
            },
            |page| federation::Command::PageContext {
                agreement: self.agreement,
                page,
                action: self.action,
            },
        )
    }
}
#[allow(dead_code)] // The shared client signer is not used by installed endpoint services.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    network: Digest,
    incarnation: Digest,
    endpoint: Digest,
    grant: &VersionRef,
    action: u64,
    expires: u64,
    nonce: Digest,
    packet: &[u8],
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let b = |v: &[u8]| V::Bytes(v.to_vec());
    let payload = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("RouteBridgeRead".into()),
        b(&network),
        b(&incarnation),
        b(&endpoint),
        b(&key.verifying_key().to_bytes()),
        crate::authority_membership::reference(grant),
        V::Uint(action),
        V::Uint(expires),
        b(&nonce),
        b(packet),
    ]))?;
    let bytes = wire::sign_envelope(&payload, key)?;
    Reader::parse(&bytes, network, incarnation)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_reader_route_never_accepts_operator_bridge_commands() {
        let signer = SigningKey::from_bytes(&[9; 32]);
        let grant = VersionRef {
            kind: 102,
            id: [8; 32],
            generation: 1,
            digest: [7; 32],
        };
        for name in ["BridgeSync", "BridgeActivate", "BridgeWithdraw"] {
            let packet = wire::encode(&V::Array(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text(name.into()),
                V::Bytes(vec![1; 32]),
                V::Null,
            ]))
            .unwrap();
            assert!(
                sign(
                    [1; 32], [2; 32], [3; 32], &grant, 0, 5000, [4; 32], &packet, &signer
                )
                .is_err()
            );
        }
    }
}
