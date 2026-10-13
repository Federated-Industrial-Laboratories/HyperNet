// SPDX-License-Identifier: MIT
// The final TLS endpoint exposes exactly one consented framed application protocol.
use crate::{
    authority_proof::{Digest, Scope, SignedRequest},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};

pub fn validate_packet(
    protocol: u64,
    network: Digest,
    incarnation: Digest,
    packet: &[u8],
) -> Result<()> {
    let value = wire::decode(packet)?;
    let fields = value.list(16)?;
    ensure!(
        fields.len() >= 3 && fields[1].uint()? == 1,
        "unsupported private application frame"
    );
    if protocol == 1 {
        let fields = value.array(5)?;
        let scope = Scope::parse(&fields[2])?;
        ensure!(
            fields[0].uint()? == 41
                && scope.network == network
                && scope.incarnation == incarnation
                && fields[3].uint()? <= 4,
            "authority endpoint refuses management or foreign control frames"
        );
        let body = if fields[3].uint()? == 1 {
            V::Null
        } else {
            wire::decode(fields[4].bytes()?)?
        };
        match fields[3].uint()? {
            0 => {
                let submission = body.array(2)?;
                let ordered = wire::decode(submission[0].bytes()?)?;
                let ordered = ordered.array(6)?;
                ensure!(
                    ordered[0].uint()? == 22
                        && ordered[1].uint()? == 1
                        && Scope::parse(&ordered[2])? == scope,
                    "authority submission context differs"
                );
                let signed = SignedRequest::from_signed(ordered[3].bytes()?)?;
                ensure!(
                    signed.network() == network && signed.incarnation() == incarnation,
                    "authority submission has another network identity"
                );
            }
            1 => {
                fields[4].fixed::<32>()?;
            }
            2 => {
                body.array(0)?;
            }
            3 => {
                let body = body.array(3)?;
                body[0].uint()?;
                body[1].fixed::<32>()?;
                body[2].fixed::<32>()?;
            }
            4 => {
                let body = body.array(5)?;
                body[0].uint()?;
                body[1].fixed::<32>()?;
                if body[2] != V::Null {
                    body[2].fixed::<32>()?;
                }
                body[3].uint()?;
                if body[4] != V::Null {
                    body[4].fixed::<32>()?;
                }
            }
            _ => unreachable!(),
        }
    } else {
        ensure!(
            fields[0].uint()? == 200,
            "private application frame kind differs"
        );
        let tag = fields[2].text()?;
        ensure!(
            match protocol {
                2 => tag == "ContentExchange",
                3 => tag == "MediaExchange",
                4 => tag == "MailExchange",
                5 => tag == "TransferExchange",
                _ => false,
            },
            "private route protocol does not expose this operation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_endpoint_refuses_management_and_foreign_scope() {
        let frame = |operation, network| {
            wire::encode(&V::Array(vec![
                V::Uint(41),
                V::Uint(1),
                Scope {
                    network,
                    incarnation: [2; 32],
                    configuration: [3; 32],
                    epoch: 1,
                }
                .value(),
                V::Uint(operation),
                V::Bytes(wire::encode(&V::Array(vec![])).unwrap()),
            ]))
            .unwrap()
        };
        assert!(validate_packet(1, [1; 32], [2; 32], &frame(2, [1; 32])).is_ok());
        assert!(validate_packet(1, [1; 32], [2; 32], &frame(5, [1; 32])).is_err());
        assert!(validate_packet(1, [1; 32], [2; 32], &frame(2, [3; 32])).is_err());
        let sync = wire::encode(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("BridgeSync".into()),
            V::Bytes(vec![9; 32]),
            V::Null,
        ]))
        .unwrap();
        assert!(validate_packet(6, [1; 32], [2; 32], &sync).is_err());
    }

    #[test]
    fn private_endpoint_allows_unspecified_target_only_for_checkpoint_preparation() {
        let scope = Scope {
            network: [1; 32],
            incarnation: [2; 32],
            configuration: [3; 32],
            epoch: 1,
        };
        let packet = |operation, body| {
            wire::encode(&V::Array(vec![
                V::Uint(41),
                V::Uint(1),
                scope.value(),
                V::Uint(operation),
                V::Bytes(wire::encode(&V::Array(body)).unwrap()),
            ]))
            .unwrap()
        };
        let body = vec![
            V::Uint(0),
            V::Bytes(vec![4; 32]),
            V::Null,
            V::Uint(0),
            V::Null,
        ];
        assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, body.clone())).is_ok());
        assert!(validate_packet(1, [1; 32], [2; 32], &packet(3, body[..3].to_vec())).is_err());
        assert!(validate_packet(1, [1; 32], [2; 32], &packet(5, body.clone())).is_err());
        assert!(validate_packet(1, [9; 32], [2; 32], &packet(4, body.clone())).is_err());
        let mut wrong = body.clone();
        wrong[2] = V::Bytes(vec![4; 31]);
        assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, wrong)).is_err());
        let mut exact = body;
        exact[2] = V::Bytes(vec![5; 32]);
        assert!(validate_packet(1, [1; 32], [2; 32], &packet(4, exact)).is_ok());
    }
}
