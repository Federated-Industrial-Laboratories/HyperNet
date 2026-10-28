// SPDX-License-Identifier: MIT
// Remote authority connectors expose only bounded same-network protocol1 control packets.
use crate::{
    authority_proof::{Digest, Scope, SignedRequest},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};

pub fn validate(network: Digest, incarnation: Digest, packet: &[u8]) -> Result<()> {
    let value = wire::decode(packet)?;
    let fields = value.array(5)?;
    let scope = Scope::parse(&fields[2])?;
    ensure!(
        fields[0].uint()? == 41
            && fields[1].uint()? == 1
            && scope.network == network
            && scope.incarnation == incarnation
            && matches!(fields[3].uint()?, 0..=4 | 6 | 7),
        "authority endpoint refuses management or foreign control frames"
    );
    let body = if matches!(fields[3].uint()?, 1 | 7) {
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
        1 | 7 => {
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
        6 => {
            let body = body.array(2)?;
            let request = crate::authority_read::Request::from_signed(body[0].bytes()?)?;
            ensure!(
                request.scope == scope,
                "fresh read submission context differs"
            );
            crate::authority_read::read_id(body[0].bytes()?, body[1].bytes()?)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
