// SPDX-License-Identifier: MIT
// The final TLS endpoint exposes exactly one consented framed application protocol.
use crate::{
    authority_proof::{Digest, Scope},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};

#[path = "AuthorityConnectorPacket.rs"]
mod authority_packet;

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
        authority_packet::validate(network, incarnation, packet)?;
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

/// A matching local pending reply keeps an already validated authority exchange active.
pub(crate) fn authority_request_pending(packet: &[u8], reply: &[u8]) -> bool {
    let pending = || -> Result<bool> {
        let request = wire::decode(packet)?;
        let request = request.array(5)?;
        ensure!(
            request[0].uint()? == 41 && request[1].uint()? == 1,
            "invalid authority request"
        );
        let scope = Scope::parse(&request[2])?;
        let operation = request[3].uint()?;
        let digest = match operation {
            0 => {
                let submission = wire::decode(request[4].bytes()?)?;
                wire::digest(submission.array(2)?[0].bytes()?)
            }
            1 | 7 => request[4].fixed::<32>()?,
            6 => {
                let submission = wire::decode(request[4].bytes()?)?;
                let submission = submission.array(2)?;
                crate::authority_read::read_id(submission[0].bytes()?, submission[1].bytes()?)?
            }
            _ => return Ok(false),
        };
        let response = wire::decode(reply)?;
        let response = response.array(10)?;
        let kind = if matches!(operation, 6 | 7) { 62 } else { 42 };
        Ok(response[0].uint()? == kind
            && response[1].uint()? == 1
            && Scope::parse(&response[2])? == scope
            && response[3].uint()? == 0
            && response[4].uint()? == 0
            && response[5].fixed::<32>()? == digest
            && response[6..9].iter().all(|value| *value == V::Null)
            && response[9].array(0)?.is_empty())
    };
    pending().unwrap_or(false)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteEndpointUnitTests.rs"]
mod tests;
