// SPDX-License-Identifier: MIT
// Historical service activation receipts acknowledge a reported effect without authorizing another one.
use super::*;
use crate::authority_proof::{self as proof, Challenge, TrustDescriptor};
use crate::trust_bootstrap::Verified;
use ed25519_dalek::SigningKey;
pub const RECEIPT_LIMIT: usize = 3 * wire::MAXIMUM;
pub struct Receipt {
    bytes: Vec<u8>,
}
impl Receipt {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= RECEIPT_LIMIT,
            "activation receipt exceeds its bound"
        );
        let value = wire::decode_state(bytes)?;
        let f = value.array(12)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "RuntimeActivationReceipt",
            "invalid activation receipt"
        );
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn canonical(&self) -> &[u8] {
        &self.bytes
    }
    pub fn create(
        request: &Request,
        challenge: &[u8],
        ordered: &[u8],
        result: &proof::VerifiedResult,
        signer: &SigningKey,
        completed_at: u64,
    ) -> Result<Self> {
        ensure!(
            signer.verifying_key().to_bytes() == request.operation().recipient
                && result.disposition() == proof::Disposition::Permit,
            "activation completion requires its exact serving recipient"
        );
        let signed = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("RuntimeActivationComplete".into()),
                result.point().prefix().scope().value(),
                b(&request.intent().digest),
                b(&result.executed.result),
                V::Uint(request.operation().role),
                V::Uint(request.operation().local_generation),
                V::Uint(completed_at),
            ]))?,
            signer,
        )?;
        let continuity = result.continuity();
        let history = result.history();
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RuntimeActivationReceipt".into()),
            b(&request.encode()?),
            b(challenge),
            b(ordered),
            b(result.operation_result_bytes()),
            b(result.point().certificate()),
            a(continuity.ancestry.iter().map(|n| b(n)).collect()),
            history.map_or(V::Null, |h| b(h.checkpoint().canonical_proof())),
            history.map_or(V::Null, |h| b(h.canonical())),
            b(&signed),
        ]))?;
        Self::parse(&bytes)
    }
    pub fn verify(&self, bootstrap: &Verified, descriptor: &TrustDescriptor) -> Result<()> {
        let value = wire::decode_state(&self.bytes)?;
        let f = value.array(12)?;
        let request = Request::parse(f[3].bytes()?)?;
        let ancestry = f[8]
            .list(128)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let result = request.verify(
            bootstrap,
            descriptor,
            f[4].bytes()?,
            f[5].bytes()?,
            f[6].bytes()?,
            f[7].bytes()?,
            &ancestry,
        )?;
        let _history = if f[9] != V::Null {
            let checkpoint = f[9].bytes()?.to_vec();
            let history = f[10].bytes()?.to_vec();
            ensure!(
                checkpoint.len() <= wire::MAXIMUM && history.len() <= wire::MAXIMUM,
                "activation receipt history exceeds its bound"
            );
            Some((checkpoint, history))
        } else {
            f[10].null()?;
            None
        };
        let (completion, signatures) = wire::envelope(f[11].bytes()?, 1)?;
        let v = wire::decode(&completion)?;
        let c = v.array(9)?;
        let challenge = Challenge::from_signed(f[4].bytes()?)?;
        let completed_at = c[8].uint()?;
        ensure!(
            result.disposition() == proof::Disposition::Permit
                && signatures.len() == 1
                && signatures[0].0 == request.operation().recipient
                && c[0].uint()? == 200
                && c[1].uint()? == 1
                && c[2].text()? == "RuntimeActivationComplete"
                && proof::Scope::parse(&c[3])? == *descriptor.scope()
                && c[4].fixed::<32>()? == request.intent().digest
                && c[5].fixed::<32>()? == result.executed.result
                && c[6].uint()? == request.operation().role
                && c[7].uint()? == request.operation().local_generation
                && challenge
                    .completion_within_interval(completed_at, result.executed.expires_at_ms),
            "activation completion differs from its exact request, proof or validity interval"
        );
        Ok(())
    }
}
