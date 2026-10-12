// SPDX-License-Identifier: MIT
// A selected-store receipt reports one verified effect and cannot authorize another media operation.
use super::MediaRequest as Request;
use super::*;
use crate::{
    authority_proof::{self as proof, Challenge, TrustDescriptor, VerifiedResult},
    trust_bootstrap::Verified,
};
use ed25519_dalek::SigningKey;
pub const MEDIA_RECEIPT_LIMIT: usize = 4 * wire::MAXIMUM;
pub struct Receipt {
    bytes: Vec<u8>,
}
pub struct Report {
    result: VerifiedResult,
    response: Vec<u8>,
    history: Option<(Vec<u8>, Vec<u8>)>,
}
impl Report {
    pub(crate) fn result(&self) -> &VerifiedResult {
        &self.result
    }
    pub(crate) fn into_verified(self) -> VerifiedResult {
        self.result
    }
    pub fn request(&self) -> &Intent {
        self.result
            .request()
            .ordinary()
            .expect("typed media request")
    }
    pub fn response(&self) -> &[u8] {
        &self.response
    }
    pub(crate) fn into_result(
        self,
        store: &crate::authority_floor::Store,
    ) -> Result<VerifiedResult> {
        if self.result.extends(store.prefix()).is_ok() {
            return Ok(self.result);
        }
        let (checkpoint, history) = self
            .history
            .context("media receipt requires history repair from retained requester floor")?;
        store.attach_history(self.result, &checkpoint, &history)
    }
}
impl Receipt {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MEDIA_RECEIPT_LIMIT,
            "media receipt exceeds bound"
        );
        let v = wire::decode_state(bytes)?;
        let f = v.array(13)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "PageMediaEffectReceipt",
            "invalid media effect receipt"
        );
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
    pub fn canonical(&self) -> &[u8] {
        &self.bytes
    }
    pub fn scope(&self) -> Result<proof::Scope> {
        let v = wire::decode_state(&self.bytes)?;
        let f = v.array(13)?;
        let ordered = wire::decode(f[5].bytes()?)?;
        proof::Scope::parse(&ordered.array(6)?[2])
    }
    pub fn create(
        request: &Request,
        challenge: &[u8],
        ordered: &[u8],
        result: &VerifiedResult,
        response: &[u8],
        key: &SigningKey,
        completed: u64,
    ) -> Result<Self> {
        ensure!(
            result.disposition() == proof::Disposition::Permit
                && result.executed.recipient == key.verifying_key().to_bytes(),
            "media completion is not from exact selected service"
        );
        request.validate_response(&result.result, response)?;
        let completion = wire::sign_envelope(
            &wire::encode(&a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("PageMediaEffectComplete".into()),
                result.point().prefix().scope().value(),
                b(&request.intent().digest),
                b(&result.executed.result),
                b(&wire::digest(response)),
                V::Uint(completed),
            ]))?,
            key,
        )?;
        let continuity = result.continuity();
        let history = result.history();
        let bytes = wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageMediaEffectReceipt".into()),
            b(request.signed()),
            b(challenge),
            b(ordered),
            b(result.operation_result_bytes()),
            b(result.point().certificate()),
            a(continuity.ancestry.iter().map(|n| b(n)).collect()),
            history.map_or(V::Null, |h| b(h.checkpoint().canonical_proof())),
            history.map_or(V::Null, |h| b(h.canonical())),
            b(&completion),
            b(response),
        ]))?;
        Self::parse(&bytes)
    }
    pub fn refusal(
        request: &Request,
        challenge: &[u8],
        ordered: &[u8],
        result: &VerifiedResult,
    ) -> Result<Self> {
        ensure!(
            result.disposition() == proof::Disposition::Refuse,
            "non-refusal cannot omit a completion report"
        );
        let continuity = result.continuity();
        let history = result.history();
        Self::parse(&wire::encode_state(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageMediaEffectReceipt".into()),
            b(request.signed()),
            b(challenge),
            b(ordered),
            b(result.operation_result_bytes()),
            b(result.point().certificate()),
            a(continuity.ancestry.iter().map(|n| b(n)).collect()),
            history.map_or(V::Null, |h| b(h.checkpoint().canonical_proof())),
            history.map_or(V::Null, |h| b(h.canonical())),
            V::Null,
            V::Null,
        ]))?)
    }
    pub fn verify(&self, bootstrap: &Verified, descriptor: &TrustDescriptor) -> Result<Report> {
        let v = wire::decode_state(&self.bytes)?;
        let f = v.array(13)?;
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
            &[],
        )?;
        let history = if f[9] != V::Null {
            let cp = f[9].bytes()?.to_vec();
            let h = f[10].bytes()?.to_vec();
            ensure!(
                cp.len() <= wire::MAXIMUM && h.len() <= wire::MAXIMUM,
                "media receipt history exceeds bound"
            );
            Some((cp, h))
        } else {
            f[10].null()?;
            None
        };
        if result.disposition() == proof::Disposition::Refuse {
            f[11].null()?;
            f[12].null()?;
            return Ok(Report {
                result,

                response: vec![],
                history,
            });
        }
        let (payload, signatures) = wire::envelope(f[11].bytes()?, 1)?;
        let c = wire::decode(&payload)?;
        let c = c.array(8)?;
        let completed = c[7].uint()?;
        let challenge = Challenge::from_signed(f[4].bytes()?)?;
        ensure!(
            result.disposition() == proof::Disposition::Permit
                && signatures.len() == 1
                && signatures[0].0 == result.executed.recipient
                && c[0].uint()? == 200
                && c[1].uint()? == 1
                && c[2].text()? == "PageMediaEffectComplete"
                && proof::Scope::parse(&c[3])? == *descriptor.scope()
                && c[4].fixed::<32>()? == request.intent().digest
                && c[5].fixed::<32>()? == result.executed.result
                && c[6].fixed::<32>()? == wire::digest(f[12].bytes()?)
                && challenge.completion_within_interval(completed, result.executed.expires_at_ms),
            "media completion differs from exact certified request or validity interval"
        );
        request.validate_response(&result.result, f[12].bytes()?)?;
        Ok(Report {
            result,

            response: f[12].bytes()?.to_vec(),
            history,
        })
    }
}
