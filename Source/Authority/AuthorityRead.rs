// SPDX-License-Identifier: MIT
// Fresh quorum reads bind a live challenge to independently evaluated durable state.
use crate::{
    authority_challenge::{ClockHealth, Session},
    authority_domains::{self as domains, Operation},
    authority_proof::{
        self as proof, CertifiedPoint, Challenge, Digest, Key, OperationResult, Prefix, Scope,
        TrustDescriptor, VersionRef,
    },
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;

#[path = "AuthorityReadEvaluation.rs"]
mod evaluation;
pub(crate) use evaluation::evaluate_domain;
pub use evaluation::verify_domain;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn record(v: &V, kind: u64, n: usize) -> Result<&[V]> {
    let f = v.array(n)?;
    ensure!(
        f[0].uint()? == kind && f[1].uint()? == 1,
        "fresh read record differs"
    );
    Ok(f)
}
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "The finite query owns its exact parsed domain operation."
)]
pub enum Query {
    PolicyContext,
    Domain(Operation),
}
impl Query {
    pub fn value(&self) -> Result<V> {
        Ok(match self {
            Self::PolicyContext => a(vec![V::Uint(0)]),
            Self::Domain(op) => a(vec![V::Uint(1), b(&op.parameters()?)]),
        })
    }
    fn parse(v: &V, scope: &Scope, minimum: u64) -> Result<Self> {
        let f = v.list(2)?;
        match f.first().context("empty fresh query")?.uint()? {
            0 => {
                v.array(1)?;
                Ok(Self::PolicyContext)
            }
            1 => {
                let f = v.array(2)?;
                let op =
                    Operation::from_parameters(f[1].bytes()?, scope.network, scope.incarnation)?;
                ensure!(
                    matches!(
                        &op.command,
                        domains::Command::Stream(
                            domains::streams::Command::Permit { .. }
                                | domains::streams::Command::Lookup { .. }
                                | domains::streams::Command::Inspect { .. }
                        ) | domains::Command::Page(domains::page::Command::View { .. })
                            | domains::Command::Route(
                                domains::routes::Command::Lookup { .. }
                                    | domains::routes::Command::VoucherContext { .. }
                            )
                    ),
                    "operation is not a fresh read"
                );
                ensure!(
                    op.snapshot.epoch == scope.epoch && op.snapshot.height == minimum,
                    "fresh read snapshot differs"
                );
                Ok(Self::Domain(op))
            }
            _ => anyhow::bail!("unsupported fresh query"),
        }
    }
    pub fn action(&self) -> &'static str {
        match self {
            Self::PolicyContext => "AuthorityPolicyContext",
            Self::Domain(_) => "AuthorityDomain",
        }
    }
    pub fn expected(&self) -> &[VersionRef] {
        match self {
            Self::PolicyContext => &[],
            Self::Domain(op) => &op.snapshot.references,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    pub scope: Scope,
    pub requester: Key,
    pub recipient: Key,
    pub client_nonce: Digest,
    pub minimum_height: u64,
    pub query: Query,
    pub digest: Digest,
}
impl Request {
    pub fn sign(
        scope: &Scope,
        signer: &SigningKey,
        recipient: Key,
        nonce: Digest,
        minimum_height: u64,
        query: Query,
    ) -> Result<Vec<u8>> {
        let payload = wire::encode(&a(vec![
            V::Uint(60),
            V::Uint(1),
            scope.value(),
            b(&signer.verifying_key().to_bytes()),
            b(&recipient),
            b(&nonce),
            V::Uint(minimum_height),
            query.value()?,
        ]))?;
        let signed = wire::sign_envelope(&payload, signer)?;
        Self::from_signed(&signed)?;
        Ok(signed)
    }
    pub fn from_signed(bytes: &[u8]) -> Result<Self> {
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        let v = wire::decode(&payload)?;
        let f = record(&v, 60, 8)?;
        let scope = Scope::parse(&f[2])?;
        let requester = f[3].fixed()?;
        let recipient = f[4].fixed()?;
        wire::valid_key(&requester)?;
        wire::valid_key(&recipient)?;
        let client_nonce = f[5].fixed()?;
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == requester
                && requester == recipient
                && client_nonce != [0; 32],
            "fresh query identity or nonce differs"
        );
        let minimum_height = f[6].uint()?;
        let query = Query::parse(&f[7], &scope, minimum_height)?;
        Ok(Self {
            scope,
            requester,
            recipient,
            client_nonce,
            minimum_height,
            query,
            digest: wire::digest(&payload),
        })
    }
    pub fn validate_challenge(&self, challenge: &Challenge) -> Result<()> {
        ensure!(
            challenge.network == self.scope.network
                && challenge.incarnation == self.scope.incarnation
                && challenge.recipient == self.recipient
                && challenge.intent == self.digest
                && challenge.client_nonce == self.client_nonce
                && challenge.maximum_duration_ms <= crate::authority_challenge::MAXIMUM_DURATION_MS,
            "fresh challenge binding differs"
        );
        Ok(())
    }
}
pub fn read_id(request: &[u8], challenge: &[u8]) -> Result<Digest> {
    let request = Request::from_signed(request)?;
    let challenge = Challenge::from_signed(challenge)?;
    request.validate_challenge(&challenge)?;
    Ok(wire::digest(&wire::encode(&a(vec![
        b(&request.digest),
        b(&challenge.digest),
    ]))?))
}
#[derive(Clone, Debug)]
pub struct Statement {
    pub scope: Scope,
    pub request: Digest,
    pub challenge: Digest,
    pub requester: Key,
    pub recipient: Key,
    pub height: u64,
    pub node: Digest,
    pub state: Digest,
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
    pub result: Digest,
}
impl Statement {
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(61),
            V::Uint(1),
            self.scope.value(),
            b(&self.request),
            b(&self.challenge),
            b(&self.requester),
            b(&self.recipient),
            V::Uint(self.height),
            b(&self.node),
            b(&self.state),
            V::Uint(self.evaluated_at_ms),
            V::Uint(self.expires_at_ms),
            b(&self.result),
        ]))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v = wire::decode(bytes)?;
        let f = record(&v, 61, 13)?;
        let s = Self {
            scope: Scope::parse(&f[2])?,
            request: f[3].fixed()?,
            challenge: f[4].fixed()?,
            requester: f[5].fixed()?,
            recipient: f[6].fixed()?,
            height: f[7].uint()?,
            node: f[8].fixed()?,
            state: f[9].fixed()?,
            evaluated_at_ms: f[10].uint()?,
            expires_at_ms: f[11].uint()?,
            result: f[12].fixed()?,
        };
        wire::valid_key(&s.requester)?;
        wire::valid_key(&s.recipient)?;
        ensure!(
            s.request != [0; 32]
                && s.challenge != [0; 32]
                && s.node != [0; 32]
                && s.state != [0; 32]
                && s.result != [0; 32]
                && s.expires_at_ms > s.evaluated_at_ms,
            "invalid fresh statement"
        );
        Ok(s)
    }
}
pub struct Response<'a> {
    pub node: &'a [u8],
    pub certificate: &'a [u8],
    pub result: &'a [u8],
    pub ancestry: &'a [Vec<u8>],
}
pub struct VerifiedRead {
    pub request: Request,
    pub challenge: Challenge,
    pub statement: Statement,
    pub result: OperationResult,
    point: CertifiedPoint,
    generations: Vec<VersionRef>,
    ancestry: Vec<proof::Node>,
    history: Option<crate::authority_history::ValidatedHistory>,
    canonical_result: Vec<u8>,
}
impl VerifiedRead {
    pub fn point(&self) -> &CertifiedPoint {
        &self.point
    }
    pub fn generations(&self) -> &[VersionRef] {
        &self.generations
    }
    pub fn operation_result_bytes(&self) -> &[u8] {
        &self.canonical_result
    }
    pub fn history(&self) -> Option<&crate::authority_history::ValidatedHistory> {
        self.history.as_ref()
    }
    pub fn continuity(&self) -> proof::ContinuityEvidence {
        proof::ContinuityEvidence {
            ancestry: self
                .ancestry
                .iter()
                .map(|n| n.canonical().to_vec())
                .collect(),
            history: self.history.as_ref().map(|h| h.canonical().to_vec()),
        }
    }
    pub(crate) fn attach_history(
        mut self,
        history: crate::authority_history::ValidatedHistory,
    ) -> Result<Self> {
        ensure!(self.history.is_none(), "fresh history already attached");
        proof::continuity::extends(
            &self.point,
            &self.ancestry,
            &history.ordinary_checkpoint()?.prefix(),
        )?;
        self.history = Some(history);
        Ok(self)
    }
    pub fn extends(&self, floor: &Prefix) -> Result<()> {
        if self.point.prefix() == floor {
            return Ok(());
        }
        if let Some(h) = &self.history {
            ensure!(h.from() == floor, "fresh history begins at another floor");
            proof::continuity::extends(
                &self.point,
                &self.ancestry,
                &h.ordinary_checkpoint()?.prefix(),
            )
        } else {
            proof::continuity::extends(&self.point, &self.ancestry, floor)
        }
    }
}
pub fn verify_response(
    descriptor: &TrustDescriptor,
    request: &[u8],
    challenge: &[u8],
    response: Response<'_>,
    validate: impl FnOnce(&Request, &OperationResult, &Statement) -> Result<Vec<VersionRef>>,
) -> Result<VerifiedRead> {
    let request = Request::from_signed(request)?;
    let challenge = Challenge::from_signed(challenge)?;
    request.validate_challenge(&challenge)?;
    let statement = Statement::parse(&descriptor.quorum(response.certificate)?)?;
    let result = OperationResult::parse(response.result)?;
    ensure!(
        statement.scope == *descriptor.scope()
            && request.scope == statement.scope
            && statement.request == request.digest
            && statement.challenge == challenge.digest
            && statement.requester == request.requester
            && statement.recipient == request.recipient
            && statement.height >= request.minimum_height
            && statement.result == wire::digest(response.result)
            && result.action == request.query.action()
            && result.disposition != proof::Disposition::Pending,
        "fresh response binding differs"
    );
    ensure!(
        challenge.evaluation_expiry(statement.evaluated_at_ms, statement.expires_at_ms)?
            == statement.expires_at_ms,
        "fresh response validity differs"
    );
    let point = CertifiedPoint::from_evidence(descriptor, response.certificate, response.node)?;
    let ancestry = proof::continuity::ancestry(descriptor.scope(), response.ancestry)?;
    ensure!(
        ancestry
            .last()
            .is_some_and(|n| n.digest() == point.prefix().node()),
        "fresh ancestry omits anchor"
    );
    let generations = if result.disposition == proof::Disposition::Permit {
        validate(&request, &result, &statement)?
    } else {
        ensure!(
            result.value == wire::encode(&a(vec![]))?,
            "fresh refusal carries data"
        );
        vec![]
    };
    proof::validate_versions(&generations, 64)?;
    ensure!(
        generations == result_versions(&result)?,
        "fresh validator versions differ from certified result"
    );
    Ok(VerifiedRead {
        request,
        challenge,
        statement,
        result,
        point,
        generations,
        ancestry,
        history: None,
        canonical_result: response.result.to_vec(),
    })
}
// These methods share the original process/boot-bound one-use challenge registry.
impl Session {
    pub fn issue_read(
        &mut self,
        request: &[u8],
        recipient: &SigningKey,
        client_nonce: Digest,
        duration_ms: u64,
        absolute_deadline: Option<u64>,
        health: ClockHealth,
    ) -> Result<Vec<u8>> {
        let read = Request::from_signed(request)?;
        ensure!(
            recipient.verifying_key().to_bytes() == read.recipient
                && client_nonce == read.client_nonce
                && (1..=crate::authority_challenge::MAXIMUM_DURATION_MS).contains(&duration_ms),
            "fresh challenge recipient or duration differs"
        );
        self.issue_bound(
            read.scope.network,
            read.scope.incarnation,
            read.digest,
            recipient,
            client_nonce,
            duration_ms,
            absolute_deadline,
            health,
        )
    }
}

pub(crate) fn result_versions(result: &OperationResult) -> Result<Vec<VersionRef>> {
    if result.disposition != proof::Disposition::Permit {
        ensure!(
            result.value == wire::encode(&a(vec![]))?,
            "fresh refusal carries context"
        );
        return Ok(vec![]);
    }
    let value = wire::decode(&result.value)?;
    let f = record(&value, 201, 5)?;
    ensure!(f[2].text()? == result.action, "fresh result action differs");
    let refs = f[3]
        .list(64)?
        .iter()
        .map(domains::version)
        .collect::<Result<Vec<_>>>()?;
    proof::validate_versions(&refs, 64)?;
    ensure!(
        result.action == "AuthorityDomain"
            || result.action == "AuthorityPolicyContext"
                && refs.len() == 2
                && refs[0].kind == 100
                && refs[1].kind == 114,
        "fresh result version schema differs"
    );
    Ok(refs)
}
