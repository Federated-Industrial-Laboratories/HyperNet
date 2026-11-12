// SPDX-License-Identifier: MIT
// Activation packages carry an immutable manager request and the exact records used to verify its reply.
use super::*;
use crate::{
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, ExecutedResult, OperationResult,
        TrustDescriptor, VerifiedResult,
    },
    runtime_manifest::Manifest,
    trust_bootstrap::Verified,
};
use anyhow::Context;
#[derive(Clone)]
pub struct Request {
    persistent: bool,
    signed: Vec<u8>,
    records: Vec<Vec<u8>>,
    intent: Intent,
    operation: Operation,
}
impl Request {
    pub fn new(signed: Vec<u8>, records: Vec<Vec<u8>>) -> Result<Self> {
        let intent = Intent::from_signed(&signed)?;
        let operation = Operation::parse(&intent)?;
        let g = Governance::parse(intent.network, intent.incarnation, &records)?;
        ensure!(
            g.versions().len() == records.len(),
            "activation records are repeated"
        );
        let mut ordered = records.clone();
        members::sort_records(&mut ordered)?;
        ensure!(
            ordered == records,
            "activation records are not in canonical order"
        );
        let out = Self {
            persistent: false,
            signed,
            records,
            intent,
            operation,
        };
        out.encode()?;
        Ok(out)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 200
                && matches!(f[1].uint()?, 1 | 2)
                && f[2].text()? == "RuntimeActivationRequest",
            "invalid activation package"
        );
        let request = Self::new(
            f[3].bytes()?.to_vec(),
            f[4].list(crate::authority_capacity::MAX_RECORDS)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
        )?;
        if f[1].uint()? == 2 {
            request.until_withdrawn()
        } else {
            Ok(request)
        }
    }
    pub fn persistent(&self) -> bool {
        self.persistent
    }
    /// Reserve a dedicated manager stream for one exact revocable deployment activation.
    pub fn until_withdrawn(mut self) -> Result<Self> {
        ensure!(
            self.intent.generation == 1
                && self.intent.sequence == 1
                && self.intent.acknowledged_through == 0,
            "Persistent activation requires the first intent of a dedicated manager profile"
        );
        let governance =
            Governance::parse(self.intent.network, self.intent.incarnation, &self.records)?;
        let registration = crate::authority_deployment_records::Registration::parse(
            governance.record_bytes(129, self.intent.resource)?,
            self.intent.network,
            self.intent.incarnation,
        )?;
        ensure!(
            self.intent.requester != registration.registrar
                && self.intent.requester != registration.operator
                && !registration
                    .services
                    .values()
                    .any(|key| *key == self.intent.requester),
            "Persistent activation requires a separate manager identity"
        );
        let grant = wire::decode(governance.record_bytes(102, self.operation.grant.id)?)?;
        let g = grant.array(17)?;
        ensure!(
            g[10] == a(vec![V::Uint(26)])
                && g[11] == a(vec![a(vec![V::Uint(5), b(&self.intent.resource)])])
                && g[14].uint()? == 0,
            "Persistent activation requires a non-delegating manager grant scoped only to this deployment"
        );
        for reference in &self.intent.expected {
            let record = wire::decode(governance.record_bytes(reference.kind, reference.id)?)?;
            let f = record.list(32)?;
            let index = match reference.kind {
                102 => Some(12),
                125 => Some(8),
                127 => Some(9),
                105 => Some(16),
                _ => None,
            };
            if let Some(index) = index {
                ensure!(
                    (if reference.kind == 102 {
                        governance.grant_validity(reference.id)?
                    } else {
                        crate::trust_validity::Validity::parse(&f[index])?
                    })
                    .1 == crate::trust_validity::End::UntilWithdrawn,
                    "Persistent activation has a finite authority or consent dependency"
                );
            }
        }
        self.persistent = true;
        Ok(self)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(if self.persistent { 2 } else { 1 }),
            V::Text("RuntimeActivationRequest".into()),
            b(&self.signed),
            a(self.records.iter().map(|v| b(v)).collect()),
        ]))
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn operation(&self) -> &Operation {
        &self.operation
    }
    pub fn check_manifest(
        &self,
        bootstrap: &Verified,
        descriptor: &TrustDescriptor,
        manifest: &Manifest,
        role: u64,
        generation: u64,
    ) -> Result<()> {
        manifest.validate()?;
        ensure!(
            bootstrap.fully_accepted()
                && bootstrap.descriptor().scope().network == descriptor.scope().network
                && bootstrap.descriptor().scope().incarnation == descriptor.scope().incarnation
                && self.intent.network == descriptor.scope().network
                && self.intent.incarnation == descriptor.scope().incarnation
                && self.intent.minimum_policy_epoch == descriptor.scope().epoch
                && manifest.network == self.intent.network
                && manifest.incarnation == self.intent.incarnation
                && manifest.deployment == self.intent.resource
                && manifest.bootstrap_digest == bootstrap.file_digest()
                && self.operation.role == role
                && self.operation.local_generation == generation
                && manifest.services().get(&role) == Some(&self.operation.recipient),
            "activation package differs from installed role, generation or accepted bootstrap"
        );
        let g = Governance::parse(manifest.network, manifest.incarnation, &self.records)?;
        ensure!(
            g.record_bytes(117, manifest.deployment)? == manifest.desired()?
                && g.record_bytes(105, manifest.deployment)? == manifest.unsigned_consent(0)?,
            "activation package changes the exact locally consented manifest"
        );
        Ok(())
    }
    pub fn validate(
        &self,
        bootstrap: &Verified,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
        challenge: &Challenge,
    ) -> Result<ActionValidation> {
        ensure!(
            intent.digest == self.intent.digest
                && executed.recipient == self.operation.recipient
                && challenge.recipient == self.operation.recipient,
            "activation result belongs to another request or recipient"
        );
        if result.disposition != Disposition::Permit {
            let value = wire::decode(&result.value)?;
            let f = value.array(4)?;
            ensure!(
                result.disposition == Disposition::Refuse
                    && f[0].uint()? == 201
                    && f[1].uint()? == 1
                    && f[2].text()? == ACTION
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0
                    && executed.restrictions == Restrictions::default(),
                "invalid activation refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            executed.expires_at_ms
                <= challenge.evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
            "activation evaluation is outside the conservative challenge interval"
        );
        let d = self.operation.authorise(
            &self.records,
            &Reservations(bootstrap.reservations().to_vec()),
            intent,
            executed.recipient,
            executed.evaluated_at_ms,
            false,
        )?;
        ensure!(
            d.code == 0
                && executed.maximum_effect == 1
                && executed.restrictions == d.restrictions
                && executed.expires_at_ms <= d.expires_ms
                && result.value == wire::encode(&d.value)?,
            "activation reply differs from independently evaluated authority and local consent"
        );
        ActionValidation::new(d.versions)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Each independently supplied proof, descriptor, deadline and retained floor stays explicit at verification."
    )]
    pub fn verify(
        &self,
        bootstrap: &Verified,
        descriptor: &TrustDescriptor,
        challenge: &[u8],
        ordered: &[u8],
        result: &[u8],
        certificate: &[u8],
        ancestry: &[Vec<u8>],
    ) -> Result<VerifiedResult> {
        let parsed = Challenge::from_signed(challenge)?;
        let disposition = OperationResult::parse(result)?.disposition;
        let restrictions = if disposition == Disposition::Permit {
            Restrictions {
                consent: Some(
                    self.intent
                        .expected
                        .iter()
                        .find(|r| r.kind == 105 && r.id == self.intent.resource)
                        .context("activation consent reference absent")?
                        .digest,
                ),
                placement: None,
                route: None,
            }
        } else {
            Restrictions::default()
        };
        proof::verify_response(
            descriptor,
            proof::ProofContext {
                intent: &self.signed,
                challenge,
                minimum_height: 0,
                maximum_effect: 1,
                restrictions,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: ordered,
                operation_result: result,
                certificate,
                ancestry,
            },
            |i, r, e| self.validate(bootstrap, i, r, e, &parsed),
        )
    }
}
