// SPDX-License-Identifier: MIT
// A serving request is the participant's immutable ordinary intent; the selected store supplies freshness.
use super::*;
use crate::{
    authority_governance::Governance,
    authority_membership::Reservations,
    authority_proof::{
        self as proof, ActionValidation, Challenge, Disposition, ExecutedResult, OperationResult,
        Restrictions, TrustDescriptor, VerifiedResult,
    },
    trust_bootstrap::Verified,
};
type ResultContext = (V, Vec<VersionRef>, State, Vec<Vec<u8>>);

#[derive(Clone)]
pub struct Request {
    signed: Vec<u8>,
    intent: Intent,
    operation: Operation,
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let intent = Intent::from_signed(bytes)?;
        let operation = Operation::parse(&intent)?;
        ensure!(
            matches!(
                operation.command,
                super::super::Command::Transfer(Command::Execute { .. })
            ) && operation.grant.is_none(),
            "request is not an explicit transfer effect"
        );
        Ok(Self {
            signed: bytes.to_vec(),
            intent,
            operation,
        })
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn command(&self) -> &Command {
        let super::super::Command::Transfer(c) = &self.operation.command else {
            unreachable!("typed transfer request")
        };
        c
    }
    pub fn result_agreement(&self, result: &OperationResult) -> Result<(Profile, Agreement)> {
        let (_, _, state, _) = self.context(result)?;
        let t = Agreement::parse(
            &state.record(135, self.intent.resource)?.payload,
            self.intent.network,
            self.intent.incarnation,
        )?;
        let accepted = t.acceptance.as_ref().context("transfer is unaccepted")?;
        let s = Service::parse(
            &state.record(134, accepted.service.id)?.payload,
            self.intent.network,
            self.intent.incarnation,
        )?;
        Ok((s.profile, t))
    }
    fn context(&self, result: &OperationResult) -> Result<ResultContext> {
        let value = wire::decode(&result.value)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
            "invalid transfer authority result"
        );
        let versions = f[3]
            .list(64)?
            .iter()
            .map(version)
            .collect::<Result<Vec<_>>>()?;
        validate_versions(&versions, 64)?;
        let body = f[4].array(4)?;
        ensure!(
            body[0].text()? == "TransferExecute" && body[3] == V::Null,
            "transfer authority result has another action"
        );
        let mut state = State::empty(self.intent.network, self.intent.incarnation);
        let mut previous = None;
        for bytes in body[1].list(2)? {
            let r = Record::parse(bytes.bytes()?, state.network, state.incarnation)?;
            ensure!(
                matches!(r.reference.kind, 134 | 135)
                    && previous.is_none_or(|p| p < r.reference.index()),
                "transfer authority records repeat or reorder"
            );
            previous = Some(r.reference.index());
            state.records.insert(r.reference.index(), r);
        }
        ensure!(
            state.records.len() == 2,
            "transfer authority result lacks its exact agreement and store"
        );
        validate_state(&state)?;
        let records = body[2]
            .list(64)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let mut exact = Governance::record_versions(state.network, state.incarnation, &records)?;
        exact.extend(state.records.values().map(|r| r.reference.clone()));
        exact.sort_by_key(VersionRef::index);
        ensure!(
            exact == versions,
            "transfer result references differ from exact records"
        );
        Ok((value, versions, state, records))
    }
    fn validate(
        &self,
        bootstrap: &Verified,
        intent: &Intent,
        result: &OperationResult,
        executed: &ExecutedResult,
        challenge: &Challenge,
        floor: &[VersionRef],
    ) -> Result<ActionValidation> {
        ensure!(
            intent.digest == self.intent.digest,
            "transfer reply belongs to another participant request"
        );
        if result.disposition == Disposition::Refuse {
            let v = wire::decode(&result.value)?;
            let f = v.array(4)?;
            ensure!(
                f[0].uint()? == 201
                    && f[1].uint()? == 1
                    && f[2].text()? == "AuthorityDomain"
                    && f[3].array(0)?.is_empty()
                    && executed.maximum_effect == 0
                    && executed.restrictions == Restrictions::default(),
                "invalid transfer refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            result.disposition == Disposition::Permit
                && executed.maximum_effect == 1
                && executed.restrictions == Restrictions::default(),
            "invalid transfer effect disposition"
        );
        let (value, versions, state, records) = self.context(result)?;
        // Sparse results omit unchanged bootstrap policy records; current records retain exact quorum references.
        let records = super::super::result::merge(bootstrap, &records)?;
        for v in &versions {
            if let Some(old) = floor.iter().find(|r| r.index() == v.index()) {
                ensure!(
                    v.generation >= old.generation
                        && (v.generation != old.generation || v.digest == old.digest),
                    "transfer authority is below retained generation"
                );
            }
        }
        for r in floor.iter().filter(|r| matches!(r.kind, 126 | 128 | 130)) {
            let target = match r.kind {
                126 => 102,
                128 => 127,
                _ => 129,
            };
            ensure!(
                !versions.iter().any(|v| v.kind == target && v.id == r.id) || versions.contains(r),
                "transfer result omitted a retained restriction"
            );
        }
        let reserved = Reservations(bootstrap.reservations().to_vec());
        state.validate_roles(&records, &reserved)?;
        let recipient = self
            .operation
            .expected_recipient(&state, &records, &reserved, intent)?;
        ensure!(
            recipient == challenge.recipient && recipient == executed.recipient,
            "transfer freshness belongs to another selected store"
        );
        // Bootstrap governance is immutable for its generation. Newer returned records still require the quorum certificate.
        for original in Governance::record_versions(
            intent.network,
            intent.incarnation,
            bootstrap.governance_records(),
        )? {
            if let Some(v) = versions.iter().find(|v| v.index() == original.index()) {
                ensure!(
                    v.generation > original.generation || *v == original,
                    "transfer reply conflicts with accepted bootstrap"
                );
            }
        }
        let decision = self.operation.prepare(
            &state,
            &records,
            &reserved,
            intent,
            executed.evaluated_at_ms,
            false,
            true,
        )?;
        ensure!(
            decision.code == 0
                && decision.value == value
                && executed.expires_at_ms <= decision.expires_ms,
            "transfer reply differs from independent participant and storage authorization"
        );
        ActionValidation::new(versions)
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
        floor: &[VersionRef],
    ) -> Result<VerifiedResult> {
        ensure!(
            bootstrap.fully_accepted()
                && self.intent.network == descriptor.scope().network
                && self.intent.incarnation == descriptor.scope().incarnation
                && bootstrap.descriptor().scope().network == self.intent.network
                && bootstrap.descriptor().scope().incarnation == self.intent.incarnation,
            "transfer request differs from accepted network"
        );
        let c = Challenge::from_signed(challenge)?;
        proof::verify_response(
            descriptor,
            proof::ProofContext {
                intent: &self.signed,
                challenge,
                restrictions: Restrictions::default(),
                minimum_height: 0,
                maximum_effect: 1,
                expected_stream: None,
            },
            proof::Response {
                ordered_request: ordered,
                operation_result: result,
                certificate,
                ancestry,
            },
            |i, r, e| self.validate(bootstrap, i, r, e, &c, floor),
        )
    }
    pub fn validate_response(&self, result: &OperationResult, bytes: &[u8]) -> Result<()> {
        let (_, t) = self.result_agreement(result)?;
        let Command::Execute {
            id,
            effect,
            offset,
            bytes: count,
            ..
        } = self.command()
        else {
            unreachable!()
        };
        let value = wire::decode(bytes)?;
        let f = value.array(12)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "TransferEffect"
                && f[3].fixed::<32>()? == *id
                && f[4].fixed::<32>()? == wire::digest(&t.offer.envelope)
                && f[5].text()? == effect.name()
                && f[6].uint()? == *offset
                && f[7].uint()? == *count
                && f[8].uint()? <= t.offer.payload_bytes,
            "transfer response changed exact operation or extent"
        );
        let stored = f[8].uint()?;
        let committed = f[9].boolean()?;
        let deleted = f[10].boolean()?;
        let payload = f[11].bytes()?;
        ensure!(
            match effect {
                Effect::Put => stored == offset + count && payload.is_empty() && !deleted,
                Effect::Commit =>
                    stored == t.offer.payload_bytes && committed && !deleted && payload.is_empty(),
                Effect::Fetch =>
                    stored == t.offer.payload_bytes
                        && committed
                        && !deleted
                        && payload.len() as u64 == *count,
                Effect::Status => payload.is_empty(),
                Effect::Delete => stored == 0 && deleted && payload.is_empty(),
            },
            "transfer response does not describe the exact requested effect"
        );
        Ok(())
    }
}
