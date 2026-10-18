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
                super::super::Command::Mail(Command::Execute { .. })
            ) && operation.grant.is_none(),
            "request is not an explicit mail effect"
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
        let super::super::Command::Mail(c) = &self.operation.command else {
            unreachable!("typed mail request")
        };
        c
    }
    pub fn result_mailbox(
        &self,
        result: &OperationResult,
    ) -> Result<(Profile, Mailbox, Option<Claim>)> {
        let (_, _, state, _) = self.context(result)?;
        let Command::Execute {
            address,
            service,
            message,
            ..
        } = self.command()
        else {
            unreachable!()
        };
        let mailbox = Mailbox::parse(&state.record(137, *address)?.payload, self.intent.network)?;
        let profile = Service::parse(
            &state.record(136, *service)?.payload,
            self.intent.network,
            self.intent.incarnation,
        )?
        .profile;
        let claim = message
            .map(|id| Claim::parse(&state.record(139, id)?.payload))
            .transpose()?;
        Ok((profile, mailbox, claim))
    }
    fn context(&self, result: &OperationResult) -> Result<ResultContext> {
        let value = wire::decode(&result.value)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
            "invalid mail authority result"
        );
        let versions = f[3]
            .list(64)?
            .iter()
            .map(version)
            .collect::<Result<Vec<_>>>()?;
        validate_versions(&versions, 64)?;
        let body = f[4].array(4)?;
        ensure!(
            body[0].text()? == "MailExecute" && body[3] == V::Null,
            "mail authority result has another action"
        );
        let mut state = State::empty(self.intent.network, self.intent.incarnation);
        let mut previous = None;
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
            let r = Record::parse(bytes.bytes()?, state.network, state.incarnation)?;
            ensure!(
                matches!(r.reference.kind, 136..=139)
                    && previous.is_none_or(|p| p < r.reference.index()),
                "mail authority records repeat or reorder"
            );
            previous = Some(r.reference.index());
            state.records.insert(r.reference.index(), r);
        }
        for record in state.records.values().cloned().collect::<Vec<_>>() {
            if record.reference.kind == 137 {
                let m = Mailbox::parse(&record.payload, state.network)?;
                reserve(&mut state, &m)?;
            }
        }
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
            "mail result references differ from exact records"
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
            "mail reply belongs to another participant request"
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
                "invalid mail refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            result.disposition == Disposition::Permit
                && executed.maximum_effect == 1
                && executed.restrictions == Restrictions::default(),
            "invalid mail effect disposition"
        );
        let (value, versions, state, records) = self.context(result)?;
        // Sparse results omit unchanged bootstrap policy records; current records retain exact quorum references.
        let records = super::super::result::merge(bootstrap, &records)?;
        for v in &versions {
            if let Some(old) = floor.iter().find(|r| r.index() == v.index()) {
                ensure!(
                    v.generation >= old.generation
                        && (v.generation != old.generation || v.digest == old.digest),
                    "mail authority is below retained generation"
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
                "mail result omitted a retained restriction"
            );
        }
        let reserved = Reservations(bootstrap.reservations().to_vec());
        state.validate_roles(&records, &reserved)?;
        let recipient = self
            .operation
            .expected_recipient(&state, &records, &reserved, intent)?;
        ensure!(
            recipient == challenge.recipient && recipient == executed.recipient,
            "mail freshness belongs to another selected store"
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
                    "mail reply conflicts with accepted bootstrap"
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
            "mail reply differs from independent participant and storage authorization"
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
            "mail request differs from accepted network"
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
        let (_, _, claim) = self.result_mailbox(result)?;
        let Command::Execute {
            address,
            service,
            effect,
            message,
            ..
        } = self.command()
        else {
            unreachable!()
        };
        let value = wire::decode(bytes)?;
        let f = value.array(9)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "MailEffect"
                && id(&f[3])? == *address
                && key(&f[4])? == *service
                && f[5].text()? == effect.name()
                && f[6] == message.as_ref().map_or(V::Null, |v| b(v)),
            "mail response differs from exact effect"
        );
        let status = f[7].text()?;
        match effect {
            Effect::Put => ensure!(
                status == "Stored" && f[8].bytes()?.is_empty(),
                "mail Put response differs"
            ),
            Effect::Delete => ensure!(
                status == "Deleted" && f[8].bytes()?.is_empty(),
                "mail Delete response differs"
            ),
            Effect::Fetch => {
                let claim = claim.context("mail fetch claim absent")?;
                let payload = f[8].bytes()?;
                ensure!(
                    status == "Fetched"
                        && payload.len() as u64 == claim.payload_bytes
                        && Some(wire::digest(payload)) == claim.payload_digest,
                    "fetched ciphertext differs from certified binding"
                );
            }
            Effect::List => {
                ensure!(status == "Listed", "mail listing status differs");
                let mut last = None;
                for item in f[8].list(16)? {
                    let item = item.array(4)?;
                    let id = id(&item[0])?;
                    ensure!(
                        last.is_none_or(|v| v < id)
                            && (1..=MAXIMUM_PAYLOAD).contains(&item[2].uint()?)
                            && item[3].uint()? > 0,
                        "mail listing bounds differ"
                    );
                    super::id(&item[1])?;
                    last = Some(id);
                }
            }
        }
        Ok(())
    }
}
