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
#[path = "AuthorityPageContentRequest.rs"]
mod content_request;
type ResultContext = (V, Vec<VersionRef>, State, Vec<Vec<u8>>);

#[derive(Clone)]
pub struct Request {
    signed: Vec<u8>,
    intent: Intent,
    operation: Operation,
    effect: Command,
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let intent = Intent::from_signed(bytes)?;
        let operation = Operation::parse(&intent)?;
        let effect = match &operation.command {
            super::super::Command::Page(
                command @ (Command::MediaAuthorise { .. }
                | Command::Content(content::Command::Authorise { .. })),
            ) => {
                ensure!(
                    operation.grant.is_some()
                        || matches!(command, Command::Content(content::Command::Authorise { host, effect: content::Effect::Purge, .. }) if host.id == intent.requester),
                    "native media effect requires an explicit participant grant"
                );
                command.clone()
            }
            super::super::Command::Federation(command) => command
                .media_command()
                .context("request is not a finite foreign media effect")?,
            _ => anyhow::bail!("request is not an explicit media effect"),
        };
        Ok(Self {
            signed: bytes.to_vec(),
            intent,
            operation,
            effect,
        })
    }
    pub fn signed(&self) -> &[u8] {
        &self.signed
    }
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn command(&self) -> &Command {
        &self.effect
    }
    // Independent clients compare pending operations before selecting a fresh effect.
    #[allow(dead_code)]
    pub fn domain_command(&self) -> &super::super::Command {
        &self.operation.command
    }
    pub fn result_asset(&self, result: &OperationResult) -> Result<(HostProfile, Asset)> {
        let (_, _, state, _) = self.context(result)?;
        let Command::MediaAuthorise { asset, host, .. } = self.command() else {
            unreachable!()
        };
        let value = state.record(144, asset.id)?;
        let selected = state.record(143, host.id)?;
        ensure!(
            value.reference == *asset && selected.reference == *host,
            "media result selected another exact asset or host"
        );
        let configured = Host::parse(
            &selected.payload,
            self.intent.network,
            self.intent.incarnation,
        )?;
        ensure!(
            !configured.withdrawn && configured.profile.role == 2,
            "media result host is withdrawn or has another role"
        );
        Ok((configured.profile, Asset::parse(&value.payload)?))
    }
    fn context(&self, result: &OperationResult) -> Result<ResultContext> {
        let value = wire::decode(&result.value)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
            "invalid media authority result"
        );
        let versions = f[3]
            .list(64)?
            .iter()
            .map(version)
            .collect::<Result<Vec<_>>>()?;
        validate_versions(&versions, 64)?;
        let body = f[4].array(4)?;
        ensure!(
            body[0].text()? == self.operation.command.name() && body[3] == V::Null,
            "media authority result has another action"
        );
        let mut state = State::empty(self.intent.network, self.intent.incarnation);
        let mut previous = None;
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
            let r = Record::parse(bytes.bytes()?, state.network, state.incarnation)?;
            ensure!(
                matches!(r.reference.kind, 104 | 107..=111 | 113 | 140..=164)
                    && previous.is_none_or(|p| p < r.reference.index()),
                "media authority records repeat or reorder"
            );
            previous = Some(r.reference.index());
            state.records.insert(r.reference.index(), r);
        }
        let state =
            State::parse_context(&state.value(), self.intent.network, self.intent.incarnation)?;
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
            "media result references differ from exact records"
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
            "media reply belongs to another participant request"
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
                "invalid media refusal"
            );
            return ActionValidation::new(vec![]);
        }
        ensure!(
            result.disposition == Disposition::Permit
                && executed.maximum_effect == 1
                && executed.restrictions == Restrictions::default(),
            "invalid media effect disposition"
        );
        let (value, versions, state, records) = self.context(result)?;
        for v in &versions {
            if let Some(old) = floor.iter().find(|r| r.index() == v.index()) {
                ensure!(
                    v.generation >= old.generation
                        && (v.generation != old.generation || v.digest == old.digest),
                    "media authority is below retained generation"
                );
            }
        }
        for r in floor
            .iter()
            .filter(|r| matches!(r.kind, 126 | 128 | 130 | 161))
        {
            let target = match r.kind {
                126 => 102,
                128 => 127,
                161 => 159,
                _ => 129,
            };
            ensure!(
                !versions.iter().any(|v| v.kind == target && v.id == r.id) || versions.contains(r),
                "media result omitted a retained restriction"
            );
        }
        let reserved = Reservations(bootstrap.reservations().to_vec());
        // Deployment proofs can refer to immutable bootstrap-appointed identities
        // without returning their already accepted appointment records again.
        let roles = super::super::result::merge(bootstrap, &records)?;
        state.validate_roles(&roles, &reserved)?;
        let recipient = self
            .operation
            .expected_recipient(&state, &roles, &reserved, intent)?;
        ensure!(
            recipient == challenge.recipient && recipient == executed.recipient,
            "media freshness belongs to another selected store"
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
                    "media reply conflicts with accepted bootstrap"
                );
            }
        }
        let mut prior = state;
        if let super::super::Command::Federation(command) = &self.operation.command {
            let proof = command
                .foreign_proof()
                .context("foreign media proof is absent")?;
            let anchor = Record::parse(&proof.anchor, intent.network, intent.incarnation)?;
            ensure!(
                anchor.reference == proof.floor,
                "foreign media floor anchor differs"
            );
            prior.records.insert(anchor.reference.index(), anchor);
        }
        let candidate = super::super::result::verify(
            bootstrap,
            &prior,
            &records,
            intent,
            result,
            executed,
            &[],
        )?;
        ensure!(
            candidate.value == value,
            "media reply differs from independent participant and storage authorization"
        );
        ActionValidation::mutation(candidate.versions, candidate.updates)
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
            "media request differs from accepted network"
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
        if matches!(self.command(), Command::Content(_)) {
            return self.validate_content_response(result, bytes);
        }
        let (_, value) = self.result_asset(result)?;
        let Command::MediaAuthorise {
            asset,
            host,
            effect,
            offset,
            bytes: count,
            digest,
        } = self.command()
        else {
            unreachable!()
        };
        let response = wire::decode(bytes)?;
        let f = response.array(11)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "PageMediaEffect"
                && version(&f[3])? == *asset
                && version(&f[4])? == *host
                && f[5].uint()? == effect.code()
                && f[6].uint()? == *offset
                && f[7].uint()? == *count,
            "media response changed its exact operation or byte range"
        );
        let payload = f[9].bytes()?;
        let raw_digest = f[8].fixed::<32>()?;
        match effect {
            MediaEffect::Upload | MediaEffect::Repair => ensure!(
                payload.is_empty() && Some(raw_digest) == *digest,
                "media upload response differs from its signed chunk"
            ),
            MediaEffect::Read | MediaEffect::Inspect => {
                use sha2::{Digest as _, Sha256};
                ensure!(
                    payload.len() as u64 == *count
                        && raw_digest == <[u8; 32]>::from(Sha256::digest(payload))
                        && f[10] != V::Null,
                    "media response lacks its exact validated extent"
                );
            }
        }
        if f[10] != V::Null {
            let receipt =
                CopyReceipt::parse(f[10].bytes()?, self.intent.network, self.intent.incarnation)?;
            ensure!(
                receipt.asset == *asset
                    && receipt.host == *host
                    && hex::encode(receipt.digest) == value.manifest.digest
                    && receipt.bytes == value.manifest.bytes,
                "media response copy receipt differs from the complete asset"
            );
        }
        Ok(())
    }
}
