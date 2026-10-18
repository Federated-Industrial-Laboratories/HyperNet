// SPDX-License-Identifier: MIT
// Portable federation evidence extends actual accepted foreign floors with complete executed quorums.
use super::*;
use crate::{authority_history as history, authority_proof as authority};
#[path = "AuthorityFederationBundle.rs"]
mod bundle;

#[derive(Clone, Debug)]
pub struct ForeignProof {
    pub trust: VersionRef,
    pub floor: VersionRef,
    pub anchor: Vec<u8>,
    pub ordered: Vec<u8>,
    pub result: Vec<u8>,
    pub certificate: Vec<u8>,
    pub ancestry: Vec<Vec<u8>>,
    pub checkpoint: Option<Vec<u8>>,
    pub history: Option<Vec<u8>>,
    pub predecessors: Vec<Vec<u8>>,
    pub bytes: Vec<u8>,
}
pub struct VerifiedForeign {
    pub command: Command,
    pub state: State,
    pub floor: ForeignFloor,
    pub expires_ms: u64,
    pub digest: Digest,
    pub cursor: Option<Digest>,
}
impl ForeignProof {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= wire::MAXIMUM,
            "foreign proof exceeds the request budget"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(13)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "FederationProof",
            "foreign proof format differs"
        );
        let list = |v: &V, max| -> Result<Vec<Vec<u8>>> {
            v.list(max)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect()
        };
        let p = Self {
            trust: exact_ref(&f[3], 150)?,
            floor: exact_ref(&f[4], 157)?,
            anchor: f[5].bytes()?.to_vec(),
            ordered: f[6].bytes()?.to_vec(),
            result: f[7].bytes()?.to_vec(),
            certificate: f[8].bytes()?.to_vec(),
            ancestry: list(&f[9], 128)?,
            checkpoint: optional_bytes(&f[10])?,
            history: optional_bytes(&f[11])?,
            predecessors: list(&f[12], MAXIMUM_CONTEXT_RECORDS)?,
            bytes: bytes.to_vec(),
        };
        ensure!(
            p.trust.id == p.floor.id && !p.ancestry.is_empty(),
            "foreign proof trust, floor or ancestry differs"
        );
        let intent = p.intent()?;
        let params = wire::decode(&intent.parameters)?;
        let operation = params.array(6)?;
        let command = operation[4].list(7)?;
        ensure!(
            intent.action == "AuthorityDomain"
                && operation[0].uint()? == 200
                && operation[1].uint()? == 1
                && operation[2].text()? == "AuthorityDomain",
            "foreign proof is not a finite domain result"
        );
        match command[0].text()? {
            "FederationAdmission" => {
                ensure!(command.len() == 7, "foreign admission arity differs");
            }
            "FederationExport" => {
                ensure!(command.len() == 6, "foreign export arity differs");
                // Inspect the nested tag before recursion: an Export can contain only a leaf Admission.
                let nested = wire::decode(command[3].bytes()?)?;
                let nested = nested.array(13)?;
                let ordered = wire::decode(nested[6].bytes()?)?;
                let ordered = ordered.array(6)?;
                let signed = Intent::from_signed(ordered[3].bytes()?)?;
                let parameters = wire::decode(&signed.parameters)?;
                let leaf = parameters.array(6)?[4].array(7)?;
                ensure!(
                    leaf[0].text()? == "FederationAdmission",
                    "foreign proof nesting exceeds Admission then Export"
                );
                Self::parse(command[3].bytes()?)?.require_action("FederationAdmission")?;
            }
            _ => anyhow::bail!("foreign proof action is not an admission or export"),
        }
        Ok(p)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("FederationProof".into()),
            reference(&self.trust),
            reference(&self.floor),
            b(&self.anchor),
            b(&self.ordered),
            b(&self.result),
            b(&self.certificate),
            a(self.ancestry.iter().map(|v| b(v)).collect()),
            self.checkpoint.as_ref().map_or(V::Null, |v| b(v)),
            self.history.as_ref().map_or(V::Null, |v| b(v)),
            a(self.predecessors.iter().map(|v| b(v)).collect()),
        ]))
    }
    pub fn intent(&self) -> Result<Intent> {
        let v = wire::decode(&self.ordered)?;
        let f = v.array(6)?;
        ensure!(
            f[0].uint()? == 22 && f[1].uint()? == 1,
            "foreign ordered request differs"
        );
        Intent::from_signed(f[3].bytes()?)
    }
    pub fn command(&self) -> Result<Command> {
        let op = Operation::parse(&self.intent()?)?;
        let super::super::Command::Federation(command) = op.command else {
            anyhow::bail!("foreign result is not federation")
        };
        Ok(command)
    }
    pub fn require_action(&self, name: &str) -> Result<()> {
        let intent = self.intent()?;
        let v = wire::decode(&intent.parameters)?;
        ensure!(
            v.array(6)?[4]
                .list(8)?
                .first()
                .context("foreign command missing")?
                .text()?
                == name,
            "foreign proof has another finite purpose"
        );
        Ok(())
    }
    pub fn exported_revision(&self) -> Result<([u8; 16], VersionRef)> {
        self.require_action("FederationExport")?;
        let intent = self.intent()?;
        let v = authority::OperationResult::parse(&self.result)?;
        ensure!(
            v.disposition == authority::Disposition::Permit,
            "foreign export is not permitted"
        );
        let value = wire::decode(&v.value)?;
        let body = value.array(5)?[4].array(4)?;
        let mut out = None;
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
            let r = Record::parse(bytes.bytes()?, intent.network, intent.incarnation)?;
            if r.reference.kind == 141 {
                ensure!(
                    out.is_none(),
                    "foreign export has more than one native revision"
                );
                let p = page::Revision::parse(&r.payload, intent.network, intent.incarnation)?;
                out = Some((p.author.raw_page, r.reference));
            }
        }
        out.context("foreign export omitted its native revision")
    }
    pub fn exported_share_metadata(&self) -> Result<(VersionRef, page::Revision)> {
        let (raw, native) = self.exported_revision()?;
        let intent = self.intent()?;
        let result = authority::OperationResult::parse(&self.result)?;
        let v = wire::decode(&result.value)?;
        let body = v.array(5)?[4].array(4)?;
        let Command::Export { agreement, .. } = self.command()? else {
            unreachable!()
        };
        let mut share = None;
        let mut metadata = None;
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
            let r = Record::parse(bytes.bytes()?, intent.network, intent.incarnation)?;
            if r.reference.kind == 153 && r.reference.id == share_id(agreement.id, raw)? {
                share = Some(r.reference)
            } else if r.reference == native {
                metadata = Some(page::Revision::parse(
                    &r.payload,
                    intent.network,
                    intent.incarnation,
                )?);
            }
        }
        Ok((
            share.context("source export omitted exact sharing generation")?,
            metadata.context("source export omitted metadata")?,
        ))
    }
    pub fn verify(
        &self,
        local: &State,
        treaty: &Treaty,
        at: u64,
        objects: &Resolved,
        replay: bool,
    ) -> Result<VerifiedForeign> {
        let trust_record = local.record(150, self.trust.id)?;
        let floor_record = local.record(157, self.floor.id)?;
        ensure!(
            trust_record.reference == self.trust,
            "foreign proof begins at stale local trust"
        );
        let anchor = Record::parse(&self.anchor, local.network, local.incarnation)?;
        ensure!(
            anchor.reference == self.floor
                && (floor_record.reference == self.floor
                    || replay
                        && self.floor.generation.checked_add(1)
                            == Some(floor_record.reference.generation)
                        && floor_record.predecessor == Some(self.floor.digest)),
            "foreign proof begins at another actual local floor"
        );
        let trust = ForeignTrust::parse(&trust_record.payload, local.network, local.incarnation)?;
        let mut floor = ForeignFloor::parse(&anchor.payload)?;
        let local_source = treaty.source_side(local.network, local.incarnation)?;
        ensure!(
            !trust.withdrawn
                && &trust.identity == treaty.foreign(local_source)
                && floor.sealed.is_none(),
            "foreign authority is withdrawn, sealed or outside the agreement"
        );
        let baseline = trust.verified()?;
        let resolved = floor.resolve(&trust)?;
        let intent = self.intent()?;
        let command = self.command()?;
        let ordered = wire::decode(&self.ordered)?;
        let ordered = ordered.array(6)?;
        let challenge = authority::Challenge::from_signed(ordered[4].bytes()?)?;
        ensure!(
            intent.requester == treaty.bridge(!local_source)
                && challenge.recipient == intent.requester,
            "foreign proof requester is not the exact counterpart bridge"
        );
        let mut prior = State::empty(intent.network, intent.incarnation);
        let mut previous = None;
        for bytes in &self.predecessors {
            let r = Record::parse(bytes, intent.network, intent.incarnation)?;
            ensure!(
                r.reference.kind == 157
                    && intent.expected.contains(&r.reference)
                    && previous.is_none_or(|p| p < r.reference.index()),
                "foreign predecessor is unrelated, repeated or unsigned"
            );
            previous = Some(r.reference.index());
            prior.records.insert(r.reference.index(), r);
        }
        let mut candidate = None;
        let verified = authority::verify_response(
            &resolved.descriptor,
            authority::ProofContext {
                intent: ordered[3].bytes()?,
                challenge: ordered[4].bytes()?,
                restrictions: authority::Restrictions::default(),
                minimum_height: resolved.prefix.height(),
                maximum_effect: 1,
                expected_stream: None,
            },
            authority::Response {
                ordered_request: &self.ordered,
                operation_result: &self.result,
                certificate: &self.certificate,
                ancestry: &self.ancestry,
            },
            |intent, result, executed| {
                ensure!(
                    result.disposition == authority::Disposition::Permit
                        && executed.maximum_effect == 1,
                    "foreign evidence cannot grant an unpermitted effect"
                );
                let selected = super::super::result::verify(
                    &baseline,
                    &prior,
                    &[],
                    intent,
                    result,
                    executed,
                    &objects.objects().cloned().collect::<Vec<_>>(),
                )?;
                let validation = authority::ActionValidation::mutation(
                    selected.versions.clone(),
                    selected.updates.clone(),
                )?;
                candidate = Some(selected);
                Ok(validation)
            },
        )?;
        let next_checkpoint = self
            .checkpoint
            .as_ref()
            .map(|bytes| history::verify_checkpoint(&resolved.descriptor, bytes))
            .transpose()?
            .or_else(|| resolved.checkpoint.clone());
        authority::validate_continuity(
            &resolved.descriptor,
            &resolved.prefix,
            resolved.checkpoint.as_ref().map(|c| c.head()),
            verified.point(),
            next_checkpoint.as_ref(),
            &authority::ContinuityEvidence {
                ancestry: self.ancestry.clone(),
                history: self.history.clone(),
            },
        )?;
        ensure!(
            at.checked_add(crate::authority_governance::UNCERTAINTY_MS)
                .is_some_and(|upper| challenge.created_at_ms <= upper
                    && upper < verified.executed.expires_at_ms),
            "foreign permission is outside its conservative current interval"
        );
        let candidate = candidate.context("foreign result context is absent")?;
        let remote = Agreement::parse(
            &candidate.state.record(151, treaty.id)?.payload,
            intent.network,
            intent.incarnation,
        )?;
        ensure!(
            remote.treaty.value() == treaty.value() && !remote.withdrawn,
            "foreign result accepted different bilateral terms"
        );
        let counterpart = ForeignTrust::parse(
            &candidate.state.record(150, remote.foreign.id)?.payload,
            intent.network,
            intent.incarnation,
        )?;
        ensure!(
            counterpart.identity == *treaty.local(local_source) && !counterpart.withdrawn,
            "foreign result trusts another local bootstrap"
        );
        floor.retained = crate::authority_epoch::archive::Retained {
            certificate: Some(hex::encode(&self.certificate)),
            node: Some(hex::encode(verified.point().node())),
            checkpoint: next_checkpoint
                .as_ref()
                .map(|c| hex::encode(c.canonical_proof())),
        };
        floor.resolve(&trust)?;
        if floor_record.reference != self.floor {
            ensure!(
                floor_record.payload == floor.value()?,
                "foreign proof retry differs from its exact retained successor"
            );
        }
        let cursor = match &candidate.value.array(5)?[4].array(4)?[3] {
            V::Null => None,
            v => Some(id(v)?),
        };
        Ok(VerifiedForeign {
            cursor,
            command,
            state: candidate.state,
            floor,
            expires_ms: verified.executed.expires_at_ms,
            digest: wire::digest(&self.bytes),
        })
    }
}
