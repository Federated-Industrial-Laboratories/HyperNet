// SPDX-License-Identifier: MIT
//! A deployment's dedicated service starts only for an explicitly authorised caller and exact local consent.
use crate::{
    authority_deployment_records::Index,
    authority_governance::{Governance, Requirement},
    authority_membership::{self as members, Reservations, Snapshot, reference, version},
    authority_proof::{Digest, Intent, Key, Restrictions, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
pub const ACTION: &str = "AuthorityRuntimeActivate";
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
#[derive(Clone, Debug)]
pub struct Operation {
    pub grant: VersionRef,
    pub admission: VersionRef,
    pub role: u64,
    pub recipient: Key,
    pub local_generation: u64,
    pub snapshot: Snapshot,
}
pub struct Decision {
    pub code: u64,
    pub value: V,
    pub versions: Vec<VersionRef>,
    pub expires_ms: u64,
    pub restrictions: Restrictions,
}
impl Decision {
    pub fn refuse(&mut self, code: u64) {
        self.code = code;
        self.value = a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(ACTION.into()),
            a(vec![]),
        ]);
        self.versions.clear();
        self.restrictions = Restrictions::default();
    }
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        action == ACTION
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        ensure!(intent.action == ACTION, "unknown runtime activation action");
        let value = wire::decode(&intent.parameters)?;
        let f = value.array(9)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == ACTION,
            "runtime activation parameters differ"
        );
        let out = Self {
            grant: version(&f[3])?,
            admission: version(&f[4])?,
            role: f[5].uint()?,
            recipient: f[6].fixed()?,
            local_generation: f[7].uint()?,
            snapshot: Snapshot::parse(&f[8])?,
        };
        wire::valid_key(&out.recipient)?;
        ensure!(
            out.grant.kind == 102
                && out.admission.kind == 129
                && out.admission.id == intent.resource
                && (1..=8).contains(&out.role)
                && out.local_generation > 0
                && intent.revision == out.local_generation
                && intent.profile_generation > 0
                && intent.minimum_policy_epoch == out.snapshot.epoch
                && intent.minimum_policy_height == out.snapshot.height
                && intent.expected == out.snapshot.references,
            "runtime activation differs from its exact signed context"
        );
        Ok(out)
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn authorise(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        recipient: Key,
        at: u64,
        replay: bool,
    ) -> Result<Decision> {
        self.evaluate(records, reservations, intent, recipient, at, replay, true)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn evaluate(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        recipient: Key,
        at: u64,
        _replay: bool,
        exact: bool,
    ) -> Result<Decision> {
        let g = Governance::parse(intent.network, intent.incarnation, records)?;
        let index = Index::parse(records, reservations, intent.network, intent.incarnation)?;
        let mut d = Decision {
            code: 0,
            value: V::Null,
            versions: vec![],
            expires_ms: u64::MAX,
            restrictions: Restrictions::default(),
        };
        let Some(registration) = index.deployments.get(&intent.resource) else {
            d.refuse(3);
            return Ok(d);
        };
        if recipient != self.recipient
            || registration.services.get(&self.role) != Some(&recipient)
            || registration.reference != self.admission
            || registration.profile.generation != intent.profile_generation
        {
            d.refuse(12);
            return Ok(d);
        }
        if index.withdrawals.contains_key(&intent.resource) {
            d.refuse(6);
            return Ok(d);
        }
        let capability = |grant: Digest, subject: Key, action| {
            g.current_capability(
                grant,
                &Requirement {
                    subject,
                    actions: &[action],
                    scope: (5, intent.resource),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: at,
                    expected: &[],
                },
            )
        };
        let manager = match capability(self.grant.id, intent.requester, 26) {
            Ok(c) => c,
            Err(_) => {
                d.refuse(members::capability_failure(&g, self.grant.id, at));
                return Ok(d);
            }
        };
        let registrar = match capability(registration.grant.id, registration.registrar, 13) {
            Ok(c) => c,
            Err(_) => {
                d.refuse(members::capability_failure(&g, registration.grant.id, at));
                return Ok(d);
            }
        };
        if !manager.dependencies.contains(&self.grant)
            || !registrar.dependencies.contains(&registration.grant)
        {
            d.refuse(12);
            return Ok(d);
        }
        let value = wire::decode(g.record_bytes(105, intent.resource)?)?;
        let consent = value.array(19)?;
        let validity = consent[16].array(2)?;
        let span = (validity[0].uint()?, validity[1].uint()?);
        if !members::current(at, span) || consent[18].uint()? != 0 {
            d.refuse(7);
            return Ok(d);
        }
        d.expires_ms = manager.expires_ms.min(registrar.expires_ms).min(span.1);
        d.versions = manager.dependencies;
        d.versions.extend(registrar.dependencies);
        d.versions.extend([
            registration.reference.clone(),
            registration.profile.clone(),
            registration.consent.clone(),
        ]);
        d.versions.sort_by_key(VersionRef::index);
        d.versions.dedup();
        if d.versions.len() > 64 {
            d.refuse(2);
            return Ok(d);
        }
        if exact && intent.expected != d.versions {
            d.refuse(12);
            return Ok(d);
        }
        d.restrictions.consent = Some(registration.consent.digest);
        d.value = a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(ACTION.into()),
            a(d.versions.iter().map(reference).collect()),
            b(&intent.resource),
            V::Uint(self.role),
            b(&recipient),
            V::Uint(self.local_generation),
            reference(&registration.profile),
            reference(&registration.consent),
            reference(&registration.reference),
        ]);
        Ok(d)
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Authority/Deployments/AuthorityRuntimeActivationTests.rs"]
mod tests;

#[path = "AuthorityActivationRequest.rs"]
mod request;
pub use request::Request;

#[path = "AuthorityActivationReceipt.rs"]
mod receipt;
pub use receipt::{RECEIPT_LIMIT, Receipt};

#[cfg(test)]
include!("../../../Tests/Support/Authority/Deployments/AuthorityRuntimeActivation.rs");
