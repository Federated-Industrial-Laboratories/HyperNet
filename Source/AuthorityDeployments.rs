// SPDX-License-Identifier: MIT
//! Exact operator consent and key possession admit permanent service identities.
use crate::{
    authority_deployment_records::{self as records, Registration},
    authority_governance::{Governance, Requirement},
    authority_membership::{self as members, Reservations, Snapshot, current, reference, version},
    authority_proof::{Digest, Intent, Key, VersionRef, validate_versions},
    runtime_manifest::Manifest,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
fn a(v: Vec<V>) -> V {
    V::Array(v)
}
fn b(v: &[u8]) -> V {
    V::Bytes(v.to_vec())
}
fn id(v: &V) -> Result<Digest> {
    let id = v.fixed()?;
    ensure!(id != [0; 32], "zero deployment identifier");
    Ok(id)
}
#[derive(Clone, Debug)]
pub struct Offer {
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub consent: Vec<u8>,
    pub possessions: Vec<Vec<u8>>,
}
impl Offer {
    pub fn parse(manifest: &[u8], consent: &[u8], possessions: &V) -> Result<Self> {
        let parsed = Manifest::parse(manifest)?;
        let (payload, signatures) = wire::envelope(consent, 1)?;
        ensure!(
            signatures.len() == 1
                && signatures[0].0 == parsed.operator
                && payload == parsed.unsigned_consent(0)?,
            "operator did not sign this exact unwithdrawn deployment"
        );
        let expected = parsed
            .roles
            .iter()
            .map(|r| (0, r.service_key))
            .chain(parsed.owned_transports()?.into_values().map(|k| (1, k)))
            .chain(std::iter::once((2, parsed.clock.monitor_key)))
            .collect::<BTreeSet<_>>();
        let profile = wire::digest(&parsed.desired()?);
        let consent_digest = wire::digest(&payload);
        let mut actual = BTreeSet::new();
        let mut previous = None;
        let mut outputs = vec![];
        for item in possessions.list(19)? {
            let bytes = item.bytes()?;
            ensure!(bytes.len() <= 1024, "deployment possession exceeds bound");
            let (payload, signatures) = wire::envelope(bytes, 1)?;
            let value = wire::decode(&payload)?;
            let f = value.array(12)?;
            let class = f[6].uint()?;
            let key = f[7].fixed()?;
            let identity = (class, key);
            ensure!(
                f[0].uint()? == 200
                    && f[1].uint()? == 1
                    && f[2].text()? == "AuthorityDeploymentPossession"
                    && f[3].fixed::<32>()? == parsed.network
                    && f[4].fixed::<32>()? == parsed.incarnation
                    && f[5].fixed::<32>()? == parsed.deployment
                    && signatures.len() == 1
                    && signatures[0].0 == key
                    && f[8].fixed::<32>()? == profile
                    && f[9].fixed::<32>()? == consent_digest,
                "deployment possession signature or binding differs"
            );
            id(&f[10])?;
            let span = f[11].array(2)?;
            let start = span[0].uint()?;
            let end = span[1].uint()?;
            ensure!(
                start >= parsed.validity.0
                    && end <= parsed.validity.1
                    && start < end
                    && end - start <= 86400000
                    && previous.is_none_or(|p| p < identity)
                    && actual.insert(identity),
                "deployment possession validity or order differs"
            );
            previous = Some(identity);
            outputs.push(bytes.to_vec());
        }
        ensure!(
            actual == expected,
            "deployment lacks exact service, transport or monitor possession"
        );
        Ok(Self {
            manifest: parsed,
            manifest_bytes: manifest.to_vec(),
            consent: consent.to_vec(),
            possessions: outputs,
        })
    }
    pub fn current(&self, at: u64) -> Result<bool> {
        if !current(at, self.manifest.validity) {
            return Ok(false);
        }
        for bytes in &self.possessions {
            let (payload, _) = wire::envelope(bytes, 1)?;
            let value = wire::decode(&payload)?;
            let span = value.array(12)?[11].array(2)?;
            if !current(at, (span[0].uint()?, span[1].uint()?)) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(test)]
    pub fn possessions_value(&self) -> V {
        a(self.possessions.iter().map(|p| b(p)).collect())
    }
    #[cfg(test)]
    pub fn possession(
        manifest: &Manifest,
        class: u64,
        key: Key,
        nonce: Digest,
        validity: (u64, u64),
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentPossession".into()),
            b(&manifest.network),
            b(&manifest.incarnation),
            b(&manifest.deployment),
            V::Uint(class),
            b(&key),
            b(&wire::digest(&manifest.desired()?)),
            b(&wire::digest(&manifest.unsigned_consent(0)?)),
            b(&nonce),
            a(vec![V::Uint(validity.0), V::Uint(validity.1)]),
        ]))
    }
}
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "Bounded records are processed individually without an additional allocation."
)]
pub enum Operation {
    Context {
        grant: Digest,
        minimum_point: (u64, u64, Digest),
        minimum: Vec<VersionRef>,
    },
    Register {
        grant: VersionRef,
        offer: Offer,
        snapshot: Snapshot,
    },
    Get {
        deployment: Digest,
        grant: Option<Digest>,
        minimum: Vec<VersionRef>,
    },
    Withdraw {
        admission: VersionRef,
        generation: u64,
        snapshot: Snapshot,
    },
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        matches!(
            action,
            "AuthorityDeploymentContext"
                | "AuthorityDeploymentRegister"
                | "AuthorityDeploymentGet"
                | "AuthorityDeploymentWithdraw"
        )
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        ensure!(
            intent.profile_generation == 0,
            "deployment request profile generation differs"
        );
        let value = wire::decode(&intent.parameters)?;
        let f = value.list(8)?;
        ensure!(
            f.len() >= 3
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == intent.action,
            "deployment request action differs"
        );
        let refs = |v: &V| -> Result<Vec<VersionRef>> {
            let refs = v
                .list(64)?
                .iter()
                .map(version)
                .collect::<Result<Vec<_>>>()?;
            validate_versions(&refs, 64)?;
            Ok(refs)
        };
        let op = match intent.action.as_str() {
            "AuthorityDeploymentContext" => {
                let f = value.array(7)?;
                let p = f[5].array(3)?;
                let deployment = id(&f[4])?;
                ensure!(
                    deployment == intent.resource
                        && p[0].uint()? == intent.minimum_policy_epoch
                        && p[1].uint()? == intent.minimum_policy_height,
                    "deployment context resource or floor differs"
                );
                Self::Context {
                    grant: id(&f[3])?,
                    minimum_point: (p[0].uint()?, p[1].uint()?, id(&p[2])?),
                    minimum: refs(&f[6])?,
                }
            }
            "AuthorityDeploymentRegister" => {
                let f = value.array(8)?;
                let grant = version(&f[3])?;
                let offer = Offer::parse(f[4].bytes()?, f[5].bytes()?, &f[6])?;
                ensure!(
                    grant.kind == 102
                        && offer.manifest.network == intent.network
                        && offer.manifest.incarnation == intent.incarnation
                        && offer.manifest.deployment == intent.resource,
                    "registration scope differs"
                );
                Self::Register {
                    grant,
                    offer,
                    snapshot: Snapshot::parse(&f[7])?,
                }
            }
            "AuthorityDeploymentGet" => {
                let f = value.array(6)?;
                let deployment = id(&f[3])?;
                ensure!(deployment == intent.resource, "deployment lookup differs");
                Self::Get {
                    deployment,
                    grant: if f[4] == V::Null {
                        None
                    } else {
                        Some(id(&f[4])?)
                    },
                    minimum: refs(&f[5])?,
                }
            }
            "AuthorityDeploymentWithdraw" => {
                let f = value.array(6)?;
                let admission = version(&f[3])?;
                let generation = f[4].uint()?;
                ensure!(
                    admission.kind == 129 && admission.id == intent.resource && generation > 0,
                    "withdrawal binding differs"
                );
                Self::Withdraw {
                    admission,
                    generation,
                    snapshot: Snapshot::parse(&f[5])?,
                }
            }
            _ => anyhow::bail!("unsupported deployment action"),
        };
        if let Some(snapshot) = op.snapshot() {
            ensure!(
                intent.revision == 1
                    && snapshot.epoch == intent.minimum_policy_epoch
                    && snapshot.height == intent.minimum_policy_height
                    && snapshot.references == intent.expected,
                "deployment snapshot differs from signed intent"
            );
        } else {
            ensure!(
                intent.revision == 0 && intent.expected.is_empty(),
                "deployment read has mutation expectations"
            );
        }
        Ok(op)
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        match self {
            Self::Register { snapshot, .. } | Self::Withdraw { snapshot, .. } => Some(snapshot),
            _ => None,
        }
    }
    pub fn derive(&self, intent: &Intent) -> Result<Vec<Vec<u8>>> {
        let mut prefix = vec![
            V::Uint(if matches!(self, Self::Register { .. }) {
                129
            } else {
                130
            }),
            V::Uint(1),
            b(&intent.network),
            b(&intent.incarnation),
            V::Uint(1),
            V::Null,
        ];
        match self {
            Self::Register {
                grant,
                offer,
                snapshot,
            } => {
                let m = &offer.manifest;
                let desired = m.desired()?;
                let consent = m.unsigned_consent(0)?;
                prefix.extend([
                    b(&m.deployment),
                    b(&m.host),
                    b(&m.operator),
                    a(m.services()
                        .iter()
                        .map(|(role, key)| a(vec![V::Uint(*role), b(key)]))
                        .collect()),
                    a(m.owned_transports()?
                        .iter()
                        .map(|(service, key)| a(vec![b(service), b(key)]))
                        .collect()),
                    b(&m.clock.monitor_key),
                    reference(&records::reference(&desired)?),
                    reference(&records::reference(&consent)?),
                    b(&intent.requester),
                    reference(grant),
                    snapshot.value.clone(),
                ]);
                Ok(vec![desired, consent, wire::encode(&a(prefix))?])
            }
            Self::Withdraw {
                admission,
                generation,
                snapshot,
            } => {
                prefix.extend([
                    b(&admission.id),
                    reference(admission),
                    b(&intent.requester),
                    V::Uint(*generation),
                    snapshot.value.clone(),
                ]);
                Ok(vec![wire::encode(&a(prefix))?])
            }
            _ => Ok(vec![]),
        }
    }
    #[cfg(test)]
    pub fn prepare(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        retained_offer: Option<(&[u8], &[u8])>,
    ) -> Result<Decision> {
        self.evaluate(
            records,
            reservations,
            intent,
            at,
            replay,
            retained_offer,
            false,
        )
    }
    pub fn authorise(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        retained_offer: Option<(&[u8], &[u8])>,
    ) -> Result<Decision> {
        self.evaluate(
            records,
            reservations,
            intent,
            at,
            replay,
            retained_offer,
            true,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep protocol inputs, state and validation callbacks explicit."
    )]
    fn evaluate(
        &self,
        entries: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        retained_offer: Option<(&[u8], &[u8])>,
        exact: bool,
    ) -> Result<Decision> {
        let g = Governance::parse(intent.network, intent.incarnation, entries)?;
        let index =
            records::Index::parse(entries, reservations, intent.network, intent.incarnation)?;
        let mut d = Decision::new(&intent.action);
        let all = g.versions();
        let capability = |grant: Digest, action: u64| -> Result<_> {
            g.current_capability(
                grant,
                &Requirement {
                    subject: intent.requester,
                    actions: &[action],
                    scope: (5, intent.resource),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: at,
                    expected: &[],
                },
            )
        };
        let mut body = vec![];
        match self {
            Self::Context { grant, minimum, .. } => {
                let c = match capability(*grant, 13).or_else(|_| capability(*grant, 26)) {
                    Ok(c) => c,
                    Err(_) => {
                        d.refuse(3);
                        return Ok(d);
                    }
                };
                d.dependencies = c.dependencies;
                d.expires_ms = c.expires_ms;
                if let Some(registration) = index.deployments.get(&intent.resource) {
                    let registrar = match g.current_capability(
                        registration.grant.id,
                        &Requirement {
                            subject: registration.registrar,
                            actions: &[13],
                            scope: (5, intent.resource),
                            namespace: None,
                            usage: [0, 1, 0, 1],
                            evaluated_at_ms: at,
                            expected: &[],
                        },
                    ) {
                        Ok(value) => value,
                        Err(_) => {
                            d.refuse(members::capability_failure(&g, registration.grant.id, at));
                            return Ok(d);
                        }
                    };
                    d.expires_ms = d.expires_ms.min(registrar.expires_ms);
                    d.dependencies.extend(registrar.dependencies);
                    d.dependencies.extend([
                        registration.reference.clone(),
                        registration.profile.clone(),
                        registration.consent.clone(),
                    ]);
                    if let Some(w) = index.withdrawals.get(&intent.resource) {
                        d.dependencies.push(w.reference.clone());
                    }
                }
                // The immutable bootstrap supplies global root dependencies to scoped clients.
                for r in &all {
                    if matches!(r.kind, 114 | 131) {
                        d.dependencies.push(r.clone());
                    }
                }
                d.dependencies.sort_by_key(VersionRef::index);
                d.dependencies.dedup();
                if minimum.iter().any(|v| {
                    d.dependencies
                        .iter()
                        .find(|r| r.index() == v.index())
                        .is_some_and(|r| {
                            r.generation < v.generation
                                || r.generation == v.generation && r.digest != v.digest
                        })
                }) {
                    d.refuse(12)
                }
                body.push(a(d
                    .dependencies
                    .iter()
                    .map(|r| Ok(b(g.record_bytes(r.kind, r.id)?)))
                    .collect::<Result<Vec<_>>>()?));
            }
            Self::Register { grant, offer, .. } => {
                let c = match capability(grant.id, 13) {
                    Ok(c) => c,
                    Err(_) => {
                        d.refuse(3);
                        return Ok(d);
                    }
                };
                d.dependencies = c.dependencies;
                d.expires_ms = c.expires_ms.min(offer.manifest.validity.1);
                if !all.contains(grant) {
                    d.refuse(12)
                }
                if !current(at, offer.manifest.validity) || (!replay && !offer.current(at)?) {
                    d.refuse(7)
                }
                let created = self.derive(intent)?;
                let record = created.last().unwrap();
                let registration = Registration::parse(record, intent.network, intent.incarnation)?;
                d.created = Some(registration.reference.clone());
                if let Some(prior) = index.deployments.get(&intent.resource) {
                    if !replay || prior.reference != registration.reference {
                        d.refuse(28)
                    }
                } else if replay {
                    d.refuse(12)
                }
                if !replay {
                    let mut next = entries.to_vec();
                    next.extend(created.clone());
                    crate::authority_membership::sort_records(&mut next)?;
                    if records::Index::parse(
                        &next,
                        reservations,
                        intent.network,
                        intent.incarnation,
                    )
                    .is_err()
                    {
                        d.refuse(38)
                    }
                    d.records = created;
                    d.admissions = registration
                        .streams()
                        .into_iter()
                        .filter(|key| !index.streams().contains(key))
                        .collect();
                }
                body.push(a(self
                    .derive(intent)?
                    .iter()
                    .map(|bytes| b(bytes))
                    .collect()));
            }
            Self::Get {
                deployment,
                grant,
                minimum,
            } => {
                let Some(registration) = index.deployments.get(deployment) else {
                    d.refuse(3);
                    return Ok(d);
                };
                if let Some(grant) = grant {
                    match capability(*grant, 13).or_else(|_| capability(*grant, 26)) {
                        Ok(c) => {
                            d.dependencies = c.dependencies;
                            d.expires_ms = c.expires_ms
                        }
                        Err(_) => {
                            d.refuse(3);
                            return Ok(d);
                        }
                    }
                } else if registration.operator != intent.requester {
                    d.refuse(3);
                    return Ok(d);
                }
                d.dependencies.extend([
                    registration.reference.clone(),
                    registration.profile.clone(),
                    registration.consent.clone(),
                ]);
                let withdrawn = index.withdrawals.get(deployment);
                if let Some(w) = withdrawn {
                    d.dependencies.push(w.reference.clone());
                }
                for m in minimum {
                    if d.dependencies
                        .iter()
                        .find(|v| v.index() == m.index())
                        .is_some_and(|v| {
                            v.generation < m.generation
                                || v.generation == m.generation && v.digest != m.digest
                        })
                        || m.kind == 130 && m.id == *deployment && withdrawn.is_none()
                    {
                        d.refuse(12)
                    }
                }
                let (manifest, consent) =
                    retained_offer.context("registered deployment provenance is absent")?;
                body.extend([
                    b(&registration.bytes),
                    b(g.record_bytes(117, *deployment)?),
                    b(consent),
                    b(manifest),
                    withdrawn.map_or(V::Null, |w| b(&w.bytes)),
                ]);
            }
            Self::Withdraw { admission, .. } => {
                let Some(registration) = index.deployments.get(&admission.id) else {
                    d.refuse(3);
                    return Ok(d);
                };
                if registration.operator != intent.requester {
                    d.refuse(3);
                    return Ok(d);
                }
                if &registration.reference != admission {
                    d.refuse(12)
                }
                d.dependencies.push(admission.clone());
                let created = self.derive(intent)?;
                let record = &created[0];
                let v = records::reference(record)?;
                d.created = Some(v.clone());
                if let Some(existing) = index.withdrawals.get(&admission.id) {
                    if !replay || existing.reference != v {
                        d.refuse(28)
                    }
                } else if replay {
                    d.refuse(12)
                }
                if !replay {
                    d.records = created.clone();
                }
                body.push(a(created.iter().map(|bytes| b(bytes)).collect()));
            }
        }
        d.dependencies.sort_by_key(VersionRef::index);
        d.dependencies.dedup();
        if self.snapshot().is_some() && exact && d.dependencies != intent.expected {
            d.refuse(12)
        }
        if let Some(created) = &d.created {
            d.dependencies.push(created.clone());
            if matches!(self, Self::Register { .. }) {
                for bytes in self.derive(intent)?.iter().take(2) {
                    d.dependencies.push(records::reference(bytes)?);
                }
            }
        }
        d.dependencies.sort_by_key(VersionRef::index);
        d.dependencies.dedup();
        if d.dependencies.len() > 64 {
            d.refuse(2)
        }
        let mut result = vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(intent.action.clone()),
            a(d.dependencies.iter().map(reference).collect()),
        ];
        result.extend(body);
        d.value = a(result);
        Ok(d)
    }
}
#[derive(Debug)]
pub struct Decision {
    pub code: u64,
    pub dependencies: Vec<VersionRef>,
    pub expires_ms: u64,
    pub value: V,
    pub records: Vec<Vec<u8>>,
    pub created: Option<VersionRef>,
    pub admissions: Vec<Key>,
}
impl Decision {
    fn new(action: &str) -> Self {
        Self {
            code: 0,
            dependencies: vec![],
            expires_ms: u64::MAX,
            value: a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text(action.into()),
                a(vec![]),
            ]),
            records: vec![],
            created: None,
            admissions: vec![],
        }
    }
    pub fn refuse(&mut self, code: u64) {
        self.code = if self.code == 0 {
            code
        } else {
            self.code.min(code)
        }
    }
}
