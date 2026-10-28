// SPDX-License-Identifier: MIT
// Application consent creates a permanent identity class with exact accepted rights.
use crate::{
    authority_governance::{Governance, Requirement},
    authority_membership::{
        self as membership, Reservations, Snapshot, current, reference, version,
    },
    authority_proof::{Digest, Intent, Key, VersionRef, validate_versions},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;

pub const MAX_CONTEXT_BYTES: usize = 98304;
fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn id(value: &V) -> Result<Digest> {
    let key = value.fixed()?;
    ensure!(key != [0; 32], "zero application identifier");
    Ok(key)
}
fn span(value: &V) -> Result<(u64, u64)> {
    let f = value.array(2)?;
    let result = (f[0].uint()?, f[1].uint()?);
    ensure!(result.0 < result.1, "invalid application validity");
    Ok(result)
}
fn refs(value: &V, maximum: usize) -> Result<Vec<VersionRef>> {
    let result = value
        .list(maximum)?
        .iter()
        .map(version)
        .collect::<Result<Vec<_>>>()?;
    validate_versions(&result, maximum)?;
    Ok(result)
}
pub fn record_reference(bytes: &[u8]) -> Result<VersionRef> {
    let value = wire::decode(bytes)?;
    let f = value.list(32)?;
    ensure!(f.len() >= 7, "truncated application context record");
    let kind = f[0].uint()?;
    let lookup = match kind {
        100 | 114 | 131 => id(&f[2])?,
        105 => id(&f[7])?,
        126 | 128 => version(&f[6])?.id,
        _ => id(&f[6])?,
    };
    Ok(VersionRef {
        kind,
        id: lookup,
        generation: f[4].uint()?,
        digest: wire::digest(bytes),
    })
}
#[cfg(test)]
fn prefix(
    value: &V,
    kind: u64,
    length: usize,
    network: Digest,
    incarnation: Digest,
) -> Result<&[V]> {
    let f = value.array(length)?;
    ensure!(
        f[0].uint()? == kind
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == network
            && f[3].fixed::<32>()? == incarnation
            && f[4].uint()? == 1
            && f[5] == V::Null,
        "application record context differs"
    );
    Ok(f)
}
#[derive(Clone, Debug)]
pub struct Registration {
    pub application: Key,
    pub owner: Key,
    pub grant: VersionRef,
    pub validity: (u64, u64),
    #[cfg(test)]
    pub renewable: bool,
    pub reference: VersionRef,
}
impl Registration {
    pub fn parse(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = value.array(11)?;
        ensure!(
            f[0].uint()? == 127
                && matches!(f[1].uint()?, 1 | 2)
                && f[2].fixed::<32>()? == network
                && f[3].fixed::<32>()? == incarnation,
            "application admission context differs"
        );
        let renewable = f[1].uint()? == 2;
        ensure!(
            if renewable {
                f[4].uint()? > 1 && f[5].fixed::<32>().is_ok()
            } else {
                f[4].uint()? == 1 && f[5] == V::Null
            },
            "application admission generation differs"
        );
        let application = f[6].fixed()?;
        let owner = f[7].fixed()?;
        wire::valid_key(&application)?;
        wire::valid_key(&owner)?;
        let grant = version(&f[8])?;
        let validity = span(&f[9])?;
        ensure!(
            application != owner && grant.kind == 102 && validity.1 - validity.0 <= 604800000,
            "invalid application identity or grant"
        );
        Snapshot::parse(&f[10])?;
        Ok(Self {
            application,
            owner,
            grant,
            validity,
            #[cfg(test)]
            renewable,
            reference: record_reference(bytes)?,
        })
    }
}
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub admission: VersionRef,
    pub withdrawer: Key,
    pub reference: VersionRef,
}
#[cfg(test)]
impl Withdrawal {
    pub fn parse(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = prefix(&value, 128, 9, network, incarnation)?;
        let admission = version(&f[6])?;
        let withdrawer = f[7].fixed()?;
        wire::valid_key(&withdrawer)?;
        ensure!(
            admission.kind == 127,
            "withdrawal target is not an application"
        );
        Snapshot::parse(&f[8])?;
        Ok(Self {
            admission,
            withdrawer,
            reference: record_reference(bytes)?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Acceptance {
    pub application: Key,
    pub owner: Key,
    pub grant: VersionRef,
    pub validity: (u64, u64),
    pub acceptance_validity: (u64, u64),
    #[cfg(test)]
    pub envelope: Vec<u8>,
}
impl Acceptance {
    pub fn parse(
        bytes: &[u8],
        network: Digest,
        incarnation: Digest,
        accepted: bool,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= 1024,
            "application acceptance exceeds its bound"
        );
        let (payload, signatures) = wire::envelope(bytes, 2)?;
        let value = wire::decode(&payload)?;
        let f = value.array(11)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityApplicationAcceptance"
                && f[3].fixed::<32>()? == network
                && f[4].fixed::<32>()? == incarnation,
            "application acceptance context differs"
        );
        let application = f[5].fixed()?;
        let owner = f[6].fixed()?;
        wire::valid_key(&application)?;
        wire::valid_key(&owner)?;
        let grant = version(&f[7])?;
        let validity = span(&f[8])?;
        id(&f[9])?;
        let acceptance_validity = span(&f[10])?;
        ensure!(
            application != owner
                && grant.kind == 102
                && validity.1 - validity.0 <= 604800000
                && acceptance_validity.1 - acceptance_validity.0 <= 86400000
                && acceptance_validity.0 >= validity.0
                && acceptance_validity.1 <= validity.1,
            "application acceptance restrictions differ"
        );
        ensure!(
            signatures.len() == if accepted { 2 } else { 1 }
                && signatures.iter().any(|(key, _)| *key == owner)
                && signatures
                    .iter()
                    .all(|(key, _)| *key == owner || accepted && *key == application),
            "application acceptance lacks exact owner and application possession"
        );
        Ok(Self {
            application,
            owner,
            grant,
            validity,
            acceptance_validity,
            #[cfg(test)]
            envelope: bytes.to_vec(),
        })
    }
}
/// Fresh dual consent extends only the validity of the retained immutable rights template.
#[derive(Clone, Debug)]
pub struct Renewal {
    pub admission: VersionRef,
    pub owner: Key,
    pub grant: VersionRef,
    pub validity: (u64, u64),
    pub acceptance_validity: (u64, u64),
}
impl Renewal {
    pub fn parse(
        bytes: &[u8],
        network: Digest,
        incarnation: Digest,
        accepted: bool,
    ) -> Result<Self> {
        ensure!(bytes.len() <= 1024, "application renewal exceeds its bound");
        let (payload, signatures) = wire::envelope(bytes, 2)?;
        let value = wire::decode(&payload)?;
        let f = value.array(11)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 2
                && f[2].text()? == "AuthorityApplicationRenewal"
                && f[3].fixed::<32>()? == network
                && f[4].fixed::<32>()? == incarnation,
            "application renewal context differs"
        );
        let admission = version(&f[5])?;
        let owner = f[6].fixed()?;
        let grant = version(&f[7])?;
        let validity = span(&f[8])?;
        id(&f[9])?;
        let acceptance_validity = span(&f[10])?;
        ensure!(
            admission.kind == 127
                && grant.kind == 102
                && admission.id != owner
                && validity.1 - validity.0 <= 604800000
                && acceptance_validity.1 - acceptance_validity.0 <= 86400000
                && acceptance_validity.0 >= validity.0
                && acceptance_validity.1 <= validity.1,
            "application renewal restrictions differ"
        );
        wire::valid_key(&owner)?;
        wire::valid_key(&admission.id)?;
        ensure!(
            signatures.len() == if accepted { 2 } else { 1 }
                && signatures.iter().any(|(key, _)| *key == owner)
                && signatures
                    .iter()
                    .all(|(key, _)| *key == owner || accepted && *key == admission.id),
            "application renewal lacks exact owner and application possession"
        );
        Ok(Self {
            admission,
            owner,
            grant,
            validity,
            acceptance_validity,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Point {
    pub epoch: u64,
    pub height: u64,
    pub state: Digest,
}
impl Point {
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(3)?;
        Ok(Self {
            epoch: f[0].uint()?,
            height: f[1].uint()?,
            state: id(&f[2])?,
        })
    }
}
#[derive(Clone, Debug)]
pub enum Operation {
    Context {
        parent: Digest,
        tier: Digest,
        child: Option<Digest>,
        minimum_point: Point,
        minimum: Vec<VersionRef>,
    },
    Register {
        parent: VersionRef,
        acceptance: Acceptance,
        snapshot: Snapshot,
    },
    Renew {
        previous: Vec<u8>,
        consent: Renewal,
        snapshot: Snapshot,
    },
    Get {
        application: Key,
        minimum: Vec<VersionRef>,
    },
    List {
        owner: Key,
        minimum: Vec<VersionRef>,
    },
    Withdraw {
        admission: VersionRef,
        snapshot: Snapshot,
    },
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        matches!(
            action,
            "AuthorityDelegationContext"
                | "AuthorityApplicationRegister"
                | "AuthorityApplicationRenew"
                | "AuthorityApplicationGet"
                | "AuthorityApplicationList"
                | "AuthorityApplicationWithdraw"
        )
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        ensure!(
            intent.profile_generation == 0,
            "application profile generation differs"
        );
        let value = wire::decode(&intent.parameters)?;
        let f = value.list(8)?;
        ensure!(
            f.len() >= 3
                && f[0].uint()? == 200
                && f[1].uint()?
                    == if intent.action == "AuthorityApplicationRenew" {
                        2
                    } else {
                        1
                    }
                && f[2].text()? == intent.action,
            "application parameters differ from action"
        );
        let operation = match intent.action.as_str() {
            "AuthorityDelegationContext" => {
                let f = value.array(8)?;
                let parent = id(&f[3])?;
                let minimum_point = Point::parse(&f[6])?;
                ensure!(
                    intent.resource == parent
                        && minimum_point.epoch == intent.minimum_policy_epoch
                        && minimum_point.height == intent.minimum_policy_height,
                    "delegation context floor differs"
                );
                Self::Context {
                    parent,
                    tier: id(&f[4])?,
                    child: if f[5] == V::Null {
                        None
                    } else {
                        Some(id(&f[5])?)
                    },
                    minimum_point,
                    minimum: refs(&f[7], 512)?,
                }
            }
            "AuthorityApplicationRegister" => {
                let f = value.array(6)?;
                let parent = version(&f[3])?;
                let acceptance =
                    Acceptance::parse(f[4].bytes()?, intent.network, intent.incarnation, true)?;
                ensure!(
                    parent.kind == 102
                        && acceptance.application == intent.resource
                        && acceptance.owner == intent.requester,
                    "registration owner or parent differs"
                );
                Self::Register {
                    parent,
                    acceptance,
                    snapshot: Snapshot::parse(&f[5])?,
                }
            }
            "AuthorityApplicationRenew" => {
                let f = value.array(6)?;
                let previous = f[3].bytes()?.to_vec();
                let old = Registration::parse(&previous, intent.network, intent.incarnation)?;
                let consent =
                    Renewal::parse(f[4].bytes()?, intent.network, intent.incarnation, true)?;
                ensure!(
                    old.reference == consent.admission
                        && old.owner == consent.owner
                        && old.grant == consent.grant
                        && old.application == intent.resource
                        && old.owner == intent.requester
                        && consent.validity.1 > old.validity.1,
                    "renewal changes identity, rights or does not extend validity"
                );
                Self::Renew {
                    previous,
                    consent,
                    snapshot: Snapshot::parse(&f[5])?,
                }
            }
            "AuthorityApplicationGet" => {
                let f = value.array(5)?;
                let application = f[3].fixed()?;
                wire::valid_key(&application)?;
                ensure!(application == intent.resource, "application lookup differs");
                Self::Get {
                    application,
                    minimum: refs(&f[4], 512)?,
                }
            }
            "AuthorityApplicationList" => {
                let f = value.array(5)?;
                let owner = f[3].fixed()?;
                ensure!(
                    owner == intent.requester && owner == intent.resource,
                    "application list owner differs"
                );
                Self::List {
                    owner,
                    minimum: refs(&f[4], 512)?,
                }
            }
            "AuthorityApplicationWithdraw" => {
                let f = value.array(5)?;
                let admission = version(&f[3])?;
                ensure!(
                    admission.kind == 127 && admission.id == intent.resource,
                    "withdrawal target differs"
                );
                Self::Withdraw {
                    admission,
                    snapshot: Snapshot::parse(&f[4])?,
                }
            }
            _ => anyhow::bail!("unsupported application operation"),
        };
        if let Some(snapshot) = operation.snapshot() {
            ensure!(
                intent.revision == 1
                    && snapshot.epoch == intent.minimum_policy_epoch
                    && snapshot.height == intent.minimum_policy_height
                    && snapshot.references == intent.expected,
                "application mutation snapshot differs"
            );
        } else {
            ensure!(
                intent.revision == 0 && intent.expected.is_empty(),
                "application read has exact mutation expectations"
            );
        }
        Ok(operation)
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        match self {
            Self::Register { snapshot, .. }
            | Self::Renew { snapshot, .. }
            | Self::Withdraw { snapshot, .. } => Some(snapshot),
            _ => None,
        }
    }
    pub fn minimum_point(&self) -> Option<&Point> {
        if let Self::Context { minimum_point, .. } = self {
            Some(minimum_point)
        } else {
            None
        }
    }
    pub fn derive(&self, intent: &Intent) -> Result<Option<Vec<u8>>> {
        if let Self::Renew {
            previous,
            consent,
            snapshot,
        } = self
        {
            let mut f = wire::decode(previous)?.array(11)?.to_vec();
            f[1] = V::Uint(2);
            f[4] = V::Uint(
                consent
                    .admission
                    .generation
                    .checked_add(1)
                    .context("application generation exhausted")?,
            );
            f[5] = b(&consent.admission.digest);
            f[9] = a(vec![
                V::Uint(consent.validity.0),
                V::Uint(consent.validity.1),
            ]);
            f[10] = snapshot.value.clone();
            return Ok(Some(wire::encode(&a(f))?));
        }
        let mut fields = vec![
            V::Uint(if matches!(self, Self::Register { .. }) {
                127
            } else {
                128
            }),
            V::Uint(1),
            b(&intent.network),
            b(&intent.incarnation),
            V::Uint(1),
            V::Null,
        ];
        match self {
            Self::Register {
                acceptance: c,
                snapshot,
                ..
            } => fields.extend([
                b(&c.application),
                b(&c.owner),
                reference(&c.grant),
                a(vec![V::Uint(c.validity.0), V::Uint(c.validity.1)]),
                snapshot.value.clone(),
            ]),
            Self::Withdraw {
                admission,
                snapshot,
            } => fields.extend([
                reference(admission),
                b(&intent.requester),
                snapshot.value.clone(),
            ]),
            _ => return Ok(None),
        }
        Ok(Some(wire::encode(&a(fields))?))
    }
    #[cfg(test)]
    pub fn prepare(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
    ) -> Result<Decision> {
        self.evaluate(records, reservations, intent, at, replay, false)
    }
    pub fn authorise(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
    ) -> Result<Decision> {
        self.evaluate(records, reservations, intent, at, replay, true)
    }
}
#[derive(Debug)]
pub struct Decision {
    pub code: u64,
    pub dependencies: Vec<VersionRef>,
    pub expires_ms: u64,
    pub value: V,
    pub record: Option<Vec<u8>>,
    pub created: Option<VersionRef>,
    pub admission: Option<Key>,
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
            record: None,
            created: None,
            admission: None,
        }
    }
    pub fn refuse(&mut self, code: u64) {
        self.code = if self.code == 0 {
            code
        } else {
            self.code.min(code)
        };
    }
    fn finish(&mut self, action: &str, extra: Vec<V>, maximum: usize) -> Result<()> {
        self.dependencies.sort_by_key(VersionRef::index);
        self.dependencies.dedup();
        if self.dependencies.len() > maximum {
            self.refuse(2);
            return Ok(());
        }
        let mut fields = vec![
            V::Uint(201),
            V::Uint(1),
            V::Text(action.into()),
            a(self.dependencies.iter().map(reference).collect()),
        ];
        fields.extend(extra);
        self.value = a(fields);
        if wire::encode(&self.value)?.len() > MAX_CONTEXT_BYTES {
            self.refuse(2);
        }
        Ok(())
    }
}
type RecordIndex<'a> = BTreeMap<(u64, Digest), (&'a [u8], VersionRef)>;
fn indexed(records: &[Vec<u8>]) -> Result<RecordIndex<'_>> {
    let mut result = BTreeMap::new();
    for bytes in records {
        let r = record_reference(bytes)?;
        ensure!(
            result.insert(r.index(), (bytes.as_slice(), r)).is_none(),
            "duplicate context record"
        );
    }
    Ok(result)
}
fn relevant_minima(versions: &[VersionRef], minimum: &[VersionRef]) -> bool {
    minimum.iter().all(|old| {
        versions
            .iter()
            .find(|v| v.index() == old.index())
            .is_none_or(|new| new.generation > old.generation || new == old)
    })
}
fn owner_capability(
    governance: &Governance,
    parent: Digest,
    owner: Key,
    at: u64,
) -> Result<crate::authority_governance::CapabilityDecision> {
    ensure!(
        governance.record_bytes(127, owner).is_err(),
        "an application cannot delegate"
    );
    let bytes = governance.record_bytes(102, parent)?;
    let decoded = wire::decode(bytes)?;
    let grant = decoded.array(17)?;
    ensure!(
        grant[8].fixed::<32>()? == owner,
        "parent is not owned by requester"
    );
    let scope = grant[11]
        .list(64)?
        .first()
        .context("parent has no scope")?
        .array(2)?;
    governance.current_capability(
        parent,
        &Requirement {
            subject: owner,
            actions: &[11],
            scope: (scope[0].uint()?, scope[1].fixed()?),
            namespace: None,
            usage: [0, 1, 0, 1],
            evaluated_at_ms: at,
            expected: &[],
        },
    )
}
impl Operation {
    fn evaluate(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        exact: bool,
    ) -> Result<Decision> {
        let mut decision = Decision::new(&intent.action);
        let index = indexed(records)?;
        match self {
            Self::Context {
                parent,
                tier,
                child,
                minimum,
                ..
            } => {
                let g = Governance::parse(intent.network, intent.incarnation, records)?;
                let capability = match owner_capability(&g, *parent, intent.requester, at) {
                    Ok(c) => c,
                    Err(_) => {
                        decision.refuse(3);
                        return Ok(decision);
                    }
                };
                decision.expires_ms = capability.expires_ms;
                decision.dependencies = capability.dependencies;
                let policy = wire::decode(g.record_bytes(100, intent.network)?)?;
                let recovery = version(&policy.array(17)?[12])?;
                ensure!(
                    index
                        .get(&recovery.index())
                        .is_some_and(|(_, r)| r == &recovery),
                    "current recovery policy dependency missing"
                );
                decision.dependencies.push(recovery);
                let Some((_, selected_tier)) = index.get(&(101, *tier)) else {
                    decision.refuse(3);
                    return Ok(decision);
                };
                decision.dependencies.push(selected_tier.clone());
                if let Some(child) = child {
                    let Some((bytes, selected_child)) = index.get(&(102, *child)) else {
                        decision.refuse(3);
                        return Ok(decision);
                    };
                    let value = wire::decode(bytes)?;
                    let fields = value.array(17)?;
                    let parent_ref = version(&fields[13]).ok();
                    if fields[7].fixed::<32>()? != intent.requester
                        || version(&fields[9])?.id != *tier
                        || parent_ref.as_ref().is_none_or(|r| r.id != *parent)
                        || index
                            .get(&(102, *parent))
                            .is_none_or(|(_, r)| Some(r) != parent_ref.as_ref())
                    {
                        decision.refuse(3);
                        return Ok(decision);
                    }
                    decision.dependencies.push(selected_child.clone());
                    if let Some((_, revoked)) = index.get(&(126, *child)) {
                        decision.dependencies.push(revoked.clone());
                    }
                }
                decision.dependencies.sort_by_key(VersionRef::index);
                decision.dependencies.dedup();
                if !relevant_minima(&decision.dependencies, minimum) {
                    decision.refuse(12);
                }
                // A retained relevant tombstone cannot disappear from a selected closure.
                for prior in minimum.iter().filter(|v| v.kind == 126) {
                    if decision
                        .dependencies
                        .iter()
                        .any(|v| v.kind == 102 && v.id == prior.id)
                        && !decision
                            .dependencies
                            .iter()
                            .any(|v| v.index() == prior.index())
                    {
                        decision.refuse(12);
                    }
                }
                let selected = decision
                    .dependencies
                    .iter()
                    .map(|r| {
                        Ok(b(index
                            .get(&r.index())
                            .context("closure record missing")?
                            .0))
                    })
                    .collect::<Result<Vec<_>>>()?;
                decision.finish(&intent.action, vec![a(selected)], 64)?;
            }
            Self::Register {
                parent,
                acceptance: consent,
                ..
            } => {
                let bytes = self
                    .derive(intent)?
                    .context("registration record missing")?;
                let created = record_reference(&bytes)?;
                decision.record = Some(bytes.clone());
                decision.created = Some(created.clone());
                if replay {
                    if index
                        .get(&created.index())
                        .is_none_or(|(_, v)| *v != created)
                    {
                        decision.refuse(12);
                    }
                    decision.dependencies = intent.expected.clone();
                } else {
                    let g = Governance::parse(intent.network, intent.incarnation, records)?;
                    if reservations.contains(&consent.application) {
                        decision.refuse(38);
                    }
                    if index.contains_key(&(127, consent.application)) {
                        decision.refuse(28);
                    }
                    for (bytes, _) in index.values().filter(|(_, r)| r.kind == 125) {
                        let value = wire::decode(bytes)?;
                        if value.array(12)?[7].fixed::<32>()? == consent.application {
                            decision.refuse(38);
                        }
                    }
                    if !current(at, consent.validity) || !current(at, consent.acceptance_validity) {
                        decision.refuse(7);
                    }
                    if index.get(&parent.index()).is_none_or(|(_, r)| r != parent)
                        || index
                            .get(&consent.grant.index())
                            .is_none_or(|(_, r)| r != &consent.grant)
                    {
                        decision.refuse(12);
                    }
                    match owner_capability(&g, parent.id, consent.owner, at) {
                        Ok(c) => {
                            decision.dependencies = c.dependencies;
                            decision.expires_ms = c.expires_ms;
                        }
                        Err(_) => {
                            decision.refuse(membership::capability_failure(&g, parent.id, at))
                        }
                    }
                    if let Some((child_bytes, _)) = index.get(&consent.grant.index()) {
                        let value = wire::decode(child_bytes)?;
                        let f = value.array(17)?;
                        let child_span = span(&f[12])?;
                        if f[7].fixed::<32>()? != consent.owner
                            || f[8].fixed::<32>()? != consent.application
                            || version(&f[13]).ok().as_ref() != Some(parent)
                            || f[14].uint()? != 0
                            || f[10].list(32)?.contains(&V::Uint(11))
                            || consent.validity.0 < child_span.0
                            || consent.validity.1 > child_span.1
                        {
                            decision.refuse(4);
                        }
                        let mut prospective = records.to_vec();
                        if !index.contains_key(&created.index()) {
                            prospective.push(bytes.clone());
                            membership::sort_records(&mut prospective)?;
                        }
                        if let Ok(prospective) =
                            Governance::parse(intent.network, intent.incarnation, &prospective)
                        {
                            let action = f[10]
                                .list(32)?
                                .first()
                                .context("application grant has no action")?
                                .uint()?;
                            let scope = f[11]
                                .list(64)?
                                .first()
                                .context("application grant has no scope")?
                                .array(2)?;
                            let requirement = Requirement {
                                subject: consent.application,
                                actions: &[action],
                                scope: (scope[0].uint()?, scope[1].fixed()?),
                                namespace: None,
                                usage: [0, 1, 0, 1],
                                evaluated_at_ms: at,
                                expected: &[],
                            };
                            match prospective.current_capability(consent.grant.id, &requirement) {
                                Ok(c) => {
                                    decision.dependencies.extend(
                                        c.dependencies.into_iter().filter(|v| *v != created),
                                    );
                                    decision.expires_ms = decision.expires_ms.min(c.expires_ms);
                                }
                                Err(_) => decision.refuse(membership::capability_failure(
                                    &prospective,
                                    consent.grant.id,
                                    at,
                                )),
                            }
                        } else if decision.code == 0 {
                            decision.refuse(4);
                        }
                    } else {
                        decision.refuse(3);
                    }
                    decision.expires_ms = decision
                        .expires_ms
                        .min(consent.acceptance_validity.1)
                        .min(consent.validity.1);
                    decision.admission = Some(consent.application);
                    decision.dependencies.sort_by_key(VersionRef::index);
                    decision.dependencies.dedup();
                    if exact && decision.dependencies != intent.expected {
                        decision.refuse(12);
                    }
                }
                decision.dependencies.push(created);
                decision.finish(&intent.action, vec![b(&bytes)], 64)?;
            }
            Self::Renew {
                previous, consent, ..
            } => {
                let bytes = self.derive(intent)?.context("renewal record missing")?;
                let created = record_reference(&bytes)?;
                decision.record = Some(bytes.clone());
                decision.created = Some(created.clone());
                if replay {
                    if index
                        .get(&created.index())
                        .is_none_or(|(_, r)| *r != created)
                    {
                        decision.refuse(12);
                    }
                    decision.dependencies = intent.expected.clone();
                } else {
                    if index
                        .get(&consent.admission.index())
                        .is_none_or(|(r, _)| *r != previous.as_slice())
                    {
                        decision.refuse(12);
                    }
                    if index.contains_key(&(128, consent.admission.id)) {
                        decision.refuse(3);
                    }
                    if !current(at, consent.validity) || !current(at, consent.acceptance_validity) {
                        decision.refuse(7);
                    }
                    let g = Governance::parse(intent.network, intent.incarnation, records)?;
                    let grant = wire::decode(g.record_bytes(102, consent.grant.id)?)?;
                    let f = grant.array(17)?;
                    let parent = version(&f[13])?;
                    match owner_capability(&g, parent.id, consent.owner, at) {
                        Ok(c) => {
                            decision.dependencies = c.dependencies;
                            decision.expires_ms = c.expires_ms;
                        }
                        Err(_) => {
                            decision.refuse(membership::capability_failure(&g, parent.id, at))
                        }
                    }
                    let mut prospective = records
                        .iter()
                        .filter(|r| record_reference(r).is_ok_and(|v| v.index() != created.index()))
                        .cloned()
                        .collect::<Vec<_>>();
                    prospective.push(bytes.clone());
                    membership::sort_records(&mut prospective)?;
                    match Governance::parse(intent.network, intent.incarnation, &prospective) {
                        Ok(g) => {
                            let actions = f[10]
                                .list(32)?
                                .iter()
                                .map(V::uint)
                                .collect::<Result<Vec<_>>>()?;
                            for scope in f[11].list(64)? {
                                let scope = scope.array(2)?;
                                match g.current_capability(
                                    consent.grant.id,
                                    &Requirement {
                                        subject: consent.admission.id,
                                        actions: &actions,
                                        scope: (scope[0].uint()?, scope[1].fixed()?),
                                        namespace: None,
                                        usage: [0, 1, 0, 1],
                                        evaluated_at_ms: at,
                                        expected: &[],
                                    },
                                ) {
                                    Ok(c) => {
                                        decision.dependencies.extend(
                                            c.dependencies
                                                .into_iter()
                                                .filter(|v| v.index() != created.index()),
                                        );
                                        decision.expires_ms = decision.expires_ms.min(c.expires_ms);
                                    }
                                    Err(_) => decision.refuse(membership::capability_failure(
                                        &g,
                                        consent.grant.id,
                                        at,
                                    )),
                                }
                            }
                        }
                        Err(_) => decision.refuse(4),
                    }
                    decision.dependencies.push(consent.admission.clone());
                    decision.dependencies.sort_by_key(VersionRef::index);
                    decision.dependencies.dedup();
                    if exact && decision.dependencies != intent.expected {
                        decision.refuse(12);
                    }
                    decision.expires_ms = decision
                        .expires_ms
                        .min(consent.acceptance_validity.1)
                        .min(consent.validity.1);
                }
                decision.dependencies.push(created);
                let dependencies = decision.dependencies.clone();
                decision.dependencies.retain(|v| {
                    v.index() != consent.admission.index()
                        || v == decision.created.as_ref().unwrap()
                });
                decision.finish(&intent.action, vec![b(&bytes)], 64)?;
                decision.dependencies = dependencies;
            }
            Self::Get {
                application,
                minimum,
            }
            | Self::List {
                owner: application,
                minimum,
            } => {
                let list = matches!(self, Self::List { .. });
                let mut rows = Vec::new();
                let mut get_values = None;
                for (bytes, r) in index.values().filter(|(_, r)| r.kind == 127) {
                    let admission = Registration::parse(bytes, intent.network, intent.incarnation)?;
                    if if list {
                        admission.owner != *application
                    } else {
                        admission.application != *application
                    } {
                        continue;
                    }
                    if intent.requester != admission.owner
                        && (list || intent.requester != admission.application)
                    {
                        decision.refuse(3);
                        return Ok(decision);
                    }
                    let (grant, grant_ref) = index
                        .get(&admission.grant.index())
                        .context("accepted application grant missing")?;
                    ensure!(
                        *grant_ref == admission.grant,
                        "application grant reference differs"
                    );
                    decision.dependencies.extend([r.clone(), grant_ref.clone()]);
                    let withdrawal = index.get(&(128, admission.application));
                    if let Some((_, wr)) = withdrawal {
                        decision.dependencies.push(wr.clone());
                    }
                    if minimum
                        .iter()
                        .any(|v| v.kind == 128 && v.id == admission.application)
                        && withdrawal.is_none()
                    {
                        decision.refuse(12);
                    }
                    rows.push(a(vec![
                        b(&admission.application),
                        reference(r),
                        reference(grant_ref),
                        withdrawal.map_or(V::Null, |(_, r)| reference(r)),
                    ]));
                    get_values = Some(vec![
                        b(bytes),
                        b(grant),
                        withdrawal.map_or(V::Null, |(bytes, _)| b(bytes)),
                    ]);
                }
                if !relevant_minima(&decision.dependencies, minimum) {
                    decision.refuse(12);
                }
                if list {
                    if index.contains_key(&(127, intent.requester)) {
                        decision.refuse(3);
                    }
                    ensure!(
                        rows.len() <= 63,
                        "application list exceeds permanent stream bound"
                    );
                    decision.finish(&intent.action, vec![a(rows)], 192)?;
                } else if let Some(values) = get_values {
                    decision.finish(&intent.action, values, 64)?;
                } else {
                    decision.refuse(3);
                }
            }
            Self::Withdraw {
                admission: target, ..
            } => {
                let Some((registration, found)) = index.get(&target.index()) else {
                    decision.refuse(3);
                    return Ok(decision);
                };
                let admission =
                    Registration::parse(registration, intent.network, intent.incarnation)?;
                if *found != *target {
                    decision.refuse(12);
                }
                if intent.requester != admission.owner && intent.requester != admission.application
                {
                    decision.refuse(3);
                }
                let bytes = self.derive(intent)?.context("withdrawal record missing")?;
                let created = record_reference(&bytes)?;
                if let Some((_, old)) = index.get(&created.index()) {
                    if !replay || old != &created {
                        decision.refuse(28);
                    }
                } else if replay {
                    decision.refuse(12);
                }
                decision.dependencies = if replay {
                    intent.expected.clone()
                } else {
                    vec![target.clone(), admission.grant]
                };
                decision.dependencies.sort_by_key(VersionRef::index);
                decision.dependencies.dedup();
                if !replay && exact && decision.dependencies != intent.expected {
                    decision.refuse(12);
                }
                decision.dependencies.push(created.clone());
                decision.record = Some(bytes.clone());
                decision.created = Some(created);
                decision.finish(&intent.action, vec![b(&bytes)], 64)?;
            }
        }
        Ok(decision)
    }
}
/// The quorum certifies ownership/completeness; this checks the exact bounded lifecycle schema.
#[cfg(test)]
pub fn validate_lifecycle_result(intent: &Intent, value: &V) -> Result<Vec<VersionRef>> {
    let operation = Operation::parse(intent)?;
    let f = value.list(7)?;
    ensure!(
        f.len() >= 4 && f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == intent.action,
        "application result context differs"
    );
    let declared = refs(
        &f[3],
        if matches!(operation, Operation::List { .. }) {
            192
        } else {
            64
        },
    )?;
    let mut derived = Vec::new();
    match operation {
        Operation::Get {
            application,
            minimum,
        } => {
            let f = value.array(7)?;
            let admission = Registration::parse(f[4].bytes()?, intent.network, intent.incarnation)?;
            ensure!(
                admission.application == application
                    && (intent.requester == application || intent.requester == admission.owner),
                "application metadata is not owned by requester"
            );
            let grant_bytes = f[5].bytes()?;
            let grant = record_reference(grant_bytes)?;
            let value = wire::decode(grant_bytes)?;
            let g = prefix(&value, 102, 17, intent.network, intent.incarnation)?;
            let child = membership::ChildSpec::parse(
                &a(vec![
                    g[6].clone(),
                    g[8].clone(),
                    g[9].clone(),
                    g[10].clone(),
                    g[11].clone(),
                    g[12].clone(),
                    g[14].clone(),
                    g[15].clone(),
                ]),
                intent.network,
            )?;
            ensure!(
                grant == admission.grant
                    && g[7].fixed::<32>()? == admission.owner
                    && child.subject == application
                    && version(&g[13])?.kind == 102
                    && child.depth == 0
                    && !child.actions.contains(&11)
                    && (admission.renewable
                        || admission.validity.0 >= child.validity.0
                            && admission.validity.1 <= child.validity.1),
                "application metadata grant differs"
            );
            Snapshot::parse(&g[16])?;
            derived.extend([admission.reference.clone(), grant]);
            if f[6] != V::Null {
                let withdrawal =
                    Withdrawal::parse(f[6].bytes()?, intent.network, intent.incarnation)?;
                ensure!(
                    withdrawal.admission == admission.reference
                        && (withdrawal.withdrawer == application
                            || withdrawal.withdrawer == admission.owner),
                    "application withdrawal differs"
                );
                derived.push(withdrawal.reference);
            } else {
                ensure!(
                    !minimum.iter().any(|v| v.kind == 128 && v.id == application),
                    "application withdrawal omitted"
                );
            }
            ensure!(
                relevant_minima(&derived, &minimum),
                "application metadata is below retained generations"
            );
        }
        Operation::List { minimum, .. } => {
            let f = value.array(5)?;
            let mut prior = None;
            for row in f[4].list(63)? {
                let r = row.array(4)?;
                let application = r[0].fixed()?;
                wire::valid_key(&application)?;
                ensure!(
                    prior.is_none_or(|p| p < application) && application != intent.requester,
                    "application list is duplicate, unsorted or self-owned"
                );
                prior = Some(application);
                let admission = version(&r[1])?;
                let grant = version(&r[2])?;
                ensure!(
                    admission.kind == 127 && admission.id == application && grant.kind == 102,
                    "application list row references differ"
                );
                derived.extend([admission, grant]);
                if r[3] != V::Null {
                    let withdrawal = version(&r[3])?;
                    ensure!(
                        withdrawal.kind == 128 && withdrawal.id == application,
                        "application list withdrawal differs"
                    );
                    derived.push(withdrawal);
                } else {
                    ensure!(
                        !minimum.iter().any(|v| v.kind == 128 && v.id == application),
                        "application list withdrawal omitted"
                    );
                }
            }
            ensure!(
                relevant_minima(&derived, &minimum),
                "application list is below retained generations"
            );
        }
        _ => anyhow::bail!("not an application metadata result"),
    }
    derived.sort_by_key(VersionRef::index);
    derived.dedup();
    ensure!(
        declared == derived && wire::encode(value)?.len() <= MAX_CONTEXT_BYTES,
        "application result versions or size differ"
    );
    Ok(declared)
}

#[cfg(test)]
mod renewal_vectors {
    use super::*;
    #[test]
    fn published_dual_consent_vector_binds_exact_predecessor_and_parties() {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../Documentation/ApplicationRenewalVector.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(value[name].as_str().unwrap()).unwrap();
        let network: Digest = bytes("network").try_into().unwrap();
        let incarnation: Digest = bytes("incarnation").try_into().unwrap();
        let previous =
            Registration::parse(&bytes("previousAdmission"), network, incarnation).unwrap();
        let envelope = bytes("renewalConsent");
        let renewal = Renewal::parse(&envelope, network, incarnation, true).unwrap();
        assert_eq!(renewal.admission, previous.reference);
        assert_eq!(renewal.owner, previous.owner);
        assert_eq!(renewal.grant, previous.grant);
        assert!(Renewal::parse(&envelope, network, incarnation, false).is_err());
        assert!(Renewal::parse(&envelope, [9; 32], incarnation, true).is_err());
        let mut changed = envelope;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(Renewal::parse(&changed, network, incarnation, true).is_err());
    }
}
