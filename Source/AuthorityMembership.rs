// SPDX-License-Identifier: MIT
// Creation codecs are shared by execution and independent admission inspection.
use crate::{
    authority_governance::{Governance, Requirement, UNCERTAINTY_MS},
    authority_proof::{Digest, Intent, Key, VersionRef, validate_versions},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
fn id(value: &V) -> Result<Digest> {
    let value = value.fixed()?;
    ensure!(value != [0; 32], "zero membership identifier");
    Ok(value)
}
pub fn reference(value: &VersionRef) -> V {
    a(vec![
        V::Uint(value.kind),
        b(&value.id),
        V::Uint(value.generation),
        b(&value.digest),
    ])
}
pub fn version(value: &V) -> Result<VersionRef> {
    let f = value.array(4)?;
    let result = VersionRef {
        kind: f[0].uint()?,
        id: id(&f[1])?,
        generation: f[2].uint()?,
        digest: id(&f[3])?,
    };
    validate_versions(std::slice::from_ref(&result), 1)?;
    ensure!(
        matches!(
            result.kind,
            100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
        ),
        "unsupported governance reference"
    );
    Ok(result)
}
fn span(value: &V) -> Result<(u64, u64)> {
    let f = value.array(2)?;
    let result = (f[0].uint()?, f[1].uint()?);
    ensure!(result.0 < result.1, "invalid validity interval");
    Ok(result)
}
pub fn current(at: u64, validity: (u64, u64)) -> bool {
    at.checked_sub(UNCERTAINTY_MS)
        .is_some_and(|t| t >= validity.0)
        && at
            .checked_add(UNCERTAINTY_MS)
            .is_some_and(|t| t < validity.1)
}
fn limits(value: &V) -> Result<[u64; 4]> {
    let f = value.array(4)?;
    Ok([f[0].uint()?, f[1].uint()?, f[2].uint()?, f[3].uint()?])
}
fn actions(value: &V) -> Result<Vec<u64>> {
    let values = value
        .list(32)?
        .iter()
        .map(V::uint)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !values.is_empty()
            && values.iter().all(|v| *v < 32)
            && values.windows(2).all(|v| v[0] < v[1]),
        "invalid action set"
    );
    Ok(values)
}
fn scopes(value: &V, network: Digest) -> Result<Vec<(u64, Digest)>> {
    let values = value
        .list(64)?
        .iter()
        .map(|v| {
            let f = v.array(2)?;
            let result = (f[0].uint()?, id(&f[1])?);
            ensure!(
                result.0 <= 5 && (result.0 != 0 || result.1 == network),
                "invalid capability scope"
            );
            Ok(result)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !values.is_empty() && values.windows(2).all(|v| v[0] < v[1]),
        "invalid scope set"
    );
    Ok(values)
}
pub fn capability_failure(governance: &Governance, grant: Digest, at: u64) -> u64 {
    let mut cursor = grant;
    let mut seen = BTreeSet::new();
    for _ in 0..=8 {
        if !seen.insert(cursor) {
            return 5;
        }
        if governance.record_bytes(126, cursor).is_ok() {
            return 6;
        }
        let Ok(bytes) = governance.record_bytes(102, cursor) else {
            return 3;
        };
        let Ok(value) = wire::decode(bytes) else {
            return 3;
        };
        let Ok(fields) = value.array(17) else {
            return 3;
        };
        if span(&fields[12]).is_ok_and(|span| !current(at, span)) {
            return 7;
        }
        let subject = fields[8].fixed::<32>().ok();
        for reference in governance.versions().iter().filter(|v| v.kind == 125) {
            if let Ok(bytes) = governance.record_bytes(125, reference.id)
                && let Ok(value) = wire::decode(bytes)
                && let Ok(member) = value.array(12)
                && member[7].fixed::<32>().ok() == subject
                && span(&member[8]).is_ok_and(|span| !current(at, span))
            {
                return 7;
            }
        }
        if fields[13] == V::Null {
            return 3;
        }
        let Ok(parent) = version(&fields[13]) else {
            return 3;
        };
        cursor = parent.id;
    }
    5
}
fn subset(child: &[(u64, Digest)], parent: &[(u64, Digest)], network: Digest) -> bool {
    child
        .iter()
        .all(|scope| parent.contains(scope) || parent.contains(&(0, network)))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservations(pub Vec<(u64, Key)>);
impl Reservations {
    pub fn parse(value: &V) -> Result<Self> {
        let mut keys = BTreeSet::new();
        let entries = value
            .list(64)?
            .iter()
            .map(|v| {
                let f = v.array(2)?;
                let pair = (f[0].uint()?, f[1].fixed()?);
                wire::valid_key(&pair.1)?;
                ensure!(
                    pair.0 <= 6 && keys.insert(pair.1),
                    "unknown role or reused reserved key"
                );
                Ok(pair)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            entries.windows(2).all(|v| v[0] < v[1]),
            "role reservations are not sorted and unique"
        );
        Ok(Self(entries))
    }
    pub fn value(&self) -> V {
        a(self
            .0
            .iter()
            .map(|(role, key)| a(vec![V::Uint(*role), b(key)]))
            .collect())
    }
    pub fn contains(&self, key: &Key) -> bool {
        self.0.iter().any(|(_, k)| k == key)
    }
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub epoch: u64,
    pub height: u64,
    pub state: Digest,
    pub references: Vec<VersionRef>,
    pub value: V,
}
impl Snapshot {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(2)?;
        let p = f[0].array(3)?;
        let references = f[1]
            .list(64)?
            .iter()
            .map(version)
            .collect::<Result<Vec<_>>>()?;
        validate_versions(&references, 64)?;
        Ok(Self {
            epoch: p[0].uint()?,
            height: p[1].uint()?,
            state: id(&p[2])?,
            references,
            value: value.clone(),
        })
    }
}
#[derive(Clone, Debug)]
pub struct ChildSpec {
    pub id: Digest,
    pub subject: Key,
    pub tier: VersionRef,
    pub actions: Vec<u64>,
    pub scopes: Vec<(u64, Digest)>,
    pub validity: (u64, u64),
    pub depth: u64,
    pub limits: [u64; 4],
    pub value: V,
}
impl ChildSpec {
    pub fn parse(value: &V, network: Digest) -> Result<Self> {
        let f = value.array(8)?;
        let subject = f[1].fixed()?;
        wire::valid_key(&subject)?;
        let tier = version(&f[2])?;
        let depth = f[6].uint()?;
        ensure!(
            tier.kind == 101 && depth <= 8,
            "invalid child tier or depth"
        );
        Ok(Self {
            id: id(&f[0])?,
            subject,
            tier,
            actions: actions(&f[3])?,
            scopes: scopes(&f[4], network)?,
            validity: span(&f[5])?,
            depth,
            limits: limits(&f[7])?,
            value: value.clone(),
        })
    }
}
#[derive(Clone, Debug)]
pub struct Acceptance {
    pub member_id: Digest,
    pub candidate: Key,
    pub validity: (u64, u64),
    pub reader: VersionRef,
    pub administrator: Key,
    pub acceptance_validity: (u64, u64),
}
impl Acceptance {
    pub fn parse(
        bytes: &[u8],
        network: Digest,
        incarnation: Digest,
        require_candidate: bool,
    ) -> Result<Self> {
        ensure!(
            bytes.len() <= 1024,
            "membership acceptance exceeds its bound"
        );
        let (payload, signatures) = wire::envelope(bytes, 2)?;
        let value = wire::decode(&payload)?;
        let f = value.array(12)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityMemberAcceptance"
                && id(&f[3])? == network
                && id(&f[4])? == incarnation,
            "membership acceptance context differs"
        );
        let candidate = f[6].fixed()?;
        let administrator = f[9].fixed()?;
        wire::valid_key(&candidate)?;
        wire::valid_key(&administrator)?;
        let reader = version(&f[8])?;
        let validity = span(&f[7])?;
        let acceptance_validity = span(&f[11])?;
        ensure!(
            candidate != administrator
                && reader.kind == 102
                && acceptance_validity.0 >= validity.0
                && acceptance_validity.1 <= validity.1
                && acceptance_validity.1 - acceptance_validity.0 <= 86_400_000,
            "invalid membership acceptance semantics"
        );
        ensure!(signatures.len() == if require_candidate {2} else {1}
            && signatures.iter().any(|(key,_)| *key == administrator)
            && signatures.iter().all(|(key,_)| *key == administrator || require_candidate && *key == candidate), "membership possession signatures differ");
        id(&f[10])?;
        Ok(Self {
            member_id: id(&f[5])?,
            candidate,
            validity,
            reader,
            administrator,
            acceptance_validity,
        })
    }
}
#[derive(Clone, Debug)]
pub enum Mutation {
    Delegate {
        parent: VersionRef,
        child: ChildSpec,
        snapshot: Snapshot,
    },
    Admit {
        grant: Digest,
        acceptance: Acceptance,
        snapshot: Snapshot,
    },
}
impl Mutation {
    pub fn parse(intent: &Intent) -> Result<Self> {
        let value = wire::decode(&intent.parameters)?;
        let f = value.array(6)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == intent.action,
            "mutation parameters differ"
        );
        let snapshot = Snapshot::parse(&f[5])?;
        ensure!(
            intent.revision == 1
                && intent.profile_generation == 0
                && intent.minimum_policy_epoch == snapshot.epoch
                && intent.minimum_policy_height == snapshot.height
                && intent.expected == snapshot.references,
            "mutation differs from its signed snapshot"
        );
        Ok(match intent.action.as_str() {
            "AuthorityDelegateGrant" => {
                let parent = version(&f[3])?;
                let child = ChildSpec::parse(&f[4], intent.network)?;
                ensure!(
                    parent.kind == 102 && child.id == intent.resource,
                    "delegation resource differs"
                );
                Self::Delegate {
                    parent,
                    child,
                    snapshot,
                }
            }
            "AuthorityAdmitMember" => {
                let acceptance =
                    Acceptance::parse(f[4].bytes()?, intent.network, intent.incarnation, true)?;
                ensure!(
                    acceptance.member_id == intent.resource
                        && acceptance.administrator == intent.requester,
                    "admission requester or resource differs"
                );
                Self::Admit {
                    grant: id(&f[3])?,
                    acceptance,
                    snapshot,
                }
            }
            _ => anyhow::bail!("unsupported membership mutation"),
        })
    }
    pub fn snapshot(&self) -> &Snapshot {
        match self {
            Self::Delegate { snapshot, .. } | Self::Admit { snapshot, .. } => snapshot,
        }
    }
    pub fn subject(&self) -> Key {
        match self {
            Self::Delegate { child, .. } => child.subject,
            Self::Admit { acceptance, .. } => acceptance.candidate,
        }
    }
    pub fn grant(&self) -> Digest {
        match self {
            Self::Delegate { parent, .. } => parent.id,
            Self::Admit { grant, .. } => *grant,
        }
    }
    pub fn derive(&self, intent: &Intent) -> Result<Vec<u8>> {
        let mut f = vec![
            V::Uint(match self {
                Self::Delegate { .. } => 102,
                Self::Admit { .. } => 125,
            }),
            V::Uint(1),
            b(&intent.network),
            b(&intent.incarnation),
            V::Uint(1),
            V::Null,
        ];
        match self {
            Self::Delegate {
                parent,
                child,
                snapshot,
            } => {
                let c = child.value.array(8)?;
                f.extend([
                    b(&child.id),
                    b(&intent.requester),
                    b(&child.subject),
                    c[2].clone(),
                    c[3].clone(),
                    c[4].clone(),
                    c[5].clone(),
                    reference(parent),
                    c[6].clone(),
                    c[7].clone(),
                    snapshot.value.clone(),
                ]);
            }
            Self::Admit {
                acceptance,
                snapshot,
                ..
            } => f.extend([
                b(&acceptance.member_id),
                b(&acceptance.candidate),
                a(vec![
                    V::Uint(acceptance.validity.0),
                    V::Uint(acceptance.validity.1),
                ]),
                V::Bool(false),
                reference(&acceptance.reader),
                snapshot.value.clone(),
            ]),
        }
        wire::encode(&a(f))
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
    /// Computes the complete dependency set before the submitter signs its current snapshot.
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
    fn evaluate(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        exact: bool,
    ) -> Result<Decision> {
        let governance = Governance::parse(intent.network, intent.incarnation, records)?;
        let all = governance.versions();
        let bytes = self.derive(intent)?;
        let kind = if matches!(self, Self::Delegate { .. }) {
            102
        } else {
            125
        };
        let created = VersionRef {
            kind,
            id: intent.resource,
            generation: 1,
            digest: wire::digest(&bytes),
        };
        let mut decision = Decision {
            code: 0,
            record: bytes,
            created,
            dependencies: vec![],
            not_before_ms: 0,
            expires_ms: u64::MAX,
            member_key: None,
        };
        if governance.record_bytes(127, intent.requester).is_ok() {
            decision.refuse(4);
        }
        if governance.record_bytes(127, self.subject()).is_ok() {
            match self {
                Self::Admit { .. } => decision.refuse(38),
                Self::Delegate { child, .. } if child.depth != 0 || child.actions.contains(&11) => {
                    decision.refuse(4);
                }
                _ => {}
            }
        }
        if reservations.contains(&self.subject()) {
            decision.refuse(38);
        }
        if all
            .iter()
            .any(|v| v.index() == decision.created.index() && (!replay || v != &decision.created))
        {
            decision.refuse(28);
        }
        if !replay && kind == 102 && governance.record_bytes(126, intent.resource).is_ok() {
            decision.refuse(6);
        }
        if replay && !all.contains(&decision.created) {
            decision.refuse(12);
        }
        if exact && intent.expected.iter().any(|v| !all.contains(v)) {
            decision.refuse(12);
        }
        if governance.revoked_chain(self.grant()).unwrap_or(false) {
            decision.refuse(6);
        }
        let scope = match self {
            Self::Delegate { child, .. } => child.scopes[0],
            _ => (0, intent.network),
        };
        let requirement = Requirement {
            subject: intent.requester,
            actions: if kind == 102 { &[11] } else { &[10] },
            scope,
            namespace: None,
            usage: [0, 1, 0, 1],
            evaluated_at_ms: at,
            expected: &[],
        };
        let capability = match governance.current_capability(self.grant(), &requirement) {
            Ok(c) => Some(c),
            Err(_) => {
                decision.refuse(capability_failure(&governance, self.grant(), at));
                None
            }
        };
        if let Some(c) = capability {
            decision.dependencies = c.dependencies;
            decision.not_before_ms = c.not_before_ms;
            decision.expires_ms = c.expires_ms;
        }
        // Exact replay discloses the original record under current submitting authority.
        // One-time acceptance and reader authority are historical, not granted again.
        if replay {
            decision.dependencies = intent.expected.clone();
            return Ok(decision);
        }
        match self {
            Self::Delegate { parent, child, .. } => {
                if child.id == parent.id {
                    decision.refuse(5);
                }
                if !all.contains(parent) || !all.contains(&child.tier) {
                    decision.refuse(12);
                }
                if !current(at, child.validity) {
                    decision.refuse(7);
                }
                if let (Ok(parent_bytes), Ok(tier_bytes)) = (
                    governance.record_bytes(102, parent.id),
                    governance.record_bytes(101, child.tier.id),
                ) {
                    let p = wire::decode(parent_bytes)?;
                    let p = p.array(17)?;
                    let t = wire::decode(tier_bytes)?;
                    let t = t.array(14)?;
                    let pa = actions(&p[10])?;
                    let ta = actions(&t[9])?;
                    let ps = scopes(&p[11], intent.network)?;
                    let ts = scopes(&t[10], intent.network)?;
                    let pl = limits(&p[15])?;
                    let tl = limits(&t[12])?;
                    let pv = span(&p[12])?;
                    if p[8].fixed::<32>()? != intent.requester
                        || !pa.contains(&11)
                        || !child
                            .actions
                            .iter()
                            .all(|a| pa.contains(a) && ta.contains(a))
                        || !subset(&child.scopes, &ps, intent.network)
                        || !subset(&child.scopes, &ts, intent.network)
                        || child.limits.iter().zip(pl).any(|(a, b)| *a > b)
                        || child.limits.iter().zip(tl).any(|(a, b)| *a > b)
                        || child.validity.0 < pv.0
                        || child.validity.1 > pv.1
                        || p[14].uint()? == 0
                        || child.depth >= p[14].uint()?
                        || child.depth > t[11].uint()?
                    {
                        decision.refuse(4);
                    }
                    decision.dependencies.push(child.tier.clone());
                    decision.not_before_ms = decision.not_before_ms.max(child.validity.0);
                    decision.expires_ms = decision.expires_ms.min(child.validity.1);
                } else {
                    decision.refuse(3);
                }
            }
            Self::Admit { acceptance, .. } => {
                if governance
                    .revoked_chain(acceptance.reader.id)
                    .unwrap_or(false)
                {
                    decision.refuse(6);
                }
                if !current(at, acceptance.validity) || !current(at, acceptance.acceptance_validity)
                {
                    decision.refuse(7);
                }
                if !all.contains(&acceptance.reader) {
                    decision.refuse(12);
                }
                for record in records {
                    let value = wire::decode(record)?;
                    let fields = value.list(32)?;
                    if fields[0].uint()? == 125
                        && fields[7].fixed::<32>()? == acceptance.candidate
                        && (!replay || wire::digest(record) != decision.created.digest)
                    {
                        decision.refuse(28);
                    }
                }
                let mut prospective = records.to_vec();
                if !all.contains(&decision.created) {
                    prospective.push(decision.record.clone());
                    sort_records(&mut prospective)?;
                }
                if let Ok(prospective) =
                    Governance::parse(intent.network, intent.incarnation, &prospective)
                {
                    let reader = prospective
                        .record_bytes(102, acceptance.reader.id)
                        .ok()
                        .map(wire::decode)
                        .transpose()?;
                    if prospective
                        .revoked_chain(acceptance.reader.id)
                        .unwrap_or(false)
                    {
                        decision.refuse(6);
                    }
                    if let Some(reader) = reader {
                        let fields = reader.array(17)?;
                        let reader_scopes = scopes(&fields[11], intent.network)?;
                        let req = Requirement {
                            subject: acceptance.candidate,
                            actions: &[0],
                            scope: reader_scopes[0],
                            namespace: None,
                            usage: [0, 1, 0, 1],
                            evaluated_at_ms: at,
                            expected: &[],
                        };
                        match prospective.current_capability(acceptance.reader.id, &req) {
                            Ok(c) => {
                                decision.dependencies.extend(
                                    c.dependencies
                                        .into_iter()
                                        .filter(|v| v != &decision.created),
                                );
                                decision.not_before_ms = decision
                                    .not_before_ms
                                    .max(c.not_before_ms)
                                    .max(acceptance.acceptance_validity.0);
                                decision.expires_ms = decision
                                    .expires_ms
                                    .min(c.expires_ms)
                                    .min(acceptance.acceptance_validity.1);
                            }
                            Err(_) => decision.refuse(capability_failure(
                                &prospective,
                                acceptance.reader.id,
                                at,
                            )),
                        }
                    } else {
                        decision.refuse(3);
                    }
                } else {
                    decision.refuse(28);
                }
                decision.member_key = Some(acceptance.candidate);
            }
        }
        decision.dependencies.sort_by_key(VersionRef::index);
        decision.dependencies.dedup();
        if decision.dependencies.len() >= 64 {
            decision.refuse(2);
        } else if exact && decision.dependencies != intent.expected {
            decision.refuse(12);
        }
        Ok(decision)
    }
}
pub struct Decision {
    pub code: u64,
    pub record: Vec<u8>,
    pub created: VersionRef,
    pub dependencies: Vec<VersionRef>,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub member_key: Option<Key>,
}
impl Decision {
    fn refuse(&mut self, code: u64) {
        self.code = if self.code == 0 {
            code
        } else {
            self.code.min(code)
        };
    }
}
pub fn sort_records(records: &mut [Vec<u8>]) -> Result<()> {
    let mut keyed = records
        .iter()
        .map(|bytes| {
            let value = wire::decode(bytes)?;
            let f = value.list(32)?;
            let kind = f[0].uint()?;
            let lookup = if matches!(kind, 100 | 114 | 131) {
                id(&f[2])?
            } else if kind == 105 {
                id(&f[7])?
            } else if matches!(kind, 126 | 128) {
                version(&f[6])?.id
            } else {
                id(&f[6])?
            };
            Ok(((kind, lookup), bytes.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by_key(|(key, _)| *key);
    for (slot, (_, bytes)) in records.iter_mut().zip(keyed) {
        *slot = bytes;
    }
    Ok(())
}
