// SPDX-License-Identifier: MIT
// Grant chains supply one restriction; they never replace object, consent or route checks.
use crate::{
    authority_proof::{Digest, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

pub const UNCERTAINTY_MS: u64 = 1250;
pub type Limits = [u64; 4];
pub type Scope = (u64, Digest);

fn id(value: &V) -> Result<Digest> {
    let result = value.fixed()?;
    ensure!(result != [0; 32], "zero governance identifier");
    Ok(result)
}
fn reference(value: &V) -> Result<VersionRef> {
    let value = value.array(4)?;
    let result = VersionRef {
        kind: value[0].uint()?,
        id: id(&value[1])?,
        generation: value[2].uint()?,
        digest: value[3].fixed()?,
    };
    ensure!(result.generation > 0, "zero governance generation");
    Ok(result)
}
fn actions(value: &V) -> Result<Vec<u64>> {
    let result = value
        .list(32)?
        .iter()
        .map(V::uint)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        result.iter().all(|v| *v < 32) && result.windows(2).all(|p| p[0] < p[1]),
        "invalid action set"
    );
    Ok(result)
}
fn scopes(value: &V, network: Digest) -> Result<Vec<Scope>> {
    let values = value
        .list(64)?
        .iter()
        .map(|v| {
            let pair = v.array(2)?;
            let scope = (pair[0].uint()?, id(&pair[1])?);
            ensure!(
                scope.0 <= 5 && (scope.0 != 0 || scope.1 == network),
                "invalid resource scope"
            );
            Ok(scope)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.windows(2).all(|p| p[0] < p[1]),
        "scope set is not sorted and unique"
    );
    Ok(values)
}
fn limits(value: &V) -> Result<Limits> {
    let f = value.array(4)?;
    Ok([f[0].uint()?, f[1].uint()?, f[2].uint()?, f[3].uint()?])
}
fn validity(value: &V) -> Result<(u64, u64)> {
    let f = value.array(2)?;
    let span = (f[0].uint()?, f[1].uint()?);
    ensure!(span.0 < span.1, "invalid grant validity");
    Ok(span)
}
fn within(child: Limits, parent: Limits) -> bool {
    child.iter().zip(parent).all(|(a, b)| *a <= b)
}
fn scope_subset(child: &[Scope], parent: &[Scope], network: Digest) -> bool {
    child
        .iter()
        .all(|v| parent.contains(v) || parent.contains(&(0, network)))
}
fn safe_label(value: &V) -> Result<()> {
    let text = value.text()?;
    ensure!(
        (1..=128).contains(&text.len())
            && !text
                .chars()
                .any(|c| c.is_control() || matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069)),
        "invalid tier label"
    );
    Ok(())
}
fn snapshot(value: &V) -> Result<()> {
    let value = value.array(2)?;
    let point = value[0].array(3)?;
    point[0].uint()?;
    point[1].uint()?;
    point[2].fixed::<32>()?;
    let refs = value[1]
        .list(64)?
        .iter()
        .map(reference)
        .collect::<Result<Vec<_>>>()?;
    crate::authority_proof::validate_versions(&refs, 64)
}

#[derive(Clone)]
struct Record {
    reference: VersionRef,
    bytes: Vec<u8>,
    fields: Vec<V>,
}
impl Record {
    fn parse(network: Digest, incarnation: Digest, bytes: &[u8]) -> Result<Self> {
        let decoded = wire::decode(bytes)?;
        let fields = decoded.list(32)?;
        ensure!(fields.len() >= 6, "truncated governance record");
        let kind = fields[0].uint()?;
        let arity = match kind {
            100 | 102 => 17,
            129 => 18,
            101 => 14,
            114 => 13,
            125 => 12,
            126 => 9,
            127 => 11,
            128 => 9,
            105 => 19,
            117 => 16,
            130 => 11,
            131 => 9,
            _ => anyhow::bail!("unsupported governance record"),
        };
        let f = decoded.array(arity)?;
        ensure!(
            (f[1].uint()? == 1 || kind == 127 && f[1].uint()? == 2)
                && id(&f[2])? == network
                && id(&f[3])? == incarnation
                && f[4].uint()? > 0,
            "governance record context differs"
        );
        if f[4].uint()? == 1 {
            f[5].null()?;
        } else {
            f[5].fixed::<32>()?;
        }
        let lookup = match kind {
            100 | 114 | 131 => network,
            105 => id(&f[7])?,
            126 | 128 => reference(&f[6])?.id,
            _ => id(&f[6])?,
        };
        match kind {
            100 => {
                ensure!(
                    f[6].uint()? <= 1 && f[8].uint()? <= 1,
                    "unknown participation or route policy"
                );
                f[7].boolean()?;
                let domains = f[9].list(16)?.iter().map(id).collect::<Result<Vec<_>>>()?;
                ensure!(
                    !domains.is_empty() && domains.windows(2).all(|p| p[0] < p[1]),
                    "invalid relay domain set"
                );
                let modes = f[10]
                    .list(2)?
                    .iter()
                    .map(V::uint)
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    !modes.is_empty()
                        && modes.iter().all(|v| *v <= 1)
                        && modes.windows(2).all(|p| p[0] < p[1])
                        && modes.contains(&f[11].uint()?),
                    "invalid publication policy"
                );
                ensure!(reference(&f[12])?.kind == 114, "invalid recovery reference");
                limits(&f[13])?;
                // Automated review needs its own namespace mechanism, never a network-wide bypass.
                ensure!(
                    f[14].boolean()?,
                    "unscoped automated review is not supported"
                );
                let roots = f[15].list(16)?.iter().map(id).collect::<Result<Vec<_>>>()?;
                ensure!(
                    !roots.is_empty() && roots.windows(2).all(|p| p[0] < p[1]),
                    "invalid root grant set"
                );
            }
            101 => {
                ensure!(
                    f[7].uint()? <= 65535 && f[11].uint()? <= 8,
                    "tier rank or depth exceeds its bound"
                );
                safe_label(&f[8])?;
                actions(&f[9])?;
                scopes(&f[10], network)?;
                limits(&f[12])?;
            }
            102 => {
                wire::valid_key(&f[7].fixed()?)?;
                wire::valid_key(&f[8].fixed()?)?;
                ensure!(
                    reference(&f[9])?.kind == 101,
                    "grant tier reference differs"
                );
                actions(&f[10])?;
                scopes(&f[11], network)?;
                validity(&f[12])?;
                if f[13] != V::Null {
                    ensure!(
                        reference(&f[13])?.kind == 102,
                        "grant parent reference differs"
                    );
                }
                ensure!(
                    f[14].uint()? <= 8,
                    "grant delegation depth exceeds its bound"
                );
                limits(&f[15])?;
            }
            125 => {
                wire::valid_key(&f[7].fixed()?)?;
                validity(&f[8])?;
                f[9].boolean()?;
                // Admission binds the explicit reader grant; it confers no unlisted capability.
                ensure!(
                    reference(&f[10])?.kind == 102,
                    "admission requires an exact reader grant"
                );
            }
            126 => {
                ensure!(
                    reference(&f[6])?.kind == 102,
                    "revocation requires an exact grant reference"
                );
                wire::valid_key(&f[7].fixed()?)?;
            }
            127 => {
                let application = f[6].fixed()?;
                let owner = f[7].fixed()?;
                wire::valid_key(&application)?;
                wire::valid_key(&owner)?;
                let span = validity(&f[9])?;
                ensure!(
                    application != owner
                        && (f[1].uint()? == 1 || f[4].uint()? > 1)
                        && reference(&f[8])?.kind == 102
                        && span.1 - span.0 <= 7 * 24 * 60 * 60 * 1000,
                    "invalid application admission"
                );
            }
            128 => {
                ensure!(
                    reference(&f[6])?.kind == 127,
                    "invalid application withdrawal"
                );
                wire::valid_key(&f[7].fixed()?)?;
            }
            105 => {
                id(&f[7])?;
                wire::valid_key(&f[8].fixed()?)?;
                for role in f[9].list(9)? {
                    ensure!(role.uint()? <= 8, "invalid hosting role");
                }
                f[10].list(16)?;
                f[11].list(16)?;
                f[12].array(4)?;
                limits(&f[13])?;
                f[14].boolean()?;
                f[15].list(16)?;
                validity(&f[16])?;
                id(&f[17])?;
                f[18].uint()?;
            }
            117 => {
                id(&f[7])?;
                ensure!(
                    f[8].uint()? == 1 && f[15].uint()? == f[4].uint()?,
                    "unsupported runtime generation"
                );
                f[9].list(9)?;
                f[10].list(16)?;
                f[11].list(16)?;
                limits(&f[12])?;
                f[13].array(4)?;
                id(&f[14])?;
            }
            129 => {
                id(&f[7])?;
                wire::valid_key(&f[8].fixed()?)?;
                let services = f[9].list(9)?;
                ensure!(!services.is_empty(), "empty deployment services");
                let mut previous = None;
                for item in services {
                    let pair = item.array(2)?;
                    let role = pair[0].uint()?;
                    ensure!(
                        role <= 8 && previous.is_none_or(|p| p < role),
                        "unsorted deployment roles"
                    );
                    wire::valid_key(&pair[1].fixed()?)?;
                    previous = Some(role);
                }
                let transports = f[10].list(9)?;
                let mut previous = None;
                for item in transports {
                    let pair = item.array(2)?;
                    let service = pair[0].fixed::<32>()?;
                    ensure!(
                        previous.is_none_or(|p| p < service),
                        "unsorted transport bindings"
                    );
                    wire::valid_key(&service)?;
                    wire::valid_key(&pair[1].fixed()?)?;
                    previous = Some(service);
                }
                wire::valid_key(&f[11].fixed()?)?;
                ensure!(
                    reference(&f[12])?.kind == 117
                        && reference(&f[13])?.kind == 105
                        && reference(&f[15])?.kind == 102,
                    "deployment references differ"
                );
                wire::valid_key(&f[14].fixed()?)?;
                let manifest = crate::runtime_manifest::Manifest::parse(f[17].bytes()?)?;
                ensure!(
                    manifest.network == network
                        && manifest.incarnation == incarnation
                        && manifest.deployment == id(&f[6])?
                        && manifest.host == id(&f[7])?
                        && manifest.operator == f[8].fixed::<32>()?
                        && manifest.generation == f[4].uint()?
                        && manifest.clock.monitor_key == f[11].fixed::<32>()?
                        && manifest
                            .services()
                            .into_iter()
                            .map(|(r, k)| V::Array(vec![V::Uint(r), V::Bytes(k.to_vec())]))
                            .collect::<Vec<_>>()
                            == f[9].list(9)?
                        && manifest
                            .owned_transports()?
                            .into_iter()
                            .map(|(k, t)| V::Array(vec![
                                V::Bytes(k.to_vec()),
                                V::Bytes(t.to_vec())
                            ]))
                            .collect::<Vec<_>>()
                            == f[10].list(9)?
                        && reference(&f[12])?.digest == wire::digest(&manifest.desired()?)
                        && reference(&f[13])?.digest
                            == wire::digest(&manifest.unsigned_consent(0)?),
                    "deployment admission differs from exact current manifest"
                );
            }
            130 => {
                ensure!(
                    reference(&f[7])?.kind == 129 && f[9].uint()? > 0,
                    "invalid deployment withdrawal"
                );
                wire::valid_key(&f[8].fixed()?)?;
            }
            131 => {
                crate::runtime_bootstrap_keys::Keys::parse(bytes, network, incarnation)?;
            }
            114 => {
                ensure!(f[6].uint()? <= 2, "unknown recovery custody");
            }
            _ => unreachable!(),
        }
        let snapshot_index = if kind == 129 { 16 } else { arity - 1 };
        if !matches!(kind, 105 | 117 | 131) && f[snapshot_index] != V::Null {
            snapshot(&f[snapshot_index])?;
        }
        ensure!(
            f[4].uint()? == 1 || f[snapshot_index] != V::Null,
            "updated governance requires a snapshot"
        );
        ensure!(
            !matches!(kind, 125..=130) || f[snapshot_index] != V::Null,
            "membership admission or grant revocation requires a snapshot"
        );
        ensure!(
            !matches!(kind, 127 | 128 | 130 | 131)
                || f[4].uint()? == 1
                || kind == 127 && f[1].uint()? == 2,
            "application records are create-only"
        );
        ensure!(
            kind != 102 || f[13] == V::Null || f[16] != V::Null,
            "delegated grants require a snapshot"
        );
        Ok(Self {
            reference: VersionRef {
                kind,
                id: lookup,
                generation: f[4].uint()?,
                digest: wire::digest(bytes),
            },
            bytes: bytes.to_vec(),
            fields: f.to_vec(),
        })
    }
}

pub struct Governance {
    network: Digest,
    records: BTreeMap<(u64, Digest), Record>,
}
pub struct Requirement<'a> {
    pub subject: Key,
    pub actions: &'a [u64],
    pub scope: Scope,
    /// This binding must come from current certified object metadata.
    pub namespace: Option<Digest>,
    pub usage: Limits,
    pub evaluated_at_ms: u64,
    pub expected: &'a [VersionRef],
}
#[derive(Debug)]
pub struct CapabilityDecision {
    pub dependencies: Vec<VersionRef>,
    pub not_before_ms: u64,
    pub expires_ms: u64,
}
impl Governance {
    /// Validate an ordered page without claiming that its global dependencies are complete.
    pub fn record_versions(
        network: Digest,
        incarnation: Digest,
        records: &[Vec<u8>],
    ) -> Result<Vec<VersionRef>> {
        ensure!(
            records.len() <= crate::authority_capacity::MAX_RECORDS,
            "record capacity exceeded"
        );
        let refs = records
            .iter()
            .map(|bytes| Ok(Record::parse(network, incarnation, bytes)?.reference))
            .collect::<Result<Vec<_>>>()?;
        crate::authority_proof::validate_versions(&refs, crate::authority_capacity::MAX_RECORDS)?;
        Ok(refs)
    }
    /// The caller authenticates the containing committed state or bootstrap first.
    pub fn parse(network: Digest, incarnation: Digest, records: &[Vec<u8>]) -> Result<Self> {
        ensure!(
            records.len() <= crate::authority_capacity::MAX_RECORDS
                && network != [0; 32]
                && incarnation != [0; 32],
            "invalid governance scope or capacity"
        );
        let mut parsed = BTreeMap::new();
        let mut prior = None;
        for bytes in records {
            let r = Record::parse(network, incarnation, bytes)?;
            let key = (r.reference.kind, r.reference.id);
            ensure!(
                prior.is_none_or(|p| p < key) && parsed.insert(key, r).is_none(),
                "governance records are not sorted and unique"
            );
            prior = Some(key);
        }
        let result = Self {
            network,
            records: parsed,
        };
        let policy = result.record(100, network)?;
        result.exact(&reference(&policy.fields[12])?)?;
        for root in policy.fields[15].list(16)? {
            let grant = result.record(102, id(root)?)?;
            grant.fields[13].null()?;
        }
        ensure!(
            result.records.keys().filter(|(k, _)| *k == 101).count() <= 256,
            "tier capacity exceeded"
        );
        let mut admitted_keys = BTreeSet::new();
        for admission in result.records.values().filter(|r| r.reference.kind == 125) {
            ensure!(
                admitted_keys.insert(admission.fields[7].fixed::<32>()?),
                "duplicate membership signing key"
            );
        }
        for application in result.records.values().filter(|r| r.reference.kind == 127) {
            let key = application.fields[6].fixed::<32>()?;
            let owner = application.fields[7].fixed::<32>()?;
            ensure!(
                admitted_keys.insert(key) && !result.records.contains_key(&(127, owner)),
                "application reuses membership or owns another application"
            );
            let grant = result.exact(&reference(&application.fields[8])?)?;
            let parent = result.exact(&reference(&grant.fields[13])?)?;
            let span = validity(&application.fields[9])?;
            let grant_span = validity(&grant.fields[12])?;
            ensure!(
                grant.fields[8].fixed::<32>()? == key
                    && grant.fields[7].fixed::<32>()? == owner
                    && parent.fields[8].fixed::<32>()? == owner
                    && grant.fields[14].uint()? == 0
                    && !actions(&grant.fields[10])?.contains(&11)
                    && (if application.fields[1].uint()? == 2 {
                        let parent_span = validity(&parent.fields[12])?;
                        span.0 >= parent_span.0 && span.1 <= parent_span.1
                    } else {
                        span.0 >= grant_span.0 && span.1 <= grant_span.1
                    }),
                "application differs from its exact accepted grant"
            );
        }
        for withdrawal in result.records.values().filter(|r| r.reference.kind == 128) {
            let target = result.exact(&reference(&withdrawal.fields[6])?)?;
            let key = withdrawal.fields[7].fixed::<32>()?;
            ensure!(
                key == target.fields[6].fixed::<32>()? || key == target.fields[7].fixed::<32>()?,
                "withdrawer does not own the application"
            );
        }
        for revocation in result.records.values().filter(|r| r.reference.kind == 126) {
            let target = reference(&revocation.fields[6])?;
            let current = result.record(102, target.id)?;
            // Ordered insertion checks historical existence. Retained state may
            // contain a later grant generation; the tombstone still names its ID.
            ensure!(
                target.generation <= current.reference.generation
                    && (target.generation < current.reference.generation
                        || target.digest == current.reference.digest),
                "revocation grant reference is future or conflicting"
            );
        }
        Ok(result)
    }
    fn record(&self, kind: u64, id: Digest) -> Result<&Record> {
        self.records
            .get(&(kind, id))
            .context("required governance record is absent")
    }
    fn exact(&self, expected: &VersionRef) -> Result<&Record> {
        let record = self.record(expected.kind, expected.id)?;
        ensure!(
            record.reference == *expected,
            "governance reference is stale or conflicting"
        );
        Ok(record)
    }
    pub fn record_bytes(&self, kind: u64, id: Digest) -> Result<&[u8]> {
        Ok(&self.record(kind, id)?.bytes)
    }
    pub fn versions(&self) -> Vec<VersionRef> {
        self.records.values().map(|r| r.reference.clone()).collect()
    }
    fn admitted(
        &self,
        subject: Key,
        t: u64,
        dependencies: &mut BTreeMap<(u64, Digest), VersionRef>,
    ) -> Result<(u64, u64)> {
        let policy = self.record(100, self.network)?;
        // Only exact root subjects receive the descriptor's initial governance admission.
        for root in policy.fields[15].list(16)? {
            let grant = self.record(102, id(root)?)?;
            if grant.fields[8].fixed::<32>()? == subject {
                return Ok((0, u64::MAX));
            }
        }
        if let Some(application) = self.records.get(&(127, subject)) {
            let span = validity(&application.fields[9])?;
            ensure!(
                !self.records.contains_key(&(128, subject)) && conservative(t, span),
                "application admission is withdrawn or expired"
            );
            dependencies.insert(application.reference.index(), application.reference.clone());
            return Ok(span);
        }
        for record in self.records.values().filter(|r| r.reference.kind == 125) {
            let f = &record.fields;
            if f[7].fixed::<32>()? != subject {
                continue;
            }
            let span = validity(&f[8])?;
            ensure!(
                !f[9].boolean()? && conservative(t, span),
                "membership admission is revoked or expired"
            );
            let reader = self.exact(&reference(&f[10])?)?;
            ensure!(
                reader.fields[8].fixed::<32>()? == subject
                    && actions(&reader.fields[10])?.contains(&0),
                "admission reader grant is absent"
            );
            dependencies.insert(record.reference.index(), record.reference.clone());
            dependencies.insert(reader.reference.index(), reader.reference.clone());
            return Ok(span);
        }
        anyhow::bail!("subject lacks current membership admission")
    }
    pub fn capability(
        &self,
        grant: Digest,
        request: &Requirement<'_>,
    ) -> Result<CapabilityDecision> {
        self.evaluate(grant, request, true)
    }
    /// Explicit current-context discovery checks current authority without inventing signed exact versions.
    pub fn current_capability(
        &self,
        grant: Digest,
        request: &Requirement<'_>,
    ) -> Result<CapabilityDecision> {
        ensure!(
            request.expected.is_empty(),
            "discovery cannot supply exact expectations"
        );
        self.evaluate(grant, request, false)
    }
    pub fn revoked_chain(&self, grant: Digest) -> Result<bool> {
        let mut seen = BTreeSet::new();
        let mut cursor = grant;
        for _ in 0..=8 {
            ensure!(seen.insert(cursor), "grant chain cycle");
            if self.records.contains_key(&(126, cursor)) {
                return Ok(true);
            }
            let record = self.record(102, cursor)?;
            if record.fields[13] == V::Null {
                return Ok(false);
            }
            cursor = reference(&record.fields[13])?.id;
        }
        anyhow::bail!("grant chain exceeds its depth bound")
    }
    fn evaluate(
        &self,
        grant: Digest,
        request: &Requirement<'_>,
        exact_expectations: bool,
    ) -> Result<CapabilityDecision> {
        ensure!(
            !request.actions.is_empty()
                && request.actions.iter().all(|a| *a < 32)
                && request.actions.windows(2).all(|p| p[0] < p[1])
                && request.scope.0 <= 5
                && request.scope.1 != [0; 32],
            "invalid capability requirement"
        );
        crate::authority_proof::validate_versions(request.expected, 64)?;
        // Other dimensions are checked by the complete action executor. This
        // capability decision cannot certify their absence or validity.
        for expected in request
            .expected
            .iter()
            .filter(|r| matches!(r.kind, 100 | 101 | 102 | 114 | 125 | 126 | 127 | 128))
        {
            self.exact(expected)?;
        }
        let policy = self.record(100, self.network)?;
        let recovery = self.record(114, self.network)?;
        let mut dependencies = BTreeMap::from([
            (policy.reference.index(), policy.reference.clone()),
            (recovery.reference.index(), recovery.reference.clone()),
        ]);
        let roots = policy.fields[15]
            .list(16)?
            .iter()
            .map(id)
            .collect::<Result<Vec<_>>>()?;
        let mut effective = limits(&policy.fields[13])?;
        let mut expiry = u64::MAX;
        let mut start = 0;
        let mut cursor = grant;
        let mut visited = BTreeSet::new();
        let mut child: Option<&Record> = None;
        for depth in 0..=8 {
            ensure!(visited.insert(cursor), "grant chain cycle");
            ensure!(
                !self.records.contains_key(&(126, cursor)),
                "grant is permanently revoked"
            );
            let current = self.record(102, cursor)?;
            let g = &current.fields;
            let pinned_tier = reference(&g[9])?;
            let tier = self.record(101, pinned_tier.id)?;
            crate::authority_tiers::current_reference(&tier.reference, &pinned_tier)?;
            let ts = &tier.fields;
            let ga = actions(&g[10])?;
            let ta = actions(&ts[9])?;
            let gs = scopes(&g[11], self.network)?;
            let tsc = scopes(&ts[10], self.network)?;
            let gl = limits(&g[15])?;
            let tl = limits(&ts[12])?;
            let span = if child.is_none()
                && let Some(application) = self.records.get(&(127, request.subject))
                && application.fields[1].uint()? == 2
                && reference(&application.fields[8])? == current.reference
            {
                validity(&application.fields[9])?
            } else {
                validity(&g[12])?
            };
            if tier.reference == pinned_tier {
                ensure!(
                    ga.iter().all(|a| ta.contains(a))
                        && scope_subset(&gs, &tsc, self.network)
                        && within(gl, tl)
                        && g[14].uint()? <= ts[11].uint()?,
                    "grant exceeds its exact issuing tier"
                );
            }
            let scope_allowed = |scopes: &[Scope]| {
                scopes.contains(&(0, self.network))
                    || scopes.contains(&request.scope)
                    || request.scope.0 == 2
                        && request.namespace.is_some_and(|n| scopes.contains(&(1, n)))
            };
            let required_depth = depth + u64::from(request.actions.contains(&11));
            ensure!(
                conservative(request.evaluated_at_ms, span)
                    && request.actions.iter().all(|a| ta.contains(a))
                    && scope_allowed(&tsc)
                    && required_depth <= ts[11].uint()?
                    && required_depth <= g[14].uint()?,
                "operation exceeds its current tier or validity"
            );
            let subject = g[8].fixed()?;
            let admission = self.admitted(subject, request.evaluated_at_ms, &mut dependencies)?;
            if let Some(child) = child {
                let c = &child.fields;
                let cv = if let Some(application) = self.records.get(&(127, request.subject))
                    && application.fields[1].uint()? == 2
                    && reference(&application.fields[8])? == child.reference
                {
                    validity(&application.fields[9])?
                } else {
                    validity(&c[12])?
                };
                ensure!(
                    c[7].fixed::<32>()? == subject
                        && ga.contains(&11)
                        && actions(&c[10])?.iter().all(|a| ga.contains(a))
                        && scope_subset(&scopes(&c[11], self.network)?, &gs, self.network)
                        && within(limits(&c[15])?, gl)
                        && cv.0 >= span.0
                        && cv.1 <= span.1
                        && g[14].uint()? > 0
                        && c[14].uint()? < g[14].uint()?,
                    "delegated grant widens or mixes parent authority"
                );
            } else {
                if let Some(application) = self.records.get(&(127, subject)) {
                    ensure!(
                        reference(&application.fields[8])? == current.reference,
                        "application grant was not accepted"
                    );
                }
                ensure!(
                    subject == request.subject && request.actions.iter().all(|a| ga.contains(a)),
                    "grant does not cover the requester and actions"
                );
                ensure!(
                    scope_allowed(&gs),
                    "grant does not cover the exact resource"
                );
            }
            for i in 0..4 {
                effective[i] = effective[i].min(gl[i]).min(tl[i]);
            }
            start = start.max(span.0).max(admission.0);
            expiry = expiry.min(span.1).min(admission.1);
            dependencies.insert(current.reference.index(), current.reference.clone());
            dependencies.insert(tier.reference.index(), tier.reference.clone());
            if g[13] == V::Null {
                ensure!(roots.contains(&cursor), "unaccepted root grant");
                ensure!(
                    within(request.usage, effective),
                    "operation exceeds its capability limits"
                );
                let dependencies = dependencies.into_values().collect::<Vec<_>>();
                ensure!(
                    !exact_expectations
                        || dependencies.iter().all(|r| request.expected.contains(r)),
                    "required capability dependency is not in the signed expectations"
                );
                return Ok(CapabilityDecision {
                    dependencies,
                    not_before_ms: start,
                    expires_ms: expiry,
                });
            }
            ensure!(depth < 8, "grant chain exceeds its depth bound");
            let parent = reference(&g[13])?;
            self.exact(&parent)?;
            cursor = parent.id;
            child = Some(current);
        }
        anyhow::bail!("grant root is absent")
    }
}
fn conservative(t: u64, span: (u64, u64)) -> bool {
    t.checked_sub(UNCERTAINTY_MS)
        .is_some_and(|lower| lower >= span.0)
        && t.checked_add(UNCERTAINTY_MS)
            .is_some_and(|upper| upper < span.1)
}

#[cfg(test)]
#[path = "AuthorityGovernanceTests.rs"]
mod tests;
