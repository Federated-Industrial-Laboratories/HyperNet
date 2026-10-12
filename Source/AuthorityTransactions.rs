// SPDX-License-Identifier: MIT
// Current discovery and exact grant revocation have distinct version semantics.
use super::{State, array, b, reference};
use crate::{
    authority_applications, authority_deployments,
    authority_governance::{CapabilityDecision, Governance, Requirement},
    authority_membership::{self as membership, Mutation},
    authority_proof::{Intent, VersionRef, validate_versions},
    consensus::records::Configuration,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};

const MAX_CONTEXT_BYTES: usize = 32768;
const MAX_CONTEXT_RECORDS: usize = 64;
#[cfg(test)]
#[path = "AuthorityDiscoveryTests.rs"]
mod discovery_tests;
#[derive(Clone)]
pub(super) struct ContextCursor {
    root: [u8; 32],
    count: usize,
    next: usize,
}
impl ContextCursor {
    fn parse(value: &V) -> Result<Option<Self>> {
        if *value == V::Null {
            return Ok(None);
        }
        let f = value.array(3)?;
        let cursor = Self {
            root: f[0].fixed()?,
            count: usize::try_from(f[1].uint()?)?,
            next: usize::try_from(f[2].uint()?)?,
        };
        ensure!(
            cursor.root != [0; 32]
                && cursor.count <= crate::authority_capacity::MAX_RECORDS
                && cursor.next > 0
                && cursor.next < cursor.count,
            "invalid context cursor"
        );
        Ok(Some(cursor))
    }
}
fn context_root(config: &Configuration, versions: &[VersionRef]) -> Result<[u8; 32]> {
    Ok(wire::digest(&wire::encode(&array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityRecordsView".into()),
        array(vec![
            b(&config.scope.network),
            b(&config.scope.incarnation),
            V::Uint(config.scope.epoch),
        ]),
        array(versions.iter().map(reference).collect()),
    ]))?))
}
fn context_page(
    root: &[u8; 32],
    current: &[VersionRef],
    records: &[Vec<u8>],
    start: usize,
) -> Result<Option<V>> {
    let mut output = None;
    for end in start + 1..=current.len().min(start + MAX_CONTEXT_RECORDS) {
        let page = value(
            "AuthorityContext",
            &current[start..end],
            array(vec![
                b(root),
                V::Uint(current.len() as u64),
                V::Uint(start as u64),
                if end == current.len() {
                    V::Null
                } else {
                    V::Uint(end as u64)
                },
                array(records[start..end].iter().map(|r| b(r)).collect()),
            ]),
        );
        let encoded = wire::encode(&array(vec![
            V::Uint(24),
            V::Uint(1),
            V::Text("AuthorityContext".into()),
            V::Uint(0),
            V::Uint(0),
            b(&wire::encode(&page)?),
        ]))?;
        if encoded.len() > MAX_CONTEXT_BYTES {
            break;
        }
        output = Some(page);
    }
    Ok(output)
}
fn version(value: &V) -> Result<VersionRef> {
    let f = value.array(4)?;
    let v = VersionRef {
        kind: f[0].uint()?,
        id: f[1].fixed()?,
        generation: f[2].uint()?,
        digest: f[3].fixed()?,
    };
    validate_versions(std::slice::from_ref(&v), 1)?;
    ensure!(
        matches!(
            v.kind,
            100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
        ),
        "unsupported governance version kind"
    );
    Ok(v)
}
fn versions(value: &V, maximum: usize) -> Result<Vec<VersionRef>> {
    let values = value
        .list(maximum)?
        .iter()
        .map(version)
        .collect::<Result<Vec<_>>>()?;
    validate_versions(&values, maximum)?;
    Ok(values)
}
#[derive(Clone)]
pub(super) struct Point {
    epoch: u64,
    height: u64,
    state: [u8; 32],
}
impl Point {
    fn parse(value: &V) -> Result<Self> {
        let f = value.array(3)?;
        let point = Self {
            epoch: f[0].uint()?,
            height: f[1].uint()?,
            state: f[2].fixed()?,
        };
        ensure!(point.state != [0; 32], "zero expected state digest");
        Ok(point)
    }
    fn exact(&self, config: &Configuration, height: u64, prior: &[u8]) -> bool {
        self.epoch == config.scope.epoch
            && self.height == height
            && self.state == wire::digest(prior)
    }
}
pub(super) enum Operation {
    Runtime(crate::authority_runtime_activation::Operation),
    Reconfigure(crate::authority_epoch::Declaration),
    Domain(crate::authority_domains::Operation),
    Application(authority_applications::Operation),
    Deployment(authority_deployments::Operation),
    Mutation(Mutation),
    Inspect {
        grant: [u8; 32],
        kind: u64,
        lookup: [u8; 32],
    },
    Context {
        grant: [u8; 32],
        point: Point,
        cursor: Option<ContextCursor>,
    },
    Revoke {
        grant: [u8; 32],
        target: VersionRef,
        point: Point,
        snapshot: V,
    },
}
impl Operation {
    pub fn parse(intent: &Intent, config: &Configuration) -> Result<Self> {
        ensure!(
            intent.network == config.scope.network
                && intent.incarnation == config.scope.incarnation,
            "governance request context differs"
        );
        if crate::authority_runtime_activation::Operation::handles(&intent.action) {
            return Ok(Self::Runtime(
                crate::authority_runtime_activation::Operation::parse(intent)?,
            ));
        }
        ensure!(
            intent.profile_generation == 0,
            "non-runtime governance profile generation differs"
        );
        if intent.action == "Reconfigure" {
            return Ok(Self::Reconfigure(
                crate::authority_epoch::Declaration::from_intent(intent)?,
            ));
        }
        if crate::authority_domains::Operation::handles(&intent.action) {
            return Ok(Self::Domain(crate::authority_domains::Operation::parse(
                intent,
            )?));
        }
        if authority_deployments::Operation::handles(&intent.action) {
            return Ok(Self::Deployment(authority_deployments::Operation::parse(
                intent,
            )?));
        }
        if authority_applications::Operation::handles(&intent.action) {
            return Ok(Self::Application(authority_applications::Operation::parse(
                intent,
            )?));
        }
        if matches!(
            intent.action.as_str(),
            "AuthorityDelegateGrant" | "AuthorityAdmitMember"
        ) {
            return Ok(Self::Mutation(Mutation::parse(intent)?));
        }
        let decoded = wire::decode(&intent.parameters)?;
        let f = decoded.array(6)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == intent.action,
            "governance parameters differ from signed action"
        );
        let grant = f[3].fixed::<32>()?;
        ensure!(grant != [0; 32], "zero authorising grant");
        Ok(match intent.action.as_str() {
            "AuthorityInspect" => {
                let kind = f[4].uint()?;
                let lookup = f[5].fixed::<32>()?;
                ensure!(
                    matches!(
                        kind,
                        100 | 101 | 102 | 105 | 114 | 117 | 125 | 126 | 127 | 128 | 129 | 130 | 131
                    ) && lookup != [0; 32]
                        && lookup == intent.resource,
                    "invalid exact inspection resource"
                );
                Self::Inspect {
                    grant,
                    kind,
                    lookup,
                }
            }
            "AuthorityContext" => {
                let point = Point::parse(&f[4])?;
                let cursor = ContextCursor::parse(&f[5])?;
                ensure!(
                    intent.resource == config.scope.network
                        && intent.revision == 0
                        && intent.expected.is_empty()
                        && point.epoch == config.scope.epoch
                        && intent.minimum_policy_height == point.height,
                    "invalid explicit context discovery"
                );
                Self::Context {
                    grant,
                    point,
                    cursor,
                }
            }
            "AuthorityRevokeGrant" => {
                let target = version(&f[4])?;
                let snapshot = f[5].array(2)?;
                let point = Point::parse(&snapshot[0])?;
                let dependencies = versions(&snapshot[1], 64)?;
                ensure!(
                    target.kind == 102
                        && target.id == intent.resource
                        && target.generation == intent.revision
                        && point.epoch == config.scope.epoch
                        && intent.minimum_policy_height == point.height
                        && dependencies == intent.expected
                        && dependencies.contains(&target),
                    "revocation differs from its exact expected snapshot"
                );
                Self::Revoke {
                    grant,
                    target,
                    point,
                    snapshot: f[5].clone(),
                }
            }
            _ => anyhow::bail!("unsupported authority action"),
        })
    }
    pub fn grant(&self) -> [u8; 32] {
        match self {
            Self::Runtime(_) => unreachable!("runtime activation has its own authority"),
            Self::Reconfigure(d) => d.grant,
            Self::Domain(_) => unreachable!("domain operations use their own authority"),
            Self::Deployment(_) => unreachable!("deployment operations use their own authority"),
            Self::Application(_) => unreachable!("application operations use their own authority"),
            Self::Mutation(mutation) => mutation.grant(),
            Self::Inspect { grant, .. }
            | Self::Context { grant, .. }
            | Self::Revoke { grant, .. } => *grant,
        }
    }
}
pub(super) struct Decision {
    pub code: u64,
    pub value: V,
    pub expires: u64,
    pub records: Option<Vec<Vec<u8>>>,
    pub domains: Option<crate::authority_domains::State>,
    pub terminal: Option<crate::authority_epoch::Terminal>,
    pub restrictions: crate::authority_proof::Restrictions,
    pub admissions: Vec<[u8; 32]>,
    pub created: Option<VersionRef>,
}
fn value(action: &str, versions: &[VersionRef], body: V) -> V {
    array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text(action.into()),
        array(versions.iter().map(reference).collect()),
        body,
    ])
}
fn used(capability: &CapabilityDecision, extra: Option<&VersionRef>) -> Vec<VersionRef> {
    let mut used = capability.dependencies.clone();
    used.extend(extra.cloned());
    used.sort_by_key(VersionRef::index);
    used.dedup();
    used
}
pub(super) struct Evaluation {
    pub at: u64,
    pub expires: u64,
    pub replay: bool,
    pub recipient: crate::authority_proof::Key,
}
pub(super) fn evaluate(
    operation: &Operation,
    state: &State,
    config: &Configuration,
    prior: &[u8],
    intent: &Intent,
    evaluation: Evaluation,
    inputs: &crate::authority_objects::Resolved,
) -> Result<Decision> {
    let Evaluation {
        at: evaluated,
        expires: request_expires,
        replay,
        recipient,
    } = evaluation;
    let deployments = state.deployments()?;
    let domain_reserved = state.domains.extend_reservations(&state.reservations);
    let reserved = deployments.extend_reservations(&domain_reserved);
    if let Operation::Runtime(runtime) = operation {
        let mut selected = runtime.authorise(
            &state.records,
            &state.reservations,
            intent,
            recipient,
            evaluated,
            replay,
        )?;
        let snapshot = runtime.snapshot();
        if snapshot.epoch != config.scope.epoch
            || snapshot.height > state.height
            || snapshot.height == state.height && snapshot.state != wire::digest(prior)
        {
            selected.refuse(12);
        }
        return Ok(Decision {
            code: selected.code,
            value: selected.value,
            expires: selected.expires_ms.min(request_expires),
            records: None,
            domains: None,
            terminal: None,
            restrictions: selected.restrictions,
            admissions: vec![],
            created: None,
        });
    }
    if let Operation::Reconfigure(declaration) = operation {
        return super::epoch_evaluation::evaluate(
            declaration,
            state,
            config,
            prior,
            intent,
            evaluated,
            request_expires,
            replay,
        );
    }
    if let Operation::Domain(domain) = operation {
        if !domain
            .expected_recipient(&state.domains, &state.records, &state.reservations, intent)
            .is_ok_and(|expected| expected == recipient)
        {
            // An absent or withdrawn service is an ordinary denial at committed order.
            return Ok(Decision {
                code: 3,
                value: V::Null,
                expires: request_expires,
                records: None,
                domains: None,
                terminal: None,
                restrictions: Default::default(),
                admissions: vec![],
                created: None,
            });
        }
        let snapshot = domain.snapshot();
        let exact = snapshot.epoch == config.scope.epoch
            && snapshot.height == state.height
            && snapshot.state == wire::digest(prior);
        let mut selected = domain.prepare_with_inputs(
            &state.domains,
            &state.records,
            &state.reservations,
            intent,
            evaluated,
            replay,
            true,
            inputs,
        )?;
        // Earlier points are causal floors. The finite evaluator above compares
        // every relevant dependency and rechecks current authority and target
        // constraints; unrelated receipt commits do not invalidate that compare.
        if !replay
            && (snapshot.epoch != config.scope.epoch
                || snapshot.height > state.height
                || snapshot.height == state.height && !exact)
        {
            selected.refuse(12);
        }
        let admissions = if !replay && selected.code == 0 {
            let before = state.domains.requesters();
            let added = selected
                .state
                .as_ref()
                .map(|s| {
                    s.requesters()
                        .into_iter()
                        .filter(|key| !before.contains(key))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ensure!(
                added.is_empty()
                    || matches!(
                        domain.command,
                        crate::authority_domains::Command::Mail(
                            crate::authority_domains::mail::Command::Publish { .. }
                        ) | crate::authority_domains::Command::SealedIdentity(
                            crate::authority_domains::sealed_identity::Command::Root { .. }
                                | crate::authority_domains::sealed_identity::Command::Device { .. }
                        )
                    ),
                "native requester admission requires an owned identity operation"
            );
            added
        } else {
            vec![]
        };
        return Ok(Decision {
            code: selected.code,
            value: selected.value,
            expires: selected.expires_ms.min(request_expires),
            records: None,
            domains: selected.state,
            restrictions: Default::default(),
            terminal: None,
            admissions,
            created: None,
        });
    }
    if let Operation::Deployment(deployment) = operation {
        let retained = state.evidence.deployment_offer(intent.resource)?;
        let mut selected = deployment.authorise(
            &state.records,
            &domain_reserved,
            intent,
            evaluated,
            replay,
            retained.as_ref().map(|(m, c)| (m.as_slice(), c.as_slice())),
        )?;
        if let Some(snapshot) = deployment.snapshot()
            && !replay
            && (snapshot.epoch != config.scope.epoch
                || snapshot.height != state.height
                || snapshot.state != wire::digest(prior))
        {
            selected.refuse(12);
        }
        if let authority_deployments::Operation::Context {
            minimum_point: (epoch, height, digest),
            ..
        } = deployment
            && (*epoch != config.scope.epoch
                || *height > state.height
                || *height == state.height && *digest != wire::digest(prior))
        {
            selected.refuse(12);
        }
        let mut changed = None;
        if selected.code == 0 && !replay && !selected.records.is_empty() {
            let mut records = state.records.clone();
            records.extend(selected.records.clone());
            membership::sort_records(&mut records)?;
            if records.len() > crate::authority_capacity::MAX_RECORDS {
                selected.refuse(2)
            } else {
                Governance::parse(config.scope.network, config.scope.incarnation, &records)?;
                changed = Some(records);
            }
        }
        return Ok(Decision {
            code: selected.code,
            value: selected.value,
            expires: selected.expires_ms.min(request_expires),
            records: changed,
            domains: None,
            restrictions: Default::default(),
            terminal: None,
            admissions: if replay { vec![] } else { selected.admissions },
            created: selected.created,
        });
    }
    if let Operation::Application(application) = operation {
        let mut selected =
            application.authorise(&state.records, &reserved, intent, evaluated, replay)?;
        if let Some(snapshot) = application.snapshot()
            && !replay
            && (snapshot.epoch != config.scope.epoch
                || snapshot.height != state.height
                || snapshot.state != wire::digest(prior))
        {
            selected.refuse(12);
        }
        if let Some(point) = application.minimum_point()
            && (point.epoch != config.scope.epoch
                || point.height > state.height
                || point.height == state.height && point.state != wire::digest(prior))
        {
            selected.refuse(12);
        }
        let mut changed = None;
        if selected.code == 0
            && !replay
            && let Some(record) = &selected.record
        {
            let mut records = state.records.clone();
            records.push(record.clone());
            membership::sort_records(&mut records)?;
            if records.len() > crate::authority_capacity::MAX_RECORDS {
                selected.refuse(2);
            } else {
                Governance::parse(config.scope.network, config.scope.incarnation, &records)?;
                changed = Some(records);
            }
        }
        return Ok(Decision {
            code: selected.code,
            value: selected.value,
            expires: selected.expires_ms.min(request_expires),
            records: changed,
            domains: None,
            restrictions: Default::default(),
            terminal: None,
            admissions: if replay {
                vec![]
            } else {
                selected.admission.into_iter().collect()
            },
            created: selected.created,
        });
    }
    if let Operation::Mutation(mutation) = operation {
        let mut selected =
            mutation.authorise(&state.records, &reserved, intent, evaluated, replay)?;
        let snapshot = mutation.snapshot();
        if !replay
            && (snapshot.epoch != config.scope.epoch
                || snapshot.height != state.height
                || snapshot.state != wire::digest(prior))
        {
            selected.code = super::minimum_code(selected.code, 12);
        }
        let mut dependencies = selected.dependencies.clone();
        dependencies.push(selected.created.clone());
        dependencies.sort_by_key(VersionRef::index);
        dependencies.dedup();
        if dependencies.len() > 64 {
            selected.code = super::minimum_code(selected.code, 2);
        }
        let mut records = state.records.clone();
        if selected.code == 0 && !replay {
            records.push(selected.record.clone());
            membership::sort_records(&mut records)?;
            if records.len() > crate::authority_capacity::MAX_RECORDS {
                selected.code = 2;
            }
            if selected.code == 0 {
                Governance::parse(config.scope.network, config.scope.incarnation, &records)?;
            }
        }
        return Ok(Decision {
            code: selected.code,
            value: value(&intent.action, &dependencies, b(&selected.record)),
            expires: selected.expires_ms.min(request_expires),
            records: (selected.code == 0 && !replay).then_some(records),
            domains: None,
            restrictions: Default::default(),
            terminal: None,
            admissions: if replay {
                vec![]
            } else {
                selected.member_key.into_iter().collect()
            },
            created: Some(selected.created),
        });
    }
    let governance = Governance::parse(
        config.scope.network,
        config.scope.incarnation,
        &state.records,
    )?;
    let current = governance.versions();
    let requirement = Requirement {
        subject: intent.requester,
        actions: if matches!(operation, Operation::Revoke { .. }) {
            &[12]
        } else {
            &[25]
        },
        scope: (0, config.scope.network),
        namespace: None,
        usage: [0, 1, 0, 1],
        evaluated_at_ms: evaluated,
        expected: &intent.expected,
    };
    let capability = if matches!(operation, Operation::Context { .. }) {
        governance.current_capability(operation.grant(), &requirement)
    } else {
        governance.capability(operation.grant(), &requirement)
    };
    let mut decision = Decision {
        code: 0,
        value: array(vec![]),
        expires: capability
            .as_ref()
            .map_or(request_expires, |c| c.expires_ms.min(request_expires)),
        records: None,
        domains: None,
        restrictions: Default::default(),
        terminal: None,
        admissions: vec![],
        created: None,
    };
    let capability = match capability {
        Ok(capability) => capability,
        Err(_) => {
            decision.code = if governance.revoked_chain(operation.grant()).unwrap_or(false) {
                6
            } else {
                3
            };
            return Ok(decision);
        }
    };
    match operation {
        Operation::Runtime(_) => unreachable!("runtime operations are evaluated above"),
        Operation::Reconfigure(_) => unreachable!("epoch operations are evaluated above"),
        Operation::Domain(_) => unreachable!("domain operations are evaluated above"),
        Operation::Deployment(_) => unreachable!("deployment operations are evaluated above"),
        Operation::Application(_) => unreachable!("application operations are evaluated above"),
        Operation::Mutation(_) => unreachable!("membership mutations are evaluated above"),
        Operation::Inspect { kind, lookup, .. } => {
            let target = current.iter().find(|v| v.kind == *kind && v.id == *lookup);
            if target
                .is_none_or(|v| !intent.expected.contains(v) || intent.revision != v.generation)
            {
                decision.code = 12;
                return Ok(decision);
            }
            let target = target.context("inspection target absent")?;
            decision.value = value(
                &intent.action,
                &used(&capability, Some(target)),
                b(governance.record_bytes(*kind, *lookup)?),
            );
        }
        Operation::Context { point, cursor, .. } => {
            let root = context_root(config, &current)?;
            if point.height > state.height
                || (point.height == state.height && !point.exact(config, state.height, prior))
                || cursor
                    .as_ref()
                    .is_some_and(|c| c.root != root || c.count != current.len())
            {
                decision.code = 12;
                return Ok(decision);
            }
            let start = cursor.as_ref().map_or(0, |c| c.next);
            if let Some(page) = context_page(&root, &current, &state.records, start)? {
                decision.value = page;
            } else {
                decision.code = 2;
            }
        }
        Operation::Revoke {
            target,
            point,
            snapshot,
            ..
        } => {
            if !current.contains(target) || (!replay && !point.exact(config, state.height, prior)) {
                decision.code = 12;
                return Ok(decision);
            }
            let dependencies = used(&capability, Some(target));
            if dependencies != intent.expected {
                decision.code = 12;
                return Ok(decision);
            }
            let tombstone = wire::encode(&array(vec![
                V::Uint(126),
                V::Uint(1),
                b(&config.scope.network),
                b(&config.scope.incarnation),
                V::Uint(1),
                V::Null,
                reference(target),
                b(&intent.requester),
                snapshot.clone(),
            ]))?;
            let revoked = VersionRef {
                kind: 126,
                id: target.id,
                generation: 1,
                digest: wire::digest(&tombstone),
            };
            decision.created = Some(revoked.clone());
            let existing = current.iter().find(|v| v.index() == revoked.index());
            if existing.is_some_and(|v| !replay || *v != revoked) {
                decision.code = 6;
                return Ok(decision);
            }
            if replay && existing.is_none() {
                decision.code = 12;
                return Ok(decision);
            }
            let mut refs = dependencies;
            refs.push(revoked.clone());
            refs.sort_by_key(VersionRef::index);
            if refs.len() > 64 {
                decision.code = 2;
                return Ok(decision);
            }
            if !replay {
                let mut records = state
                    .records
                    .iter()
                    .cloned()
                    .zip(current.iter().map(VersionRef::index))
                    .map(|(bytes, key)| (key, bytes))
                    .collect::<Vec<_>>();
                records.push((revoked.index(), tombstone.clone()));
                records.sort_by_key(|(key, _)| *key);
                let records = records
                    .into_iter()
                    .map(|(_, bytes)| bytes)
                    .collect::<Vec<_>>();
                if records.len() > crate::authority_capacity::MAX_RECORDS
                    || records.iter().map(Vec::len).sum::<usize>() > super::MAX_GOVERNANCE_BYTES
                {
                    decision.code = 2;
                    return Ok(decision);
                }
                Governance::parse(config.scope.network, config.scope.incarnation, &records)?;
                decision.records = Some(records);
            }
            decision.value = value(&intent.action, &refs, b(&tombstone));
        }
    }
    Ok(decision)
}
