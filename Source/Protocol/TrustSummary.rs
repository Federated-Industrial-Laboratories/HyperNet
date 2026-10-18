// SPDX-License-Identifier: MIT
// Display every public genesis capability and its exact record reference.
use crate::trust_wire::{self as wire, Value};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    kind: u64,
    record_type: &'static str,
    id: String,
    generation: u64,
    digest: String,
}
#[derive(Clone, Serialize)]
pub struct Action {
    code: u64,
    name: &'static str,
}
#[derive(Clone, Serialize)]
pub struct Scope {
    code: u64,
    kind: &'static str,
    id: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    max_bytes: u64,
    max_objects: u64,
    max_connections: u64,
    max_concurrent_operations: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validity {
    not_before_ms: u64,
    expires_ms: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    record: Reference,
    enrolment: &'static str,
    public_reading: bool,
    minimum_route: &'static str,
    allowed_relay_domains: Vec<String>,
    allowed_publication_modes: Vec<&'static str>,
    default_publication_mode: &'static str,
    recovery_policy: Reference,
    limits: Limits,
    manual_review_default: bool,
    policy_authority: Vec<Reference>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tier {
    record: Reference,
    rank: u64,
    label: String,
    allowed_actions: Vec<Action>,
    scopes: Vec<Scope>,
    maximum_delegation_depth: u64,
    limits: Limits,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    record: Reference,
    issuer: String,
    subject: String,
    tier: Reference,
    actions: Vec<Action>,
    scopes: Vec<Scope>,
    validity: Validity,
    parent_grant: Option<Reference>,
    remaining_delegation_depth: u64,
    limits: Limits,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKey {
    principal: String,
    signing_key: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryPolicy {
    record: Reference,
    custody: &'static str,
    threshold: u64,
    principals: Vec<String>,
    keys: Vec<RecoveryKey>,
    immutable_shared: bool,
    accepted_by: Vec<String>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    pub record_digest: String,
    generation: u64,
    predecessor: Option<String>,
    expected_snapshot: Option<String>,
    network_policy: NetworkPolicy,
    tiers: Vec<Tier>,
    root_grants: Vec<Grant>,
    recovery_policy: RecoveryPolicy,
}

fn label(kind: u64) -> Result<&'static str> {
    Ok(match kind {
        100 => "NetworkPolicy",
        101 => "TierPolicy",
        102 => "Grant",
        114 => "RecoveryPolicy",
        _ => anyhow::bail!("unknown governance record"),
    })
}
fn identifier(value: &Value) -> Result<String> {
    Ok(hex::encode(value.fixed::<32>()?))
}
fn identifiers(value: &Value) -> Result<Vec<String>> {
    value.list(16)?.iter().map(identifier).collect()
}
fn reference(value: &Value) -> Result<Reference> {
    let record = value.array(4)?;
    Ok(Reference {
        kind: record[0].uint()?,
        record_type: label(record[0].uint()?)?,
        id: identifier(&record[1])?,
        generation: record[2].uint()?,
        digest: identifier(&record[3])?,
    })
}
fn own_reference(bytes: &[u8], record: &[Value]) -> Result<Reference> {
    let kind = record[0].uint()?;
    Ok(Reference {
        kind,
        record_type: label(kind)?,
        id: identifier(&record[if kind == 100 || kind == 114 { 2 } else { 6 }])?,
        generation: record[4].uint()?,
        digest: hex::encode(wire::digest(bytes)),
    })
}
fn limits(value: &Value) -> Result<Limits> {
    let list = value.array(4)?;
    Ok(Limits {
        max_bytes: list[0].uint()?,
        max_objects: list[1].uint()?,
        max_connections: list[2].uint()?,
        max_concurrent_operations: list[3].uint()?,
    })
}
fn actions(value: &Value) -> Result<Vec<Action>> {
    const NAMES: [&str; 32] = [
        "ReadPage",
        "SearchCatalogue",
        "PublishPage",
        "ReviewPage",
        "SharePublication",
        "HostPages",
        "RelayTransit",
        "IndexPages",
        "VoteAuthority",
        "AdministerPolicy",
        "AdmitMember",
        "DelegateGrant",
        "RevokeGrant",
        "RegisterService",
        "StoreMail",
        "SendMail",
        "ReadMail",
        "StoreTransfer",
        "SendTransfer",
        "ReadTransfer",
        "OpenSshSession",
        "AdministerPlacement",
        "AcceptFederation",
        "RegisterRecipientDevice",
        "ApproveRecipientRecovery",
        "InspectAudit",
        "ManageLocalRuntime",
        "AcceptRecoveryPolicy",
        "ApproveNetworkRecovery",
        "ReviewSealedPage",
        "FinaliseSealedPage",
        "RevealPublicMetadata",
    ];
    value
        .list(32)?
        .iter()
        .map(|value| {
            let code = value.uint()?;
            let name = NAMES
                .get(usize::try_from(code)?)
                .ok_or_else(|| anyhow::anyhow!("unknown action code"))?;
            Ok(Action { code, name })
        })
        .collect()
}
fn scopes(value: &Value) -> Result<Vec<Scope>> {
    const NAMES: [&str; 6] = [
        "Network",
        "Namespace",
        "Object",
        "Service",
        "Member",
        "Deployment",
    ];
    value
        .list(64)?
        .iter()
        .map(|value| {
            let pair = value.array(2)?;
            let code = pair[0].uint()?;
            let kind = NAMES
                .get(usize::try_from(code)?)
                .ok_or_else(|| anyhow::anyhow!("unknown scope kind"))?;
            Ok(Scope {
                code,
                kind,
                id: identifier(&pair[1])?,
            })
        })
        .collect()
}
fn mode(value: &Value) -> Result<&'static str> {
    Ok(match value.uint()? {
        0 => "HostReadable",
        1 => "Sealed",
        _ => anyhow::bail!("unknown publication mode"),
    })
}

type Records = BTreeMap<(u64, [u8; 32]), (Vec<u8>, Value)>;
pub fn describe(records: &Records, network: &[u8; 32], governance: &[u8]) -> Result<Genesis> {
    let get = |kind, id| {
        records
            .get(&(kind, id))
            .ok_or_else(|| anyhow::anyhow!("missing inspected governance record"))
    };
    let (policy_bytes, policy_value) = get(100, *network)?;
    let policy = policy_value.array(17)?;
    let mut policy_authority = Vec::new();
    for id in policy[15].list(16)? {
        let (bytes, value) = get(102, id.fixed::<32>()?)?;
        policy_authority.push(own_reference(bytes, value.array(17)?)?);
    }
    let network_policy = NetworkPolicy {
        record: own_reference(policy_bytes, policy)?,
        enrolment: if policy[6].uint()? == 0 {
            "InvitationOnly"
        } else {
            "ApprovedApplications"
        },
        public_reading: policy[7].boolean()?,
        minimum_route: if policy[8].uint()? == 0 {
            "Organisational"
        } else {
            "Independent"
        },
        allowed_relay_domains: identifiers(&policy[9])?,
        allowed_publication_modes: policy[10]
            .list(2)?
            .iter()
            .map(mode)
            .collect::<Result<_>>()?,
        default_publication_mode: mode(&policy[11])?,
        recovery_policy: reference(&policy[12])?,
        limits: limits(&policy[13])?,
        manual_review_default: policy[14].boolean()?,
        policy_authority,
    };
    let mut tiers = Vec::new();
    let mut root_grants = Vec::new();
    for ((kind, _), (bytes, value)) in records {
        if *kind == 101 {
            let record = value.array(14)?;
            tiers.push(Tier {
                record: own_reference(bytes, record)?,
                rank: record[7].uint()?,
                label: record[8].text()?.into(),
                allowed_actions: actions(&record[9])?,
                scopes: scopes(&record[10])?,
                maximum_delegation_depth: record[11].uint()?,
                limits: limits(&record[12])?,
            });
        } else if *kind == 102 {
            let record = value.array(17)?;
            let validity = record[12].array(2)?;
            record[13].null()?;
            root_grants.push(Grant {
                record: own_reference(bytes, record)?,
                issuer: identifier(&record[7])?,
                subject: identifier(&record[8])?,
                tier: reference(&record[9])?,
                actions: actions(&record[10])?,
                scopes: scopes(&record[11])?,
                validity: Validity {
                    not_before_ms: validity[0].uint()?,
                    expires_ms: validity[1].uint()?,
                },
                parent_grant: None,
                remaining_delegation_depth: record[14].uint()?,
                limits: limits(&record[15])?,
            });
        }
    }
    let (recovery_bytes, recovery_value) = get(114, *network)?;
    let recovery = recovery_value.array(13)?;
    let recovery_policy = RecoveryPolicy {
        record: own_reference(recovery_bytes, recovery)?,
        custody: match recovery[6].uint()? {
            0 => "OwnerSingle",
            1 => "OwnerThreshold",
            2 => "SharedThreshold",
            _ => anyhow::bail!("invalid custody"),
        },
        threshold: recovery[7].uint()?,
        principals: identifiers(&recovery[8])?,
        keys: recovery[9]
            .list(3)?
            .iter()
            .map(|value| {
                let pair = value.array(2)?;
                Ok(RecoveryKey {
                    principal: identifier(&pair[0])?,
                    signing_key: identifier(&pair[1])?,
                })
            })
            .collect::<Result<_>>()?,
        immutable_shared: recovery[10].boolean()?,
        accepted_by: identifiers(&recovery[11])?,
    };
    ensure!(
        tiers.len() <= 16 && root_grants.len() <= 16,
        "governance summary exceeds record bound"
    );
    Ok(Genesis {
        record_digest: hex::encode(wire::digest(governance)),
        generation: 1,
        predecessor: None,
        expected_snapshot: None,
        network_policy,
        tiers,
        root_grants,
        recovery_policy,
    })
}
