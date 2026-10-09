// SPDX-License-Identifier: MIT
// Application identities delegate exact page operations without becoming members.
use crate::{
    authority, host, page_authority,
    protocol::{self, VerifiedRequest},
    types::*,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Failure = &'static str;
const MAX_DURATION: u64 = 7 * 24 * 60 * 60;
const MAX_LIST_REPLY: usize = 256 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApplicationRecord {
    pub owner_key: String,
    pub application_key: String,
    pub grant: Envelope,
    pub grant_digest: String,
    pub expires: u64,
    pub namespaces: Vec<String>,
    pub page_ids: Option<Vec<String>>,
    pub permissions: Vec<String>,
    pub review_policy_digest: Option<String>,
    pub review_mode: Option<String>,
    pub revoked: bool,
}

pub fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::ApplicationGrantCreate { .. }
            | Command::ApplicationGrantGet { .. }
            | Command::ApplicationGrantList { .. }
            | Command::ApplicationGrantRevoke { .. }
    )
}
pub fn admit(state: &State, request: &VerifiedRequest) -> Result<(), Failure> {
    if state.applications.contains_key(&request.key)
        && !matches!(
            request.request.command,
            Command::ApplicationGrantGet { .. }
                | Command::ApplicationGrantRevoke { .. }
                | Command::PageSubmit { .. }
                | Command::PageList { .. }
                | Command::PageRead { .. }
                | Command::PageQueue { .. }
                | Command::PageInspect { .. }
                | Command::PageReview { .. }
                | Command::PageWithdraw { .. }
                | Command::PageMediaReceipt { .. }
                | Command::PageMediaHosts
        )
    {
        return Err("ApplicationPermissionDenied");
    }
    Ok(())
}
fn fresh(request: &VerifiedRequest, now: u64) -> Result<(), Failure> {
    if request.request.issued_at > now.saturating_add(30)
        || request.request.issued_at.saturating_add(60) < now
    {
        return Err("StaleRequest");
    }
    Ok(())
}
fn sorted(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1])
}
fn review_scope(record: &ApplicationRecord) -> bool {
    record
        .permissions
        .iter()
        .any(|p| p.starts_with("Review") || p == "MediaInspect")
}
pub fn current<'a>(
    state: &'a State,
    key: &str,
    now: u64,
) -> Result<&'a ApplicationRecord, Failure> {
    let record = state
        .applications
        .get(key)
        .ok_or("ApplicationUnavailable")?;
    let now = now.max(state.high_water_time);
    if record.revoked || record.expires <= now {
        return Err("ApplicationPermissionDenied");
    }
    page_authority::client(state, &record.owner_key, now)?;
    if review_scope(record) {
        authority::require(state, &record.owner_key, MEMBER | ADMIN, now)?;
    }
    Ok(record)
}
pub fn permits(
    state: &State,
    key: &str,
    permission: &str,
    namespace: &str,
    page_id: Option<&str>,
    now: u64,
) -> Result<(), Failure> {
    let record = current(state, key, now)?;
    if !record.permissions.iter().any(|p| p == permission)
        || !record.namespaces.iter().any(|n| n == namespace)
        || page_id.is_some_and(|id| {
            record
                .page_ids
                .as_ref()
                .is_some_and(|ids| !ids.iter().any(|p| p == id))
        })
    {
        return Err("ApplicationPermissionDenied");
    }
    Ok(())
}
pub fn deadline(state: &State, key: &str, now: u64) -> u64 {
    if let Some(record) = state.applications.get(key) {
        record.expires.min(
            state
                .members
                .get(&record.owner_key)
                .map_or(now, |m| m.expires),
        )
    } else {
        state.members.get(key).map_or(now, |m| m.expires)
    }
}
fn value_references(value: &Value, key: &str) -> bool {
    match value {
        Value::String(s) => s == key,
        Value::Array(values) => values.iter().any(|v| value_references(v, key)),
        Value::Object(values) => values.values().any(|v| value_references(v, key)),
        _ => false,
    }
}
fn referenced(state: &State, key: &str, now: u64) -> bool {
    state.pages.values().any(|p| {
        p.author == key
            || p.published
                .as_ref()
                .is_some_and(|p| p.descriptor.reviewer == key)
    }) || state.replica_tickets.values().any(|r| {
        r.ticket.expires > now
            && (r.ticket.descriptor.author == key || r.ticket.descriptor.reviewer == key)
    }) || state.receipts.iter().any(|(id, r)| {
        r.expires >= now
            && (id.starts_with(&format!("{key}:")) || value_references(&r.reply.result, key))
    })
}
fn prune(state: &mut State, now: u64) {
    let remove: Vec<_> = state
        .applications
        .iter()
        .filter(|(key, r)| r.expires <= now && !referenced(state, key, now))
        .map(|(key, _)| key.clone())
        .collect();
    for key in remove {
        state.applications.remove(&key);
    }
}
fn role_conflict(state: &State, key: &str, now: u64) -> bool {
    crate::mail_authority::reserved_identity_conflict(state, key)
        || state
            .invitations
            .values()
            .any(|invite| !invite.redeemed && invite.expires > now && invite.device_key == key)
}

pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    now: u64,
    revision: i64,
) -> Result<Reply, Failure> {
    if state.version != crate::types::STATE_VERSION {
        return Err("UnsupportedState");
    }
    // Expired grants must not revive after their unreferenced records are reclaimed.
    if state.high_water_time > now {
        return Err("ClockRollback");
    }
    fresh(request, now)?;
    match &request.request.command {
        Command::ApplicationGrantCreate { .. } | Command::ApplicationGrantList { .. } => {
            page_authority::client(state, &request.key, now)?
        }
        Command::ApplicationGrantGet { application_key }
        | Command::ApplicationGrantRevoke { application_key } => {
            protocol::fixed_hex::<32>(application_key)?;
            let record = state
                .applications
                .get(application_key)
                .ok_or("ApplicationUnavailable")?;
            if request.key != record.owner_key && request.key != *application_key {
                return Err("ApplicationPermissionDenied");
            }
        }
        _ => return Err("UnsupportedCommand"),
    }
    let mutate = matches!(
        request.request.command,
        Command::ApplicationGrantCreate { .. } | Command::ApplicationGrantRevoke { .. }
    );
    let receipt_id = format!("{}:{}", request.key, request.request.request_id);
    if mutate {
        if let Some(receipt) = state.receipts.get(&receipt_id) {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            state.high_water_time = now;
            return Ok(receipt.reply.clone());
        }
        state.receipts.retain(|_, r| r.expires >= now);
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let result = match &request.request.command {
        Command::ApplicationGrantCreate { consent } => {
            let proof = protocol::verify_archived(consent, &state.network)?;
            fresh(&proof, now)?;
            let Command::ApplicationConsent {
                owner_key,
                expires,
                namespaces,
                page_ids,
                permissions,
                review_policy_digest,
                review_mode,
            } = &proof.request.command
            else {
                return Err("InvalidApplicationConsent");
            };
            if owner_key != &request.key || proof.key == request.key {
                return Err("InvalidApplicationConsent");
            }
            if *expires <= now
                || *expires > now.saturating_add(MAX_DURATION)
                || *expires > state.members[&request.key].expires
            {
                return Err("InvalidExpiry");
            }
            if !sorted(namespaces, 8)
                || namespaces.iter().any(|n| !host::valid_namespace(n))
                || !sorted(permissions, 7)
                || permissions.iter().any(|p| {
                    !matches!(
                        p.as_str(),
                        "PagesRead"
                            | "PagesSubmit"
                            | "ReviewInspect"
                            | "ReviewDecide"
                            | "MediaRead"
                            | "MediaSubmit"
                            | "MediaInspect"
                    )
                })
            {
                return Err("InvalidApplicationScope");
            }
            if let Some(ids) = page_ids {
                if !sorted(ids, 16) {
                    return Err("InvalidApplicationScope");
                }
                for id in ids {
                    protocol::fixed_hex::<16>(id)?;
                }
            }
            let deciding = permissions.iter().any(|p| p == "ReviewDecide");
            if deciding {
                if !permissions.iter().any(|p| p == "ReviewInspect")
                    || !matches!(review_mode.as_deref(), Some("Manual" | "Automatic"))
                {
                    return Err("InvalidApplicationScope");
                }
                protocol::fixed_hex::<32>(
                    review_policy_digest
                        .as_deref()
                        .ok_or("InvalidApplicationScope")?,
                )?;
            } else if review_policy_digest.is_some() || review_mode.is_some() {
                return Err("InvalidApplicationScope");
            }
            if permissions
                .iter()
                .any(|p| p.starts_with("Review") || p == "MediaInspect")
            {
                authority::require(state, &request.key, MEMBER | ADMIN, now)?;
            }
            prune(state, now);
            if role_conflict(state, &proof.key, now) {
                return Err("SeparateApplicationIdentityRequired");
            }
            if state.applications.len() >= 64
                || state
                    .applications
                    .values()
                    .filter(|r| r.owner_key == request.key)
                    .count()
                    >= 8
            {
                return Err("ApplicationQuotaExceeded");
            }
            let record = ApplicationRecord {
                owner_key: request.key.clone(),
                application_key: proof.key.clone(),
                grant: request.envelope.clone(),
                grant_digest: request.digest.clone(),
                expires: *expires,
                namespaces: namespaces.clone(),
                page_ids: page_ids.clone(),
                permissions: permissions.clone(),
                review_policy_digest: review_policy_digest.clone(),
                review_mode: review_mode.clone(),
                revoked: false,
            };
            state.applications.insert(proof.key, record.clone());
            json!({"application":record})
        }
        Command::ApplicationGrantGet { application_key } => {
            json!({"application":state.applications[application_key],"authorityRevision":revision})
        }
        Command::ApplicationGrantList { after } => {
            if let Some(after) = after {
                protocol::fixed_hex::<32>(after)?;
            }
            let mut records = state
                .applications
                .values()
                .filter(|r| {
                    r.owner_key == request.key
                        && after.as_ref().is_none_or(|a| r.application_key > *a)
                })
                .peekable();
            let mut entries: Vec<&ApplicationRecord> = Vec::new();
            let mut next = None;
            while let Some(record) = records.next() {
                entries.push(record);
                let candidate_next = records.peek().map(|_| record.application_key.clone());
                let candidate = Reply::success(
                    state.epoch,
                    json!({
                        "entries":entries,"next":candidate_next,"authorityRevision":revision
                    }),
                );
                if serde_json::to_vec(&candidate)
                    .map_err(|_| "InvalidApplicationRecord")?
                    .len()
                    > MAX_LIST_REPLY
                {
                    entries.pop();
                    // A single admitted envelope and its bounded scope fit this reply budget.
                    next = Some(
                        entries
                            .last()
                            .ok_or("ApplicationReplyTooLarge")?
                            .application_key
                            .clone(),
                    );
                    break;
                }
                next = candidate_next;
            }
            json!({"entries":entries,"next":next,"authorityRevision":revision})
        }
        Command::ApplicationGrantRevoke { application_key } => {
            state
                .applications
                .get_mut(application_key)
                .ok_or("ApplicationUnavailable")?
                .revoked = true;
            json!({"applicationKey":application_key,"revoked":true})
        }
        _ => return Err("UnsupportedCommand"),
    };
    if mutate {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }

    state.high_water_time = now;
    let reply = Reply::success(state.epoch, result);
    if mutate {
        state.receipts.insert(
            receipt_id,
            Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
}

#[cfg(test)]
#[path = "../Tests/ApplicationAuthority.rs"]
mod tests;
