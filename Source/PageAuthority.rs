// SPDX-License-Identifier: MIT
use crate::{
    authority, host, markup,
    protocol::{self, VerifiedRequest},
    types::*,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_BUNDLE: usize = 56 * 1024;
const MAX_SUBMISSION: usize = 48 * 1024;
const MAX_APPROVAL: usize = 4 * 1024;
const MAX_QUARANTINE: u64 = 4 * 1024 * 1024;
const MAX_PUBLISHED: u64 = 8 * 1024 * 1024;
const PROFILE: &str = "HyperNetPage/1";

pub struct Change {
    pub reply: Reply,
    pub puts: Vec<(String, Vec<u8>)>,
    pub deletes: Vec<String>,
}

pub fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::PageSubmit { .. }
            | Command::PageQueue { .. }
            | Command::PageInspect { .. }
            | Command::PageReview { .. }
            | Command::PageWithdraw { .. }
            | Command::PageList { .. }
            | Command::PageRead { .. }
            | Command::PageSync { .. }
            | Command::PageReplicaRequest { .. }
            | Command::PageReplicaResult { .. }
            | Command::ReplicaDeliver { .. }
    )
}

pub(crate) fn client(state: &State, key: &str, now: u64) -> Result<(), &'static str> {
    authority::require(state, key, MEMBER, now)?;
    let member = state.members.get(key).ok_or("NotMember")?;
    if state.consents.contains_key(key)
        || state.bridge_consents.contains_key(key)
        || member.grants & FEDERATION != 0
        || (member.grants & HOST != 0 && member.grants & ADMIN == 0)
    {
        return Err("SeparateClientIdentityRequired");
    }
    Ok(())
}

fn host_scope(
    state: &State,
    key: &str,
    profile: &str,
    now: u64,
) -> Result<host::Consent, &'static str> {
    authority::require(state, key, MEMBER | HOST, now)?;
    if state.members.get(key).ok_or("NotMember")?.grants & ADMIN != 0 {
        return Err("SeparateHostIdentityRequired");
    }
    let registered = state.consents.get(key).ok_or("ConsentRequired")?;
    if !registered.active
        || registered.expires <= now
        || registered.profile != profile
        || registered.grants != HOST
    {
        return Err("ConsentRequired");
    }
    let document = registered.document.as_ref().ok_or("PagesConsentRequired")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(document)
        .map_err(|_| "InvalidConsent")?;
    if hex::encode(Sha256::digest(&bytes)) != profile {
        return Err("InvalidConsent");
    }
    let consent =
        host::verify_consent(&bytes, &state.network, key, now).map_err(|_| "InvalidConsent")?;
    if consent.version != 2
        || !consent
            .services
            .as_ref()
            .is_some_and(|services| services.len() == 1 && services[0] == "Pages")
        || consent.grants != registered.grants
        || consent.expires != registered.expires
    {
        return Err("PagesConsentRequired");
    }
    Ok(consent)
}

fn scope_contains(scope: &host::Consent, namespace: &str) -> bool {
    scope
        .namespaces
        .as_ref()
        .is_some_and(|namespaces| namespaces.iter().any(|entry| entry == namespace))
}

pub(crate) fn published<'a>(
    state: &'a State,
    page_id: &str,
    now: u64,
) -> Result<&'a PublishedPage, &'static str> {
    let publication = state
        .pages
        .get(page_id)
        .and_then(|record| record.published.as_ref())
        .ok_or("PageUnavailable")?;
    authority::require(state, &publication.descriptor.author, MEMBER, now)
        .map_err(|_| "PageUnavailable")?;
    authority::require(state, &publication.descriptor.reviewer, MEMBER | ADMIN, now)
        .map_err(|_| "PageUnavailable")?;
    Ok(publication)
}

fn inspectable(state: &State, page_id: &str, key: &str, now: u64) -> Result<(), &'static str> {
    let page = state.pages.get(page_id).ok_or("PageUnavailable")?;
    if page.author != key {
        authority::require(state, key, ADMIN, now)?;
    }
    Ok(())
}

pub fn preflight(
    state: &State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
) -> Result<(), &'static str> {
    if !(1..=3).contains(&state.version) {
        return Err("UnsupportedState");
    }
    if state.high_water_time > now.saturating_add(2) {
        return Err("ClockRollback");
    }
    match &request.request.command {
        Command::PageSync { profile, .. } | Command::ReplicaDeliver { profile, .. } => {
            // Shared host checks precede retrieval of any page bytes.
            let _ = host_scope(state, &request.key, profile, now)?;
            let registered = state.consents.get(&request.key).ok_or("ConsentRequired")?;
            if certificate != Some(registered.certificate.as_str()) {
                return Err("ClientCertificateRequired");
            }
            if let Command::PageSync {
                known_inventory,
                fetch,
                ..
            } = &request.request.command
            {
                if let Some(token) = known_inventory {
                    protocol::fixed_hex::<32>(token)?;
                }
                if let Some(page_id) = fetch {
                    protocol::fixed_hex::<16>(page_id)?;
                }
            }
            Ok(())
        }
        command => {
            client(state, &request.key, now)?;
            match command {
                Command::PageInspect { page_id } => inspectable(state, page_id, &request.key, now),
                Command::PageReview { .. } => authority::require(state, &request.key, ADMIN, now),
                Command::PageWithdraw { page_id, .. } => {
                    inspectable(state, page_id, &request.key, now)
                }
                Command::PageRead { page_id } | Command::PageReplicaRequest { page_id, .. } => {
                    published(state, page_id, now).map(|_| ())
                }
                Command::PageReplicaResult { ticket_id } => {
                    let ticket = state
                        .replica_tickets
                        .get(ticket_id)
                        .ok_or("ReplicaUnavailable")?;
                    if ticket.reader != request.key {
                        return Err("ReplicaUnavailable");
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }
}

fn quarantine_key(page_id: &str, revision: u64) -> String {
    format!("Quarantine/{page_id}/{revision}")
}
pub(crate) fn publication_key(descriptor: &PageDescriptor) -> String {
    format!(
        "Published/{}/{}",
        descriptor.page_id, descriptor.publication_version
    )
}
fn delivery_key(ticket_id: &str) -> String {
    format!("Delivery/{ticket_id}")
}

pub fn required_blobs(
    state: &State,
    request: &VerifiedRequest,
    now: u64,
) -> Result<Vec<String>, &'static str> {
    if state
        .receipts
        .contains_key(&format!("{}:{}", request.key, request.request.request_id))
    {
        return Ok(Vec::new());
    }
    let key = match &request.request.command {
        Command::PageInspect { page_id } | Command::PageReview { page_id, .. } => state
            .pages
            .get(page_id)
            .and_then(|page| page.pending.as_ref())
            .map(|pending| quarantine_key(page_id, pending.revision)),
        Command::PageRead { page_id } => {
            Some(publication_key(&published(state, page_id, now)?.descriptor))
        }
        Command::PageSync {
            profile,
            fetch: Some(page_id),
            ..
        } => {
            let scope = host_scope(state, &request.key, profile, now)?;
            published(state, page_id, now)
                .ok()
                .filter(|page| scope_contains(&scope, &page.descriptor.namespace))
                .map(|page| publication_key(&page.descriptor))
        }
        Command::PageReplicaResult { ticket_id } => state
            .replica_tickets
            .get(ticket_id)
            .filter(|ticket| ticket.delivered)
            .map(|_| delivery_key(ticket_id)),
        _ => None,
    };
    Ok(key.into_iter().collect())
}

fn encoded<T: serde::Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "InvalidPage")?;
    if bytes.len() > maximum {
        return Err("PageTooLarge");
    }
    Ok(bytes)
}

fn decode_blob<T: serde::de::DeserializeOwned>(
    blobs: &BTreeMap<String, Vec<u8>>,
    key: &str,
) -> Result<T, &'static str> {
    let bytes = blobs.get(key).ok_or("PageUnavailable")?;
    if bytes.len() > MAX_BUNDLE {
        return Err("InvalidPage");
    }
    serde_json::from_slice(bytes).map_err(|_| "InvalidPage")
}

pub fn verify_bundle(
    network: &str,
    descriptor: &PageDescriptor,
    bundle: &PageBundle,
) -> Result<String, &'static str> {
    encoded(bundle, MAX_BUNDLE)?;
    encoded(&bundle.submission, MAX_SUBMISSION)?;
    encoded(&bundle.approval, MAX_APPROVAL)?;
    let submission = protocol::verify_archived(&bundle.submission, network)?;
    let approval = protocol::verify_archived(&bundle.approval, network)?;
    if submission.key != descriptor.author
        || approval.key != descriptor.reviewer
        || submission.digest != descriptor.submission_digest
        || approval.digest != descriptor.approval_digest
    {
        return Err("InvalidPageProof");
    }
    let Command::PageSubmit {
        page_id,
        expected_version,
        namespace,
        audience,
        profile,
        digest,
        body,
    } = &submission.request.command
    else {
        return Err("InvalidPageProof");
    };
    validate_content(page_id, namespace, audience, profile, digest, body)?;
    if page_id != &descriptor.page_id
        || namespace != &descriptor.namespace
        || audience != &descriptor.audience
        || profile != &descriptor.profile
        || digest != &descriptor.digest
        || expected_version.checked_add(1) != Some(descriptor.revision)
    {
        return Err("InvalidPageProof");
    }
    let Command::PageReview {
        page_id,
        expected_version,
        revision,
        digest,
        profile,
        author,
        namespace,
        audience,
        submission_digest,
        decision,
    } = &approval.request.command
    else {
        return Err("InvalidPageProof");
    };
    if decision != "Approve"
        || page_id != &descriptor.page_id
        || *revision != descriptor.revision
        || digest != &descriptor.digest
        || profile != &descriptor.profile
        || author != &descriptor.author
        || namespace != &descriptor.namespace
        || audience != &descriptor.audience
        || submission_digest != &descriptor.submission_digest
        || expected_version.checked_add(1) != Some(descriptor.publication_version)
        || *expected_version < *revision
    {
        return Err("InvalidPageProof");
    }
    Ok(body.clone())
}

pub fn inventory_digest(entries: &[PageDescriptor]) -> Result<String, &'static str> {
    let mut bytes = b"HyperNet/Inventory/1\0".to_vec();
    bytes.extend_from_slice(&encoded(&entries, 200 * 1024)?);
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_content(
    page_id: &str,
    namespace: &str,
    audience: &str,
    profile: &str,
    digest: &str,
    body: &str,
) -> Result<(), &'static str> {
    protocol::fixed_hex::<16>(page_id)?;
    protocol::fixed_hex::<32>(digest)?;
    if !host::valid_namespace(namespace) || audience != "Members" || profile != PROFILE {
        return Err("UnsupportedPageProfile");
    }
    if body.len() > 16 * 1024 {
        return Err("PageTooLarge");
    }
    markup::validate(body)?;
    if hex::encode(Sha256::digest(body.as_bytes())) != digest {
        return Err("PageDigestMismatch");
    }
    Ok(())
}

fn until(state: &State, key: &str, descriptor: Option<&PageDescriptor>, now: u64) -> u64 {
    let mut deadline = now
        .saturating_add(5)
        .min(state.members.get(key).map_or(now, |member| member.expires));
    if let Some(descriptor) = descriptor {
        for signer in [&descriptor.author, &descriptor.reviewer] {
            deadline = deadline.min(
                state
                    .members
                    .get(signer)
                    .map_or(now, |member| member.expires),
            );
        }
    }
    deadline
}

fn ticket_valid(state: &State, record: &TicketRecord, now: u64) -> Result<(), &'static str> {
    if record.ticket.expires <= now {
        return Err("ReplicaUnavailable");
    }
    client(state, &record.reader, now).map_err(|_| "ReplicaUnavailable")?;
    let scope = host_scope(state, &record.host, &record.host_profile, now)
        .map_err(|_| "ReplicaUnavailable")?;
    let publication = published(state, &record.ticket.descriptor.page_id, now)?;
    if publication.descriptor != record.ticket.descriptor
        || !scope_contains(&scope, &publication.descriptor.namespace)
    {
        return Err("ReplicaUnavailable");
    }
    Ok(())
}

fn list_filter(namespace: &Option<String>, after: &Option<String>) -> Result<(), &'static str> {
    if namespace
        .as_ref()
        .is_some_and(|value| !host::valid_namespace(value))
    {
        return Err("InvalidNamespace");
    }
    if let Some(after) = after {
        protocol::fixed_hex::<16>(after)?;
    }
    Ok(())
}

pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
    blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<Change, &'static str> {
    preflight(state, request, certificate, now)?;
    let receipt_key = format!("{}:{}", request.key, request.request.request_id);
    if let Some(receipt) = state.receipts.get(&receipt_key) {
        if receipt.digest != request.digest {
            return Err("RequestConflict");
        }
        state.high_water_time = state.high_water_time.max(now);
        return Ok(Change {
            reply: receipt.reply.clone(),
            puts: Vec::new(),
            deletes: Vec::new(),
        });
    }
    let read_only = matches!(
        request.request.command,
        Command::PageQueue { .. }
            | Command::PageInspect { .. }
            | Command::PageList { .. }
            | Command::PageRead { .. }
            | Command::PageSync { .. }
            | Command::PageReplicaResult { .. }
    );
    state.receipts.retain(|_, receipt| receipt.expires >= now);
    if !read_only {
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let mut puts = Vec::new();
    let mut deletes = Vec::new();
    state.replica_tickets.retain(|key, record| {
        if record.ticket.expires <= now {
            if record.delivered {
                deletes.push(delivery_key(key));
            }
            false
        } else {
            true
        }
    });
    let mut policy_changed = false;
    let result = match &request.request.command {
        Command::PageSubmit {
            page_id,
            expected_version,
            namespace,
            audience,
            profile,
            digest,
            body,
        } => {
            validate_content(page_id, namespace, audience, profile, digest, body)?;
            let bytes = encoded(&request.envelope, MAX_SUBMISSION)?;
            let existing = state.pages.get(page_id);
            if existing
                .is_some_and(|page| page.author != request.key || page.namespace != *namespace)
            {
                return Err("PageOwnerMismatch");
            }
            if existing.map_or(0, |page| page.version) != *expected_version {
                return Err("PageVersionConflict");
            }
            if existing.is_none()
                && (state.pages.len() >= 256
                    || state
                        .pages
                        .values()
                        .filter(|page| page.author == request.key)
                        .count()
                        >= 16)
            {
                return Err("PageQuotaExceeded");
            }
            let old_pending = existing.and_then(|page| page.pending.as_ref());
            if old_pending.is_none()
                && state
                    .pages
                    .values()
                    .filter(|page| page.author == request.key && page.pending.is_some())
                    .count()
                    >= 4
            {
                return Err("PageQuotaExceeded");
            }
            let used: u64 = state
                .pages
                .values()
                .filter_map(|page| page.pending.as_ref())
                .map(|pending| pending.bytes)
                .sum();
            if used - old_pending.map_or(0, |pending| pending.bytes) + bytes.len() as u64
                > MAX_QUARANTINE
            {
                return Err("PageQuotaExceeded");
            }
            if let Some(old) = old_pending {
                deletes.push(quarantine_key(page_id, old.revision));
            }
            let version = expected_version.checked_add(1).ok_or("CapacityExceeded")?;
            let page = state.pages.entry(page_id.clone()).or_insert(PageRecord {
                version: 0,
                author: request.key.clone(),
                namespace: namespace.clone(),
                pending: None,
                published: None,
            });
            page.version = version;
            page.pending = Some(PendingPage {
                revision: version,
                digest: digest.clone(),
                profile: profile.clone(),
                audience: audience.clone(),
                submission_digest: request.digest.clone(),
                bytes: bytes.len() as u64,
            });
            puts.push((quarantine_key(page_id, version), bytes));
            policy_changed = true;
            json!({"pageId":page_id,"version":version,"revision":version,"digest":digest,"submissionDigest":request.digest,"state":"Pending"})
        }
        Command::PageQueue { namespace, after } => {
            list_filter(namespace, after)?;
            let admin = authority::require(state, &request.key, ADMIN, now).is_ok();
            let mut entries = Vec::new();
            let mut next = None;
            for (page_id, page) in &state.pages {
                let Some(pending) = &page.pending else {
                    continue;
                };
                if (!admin && page.author != request.key)
                    || namespace
                        .as_ref()
                        .is_some_and(|value| value != &page.namespace)
                    || after.as_ref().is_some_and(|value| page_id <= value)
                {
                    continue;
                }
                if entries.len() == 32 {
                    next = entries
                        .last()
                        .and_then(|entry: &Value| entry["pageId"].as_str())
                        .map(str::to_string);
                    break;
                }
                entries.push(json!({"pageId":page_id,"version":page.version,"author":page.author,"namespace":page.namespace,"revision":pending.revision,"digest":pending.digest,"profile":pending.profile,"audience":pending.audience,"submissionDigest":pending.submission_digest}));
            }
            json!({"entries":entries,"next":next,"authorityRevision":revision})
        }
        Command::PageInspect { page_id } => {
            let page = state.pages.get(page_id).ok_or("PageUnavailable")?;
            let pending = if let Some(pending) = &page.pending {
                let submission: Envelope =
                    decode_blob(blobs, &quarantine_key(page_id, pending.revision))?;
                let verified = protocol::verify_archived(&submission, &state.network)?;
                if verified.digest != pending.submission_digest || verified.key != page.author {
                    return Err("InvalidPageProof");
                }
                Some(
                    json!({"revision":pending.revision,"digest":pending.digest,"profile":pending.profile,"audience":pending.audience,"submissionDigest":pending.submission_digest,"submission":submission}),
                )
            } else {
                None
            };
            json!({"pageId":page_id,"version":page.version,"author":page.author,"namespace":page.namespace,"pending":pending,"published":page.published.as_ref().map(|page| &page.descriptor)})
        }
        Command::PageReview {
            page_id,
            expected_version,
            revision: content_revision,
            digest,
            profile,
            author,
            namespace,
            audience,
            submission_digest,
            decision,
        } => {
            if decision != "Approve" && decision != "Reject" {
                return Err("InvalidReviewDecision");
            }
            encoded(&request.envelope, MAX_APPROVAL)?;
            let page = state.pages.get(page_id).ok_or("PageUnavailable")?;
            let pending = page.pending.as_ref().ok_or("PageUnavailable")?;
            if page.version != *expected_version {
                return Err("PageVersionConflict");
            }
            if page.author != *author
                || page.namespace != *namespace
                || pending.revision != *content_revision
                || pending.digest != *digest
                || pending.profile != *profile
                || pending.audience != *audience
                || pending.submission_digest != *submission_digest
            {
                return Err("ReviewObjectMismatch");
            }
            let version = expected_version.checked_add(1).ok_or("CapacityExceeded")?;
            let publication = if decision == "Approve" {
                authority::require(state, author, MEMBER, now)?;
                let submission = decode_blob(blobs, &quarantine_key(page_id, pending.revision))?;
                let bundle = PageBundle {
                    submission,
                    approval: request.envelope.clone(),
                };
                let descriptor = PageDescriptor {
                    page_id: page_id.clone(),
                    publication_version: version,
                    revision: *content_revision,
                    author: author.clone(),
                    reviewer: request.key.clone(),
                    namespace: namespace.clone(),
                    audience: audience.clone(),
                    profile: profile.clone(),
                    digest: digest.clone(),
                    submission_digest: submission_digest.clone(),
                    approval_digest: request.digest.clone(),
                };
                verify_bundle(&state.network, &descriptor, &bundle)?;
                let bytes = encoded(&bundle, MAX_BUNDLE)?;
                let used: u64 = state
                    .pages
                    .values()
                    .filter_map(|page| page.published.as_ref())
                    .map(|page| page.bytes)
                    .sum();
                if used - page.published.as_ref().map_or(0, |page| page.bytes) + bytes.len() as u64
                    > MAX_PUBLISHED
                {
                    return Err("PageQuotaExceeded");
                }
                if let Some(old) = &page.published {
                    deletes.push(publication_key(&old.descriptor));
                }
                puts.push((publication_key(&descriptor), bytes.clone()));
                Some(PublishedPage {
                    descriptor,
                    bytes: bytes.len() as u64,
                })
            } else {
                page.published.clone()
            };
            deletes.push(quarantine_key(page_id, pending.revision));
            let page = state.pages.get_mut(page_id).ok_or("PageUnavailable")?;
            page.version = version;
            page.pending = None;
            page.published = publication;
            policy_changed = true;
            json!({"pageId":page_id,"version":version,"decision":decision,"published":page.published.as_ref().map(|page| &page.descriptor)})
        }
        Command::PageWithdraw {
            page_id,
            expected_version,
        } => {
            let page = state.pages.get_mut(page_id).ok_or("PageUnavailable")?;
            if page.version != *expected_version {
                return Err("PageVersionConflict");
            }
            if let Some(pending) = &page.pending {
                deletes.push(quarantine_key(page_id, pending.revision));
            }
            if let Some(published) = &page.published {
                deletes.push(publication_key(&published.descriptor));
            }
            page.version = page.version.checked_add(1).ok_or("CapacityExceeded")?;
            page.pending = None;
            page.published = None;
            policy_changed = true;
            json!({"pageId":page_id,"version":page.version,"published":null})
        }
        Command::PageList { namespace, after } => {
            list_filter(namespace, after)?;
            let mut entries = Vec::new();
            let mut next = None;
            let mut deadline = until(state, &request.key, None, now);
            for page_id in state.pages.keys() {
                let Ok(page) = published(state, page_id, now) else {
                    continue;
                };
                if namespace
                    .as_ref()
                    .is_some_and(|value| value != &page.descriptor.namespace)
                    || after.as_ref().is_some_and(|value| page_id <= value)
                {
                    continue;
                }
                if entries.len() == 32 {
                    next = entries
                        .last()
                        .map(|entry: &PageDescriptor| entry.page_id.clone());
                    break;
                }
                deadline = deadline.min(until(state, &request.key, Some(&page.descriptor), now));
                entries.push(page.descriptor.clone());
            }
            json!({"entries":entries,"next":next,"authorityRevision":revision,"validUntil":deadline})
        }
        Command::PageRead { page_id } => {
            let descriptor = &published(state, page_id, now)?.descriptor;
            let bundle: PageBundle = decode_blob(blobs, &publication_key(descriptor))?;
            verify_bundle(&state.network, descriptor, &bundle)?;
            json!({"descriptor":descriptor,"bundle":bundle,"authorityRevision":revision,"validUntil":until(state,&request.key,Some(descriptor),now)})
        }
        Command::PageSync {
            profile,
            known_inventory,
            fetch,
        } => {
            let scope = host_scope(state, &request.key, profile, now)?;
            let mut entries = Vec::new();
            let mut deadline = until(state, &request.key, None, now).min(scope.expires);
            for page_id in state.pages.keys() {
                let Ok(page) = published(state, page_id, now) else {
                    continue;
                };
                if scope_contains(&scope, &page.descriptor.namespace) {
                    deadline =
                        deadline.min(until(state, &request.key, Some(&page.descriptor), now));
                    entries.push(page.descriptor.clone());
                }
            }
            let inventory_digest = inventory_digest(&entries)?;
            let bundle = if let Some(descriptor) = fetch
                .as_ref()
                .and_then(|page_id| entries.iter().find(|entry| entry.page_id == *page_id))
            {
                let bundle = decode_blob(blobs, &publication_key(descriptor))?;
                verify_bundle(&state.network, descriptor, &bundle)?;
                Some(bundle)
            } else {
                None
            };
            let requests = state
                .replica_tickets
                .values()
                .filter(|record| {
                    record.host == request.key
                        && !record.delivered
                        && ticket_valid(state, record, now).is_ok()
                })
                .map(|record| record.ticket.clone())
                .take(4)
                .collect();
            serde_json::to_value(PageSyncResult {
                profile: profile.clone(),
                authority_revision: revision as u64,
                valid_until: deadline,
                entries: if known_inventory.as_deref() == Some(&inventory_digest) {
                    None
                } else {
                    Some(entries)
                },
                inventory_digest,
                bundle,
                requests,
            })
            .map_err(|_| "InvalidPage")?
        }
        Command::PageReplicaRequest {
            page_id,
            replica_device_key,
            publication_version,
        } => {
            protocol::fixed_hex::<32>(replica_device_key)?;
            let descriptor = published(state, page_id, now)?.descriptor.clone();
            if descriptor.publication_version != *publication_version {
                return Err("PageVersionConflict");
            }
            let profile = state
                .consents
                .get(replica_device_key)
                .ok_or("ReplicaUnavailable")?
                .profile
                .clone();
            let scope = host_scope(state, replica_device_key, &profile, now)?;
            if !scope_contains(&scope, &descriptor.namespace) {
                return Err("ReplicaUnavailable");
            }
            if state.replica_tickets.len() >= 16
                || state
                    .replica_tickets
                    .values()
                    .filter(|record| record.reader == request.key)
                    .count()
                    >= 2
                || state
                    .replica_tickets
                    .values()
                    .filter(|record| record.host == *replica_device_key)
                    .count()
                    >= 4
            {
                return Err("ReplicaBusy");
            }
            let ticket = ReplicaTicket {
                ticket_id: request.digest.clone(),
                descriptor,
                expires: now.saturating_add(15),
            };
            state.replica_tickets.insert(
                ticket.ticket_id.clone(),
                TicketRecord {
                    ticket: ticket.clone(),
                    reader: request.key.clone(),
                    host: replica_device_key.clone(),
                    host_profile: profile,
                    delivered: false,
                },
            );
            serde_json::to_value(ticket).map_err(|_| "InvalidPage")?
        }
        Command::ReplicaDeliver {
            profile: _,
            ticket_id,
            bundle,
        } => {
            protocol::fixed_hex::<32>(ticket_id)?;
            let record = state
                .replica_tickets
                .get(ticket_id)
                .ok_or("ReplicaUnavailable")?;
            if record.host != request.key {
                return Err("ReplicaUnavailable");
            }
            ticket_valid(state, record, now)?;
            verify_bundle(&state.network, &record.ticket.descriptor, bundle)?;
            let bytes = encoded(bundle, MAX_BUNDLE)?;
            puts.push((delivery_key(ticket_id), bytes));
            state
                .replica_tickets
                .get_mut(ticket_id)
                .ok_or("ReplicaUnavailable")?
                .delivered = true;
            json!({"ticketId":ticket_id,"delivered":true})
        }
        Command::PageReplicaResult { ticket_id } => {
            let record = state
                .replica_tickets
                .get(ticket_id)
                .ok_or("ReplicaUnavailable")?;
            ticket_valid(state, record, now)?;
            if record.delivered {
                let bundle: PageBundle = decode_blob(blobs, &delivery_key(ticket_id))?;
                verify_bundle(&state.network, &record.ticket.descriptor, &bundle)?;
                json!({"state":"Ready","ticketId":ticket_id,"descriptor":record.ticket.descriptor,"bundle":bundle,"authorityRevision":revision,"validUntil":until(state,&request.key,Some(&record.ticket.descriptor),now).min(record.ticket.expires)})
            } else {
                json!({"state":"Pending","ticketId":ticket_id,"expires":record.ticket.expires})
            }
        }
        _ => return Err("UnsupportedCommand"),
    };
    if policy_changed {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }
    state.version = state.version.max(2);
    state.high_water_time = state.high_water_time.max(now);
    let reply = Reply::success(state.epoch, result);
    encoded(&reply, 256 * 1024)?;
    if !read_only {
        state.receipts.insert(
            receipt_key,
            Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(Change {
        reply,
        puts,
        deletes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn public(seed: u8) -> String {
        hex::encode(key(seed).verifying_key().to_bytes())
    }
    fn request(state: &State, signer: u8, nonce: u8, command: Command) -> VerifiedRequest {
        let request = Request {
            version: 1,
            request_id: hex::encode([nonce; 16]),
            issued_at: 100,
            command,
        };
        let payload = serde_json::to_vec(&request).unwrap();
        let signing = key(signer);
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&protocol::fixed_hex::<32>(&state.network).unwrap());
        message.extend_from_slice(signing.verifying_key().as_bytes());
        message.extend_from_slice(&payload);
        let envelope = Envelope {
            network: state.network.clone(),
            public_key: public(signer),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(signing.sign(&message).to_bytes()),
        };
        protocol::verify_archived(&envelope, &state.network).unwrap()
    }
    fn initial() -> (State, BTreeMap<String, Vec<u8>>) {
        let mut state = State::initial(hex::encode([9; 32]), public(1), 100);
        for signer in [2, 3, 4] {
            state.members.insert(
                public(signer),
                Member {
                    grants: MEMBER,
                    expires: 1000,
                    revoked: false,
                },
            );
        }
        (state, BTreeMap::new())
    }
    fn perform(
        state: &mut State,
        blobs: &mut BTreeMap<String, Vec<u8>>,
        request: &VerifiedRequest,
    ) -> Result<Reply, &'static str> {
        let mut candidate = state.clone();
        let change = apply(&mut candidate, request, None, 100, 20, blobs)?;
        for key in change.deletes {
            blobs.remove(&key);
        }
        for (key, value) in change.puts {
            blobs.insert(key, value);
        }
        *state = candidate;
        Ok(change.reply)
    }
    fn submit(
        state: &State,
        nonce: u8,
        page: u8,
        expected_version: u64,
        body: &str,
    ) -> VerifiedRequest {
        request(
            state,
            2,
            nonce,
            Command::PageSubmit {
                page_id: hex::encode([page; 16]),
                expected_version,
                namespace: "Board".into(),
                audience: "Members".into(),
                profile: PROFILE.into(),
                digest: hex::encode(Sha256::digest(body.as_bytes())),
                body: body.into(),
            },
        )
    }
    fn review(state: &State, nonce: u8, page: u8, decision: &str) -> VerifiedRequest {
        let page_id = hex::encode([page; 16]);
        let record = &state.pages[&page_id];
        let pending = record.pending.as_ref().unwrap();
        request(
            state,
            1,
            nonce,
            Command::PageReview {
                page_id,
                expected_version: record.version,
                revision: pending.revision,
                digest: pending.digest.clone(),
                profile: pending.profile.clone(),
                author: record.author.clone(),
                namespace: record.namespace.clone(),
                audience: pending.audience.clone(),
                submission_digest: pending.submission_digest.clone(),
                decision: decision.into(),
            },
        )
    }

    #[test]
    fn quarantine_publication_proofs_and_withdrawal_are_distinct() {
        let (mut state, mut blobs) = initial();
        let page_id = hex::encode([7; 16]);
        let body = "HyperNetPage/1\n# Notice\n: Reviewed text.\n";
        let submission = submit(&state, 1, 7, 0, body);
        perform(&mut state, &mut blobs, &submission).unwrap();
        let list = request(
            &state,
            3,
            2,
            Command::PageList {
                namespace: None,
                after: None,
            },
        );
        assert!(
            perform(&mut state, &mut blobs, &list).unwrap().result["entries"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let inspect = request(
            &state,
            3,
            3,
            Command::PageInspect {
                page_id: page_id.clone(),
            },
        );
        assert!(perform(&mut state, &mut blobs, &inspect).is_err());
        let approval = review(&state, 4, 7, "Approve");
        perform(&mut state, &mut blobs, &approval).unwrap();
        let read = request(
            &state,
            3,
            5,
            Command::PageRead {
                page_id: page_id.clone(),
            },
        );
        let reply = perform(&mut state, &mut blobs, &read).unwrap();
        let descriptor: PageDescriptor =
            serde_json::from_value(reply.result["descriptor"].clone()).unwrap();
        let bundle: PageBundle = serde_json::from_value(reply.result["bundle"].clone()).unwrap();
        assert_eq!(
            verify_bundle(&state.network, &descriptor, &bundle).unwrap(),
            body
        );
        let mut substituted = bundle.clone();
        substituted.submission.payload = URL_SAFE_NO_PAD.encode(b"{}");
        assert!(verify_bundle(&state.network, &descriptor, &substituted).is_err());
        let replacement = submit(
            &state,
            6,
            7,
            2,
            "HyperNetPage/1\n# Notice\n: Pending change.\n",
        );
        perform(&mut state, &mut blobs, &replacement).unwrap();
        assert_eq!(
            perform(&mut state, &mut blobs, &read).unwrap().result["descriptor"],
            reply.result["descriptor"]
        );
        let stale = request(&state, 1, 7, approval.request.command.clone());
        assert_eq!(
            perform(&mut state, &mut blobs, &stale).err(),
            Some("PageVersionConflict")
        );
        let reject = review(&state, 8, 7, "Reject");
        perform(&mut state, &mut blobs, &reject).unwrap();
        let withdrawal = request(
            &state,
            2,
            9,
            Command::PageWithdraw {
                page_id: page_id.clone(),
                expected_version: 4,
            },
        );
        perform(&mut state, &mut blobs, &withdrawal).unwrap();
        assert!(perform(&mut state, &mut blobs, &read).is_err());
        assert_eq!(state.pages[&page_id].version, 5);
        assert!(verify_bundle(&state.network, &descriptor, &bundle).is_ok());
        assert!(blobs.is_empty());
    }

    #[test]
    fn per_author_queue_limits_and_service_identity_cannot_be_bypassed() {
        let (mut state, mut blobs) = initial();
        for id in 1..=4 {
            let submission = submit(&state, id, id, 0, "HyperNetPage/1\n# Notice\n: Pending.\n");
            perform(&mut state, &mut blobs, &submission).unwrap();
        }
        let excess = submit(&state, 5, 5, 0, "HyperNetPage/1\n# Notice\n: Pending.\n");
        assert_eq!(
            perform(&mut state, &mut blobs, &excess).err(),
            Some("PageQuotaExceeded")
        );
        state.consents.insert(
            public(3),
            Consent {
                profile: hex::encode([1; 32]),
                grants: HOST,
                expires: 1000,
                certificate: hex::encode([2; 32]),
                active: false,
                document: None,
            },
        );
        let list = request(
            &state,
            3,
            6,
            Command::PageList {
                namespace: None,
                after: None,
            },
        );
        assert_eq!(
            perform(&mut state, &mut blobs, &list).err(),
            Some("SeparateClientIdentityRequired")
        );
        state.members.get_mut(&public(3)).unwrap().grants = ALL;
        assert_eq!(
            perform(&mut state, &mut blobs, &list).err(),
            Some("SeparateClientIdentityRequired")
        );
        assert_eq!(
            authority::require(&state, &public(3), ADMIN, 100).err(),
            Some("ServiceIdentity")
        );
    }
}
