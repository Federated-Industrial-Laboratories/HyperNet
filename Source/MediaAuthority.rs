// SPDX-License-Identifier: MIT
// Page references, current membership and independent media consent gate every byte.
use crate::{
    application_authority as applications, authority, host as page_host,
    mail_authority::{self, object_digest, sign, verify},
    markup,
    media_types::*,
    page_authority,
    protocol::{self, VerifiedRequest},
    types::{self, Command, Envelope, Reply, State},
};
use ed25519_dalek::SigningKey;
use serde_json::json;
type Failure = &'static str;

pub fn host_consent(object: &Envelope, network: &str) -> Result<HostConsent, Failure> {
    let value: HostConsent = verify(HOST, object, network)?;
    let mut common = serde_json::to_value(&value).map_err(|_| "MediaInvalidObject")?;
    common
        .as_object_mut()
        .ok_or("MediaInvalidObject")?
        .remove("namespaces");
    common
        .as_object_mut()
        .ok_or("MediaInvalidObject")?
        .remove("retentionSeconds");
    let common = serde_json::from_value(common).map_err(|_| "MediaInvalidObject")?;
    mail_authority::validate_host(&common, network, &object.public_key, "PageMedia")?;
    if value.namespaces.is_empty()
        || value.namespaces.len() > 16
        || value.namespaces.windows(2).any(|p| p[0] >= p[1])
        || value
            .namespaces
            .iter()
            .any(|n| !page_host::valid_namespace(n))
        || !(1..=MAX_LIFETIME).contains(&value.retention_seconds)
    {
        return Err("MediaInvalidConsent");
    }
    Ok(value)
}
pub fn host<'a>(state: &'a State, key: &str, now: u64) -> Result<&'a HostRecord, Failure> {
    authority::require(state, key, types::MEMBER | types::HOST, now)?;
    let host = state.media.hosts.get(key).ok_or("MediaUnavailable")?;
    if !host.active
        || host.body.expires <= now
        || state.members[key].grants != types::MEMBER | types::HOST
    {
        return Err("MediaConsentRequired");
    }
    Ok(host)
}
fn permission(
    state: &State,
    key: &str,
    right: &str,
    record: &AssetRecord,
    now: u64,
) -> Result<(), Failure> {
    if state.applications.contains_key(key) {
        applications::permits(
            state,
            key,
            right,
            &record.namespace,
            Some(&record.page_id),
            now,
        )
    } else {
        page_authority::client(state, key, now)?;
        if right == "MediaInspect" {
            authority::require(state, key, types::ADMIN, now)?;
        }
        Ok(())
    }
}
fn pending(state: &State, record: &AssetRecord, now: u64) -> bool {
    if let Some(id) = &record.agreement_id {
        return record.upload_expires > now
            && crate::federation_authority::foreign_current(state, id, &record.page_id, now)
                .is_ok_and(|(_, p, _)| {
                    p.pending
                        && p.observed.revision == record.revision
                        && p.observed.digest == record.source_digest
                });
    }
    record.upload_expires > now
        && state
            .pages
            .get(&record.page_id)
            .and_then(|p| p.pending.as_ref())
            .is_some_and(|p| p.revision == record.revision && p.digest == record.source_digest)
}
fn published(state: &State, record: &AssetRecord, now: u64) -> bool {
    if let Some(id) = &record.agreement_id {
        return crate::federation_authority::foreign_published(state, id, &record.page_id, now)
            .is_ok_and(|(_, p, _)| {
                p.observed.revision == record.revision && p.observed.digest == record.source_digest
            });
    }
    page_authority::published(state, &record.page_id, now).is_ok_and(|p| {
        p.descriptor.revision == record.revision && p.descriptor.digest == record.source_digest
    })
}
fn usable(state: &State, record: &AssetRecord, now: u64) -> bool {
    record.expires > now
        && (pending(state, record, now) || published(state, record, now))
        && (record.agreement_id.is_some()
            || permission(state, &record.author, "MediaSubmit", record, now).is_ok())
}
fn retained(state: &State, r: &AssetRecord, now: u64) -> bool {
    if let Some(id) = &r.agreement_id {
        return r.expires > now
            && state
                .federation_agreements
                .get(id)
                .is_some_and(|a| a.active && a.treaty.expires > now)
            && state
                .federation_pages
                .get(&format!("{id}/{}", r.page_id))
                .is_some_and(|p| {
                    p.observed.revision == r.revision
                        && p.observed.digest == r.source_digest
                        && ((p.pending && r.upload_expires > now)
                            || p.published
                                .as_ref()
                                .is_some_and(|v| v.descriptor == p.observed))
                });
    }
    usable(state, r, now)
}
pub fn prune(state: &mut State, now: u64) {
    let removed: Vec<_> = state
        .media
        .assets
        .iter()
        .filter(|(_, r)| !retained(state, r, now))
        .map(|(k, _)| k.clone())
        .collect();
    for key in removed {
        state.media.assets.remove(&key);
    }
}
#[allow(clippy::too_many_arguments)]
pub fn reserve(
    state: &mut State,
    request: &VerifiedRequest,
    now: u64,
    revision: u64,
    page_id: &str,
    namespace: &str,
    source_digest: &str,
    assets: &[markup::media::Asset],
) -> Result<(), Failure> {
    prune(state, now);
    let superseded: Vec<_> = state
        .media
        .assets
        .iter()
        .filter(|(_, r)| {
            r.agreement_id.is_none()
                && r.page_id == page_id
                && pending(state, r, now)
                && !published(state, r, now)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for key in superseded {
        state.media.assets.remove(&key);
    }
    if assets.is_empty() {
        return Ok(());
    }
    if state.media.assets.len().saturating_add(assets.len()) > 256 {
        return Err("MediaQuotaExceeded");
    }
    let active: Vec<_> = state
        .media
        .assets
        .values()
        .filter(|r| r.author == request.key && pending(state, r, now))
        .collect();
    if active.len().saturating_add(assets.len()) > 8
        || active.iter().map(|r| r.asset.bytes).sum::<u64>()
            + assets.iter().map(|a| a.bytes).sum::<u64>()
            > 8 * 1024 * 1024
    {
        return Err("MediaQuotaExceeded");
    }
    let mut reserved = std::collections::BTreeMap::<String, u64>::new();
    for r in state.media.assets.values() {
        for key in &r.storage_hosts {
            *reserved.entry(key.clone()).or_default() += r.asset.bytes + 4096;
        }
    }
    for asset in assets {
        if asset.copies < state.media.minimum_copies {
            return Err("MediaCopiesRequired");
        }
        let mut expires = now.saturating_add(MAX_LIFETIME);
        for key in &asset.hosts {
            let h = host(state, key, now)?;
            if !h.body.namespaces.iter().any(|n| n == namespace) {
                return Err("MediaNamespaceDenied");
            }
            let used = reserved.entry(key.clone()).or_default();
            *used = used
                .checked_add(asset.bytes + 4096)
                .ok_or("MediaQuotaExceeded")?;
            if *used > h.body.state_bytes / 4 - 65536 {
                return Err("MediaQuotaExceeded");
            }
            expires = expires
                .min(now.saturating_add(h.body.retention_seconds))
                .min(h.body.expires);
        }
        let record = AssetRecord {
            agreement_id: None,
            storage_hosts: asset.hosts.clone(),
            required_copies: asset.copies.max(state.media.minimum_copies),
            page_id: page_id.into(),
            revision,
            source_digest: source_digest.into(),
            author: request.key.clone(),
            namespace: namespace.into(),
            asset: asset.clone(),
            upload_expires: now.saturating_add(UPLOAD_LIFETIME).min(expires),
            expires,
            receipts: Default::default(),
            reviewed_by: Default::default(),
        };
        permission(state, &request.key, "MediaSubmit", &record, now)?;
        state
            .media
            .assets
            .insert(asset_key(None, page_id, revision, &asset.id), record);
    }
    Ok(())
}
pub fn approve(
    state: &State,
    page_id: &str,
    revision: u64,
    assets: &[markup::media::Asset],
    reviewer: &str,
    now: u64,
) -> Result<(), Failure> {
    for asset in assets {
        let record = state
            .media
            .assets
            .get(&asset_key(None, page_id, revision, &asset.id))
            .ok_or("MediaIncomplete")?;
        if !usable(state, record, now) || record.asset != *asset {
            return Err("MediaIncomplete");
        }
        permission(state, reviewer, "MediaInspect", record, now)?;
        if !record.reviewed_by.contains(reviewer) {
            return Err("MediaReviewRequired");
        }
        let copies = record
            .receipts
            .iter()
            .filter(|(k, e)| {
                host(state, k, now).is_ok_and(|h| {
                    verify::<StoreReceipt>(RECEIPT, e, &state.network).is_ok_and(|r| {
                        r.host_generation == h.body.generation
                            && r.status == "Complete"
                            && r.digest == asset.digest
                            && r.bytes == asset.bytes
                    })
                })
            })
            .count();
        if copies < asset.copies.max(state.media.minimum_copies) as usize {
            return Err("MediaIncomplete");
        }
    }
    Ok(())
}
pub fn read_only(command: &Command) -> bool {
    matches!(
        command,
        Command::PageMediaAuthorise { .. } | Command::PageMediaPolicySync { .. }
    )
}
pub fn handles(command: &Command) -> bool {
    read_only(command)
        || matches!(
            command,
            Command::PageMediaHostRegister { .. }
                | Command::PageMediaHostWithdraw { .. }
                | Command::PageMediaHosts
                | Command::PageMediaReceipt { .. }
                | Command::PageMediaPolicySet { .. }
        )
}
pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
    key: Option<&SigningKey>,
) -> Result<Reply, Failure> {
    crate::transfer_authority::check_state(state, now)?;
    let key = crate::transfer_authority::signing(state, key)?;
    match &request.request.command {
        Command::PageMediaHostRegister { .. } => {
            authority::require(state, &request.key, types::MEMBER | types::HOST, now)?
        }
        Command::PageMediaHostWithdraw { host_key, .. } => {
            if *host_key != request.key || !state.media.hosts.contains_key(host_key) {
                return Err("MediaPermissionDenied");
            }
        }
        Command::PageMediaReceipt { .. } => {}
        Command::PageMediaHosts if state.applications.contains_key(&request.key) => {
            let app = applications::current(state, &request.key, now)?;
            if !app
                .permissions
                .iter()
                .any(|p| matches!(p.as_str(), "MediaRead" | "MediaSubmit" | "MediaInspect"))
            {
                return Err("ApplicationPermissionDenied");
            }
        }
        _ => page_authority::client(state, &request.key, now)?,
    }
    prune(state, now);
    state.receipts.retain(|_, r| r.expires >= now);
    let receipt_id = format!("{}:{}", request.key, request.request.request_id);
    if !matches!(request.request.command, Command::PageMediaHosts) {
        if let Some(receipt) = state.receipts.get(&receipt_id) {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            return Ok(receipt.reply.clone());
        }
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let result = match &request.request.command {
        Command::PageMediaHostRegister { consent } => {
            let body = host_consent(consent, &state.network)?;
            crate::transfer_authority::expiry(body.expires, now)?;
            if body.host_key != request.key
                || state.members[&request.key].grants != types::MEMBER | types::HOST
                || state.consents.contains_key(&request.key)
                || state.bridge_consents.contains_key(&request.key)
                || state.mail.hosts.contains_key(&request.key)
                || state.transfers.hosts.contains_key(&request.key)
                || state.ssh.services.contains_key(&request.key)
                || certificate != Some(body.certificate_digest.as_str())
                || body.authority_signer != hex::encode(key.verifying_key().as_bytes())
                || body.expires > state.members[&request.key].expires
            {
                return Err("SeparateServiceIdentityRequired");
            }
            let next = state
                .media
                .hosts
                .get(&request.key)
                .map(|h| h.body.generation.checked_add(1).ok_or("CapacityExceeded"))
                .transpose()?
                .unwrap_or(1);
            if body.generation != next {
                return Err("MediaGenerationConflict");
            }
            if !state.media.hosts.contains_key(&request.key) && state.media.hosts.len() >= 16 {
                return Err("MediaQuotaExceeded");
            }
            let records: Vec<_> = state
                .media
                .assets
                .values()
                .filter(|r| r.storage_hosts.contains(&request.key))
                .collect();
            if records.iter().map(|r| r.asset.bytes + 4096).sum::<u64>()
                > body.state_bytes / 4 - 65536
                || records.iter().any(|r| {
                    !body.namespaces.contains(&r.namespace)
                        || r.expires > body.expires
                        || r.expires > now.saturating_add(body.retention_seconds)
                })
            {
                return Err("MediaQuotaExceeded");
            }
            let digest = object_digest(HOST, consent)?;
            state.media.hosts.insert(
                request.key.clone(),
                HostRecord {
                    consent: consent.clone(),
                    digest: digest.clone(),
                    body: body.clone(),
                    active: true,
                },
            );
            json!({"hostKey":body.host_key,"generation":body.generation,"consentDigest":digest})
        }
        Command::PageMediaHostWithdraw {
            host_key,
            expected_generation,
        } => {
            let h = state
                .media
                .hosts
                .get_mut(host_key)
                .ok_or("MediaUnavailable")?;
            if h.body.generation != *expected_generation {
                return Err("MediaGenerationConflict");
            }
            h.active = false;
            json!({"hostKey":host_key,"active":false})
        }
        Command::PageMediaHosts => {
            json!({"hosts":state.media.hosts.iter().filter(|(k,h)|host(state,k,now).is_ok() && state.applications.get(&request.key).is_none_or(|app|h.body.namespaces.iter().any(|n|app.namespaces.contains(n)))).map(|(_,h)|&h.consent).collect::<Vec<_>>(),"minimumCopies":state.media.minimum_copies,"authoritySigner":hex::encode(key.verifying_key().as_bytes()),"validUntil":now+5,"authorityRevision":revision})
        }
        Command::PageMediaPolicySet { minimum_copies } => {
            authority::require(state, &request.key, types::ADMIN, now)?;
            if !(1..=3).contains(minimum_copies) {
                return Err("MediaInvalidObject");
            }
            state.media.minimum_copies = *minimum_copies;
            json!({"minimumCopies":minimum_copies})
        }
        Command::PageMediaReceipt {
            agreement_id,
            page_id,
            revision,
            asset_id,
            receipt,
        } => {
            let r: StoreReceipt = verify(RECEIPT, receipt, &state.network)?;
            let h = host(state, &receipt.public_key, now)?;
            let id = asset_key(agreement_id.as_deref(), page_id, *revision, asset_id);
            let record = state.media.assets.get(&id).ok_or("MediaUnavailable")?;
            if !usable(state, record, now)
                || r.version != 1
                || r.network != state.network
                || r.host_key != receipt.public_key
                || r.host_generation != h.body.generation
                || r.page_id != *page_id
                || r.revision != *revision
                || r.asset_id != *asset_id
                || r.agreement_id != *agreement_id
                || r.source_digest != record.source_digest
                || r.digest != record.asset.digest
                || r.bytes != record.asset.bytes
                || r.stored_bytes != r.bytes
                || r.status != "Complete"
                || r.recorded_at > now.saturating_add(2)
                || !record.storage_hosts.contains(&r.host_key)
            {
                return Err("MediaInvalidReceipt");
            }
            let review = r.action == "Fetch"
                && r.requester_key == request.key
                && permission(state, &request.key, "MediaInspect", record, now).is_ok();
            let bridge = record.agreement_id.as_ref().is_some_and(|id| {
                bridge_permission(state, id, &request.key, &r.host_key, record, now).is_ok()
            });
            if !review
                && !bridge
                && (request.key != record.author
                    || permission(state, &request.key, "MediaSubmit", record, now).is_err())
            {
                return Err("MediaPermissionDenied");
            }
            let record = state.media.assets.get_mut(&id).ok_or("MediaUnavailable")?;
            record.receipts.insert(r.host_key, receipt.clone());
            if review {
                record.reviewed_by.insert(request.key.clone());
            }
            json!({"pageId":page_id,"revision":revision,"assetId":asset_id,"copies":record.receipts.len(),"reviewed":review})
        }
        _ => return Err("UnsupportedCommand"),
    };
    if !matches!(request.request.command, Command::PageMediaHosts) {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }
    state.high_water_time = state.high_water_time.max(now);
    let reply = Reply::success(state.epoch, result);
    if !matches!(request.request.command, Command::PageMediaHosts) {
        state.receipts.insert(
            receipt_id,
            types::Receipt {
                digest: request.digest.clone(),
                expires: now.saturating_add(300),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
}
pub fn operation(object: &Envelope, network: &str, now: u64) -> Result<Operation, Failure> {
    let op: Operation = verify(OPERATION, object, network)?;
    protocol::fixed_hex::<16>(&op.operation_id)?;
    protocol::fixed_hex::<16>(&op.page_id)?;
    if let Some(id) = &op.agreement_id {
        protocol::fixed_hex::<16>(id)?;
    }
    protocol::fixed_hex::<32>(&op.host_key)?;
    protocol::fixed_hex::<32>(&op.source_digest)?;
    if op.version != 1
        || op.network != network
        || op.revision == 0
        || op.asset_id.is_empty()
        || op.asset_id.len() > 32
        || !op
            .asset_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || op.issued_at > now.saturating_add(2)
        || op.issued_at.saturating_add(30) < now
    {
        return Err("MediaStaleOperation");
    }
    match op.action.as_str() {
        "Put" | "Fetch" => {
            if !(1..=CHUNK).contains(&op.chunk_bytes) || !op.offset.is_multiple_of(CHUNK) {
                return Err("MediaInvalidObject");
            }
            if op.action == "Put" {
                protocol::fixed_hex::<32>(op.chunk_digest.as_deref().ok_or("MediaInvalidObject")?)?;
            } else if op.chunk_digest.is_some() {
                return Err("MediaInvalidObject");
            }
        }
        "Status" | "Seal" => {
            if op.offset != 0 || op.chunk_bytes != 0 || op.chunk_digest.is_some() {
                return Err("MediaInvalidObject");
            }
        }
        _ => return Err("MediaInvalidObject"),
    }
    Ok(op)
}
pub fn authorise(
    state: &State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
    key: Option<&SigningKey>,
) -> Result<Reply, Failure> {
    crate::transfer_authority::check_state(state, now)?;
    let key = crate::transfer_authority::signing(state, key)?;
    let host_key = match &request.request.command {
        Command::PageMediaAuthorise { host_key, .. }
        | Command::PageMediaPolicySync { host_key } => host_key,
        _ => return Err("UnsupportedCommand"),
    };
    if *host_key != request.key {
        return Err("MediaPermissionDenied");
    }
    let h = host(state, host_key, now)?;
    if certificate != Some(h.body.certificate_digest.as_str()) {
        return Err("ClientCertificateRequired");
    }
    let expires = (now + 5)
        .min(h.body.expires)
        .min(state.members[host_key].expires);
    if let Command::PageMediaAuthorise {
        operation: object, ..
    } = &request.request.command
    {
        let op = operation(object, &state.network, now)?;
        let foreign = op.agreement_id.as_deref().filter(|id| {
            state
                .federation_agreements
                .get(*id)
                .is_some_and(|a| a.treaty.destination_network == state.network)
        });
        let record = state
            .media
            .assets
            .get(&asset_key(foreign, &op.page_id, op.revision, &op.asset_id))
            .ok_or("MediaUnavailable")?;
        if !usable(state, record, now)
            || op.host_key != *host_key
            || op.source_digest != record.source_digest
            || !record.storage_hosts.contains(host_key)
            || !h.body.namespaces.contains(&record.namespace)
        {
            return Err("MediaPermissionDenied");
        }
        let is_pending = pending(state, record, now);
        let mut scope_until = expires;
        let is_bridge = op.agreement_id.as_ref().is_some_and(|id| {
            bridge_permission(state, id, &object.public_key, host_key, record, now).is_ok()
        });
        if is_bridge {
            scope_until = scope_until.min(
                state
                    .bridge_consents
                    .get(&object.public_key)
                    .ok_or("BridgeConsentRequired")?
                    .expires,
            );
            if foreign.is_none() {
                let id = op.agreement_id.as_deref().ok_or("MediaPermissionDenied")?;
                let a = crate::federation_authority::agreement(state, id, now)?;
                let permit = crate::federation_authority::verify_admission(
                    &a.treaty,
                    op.admission.as_ref().ok_or("MediaAdmissionRequired")?,
                    now,
                )?;
                let consent = state
                    .bridge_consents
                    .get(&object.public_key)
                    .ok_or("BridgeConsentRequired")?;
                scope_until = scope_until.min(permit.valid_until);
                if permit.destination_profile != consent.profile {
                    return Err("MediaPermissionDenied");
                }
            } else if op.admission.is_some() {
                return Err("MediaInvalidObject");
            }
            if (foreign.is_some() && op.action == "Fetch")
                || (foreign.is_none() && !matches!(op.action.as_str(), "Fetch" | "Status"))
            {
                return Err("MediaPermissionDenied");
            }
        } else {
            if op.admission.is_some() {
                return Err("MediaInvalidObject");
            }
            if op.agreement_id.is_some() && foreign.is_none() {
                return Err("MediaPermissionDenied");
            }
            let right = if matches!(op.action.as_str(), "Put" | "Seal") {
                if record.agreement_id.is_some()
                    || object.public_key != record.author
                    || (!is_pending && !published(state, record, now))
                {
                    return Err("MediaPermissionDenied");
                }
                "MediaSubmit"
            } else if record.agreement_id.is_none()
                && object.public_key == record.author
                && is_pending
            {
                "MediaSubmit"
            } else if is_pending {
                "MediaInspect"
            } else {
                "MediaRead"
            };
            permission(state, &object.public_key, right, record, now)?;
        }
        if matches!(op.action.as_str(), "Put" | "Fetch")
            && !crate::policy::media_chunk(record.asset.bytes, op.offset, op.chunk_bytes)
        {
            return Err("MediaInvalidObject");
        }
        let mut expires = scope_until.min(record.expires).min(applications::deadline(
            state,
            &object.public_key,
            now,
        ));
        let pending_reference = is_pending && (!is_bridge || foreign.is_some());
        if pending_reference {
            expires = expires.min(record.upload_expires);
        }
        if let Some(id) = &record.agreement_id {
            let (_, page, export) = if pending_reference {
                crate::federation_authority::foreign_current(state, id, &record.page_id, now)?
            } else {
                crate::federation_authority::foreign_published(state, id, &record.page_id, now)?
            };
            expires = expires.min(export.valid_until);
            if !pending_reference {
                let reviewer = &page
                    .published
                    .as_ref()
                    .ok_or("MediaPermissionDenied")?
                    .reviewer;
                expires = expires.min(applications::deadline(state, reviewer, now));
            }
        } else {
            expires = expires.min(applications::deadline(state, &record.author, now));
            if !pending_reference {
                let page = page_authority::published(state, &record.page_id, now)?;
                expires = expires.min(page_authority::until(
                    state,
                    &object.public_key,
                    Some(&page.descriptor),
                    now,
                ));
            }
        }
        let value = Permission {
            version: 1,
            network: state.network.clone(),
            host_key: host_key.clone(),
            host_generation: h.body.generation,
            authority_revision: revision,
            authority_epoch: state.epoch,
            issued_at: now,
            expires,
            operation_digest: object_digest(OPERATION, object)?,
            asset: record.clone(),
        };
        Ok(Reply::success(
            state.epoch,
            json!({"permission":sign(PERMISSION,&state.network,&value,key)?}),
        ))
    } else {
        let assets = state
            .media
            .assets
            .iter()
            .filter(|(_, r)| {
                retained(state, r, now)
                    && r.storage_hosts.contains(host_key)
                    && h.body.namespaces.contains(&r.namespace)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let value = StorePolicy {
            version: 1,
            network: state.network.clone(),
            host_key: host_key.clone(),
            host_generation: h.body.generation,
            authority_revision: revision,
            authority_epoch: state.epoch,
            issued_at: now,
            expires,
            assets,
        };
        Ok(Reply::success(
            state.epoch,
            json!({"policy":sign(POLICY,&state.network,&value,key)?}),
        ))
    }
}

pub fn export_scope(
    state: &State,
    treaty: &types::FederationTreaty,
    descriptor: &types::PageDescriptor,
    assets: &[markup::media::Asset],
    now: u64,
) -> Result<(), Failure> {
    if assets.is_empty() {
        return Ok(());
    }
    if assets.iter().map(|a| a.bytes).sum::<u64>() > treaty.media_max_bytes
        || assets.iter().any(|a| {
            !treaty.media_profiles.contains(&a.profile)
                || a.hosts
                    .iter()
                    .any(|h| !treaty.media_source_hosts.contains(h))
        })
    {
        return Err("FederationMediaDenied");
    }
    for asset in assets {
        let r = state
            .media
            .assets
            .get(&asset_key(
                None,
                &descriptor.page_id,
                descriptor.revision,
                &asset.id,
            ))
            .ok_or("MediaUnavailable")?;
        if r.expires <= now || r.source_digest != descriptor.digest || r.asset != *asset {
            return Err("MediaUnavailable");
        }
    }
    Ok(())
}
fn bridge_permission(
    state: &State,
    id: &str,
    key: &str,
    host_key: &str,
    r: &AssetRecord,
    now: u64,
) -> Result<(), Failure> {
    let a = crate::federation_authority::agreement(state, id, now)?;
    let source = a.treaty.source_network == state.network;
    let expected = if source {
        &a.treaty.source_bridge_key
    } else {
        &a.treaty.destination_bridge_key
    };
    if key != expected
        || a.treaty.media_profiles.is_empty()
        || !a.treaty.media_profiles.contains(&r.asset.profile)
    {
        return Err("MediaPermissionDenied");
    }
    let c = state
        .bridge_consents
        .get(key)
        .ok_or("BridgeConsentRequired")?;
    let consent =
        crate::federation_authority::bridge_document(state, &a.treaty, key, &c.profile, now)?;
    let h = host(state, host_key, now)?;
    if !consent.media.iter().any(|m| {
        m.network == state.network
            && m.host_key == host_key
            && m.endpoint == h.body.endpoint
            && m.address == h.body.address
            && m.ca_digest == h.body.ca_digest
            && m.certificate_digest == h.body.certificate_digest
            && m.authority_signer == h.body.authority_signer
    }) {
        return Err("MediaConsentRequired");
    }
    if source {
        let descriptor =
            crate::federation_authority::exportable(state, &a.treaty, &r.page_id, now)?;
        if descriptor.revision != r.revision
            || descriptor.digest != r.source_digest
            || !a.treaty.media_source_hosts.contains(&host_key.to_string())
        {
            return Err("MediaPermissionDenied");
        }
    } else {
        let (_, p, _) = crate::federation_authority::foreign_current(state, id, &r.page_id, now)?;
        if (!p.pending && p.published.is_none())
            || p.observed.revision != r.revision
            || p.observed.digest != r.source_digest
            || !a
                .treaty
                .media_destination_hosts
                .contains(&host_key.to_string())
        {
            return Err("MediaPermissionDenied");
        }
    }
    Ok(())
}
pub fn import_assets(
    state: &mut State,
    treaty: &types::FederationTreaty,
    descriptor: &types::PageDescriptor,
    assets: &[markup::media::Asset],
    now: u64,
) -> Result<(), Failure> {
    prune(state, now);
    if assets.is_empty() {
        return Ok(());
    }
    if assets.iter().map(|a| a.bytes).sum::<u64>() > treaty.media_max_bytes
        || assets.iter().any(|a| {
            !treaty.media_profiles.contains(&a.profile)
                || a.hosts
                    .iter()
                    .any(|h| !treaty.media_source_hosts.contains(h))
        })
    {
        return Err("FederationMediaDenied");
    }
    let id = &treaty.agreement_id;
    let new: Vec<_> = assets
        .iter()
        .filter(|a| {
            !state.media.assets.contains_key(&asset_key(
                Some(id),
                &descriptor.page_id,
                descriptor.revision,
                &a.id,
            ))
        })
        .collect();
    if state.media.assets.len() + new.len() > 256 {
        return Err("MediaQuotaExceeded");
    }
    let mut expires = treaty.expires;
    for key in &treaty.media_destination_hosts {
        let h = host(state, key, now)?;
        if !h.body.namespaces.contains(&treaty.destination_namespace) {
            return Err("MediaNamespaceDenied");
        }
        let used: u64 = state
            .media
            .assets
            .values()
            .filter(|r| r.storage_hosts.contains(key))
            .map(|r| r.asset.bytes + 4096)
            .sum();
        let added: u64 = new.iter().map(|a| a.bytes + 4096).sum();
        if used + added > h.body.state_bytes / 4 - 65536 {
            return Err("MediaQuotaExceeded");
        }
        expires = expires
            .min(h.body.expires)
            .min(now.saturating_add(h.body.retention_seconds));
    }
    for asset in new {
        state.media.assets.insert(
            asset_key(
                Some(id),
                &descriptor.page_id,
                descriptor.revision,
                &asset.id,
            ),
            AssetRecord {
                agreement_id: Some(id.clone()),
                storage_hosts: treaty.media_destination_hosts.clone(),
                required_copies: treaty.media_required_copies.max(state.media.minimum_copies),
                page_id: descriptor.page_id.clone(),
                revision: descriptor.revision,
                source_digest: descriptor.digest.clone(),
                author: descriptor.author.clone(),
                namespace: treaty.destination_namespace.clone(),
                asset: asset.clone(),
                upload_expires: now.saturating_add(UPLOAD_LIFETIME).min(expires),
                expires,
                receipts: Default::default(),
                reviewed_by: Default::default(),
            },
        );
    }
    Ok(())
}
pub fn approve_foreign(
    state: &State,
    agreement: &str,
    page: &str,
    revision: u64,
    assets: &[markup::media::Asset],
    reviewer: &str,
    now: u64,
) -> Result<(), Failure> {
    for asset in assets {
        let r = state
            .media
            .assets
            .get(&asset_key(Some(agreement), page, revision, &asset.id))
            .ok_or("MediaIncomplete")?;
        if !usable(state, r, now) || r.asset != *asset {
            return Err("MediaIncomplete");
        }
        permission(state, reviewer, "MediaInspect", r, now)?;
        if !r.reviewed_by.contains(reviewer) {
            return Err("MediaReviewRequired");
        }
        let copies = r
            .receipts
            .iter()
            .filter(|(key, e)| {
                host(state, key, now).is_ok_and(|h| {
                    verify::<StoreReceipt>(RECEIPT, e, &state.network).is_ok_and(|receipt| {
                        receipt.host_generation == h.body.generation
                            && receipt.status == "Complete"
                            && receipt.digest == asset.digest
                            && receipt.bytes == asset.bytes
                    })
                })
            })
            .count();
        if copies < r.required_copies.max(state.media.minimum_copies) as usize {
            return Err("MediaIncomplete");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../Tests/MediaAuthority.rs"]
mod tests;
