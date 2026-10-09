// SPDX-License-Identifier: MIT
// Recipient acceptance reserves bounded selected storage before payload admission.
use crate::{
    authority,
    mail_authority::{self, object_digest, sign, verify},
    page_authority,
    protocol::{self, VerifiedRequest},
    transfer_types::*,
    types::{self, Command, Envelope, Reply, State},
};
use bech32::{FromBase32, ToBase32, Variant};
use ed25519_dalek::SigningKey;
use serde_json::json;
type Failure = &'static str;

fn age_recipient(value: &str) -> bool {
    if value.len() != 62 {
        return false;
    }
    let Ok((hrp, data, variant)) = bech32::decode(value) else {
        return false;
    };
    let Ok(bytes) = Vec::<u8>::from_base32(&data) else {
        return false;
    };
    hrp == "age"
        && variant == Variant::Bech32
        && bytes.len() == 32
        && bech32::encode("age", bytes.to_base32(), Variant::Bech32)
            .is_ok_and(|canonical| canonical == value)
}

pub fn check_state(state: &State, now: u64) -> Result<(), Failure> {
    if state.version != crate::types::STATE_VERSION {
        return Err("UnsupportedState");
    }
    if state.high_water_time > now {
        return Err("ClockRollback");
    }
    Ok(())
}
pub fn signing<'a>(state: &State, key: Option<&'a SigningKey>) -> Result<&'a SigningKey, Failure> {
    let key = key.ok_or("ServiceUnavailable")?;
    if mail_authority::reserved_identity_conflict(
        state,
        &hex::encode(key.verifying_key().as_bytes()),
    ) {
        return Err("DedicatedAuthorityKeyRequired");
    }
    Ok(key)
}
pub fn expiry(value: u64, now: u64) -> Result<(), Failure> {
    if value <= now || value > now.saturating_add(MAX_LIFETIME) {
        return Err("InvalidExpiry");
    }
    Ok(())
}
pub fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub fn host_consent(object: &Envelope, network: &str) -> Result<HostConsent, Failure> {
    let body: HostConsent = verify(HOST, object, network)?;
    mail_authority::validate_host(&body, network, &object.public_key, "Transfer")?;
    Ok(body)
}
pub fn host<'a>(
    state: &'a State,
    key: &str,
    now: u64,
) -> Result<&'a crate::mail_types::HostRecord, Failure> {
    authority::require(state, key, types::MEMBER | types::HOST, now)?;
    let host = state
        .transfers
        .hosts
        .get(key)
        .ok_or("TransferUnavailable")?;
    if !host.active
        || host.body.expires <= now
        || state.members[key].grants != types::MEMBER | types::HOST
    {
        return Err("TransferConsentRequired");
    }
    Ok(host)
}
fn participant(state: &State, key: &str, record: &TransferRecord, now: u64) -> Result<(), Failure> {
    page_authority::client(state, key, now)?;
    if key != record.body.sender_key && key != record.body.recipient_key {
        return Err("TransferPermissionDenied");
    }
    Ok(())
}
fn usable(state: &State, record: &TransferRecord, now: u64) -> Result<(), Failure> {
    if record.cancelled || record.body.expires <= now {
        return Err("TransferUnavailable");
    }
    page_authority::client(state, &record.body.sender_key, now)?;
    page_authority::client(state, &record.body.recipient_key, now)?;
    Ok(())
}
pub fn read_only(command: &Command) -> bool {
    matches!(
        command,
        Command::TransferAuthorise { .. } | Command::TransferPolicySync { .. }
    )
}
pub fn handles(command: &Command) -> bool {
    read_only(command)
        || matches!(
            command,
            Command::TransferHostRegister { .. }
                | Command::TransferHostWithdraw { .. }
                | Command::TransferHosts
                | Command::TransferOfferCreate { .. }
                | Command::TransferOfferGet { .. }
                | Command::TransferOfferList { .. }
                | Command::TransferOfferAccept { .. }
                | Command::TransferOfferCancel { .. }
        )
}

pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    key: Option<&SigningKey>,
) -> Result<Reply, Failure> {
    check_state(state, now)?;
    let key = signing(state, key)?;
    match &request.request.command {
        Command::TransferHostRegister { .. } => {
            authority::require(state, &request.key, types::MEMBER | types::HOST, now)?
        }
        Command::TransferHostWithdraw { host_key, .. } => {
            if *host_key != request.key
                || !state.transfers.hosts.contains_key(host_key)
                || state.media.hosts.contains_key(host_key)
            {
                return Err("TransferPermissionDenied");
            }
        }
        _ => page_authority::client(state, &request.key, now)?,
    }
    // Expired signed offers cannot be admitted again at the guarded authority time.
    state
        .transfers
        .offers
        .retain(|_, record| record.body.expires > now);
    let read = matches!(
        request.request.command,
        Command::TransferHosts
            | Command::TransferOfferGet { .. }
            | Command::TransferOfferList { .. }
    );
    state.receipts.retain(|_, r| r.expires >= now);
    let receipt_id = format!("{}:{}", request.key, request.request.request_id);
    if !read {
        if let Some(receipt) = state.receipts.get(&receipt_id) {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            return Ok(receipt.reply.clone());
        }
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let result = match &request.request.command {
        Command::TransferHostRegister { consent } => {
            let body = host_consent(consent, &state.network)?;
            expiry(body.expires, now)?;
            if body.host_key != request.key
                || state.members[&request.key].grants != types::MEMBER | types::HOST
                || state.consents.contains_key(&request.key)
                || state.bridge_consents.contains_key(&request.key)
                || state.mail.hosts.contains_key(&request.key)
                || state.media.hosts.contains_key(&request.key)
                || state.ssh.services.contains_key(&request.key)
                || certificate != Some(body.certificate_digest.as_str())
                || body.authority_signer != hex::encode(key.verifying_key().as_bytes())
                || body.expires > state.members[&request.key].expires
            {
                return Err("SeparateServiceIdentityRequired");
            }
            let next = state
                .transfers
                .hosts
                .get(&request.key)
                .map(|h| h.body.generation.checked_add(1).ok_or("CapacityExceeded"))
                .transpose()?
                .unwrap_or(1);
            if body.generation != next {
                return Err("TransferGenerationConflict");
            }
            if !state.transfers.hosts.contains_key(&request.key)
                && state.transfers.hosts.len() >= 16
            {
                return Err("CapacityExceeded");
            }
            // Existing reservations cannot exceed a reduced renewed quota.
            let reserved: u64 = state
                .transfers
                .offers
                .values()
                .filter(|r| {
                    !r.cancelled
                        && r.body.expires > now
                        && r.accepted
                            .as_ref()
                            .is_some_and(|a| a.host_key == request.key && a.expires > now)
                })
                .map(|r| r.body.payload_bytes)
                .sum();
            if reserved > body.state_bytes / 4 {
                return Err("TransferQuotaExceeded");
            }
            let digest = object_digest(HOST, consent)?;
            state.transfers.hosts.insert(
                request.key.clone(),
                crate::mail_types::HostRecord {
                    consent: consent.clone(),
                    digest: digest.clone(),
                    body: body.clone(),
                    active: true,
                },
            );
            json!({"hostKey":body.host_key,"generation":body.generation,"consentDigest":digest})
        }
        Command::TransferHostWithdraw {
            host_key,
            expected_generation,
        } => {
            let host = state
                .transfers
                .hosts
                .get_mut(host_key)
                .ok_or("TransferUnavailable")?;
            if host.body.generation != *expected_generation {
                return Err("TransferGenerationConflict");
            }
            host.active = false;
            for record in state
                .transfers
                .offers
                .values_mut()
                .filter(|r| r.accepted.as_ref().is_some_and(|a| a.host_key == *host_key))
            {
                record.cancelled = true;
            }
            json!({"hostKey":host_key,"active":false})
        }
        Command::TransferHosts => {
            json!({"hosts":state.transfers.hosts.iter().filter(|(k,_)|host(state,k,now).is_ok()).map(|(_,h)|&h.consent).collect::<Vec<_>>() })
        }
        Command::TransferOfferCreate { offer } => {
            let body: Offer = verify(OFFER, offer, &state.network)?;
            protocol::fixed_hex::<16>(&body.transfer_id)?;
            protocol::fixed_hex::<32>(&body.payload_digest)?;
            page_authority::client(state, &body.recipient_key, now)?;
            if body.version != 1
                || body.network != state.network
                || body.sender_key != request.key
                || offer.public_key != request.key
                || body.sender_key == body.recipient_key
                || !(1..=MAX_FILE).contains(&body.payload_bytes)
                || body.file_bytes > MAX_FILE
                || body.file_bytes >= body.payload_bytes
                || !label(&body.label)
                || !age_recipient(&body.recipient_encryption_key)
            {
                return Err("TransferInvalidObject");
            }
            let digest = object_digest(OFFER, offer)?;
            if let Some(existing) = state.transfers.offers.get(&body.transfer_id) {
                if existing.offer_digest != digest {
                    return Err("TransferConflict");
                }
                if existing.cancelled {
                    return Err("TransferUnavailable");
                }
                json!({"transfer":existing})
            } else {
                expiry(body.expires, now)?;
                if state.transfers.offers.len() >= 256
                    || state
                        .transfers
                        .offers
                        .values()
                        .filter(|r| r.body.sender_key == request.key)
                        .count()
                        >= 32
                {
                    return Err("CapacityExceeded");
                }
                let record = TransferRecord {
                    offer: offer.clone(),
                    body: body.clone(),
                    offer_digest: digest,
                    acceptance: None,
                    accepted: None,
                    cancelled: false,
                };
                state
                    .transfers
                    .offers
                    .insert(body.transfer_id, record.clone());
                json!({"transfer":record})
            }
        }
        Command::TransferOfferGet { transfer_id } => {
            let r = state
                .transfers
                .offers
                .get(transfer_id)
                .ok_or("TransferUnavailable")?;
            participant(state, &request.key, r, now)?;
            json!({"transfer":r})
        }
        Command::TransferOfferList { after } => {
            if let Some(after) = after {
                protocol::fixed_hex::<16>(after)?;
            }
            let mut records: Vec<_> = state
                .transfers
                .offers
                .iter()
                .filter(|(id, r)| {
                    after.as_ref().is_none_or(|after| *id > after)
                        && (r.body.sender_key == request.key || r.body.recipient_key == request.key)
                })
                .take(17)
                .collect();
            let next = if records.len() > 16 {
                records.pop();
                records.last().map(|(id, _)| (*id).clone())
            } else {
                None
            };
            json!({"transfers":records.into_iter().map(|(_,r)|r).collect::<Vec<_>>(),"next":next})
        }
        Command::TransferOfferAccept { acceptance } => {
            let accepted: Acceptance = verify(ACCEPTANCE, acceptance, &state.network)?;
            let record = state
                .transfers
                .offers
                .get(&accepted.transfer_id)
                .ok_or("TransferUnavailable")?;
            usable(state, record, now)?;
            if accepted.version != 1
                || accepted.network != state.network
                || acceptance.public_key != request.key
                || record.body.recipient_key != request.key
                || record.offer_digest != accepted.offer_digest
                || !label(&accepted.destination)
                || accepted.expires > record.body.expires
            {
                return Err("TransferPermissionDenied");
            }
            if let Some(old) = &record.acceptance {
                if object_digest(ACCEPTANCE, old)? != object_digest(ACCEPTANCE, acceptance)? {
                    return Err("TransferConflict");
                }
                return Ok(Reply::success(state.epoch, json!({"transfer":record})));
            }
            expiry(accepted.expires, now)?;
            let host = host(state, &accepted.host_key, now)?;
            if accepted.expires > host.body.expires {
                return Err("InvalidExpiry");
            }
            let reserved: u64 = state
                .transfers
                .offers
                .values()
                .filter(|r| {
                    !r.cancelled
                        && r.body.expires > now
                        && r.accepted
                            .as_ref()
                            .is_some_and(|a| a.host_key == accepted.host_key && a.expires > now)
                })
                .map(|r| r.body.payload_bytes)
                .sum();
            if reserved
                .checked_add(record.body.payload_bytes)
                .is_none_or(|n| n > host.body.state_bytes / 4)
            {
                return Err("TransferQuotaExceeded");
            }
            let record = state
                .transfers
                .offers
                .get_mut(&accepted.transfer_id)
                .unwrap();
            record.acceptance = Some(acceptance.clone());
            record.accepted = Some(accepted);
            json!({"transfer":record})
        }
        Command::TransferOfferCancel {
            transfer_id,
            offer_digest,
        } => {
            let r = state
                .transfers
                .offers
                .get(transfer_id)
                .ok_or("TransferUnavailable")?;
            participant(state, &request.key, r, now)?;
            if r.offer_digest != *offer_digest {
                return Err("TransferConflict");
            }
            let r = state.transfers.offers.get_mut(transfer_id).unwrap();
            r.cancelled = true;
            json!({"transfer":r})
        }
        _ => return Err("UnsupportedCommand"),
    };

    state.high_water_time = state.high_water_time.max(now);
    if !read {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }
    let reply = Reply::success(state.epoch, result);
    if !read {
        state.receipts.insert(
            receipt_id,
            types::Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
}
pub fn operation(object: &Envelope, network: &str, now: u64) -> Result<Operation, Failure> {
    let op: Operation = verify(OPERATION, object, network)?;
    protocol::fixed_hex::<16>(&op.operation_id)?;
    protocol::fixed_hex::<16>(&op.transfer_id)?;
    protocol::fixed_hex::<32>(&op.host_key)?;
    protocol::fixed_hex::<32>(&op.offer_digest)?;
    if op.version != 1
        || op.network != network
        || op.issued_at > now.saturating_add(2)
        || op.issued_at.saturating_add(30) < now
    {
        return Err("TransferStaleOperation");
    }
    match op.action.as_str() {
        "Put" => {
            if !(1..=CHUNK).contains(&op.chunk_bytes) {
                return Err("TransferInvalidObject");
            }
            protocol::fixed_hex::<32>(op.chunk_digest.as_deref().ok_or("TransferInvalidObject")?)?;
        }
        "Fetch" => {
            if !(1..=CHUNK).contains(&op.chunk_bytes) || op.chunk_digest.is_some() {
                return Err("TransferInvalidObject");
            }
        }
        "Status" | "Commit" | "Delete" => {
            if op.offset != 0 || op.chunk_bytes != 0 || op.chunk_digest.is_some() {
                return Err("TransferInvalidObject");
            }
        }
        _ => return Err("TransferInvalidObject"),
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
    check_state(state, now)?;
    let key = signing(state, key)?;
    let host_key = match &request.request.command {
        Command::TransferAuthorise { host_key, .. } | Command::TransferPolicySync { host_key } => {
            host_key
        }
        _ => return Err("UnsupportedCommand"),
    };
    if *host_key != request.key {
        return Err("TransferPermissionDenied");
    }
    let host = host(state, host_key, now)?;
    if certificate != Some(host.body.certificate_digest.as_str()) {
        return Err("ClientCertificateRequired");
    }
    let expires = (now + 5)
        .min(host.body.expires)
        .min(state.members[host_key].expires);
    if let Command::TransferAuthorise {
        operation: object, ..
    } = &request.request.command
    {
        let op = operation(object, &state.network, now)?;
        let r = state
            .transfers
            .offers
            .get(&op.transfer_id)
            .ok_or("TransferUnavailable")?;
        usable(state, r, now)?;
        let a = r.accepted.as_ref().ok_or("TransferAcceptanceRequired")?;
        if op.host_key != *host_key
            || a.host_key != *host_key
            || a.expires <= now
            || op.offer_digest != r.offer_digest
        {
            return Err("TransferPermissionDenied");
        }
        participant(state, &object.public_key, r, now)?;
        if (matches!(op.action.as_str(), "Put" | "Commit")
            && object.public_key != r.body.sender_key)
            || (matches!(op.action.as_str(), "Fetch" | "Delete")
                && object.public_key != r.body.recipient_key)
        {
            return Err("TransferPermissionDenied");
        }
        if op
            .offset
            .checked_add(op.chunk_bytes)
            .is_none_or(|end| end > r.body.payload_bytes)
        {
            return Err("TransferInvalidObject");
        }
        let expires = expires
            .min(a.expires)
            .min(r.body.expires)
            .min(state.members[&r.body.sender_key].expires)
            .min(state.members[&r.body.recipient_key].expires);
        let value = Permission {
            version: 1,
            network: state.network.clone(),
            host_key: host_key.clone(),
            host_generation: host.body.generation,
            authority_revision: revision,
            authority_epoch: state.epoch,
            issued_at: now,
            expires,
            operation_digest: object_digest(OPERATION, object)?,
            transfer: r.clone(),
        };
        Ok(Reply::success(
            state.epoch,
            json!({"permission":sign(PERMISSION,&state.network,&value,key)?}),
        ))
    } else {
        let selected = state
            .transfers
            .offers
            .iter()
            .filter(|(_, r)| {
                usable(state, r, now).is_ok()
                    && r.accepted
                        .as_ref()
                        .is_some_and(|a| a.host_key == *host_key && a.expires > now)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let value = StorePolicy {
            version: 1,
            network: state.network.clone(),
            host_key: host_key.clone(),
            host_generation: host.body.generation,
            authority_revision: revision,
            authority_epoch: state.epoch,
            issued_at: now,
            expires,
            transfers: selected,
        };
        Ok(Reply::success(
            state.epoch,
            json!({"policy":sign(POLICY,&state.network,&value,key)?}),
        ))
    }
}

#[cfg(test)]
#[path = "../Tests/TransferAuthority.rs"]
mod tests;
