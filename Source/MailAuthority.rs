// SPDX-License-Identifier: MIT
// Quorum metadata transitions; message permissions are read-only and never become receipts.
use crate::{
    authority,
    mail_types::*,
    page_authority,
    protocol::{self, VerifiedRequest},
    types::{self, Command, Reply, State},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

type Failure = &'static str;
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn address_id(network: &str, owner: &str) -> Result<String, Failure> {
    let mut bytes = b"HyperNet/MailAddress/1\0".to_vec();
    bytes.extend(protocol::fixed_hex::<32>(network)?);
    bytes.extend(protocol::fixed_hex::<32>(owner)?);
    Ok(hash(&bytes))
}
pub fn device_id(address: &str, key: &str) -> Result<String, Failure> {
    let mut bytes = b"HyperNet/MailDevice/1\0".to_vec();
    bytes.extend(protocol::fixed_hex::<32>(address)?);
    bytes.extend(protocol::fixed_hex::<32>(key)?);
    Ok(hash(&bytes))
}
fn signed_bytes(domain: &[u8], object: &SignedMailObject) -> Result<Vec<u8>, Failure> {
    if object.payload.len() > 48 * 1024 {
        return Err("MailInvalidObject");
    }
    let mut bytes = domain.to_vec();
    bytes.extend(protocol::fixed_hex::<32>(&object.network)?);
    bytes.extend(protocol::fixed_hex::<32>(&object.public_key)?);
    bytes.extend(
        URL_SAFE_NO_PAD
            .decode(&object.payload)
            .map_err(|_| "MailInvalidObject")?,
    );
    Ok(bytes)
}
pub fn object_digest(domain: &[u8], object: &SignedMailObject) -> Result<String, Failure> {
    Ok(hash(&signed_bytes(domain, object)?))
}
pub fn verify<T: DeserializeOwned>(
    domain: &[u8],
    object: &SignedMailObject,
    network: &str,
) -> Result<T, Failure> {
    if object.network != network {
        return Err("WrongNetwork");
    }
    let bytes = signed_bytes(domain, object)?;
    VerifyingKey::from_bytes(&protocol::fixed_hex::<32>(&object.public_key)?)
        .map_err(|_| "InvalidKey")?
        .verify_strict(
            &bytes,
            &Signature::from_bytes(&protocol::fixed_hex::<64>(&object.signature)?),
        )
        .map_err(|_| "InvalidSignature")?;
    serde_json::from_slice(&bytes[domain.len() + 64..]).map_err(|_| "MailInvalidObject")
}
pub fn sign<T: Serialize>(
    domain: &[u8],
    network: &str,
    value: &T,
    key: &SigningKey,
) -> Result<SignedMailObject, Failure> {
    let payload = serde_json::to_vec(value).map_err(|_| "MailInvalidObject")?;
    let mut result = SignedMailObject {
        network: network.into(),
        public_key: hex::encode(key.verifying_key().as_bytes()),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: String::new(),
    };
    result.signature = hex::encode(key.sign(&signed_bytes(domain, &result)?).to_bytes());
    Ok(result)
}
pub fn manifest(object: &SignedMailObject, network: &str) -> Result<AddressManifest, Failure> {
    let value: AddressManifest = verify(MANIFEST, object, network)?;
    if value.version != 1
        || value.network != network
        || value.owner_key != object.public_key
        || value.address_id != address_id(network, &value.owner_key)?
        || value.generation == 0
        || value.devices.len() > 8
        || value.storage_hosts.len() > 4
        || !(60..=MAX_LIFETIME).contains(&value.retention_seconds)
        || value.required_copies as usize > value.storage_hosts.len()
        || (!value.deleted && (value.required_copies == 0 || value.devices.is_empty()))
        || (value.deleted
            && (!value.devices.is_empty()
                || !value.storage_hosts.is_empty()
                || value.required_copies != 0))
    {
        return Err("MailInvalidObject");
    }
    if let Some(previous) = &value.previous_digest {
        protocol::fixed_hex::<32>(previous)?;
    }
    let mut keys = BTreeSet::from([value.owner_key.as_str()]);
    let mut devices = BTreeSet::new();
    for device in &value.devices {
        for key in [&device.request_key, &device.mls_signature_key] {
            VerifyingKey::from_bytes(&protocol::fixed_hex::<32>(key)?).map_err(|_| "InvalidKey")?;
            if !keys.insert(key) {
                return Err("SeparateMailIdentityRequired");
            }
        }
        if device.device_id != device_id(&value.address_id, &device.request_key)?
            || !devices.insert(&device.device_id)
            || device.expires > value.expires
            || device.permissions.is_empty()
            || device.permissions.len() > 3
            || device.permissions.iter().collect::<BTreeSet<_>>().len() != device.permissions.len()
            || device
                .permissions
                .iter()
                .any(|p| !matches!(p.as_str(), "Read" | "Send" | "Delete"))
        {
            return Err("MailInvalidObject");
        }
    }
    let mut hosts = BTreeSet::new();
    for host in &value.storage_hosts {
        protocol::fixed_hex::<32>(host)?;
        if !hosts.insert(host) {
            return Err("MailInvalidObject");
        }
    }
    Ok(value)
}
pub fn host_consent(object: &SignedMailObject, network: &str) -> Result<MailHostConsent, Failure> {
    let value: MailHostConsent = verify(crate::mail_types::HOST, object, network)?;
    validate_host(&value, network, &object.public_key, "Mail")?;
    Ok(value)
}
pub fn validate_host(
    value: &MailHostConsent,
    network: &str,
    public_key: &str,
    service: &str,
) -> Result<(), Failure> {
    for digest in [
        &value.ca_digest,
        &value.certificate_digest,
        &value.authority_signer,
    ] {
        protocol::fixed_hex::<32>(digest)?;
    }
    for endpoint in [&value.endpoint, &value.authority_endpoint] {
        let url = reqwest::Url::parse(endpoint).map_err(|_| "MailInvalidObject")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("MailInvalidObject");
        }
    }
    if value.version != 1
        || value.network != network
        || value.host_key != public_key
        || value.generation == 0
        || value.services != [service]
        || value.address.port() == 0
        || value.authority_address.port() == 0
        || value.address.ip().is_unspecified()
        || value.authority_address.ip().is_unspecified()
        || value.memory_bytes < 512 * 1024 * 1024
        || value.memory_bytes > 8 * 1024 * 1024 * 1024
        || !(32..=512).contains(&value.pids)
        || value.cpu_period != 100000
        || !(1000..=800000).contains(&value.cpu_quota)
        || !(8 * 1024 * 1024..=64 * 1024 * 1024).contains(&value.state_bytes)
        || !value.state_bytes.is_multiple_of(4096)
    {
        return Err("MailInvalidObject");
    }
    Ok(())
}
fn address<'a>(
    state: &'a State,
    id: &str,
    now: u64,
) -> Result<(&'a AddressRecord, AddressManifest), Failure> {
    protocol::fixed_hex::<32>(id)?;
    let record = state.mail.addresses.get(id).ok_or("MailUnavailable")?;
    let value = manifest(&record.manifest, &state.network)?;
    page_authority::client(state, &record.member, now).map_err(|_| "MailUnavailable")?;
    if value.deleted || value.expires <= now {
        return Err("MailUnavailable");
    }
    Ok((record, value))
}
fn device<'a>(
    value: &'a AddressManifest,
    key: &str,
    id: &str,
    scope: &str,
    now: u64,
) -> Result<&'a DeviceBinding, Failure> {
    value
        .devices
        .iter()
        .find(|device| {
            device.request_key == key
                && device.device_id == id
                && device.expires > now
                && device
                    .permissions
                    .iter()
                    .any(|permission| permission == scope)
        })
        .ok_or("MailPermissionDenied")
}
fn directory_access(state: &State, key: &str, now: u64) -> Result<(), Failure> {
    if page_authority::client(state, key, now).is_ok() {
        return Ok(());
    }
    for id in state.mail.addresses.keys() {
        if let Ok((_, value)) = address(state, id, now)
            && (value.owner_key == key
                || value
                    .devices
                    .iter()
                    .any(|d| d.request_key == key && d.expires > now))
        {
            return Ok(());
        }
    }
    Err("MailPermissionDenied")
}
fn live_host<'a>(
    state: &'a State,
    key: &str,
    certificate: Option<&str>,
    now: u64,
) -> Result<&'a HostRecord, Failure> {
    authority::require(state, key, types::MEMBER | types::HOST, now)?;
    if state.members.get(key).ok_or("NotMember")?.grants != types::MEMBER | types::HOST
        || state.consents.contains_key(key)
        || state.bridge_consents.contains_key(key)
    {
        return Err("SeparateMailIdentityRequired");
    }
    let host = state.mail.hosts.get(key).ok_or("MailUnavailable")?;
    if !host.active
        || host.body.expires <= now
        || certificate != Some(host.body.certificate_digest.as_str())
    {
        return Err("MailPermissionDenied");
    }
    Ok(host)
}
fn expiry(expires: u64, now: u64) -> Result<(), Failure> {
    if expires <= now || expires > now.saturating_add(MAX_LIFETIME) {
        return Err("InvalidExpiry");
    }
    Ok(())
}
fn signer<'a>(state: &State, key: Option<&'a SigningKey>) -> Result<&'a SigningKey, Failure> {
    let key = key.ok_or("MailUnavailable")?;
    let public = hex::encode(key.verifying_key().as_bytes());
    if reserved_identity_conflict(state, &public) {
        return Err("DedicatedAuthorityKeyRequired");
    }
    Ok(key)
}
pub fn reserved_identity_conflict(state: &State, key: &str) -> bool {
    state.applications.contains_key(key)
        || state.members.contains_key(key)
        || (state.mail.device_history.contains(key) || state.ssh.key_history.contains(key))
        || state
            .mail
            .addresses
            .values()
            .any(|record| record.manifest.public_key == key)
}
pub fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::MailAddressCreate { .. }
            | Command::MailAddressUpdate { .. }
            | Command::MailAddressDelete { .. }
            | Command::MailAddressGet { .. }
            | Command::MailHostRegister { .. }
            | Command::MailHostWithdraw { .. }
            | Command::MailHosts
            | Command::MailKeyPackagesPublish { .. }
            | Command::MailKeyPackagesClaim { .. }
            | Command::MailKeyPackagesClaimStatus { .. }
            | Command::MailAuthorise { .. }
            | Command::MailPolicySync { .. }
    )
}
pub fn read_only(command: &Command) -> bool {
    matches!(
        command,
        Command::MailAuthorise { .. } | Command::MailPolicySync { .. }
    )
}
fn check_state(state: &State, now: u64) -> Result<(), Failure> {
    if state.version != crate::types::STATE_VERSION {
        return Err("UnsupportedState");
    }
    if state.high_water_time > now.saturating_add(2) {
        return Err("ClockRollback");
    }
    Ok(())
}
fn check_keys(
    state: &State,
    new: &AddressManifest,
    old: Option<&AddressManifest>,
    authority_key: &SigningKey,
) -> Result<(), Failure> {
    let dedicated = hex::encode(authority_key.verifying_key().as_bytes());
    for binding in &new.devices {
        for key in [&binding.request_key, &binding.mls_signature_key] {
            let retained = old.is_some_and(|old| {
                old.devices.iter().any(|d| {
                    d.device_id == binding.device_id
                        && d.request_key == binding.request_key
                        && d.mls_signature_key == binding.mls_signature_key
                })
            });
            if state.applications.contains_key(key)
                || key == &dedicated
                || state.members.contains_key(key)
                || (state.mail.hosts.contains_key(key)
                    || state.transfers.hosts.contains_key(key)
                    || state.ssh.services.contains_key(key))
                || state
                    .mail
                    .addresses
                    .values()
                    .any(|r| r.manifest.public_key == *key)
                || (!retained
                    && (state.mail.device_history.contains(key)
                        || state.ssh.key_history.contains(key)))
            {
                return Err("SeparateMailIdentityRequired");
            }
        }
    }
    if state.applications.contains_key(&new.owner_key)
        || new.owner_key == dedicated
        || state.members.contains_key(&new.owner_key)
        || state.mail.device_history.contains(&new.owner_key)
        || state.ssh.key_history.contains(&new.owner_key)
        || (state.mail.hosts.contains_key(&new.owner_key)
            || state.transfers.hosts.contains_key(&new.owner_key)
            || state.ssh.services.contains_key(&new.owner_key))
    {
        return Err("SeparateMailIdentityRequired");
    }
    if state.mail.device_history.len() + new.devices.len() * 2 > 4096 {
        return Err("MailQuotaExceeded");
    }
    Ok(())
}
pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
    key: Option<&SigningKey>,
) -> Result<Reply, Failure> {
    check_state(state, now)?;
    let signing = signer(state, key)?;
    if read_only(&request.request.command) {
        return Err("MailReadOnlyPathRequired");
    }
    let mutate = !matches!(
        request.request.command,
        Command::MailAddressGet { .. }
            | Command::MailHosts
            | Command::MailKeyPackagesClaimStatus { .. }
    );
    let receipt_key = format!("{}:{}", request.key, request.request.request_id);
    // Authorisation is repeated before returning a public mutation receipt.
    match &request.request.command {
        Command::MailAddressCreate { .. } => page_authority::client(state, &request.key, now)?,
        Command::MailAddressUpdate { address_id, .. }
        | Command::MailAddressDelete { address_id, .. } => {
            let record = state
                .mail
                .addresses
                .get(address_id)
                .ok_or("MailUnavailable")?;
            if record.manifest.public_key != request.key {
                return Err("MailOwnerMismatch");
            }
            page_authority::client(state, &record.member, now)?;
        }
        Command::MailHostRegister { .. } => {
            authority::require(state, &request.key, types::MEMBER | types::HOST, now)?
        }
        Command::MailHostWithdraw { host_key, .. } => {
            if host_key != &request.key || !state.mail.hosts.contains_key(host_key) {
                return Err("MailPermissionDenied");
            }
        }
        Command::MailKeyPackagesPublish {
            address_id,
            device_id,
            manifest_generation,
            ..
        } => {
            let (_, value) = address(state, address_id, now)?;
            device(&value, &request.key, device_id, "Read", now)?;
            if value.generation != *manifest_generation {
                return Err("MailGenerationConflict");
            }
        }
        Command::MailKeyPackagesClaim {
            sender_address,
            sender_device,
            ..
        }
        | Command::MailKeyPackagesClaimStatus {
            sender_address,
            sender_device,
            ..
        } => {
            let (_, value) = address(state, sender_address, now)?;
            device(&value, &request.key, sender_device, "Send", now)?;
        }
        Command::MailAddressGet { address_id }
            if state
                .mail
                .addresses
                .get(address_id)
                .is_some_and(|r| r.manifest.public_key == request.key) =>
        {
            page_authority::client(state, &state.mail.addresses[address_id].member, now)?;
        }
        _ => directory_access(state, &request.key, now)?,
    }
    if mutate {
        if let Some(receipt) = state.receipts.get(&receipt_key) {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            return Ok(receipt.reply.clone());
        }
        state.receipts.retain(|_, receipt| receipt.expires >= now);
        authority::mutation_capacity(state, &request.key, now)?;
    }
    state.mail.packages.retain(|_, p| p.package.expires > now);
    state.mail.claims.retain(|_, c| c.expires > now);
    state
        .mail
        .consumed
        .retain(|_, package| package.retain_until > now);
    let result = match &request.request.command {
        Command::MailAddressCreate { manifest: object } => {
            let value = manifest(object, &state.network)?;
            expiry(value.expires, now)?;
            if value.generation != 1 || value.previous_digest.is_some() || value.deleted {
                return Err("MailGenerationConflict");
            }
            if state.mail.addresses.contains_key(&value.address_id) {
                return Err("MailAddressExists");
            }
            if state.mail.addresses.len() >= 64 {
                return Err("MailQuotaExceeded");
            }
            check_keys(state, &value, None, signing)?;
            for host in &value.storage_hosts {
                if !state
                    .mail
                    .hosts
                    .get(host)
                    .is_some_and(|h| h.active && h.body.expires > now)
                {
                    return Err("MailPlacementDenied");
                }
            }
            let digest = object_digest(MANIFEST, object)?;
            for d in &value.devices {
                state.mail.device_history.insert(d.request_key.clone());
                state
                    .mail
                    .device_history
                    .insert(d.mls_signature_key.clone());
            }
            state.mail.addresses.insert(
                value.address_id.clone(),
                AddressRecord {
                    member: request.key.clone(),
                    manifest: object.clone(),
                    digest: digest.clone(),
                },
            );
            json!({"addressId":value.address_id,"generation":value.generation,"manifestDigest":digest})
        }
        Command::MailAddressUpdate {
            address_id,
            expected_generation,
            manifest: object,
        }
        | Command::MailAddressDelete {
            address_id,
            expected_generation,
            manifest: object,
        } => {
            let old_record = state
                .mail
                .addresses
                .get(address_id)
                .ok_or("MailUnavailable")?
                .clone();
            let old = manifest(&old_record.manifest, &state.network)?;
            let value = manifest(object, &state.network)?;
            expiry(value.expires, now)?;
            if old.deleted
                || old.generation != *expected_generation
                || value.generation
                    != expected_generation
                        .checked_add(1)
                        .ok_or("MailQuotaExceeded")?
                || value.previous_digest.as_deref() != Some(&old_record.digest)
                || value.address_id != *address_id
                || value.owner_key != old.owner_key
                || value.deleted
                    != matches!(request.request.command, Command::MailAddressDelete { .. })
            {
                return Err("MailGenerationConflict");
            }
            check_keys(state, &value, Some(&old), signing)?;
            for host in &value.storage_hosts {
                if !state
                    .mail
                    .hosts
                    .get(host)
                    .is_some_and(|h| h.active && h.body.expires > now)
                {
                    return Err("MailPlacementDenied");
                }
            }
            let digest = object_digest(MANIFEST, object)?;
            for d in &value.devices {
                state.mail.device_history.insert(d.request_key.clone());
                state
                    .mail
                    .device_history
                    .insert(d.mls_signature_key.clone());
            }
            state
                .mail
                .packages
                .retain(|_, p| p.address_id != *address_id);
            state.mail.claims.retain(|_, c| {
                c.recipient_address != *address_id && c.sender_address != *address_id
            });
            state.mail.addresses.insert(
                address_id.clone(),
                AddressRecord {
                    member: old_record.member,
                    manifest: object.clone(),
                    digest: digest.clone(),
                },
            );
            json!({"addressId":address_id,"generation":value.generation,"manifestDigest":digest})
        }
        Command::MailAddressGet { address_id } => {
            protocol::fixed_hex::<32>(address_id)?;
            let record = state
                .mail
                .addresses
                .get(address_id)
                .ok_or("MailUnavailable")?;
            json!({"manifest":record.manifest,"authorityRevision":revision,"validUntil":now+5})
        }
        Command::MailHostRegister { consent } => {
            let value = host_consent(consent, &state.network)?;
            expiry(value.expires, now)?;
            if value.host_key != request.key
                || state.members[&request.key].grants != types::MEMBER | types::HOST
                || state.consents.contains_key(&request.key)
                || state.bridge_consents.contains_key(&request.key)
                || state.transfers.hosts.contains_key(&request.key)
                || state.ssh.services.contains_key(&request.key)
                || (state.mail.device_history.contains(&request.key)
                    || state.ssh.key_history.contains(&request.key))
                || state
                    .mail
                    .addresses
                    .values()
                    .any(|r| r.manifest.public_key == request.key)
                || certificate != Some(value.certificate_digest.as_str())
                || value.authority_signer != hex::encode(signing.verifying_key().as_bytes())
            {
                return Err("SeparateMailIdentityRequired");
            }
            let next = state
                .mail
                .hosts
                .get(&request.key)
                .map(|h| h.body.generation.checked_add(1).ok_or("MailQuotaExceeded"))
                .transpose()?
                .unwrap_or(1);
            if value.generation != next {
                return Err("MailGenerationConflict");
            }
            if !state.mail.hosts.contains_key(&request.key) && state.mail.hosts.len() >= 16 {
                return Err("MailQuotaExceeded");
            }
            let digest = object_digest(crate::mail_types::HOST, consent)?;
            state.mail.hosts.insert(
                request.key.clone(),
                HostRecord {
                    consent: consent.clone(),
                    digest: digest.clone(),
                    body: value.clone(),
                    active: true,
                },
            );
            json!({"hostKey":value.host_key,"generation":value.generation,"consentDigest":digest})
        }
        Command::MailHostWithdraw {
            host_key,
            expected_generation,
        } => {
            let host = state
                .mail
                .hosts
                .get_mut(host_key)
                .ok_or("MailUnavailable")?;
            if host.body.generation != *expected_generation {
                return Err("MailGenerationConflict");
            }
            host.active = false;
            json!({"hostKey":host_key,"generation":expected_generation,"active":false})
        }
        Command::MailHosts => {
            let hosts: Vec<_> = state
                .mail
                .hosts
                .values()
                .filter(|host| {
                    host.active
                        && host.body.expires > now
                        && authority::require(
                            state,
                            &host.body.host_key,
                            types::MEMBER | types::HOST,
                            now,
                        )
                        .is_ok()
                })
                .map(|h| &h.consent)
                .collect();
            json!({"hosts":hosts,"authoritySigner":hex::encode(signing.verifying_key().as_bytes()),"authorityRevision":revision,"validUntil":now+5})
        }
        Command::MailKeyPackagesPublish {
            address_id,
            device_id,
            manifest_generation,
            packages,
        } => {
            let (_, value) = address(state, address_id, now)?;
            device(&value, &request.key, device_id, "Read", now)?;
            if value.generation != *manifest_generation {
                return Err("MailGenerationConflict");
            }
            if packages.is_empty() || packages.len() > 8 {
                return Err("MailQuotaExceeded");
            }
            let mut published = 0;
            let mut consumed_references = Vec::new();
            let mut seen = BTreeSet::new();
            for package in packages {
                let bytes = URL_SAFE_NO_PAD
                    .decode(&package.package)
                    .map_err(|_| "MailInvalidObject")?;
                let reference = URL_SAFE_NO_PAD
                    .decode(&package.reference)
                    .map_err(|_| "MailInvalidObject")?;
                let hash = hash(&bytes);
                expiry(package.expires, now)?;
                if bytes.is_empty()
                    || bytes.len() > 4096
                    || reference.len() != 32
                    || package.device_id != *device_id
                    || package.expires > value.expires
                    || !seen.insert(hash.clone())
                {
                    return Err("MailInvalidObject");
                }
                if let Some(old) = state.mail.packages.get(&hash) {
                    if old.address_id != *address_id
                        || old.generation != value.generation
                        || old.package.reference != package.reference
                        || old.package.device_id != *device_id
                        || old.package.expires != package.expires
                    {
                        return Err("MailInvalidObject");
                    }
                    continue;
                }
                if let Some(old) = state.mail.consumed.get(&hash) {
                    if old.address_id != *address_id
                        || old.device_id != *device_id
                        || old.generation != value.generation
                        || old.reference != package.reference
                        || old.expires != package.expires
                    {
                        return Err("MailKeyPackageConsumed");
                    }
                    consumed_references.push(package.reference.clone());
                    continue;
                }
                let count = state
                    .mail
                    .packages
                    .values()
                    .filter(|p| p.address_id == *address_id && p.package.device_id == *device_id)
                    .count();
                if count >= 32 || state.mail.packages.len() >= 256 {
                    return Err("MailQuotaExceeded");
                }
                state.mail.packages.insert(
                    hash,
                    PackageRecord {
                        address_id: address_id.clone(),
                        generation: value.generation,
                        package: package.clone(),
                    },
                );
                published += 1;
            }
            json!({"published":published,"consumedReferences":consumed_references})
        }

        Command::MailKeyPackagesClaim {
            sender_address,
            sender_device,
            recipient_address,
            recipient_manifest_digest,
            claim_id,
            expires,
        } => {
            let (_, sender) = address(state, sender_address, now)?;
            let sending = device(&sender, &request.key, sender_device, "Send", now)?;
            let (record, recipient) = address(state, recipient_address, now)?;
            protocol::fixed_hex::<16>(claim_id)?;
            expiry(*expires, now)?;
            if record.digest != *recipient_manifest_digest {
                return Err("MailGenerationConflict");
            }
            if *expires > now + recipient.retention_seconds
                || *expires > sender.expires
                || *expires > sending.expires
                || *expires > recipient.expires
            {
                return Err("InvalidExpiry");
            }
            let id = format!("{sender_address}/{claim_id}");
            if let Some(claim) = state.mail.claims.get(&id) {
                if claim.sender_device != *sender_device
                    || claim.recipient_address != *recipient_address
                    || claim.recipient_manifest_digest != *recipient_manifest_digest
                    || claim.expires != *expires
                {
                    return Err("MailClaimConflict");
                }
                json!({"claim":claim})
            } else {
                if state.mail.claims.len() >= 128
                    || state
                        .mail
                        .claims
                        .values()
                        .filter(|c| c.sender_address == *sender_address)
                        .count()
                        >= 16
                    || state
                        .mail
                        .claims
                        .values()
                        .filter(|c| c.recipient_address == *recipient_address)
                        .count()
                        >= 32
                {
                    return Err("MailQuotaExceeded");
                }
                let receiving: Vec<_> = recipient
                    .devices
                    .iter()
                    .filter(|d| d.permissions.iter().any(|p| p == "Read") && d.expires > now)
                    .collect();
                if receiving.is_empty() {
                    return Err("MailKeyPackagesUnavailable");
                }
                let mut chosen = Vec::new();
                for receiver in receiving {
                    if receiver.expires < *expires {
                        return Err("MailKeyPackagesUnavailable");
                    }
                    let (hash, package) = state
                        .mail
                        .packages
                        .iter()
                        .find(|(_, p)| {
                            p.address_id == *recipient_address
                                && p.generation == recipient.generation
                                && p.package.device_id == receiver.device_id
                                && p.package.expires >= *expires
                        })
                        .ok_or("MailKeyPackagesUnavailable")?;
                    chosen.push((hash.clone(), package.package.clone()));
                }
                if state.mail.consumed.len() + chosen.len() > 4096 {
                    return Err("MailQuotaExceeded");
                }
                let claim = KeyPackageClaim {
                    version: 1,
                    network: state.network.clone(),
                    sender_address: sender_address.clone(),
                    sender_device: sender_device.clone(),
                    claim_id: claim_id.clone(),
                    recipient_address: recipient_address.clone(),
                    recipient_generation: recipient.generation,
                    recipient_manifest_digest: record.digest.clone(),
                    expires: *expires,
                    packages: chosen.iter().map(|(_, p)| p.clone()).collect(),
                };
                for (hash, package) in chosen {
                    state.mail.packages.remove(&hash);
                    state.mail.consumed.insert(
                        hash,
                        ConsumedPackage {
                            address_id: recipient_address.clone(),
                            device_id: package.device_id,
                            generation: recipient.generation,
                            reference: package.reference,
                            expires: package.expires,
                            retain_until: now + MAX_LIFETIME,
                        },
                    );
                }
                state.mail.claims.insert(id, claim.clone());
                json!({"claim":claim})
            }
        }
        Command::MailKeyPackagesClaimStatus {
            sender_address,
            sender_device,
            claim_id,
        } => {
            let (_, value) = address(state, sender_address, now)?;
            device(&value, &request.key, sender_device, "Send", now)?;
            protocol::fixed_hex::<16>(claim_id)?;
            let claim = state
                .mail
                .claims
                .get(&format!("{sender_address}/{claim_id}"));
            if claim.is_some_and(|c| c.sender_device != *sender_device) {
                return Err("MailPermissionDenied");
            }
            json!({"claim":claim})
        }
        _ => return Err("UnsupportedCommand"),
    };
    if mutate {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }

    state.high_water_time = state.high_water_time.max(now);
    let reply = Reply::success(state.epoch, result);
    if mutate {
        state.receipts.insert(
            receipt_key,
            types::Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
}

pub fn operation(
    object: &SignedMailObject,
    network: &str,
    now: u64,
) -> Result<MailOperation, Failure> {
    let value: MailOperation = verify(OPERATION, object, network)?;
    protocol::fixed_hex::<16>(&value.operation_id)?;
    protocol::fixed_hex::<32>(&value.host_key)?;
    protocol::fixed_hex::<32>(&value.address_id)?;
    protocol::fixed_hex::<32>(&value.device_id)?;
    protocol::fixed_hex::<32>(&value.manifest_digest)?;
    if value.version != 1
        || value.network != network
        || value.issued_at > now.saturating_add(30)
        || value.issued_at.saturating_add(60) < now
    {
        return Err("MailStaleOperation");
    }
    if let Some(id) = &value.message_id {
        protocol::fixed_hex::<16>(id)?;
    }
    if let Some(id) = &value.after {
        protocol::fixed_hex::<16>(id)?;
    }
    if let Some(digest) = &value.payload_digest {
        protocol::fixed_hex::<32>(digest)?;
    }
    let valid = match value.action.as_str() {
        "Put" => {
            value.route.is_some()
                && value.message_id.is_some()
                && value.payload_digest.is_some()
                && value.payload_bytes > 0
                && value.payload_bytes <= MAX_CIPHERTEXT as u64
                && value.after.is_none()
        }
        "Receipt" => {
            value.route.is_some()
                && value.message_id.is_some()
                && value.payload_digest.is_some()
                && value.payload_bytes == 0
                && value.after.is_none()
        }
        "List" => {
            value.route.is_none()
                && value.message_id.is_none()
                && value.payload_digest.is_none()
                && value.payload_bytes == 0
        }
        "Fetch" => {
            value.route.is_none()
                && value.message_id.is_some()
                && value.payload_digest.is_none()
                && value.payload_bytes == 0
                && value.after.is_none()
        }
        "Acknowledge" | "Delete" => {
            value.route.is_none()
                && value.message_id.is_some()
                && value.payload_digest.is_some()
                && value.payload_bytes == 0
                && value.after.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err("MailInvalidObject");
    }
    Ok(value)
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
    let signing = signer(state, key)?;
    let host_key = match &request.request.command {
        Command::MailAuthorise { host_key, .. } | Command::MailPolicySync { host_key } => host_key,
        _ => return Err("UnsupportedCommand"),
    };
    if host_key != &request.key {
        return Err("MailPermissionDenied");
    }
    let host = live_host(state, host_key, certificate, now)?;
    let host_until = host.body.expires.min(state.members[host_key].expires);
    if let Command::MailPolicySync { .. } = &request.request.command {
        let mut selected = Vec::new();
        let mut expires = (now + 5).min(host_until);
        for id in state.mail.addresses.keys() {
            if let Ok((record, value)) = address(state, id, now)
                && value.storage_hosts.contains(host_key)
            {
                expires = expires
                    .min(value.expires)
                    .min(state.members[&record.member].expires);
                selected.push(MailPlacement {
                    address_id: id.clone(),
                    generation: value.generation,
                    manifest_digest: record.digest.clone(),
                    retention_seconds: value.retention_seconds,
                });
            }
        }
        let policy = MailPolicy {
            version: 1,
            network: state.network.clone(),
            host_key: host_key.clone(),
            host_generation: host.body.generation,
            authority_epoch: state.epoch,
            authority_revision: revision,
            issued_at: now,
            expires,
            addresses: selected,
        };
        return Ok(Reply::success(
            state.epoch,
            json!({"policy":sign(POLICY,&state.network,&policy,signing)?}),
        ));
    }
    let Command::MailAuthorise {
        operation: object, ..
    } = &request.request.command
    else {
        unreachable!()
    };
    let op = operation(object, &state.network, now)?;
    if op.host_key != *host_key {
        return Err("MailPermissionDenied");
    }
    let (record, actor) = address(state, &op.address_id, now)?;
    if record.digest != op.manifest_digest || actor.generation != op.manifest_generation {
        return Err("MailGenerationConflict");
    }
    let scope = match op.action.as_str() {
        "Put" | "Receipt" => "Send",
        "Delete" => "Delete",
        _ => "Read",
    };
    let mut expires = (now + 5)
        .min(host_until)
        .min(actor.expires)
        .min(state.members[&record.member].expires);
    if object.public_key == actor.owner_key
        && op.action == "Delete"
        && op.device_id == op.address_id
    {
    } else {
        expires =
            expires.min(device(&actor, &object.public_key, &op.device_id, scope, now)?.expires);
    }
    if matches!(op.action.as_str(), "Put" | "Receipt") {
        let route = op.route.as_ref().ok_or("MailInvalidObject")?;
        protocol::fixed_hex::<16>(&route.claim_id)?;
        let (recipient_record, recipient) = address(state, &route.recipient_address, now)?;
        if route.version != 1
            || route.profile != "HyperNetMailMls1"
            || route.network != state.network
            || route.sender_address != op.address_id
            || op.message_id.as_ref() != Some(&route.message_id)
            || !recipient.storage_hosts.contains(host_key)
        {
            return Err("MailPlacementDenied");
        }
        expires = expires
            .min(recipient.expires)
            .min(state.members[&recipient_record.member].expires);
        if op.action == "Put" {
            if route.sender_device != op.device_id
                || route.expires <= now
                || route.expires > now + recipient.retention_seconds
                || route.recipient_generation != recipient.generation
                || route.recipient_manifest_digest != recipient_record.digest
            {
                return Err("MailGenerationConflict");
            }
            let claim = state
                .mail
                .claims
                .get(&format!("{}/{}", route.sender_address, route.claim_id))
                .ok_or("MailClaimConflict")?;
            if claim.sender_device != route.sender_device
                || claim.recipient_address != route.recipient_address
                || claim.recipient_manifest_digest != route.recipient_manifest_digest
                || claim.recipient_generation != route.recipient_generation
                || claim.expires < route.expires
                || claim.expires <= now
            {
                return Err("MailClaimConflict");
            }
            expires = expires.min(route.expires).min(claim.expires);
        }
    } else if !actor.storage_hosts.contains(host_key) {
        return Err("MailPlacementDenied");
    }
    let permission = MailPermission {
        version: 1,
        network: state.network.clone(),
        authority_epoch: state.epoch,
        authority_revision: revision,
        host_key: host_key.clone(),
        host_generation: host.body.generation,
        operation_digest: object_digest(OPERATION, object)?,
        address_id: op.address_id,
        manifest_generation: op.manifest_generation,
        manifest_digest: op.manifest_digest,
        issued_at: now,
        expires,
    };
    Ok(Reply::success(
        state.epoch,
        json!({"permission":sign(PERMISSION,&state.network,&permission,signing)?}),
    ))
}

#[cfg(test)]
#[path = "../Tests/MailAuthority.rs"]
mod tests;
