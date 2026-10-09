// SPDX-License-Identifier: MIT
// Native SSH access requires an explicit member grant and service-operator acceptance.
use crate::{
    authority,
    mail_authority::{self, object_digest, sign, verify},
    page_authority,
    protocol::{self, VerifiedRequest},
    ssh_types::*,
    transfer_authority::{check_state, expiry, label, signing},
    types::{self, Command, Envelope, Reply, State},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use serde_json::json;
type Failure = &'static str;
pub fn public_key(value: &str) -> Result<String, Failure> {
    let encoded = value.strip_prefix("ssh-ed25519 ").ok_or("SshInvalidKey")?;
    let bytes = STANDARD.decode(encoded).map_err(|_| "SshInvalidKey")?;
    if STANDARD.encode(&bytes) != encoded
        || bytes.len() != 51
        || bytes[..19]
            != [
                0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0,
                0, 0, 32,
            ]
    {
        return Err("SshInvalidKey");
    }
    ed25519_dalek::VerifyingKey::from_bytes(bytes[19..].try_into().unwrap())
        .map_err(|_| "SshInvalidKey")?;
    Ok(hex::encode(&bytes[19..]))
}
fn unassigned(state: &State, key: &str) -> bool {
    !mail_authority::reserved_identity_conflict(state, key)
}
pub fn consent(object: &Envelope, network: &str) -> Result<SshConsent, Failure> {
    let value: SshConsent = verify(CONSENT, object, network)?;
    public_key(&value.ssh_host_key)?;
    for digest in [
        &value.service_key,
        &value.command_digest,
        &value.image_digest,
        &value.authority_signer,
        &value.certificate_digest,
    ] {
        protocol::fixed_hex::<32>(digest)?;
    }
    let endpoint = reqwest::Url::parse(&value.endpoint).map_err(|_| "SshInvalidConsent")?;
    let authority =
        reqwest::Url::parse(&value.authority_endpoint).map_err(|_| "SshInvalidConsent")?;
    for url in [&endpoint, &authority] {
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("SshInvalidConsent");
        }
    }
    if value.version != 1
        || value.network != network
        || value.service_key != object.public_key
        || value.generation == 0
        || endpoint.scheme() != "ssh"
        || endpoint.port() != Some(value.address.port())
        || authority.scheme() != "https"
        || authority.port_or_known_default() != Some(value.authority_address.port())
        || value.address.port() == 0
        || value.authority_address.port() == 0
        || value.address.ip().is_unspecified()
        || value.authority_address.ip().is_unspecified()
        || value.account != "HyperNetService"
        || !label(&value.purpose)
        || !(128 * 1024 * 1024..=8 * 1024 * 1024 * 1024).contains(&value.memory_bytes)
        || !(32..=512).contains(&value.pids)
        || value.cpu_period != 100000
        || !(1000..=800000).contains(&value.cpu_quota)
        || !(8 * 1024 * 1024..=64 * 1024 * 1024).contains(&value.state_bytes)
        || !value.state_bytes.is_multiple_of(4096)
        || !(1..=300).contains(&value.maximum_session_seconds)
    {
        return Err("SshInvalidConsent");
    }
    Ok(value)
}
fn service<'a>(state: &'a State, key: &str, now: u64) -> Result<&'a ServiceRecord, Failure> {
    authority::require(state, key, types::MEMBER | types::HOST, now)?;
    let service = state.ssh.services.get(key).ok_or("SshUnavailable")?;
    if !service.active
        || service.body.expires <= now
        || state.members[key].grants != types::MEMBER | types::HOST
    {
        return Err("SshConsentRequired");
    }
    Ok(service)
}
fn operator(state: &State, key: &str, certificate: Option<&str>, now: u64) -> Result<(), Failure> {
    let s = service(state, key, now)?;
    if certificate != Some(s.body.certificate_digest.as_str()) {
        return Err("ClientCertificateRequired");
    }
    Ok(())
}
pub fn read_only(command: &Command) -> bool {
    matches!(command, Command::SshAuthorise { .. })
}
pub fn handles(command: &Command) -> bool {
    read_only(command)
        || matches!(
            command,
            Command::SshServiceRegister { .. }
                | Command::SshServiceWithdraw { .. }
                | Command::SshServices
                | Command::SshServiceGet { .. }
                | Command::SshGrantCreate { .. }
                | Command::SshGrantAccept { .. }
                | Command::SshGrantRevoke { .. }
                | Command::SshGrantGet { .. }
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
        Command::SshServiceRegister { .. } => {
            authority::require(state, &request.key, types::MEMBER | types::HOST, now)?
        }
        Command::SshServiceWithdraw { service_key, .. } => {
            if request.key != *service_key || !state.ssh.services.contains_key(service_key) {
                return Err("SshPermissionDenied");
            }
        }
        Command::SshGrantAccept { .. } => operator(state, &request.key, certificate, now)?,
        Command::SshGrantGet { grant_id } | Command::SshGrantRevoke { grant_id } => {
            let grant = state.ssh.grants.get(grant_id).ok_or("SshUnavailable")?;
            if request.key == grant.member_key {
                page_authority::client(state, &request.key, now)?;
            } else if request.key == grant.service_key {
                if matches!(request.request.command, Command::SshGrantGet { .. }) {
                    operator(state, &request.key, certificate, now)?;
                }
            } else {
                return Err("SshPermissionDenied");
            }
        }
        _ => page_authority::client(state, &request.key, now)?,
    }
    if let Command::SshGrantCreate {
        ssh_public_key,
        ssh_key_proof,
        ..
    } = &request.request.command
    {
        crate::ssh_proof::verify(ssh_key_proof, &state.network, &request.key, ssh_public_key)?;
        let native = public_key(ssh_public_key)?;
        if (!unassigned(state, &native) && state.ssh.key_owners.get(&native) != Some(&request.key))
            || state
                .ssh
                .key_owners
                .get(&native)
                .is_some_and(|owner| owner != &request.key)
        {
            return Err("SshPermissionDenied");
        }
    }
    // Accepted key roles outlive short grants; pending requests reserve no native keys.
    state.ssh.grants.retain(|_, grant| grant.expires > now);
    let read = matches!(
        request.request.command,
        Command::SshServices | Command::SshServiceGet { .. } | Command::SshGrantGet { .. }
    );
    state.receipts.retain(|_, r| r.expires >= now);
    let rid = format!("{}:{}", request.key, request.request.request_id);
    if !read {
        if let Some(receipt) = state.receipts.get(&rid) {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            return Ok(receipt.reply.clone());
        }
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let result = match &request.request.command {
        Command::SshServiceRegister { consent: object } => {
            let body = consent(object, &state.network)?;
            expiry(body.expires, now)?;
            let native = public_key(&body.ssh_host_key)?;
            let old = state.ssh.services.get(&request.key);
            if body.service_key != request.key
                || state.members[&request.key].grants != types::MEMBER | types::HOST
                || state.consents.contains_key(&request.key)
                || state.bridge_consents.contains_key(&request.key)
                || state.mail.hosts.contains_key(&request.key)
                || state.transfers.hosts.contains_key(&request.key)
                || certificate != Some(body.certificate_digest.as_str())
                || body.authority_signer != hex::encode(key.verifying_key().as_bytes())
                || native == body.authority_signer
                || body.expires > state.members[&request.key].expires
                || (old.is_none_or(|r| r.body.ssh_host_key != body.ssh_host_key)
                    && !unassigned(state, &native))
            {
                return Err("SeparateServiceIdentityRequired");
            }
            if body.generation
                != old
                    .map(|r| r.body.generation.checked_add(1).ok_or("CapacityExceeded"))
                    .transpose()?
                    .unwrap_or(1)
            {
                return Err("SshGenerationConflict");
            }
            if (old.is_none() && state.ssh.services.len() >= 16)
                || (!state.ssh.key_history.contains(&native) && state.ssh.key_history.len() >= 4096)
            {
                return Err("CapacityExceeded");
            }
            state.ssh.key_history.insert(native);
            for grant in state
                .ssh
                .grants
                .values_mut()
                .filter(|g| g.service_key == request.key)
            {
                grant.revoked = true;
            }
            let record = ServiceRecord {
                consent: object.clone(),
                consent_digest: object_digest(CONSENT, object)?,
                body,
                active: true,
            };
            state
                .ssh
                .services
                .insert(request.key.clone(), record.clone());
            json!({"service":record})
        }
        Command::SshServiceWithdraw {
            service_key,
            expected_generation,
        } => {
            let s = state
                .ssh
                .services
                .get_mut(service_key)
                .ok_or("SshUnavailable")?;
            if s.body.generation != *expected_generation {
                return Err("SshGenerationConflict");
            }
            s.active = false;
            for g in state
                .ssh
                .grants
                .values_mut()
                .filter(|g| g.service_key == *service_key)
            {
                g.revoked = true;
            }
            json!({"serviceKey":service_key,"active":false})
        }
        Command::SshServices => {
            json!({"services":state.ssh.services.iter().filter(|(k,_)|service(state,k,now).is_ok()).map(|(_,s)|s).collect::<Vec<_>>()})
        }
        Command::SshServiceGet { service_key } => {
            json!({"service":service(state,service_key,now)?})
        }
        Command::SshGrantCreate {
            grant_id,
            service_key,
            service_generation,
            ssh_public_key,
            ssh_key_proof: _,
            account,
            purpose,
            expires,
        } => {
            protocol::fixed_hex::<16>(grant_id)?;
            let native = public_key(ssh_public_key)?;
            let s = service(state, service_key, now)?;
            if let Some(g) = state.ssh.grants.get(grant_id) {
                if g.member_key != request.key
                    || g.service_key != *service_key
                    || g.service_generation != *service_generation
                    || g.ssh_public_key != *ssh_public_key
                    || g.account != *account
                    || g.purpose != *purpose
                    || g.expires != *expires
                {
                    return Err("SshGrantConflict");
                }
                if g.revoked {
                    return Err("SshUnavailable");
                }
                return Ok(Reply::success(state.epoch, json!({"grant":g})));
            }
            if *service_generation != s.body.generation
                || *account != s.body.account
                || *purpose != s.body.purpose
                || *expires <= now
                || *expires > now + s.body.maximum_session_seconds
                || *expires > s.body.expires
                || *expires > state.members[&request.key].expires
                || native == hex::encode(key.verifying_key().as_bytes())
            {
                return Err("SshPermissionDenied");
            }
            if state.ssh.grants.len() >= 256
                || state
                    .ssh
                    .grants
                    .values()
                    .filter(|g| g.member_key == request.key)
                    .count()
                    >= 32
            {
                return Err("CapacityExceeded");
            }
            let grant = Grant {
                grant_id: grant_id.clone(),
                service_key: service_key.clone(),
                service_generation: *service_generation,
                member_key: request.key.clone(),
                ssh_public_key: ssh_public_key.clone(),
                account: account.clone(),
                purpose: purpose.clone(),
                expires: *expires,
                accepted: false,
                revoked: false,
            };
            state.ssh.grants.insert(grant_id.clone(), grant.clone());
            json!({"grant":grant})
        }
        Command::SshGrantAccept { grant_id } => {
            let g = state.ssh.grants.get(grant_id).ok_or("SshUnavailable")?;
            let s = service(state, &request.key, now)?;
            page_authority::client(state, &g.member_key, now)?;
            let native = public_key(&g.ssh_public_key)?;
            if g.service_key != request.key
                || g.revoked
                || g.expires <= now
                || g.service_generation != s.body.generation
                || native == hex::encode(key.verifying_key().as_bytes())
                || (!unassigned(state, &native)
                    && state.ssh.key_owners.get(&native) != Some(&g.member_key))
                || state
                    .ssh
                    .key_owners
                    .get(&native)
                    .is_some_and(|owner| owner != &g.member_key)
            {
                return Err("SshPermissionDenied");
            }
            if state.ssh.grants.values().any(|other| {
                other.grant_id != *grant_id
                    && other.service_key == request.key
                    && other.accepted
                    && !other.revoked
                    && other.expires > now
            }) {
                return Err("SshServiceBusy");
            }
            if !state.ssh.key_history.contains(&native) && state.ssh.key_history.len() >= 4096 {
                return Err("CapacityExceeded");
            }
            state
                .ssh
                .key_owners
                .insert(native.clone(), g.member_key.clone());
            state.ssh.key_history.insert(native);
            let g = state.ssh.grants.get_mut(grant_id).unwrap();
            g.accepted = true;
            json!({"grant":g})
        }
        Command::SshGrantRevoke { grant_id } => {
            let g = state.ssh.grants.get_mut(grant_id).ok_or("SshUnavailable")?;
            g.revoked = true;
            json!({"grant":g})
        }
        Command::SshGrantGet { grant_id } => {
            json!({"grant":state.ssh.grants.get(grant_id).ok_or("SshUnavailable")?})
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
            rid,
            types::Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(reply)
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
    let Command::SshAuthorise {
        service_key,
        grant_id,
    } = &request.request.command
    else {
        return Err("UnsupportedCommand");
    };
    if *service_key != request.key {
        return Err("SshPermissionDenied");
    }
    operator(state, service_key, certificate, now)?;
    let s = service(state, service_key, now)?;
    let g = state.ssh.grants.get(grant_id).ok_or("SshUnavailable")?;
    page_authority::client(state, &g.member_key, now)?;
    if !g.accepted
        || g.revoked
        || g.service_key != *service_key
        || g.service_generation != s.body.generation
        || g.expires <= now
    {
        return Err("SshPermissionDenied");
    }
    let expires = (now + 5)
        .min(g.expires)
        .min(s.body.expires)
        .min(state.members[service_key].expires)
        .min(state.members[&g.member_key].expires);
    let lease = Lease {
        version: 1,
        network: state.network.clone(),
        authority_epoch: state.epoch,
        authority_revision: revision,
        service_key: service_key.clone(),
        service_generation: s.body.generation,
        consent_digest: s.consent_digest.clone(),
        issued_at: now,
        expires,
        grant: g.clone(),
    };
    Ok(Reply::success(
        state.epoch,
        json!({"lease":sign(LEASE,&state.network,&lease,key)?}),
    ))
}

#[cfg(test)]
#[path = "../Tests/SshAuthority.rs"]
mod tests;
