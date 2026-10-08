// SPDX-License-Identifier: MIT
use crate::{
    authority, bridge, markup, page_authority,
    protocol::{self, VerifiedRequest},
    types::*,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const ADMISSION: &[u8] = b"HyperNet/FederationAdmission/1\0";
const EXPORT: &[u8] = b"HyperNet/FederationExport/1\0";
pub const MAX_BLOB: usize = 64 * 1024;
const MAX_PROOF: usize = 4096;

fn encoded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "InvalidFederationObject")?;
    if bytes.len() > limit {
        return Err("FederationObjectTooLarge");
    }
    Ok(bytes)
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, &'static str> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&encoded(value, MAX_PROOF)?);
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn treaty_digest(treaty: &FederationTreaty) -> Result<String, &'static str> {
    validate_treaty(treaty)?;
    digest(b"HyperNet/FederationTreaty/1\0", treaty)
}

pub fn descriptor_digest(descriptor: &PageDescriptor) -> Result<String, &'static str> {
    digest(b"HyperNet/FederationPage/1\0", descriptor)
}

fn validate_treaty(treaty: &FederationTreaty) -> Result<(), &'static str> {
    protocol::fixed_hex::<16>(&treaty.agreement_id)?;
    for value in [
        &treaty.source_network,
        &treaty.destination_network,
        &treaty.source_authority_key,
        &treaty.destination_authority_key,
        &treaty.source_bridge_key,
        &treaty.destination_bridge_key,
    ] {
        protocol::fixed_hex::<32>(value)?;
    }
    let keys = [
        &treaty.source_authority_key,
        &treaty.destination_authority_key,
        &treaty.source_bridge_key,
        &treaty.destination_bridge_key,
    ];
    for (index, key) in keys.iter().enumerate() {
        VerifyingKey::from_bytes(&protocol::fixed_hex::<32>(key)?).map_err(|_| "InvalidKey")?;
        if keys[..index].contains(key) {
            return Err("SeparateFederationIdentityRequired");
        }
    }
    if treaty.version != 1
        || treaty.service != "Pages"
        || treaty.profile != "HyperNetPage/1"
        || treaty.source_network == treaty.destination_network
        || !markup::namespace(&treaty.source_namespace)
        || !markup::namespace(&treaty.destination_namespace)
    {
        return Err("InvalidFederationTreaty");
    }
    Ok(())
}

fn evidence_message(domain: &[u8], evidence: &SignedEvidence) -> Result<Vec<u8>, &'static str> {
    encoded(evidence, MAX_PROOF)?;
    let payload = URL_SAFE_NO_PAD
        .decode(&evidence.payload)
        .map_err(|_| "InvalidFederationEvidence")?;
    let mut message = domain.to_vec();
    message.extend_from_slice(&payload);
    Ok(message)
}

fn evidence_digest(domain: &[u8], evidence: &SignedEvidence) -> Result<String, &'static str> {
    Ok(hex::encode(Sha256::digest(evidence_message(
        domain, evidence,
    )?)))
}

fn sign<T: Serialize>(
    domain: &[u8],
    value: &T,
    key: &SigningKey,
) -> Result<SignedEvidence, &'static str> {
    let payload = encoded(value, 2800)?;
    let mut message = domain.to_vec();
    message.extend_from_slice(&payload);
    Ok(SignedEvidence {
        public_key: hex::encode(key.verifying_key().as_bytes()),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: hex::encode(key.sign(&message).to_bytes()),
    })
}

fn verify<T: DeserializeOwned>(
    domain: &[u8],
    evidence: &SignedEvidence,
    public: &str,
) -> Result<T, &'static str> {
    if evidence.public_key != public {
        return Err("WrongFederationAuthority");
    }
    let message = evidence_message(domain, evidence)?;
    VerifyingKey::from_bytes(&protocol::fixed_hex::<32>(public)?)
        .map_err(|_| "InvalidKey")?
        .verify_strict(
            &message,
            &Signature::from_bytes(&protocol::fixed_hex::<64>(&evidence.signature)?),
        )
        .map_err(|_| "InvalidFederationSignature")?;
    serde_json::from_slice(&message[domain.len()..]).map_err(|_| "InvalidFederationEvidence")
}

pub fn verify_admission(
    treaty: &FederationTreaty,
    evidence: &SignedEvidence,
    now: u64,
) -> Result<FederationAdmission, &'static str> {
    let value: FederationAdmission =
        verify(ADMISSION, evidence, &treaty.destination_authority_key)?;
    protocol::fixed_hex::<16>(&value.request_id)?;
    protocol::fixed_hex::<32>(&value.destination_profile)?;
    if value.version != 1
        || value.agreement_digest != treaty_digest(treaty)?
        || value.source_network != treaty.source_network
        || value.destination_network != treaty.destination_network
        || value.source_bridge_key != treaty.source_bridge_key
        || value.destination_bridge_key != treaty.destination_bridge_key
        || value.authority_revision == 0
        || value.issued_at > now
        || value.valid_until <= now
        || value.valid_until <= value.issued_at
        || value.valid_until > value.issued_at.saturating_add(5)
        || value.valid_until > treaty.expires
    {
        return Err("StaleFederationAdmission");
    }
    Ok(value)
}

pub fn verify_export(
    treaty: &FederationTreaty,
    admission: &SignedEvidence,
    evidence: &SignedEvidence,
    now: u64,
) -> Result<FederationExportEvidence, &'static str> {
    let permit = verify_admission(treaty, admission, now)?;
    let value: FederationExportEvidence = verify(EXPORT, evidence, &treaty.source_authority_key)?;
    protocol::fixed_hex::<32>(&value.source_profile)?;
    protocol::fixed_hex::<32>(&value.author_share_digest)?;
    if value.version != 1
        || value.agreement_digest != treaty_digest(treaty)?
        || value.admission_digest != evidence_digest(ADMISSION, admission)?
        || value.source_profile != permit.destination_profile
        || value.authority_revision == 0
        || value.issued_at > now
        || value.valid_until <= now
        || value.valid_until <= value.issued_at
        || value.valid_until > permit.valid_until
        || value.valid_until > value.issued_at.saturating_add(5)
        || value.descriptor.namespace != treaty.source_namespace
        || value.descriptor.profile != treaty.profile
        || value.descriptor.audience != "Members"
    {
        return Err("StaleFederationExport");
    }
    Ok(value)
}

pub fn verify_share(
    treaty: &FederationTreaty,
    descriptor: &PageDescriptor,
    envelope: &Envelope,
) -> Result<String, &'static str> {
    encoded(envelope, MAX_PROOF)?;
    let verified = protocol::verify_archived(envelope, &treaty.source_network)?;
    let Command::FederationShare {
        agreement_id,
        agreement_digest,
        page_id,
        publication_version,
        descriptor_digest: bound_descriptor,
        allow,
        ..
    } = &verified.request.command
    else {
        return Err("InvalidAuthorShare");
    };
    if verified.key != descriptor.author
        || !allow
        || agreement_id != &treaty.agreement_id
        || agreement_digest != &treaty_digest(treaty)?
        || page_id != &descriptor.page_id
        || *publication_version != descriptor.publication_version
        || bound_descriptor != &descriptor_digest(descriptor)?
    {
        return Err("InvalidAuthorShare");
    }
    Ok(verified.digest)
}

pub fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::FederationAccept { .. }
            | Command::FederationWithdraw { .. }
            | Command::FederationAgreements
            | Command::BridgeConsent { .. }
            | Command::BridgeWithdraw
            | Command::FederationShare { .. }
            | Command::FederationUnshare { .. }
            | Command::FederationShareStatus { .. }
            | Command::FederationPermit { .. }
            | Command::FederationExport { .. }
            | Command::FederationImport { .. }
            | Command::FederationQueue { .. }
            | Command::FederationInspect { .. }
            | Command::FederationReview { .. }
            | Command::FederationPageWithdraw { .. }
            | Command::FederationList { .. }
            | Command::FederationRead { .. }
    )
}

fn agreement<'a>(
    state: &'a State,
    id: &str,
    now: u64,
) -> Result<&'a FederationAgreement, &'static str> {
    protocol::fixed_hex::<16>(id)?;
    let value = state
        .federation_agreements
        .get(id)
        .ok_or("FederationUnavailable")?;
    if !value.active || value.treaty.expires <= now {
        return Err("FederationUnavailable");
    }
    Ok(value)
}

fn side<'a>(
    state: &State,
    treaty: &'a FederationTreaty,
    source: bool,
) -> Result<&'a str, &'static str> {
    let (network, key) = if source {
        (&treaty.source_network, &treaty.source_bridge_key)
    } else {
        (&treaty.destination_network, &treaty.destination_bridge_key)
    };
    if &state.network != network {
        return Err("WrongFederationDirection");
    }
    Ok(key)
}

fn bridge_document(
    state: &State,
    treaty: &FederationTreaty,
    key: &str,
    profile: &str,
    now: u64,
) -> Result<bridge::BridgeConsent, &'static str> {
    authority::require(state, key, MEMBER | FEDERATION, now)?;
    if state.members.get(key).ok_or("NotMember")?.grants != MEMBER | FEDERATION
        || state.consents.contains_key(key)
    {
        return Err("SeparateBridgeIdentityRequired");
    }
    let registered = state
        .bridge_consents
        .get(key)
        .ok_or("BridgeConsentRequired")?;
    if !registered.active
        || registered.expires <= now
        || registered.profile != profile
        || registered.grants != FEDERATION
    {
        return Err("BridgeConsentRequired");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(
            registered
                .document
                .as_ref()
                .ok_or("BridgeConsentRequired")?,
        )
        .map_err(|_| "InvalidBridgeConsent")?;
    if hex::encode(Sha256::digest(&bytes)) != profile {
        return Err("InvalidBridgeConsent");
    }
    let consent = bridge::verify_bridge_consent(&bytes, &state.network, key, now)
        .map_err(|_| "InvalidBridgeConsent")?;
    match_consent(treaty, &consent)?;
    if consent.expires != registered.expires {
        return Err("InvalidBridgeConsent");
    }
    Ok(consent)
}

fn match_consent(
    treaty: &FederationTreaty,
    consent: &bridge::BridgeConsent,
) -> Result<(), &'static str> {
    if consent.agreement_id != treaty.agreement_id
        || consent.treaty_digest != treaty_digest(treaty)?
        || consent.source_namespace != treaty.source_namespace
        || consent.destination_namespace != treaty.destination_namespace
        || consent.source.network != treaty.source_network
        || consent.destination.network != treaty.destination_network
        || consent.source.device_key != treaty.source_bridge_key
        || consent.destination.device_key != treaty.destination_bridge_key
        || consent.source.authority_key != treaty.source_authority_key
        || consent.destination.authority_key != treaty.destination_authority_key
        || consent.expires > treaty.expires
    {
        return Err("BridgeTreatyMismatch");
    }
    Ok(())
}

fn bridge_access(
    state: &State,
    treaty: &FederationTreaty,
    key: &str,
    profile: &str,
    certificate: Option<&str>,
    source: bool,
    now: u64,
) -> Result<(), &'static str> {
    if side(state, treaty, source)? != key {
        return Err("WrongFederationBridge");
    }
    bridge_document(state, treaty, key, profile, now)?;
    if certificate
        != Some(
            state
                .bridge_consents
                .get(key)
                .ok_or("BridgeConsentRequired")?
                .certificate
                .as_str(),
        )
    {
        return Err("ClientCertificateRequired");
    }
    Ok(())
}

pub fn preflight(
    state: &State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
) -> Result<(), &'static str> {
    if !(1..=4).contains(&state.version) {
        return Err("UnsupportedState");
    }
    if state.high_water_time > now.saturating_add(2) {
        return Err("ClockRollback");
    }
    match &request.request.command {
        Command::BridgeWithdraw => {
            if !state.members.contains_key(&request.key) {
                return Err("NotMember");
            }
        }
        Command::BridgeConsent { agreement_id, .. } => {
            authority::require(state, &request.key, MEMBER | FEDERATION, now)?;
            if state.members.get(&request.key).ok_or("NotMember")?.grants != MEMBER | FEDERATION
                || state.consents.contains_key(&request.key)
            {
                return Err("SeparateBridgeIdentityRequired");
            }
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            if request.key != treaty.source_bridge_key
                && request.key != treaty.destination_bridge_key
            {
                return Err("WrongFederationBridge");
            }
        }
        Command::FederationPermit {
            agreement_id,
            profile,
        }
        | Command::FederationImport {
            agreement_id,
            profile,
            ..
        } => {
            bridge_access(
                state,
                &agreement(state, agreement_id, now)?.treaty,
                &request.key,
                profile,
                certificate,
                false,
                now,
            )?;
        }
        Command::FederationExport {
            agreement_id,
            profile,
            ..
        } => {
            bridge_access(
                state,
                &agreement(state, agreement_id, now)?.treaty,
                &request.key,
                profile,
                certificate,
                true,
                now,
            )?;
        }
        Command::FederationAgreements => {
            authority::require(state, &request.key, MEMBER, now)?;
        }
        command => {
            page_authority::client(state, &request.key, now)?;
            if !matches!(
                command,
                Command::FederationShare { .. }
                    | Command::FederationShareStatus { .. }
                    | Command::FederationUnshare { .. }
                    | Command::FederationList { .. }
                    | Command::FederationRead { .. }
            ) {
                authority::require(state, &request.key, MEMBER | ADMIN, now)?;
            }
        }
    }
    Ok(())
}

fn object_key(agreement: &str, page: &str) -> String {
    format!("{agreement}/{page}")
}
fn share_key(agreement: &str, page: &str) -> String {
    format!("Share/{agreement}/{page}")
}
fn page_key(agreement: &str, page: &str) -> String {
    format!("Foreign/{agreement}/{page}")
}

fn share_capacity(state: &State, agreement: &str, key: &str) -> Result<(), &'static str> {
    if !state.federation_shares.contains_key(key) {
        let prefix = format!("{agreement}/");
        if state.federation_shares.len() >= 256
            || state
                .federation_shares
                .keys()
                .filter(|key| key.starts_with(&prefix))
                .count()
                >= 32
        {
            return Err("FederationQuotaExceeded");
        }
    }
    Ok(())
}

fn share_owner(
    state: &State,
    actor: &str,
    agreement: &str,
    page: &str,
) -> Result<(), &'static str> {
    protocol::fixed_hex::<16>(agreement)?;
    protocol::fixed_hex::<16>(page)?;
    let treaty = &state
        .federation_agreements
        .get(agreement)
        .ok_or("FederationUnavailable")?
        .treaty;
    side(state, treaty, true)?;
    let record = state.pages.get(page).ok_or("PageUnavailable")?;
    if record.author != actor {
        return Err("PageOwnerMismatch");
    }
    if record.namespace != treaty.source_namespace {
        return Err("PageVersionConflict");
    }
    Ok(())
}

fn share_status(state: &State, agreement: &str, page: &str) -> serde_json::Value {
    let record = state.federation_shares.get(&object_key(agreement, page));
    json!({"agreementId":agreement,"pageId":page,"generation":record.map_or(0, |value| value.generation),
        "lastWithdrawalGeneration":record.map_or(0, |value| value.last_withdrawal_generation),
        "allowed":record.is_some_and(|value| value.allowed)})
}

pub fn required_blobs(
    state: &State,
    request: &VerifiedRequest,
    now: u64,
) -> Result<Vec<String>, &'static str> {
    let mut keys = Vec::new();
    match &request.request.command {
        Command::FederationExport {
            agreement_id,
            page_id: Some(page_id),
            include_bundle,
            ..
        } => {
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            let descriptor = exportable(state, treaty, page_id, now)?;
            keys.push(share_key(agreement_id, page_id));
            if *include_bundle {
                keys.push(format!(
                    "Native/{}",
                    page_authority::publication_key(descriptor)
                ));
            }
        }
        Command::FederationImport {
            agreement_id,
            export,
            admission,
            ..
        } => {
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            let value = verify_export(treaty, admission, export, now)?;
            if state
                .federation_pages
                .contains_key(&object_key(agreement_id, &value.descriptor.page_id))
            {
                keys.push(page_key(agreement_id, &value.descriptor.page_id));
            }
        }
        Command::FederationInspect {
            agreement_id,
            page_id,
        }
        | Command::FederationRead {
            agreement_id,
            page_id,
        }
        | Command::FederationReview {
            agreement_id,
            page_id,
            ..
        } => keys.push(page_key(agreement_id, page_id)),
        _ => {}
    }
    Ok(keys)
}

fn blob<T: DeserializeOwned>(
    blobs: &BTreeMap<String, Vec<u8>>,
    key: &str,
) -> Result<T, &'static str> {
    let bytes = blobs.get(key).ok_or("FederationPageUnavailable")?;
    if bytes.len() > MAX_BLOB {
        return Err("FederationObjectTooLarge");
    }
    serde_json::from_slice(bytes).map_err(|_| "InvalidFederationObject")
}

fn exportable<'a>(
    state: &'a State,
    treaty: &FederationTreaty,
    page_id: &str,
    now: u64,
) -> Result<&'a PageDescriptor, &'static str> {
    protocol::fixed_hex::<16>(page_id)?;
    let descriptor = &page_authority::published(state, page_id, now)?.descriptor;
    let share = state
        .federation_shares
        .get(&object_key(&treaty.agreement_id, page_id))
        .ok_or("AuthorShareRequired")?;
    if !share.allowed
        || share.descriptor_digest != descriptor_digest(descriptor)?
        || descriptor.namespace != treaty.source_namespace
    {
        return Err("AuthorShareRequired");
    }
    page_authority::client(state, &descriptor.author, now).map_err(|_| "AuthorShareRequired")?;
    Ok(descriptor)
}

fn foreign_current<'a>(
    state: &'a State,
    agreement_id: &str,
    page_id: &str,
    now: u64,
) -> Result<
    (
        &'a FederationAgreement,
        &'a FederationPageRecord,
        FederationExportEvidence,
    ),
    &'static str,
> {
    let agreement = agreement(state, agreement_id, now)?;
    let key = side(state, &agreement.treaty, false)?;
    let record = state
        .federation_pages
        .get(&object_key(agreement_id, page_id))
        .ok_or("FederationPageUnavailable")?;
    let admission = verify_admission(&agreement.treaty, &record.admission, now)?;
    bridge_document(
        state,
        &agreement.treaty,
        key,
        &admission.destination_profile,
        now,
    )?;
    let export = verify_export(&agreement.treaty, &record.admission, &record.export, now)?;
    if export.descriptor != record.observed {
        return Err("InvalidFederationEvidence");
    }
    Ok((agreement, record, export))
}

fn foreign_published<'a>(
    state: &'a State,
    agreement_id: &str,
    page_id: &str,
    now: u64,
) -> Result<
    (
        &'a FederationAgreement,
        &'a FederationPageRecord,
        FederationExportEvidence,
    ),
    &'static str,
> {
    let (agreement, record, export) = foreign_current(state, agreement_id, page_id, now)?;
    let published = record
        .published
        .as_ref()
        .ok_or("FederationPageUnavailable")?;
    if published.descriptor != record.observed {
        return Err("FederationPageUnavailable");
    }
    page_authority::client(state, &published.reviewer, now)?;
    authority::require(state, &published.reviewer, MEMBER | ADMIN, now)?;
    Ok((agreement, record, export))
}

fn signer<'a>(state: &State, key: Option<&'a SigningKey>) -> Result<&'a SigningKey, &'static str> {
    let key = key.ok_or("FederationSigningKeyRequired")?;
    if state
        .members
        .contains_key(&hex::encode(key.verifying_key().as_bytes()))
    {
        return Err("DedicatedAuthorityKeyRequired");
    }
    Ok(key)
}

fn signing_for<'a>(
    state: &State,
    treaty: &FederationTreaty,
    key: Option<&'a SigningKey>,
    source: bool,
) -> Result<&'a SigningKey, &'static str> {
    side(state, treaty, source)?;
    let key = signer(state, key)?;
    let expected = if source {
        &treaty.source_authority_key
    } else {
        &treaty.destination_authority_key
    };
    if &hex::encode(key.verifying_key().as_bytes()) != expected {
        return Err("WrongFederationAuthority");
    }
    Ok(key)
}

fn bounded_until(state: &State, key: &str, treaty: &FederationTreaty, now: u64) -> u64 {
    now.saturating_add(5)
        .min(treaty.expires)
        .min(state.members.get(key).map_or(now, |member| member.expires))
        .min(
            state
                .bridge_consents
                .get(key)
                .map_or(now, |consent| consent.expires),
        )
}

pub fn apply(
    state: &mut State,
    request: &VerifiedRequest,
    certificate: Option<&str>,
    now: u64,
    revision: i64,
    blobs: &BTreeMap<String, Vec<u8>>,
    signing_key: Option<&SigningKey>,
) -> Result<page_authority::Change, &'static str> {
    preflight(state, request, certificate, now)?;
    let receipt_key = format!("{}:{}", request.key, request.request.request_id);
    let recorded = matches!(
        request.request.command,
        Command::FederationAccept { .. }
            | Command::FederationWithdraw { .. }
            | Command::BridgeConsent { .. }
            | Command::BridgeWithdraw
            | Command::FederationShare { .. }
            | Command::FederationUnshare { .. }
            | Command::FederationReview { .. }
            | Command::FederationPageWithdraw { .. }
    );
    if recorded {
        if !matches!(request.request.command, Command::FederationUnshare { .. })
            && let Some(receipt) = state.receipts.get(&receipt_key)
        {
            if receipt.digest != request.digest {
                return Err("RequestConflict");
            }
            return Ok(page_authority::Change {
                reply: receipt.reply.clone(),
                puts: Vec::new(),
                deletes: Vec::new(),
            });
        }
        state.receipts.retain(|_, value| value.expires >= now);
        authority::mutation_capacity(state, &request.key, now)?;
    }
    let mut puts = Vec::new();
    let mut changed = recorded;
    let result = match &request.request.command {
        Command::FederationAccept { treaty } => {
            let digest = treaty_digest(treaty)?;
            signing_for(
                state,
                treaty,
                signing_key,
                state.network == treaty.source_network,
            )?;
            if let Some(existing) = state.federation_agreements.get(&treaty.agreement_id) {
                if existing.treaty != *treaty || !existing.active {
                    return Err("FederationAgreementExists");
                }
                changed = false;
            } else {
                if treaty.expires <= now || treaty.expires > now.saturating_add(604800) {
                    return Err("InvalidExpiry");
                }
                if state.federation_agreements.len() >= 8 {
                    return Err("FederationQuotaExceeded");
                }
                state.federation_agreements.insert(
                    treaty.agreement_id.clone(),
                    FederationAgreement {
                        treaty: treaty.clone(),
                        digest: digest.clone(),
                        version: 1,
                        active: true,
                        source_revision: 0,
                    },
                );
            }
            json!({"agreementId":treaty.agreement_id,"agreementDigest":digest,"version":1,"active":true})
        }
        Command::FederationWithdraw {
            agreement_id,
            expected_version,
        } => {
            let value = state
                .federation_agreements
                .get_mut(agreement_id)
                .ok_or("FederationUnavailable")?;
            if value.version != *expected_version {
                return Err("FederationVersionConflict");
            }
            value.version = value.version.checked_add(1).ok_or("CapacityExceeded")?;
            value.active = false;
            json!({"agreementId":agreement_id,"version":value.version,"active":false})
        }
        Command::FederationAgreements => {
            let ordinary = page_authority::client(state, &request.key, now).is_ok();
            let entries: Vec<_> = state
                .federation_agreements
                .values()
                .filter(|value| {
                    ordinary
                        || value.treaty.source_bridge_key == request.key
                        || value.treaty.destination_bridge_key == request.key
                })
                .collect();
            json!({"entries":entries,"authorityKey":signing_key.map(|key|hex::encode(key.verifying_key().as_bytes())),"authorityRevision":revision})
        }
        Command::BridgeConsent {
            agreement_id,
            profile,
            expires,
            certificate,
            document,
        } => {
            protocol::fixed_hex::<32>(profile)?;
            protocol::fixed_hex::<32>(certificate)?;
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            side(state, treaty, state.network == treaty.source_network)?;
            let local = if state.network == treaty.source_network {
                &treaty.source_bridge_key
            } else {
                &treaty.destination_bridge_key
            };
            if local != &request.key {
                return Err("WrongFederationBridge");
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(document)
                .map_err(|_| "InvalidBridgeConsent")?;
            if bytes.len() > 16384 || hex::encode(Sha256::digest(&bytes)) != *profile {
                return Err("InvalidBridgeConsent");
            }
            let consent = bridge::verify_bridge_consent(&bytes, &state.network, &request.key, now)
                .map_err(|_| "InvalidBridgeConsent")?;
            match_consent(treaty, &consent)?;
            if *expires != consent.expires
                || *expires > state.members.get(&request.key).ok_or("NotMember")?.expires
            {
                return Err("InvalidExpiry");
            }
            state.bridge_consents.insert(
                request.key.clone(),
                Consent {
                    profile: profile.clone(),
                    grants: FEDERATION,
                    expires: *expires,
                    certificate: certificate.clone(),
                    active: true,
                    document: Some(document.clone()),
                },
            );
            json!({"deviceKey":request.key,"consent":state.bridge_consents.get(&request.key)})
        }
        Command::BridgeWithdraw => {
            if let Some(consent) = state.bridge_consents.get_mut(&request.key) {
                consent.active = false;
            }
            json!({"deviceKey":request.key,"active":false})
        }
        Command::FederationShare {
            agreement_id,
            agreement_digest,
            page_id,
            publication_version,
            descriptor_digest: bound,
            allow,
            expected_generation,
        } => {
            if !allow {
                return Err("DedicatedWithdrawalRequired");
            }
            let generation = expected_generation.ok_or("ShareGenerationRequired")?;
            let key = object_key(agreement_id, page_id);
            let current = state.federation_shares.get(&key);
            if generation != current.map_or(0, |value| value.generation) {
                return Err("ShareGenerationConflict");
            }
            let last_withdrawal_generation =
                current.map_or(0, |value| value.last_withdrawal_generation);
            let generation = generation.checked_add(1).ok_or("CapacityExceeded")?;
            let value = agreement(state, agreement_id, now)?;
            side(state, &value.treaty, true)?;
            if &value.digest != agreement_digest {
                return Err("FederationTreatyMismatch");
            }
            let descriptor = &page_authority::published(state, page_id, now)?.descriptor;
            if descriptor.author != request.key {
                return Err("PageOwnerMismatch");
            }
            if descriptor.namespace != value.treaty.source_namespace
                || descriptor.publication_version != *publication_version
                || descriptor_digest(descriptor)? != *bound
            {
                return Err("PageVersionConflict");
            }
            let key = object_key(agreement_id, page_id);
            share_capacity(state, agreement_id, &key)?;
            let bytes = encoded(&request.envelope, MAX_PROOF)?;
            state.federation_shares.insert(
                key,
                FederationShareRecord {
                    descriptor_digest: bound.clone(),
                    share_digest: request.digest.clone(),
                    allowed: *allow,
                    generation,
                    last_withdrawal_generation,
                },
            );
            puts.push((share_key(agreement_id, page_id), bytes));
            json!({"agreementId":agreement_id,"pageId":page_id,"allowed":allow,"shareDigest":request.digest,"generation":generation,"lastWithdrawalGeneration":last_withdrawal_generation})
        }
        Command::FederationShareStatus {
            agreement_id,
            page_id,
        } => {
            share_owner(state, &request.key, agreement_id, page_id)?;
            share_status(state, agreement_id, page_id)
        }
        Command::FederationUnshare {
            agreement_id,
            page_id,
            expected_generation,
        } => {
            share_owner(state, &request.key, agreement_id, page_id)?;
            let key = object_key(agreement_id, page_id);
            let current = state.federation_shares.get(&key);
            let generation = current.map_or(0, |value| value.generation);
            let withdrawn = current.map_or(0, |value| value.last_withdrawal_generation);
            // A bound retry cannot revoke a newer explicit grant after its withdrawal committed.
            if withdrawn <= *expected_generation {
                if generation != *expected_generation {
                    return Err("ShareGenerationConflict");
                }
                share_capacity(state, agreement_id, &key)?;
                let generation = generation.checked_add(1).ok_or("CapacityExceeded")?;
                let record = state
                    .federation_shares
                    .entry(key)
                    .or_insert(FederationShareRecord {
                        descriptor_digest: String::new(),
                        share_digest: String::new(),
                        allowed: false,
                        generation: 0,
                        last_withdrawal_generation: 0,
                    });
                record.allowed = false;
                record.generation = generation;
                record.last_withdrawal_generation = generation;
            }
            share_status(state, agreement_id, page_id)
        }
        Command::FederationPermit {
            agreement_id,
            profile,
        } => {
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            let key = signing_for(state, treaty, signing_key, false)?;
            let value = FederationAdmission {
                version: 1,
                agreement_digest: treaty_digest(treaty)?,
                source_network: treaty.source_network.clone(),
                destination_network: treaty.destination_network.clone(),
                source_bridge_key: treaty.source_bridge_key.clone(),
                destination_bridge_key: treaty.destination_bridge_key.clone(),
                destination_profile: profile.clone(),
                request_id: request.request.request_id.clone(),
                authority_revision: revision.try_into().map_err(|_| "AuthorityUnavailable")?,
                issued_at: now,
                valid_until: bounded_until(state, &request.key, treaty, now),
            };
            json!({"admission":sign(ADMISSION,&value,key)?})
        }
        Command::FederationExport {
            agreement_id,
            profile,
            admission,
            page_id,
            include_bundle,
        } => {
            let treaty = &agreement(state, agreement_id, now)?.treaty;
            let key = signing_for(state, treaty, signing_key, true)?;
            let permit = verify_admission(treaty, admission, now)?;
            if permit.destination_profile != *profile {
                return Err("BridgeConsentRequired");
            }
            let mut until = bounded_until(state, &request.key, treaty, now).min(permit.valid_until);
            if let Some(page_id) = page_id {
                let descriptor = exportable(state, treaty, page_id, now)?.clone();
                for identity in [&descriptor.author, &descriptor.reviewer] {
                    until = until.min(
                        state
                            .members
                            .get(identity)
                            .ok_or("PageUnavailable")?
                            .expires,
                    );
                }
                let author_share: Envelope = blob(blobs, &share_key(agreement_id, page_id))?;
                let author_share_digest = verify_share(treaty, &descriptor, &author_share)?;
                if author_share_digest
                    != state
                        .federation_shares
                        .get(&object_key(agreement_id, page_id))
                        .ok_or("AuthorShareRequired")?
                        .share_digest
                {
                    return Err("InvalidAuthorShare");
                }
                let bundle: Option<PageBundle> = if *include_bundle {
                    let bundle = blob(
                        blobs,
                        &format!("Native/{}", page_authority::publication_key(&descriptor)),
                    )?;
                    page_authority::verify_bundle(&state.network, &descriptor, &bundle)?;
                    Some(bundle)
                } else {
                    None
                };
                let value = FederationExportEvidence {
                    version: 1,
                    agreement_digest: treaty_digest(treaty)?,
                    admission_digest: evidence_digest(ADMISSION, admission)?,
                    descriptor: descriptor.clone(),
                    author_share_digest,
                    source_profile: profile.clone(),
                    authority_revision: revision.try_into().map_err(|_| "AuthorityUnavailable")?,
                    issued_at: now,
                    valid_until: until,
                };
                json!({"descriptor":descriptor,"authorShare":author_share,"bundle":bundle,"export":sign(EXPORT,&value,key)?})
            } else {
                let entries: Vec<_> = state
                    .pages
                    .keys()
                    .filter_map(|id| exportable(state, treaty, id, now).ok())
                    .collect();
                json!({"entries":entries,"authorityRevision":revision,"validUntil":until})
            }
        }
        Command::FederationImport {
            agreement_id,
            profile,
            admission,
            export,
            bundle,
            author_share,
        } => {
            let value = agreement(state, agreement_id, now)?.clone();
            let permit = verify_admission(&value.treaty, admission, now)?;
            if permit.destination_profile != *profile {
                return Err("BridgeConsentRequired");
            }
            let exported = verify_export(&value.treaty, admission, export, now)?;
            if exported.authority_revision < value.source_revision {
                return Err("SourceRevisionRollback");
            }
            let page_id = exported.descriptor.page_id.clone();
            protocol::fixed_hex::<16>(&page_id)?;
            let key = object_key(agreement_id, &page_id);
            let existing = state.federation_pages.get(&key);
            let same = existing.is_some_and(|record| record.observed == exported.descriptor);
            let mut object = if same {
                blob::<FederationPageBlob>(blobs, &page_key(agreement_id, &page_id))?
            } else {
                FederationPageBlob {
                    bundle: bundle.clone().ok_or("FederationBundleRequired")?,
                    author_share: author_share.clone().ok_or("FederationBundleRequired")?,
                    approval: None,
                }
            };
            if let Some(bundle) = bundle {
                object.bundle = bundle.clone();
            }
            if let Some(author_share) = author_share {
                object.author_share = author_share.clone();
            }
            page_authority::verify_bundle(
                &value.treaty.source_network,
                &exported.descriptor,
                &object.bundle,
            )?;
            if verify_share(&value.treaty, &exported.descriptor, &object.author_share)?
                != exported.author_share_digest
            {
                return Err("InvalidAuthorShare");
            }
            if let Some(existing) = existing {
                if exported.descriptor.publication_version < existing.observed.publication_version
                    || (exported.descriptor.publication_version
                        == existing.observed.publication_version
                        && !same)
                {
                    return Err("SourcePublicationRollback");
                }
            } else if state.federation_pages.len() >= 128
                || state
                    .federation_pages
                    .keys()
                    .filter(|key| key.starts_with(&format!("{agreement_id}/")))
                    .count()
                    >= 32
            {
                return Err("FederationQuotaExceeded");
            }
            let bytes = encoded(&object, MAX_BLOB)?;
            let used: u64 = state
                .federation_pages
                .values()
                .map(|record| record.bytes)
                .sum();
            if used - existing.map_or(0, |record| record.bytes) + bytes.len() as u64
                > 8 * 1024 * 1024
            {
                return Err("FederationQuotaExceeded");
            }
            if same {
                let record = state
                    .federation_pages
                    .get_mut(&key)
                    .ok_or("FederationPageUnavailable")?;
                record.admission = admission.clone();
                record.export = export.clone();
                let path = page_key(agreement_id, &page_id);
                if blobs.get(&path) != Some(&bytes) {
                    record.bytes = bytes.len() as u64;
                    puts.push((path, bytes));
                }
            } else {
                let version = existing
                    .map_or(0, |record| record.version)
                    .checked_add(1)
                    .ok_or("CapacityExceeded")?;
                state.federation_pages.insert(
                    key.clone(),
                    FederationPageRecord {
                        version,
                        observed: exported.descriptor,
                        pending: true,
                        published: None,
                        admission: admission.clone(),
                        export: export.clone(),
                        bytes: bytes.len() as u64,
                    },
                );
                puts.push((page_key(agreement_id, &page_id), bytes));
                changed = true;
            }
            state
                .federation_agreements
                .get_mut(agreement_id)
                .ok_or("FederationUnavailable")?
                .source_revision = exported.authority_revision;
            let record = state
                .federation_pages
                .get(&key)
                .ok_or("FederationPageUnavailable")?;
            json!({"pageId":page_id,"version":record.version,"state":if record.pending {"Pending"} else if record.published.is_some() {"Approved"} else {"Suppressed"}})
        }
        Command::FederationQueue {
            agreement_id,
            after,
        }
        | Command::FederationList {
            agreement_id,
            after,
        } => {
            let agreement = agreement(state, agreement_id, now)?;
            side(state, &agreement.treaty, false)?;
            if let Some(after) = after {
                protocol::fixed_hex::<16>(after)?;
            }
            let queue = matches!(request.request.command, Command::FederationQueue { .. });
            let mut entries = Vec::new();
            let mut next = None;
            let mut until = now.saturating_add(5);
            for (key, record) in &state.federation_pages {
                let Some(page_id) = key.strip_prefix(&format!("{agreement_id}/")) else {
                    continue;
                };
                if after
                    .as_ref()
                    .is_some_and(|after| page_id <= after.as_str())
                {
                    continue;
                }
                if queue {
                    if !record.pending {
                        continue;
                    }
                } else if let Ok((_, _, export)) =
                    foreign_published(state, agreement_id, page_id, now)
                {
                    until = until.min(export.valid_until);
                } else {
                    continue;
                }
                if entries.len() == 32 {
                    next = Some(record.observed.page_id.clone());
                    break;
                }
                entries.push(if queue {json!({"pageId":page_id,"version":record.version,"descriptor":record.observed,"descriptorDigest":descriptor_digest(&record.observed)?})}
                    else {serde_json::to_value(&record.observed).map_err(|_|"InvalidFederationObject")?});
            }
            if next.is_some() {
                next = entries
                    .last()
                    .and_then(|entry| entry["pageId"].as_str())
                    .map(str::to_string);
            }
            json!({"entries":entries,"next":next,"authorityRevision":revision,"validUntil":until.min(state.members.get(&request.key).ok_or("NotMember")?.expires)})
        }
        Command::FederationInspect {
            agreement_id,
            page_id,
        } => {
            let value = agreement(state, agreement_id, now)?;
            side(state, &value.treaty, false)?;
            let record = state
                .federation_pages
                .get(&object_key(agreement_id, page_id))
                .ok_or("FederationPageUnavailable")?;
            let object: FederationPageBlob = blob(blobs, &page_key(agreement_id, page_id))?;
            page_authority::verify_bundle(
                &value.treaty.source_network,
                &record.observed,
                &object.bundle,
            )?;
            verify_share(&value.treaty, &record.observed, &object.author_share)?;
            let pending = if record.pending {
                Some(
                    json!({"descriptor":record.observed,"descriptorDigest":descriptor_digest(&record.observed)?,"bundle":object.bundle,"authorShare":object.author_share}),
                )
            } else {
                None
            };
            let until = verify_export(&value.treaty, &record.admission, &record.export, now)
                .map_or(0, |value| value.valid_until);
            json!({"treaty":value.treaty,"agreementDigest":value.digest,"pageId":page_id,"version":record.version,"pending":pending,"published":record.published,"sourceValidUntil":until})
        }
        Command::FederationReview {
            agreement_id,
            page_id,
            expected_version,
            descriptor_digest: bound,
            decision,
        } => {
            let (value, record, _) = foreign_current(state, agreement_id, page_id, now)?;
            if record.version != *expected_version
                || !record.pending
                || descriptor_digest(&record.observed)? != *bound
            {
                return Err("FederationVersionConflict");
            }
            if decision != "Approve" && decision != "Reject" {
                return Err("InvalidDecision");
            }
            let mut object: FederationPageBlob = blob(blobs, &page_key(agreement_id, page_id))?;
            page_authority::verify_bundle(
                &value.treaty.source_network,
                &record.observed,
                &object.bundle,
            )?;
            verify_share(&value.treaty, &record.observed, &object.author_share)?;
            let version = record.version.checked_add(1).ok_or("CapacityExceeded")?;
            let record = state
                .federation_pages
                .get_mut(&object_key(agreement_id, page_id))
                .ok_or("FederationPageUnavailable")?;
            record.version = version;
            record.pending = false;
            if decision == "Approve" {
                encoded(&request.envelope, MAX_PROOF)?;
                object.approval = Some(request.envelope.clone());
                record.published = Some(FederationPublication {
                    descriptor: record.observed.clone(),
                    reviewer: request.key.clone(),
                    approval_digest: request.digest.clone(),
                    publication_version: version,
                });
                let bytes = encoded(&object, MAX_BLOB)?;
                record.bytes = bytes.len() as u64;
                puts.push((page_key(agreement_id, page_id), bytes));
            }
            json!({"pageId":page_id,"version":version,"state":decision})
        }
        Command::FederationPageWithdraw {
            agreement_id,
            page_id,
            expected_version,
        } => {
            let value = agreement(state, agreement_id, now)?;
            side(state, &value.treaty, false)?;
            let record = state
                .federation_pages
                .get_mut(&object_key(agreement_id, page_id))
                .ok_or("FederationPageUnavailable")?;
            if record.version != *expected_version {
                return Err("FederationVersionConflict");
            }
            record.version = record.version.checked_add(1).ok_or("CapacityExceeded")?;
            record.pending = false;
            record.published = None;
            json!({"pageId":page_id,"version":record.version,"state":"Withdrawn"})
        }
        Command::FederationRead {
            agreement_id,
            page_id,
        } => {
            let (value, record, export) = foreign_published(state, agreement_id, page_id, now)?;
            let object: FederationPageBlob = blob(blobs, &page_key(agreement_id, page_id))?;
            page_authority::verify_bundle(
                &value.treaty.source_network,
                &record.observed,
                &object.bundle,
            )?;
            if verify_share(&value.treaty, &record.observed, &object.author_share)?
                != export.author_share_digest
            {
                return Err("InvalidAuthorShare");
            }
            let approval = object.approval.ok_or("FederationPageUnavailable")?;
            let proof = protocol::verify_archived(&approval, &state.network)?;
            let publication = record
                .published
                .as_ref()
                .ok_or("FederationPageUnavailable")?;
            if proof.key != publication.reviewer || proof.digest != publication.approval_digest {
                return Err("InvalidFederationApproval");
            }
            let Command::FederationReview {
                agreement_id: review_agreement,
                page_id: review_page,
                expected_version,
                descriptor_digest: bound,
                decision,
            } = &proof.request.command
            else {
                return Err("InvalidFederationApproval");
            };
            if review_agreement != agreement_id
                || review_page != page_id
                || decision != "Approve"
                || *bound != descriptor_digest(&record.observed)?
                || expected_version.checked_add(1) != Some(publication.publication_version)
            {
                return Err("InvalidFederationApproval");
            }
            let until = export
                .valid_until
                .min(state.members.get(&request.key).ok_or("NotMember")?.expires)
                .min(
                    state
                        .members
                        .get(&publication.reviewer)
                        .ok_or("NotMember")?
                        .expires,
                );
            json!({"treaty":value.treaty,"agreementDigest":value.digest,"descriptor":record.observed,"bundle":object.bundle,"authorShare":object.author_share,
                "approval":approval,"admission":record.admission,"export":record.export,"authorityRevision":revision,"validUntil":until})
        }
        _ => return Err("UnsupportedCommand"),
    };
    if changed {
        state.epoch = state.epoch.checked_add(1).ok_or("CapacityExceeded")?;
    }
    state.version = 4;
    state.high_water_time = state.high_water_time.max(now);
    let reply = Reply::success(state.epoch, result);
    encoded(&reply, 256 * 1024)?;
    if recorded {
        state.receipts.insert(
            receipt_key,
            Receipt {
                digest: request.digest.clone(),
                expires: request.request.issued_at.saturating_add(60),
                reply: reply.clone(),
            },
        );
    }
    Ok(page_authority::Change {
        reply,
        puts,
        deletes: Vec::new(),
    })
}

#[cfg(test)]
#[path = "FederationTests.rs"]
mod tests;
