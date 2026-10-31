// SPDX-License-Identifier: MIT
use super::*;

include!("../../../Support/Authority/Domains/ApplicationStreamControl.rs");

#[test]
fn signed_ready_and_exact_receipt_round_trip() {
    let (binding, key, ready, request) = fixture();
    let signed = sign(&ready, &binding, &key).unwrap();
    assert_eq!(verify::<Ready>(&signed, &binding).unwrap(), ready);
    let receipt = Receipt {
        request: request.clone(),
        disposition: Disposition::Permitted,
        authority: Some(Authority {
            network: binding.network,
            incarnation: binding.incarnation,
            configuration: [13; 32],
            epoch: 1,
            height: 2,
            state: [14; 32],
            statement_digest: [15; 32],
            evaluated_at_ms: 10000,
            expires_at_ms: 11000,
            code: 0,
        }),
        not_after_boot_ms: 900,
        privacy: ready.privacy,
    };
    let signed = sign(&receipt, &binding, &key).unwrap();
    assert_eq!(verify::<Receipt>(&signed, &binding).unwrap(), receipt);
    let mut other = binding.clone();
    other.endpoint = ed25519_dalek::SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .to_bytes();
    assert!(verify::<Receipt>(&signed, &other).is_err());
    let mut other_binding = binding.clone();
    other_binding.id = [99; 32];
    assert!(verify::<Receipt>(&signed, &other_binding).is_err());
    let mut altered = signed;
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(verify::<Receipt>(&altered, &binding).is_err());
}
#[test]
fn exact_control_correlation_and_original_deadline_are_required() {
    let (_, _, ready, request) = fixture();
    request.matches_ready(&ready).unwrap();
    for changed in 0..4 {
        let mut other = request.clone();
        match changed {
            0 => other.binding_digest = [1; 32],
            1 => other.companion_instance = [1; 32],
            2 => other.endpoint_instance = [1; 32],
            _ => other.control_generation += 1,
        }
        assert!(other.matches_ready(&ready).is_err());
    }
    let mut extended = request.clone();
    extended.caller_deadline_boot_ms += 1;
    assert!(encode(&extended).is_err());
    let mut wrong = request;
    wrong.session.kind = 172;
    assert!(encode(&wrong).is_err());
}
#[test]
fn strict_records_reject_unknown_fields_and_unbounded_payloads() {
    let (_, _, _, request) = fixture();
    let mut json = serde_json::to_value(&request).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("extra".into(), serde_json::json!(true));
    let malformed = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(Request::LABEL.into()),
        V::Bytes(serde_json::to_vec(&json).unwrap()),
    ]))
    .unwrap();
    assert!(parse::<Request>(&malformed).is_err());
    assert!(parse::<Request>(&vec![0; MAXIMUM_FRAME + 1]).is_err());
    assert!(parse::<Cancel>(&encode(&request).unwrap()).is_err());
    let cancel = Cancel { request };
    assert_eq!(parse::<Cancel>(&encode(&cancel).unwrap()).unwrap(), cancel);
}
#[test]
fn privacy_cannot_invent_transit_independence_or_currentness() {
    let (_, _, mut ready, _) = fixture();
    ready.privacy.attachment = Some(Attachment {
        relay_service: [2; 32],
        profile_digest: [3; 32],
    });
    assert!(encode(&ready).is_err());
    ready.privacy.endpoint_mode = 3;
    ready.privacy.incoming_path = IncomingPath::ApprovedAttachment;
    encode(&ready).unwrap();
    ready.privacy.physical_independence_verified = true;
    assert!(encode(&ready).is_err());
    ready.privacy.physical_independence_verified = false;
    ready.privacy.profile_currentness_asserted = true;
    assert!(encode(&ready).is_err());
    ready.privacy.profile_currentness_asserted = false;
    ready.boottime_offset_ns = 1;
    assert!(encode(&ready).is_err());
}
#[test]
fn receipts_distinguish_certified_refusal_from_local_unavailability() {
    let (_, _, ready, request) = fixture();
    let mut receipt = Receipt {
        request,
        disposition: Disposition::Unavailable,
        authority: None,
        not_after_boot_ms: 5100,
        privacy: ready.privacy,
    };
    encode(&receipt).unwrap();
    receipt.disposition = Disposition::Denied;
    assert!(encode(&receipt).is_err());
    receipt.disposition = Disposition::Expired;
    receipt.not_after_boot_ms = 5101;
    assert!(encode(&receipt).is_err());
}
