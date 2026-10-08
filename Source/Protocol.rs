// SPDX-License-Identifier: MIT
use crate::types::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub struct VerifiedRequest {
    pub key: String,
    pub digest: String,
    pub request: Request,
}

pub fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("InvalidEncoding");
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "InvalidEncoding")?;
    Ok(bytes)
}

pub fn verify(bytes: &[u8], network: &str, now: u64) -> Result<VerifiedRequest, &'static str> {
    if bytes.len() > MAX_ENVELOPE {
        return Err("RequestTooLarge");
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| "InvalidEnvelope")?;
    if envelope.network != network {
        return Err("WrongNetwork");
    }
    let network = fixed_hex::<32>(&envelope.network)?;
    let key_bytes = fixed_hex::<32>(&envelope.public_key)?;
    let signature = Signature::from_bytes(&fixed_hex::<64>(&envelope.signature)?);
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| "InvalidEncoding")?;
    if payload.len() > MAX_PAYLOAD {
        return Err("RequestTooLarge");
    }
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "InvalidKey")?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + 64 + payload.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&network);
    signed.extend_from_slice(&key_bytes);
    signed.extend_from_slice(&payload);
    key.verify_strict(&signed, &signature)
        .map_err(|_| "InvalidSignature")?;
    let request: Request = serde_json::from_slice(&payload).map_err(|_| "InvalidPayload")?;
    if request.version != 1 {
        return Err("UnsupportedVersion");
    }
    fixed_hex::<16>(&request.request_id)?;
    if request.issued_at > now.saturating_add(30) || request.issued_at.saturating_add(60) < now {
        return Err("StaleRequest");
    }
    Ok(VerifiedRequest {
        key: envelope.public_key,
        digest: hex::encode(Sha256::digest(&signed)),
        request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn signed(payload: &[u8]) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let network = [9; 32];
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        bytes.extend_from_slice(payload);
        serde_json::to_vec(&Envelope {
            network: hex::encode(network),
            public_key: hex::encode(key.verifying_key().as_bytes()),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn signed_payload_has_strict_schema_and_network_binding() {
        let payload = br#"{"version":1,"requestId":"00000000000000000000000000000001","issuedAt":100,"command":{"type":"Status"}}"#;
        let bytes = signed(payload);
        assert!(verify(&bytes, &hex::encode([9; 32]), 100).is_ok());
        assert!(verify(&bytes, &hex::encode([8; 32]), 100).is_err());
        assert!(verify(&bytes, &hex::encode([9; 32]), 161).is_err());
        let duplicate = br#"{"version":1,"version":1,"requestId":"00000000000000000000000000000001","issuedAt":100,"command":{"type":"Status"}}"#;
        assert!(verify(&signed(duplicate), &hex::encode([9; 32]), 100).is_err());
        let unknown = json!({"version":1,"requestId":"00000000000000000000000000000001","issuedAt":100,"command":{"type":"Status","extra":true}});
        assert!(
            verify(
                &signed(&serde_json::to_vec(&unknown).unwrap()),
                &hex::encode([9; 32]),
                100
            )
            .is_err()
        );
        let mut tampered: Envelope = serde_json::from_slice(&bytes).unwrap();
        tampered.payload = URL_SAFE_NO_PAD.encode(b"{}");
        assert!(
            verify(
                &serde_json::to_vec(&tampered).unwrap(),
                &hex::encode([9; 32]),
                100
            )
            .is_err()
        );
    }
}
