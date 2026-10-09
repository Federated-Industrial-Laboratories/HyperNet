// SPDX-License-Identifier: MIT
use super::*;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;

#[test]
fn sshsig_binds_context_and_rejects_truncation_changes_and_extra_bytes() {
    let key = SigningKey::from_bytes(&[4; 32]);
    let mut public = Vec::new();
    string(&mut public, b"ssh-ed25519");
    string(&mut public, key.verifying_key().as_bytes());
    let native = format!("ssh-ed25519 {}", STANDARD.encode(public));
    let network = "09".repeat(32);
    let member = "01".repeat(32);
    let valid = proof(&network, &member, &key);
    verify(&valid, &network, &member, &native).unwrap();
    assert!(verify(&valid, &"08".repeat(32), &member, &native).is_err());
    assert!(verify(&valid, &network, &"02".repeat(32), &native).is_err());
    assert!(verify(&format!("{valid}="), &network, &member, &native).is_err());
    assert!(verify(&"A".repeat(1025), &network, &member, &native).is_err());
    let raw = URL_SAFE_NO_PAD.decode(valid).unwrap();
    for length in 0..raw.len() {
        assert!(
            verify(
                &URL_SAFE_NO_PAD.encode(&raw[..length]),
                &network,
                &member,
                &native
            )
            .is_err()
        );
        let mut changed = raw.clone();
        changed[length] ^= 1;
        assert!(verify(&URL_SAFE_NO_PAD.encode(changed), &network, &member, &native).is_err());
    }
    let mut extra = raw;
    extra.push(0);
    assert!(verify(&URL_SAFE_NO_PAD.encode(extra), &network, &member, &native).is_err());
}
