// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn proof(network: &str, member: &str, key: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    let mut public = Vec::new();
    string(&mut public, b"ssh-ed25519");
    string(&mut public, key.verifying_key().as_bytes());
    let mut signature = Vec::new();
    string(&mut signature, b"ssh-ed25519");
    string(
        &mut signature,
        &key.sign(&signed_data(
            &protocol::fixed_hex::<32>(network).unwrap(),
            &protocol::fixed_hex::<32>(member).unwrap(),
            key.verifying_key().as_bytes(),
        ))
        .to_bytes(),
    );
    let mut blob = b"SSHSIG".to_vec();
    blob.extend_from_slice(&1u32.to_be_bytes());
    for bytes in [&public[..], NAMESPACE, b"", HASH, &signature] {
        string(&mut blob, bytes);
    }
    URL_SAFE_NO_PAD.encode(blob)
}
