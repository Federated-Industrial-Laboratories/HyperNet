// SPDX-License-Identifier: MIT
// SSHSIG proves possession without importing native SSH private keys.
use crate::protocol;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};

const NAMESPACE: &[u8] = b"HyperNetSshKey1";
const HASH: &[u8] = b"sha512";
const DOMAIN: &[u8] = b"HyperNet/SshKeyProof/1\0";
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

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Failure> {
        let value = self.0.get(..count).ok_or("SshInvalidKeyProof")?;
        self.0 = &self.0[count..];
        Ok(value)
    }
    fn number(&mut self) -> Result<u32, Failure> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a [u8], Failure> {
        let count = self.number()? as usize;
        self.take(count)
    }
}
fn string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
fn signed_data(network: &[u8; 32], member: &[u8; 32], native: &[u8; 32]) -> Vec<u8> {
    let mut message = Sha512::new();
    for bytes in [
        DOMAIN,
        network.as_slice(),
        member.as_slice(),
        native.as_slice(),
    ] {
        message.update(bytes);
    }
    let mut output = b"SSHSIG".to_vec();
    string(&mut output, NAMESPACE);
    string(&mut output, b"");
    string(&mut output, HASH);
    string(&mut output, &message.finalize());
    output
}
pub fn verify(proof: &str, network: &str, member: &str, native: &str) -> Result<(), Failure> {
    if proof.len() > 1024 {
        return Err("SshInvalidKeyProof");
    }
    let raw = URL_SAFE_NO_PAD
        .decode(proof)
        .map_err(|_| "SshInvalidKeyProof")?;
    if URL_SAFE_NO_PAD.encode(&raw) != proof {
        return Err("SshInvalidKeyProof");
    }
    let native = protocol::fixed_hex::<32>(&public_key(native)?)?;
    let network = protocol::fixed_hex::<32>(network)?;
    let member = protocol::fixed_hex::<32>(member)?;
    let mut blob = Reader(&raw);
    if blob.take(6)? != b"SSHSIG" || blob.number()? != 1 {
        return Err("SshInvalidKeyProof");
    }
    let mut public = Reader(blob.string()?);
    if public.string()? != b"ssh-ed25519"
        || public.string()? != native
        || !public.0.is_empty()
        || blob.string()? != NAMESPACE
        || !blob.string()?.is_empty()
        || blob.string()? != HASH
    {
        return Err("SshInvalidKeyProof");
    }
    let mut signature = Reader(blob.string()?);
    if !blob.0.is_empty() || signature.string()? != b"ssh-ed25519" {
        return Err("SshInvalidKeyProof");
    }
    let value = Signature::from_slice(signature.string()?).map_err(|_| "SshInvalidKeyProof")?;
    if !signature.0.is_empty() {
        return Err("SshInvalidKeyProof");
    }
    VerifyingKey::from_bytes(&native)
        .map_err(|_| "SshInvalidKeyProof")?
        .verify_strict(&signed_data(&network, &member, &native), &value)
        .map_err(|_| "SshInvalidKeyProof")
}

#[cfg(test)]
#[path = "../../Tests/Unit/Services/SshProof.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Services/SshProof.rs");
