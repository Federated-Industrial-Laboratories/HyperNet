// SPDX-License-Identifier: MIT
// Exact bounded CBOR records and purpose-separated bootstrap signatures.
use anyhow::{Result, bail, ensure};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[path = "TrustSignatureCache.rs"]
mod signature_cache;
#[cfg(test)]
#[path = "../../Tests/Unit/Protocol/TrustSignatureTests.rs"]
mod signature_tests;

pub const MAXIMUM: usize = 262144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn array(&self, arity: usize) -> Result<&[Value]> {
        let Self::Array(value) = self else {
            bail!("expected record array")
        };
        ensure!(
            value.len() == arity,
            "incorrect record arity: expected {arity}, received {}",
            value.len()
        );
        Ok(value)
    }
    pub fn list(&self, maximum: usize) -> Result<&[Value]> {
        let Self::Array(value) = self else {
            bail!("expected bounded list")
        };
        ensure!(value.len() <= maximum, "list limit exceeded");
        Ok(value)
    }
    pub fn uint(&self) -> Result<u64> {
        let Self::Uint(value) = self else {
            bail!("expected unsigned integer")
        };
        Ok(*value)
    }
    pub fn bytes(&self) -> Result<&[u8]> {
        let Self::Bytes(value) = self else {
            bail!("expected byte string")
        };
        Ok(value)
    }
    pub fn fixed<const N: usize>(&self) -> Result<[u8; N]> {
        self.bytes()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("incorrect byte-string size"))
    }
    pub fn text(&self) -> Result<&str> {
        let Self::Text(value) = self else {
            bail!("expected text")
        };
        Ok(value)
    }
    pub fn boolean(&self) -> Result<bool> {
        let Self::Bool(value) = self else {
            bail!("expected boolean")
        };
        Ok(*value)
    }
    pub fn null(&self) -> Result<()> {
        ensure!(*self == Self::Null, "expected null");
        Ok(())
    }
}

fn header(kind: u8, value: u64, out: &mut Vec<u8>) {
    if value < 24 {
        out.push(kind * 32 + value as u8);
    } else {
        let (tag, count) = if value <= 255 {
            (24, 1)
        } else if value <= 65535 {
            (25, 2)
        } else if value <= u32::MAX as u64 {
            (26, 4)
        } else {
            (27, 8)
        };
        out.push(kind * 32 + tag);
        out.extend_from_slice(&value.to_be_bytes()[8 - count..]);
    }
}

pub fn encode(value: &Value) -> Result<Vec<u8>> {
    encode_bounded(value, MAXIMUM)
}
/// Retained application state uses a separate bound from untrusted wire messages.
pub fn encode_state(value: &Value) -> Result<Vec<u8>> {
    encode_bounded(value, crate::authority_capacity::MAX_STATE_BYTES)
}
pub(crate) fn encode_bounded(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    fn append(value: &Value, depth: usize, out: &mut Vec<u8>, maximum: usize) -> Result<()> {
        ensure!(depth <= 16, "record nesting limit exceeded");
        match value {
            Value::Uint(v) => header(0, *v, out),
            Value::Bytes(v) => {
                header(2, v.len() as u64, out);
                out.extend(v);
            }
            Value::Text(v) => {
                ensure!(v.len() <= 1024, "record text limit exceeded");
                header(3, v.len() as u64, out);
                out.extend(v.as_bytes());
            }
            Value::Array(v) => {
                ensure!(v.len() <= 4096, "record array limit exceeded");
                header(4, v.len() as u64, out);
                for item in v {
                    append(item, depth + 1, out, maximum)?;
                }
            }
            Value::Bool(v) => out.push(if *v { 245 } else { 244 }),
            Value::Null => out.push(246),
        }
        ensure!(out.len() <= maximum, "record size limit exceeded");
        Ok(())
    }
    let mut out = Vec::new();
    append(value, 0, &mut out, maximum)?;
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    decode_bounded(bytes, MAXIMUM)
}
/// This entry point is for already bounded retained state and checkpoint assembly.
pub fn decode_state(bytes: &[u8]) -> Result<Value> {
    decode_bounded(bytes, crate::authority_capacity::MAX_STATE_BYTES)
}
pub(crate) fn decode_bounded(bytes: &[u8], maximum: usize) -> Result<Value> {
    fn item(data: &[u8], cursor: &mut usize, depth: usize) -> Result<Value> {
        ensure!(depth <= 16, "record nesting limit exceeded");
        let first = *data
            .get(*cursor)
            .ok_or_else(|| anyhow::anyhow!("truncated record"))?;
        *cursor += 1;
        if first == 244 {
            return Ok(Value::Bool(false));
        }
        if first == 245 {
            return Ok(Value::Bool(true));
        }
        if first == 246 {
            return Ok(Value::Null);
        }
        let kind = first / 32;
        let argument = first % 32;
        ensure!(
            matches!(kind, 0 | 2 | 3 | 4) && argument < 28,
            "unsupported CBOR type"
        );
        let value = if argument < 24 {
            argument as u64
        } else {
            let size = 1usize << (argument - 24);
            let end = cursor
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("record length overflow"))?;
            let part = data
                .get(*cursor..end)
                .ok_or_else(|| anyhow::anyhow!("truncated integer"))?;
            *cursor = end;
            let mut buffer = [0; 8];
            buffer[8 - size..].copy_from_slice(part);
            let value = u64::from_be_bytes(buffer);
            let minimum = match size {
                1 => 24,
                2 => 256,
                4 => 65536,
                _ => 4294967296,
            };
            ensure!(value >= minimum, "noncanonical CBOR argument");
            value
        };
        if kind == 0 {
            return Ok(Value::Uint(value));
        }
        let count = usize::try_from(value)?;
        if kind == 4 {
            ensure!(count <= 4096, "record array limit exceeded");
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(item(data, cursor, depth + 1)?);
            }
            return Ok(Value::Array(list));
        }
        let end = cursor
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("record length overflow"))?;
        let part = data
            .get(*cursor..end)
            .ok_or_else(|| anyhow::anyhow!("truncated string"))?;
        *cursor = end;
        if kind == 3 {
            ensure!(count <= 1024, "record text limit exceeded");
            Ok(Value::Text(std::str::from_utf8(part)?.to_owned()))
        } else {
            Ok(Value::Bytes(part.to_vec()))
        }
    }
    ensure!(bytes.len() <= maximum, "record size limit exceeded");
    let mut cursor = 0;
    let value = item(bytes, &mut cursor, 0)?;
    ensure!(cursor == bytes.len(), "trailing record bytes");
    Ok(value)
}

pub fn digest(payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"HyperNet/RecordDigest/1\0");
    hash.update((payload.len() as u32).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}

pub fn signature_message(payload: &[u8], public: &[u8; 32]) -> Vec<u8> {
    let mut out = b"HyperNet/RecordSignature/1\0".to_vec();
    out.extend((payload.len() as u32).to_be_bytes());
    out.extend(payload);
    out.extend(public);
    out
}

pub fn valid_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes)?;
    ensure!(!key.is_weak() && *bytes != [0; 32], "weak public key");
    Ok(key)
}

pub fn sign_envelope(payload: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    decode(payload)?;
    let public = key.verifying_key().to_bytes();
    let signature = key.sign(&signature_message(payload, &public)).to_bytes();
    encode(&Value::Array(vec![
        Value::Uint(0),
        Value::Uint(1),
        Value::Bytes(payload.to_vec()),
        Value::Array(vec![Value::Array(vec![
            Value::Bytes(public.to_vec()),
            Value::Bytes(signature.to_vec()),
        ])]),
    ]))
}

pub type SignedRecord = (Vec<u8>, Vec<([u8; 32], [u8; 64])>);
pub(crate) fn take_signature_statistics() -> signature_cache::SignatureStatistics {
    signature_cache::take_signature_statistics()
}

pub fn envelope(bytes: &[u8], maximum: usize) -> Result<SignedRecord> {
    envelope_with_cache(bytes, maximum, signature_cache::global())
}
fn envelope_with_cache(
    bytes: &[u8],
    maximum: usize,
    cache: &signature_cache::Cache,
) -> Result<SignedRecord> {
    let value = decode(bytes)?;
    let record = value.array(4)?;
    ensure!(
        record[0].uint()? == 0 && record[1].uint()? == 1,
        "incorrect envelope kind or version"
    );
    let payload = record[2].bytes()?;
    decode(payload)?;
    let pairs = record[3].list(maximum)?;
    ensure!(!pairs.is_empty(), "unsigned envelope");
    let mut signatures = Vec::new();
    let mut previous = None;
    for value in pairs {
        let pair = value.array(2)?;
        let key = pair[0].fixed::<32>()?;
        let signature = pair[1].fixed::<64>()?;
        ensure!(
            previous.is_none_or(|prior| prior < key),
            "repeated or unsorted signer"
        );
        cache.verify(
            &valid_key(&key)?,
            &signature_message(payload, &key),
            signature,
        )?;
        previous = Some(key);
        signatures.push((key, signature));
    }
    Ok((payload.to_vec(), signatures))
}

#[cfg(test)]
#[path = "../../Tests/Unit/Protocol/TrustWireUnitTests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Protocol/TrustWireStateCapacityTests.rs"]
mod state_capacity_tests;
