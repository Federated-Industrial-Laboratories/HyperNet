// SPDX-License-Identifier: MIT
// Physical two-bank admission accounts for canonical metadata and complete immutable payloads.
use super::*;

pub const STORAGE_BANK_HEADER_BYTES: u64 = 64;

pub fn serialized_bank_bytes(state_bytes: u64) -> Result<u64> {
    state_bytes
        .checked_div(2)
        .and_then(|n| n.checked_sub(STORAGE_BANK_HEADER_BYTES))
        .filter(|n| *n > 0)
        .context("Page storage cannot hold a committed bank")
}

fn head_bytes(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}

pub fn media_storage_budget(state_bytes: u64) -> Result<u64> {
    // State has four fixed digests, one monotonic time, and the canonical entry list.
    // The empty list's one-byte header is replaced by the largest admitted list header.
    let header = wire::encode(&a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityMediaStorage".into()),
        b(&[0; 32]),
        b(&[0; 32]),
        b(&[0; 32]),
        b(&[0; 32]),
        V::Uint(u64::MAX),
        a(vec![]),
    ]))?
    .len() as u64
        - 1
        + head_bytes(crate::authority_domains::MAXIMUM_RECORDS as u64);
    serialized_bank_bytes(state_bytes)?
        .checked_sub(header)
        .filter(|n| *n > 0)
        .context("media storage cannot hold its canonical state header")
}

pub fn media_storage_charge(asset: &Asset) -> Result<u64> {
    // Digest and signature contents do not affect their encoded lengths. Maximum generation
    // and timestamp encodings bound every valid receipt without constructing payload bytes.
    let asset_ref = VersionRef {
        kind: 144,
        id: [0; 32],
        generation: u64::MAX,
        digest: [0; 32],
    };
    let host_ref = VersionRef {
        kind: 143,
        id: [0; 32],
        generation: u64::MAX,
        digest: [0; 32],
    };
    let receipt = CopyReceipt {
        asset: asset_ref.clone(),
        host: host_ref.clone(),
        request: [0; 32],
        digest: [0; 32],
        bytes: asset.manifest.bytes,
        recorded_ms: u64::MAX,
        envelope: vec![],
    };
    let receipt_payload = receipt.payload([0; 32], [0; 32])?;
    let receipt_envelope = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&receipt_payload),
        a(vec![a(vec![b(&[0; 32]), b(&[0; 64])])]),
    ]))?;
    let empty_entry = wire::encode(&a(vec![
        reference(&asset_ref),
        asset.value(),
        reference(&host_ref),
        V::Uint(u64::MAX),
        b(&[]),
        b(&receipt_envelope),
    ]))?;
    (empty_entry.len() as u64 - 1)
        .checked_add(head_bytes(asset.manifest.bytes))
        .and_then(|n| n.checked_add(asset.manifest.bytes))
        .context("media storage reservation overflow")
}
