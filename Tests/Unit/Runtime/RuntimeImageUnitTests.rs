// SPDX-License-Identifier: MIT
// Unit tests for RuntimeImage.
use super::*;
fn archive(kind: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    bytes[..8].copy_from_slice(b"HyperNet");
    bytes[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    bytes[156] = kind;
    bytes[148..156].fill(b' ');
    let checksum = bytes.iter().map(|b| *b as usize).sum::<usize>();
    bytes[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    bytes.extend_from_slice(content);
    bytes.resize(bytes.len().div_ceil(512) * 512 + 1024, 0);
    bytes
}
#[test]
fn image_verification_accepts_only_exact_regular_payload_and_safe_framing() {
    let body = b"approved executable bytes";
    let bytes = archive(b'0', body);
    assert_eq!(executable(&bytes, body.len()).unwrap(), body);
    assert!(executable(&archive(b'2', body), body.len()).is_err());
    assert!(executable(&bytes, body.len() - 1).is_err());
    let mut malformed = bytes.clone();
    malformed[0] ^= 1;
    assert!(executable(&malformed, body.len()).is_err());
    malformed = bytes.clone();
    *malformed.last_mut().unwrap() = 1;
    assert!(executable(&malformed, body.len()).is_err());
    assert!(executable(&bytes[..512], body.len()).is_err());
    assert!(pax(b"17 path=HyperNet\n").is_err());
    assert!(pax(b"10 size=1\n").is_err());
    pax(b"11 mtime=1\n").unwrap();
}
