// SPDX-License-Identifier: MIT
//! Read only one regular executable from bounded Podman tar output; never extract paths.
use super::super::files::{capture, hex_digest, strings};
use anyhow::{Context, Result, ensure};
use std::path::Path;

const FRAMING: usize = 65536;
fn octal(bytes: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "Invalid image archive number"
    );
    Ok(usize::from_str_radix(text, 8)?)
}
fn pax(mut bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= FRAMING,
        "Image metadata exceeds framing bound"
    );
    while !bytes.is_empty() {
        let space = bytes
            .iter()
            .position(|b| *b == b' ')
            .context("Invalid image metadata length")?;
        let length = std::str::from_utf8(&bytes[..space])?.parse::<usize>()?;
        ensure!(
            length > space + 2 && length <= bytes.len() && bytes[length - 1] == b'\n',
            "Invalid image metadata framing"
        );
        let record = &bytes[space + 1..length - 1];
        let equal = record
            .iter()
            .position(|b| *b == b'=')
            .context("Invalid image metadata key")?;
        let key = std::str::from_utf8(&record[..equal])?;
        ensure!(
            matches!(
                key,
                "mtime" | "atime" | "ctime" | "uid" | "gid" | "uname" | "gname"
            ) || key.starts_with("SCHILY.xattr."),
            "Image metadata cannot override executable path, size or type"
        );
        bytes = &bytes[length..];
    }
    Ok(())
}
fn executable(bytes: &[u8], expected_size: usize) -> Result<&[u8]> {
    ensure!(
        bytes.len().is_multiple_of(512)
            && bytes.len()
                <= expected_size
                    .checked_add(FRAMING)
                    .context("Image bound overflow")?,
        "Image archive exceeds bound or block framing"
    );
    let mut cursor = 0usize;
    let mut found = None;
    while cursor + 512 <= bytes.len() {
        let header = &bytes[cursor..cursor + 512];
        if header.iter().all(|b| *b == 0) {
            ensure!(
                bytes.len() - cursor >= 1024 && bytes[cursor..].iter().all(|b| *b == 0),
                "Image archive has invalid terminal padding"
            );
            return found.context("Image archive has no executable");
        }
        let checksum = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32usize
                } else {
                    *b as usize
                }
            })
            .sum::<usize>();
        ensure!(
            octal(&header[148..156])? == checksum,
            "Image archive checksum differs"
        );
        let size = octal(&header[124..136])?;
        let begin = cursor + 512;
        let end = begin.checked_add(size).context("Image length overflow")?;
        let padded = end.checked_add(511).context("Image padding overflow")? / 512 * 512;
        ensure!(
            padded <= bytes.len() && bytes[end..padded].iter().all(|b| *b == 0),
            "Image entry exceeds archive or has invalid padding"
        );
        match header[156] {
            0 | b'0' => {
                ensure!(
                    found.is_none()
                        && size == expected_size
                        && header[..9] == *b"HyperNet\0"
                        && header[9..100].iter().all(|b| *b == 0)
                        && header[157..257].iter().all(|b| *b == 0)
                        && header[345..500].iter().all(|b| *b == 0),
                    "Image must contain exactly the expected regular HyperNet executable"
                );
                found = Some(&bytes[begin..end]);
            }
            b'x' | b'g' => {
                ensure!(found.is_none(), "Unexpected trailing image metadata");
                pax(&bytes[begin..end])?;
            }
            _ => anyhow::bail!("Image executable cannot be a link, sparse file or special entry"),
        }
        cursor = padded;
    }
    anyhow::bail!("Image archive is missing terminal blocks")
}
pub fn verify(id: &str, expected_digest: &str) -> Result<()> {
    let executable_path = std::env::current_exe()?.canonicalize()?;
    let size = usize::try_from(std::fs::metadata(&executable_path)?.len())?;
    let maximum = size
        .checked_add(FRAMING)
        .context("Image output bound overflow")?;
    let (bytes, _) = capture(
        Path::new("/usr/bin/podman"),
        &strings(&["cp", &format!("{id}:/HyperNet"), "-"]),
        45,
        maximum,
        4096,
    )?;
    ensure!(
        hex_digest(executable(&bytes, size)?) == expected_digest,
        "Image executable differs from the consented installed software"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
