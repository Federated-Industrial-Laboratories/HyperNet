// SPDX-License-Identifier: MIT
// Bounded Ed25519 certificate succession preserves every identity and extension while renewing dates.
use super::Key;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use std::{net::IpAddr, sync::Arc, time::Duration};

const ALGORITHM: &[u8] = &[0x30, 5, 6, 3, 0x2b, 0x65, 0x70];

#[derive(Clone, Copy)]
struct Item<'a> {
    tag: u8,
    full: &'a [u8],
    value: &'a [u8],
}
fn take<'a>(input: &mut &'a [u8]) -> Result<Item<'a>> {
    ensure!(input.len() >= 2, "Truncated certificate field");
    let tag = input[0];
    ensure!(tag & 31 != 31, "Unsupported certificate tag");
    let (header, length) = if input[1] < 128 {
        (2, usize::from(input[1]))
    } else {
        let count = usize::from(input[1] & 127);
        ensure!(
            (1..=3).contains(&count) && input.len() >= 2 + count && input[2] != 0,
            "Invalid certificate length"
        );
        let mut length = 0usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        ensure!(length >= 128, "Noncanonical certificate length");
        (2 + count, length)
    };
    let end = header
        .checked_add(length)
        .context("Certificate length overflow")?;
    ensure!(end <= input.len(), "Truncated certificate value");
    let result = Item {
        tag,
        full: &input[..end],
        value: &input[header..end],
    };
    *input = &input[end..];
    Ok(result)
}
fn field<'a>(input: &mut &'a [u8], tag: u8) -> Result<Item<'a>> {
    let item = take(input)?;
    ensure!(item.tag == tag, "Unexpected certificate field");
    Ok(item)
}
fn decimal(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit),
        "Invalid certificate date"
    );
    Ok(bytes
        .iter()
        .fold(0, |value, byte| value * 10 + u64::from(byte - b'0')))
}
fn date(item: Item<'_>) -> Result<u64> {
    let bytes = item.value;
    let year_size = match item.tag {
        0x17 => 2,
        0x18 => 4,
        _ => anyhow::bail!("Unsupported certificate time"),
    };
    ensure!(
        bytes.len() == year_size + 11 && bytes.last() == Some(&b'Z'),
        "Certificate time requires canonical UTC seconds"
    );
    let raw_year = decimal(&bytes[..year_size])?;
    let year = if year_size == 2 {
        if raw_year >= 50 {
            1900 + raw_year
        } else {
            2000 + raw_year
        }
    } else {
        raw_year
    };
    ensure!(
        (1970..=9999).contains(&year) && (year_size != 4 || year >= 2050),
        "Certificate year is outside the supported interval"
    );
    let month = decimal(&bytes[year_size..year_size + 2])?;
    let day = decimal(&bytes[year_size + 2..year_size + 4])?;
    let hour = decimal(&bytes[year_size + 4..year_size + 6])?;
    let minute = decimal(&bytes[year_size + 6..year_size + 8])?;
    let second = decimal(&bytes[year_size + 8..year_size + 10])?;
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1..=12).contains(&month)
            && day >= 1
            && day <= months[(month - 1) as usize]
            && hour < 24
            && minute < 60
            && second < 60,
        "Invalid certificate calendar date"
    );
    let leap_days = |before: u64| before / 4 - before / 100 + before / 400;
    let days = (year - 1970) * 365 + leap_days(year - 1) - leap_days(1969)
        + months[..(month - 1) as usize].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

struct Certificate<'a> {
    tbs: &'a [u8],
    signature: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    extensions: &'a [u8],
    key: Key,
    before: u64,
    after: u64,
}
impl<'a> Certificate<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 4096,
            "Certificate exceeds its bound"
        );
        let key = super::leaf_key(bytes)?;
        let mut input = bytes;
        let top = field(&mut input, 0x30)?;
        ensure!(input.is_empty(), "Trailing certificate bytes");
        let mut top_fields = top.value;
        let tbs = field(&mut top_fields, 0x30)?;
        ensure!(
            field(&mut top_fields, 0x30)?.full == ALGORITHM,
            "Certificate signature algorithm differs"
        );
        let signature = field(&mut top_fields, 3)?;
        ensure!(
            top_fields.is_empty() && signature.value.len() == 65 && signature.value[0] == 0,
            "Invalid Ed25519 certificate signature"
        );
        let mut fields = tbs.value;
        ensure!(
            field(&mut fields, 0xa0)?.value == [2, 1, 2],
            "Certificate succession requires X.509 v3"
        );
        let serial = field(&mut fields, 2)?;
        ensure!(
            !serial.value.is_empty() && serial.value.len() <= 20 && serial.value[0] & 128 == 0,
            "Invalid certificate serial"
        );
        ensure!(
            field(&mut fields, 0x30)?.full == ALGORITHM,
            "Certificate TBS algorithm differs"
        );
        let issuer = field(&mut fields, 0x30)?.full;
        let validity = field(&mut fields, 0x30)?;
        let mut times = validity.value;
        let before = date(take(&mut times)?)?;
        let after = date(take(&mut times)?)?;
        ensure!(
            times.is_empty() && before < after,
            "Invalid certificate validity"
        );
        let subject = field(&mut fields, 0x30)?.full;
        let spki = field(&mut fields, 0x30)?.full;
        let extensions = field(&mut fields, 0xa3)?.full;
        ensure!(fields.is_empty(), "Unsupported certificate identity fields");
        Ok(Self {
            tbs: tbs.full,
            signature: &signature.value[1..],
            issuer,
            subject,
            spki,
            extensions,
            key,
            before,
            after,
        })
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.subject == other.subject
            && self.spki == other.spki
            && self.extensions == other.extensions
    }
    fn signed_by(&self, issuer: &Self) -> Result<()> {
        ensure!(
            self.issuer == issuer.subject,
            "Certificate issuer identity differs"
        );
        VerifyingKey::from_bytes(&issuer.key)?
            .verify_strict(self.tbs, &Signature::from_slice(self.signature)?)?;
        Ok(())
    }
    fn current(&self, at_ms: u64) -> Result<()> {
        let at = at_ms / 1000;
        ensure!(
            self.before <= at && at < self.after,
            "Certificate is not currently valid"
        );
        Ok(())
    }
}

pub fn der(pem: &str) -> Result<Vec<u8>> {
    ensure!(pem.len() <= 8192, "Certificate PEM exceeds its bound");
    let values = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(values.len() == 1, "One exact certificate is required");
    let bytes = values[0].as_ref().to_vec();
    Certificate::parse(&bytes)?;
    Ok(bytes)
}
/// Legacy replica trust stores repeat each peer's issuer without changing its trust identity.
/// Retain the original PEM bytes for consent hashes; extract only the shared certificate.
pub fn repeated_issuer_der(pem: &str) -> Result<Vec<u8>> {
    ensure!(pem.len() <= 65536, "Runtime issuer store exceeds its bound");
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut remaining = pem;
    let mut issuer: Option<Vec<u8>> = None;
    let mut count = 0;
    loop {
        remaining = remaining.trim_start_matches([' ', '\t', '\r', '\n']);
        if remaining.is_empty() {
            break;
        }
        ensure!(
            count < 16 && remaining.starts_with(BEGIN),
            "Runtime issuer store requires at most 16 certificates and no other material"
        );
        let end = remaining
            .find(END)
            .context("Incomplete runtime issuer certificate")?
            + END.len();
        let bytes = der(&remaining[..end])?;
        if let Some(original) = &issuer {
            ensure!(
                *original == bytes,
                "Runtime issuer store contains distinct certificates; certificate succession requires one issuer"
            );
        } else {
            issuer = Some(bytes);
        }
        remaining = &remaining[end..];
        count += 1;
    }
    issuer.context("Runtime issuer store is empty")
}
pub fn pem(bytes: &[u8]) -> Result<String> {
    Certificate::parse(bytes)?;
    let encoded = STANDARD.encode(bytes);
    let mut result = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(line)?);
        result.push('\n');
    }
    result.push_str("-----END CERTIFICATE-----\n");
    Ok(result)
}
pub fn interval(bytes: &[u8]) -> Result<(u64, u64)> {
    let certificate = Certificate::parse(bytes)?;
    Ok((certificate.before, certificate.after))
}
pub fn issuer_successor(original: &[u8], current: &[u8]) -> Result<()> {
    let old = Certificate::parse(original)?;
    let new = Certificate::parse(current)?;
    old.signed_by(&old)?;
    new.signed_by(&new)?;
    ensure!(
        new.same_identity(&old)
            && new.before >= old.before
            && new.after >= old.after
            && new.after - new.before <= 3650 * 86400,
        "Issuer successor changes identity, extensions or validity policy"
    );
    Ok(())
}
pub fn leaf_successor(
    original: &[u8],
    current: &[u8],
    original_issuer: &[u8],
    current_issuer: &[u8],
) -> Result<()> {
    issuer_successor(original_issuer, current_issuer)?;
    let old = Certificate::parse(original)?;
    let new = Certificate::parse(current)?;
    old.signed_by(&Certificate::parse(original_issuer)?)?;
    new.signed_by(&Certificate::parse(current_issuer)?)?;
    ensure!(
        new.same_identity(&old)
            && new.before >= old.before
            && new.after >= old.after
            && new.after - new.before <= 366 * 86400,
        "Leaf successor changes key, identity, extensions or validity policy"
    );
    Ok(())
}
pub fn current(leaf: &[u8], issuer: &[u8], address: IpAddr, at_ms: u64) -> Result<()> {
    let leaf_parsed = Certificate::parse(leaf)?;
    let issuer_parsed = Certificate::parse(issuer)?;
    leaf_parsed.current(at_ms)?;
    issuer_parsed.current(at_ms)?;
    issuer_parsed.signed_by(&issuer_parsed)?;
    leaf_parsed.signed_by(&issuer_parsed)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(issuer.to_vec()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = Arc::new(roots);
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        roots.clone(),
        provider.clone(),
    )
    .build()?;
    use rustls::client::danger::ServerCertVerifier;
    let time = UnixTime::since_unix_epoch(Duration::from_millis(at_ms));
    verifier.verify_server_cert(
        &CertificateDer::from(leaf),
        &[],
        &ServerName::IpAddress(address.into()),
        &[],
        time,
    )?;
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider).build()?;
    verifier.verify_client_cert(&CertificateDer::from(leaf), &[], time)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeCertificatesTests.rs"]
pub(crate) mod tests;
