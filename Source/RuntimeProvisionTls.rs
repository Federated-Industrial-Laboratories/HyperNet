// SPDX-License-Identifier: MIT
//! Bounded native certificate preparation with explicit pins and no shell interpolation.
use crate::{authority_files, runtime_management::files};
use anyhow::{Context, Result, ensure};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{fs, path::Path};
use zeroize::Zeroizing;

const OPENSSL: &str = "/usr/bin/openssl";
pub(super) fn command(arguments: &[String], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let executable = Path::new(OPENSSL);
    files::ancestors(executable.parent().context("OpenSSL parent absent")?)?;
    files::executable(executable)?;
    // Dependency diagnostics can include supplied material. Keep failures categorical.
    files::capture_input(executable, arguments, 30, 65536, 8192, input)
        .map(|v| v.0)
        .map_err(|_| {
            anyhow::anyhow!(
                "Certificate preparation failed; check the pinned inputs and installed OpenSSL"
            )
        })
}
pub(super) fn text(path: &Path) -> Result<String> {
    files::safe_path(path)?;
    Ok(path.to_str().context("UTF-8 path required")?.to_owned())
}
pub(super) fn certificate(pem: &[u8]) -> Result<Vec<u8>> {
    let values = CertificateDer::pem_slice_iter(pem).collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(values.len() == 1, "One exact certificate is required");
    let der = values[0].as_ref().to_vec();
    crate::runtime_manifest::leaf_key(&der)?;
    Ok(der)
}
pub(super) fn public_key(pem: &[u8]) -> Result<[u8; 32]> {
    let der = command(
        &files::strings(&["pkey", "-pubin", "-outform", "DER"]),
        Some(pem),
    )?;
    const PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
    ];
    ensure!(
        der.len() == 44 && der.starts_with(PREFIX),
        "An Ed25519 transport key is required"
    );
    let key = der[12..].try_into()?;
    crate::trust_wire::valid_key(&key)?;
    Ok(key)
}
pub(super) fn key(directory: &Path) -> Result<[u8; 32]> {
    let private = Zeroizing::new(command(
        &files::strings(&["genpkey", "-algorithm", "ED25519"]),
        None,
    )?);
    files::create(&directory.join("Transport.key"), &private)?;
    let public = command(&files::strings(&["pkey", "-pubout"]), Some(&private))?;
    public_key(&public)
}
pub(super) fn verify_request(pem: &[u8], expected: &[u8; 32]) -> Result<()> {
    command(&files::strings(&["req", "-verify", "-noout"]), Some(pem))?;
    let public = command(&files::strings(&["req", "-pubkey", "-noout"]), Some(pem))?;
    ensure!(
        &public_key(&public)? == expected,
        "Certificate request transport identity differs"
    );
    Ok(())
}
pub(super) fn verify_leaf(
    directory: &Path,
    leaf: &[u8],
    authority: &[u8],
    address: &str,
) -> Result<()> {
    certificate(leaf)?;
    certificate(authority)?;
    let scratch = directory.join(format!("CertificateCheck{}", files::random_id()));
    files::directory(&scratch)?;
    let result = (|| {
        files::create(&scratch.join("Leaf.pem"), leaf)?;
        files::create(&scratch.join("Authority.pem"), authority)?;
        for purpose in ["sslserver", "sslclient"] {
            command(
                &files::strings(&[
                    "verify",
                    "-no-CApath",
                    "-no-CAstore",
                    "-CAfile",
                    &text(&scratch.join("Authority.pem"))?,
                    "-purpose",
                    purpose,
                    "-verify_ip",
                    address,
                    &text(&scratch.join("Leaf.pem"))?,
                ]),
                None,
            )?;
        }
        Ok(())
    })();
    // This directory contains only the two public certificates created above.
    for name in ["Leaf.pem", "Authority.pem"] {
        let path = scratch.join(name);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    fs::remove_dir(&scratch)?;
    result
}
pub(super) fn read_pinned(path: &Path, pin: &str) -> Result<Vec<u8>> {
    crate::trust_bootstrap::hex32(pin)?;
    let bytes = authority_files::read_single(path, 65536, false)?;
    ensure!(
        files::hex_digest(&bytes) == pin,
        "Input differs from its independently authenticated digest"
    );
    Ok(bytes)
}
