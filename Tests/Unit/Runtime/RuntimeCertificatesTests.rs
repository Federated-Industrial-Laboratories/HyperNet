// SPDX-License-Identifier: MIT
// Real Ed25519 issuance checks constrained certificate renewal and legacy resource-identity continuity.
use super::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

pub(crate) struct Fixture {
    pub(crate) original: super::super::Manifest,
    pub(crate) renewed: super::super::Manifest,
    pub(crate) issuer: String,
    pub(crate) next_issuer: String,
}
fn openssl(root: &Path, arguments: &[&str]) {
    let result = Command::new("/usr/bin/openssl")
        .current_dir(root)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "certificate fixture command failed"
    );
}
pub(crate) fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root: PathBuf = std::env::temp_dir().join(format!("HyperNetCertificateSuccessor{}", hex::encode(rand::random::<[u8;16]>())));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        openssl(&root, &["genpkey", "-algorithm", "ED25519", "-out", "Issuer.key"]);
        openssl(&root, &["req", "-new", "-x509", "-batch", "-config", "/dev/null", "-key", "Issuer.key", "-subj", "/CN=HyperNet Transport Issuer", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "Original.pem"]);
        openssl(&root, &["x509", "-in", "Original.pem", "-signkey", "Issuer.key", "-days", "3", "-set_serial", "0x1234", "-out", "Renewed.pem"]);
        let issuer = fs::read_to_string(root.join("Original.pem")).unwrap();
        let next_issuer = pem(&der(&fs::read_to_string(root.join("Renewed.pem")).unwrap()).unwrap()).unwrap();
        let mut original = super::super::tests::fixture();
        original.validity = crate::trust_validity::Validity(1000, crate::trust_validity::End::UntilWithdrawn);
        let mut leaves = BTreeMap::new();
        for (index, endpoint) in original.endpoints.iter_mut().enumerate() {
            openssl(&root, &["genpkey", "-algorithm", "ED25519", "-out", "Transport.key"]);
            openssl(&root, &["req", "-new", "-batch", "-config", "/dev/null", "-key", "Transport.key", "-subj", "/CN=HyperNet Transport", "-out", "Request.pem"]);
            fs::write(root.join("Extensions.cnf"), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:{}\n", endpoint.address)).unwrap();
            openssl(&root, &["x509", "-req", "-in", "Request.pem", "-CA", "Original.pem", "-CAkey", "Issuer.key", "-days", "1", "-set_serial", &format!("{}", index + 1), "-extfile", "Extensions.cnf", "-out", "Leaf.pem"]);
            let old_pem = fs::read_to_string(root.join("Leaf.pem")).unwrap();
            endpoint.leaf_der = der(&old_pem).unwrap();
            endpoint.transport_key = super::super::leaf_key(&endpoint.leaf_der).unwrap();
            if index == 0 {
                use sha2::{Digest, Sha256};
                original.authority_config.as_mut().unwrap().tls_file_digests = [
                    Sha256::digest(issuer.as_bytes()).into(), Sha256::digest(old_pem.as_bytes()).into(), Sha256::digest(fs::read(root.join("Transport.key")).unwrap()).into(),
                ];
            }
            openssl(&root, &["x509", "-req", "-in", "Request.pem", "-CA", "Renewed.pem", "-CAkey", "Issuer.key", "-days", "2", "-set_serial", &format!("{}", index + 101), "-extfile", "Extensions.cnf", "-out", "Leaf.pem"]);
            leaves.insert(endpoint.endpoint_id, der(&fs::read_to_string(root.join("Leaf.pem")).unwrap()).unwrap());
        }
        original.validate().unwrap();
        let mut renewed = original.clone();
        renewed.generation += 1;
        renewed.previous_profile = Some(crate::trust_wire::digest(&original.desired().unwrap()));
        renewed.previous_consent = Some(crate::trust_wire::digest(&original.unsigned_consent(0).unwrap()));
        renewed.adopt_certificates(&original, next_issuer.clone(), &leaves, issuer.clone()).unwrap();
        fs::remove_dir_all(root).unwrap();
        Fixture {original, renewed, issuer, next_issuer}
    })
}
#[test]
fn renewed_certificates_keep_legacy_resource_digest_and_finite_currentness() {
    let f = fixture();
    let before = f.original.operational_digest().unwrap();
    assert_eq!(f.renewed.operational_digest().unwrap(), before);
    assert_eq!(f.renewed.validity, f.original.validity);
    assert!(f.renewed.transport_changed(&f.original));
    let encoded = f.renewed.encode().unwrap();
    assert_eq!(
        crate::trust_wire::decode(&encoded)
            .unwrap()
            .array(24)
            .unwrap()[1]
            .uint()
            .unwrap(),
        2
    );
    assert_eq!(super::super::Manifest::parse(&encoded).unwrap(), f.renewed);
    assert!(
        crate::trust_wire::decode(&f.original.encode().unwrap())
            .unwrap()
            .array(23)
            .is_ok()
    );
    let at = (interval(&f.original.endpoints[0].leaf_der).unwrap().0 + 36 * 3600) * 1000;
    assert!(
        current(
            &f.original.endpoints[0].leaf_der,
            &der(&f.issuer).unwrap(),
            f.original.endpoints[0].address,
            at
        )
        .is_err()
    );
    f.renewed.current_transport(at).unwrap();
    assert!(f.renewed.current_transport(0).is_err());
    assert!(
        f.renewed
            .current_transport(interval(&f.renewed.endpoints[0].leaf_der).unwrap().1 * 1000)
            .is_err()
    );
    assert!(
        current(
            &f.renewed.endpoints[0].leaf_der,
            &der(&f.next_issuer).unwrap(),
            "192.0.2.250".parse().unwrap(),
            at
        )
        .is_err()
    );
}
#[test]
fn certificate_origin_cannot_change_resources_private_key_or_endpoint_identity() {
    let f = fixture();
    for change in 0..6 {
        let mut altered = f.renewed.clone();
        match change {
            0 => altered.roles[0].memory_bytes += 4096,
            1 => altered.endpoints[0].port += 1,
            2 => altered.authority_config.as_mut().unwrap().tls_file_digests[2] = [91; 32],
            3 => {
                altered
                    .transport_certificates
                    .as_mut()
                    .unwrap()
                    .origin
                    .endpoints[0]
                    .leaf_der[20] ^= 1
            }
            4 => altered.transport_certificates = None,
            _ => altered.endpoints[0].transport_key = [92; 32],
        }
        assert!(
            altered.successor_of(&f.original).is_err(),
            "change {change}"
        );
    }
    let mut stale = f.renewed.clone();
    stale.previous_consent = Some([99; 32]);
    assert!(stale.successor_of(&f.original).is_err());
}
#[test]
fn certificate_date_parser_checks_calendar_and_canonical_utc_encoding() {
    let time = |tag, value: &'static [u8]| {
        date(Item {
            tag,
            full: value,
            value,
        })
    };
    assert_eq!(time(0x17, b"700101000000Z").unwrap(), 0);
    assert_eq!(time(0x17, b"000229000000Z").unwrap(), 951782400);
    assert!(time(0x18, b"21000229000000Z").is_err());
    assert!(time(0x17, b"001301000000Z").is_err());
    assert!(time(0x17, b"000101000060Z").is_err());
    assert!(time(0x18, b"20260101000000Z").is_err());
    assert!(time(0x17, b"7001010000Z").is_err());
}

#[cfg(test)]
pub(crate) fn expired_certificate(value: &str, key: &Path, directory: &Path) -> String {
    dated_certificate(value, key, directory, b"200101000000Z", b"200102000000Z")
}
fn dated_certificate(
    value: &str,
    key: &Path,
    directory: &Path,
    before: &[u8],
    after: &[u8],
) -> String {
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if bytes.len() < 128 {
            out.push(bytes.len() as u8);
        } else if bytes.len() <= 255 {
            out.extend([0x81, bytes.len() as u8]);
        } else {
            out.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
        }
        out.extend(bytes);
        out
    }
    let bytes = der(value).unwrap();
    let parsed = Certificate::parse(&bytes).unwrap();
    let mut encoded_tbs = parsed.tbs;
    let mut fields = field(&mut encoded_tbs, 0x30).unwrap().value;
    let mut body = Vec::new();
    for index in 0..8 {
        let item = take(&mut fields).unwrap();
        if index == 4 {
            let mut dates = tlv(0x17, before);
            dates.extend(tlv(0x17, after));
            body.extend(tlv(0x30, &dates));
        } else {
            body.extend(item.full);
        }
    }
    assert!(fields.is_empty());
    let tbs = tlv(0x30, &body);
    let input = directory.join("ExpiredTbs.der");
    let output = directory.join("ExpiredSignature.bin");
    fs::write(&input, &tbs).unwrap();
    let result = Command::new("/usr/bin/openssl")
        .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
        .arg(key)
        .arg("-in")
        .arg(&input)
        .arg("-out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "historical certificate signing failed"
    );
    let mut signed = tbs;
    signed.extend(ALGORITHM);
    let mut signature = vec![0];
    signature.extend(fs::read(&output).unwrap());
    signed.extend(tlv(3, &signature));
    fs::remove_file(input).unwrap();
    fs::remove_file(output).unwrap();
    pem(&tlv(0x30, &signed)).unwrap()
}

#[test]
fn expired_issuer_signature_remains_history_but_cannot_serve_as_current_certificate() {
    let root = std::env::temp_dir().join(format!(
        "HyperNetExpiredIssuer{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    openssl(
        &root,
        &["genpkey", "-algorithm", "ED25519", "-out", "Issuer.key"],
    );
    openssl(
        &root,
        &[
            "req",
            "-new",
            "-x509",
            "-batch",
            "-config",
            "/dev/null",
            "-key",
            "Issuer.key",
            "-subj",
            "/CN=HyperNet Transport Issuer",
            "-days",
            "2",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            "Current.pem",
        ],
    );
    let current = fs::read_to_string(root.join("Current.pem")).unwrap();
    let expired = expired_certificate(&current, &root.join("Issuer.key"), &root);
    let old_der = der(&expired).unwrap();
    let new_der = der(&current).unwrap();
    issuer_successor(&old_der, &new_der).unwrap();
    let at = interval(&new_der).unwrap().0 * 1000;
    assert!(Certificate::parse(&old_der).unwrap().current(at).is_err());
    Certificate::parse(&new_der).unwrap().current(at).unwrap();
    fs::remove_dir_all(root).unwrap();
}

/// Real signatures at the small logical clock used by the authority integration fixtures.
pub(crate) fn route_certificates() -> (String, String, Vec<u8>, Vec<u8>) {
    route_certificates_until(b"700102000000Z", b"700103000000Z")
}
pub(crate) fn route_certificates_until(
    before: &[u8],
    after: &[u8],
) -> (String, String, Vec<u8>, Vec<u8>) {
    let root = std::env::temp_dir().join(format!(
        "HyperNetRouteCertificates{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    openssl(
        &root,
        &["genpkey", "-algorithm", "ED25519", "-out", "Issuer.key"],
    );
    openssl(
        &root,
        &[
            "req",
            "-new",
            "-x509",
            "-batch",
            "-config",
            "/dev/null",
            "-key",
            "Issuer.key",
            "-subj",
            "/CN=HyperNet Route Issuer",
            "-days",
            "2",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            "Issuer.pem",
        ],
    );
    let mut key = vec![
        0x30, 0x2e, 0x02, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    key.extend([110; 32]);
    fs::write(root.join("Transport.der"), key).unwrap();
    openssl(
        &root,
        &[
            "req",
            "-new",
            "-batch",
            "-config",
            "/dev/null",
            "-keyform",
            "DER",
            "-key",
            "Transport.der",
            "-subj",
            "/CN=HyperNet Route",
            "-out",
            "Request.pem",
        ],
    );
    fs::write(root.join("Extensions.cnf"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:192.0.2.10\n").unwrap();
    openssl(
        &root,
        &[
            "x509",
            "-req",
            "-in",
            "Request.pem",
            "-CA",
            "Issuer.pem",
            "-CAkey",
            "Issuer.key",
            "-days",
            "1",
            "-set_serial",
            "1",
            "-extfile",
            "Extensions.cnf",
            "-out",
            "Leaf.pem",
        ],
    );
    let issuer = fs::read_to_string(root.join("Issuer.pem")).unwrap();
    let leaf = fs::read_to_string(root.join("Leaf.pem")).unwrap();
    let date = |value: &str, end: &[u8]| {
        dated_certificate(
            value,
            &root.join("Issuer.key"),
            &root,
            b"700101000000Z",
            end,
        )
    };
    let before_issuer = date(&issuer, before);
    let after_issuer = date(&issuer, after);
    let before_leaf = der(&date(&leaf, before)).unwrap();
    let after_leaf = der(&date(&leaf, after)).unwrap();
    current(
        &after_leaf,
        &der(&after_issuer).unwrap(),
        "192.0.2.10".parse().unwrap(),
        1000,
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
    (before_issuer, after_issuer, before_leaf, after_leaf)
}

#[test]
fn repeated_issuer_store_accepts_only_bounded_identical_certificates() {
    let f = fixture();
    let expected = der(&f.issuer).unwrap();
    for count in [1, 4, 16] {
        let raw = format!("{}\n", f.issuer).repeat(count);
        assert_eq!(repeated_issuer_der(&raw).unwrap(), expected);
    }
    assert!(der(&format!("{}\n{}", f.issuer, f.issuer)).is_err());
    for invalid in [
        String::new(),
        format!("{}\n", f.issuer).repeat(17),
        format!("{}\n{}", f.issuer, f.next_issuer),
        format!("{}\nnot a certificate", f.issuer),
        format!("{}\n-----BEGIN PRIVATE KEY-----\n", f.issuer),
        " ".repeat(65537),
    ] {
        assert!(repeated_issuer_der(&invalid).is_err());
    }
}

#[test]
fn repeated_issuer_origin_preserves_exact_legacy_consent_and_future_successors() {
    use sha2::{Digest, Sha256};
    let f = fixture();
    let raw = format!("{}\n", f.issuer).repeat(4);
    let mut original = f.original.clone();
    original.authority_config.as_mut().unwrap().tls_file_digests[0] =
        Sha256::digest(raw.as_bytes()).into();
    let original_digest = original.operational_digest().unwrap();
    let mut successor = original.clone();
    successor.generation += 1;
    successor.previous_profile = Some(crate::trust_wire::digest(&original.desired().unwrap()));
    successor.previous_consent = Some(crate::trust_wire::digest(
        &original.unsigned_consent(0).unwrap(),
    ));
    let leaves = f
        .renewed
        .endpoints
        .iter()
        .map(|e| (e.endpoint_id, e.leaf_der.clone()))
        .collect();
    successor
        .adopt_certificates(&original, f.next_issuer.clone(), &leaves, raw.clone())
        .unwrap();
    assert_eq!(successor.operational_digest().unwrap(), original_digest);
    assert_eq!(
        successor
            .transport_certificates
            .as_ref()
            .unwrap()
            .origin
            .issuer_pem,
        raw
    );
    assert_eq!(
        successor
            .authority_config
            .as_ref()
            .unwrap()
            .tls_file_digests[2],
        original.authority_config.as_ref().unwrap().tls_file_digests[2]
    );
    assert_eq!(
        super::super::Manifest::parse(&successor.encode().unwrap()).unwrap(),
        successor
    );
    let at = successor.transport_interval().unwrap().unwrap().0;
    successor.current_transport(at).unwrap();
    let original_encoding = f.renewed.transport_certificates.as_ref().unwrap().value();
    assert_eq!(
        original_encoding.array(5).unwrap()[0],
        super::super::V::Uint(1)
    );
    let metadata = successor.transport_certificates.as_ref().unwrap().value();
    assert_eq!(metadata.array(5).unwrap()[0], super::super::V::Uint(2));
    for case in 0..5 {
        let mut fields = metadata.array(5).unwrap().to_vec();
        match case {
            0 => fields[0] = super::super::V::Uint(1),
            1 => fields[3] = super::super::V::Bytes(f.issuer.as_bytes().to_vec()),
            2 => fields[3] = super::super::V::Text(raw.clone()),
            3 => fields[3] = super::super::V::Bytes(vec![255; 1025]),
            _ => fields[3] = super::super::V::Bytes(vec![b' '; 65537]),
        }
        assert!(
            super::super::transport::Certificates::parse(&super::super::V::Array(fields)).is_err(),
            "origin form {case}"
        );
    }
    let mut changed_origin = successor.clone();
    changed_origin
        .transport_certificates
        .as_mut()
        .unwrap()
        .origin
        .issuer_pem = f.issuer.clone();
    assert!(changed_origin.validate().is_err());
    let mut future = successor.clone();
    future.generation += 1;
    future.previous_profile = Some(crate::trust_wire::digest(&successor.desired().unwrap()));
    future.previous_consent = Some(crate::trust_wire::digest(
        &successor.unsigned_consent(0).unwrap(),
    ));
    future
        .adopt_certificates(
            &successor,
            f.next_issuer.clone(),
            &leaves,
            f.next_issuer.clone(),
        )
        .unwrap();
    assert_eq!(future.operational_digest().unwrap(), original_digest);
    assert_eq!(
        future
            .transport_certificates
            .as_ref()
            .unwrap()
            .origin
            .issuer_pem,
        raw
    );
}
