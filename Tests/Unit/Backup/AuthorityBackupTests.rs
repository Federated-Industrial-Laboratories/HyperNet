// SPDX-License-Identifier: MIT
// Cold archives cannot exceed separate owner, placement, encryption or retention consent.
use super::*;
use crate::authority_deployment_tests as deployment;
pub(crate) fn profile() -> Profile {
    let mut manifest = deployment::manifest();
    manifest
        .volumes
        .iter_mut()
        .find(|v| v.volume_id == [101; 32])
        .unwrap()
        .storage_admission_bytes += 4 * 1024 * 1024;
    let mut p = Profile {
        manifest,
        id: [210; 32],
        name: "ColdArchive".into(),
        volume: [101; 32],
        bytes: 2 * 1024 * 1024,
        objects: 4,
        retention_ms: 86400000,
        recipients: vec![[9; 32]],
        owners: vec![deployment::key(5).verifying_key().to_bytes()],
        opaque: false,
        envelope: vec![],
    };
    p.envelope = wire::sign_envelope(&p.payload().unwrap(), &deployment::key(90)).unwrap();
    Profile::parse(&p.envelope, p.manifest.network, p.manifest.incarnation).unwrap()
}
pub(crate) fn archive(p: &Profile, bytes: &[u8]) -> Archive {
    let mut a = Archive {
        id: [211; 32],
        owner: p.owners[0],
        destination: VersionRef {
            kind: DESTINATION,
            id: p.id,
            generation: 1,
            digest: [212; 32],
        },
        placement: VersionRef {
            kind: 159,
            id: [213; 32],
            generation: 1,
            digest: [214; 32],
        },
        assets: vec![],
        digest: wire::digest(bytes),
        bytes: bytes.len() as u64,
        created_ms: 10000,
        expires_ms: 20000,
        opaque: false,
        envelope: vec![],
    };
    a.envelope = wire::sign_envelope(
        &a.payload(p.manifest.network, p.manifest.incarnation)
            .unwrap(),
        &deployment::key(5),
    )
    .unwrap();
    a
}
#[test]
fn backup_consent_cannot_consume_service_allocation_and_manifest_is_exact() {
    let mut p = profile();
    p.bytes = 5 * 1024 * 1024;
    p.envelope = wire::sign_envelope(&p.payload().unwrap(), &deployment::key(90)).unwrap();
    assert!(Profile::parse(&p.envelope, p.manifest.network, p.manifest.incarnation).is_err());
    let p = profile();
    let data = b"age-encryption.org/v1\nCiphertext";
    let a = archive(&p, data);
    a.admitted(&p, 10000).unwrap();
    assert!(a.admitted(&p, 20000).is_err());
    let mut wrong = p.clone();
    wrong.owners = vec![deployment::key(4).verifying_key().to_bytes()];
    assert!(a.admitted(&wrong, 10000).is_err());
    let package = package::Package {
        profile: p.clone(),
        archive: a,
        ciphertext: data.to_vec(),
    };
    let encoded = package.encode().unwrap();
    package::Package::parse(&encoded, p.manifest.network, p.manifest.incarnation).unwrap();
    let mut bad = wire::decode_bounded(&encoded, package::PACKAGE_LIMIT).unwrap();
    if let V::Array(ref mut f) = bad {
        f[5] = b(b"age-encryption.org/v1\nChanged");
    }
    assert!(
        package::Package::parse(
            &wire::encode_bounded(&bad, package::PACKAGE_LIMIT).unwrap(),
            p.manifest.network,
            p.manifest.incarnation
        )
        .is_err()
    );
}
