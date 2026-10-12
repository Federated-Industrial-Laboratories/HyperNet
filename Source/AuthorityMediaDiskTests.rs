// SPDX-License-Identifier: MIT
// Complete-copy receipts require validated immutable bytes across interruption and exact retries.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_domains::Operation};
struct Fixture {
    path: std::path::PathBuf,
    profile: HostProfile,
    asset: Asset,
    asset_ref: VersionRef,
    host_ref: VersionRef,
    payload: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
impl Fixture {
    fn new() -> Self {
        let manifest = deployment::manifest();
        let service = manifest.services()[&2];
        let mut profile = HostProfile {
            manifest: manifest.clone(),
            role: 2,
            service,
            volume: [102; 32],
            namespaces: vec!["Books".into()],
            state_bytes: 1024 * 1024,
            maximum_asset_bytes: 128 * 1024,
            retention_ms: 100000,
            content: None,
            envelope: vec![],
        };
        profile.envelope =
            wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
        let profile =
            HostProfile::parse(&profile.envelope, manifest.network, manifest.incarnation).unwrap();
        let version = |kind, id| VersionRef {
            kind,
            id,
            generation: 1,
            digest: [81; 32],
        };
        let host_ref = version(143, service);
        let payload = vec![47; 192 * 192 * 3];
        let asset = Asset {
            revision: version(141, [71; 32]),
            manifest: crate::markup::media::Asset {
                id: "Poster".into(),
                profile: crate::markup::media::RASTER_PROFILE.into(),
                width: 192,
                height: 192,
                bytes: payload.len() as u64,
                digest: hex::encode(hash(&payload)),
                hosts: vec![hex::encode(service)],
                copies: 1,
            },
            hosts: vec![host_ref.clone()],
            required_copies: 1,
            upload_expires_ms: 50000,
            expires_ms: 100000,
        };
        let asset_ref = version(144, asset.identity().unwrap());
        let path = std::env::temp_dir().join(format!(
            "HyperNetMediaDisk{}.bin",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        Disk::initialise(&path, &profile).unwrap();
        Self {
            path,
            profile,
            asset,
            asset_ref,
            host_ref,
            payload,
        }
    }
    fn request(
        &self,
        effect: MediaEffect,
        offset: u64,
        bytes: u64,
        digest: Option<Digest>,
    ) -> MediaRequest {
        let command = Command::MediaAuthorise {
            asset: self.asset_ref.clone(),
            host: self.host_ref.clone(),
            effect,
            offset,
            bytes,
            digest,
        };
        let operation = Operation {
            grant: Some(VersionRef {
                kind: 102,
                id: [23; 32],
                generation: 1,
                digest: [82; 32],
            }),
            command: command.into(),
            snapshot: domains::snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        MediaRequest::parse(&deployment::signed(
            &deployment::key(5),
            "AuthorityDomain",
            operation.command.resource(),
            u64::from(operation.mutation()),
            wire::decode(&operation.parameters().unwrap()).unwrap(),
            vec![],
        ))
        .unwrap()
    }
    fn put(&self, disk: &mut Disk, offset: usize, bytes: &[u8]) -> Result<Vec<u8>> {
        let request = self.request(
            MediaEffect::Upload,
            offset as u64,
            bytes.len() as u64,
            Some(hash(bytes)),
        );
        disk.execute(
            &request,
            &self.asset,
            &self.profile,
            bytes,
            &deployment::key(101),
            1000,
        )
    }
}
#[test]
fn media_interrupted_upload_reopens_and_issues_only_complete_validated_receipt() {
    let f = Fixture::new();
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    let first = f.put(&mut disk, 0, &f.payload[..32768]).unwrap();
    assert_eq!(
        wire::decode(&first).unwrap().array(11).unwrap()[10],
        V::Null
    );
    let inactive = (1 - disk.active) as u64 * disk.bank;
    disk.file
        .write_all_at(b"InterruptedSuccessor", inactive + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    assert_eq!(disk.state.records[&f.asset_ref.id].payload.len(), 32768);
    assert_eq!(f.put(&mut disk, 0, &f.payload[..32768]).unwrap(), first);
    let last_start = (f.payload.len() - 1) / 32768 * 32768;
    for start in (32768..last_start).step_by(32768) {
        f.put(&mut disk, start, &f.payload[start..start + 32768])
            .unwrap();
    }
    let mut altered = f.payload[last_start..].to_vec();
    altered[0] ^= 1;
    assert!(f.put(&mut disk, last_start, &altered).is_err());
    assert!(disk.state.records[&f.asset_ref.id].receipt.is_none());
    assert_eq!(
        disk.state.records[&f.asset_ref.id].payload.len(),
        last_start
    );
    let complete = f
        .put(&mut disk, last_start, &f.payload[last_start..])
        .unwrap();
    let value = wire::decode(&complete).unwrap();
    let receipt = CopyReceipt::parse(
        value.array(11).unwrap()[10].bytes().unwrap(),
        f.profile.manifest.network,
        f.profile.manifest.incarnation,
    )
    .unwrap();
    assert_eq!(receipt.digest, hash(&f.payload));
    assert_eq!(receipt.bytes, f.payload.len() as u64);
    assert!(
        crate::authority_domains::page::media_storage_charge(&f.asset).unwrap()
            >= wire::encode_bounded(&disk.state.records[&f.asset_ref.id].value(), 1024 * 1024)
                .unwrap()
                .len() as u64
    );
    drop(disk);
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    assert_eq!(
        f.put(&mut disk, last_start, &f.payload[last_start..])
            .unwrap(),
        complete
    );
    let request = f.request(
        MediaEffect::Read,
        last_start as u64,
        (f.payload.len() - last_start) as u64,
        None,
    );
    let response = disk
        .execute(
            &request,
            &f.asset,
            &f.profile,
            &[],
            &deployment::key(101),
            1000,
        )
        .unwrap();
    assert_eq!(
        wire::decode(&response).unwrap().array(11).unwrap()[9]
            .bytes()
            .unwrap(),
        &f.payload[last_start..]
    );
}
#[test]
fn media_corrupt_committed_bank_is_not_reset_or_served() {
    let f = Fixture::new();
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    f.put(&mut disk, 0, &f.payload[..32768]).unwrap();
    disk.file
        .write_all_at(&[255], disk.active as u64 * disk.bank + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    assert!(Disk::open(&f.path, &f.profile, 1000).is_err());
}
