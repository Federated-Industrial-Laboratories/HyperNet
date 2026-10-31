// SPDX-License-Identifier: MIT
// Interrupted banks preserve committed ciphertext; deletion cannot reopen a transfer through replay.
use super::*;
use crate::{
    authority_domains::transfer::{Acceptance, Offer},
    authority_proof::VersionRef,
};
struct Fixture {
    path: std::path::PathBuf,
    profile: Profile,
    transfer: Agreement,
    payload: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
impl Fixture {
    fn new() -> Self {
        let manifest = crate::authority_deployment_tests::manifest();
        let service = manifest.services()[&4];
        let payload = vec![47; transfer::CHUNK as usize + 29];
        let profile = Profile {
            manifest: manifest.clone(),
            service,
            endpoint: Some([84; 32]),
            volume: [104; 32],
            state_bytes: 1024 * 1024,
            maximum_payload: 128 * 1024,
            maximum_lifetime_ms: 100000,
            envelope: vec![],
        };
        let version = |kind, id| VersionRef {
            kind,
            id,
            generation: 1,
            digest: [81; 32],
        };
        let transfer = Agreement {
            offer: Offer {
                network: manifest.network,
                incarnation: manifest.incarnation,
                id: [77; 32],
                sender: [78; 32],
                recipient: [79; 32],
                encryption_key: String::new(),
                payload_bytes: payload.len() as u64,
                payload_digest: wire::digest(&payload),
                file_bytes: 100,
                label: "Document".into(),
                expires: 100000,
                envelope: b"ImmutableAcceptedOffer".to_vec(),
            },
            capability: version(102, [80; 32]),
            acceptance: Some(Acceptance {
                service: version(134, service),
                capability: version(102, [82; 32]),
                destination: "Inbox".into(),
                expires: 100000,
                intent: [83; 32],
            }),
            cancelled: false,
            creation: [84; 32],
        };
        let path = std::env::temp_dir().join(format!(
            "HyperNetTransferDisk{}.bin",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        Disk::initialise(&path, &profile).unwrap();
        Self {
            path,
            profile,
            transfer,
            payload,
        }
    }
    fn command(&self, effect: Effect, offset: u64, count: u64) -> Command {
        Command::Execute {
            id: self.transfer.offer.id,
            effect,
            offset,
            bytes: count,
            digest: if effect == Effect::Put {
                Some(wire::digest(
                    &self.payload[offset as usize..(offset + count) as usize],
                ))
            } else {
                None
            },
        }
    }
    fn put(&self, d: &mut Disk, offset: u64) {
        let bytes = (self.payload.len() as u64 - offset).min(transfer::CHUNK);
        d.execute(
            &self.transfer,
            &self.command(Effect::Put, offset, bytes),
            &self.payload[offset as usize..(offset + bytes) as usize],
            1000,
            false,
        )
        .unwrap();
    }
}
#[test]
fn transfer_bank_interruption_resume_and_tombstone_reconciliation() {
    let f = Fixture::new();
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    f.put(&mut disk, 0);
    let inactive = (1 - disk.active) as u64 * disk.bank;
    // A payload written before its header is durable is not a committed successor.
    disk.file
        .write_all_at(b"InterruptedNewPayload", inactive + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    assert_eq!(
        disk.state.records[&f.transfer.offer.id].payload.len(),
        transfer::CHUNK as usize
    );
    f.put(&mut disk, transfer::CHUNK);
    let commit = f.command(Effect::Commit, 0, 0);
    disk.execute(&f.transfer, &commit, &[], 1000, false)
        .unwrap();
    drop(disk);
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    let got = disk
        .execute(
            &f.transfer,
            &f.command(Effect::Fetch, transfer::CHUNK, 29),
            &[],
            1000,
            false,
        )
        .unwrap();
    assert_eq!(
        wire::decode(&got).unwrap().array(12).unwrap()[11]
            .bytes()
            .unwrap(),
        &f.payload[transfer::CHUNK as usize..]
    );
    let delete = f.command(Effect::Delete, 0, 0);
    disk.execute(&f.transfer, &delete, &[], 1000, false)
        .unwrap();
    drop(disk);
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    let put = f.command(Effect::Put, 0, transfer::CHUNK);
    let bytes = &f.payload[..transfer::CHUNK as usize];
    assert!(disk.execute(&f.transfer, &put, bytes, 1000, false).is_err());
    disk.execute(&f.transfer, &put, bytes, 1000, true).unwrap();
    assert!(disk.state.records[&f.transfer.offer.id].payload.is_empty());
    assert!(
        disk.execute(
            &f.transfer,
            &f.command(Effect::Fetch, 0, 29),
            &[],
            1000,
            true
        )
        .is_err()
    );
    disk.execute(&f.transfer, &delete, &[], 1000, true).unwrap();
}
#[test]
fn transfer_disk_rejects_corruption_and_changed_chunk_without_reset() {
    let f = Fixture::new();
    let mut disk = Disk::open(&f.path, &f.profile, 1000).unwrap();
    f.put(&mut disk, 0);
    let command = f.command(Effect::Put, 0, transfer::CHUNK);
    let mut changed = f.payload[..transfer::CHUNK as usize].to_vec();
    changed[0] ^= 1;
    assert!(
        disk.execute(&f.transfer, &command, &changed, 1000, true)
            .is_err()
    );
    let active = disk.active as u64 * disk.bank;
    disk.file.write_all_at(&[255], active + HEADER).unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    assert!(Disk::open(&f.path, &f.profile, 1000).is_err());
}
