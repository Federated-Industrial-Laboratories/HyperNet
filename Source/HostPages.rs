// SPDX-License-Identifier: MIT
//! Volatile approved-page storage and outward-only replica delivery.
use super::{HostConfig, fixed_hex, now, read_bounded, request};
use crate::{page_authority, types};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, os::unix::fs::MetadataExt, path::PathBuf};

const MAXIMUM_OBJECTS: usize = 256;
const MAXIMUM_BUNDLE: usize = 64 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    enabled: bool,
    ready: bool,
    objects: usize,
    bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPage {
    descriptor: types::PageDescriptor,
    bundle: types::PageBundle,
}

struct Cached {
    path: PathBuf,
    descriptor: Vec<u8>,
    cost: u64,
    inserted: u64,
}

struct Storage {
    directory: PathBuf,
    quota: u64,
    block_size: u64,
    sequence: u64,
    files: BTreeMap<String, Cached>,
}

impl Storage {
    fn new(directory: PathBuf, quota: u64) -> Result<Self> {
        fs::create_dir(&directory).context("a fresh Pages cache is required")?;
        let block_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        ensure!(block_size > 0, "filesystem allocation size is unavailable");
        Ok(Self {
            directory,
            quota,
            block_size: block_size as u64,
            sequence: 0,
            files: BTreeMap::new(),
        })
    }

    fn bytes(&self) -> u64 {
        self.files.values().map(|file| file.cost).sum()
    }

    fn remove(&mut self, page_id: &str) -> Result<()> {
        if let Some(file) = self.files.get(page_id) {
            match fs::remove_file(&file.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.files.remove(page_id);
        Ok(())
    }

    fn prune(&mut self, inventory: &BTreeMap<String, types::PageDescriptor>) -> Result<()> {
        let mut removed = Vec::new();
        for (id, file) in &self.files {
            if inventory
                .get(id)
                .map(serde_json::to_vec)
                .transpose()?
                .is_none_or(|descriptor| descriptor != file.descriptor)
            {
                removed.push(id.clone());
            }
        }
        for id in removed {
            self.remove(&id)?;
        }
        Ok(())
    }

    fn insert(&mut self, page: &StoredPage) -> Result<()> {
        let bytes = serde_json::to_vec(page)?;
        ensure!(
            bytes.len() <= MAXIMUM_BUNDLE,
            "approved bundle exceeds cache object limit"
        );
        let cost = (bytes.len() as u64).div_ceil(self.block_size) * self.block_size;
        ensure!(cost <= self.quota, "approved bundle exceeds cache consent");
        self.remove(&page.descriptor.page_id)?;
        while self.bytes() + cost > self.quota || self.files.len() >= MAXIMUM_OBJECTS {
            let oldest = self
                .files
                .iter()
                .min_by_key(|(_, file)| file.inserted)
                .map(|(id, _)| id.clone())
                .context("cache quota cannot be satisfied")?;
            self.remove(&oldest)?;
        }
        let path = self
            .directory
            .join(format!("Page{}.json", hex::encode(Sha256::digest(&bytes))));
        let temporary = self.directory.join("Incoming.json");
        let stored = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            ensure!(
                file.metadata()?.blocks().saturating_mul(512) <= cost,
                "cache allocation exceeds its quota charge"
            );
            fs::rename(&temporary, &path)?;
            Ok(())
        })();
        if stored.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        stored?;
        self.sequence = self.sequence.saturating_add(1);
        self.files.insert(
            page.descriptor.page_id.clone(),
            Cached {
                path,
                descriptor: serde_json::to_vec(&page.descriptor)?,
                cost,
                inserted: self.sequence,
            },
        );
        Ok(())
    }

    fn bundle(
        &self,
        network: &str,
        descriptor: &types::PageDescriptor,
    ) -> Result<Option<types::PageBundle>> {
        let Some(file) = self.files.get(&descriptor.page_id) else {
            return Ok(None);
        };
        ensure!(
            file.descriptor == serde_json::to_vec(descriptor)?,
            "cached publication changed"
        );
        let bytes = read_bounded(&file.path, MAXIMUM_BUNDLE)?;
        let expected = format!("Page{}.json", hex::encode(Sha256::digest(&bytes)));
        ensure!(
            file.path
                .file_name()
                .is_some_and(|name| name == expected.as_str()),
            "cache content changed"
        );
        let stored: StoredPage = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_vec(&stored.descriptor)? == file.descriptor,
            "cache descriptor changed"
        );
        page_authority::verify_bundle(network, descriptor, &stored.bundle)
            .map_err(anyhow::Error::msg)?;
        Ok(Some(stored.bundle))
    }
}

pub struct Replica {
    storage: Option<Storage>,
    inventory: BTreeMap<String, types::PageDescriptor>,
    inventory_digest: Option<String>,
    pending: Vec<types::ReplicaTicket>,
    authority_revision: u64,
    valid_until: u64,
    ready: bool,
}

impl Replica {
    pub fn new(config: &HostConfig) -> Result<Self> {
        let storage = config
            .consent
            .page_cache_bytes
            .map(|quota| Storage::new(config.state_directory.join("Pages"), quota))
            .transpose()?;
        Ok(Self {
            storage,
            inventory: BTreeMap::new(),
            inventory_digest: None,
            pending: Vec::new(),
            authority_revision: 0,
            valid_until: 0,
            ready: false,
        })
    }

    pub fn invalidate(&mut self) {
        self.ready = false;
        self.valid_until = 0;
        self.inventory_digest = None;
        self.inventory.clear();
        self.pending.clear();
    }

    pub fn status(&self) -> Status {
        Status {
            enabled: self.storage.is_some(),
            ready: self.ready,
            objects: self
                .storage
                .as_ref()
                .map_or(0, |storage| storage.files.len()),
            bytes: self.storage.as_ref().map_or(0, Storage::bytes),
        }
    }

    fn validate_inventory(
        &self,
        config: &HostConfig,
        entries: Vec<types::PageDescriptor>,
    ) -> Result<BTreeMap<String, types::PageDescriptor>> {
        ensure!(
            entries.len() <= MAXIMUM_OBJECTS,
            "replica inventory exceeds object limit"
        );
        let namespaces = config
            .consent
            .namespaces
            .as_ref()
            .context("Pages consent is required")?;
        let mut inventory = BTreeMap::new();
        for descriptor in entries {
            fixed_hex::<16>(&descriptor.page_id)?;
            fixed_hex::<32>(&descriptor.digest)?;
            fixed_hex::<32>(&descriptor.author)?;
            fixed_hex::<32>(&descriptor.reviewer)?;
            fixed_hex::<32>(&descriptor.submission_digest)?;
            fixed_hex::<32>(&descriptor.approval_digest)?;
            ensure!(
                namespaces.contains(&descriptor.namespace)
                    && descriptor.audience == "Members"
                    && descriptor.profile == "HyperNetPage/1"
                    && descriptor.publication_version > 0,
                "inventory exceeds Pages consent"
            );
            ensure!(
                inventory
                    .insert(descriptor.page_id.clone(), descriptor)
                    .is_none(),
                "duplicate page identity"
            );
        }
        Ok(inventory)
    }

    pub async fn synchronise(
        &mut self,
        config: &HostConfig,
        client: &reqwest::Client,
        epoch: &mut u64,
    ) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let fetch = self
            .pending
            .iter()
            .map(|ticket| &ticket.descriptor.page_id)
            .chain(self.inventory.keys())
            .find(|id| !storage.files.contains_key(*id))
            .cloned();
        let reply = request(
            config,
            client,
            types::Command::PageSync {
                profile: config.profile_digest.clone(),
                known_inventory: self.inventory_digest.clone(),
                fetch: fetch.clone(),
            },
            *epoch,
        )
        .await?;
        *epoch = reply.epoch;
        let result: types::PageSyncResult = serde_json::from_value(reply.result)?;
        let current = now()?;
        ensure!(
            result.profile == config.profile_digest
                && result.authority_revision >= self.authority_revision
                && result.authority_revision > 0
                && result.valid_until > current
                && result.valid_until <= current.saturating_add(5)
                && result.valid_until <= config.consent.expires,
            "invalid Pages freshness"
        );
        fixed_hex::<32>(&result.inventory_digest)?;
        if let Some(entries) = result.entries {
            ensure!(
                entries
                    .windows(2)
                    .all(|pair| pair[0].page_id < pair[1].page_id),
                "inventory is not ordered"
            );
            ensure!(
                page_authority::inventory_digest(&entries).map_err(anyhow::Error::msg)?
                    == result.inventory_digest,
                "inventory digest mismatch"
            );
            let inventory = self.validate_inventory(config, entries)?;
            self.storage.as_mut().context("cache")?.prune(&inventory)?;
            self.inventory = inventory;
        } else {
            ensure!(
                self.inventory_digest.as_ref() == Some(&result.inventory_digest),
                "changed inventory was omitted"
            );
        }
        ensure!(result.requests.len() <= 4, "too many replica requests");
        let mut tickets = std::collections::BTreeSet::new();
        for ticket in &result.requests {
            fixed_hex::<32>(&ticket.ticket_id)?;
            ensure!(
                tickets.insert(&ticket.ticket_id),
                "duplicate replica ticket"
            );
            let descriptor = self
                .inventory
                .get(&ticket.descriptor.page_id)
                .context("ticket is outside consented inventory")?;
            ensure!(
                ticket.descriptor == *descriptor
                    && ticket.expires > current
                    && ticket.expires <= current.saturating_add(15),
                "invalid replica ticket"
            );
        }
        if let Some(bundle) = result.bundle {
            let id = fetch.as_ref().context("unsolicited replica bundle")?;
            let descriptor = self
                .inventory
                .get(id)
                .context("bundle is outside current inventory")?;
            page_authority::verify_bundle(&config.raw.network, descriptor, &bundle)
                .map_err(anyhow::Error::msg)?;
            self.storage
                .as_mut()
                .context("cache")?
                .insert(&StoredPage {
                    descriptor: descriptor.clone(),
                    bundle,
                })?;
        }
        self.inventory_digest = Some(result.inventory_digest);
        self.authority_revision = result.authority_revision;
        self.valid_until = result.valid_until;
        self.pending = result.requests;
        self.ready = true;
        for ticket in &self.pending {
            if now()? >= self.valid_until || now()? >= ticket.expires {
                break;
            }
            let descriptor = self
                .inventory
                .get(&ticket.descriptor.page_id)
                .context("ticket publication missing")?;
            let storage = self.storage.as_mut().context("cache")?;
            let bundle = match storage.bundle(&config.raw.network, descriptor) {
                Ok(bundle) => bundle,
                Err(error) => {
                    storage.remove(&descriptor.page_id)?;
                    return Err(error);
                }
            };
            let Some(bundle) = bundle else {
                continue;
            };
            let reply = request(
                config,
                client,
                types::Command::ReplicaDeliver {
                    profile: config.profile_digest.clone(),
                    ticket_id: ticket.ticket_id.clone(),
                    bundle,
                },
                *epoch,
            )
            .await?;
            *epoch = reply.epoch;
        }
        self.ready = now()? < self.valid_until;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("HyperNetPageCache{}-{nonce}", std::process::id()));
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn page(identity: u8) -> StoredPage {
        let envelope = types::Envelope {
            network: hex::encode([0; 32]),
            public_key: hex::encode([1; 32]),
            payload: "x".repeat(200),
            signature: hex::encode([2; 64]),
        };
        StoredPage {
            descriptor: types::PageDescriptor {
                page_id: hex::encode([identity; 16]),
                publication_version: 1,
                revision: 1,
                author: hex::encode([1; 32]),
                reviewer: hex::encode([2; 32]),
                namespace: "Public".into(),
                audience: "Members".into(),
                profile: "HyperNetPage/1".into(),
                digest: hex::encode([3; 32]),
                submission_digest: hex::encode([4; 32]),
                approval_digest: hex::encode([5; 32]),
            },
            bundle: types::PageBundle {
                submission: envelope.clone(),
                approval: envelope,
            },
        }
    }

    #[test]
    fn quota_evicts_before_admission_and_prunes_changed_publications() {
        let directory = Directory::new();
        let block = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let mut storage = Storage::new(directory.0.clone(), block * 2).unwrap();
        let first = page(1);
        let second = page(2);
        let third = page(3);
        for page in [&first, &second, &third] {
            storage.insert(page).unwrap();
        }
        assert_eq!(storage.files.len(), 2);
        assert!(!storage.files.contains_key(&first.descriptor.page_id));
        assert_eq!(storage.bytes(), block * 2);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
        assert!(!directory.0.join("Incoming.json").exists());
        let mut replacement = second.descriptor.clone();
        replacement.publication_version += 1;
        storage
            .prune(&BTreeMap::from([
                (replacement.page_id.clone(), replacement),
                (third.descriptor.page_id.clone(), third.descriptor.clone()),
            ]))
            .unwrap();
        assert_eq!(storage.files.len(), 1);
        storage.prune(&BTreeMap::new()).unwrap();
        assert_eq!(storage.bytes(), 0);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn oversized_or_modified_cache_files_are_not_delivered() {
        let directory = Directory::new();
        let mut storage = Storage::new(directory.0.clone(), 65536).unwrap();
        let mut object = page(1);
        object.bundle.submission.payload = "x".repeat(MAXIMUM_BUNDLE);
        assert!(storage.insert(&object).is_err());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
        let object = page(1);
        storage.insert(&object).unwrap();
        let file = &storage.files[&object.descriptor.page_id];
        fs::write(&file.path, b"modified").unwrap();
        let result = storage.bundle(&hex::encode([0; 32]), &object.descriptor);
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("cache content changed")
        );
    }

    #[test]
    fn disappeared_files_can_be_refilled_and_do_not_block_pruning() {
        let directory = Directory::new();
        let mut storage = Storage::new(directory.0.clone(), 65536).unwrap();
        let first = page(1);
        let second = page(2);
        let third = page(3);
        storage.insert(&first).unwrap();
        storage.insert(&second).unwrap();
        let first_path = storage.files[&first.descriptor.page_id].path.clone();
        let second_path = storage.files[&second.descriptor.page_id].path.clone();
        let second_bytes = fs::read(&second_path).unwrap();
        fs::remove_file(&first_path).unwrap();
        assert!(
            storage
                .bundle(&hex::encode([0; 32]), &first.descriptor)
                .is_err()
        );
        storage.remove(&first.descriptor.page_id).unwrap();
        assert!(!storage.files.contains_key(&first.descriptor.page_id));
        storage.insert(&first).unwrap();
        assert!(first_path.is_file());
        storage.insert(&third).unwrap();
        let third_path = storage.files[&third.descriptor.page_id].path.clone();
        fs::remove_file(&first_path).unwrap();
        storage
            .prune(&BTreeMap::from([(
                second.descriptor.page_id.clone(),
                second.descriptor.clone(),
            )]))
            .unwrap();
        assert_eq!(storage.files.len(), 1);
        assert_eq!(
            storage.bytes(),
            storage.files[&second.descriptor.page_id].cost
        );
        assert!(!third_path.exists());
        assert_eq!(fs::read(&second_path).unwrap(), second_bytes);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn removal_keeps_accounting_when_the_filesystem_reports_another_error() {
        let directory = Directory::new();
        let mut storage = Storage::new(directory.0.clone(), 65536).unwrap();
        let object = page(1);
        storage.insert(&object).unwrap();
        let file = &storage.files[&object.descriptor.page_id];
        let cost = file.cost;
        fs::remove_file(&file.path).unwrap();
        fs::create_dir(&file.path).unwrap();
        assert!(storage.remove(&object.descriptor.page_id).is_err());
        assert!(storage.files.contains_key(&object.descriptor.page_id));
        assert_eq!(storage.bytes(), cost);
    }

    #[test]
    fn authority_loss_forces_inventory_refresh_without_reusing_requests() {
        let mut replica = Replica {
            storage: None,
            inventory: BTreeMap::from([("old".into(), page(1).descriptor)]),
            inventory_digest: Some("old".into()),
            pending: Vec::new(),
            authority_revision: 42,
            valid_until: 100,
            ready: true,
        };
        replica.invalidate();
        assert!(!replica.ready);
        assert!(replica.inventory_digest.is_none());
        assert!(replica.inventory.is_empty());
        assert!(replica.pending.is_empty());
        assert_eq!(replica.authority_revision, 42);
    }
}
