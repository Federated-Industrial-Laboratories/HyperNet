// SPDX-License-Identifier: MIT
//! Bounded outward-only federation refresh with independently checked evidence.
use super::{BridgeConfig, Connection, fixed_hex, now};
use crate::{confinement, federation_authority, page_authority, types};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, sync::Arc, time::Duration};
use tokio::task::JoinSet;

const MAXIMUM_OBJECTS: usize = 32;
const CONCURRENT_FETCHES: usize = 4;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Permit {
    admission: types::SignedEvidence,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inventory {
    entries: Vec<types::PageDescriptor>,
    authority_revision: u64,
    valid_until: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Export {
    descriptor: types::PageDescriptor,
    author_share: types::Envelope,
    bundle: Option<types::PageBundle>,
    export: types::SignedEvidence,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Imported {
    page_id: String,
    version: u64,
    state: String,
}

struct Fetched {
    admission: types::SignedEvidence,
    value: Export,
    evidence: types::FederationExportEvidence,
}

struct Transfer {
    source: Connection,
    destination: Connection,
    treaty: types::FederationTreaty,
    profile: String,
    media: Vec<super::media::Route>,
}

impl Transfer {
    async fn permit(&self) -> Result<(types::SignedEvidence, types::FederationAdmission)> {
        let reply = self
            .destination
            .request(types::Command::FederationPermit {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
            })
            .await?;
        let value: Permit = serde_json::from_value(reply.result)?;
        let permit = federation_authority::verify_admission(&self.treaty, &value.admission, now()?)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            permit.destination_profile == self.profile,
            "destination consent changed"
        );
        Ok((value.admission, permit))
    }

    async fn inventory(&self) -> Result<Inventory> {
        let (admission, permit) = self.permit().await?;
        let reply = self
            .source
            .request(types::Command::FederationExport {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
                admission,
                page_id: None,
                include_bundle: false,
            })
            .await?;
        let inventory: Inventory = serde_json::from_value(reply.result)?;
        ensure!(
            inventory.entries.len() <= MAXIMUM_OBJECTS
                && inventory.authority_revision > 0
                && inventory.valid_until > now()?
                && inventory.valid_until <= permit.valid_until,
            "invalid or expired federation inventory"
        );
        let mut identities = std::collections::BTreeSet::new();
        for descriptor in &inventory.entries {
            fixed_hex::<16>(&descriptor.page_id)?;
            ensure!(
                identities.insert(&descriptor.page_id)
                    && descriptor.namespace == self.treaty.source_namespace
                    && descriptor.profile == self.treaty.profile
                    && descriptor.audience == "Members",
                "federation inventory escaped its scope"
            );
        }
        Ok(inventory)
    }

    async fn fetch(
        &self,
        descriptor: types::PageDescriptor,
        include_bundle: bool,
    ) -> Result<Fetched> {
        // A queued page gets its own permit so earlier transfers cannot consume its lease.
        let (admission, _) = self.permit().await?;
        let reply = self
            .source
            .request(types::Command::FederationExport {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
                admission: admission.clone(),
                page_id: Some(descriptor.page_id.clone()),
                include_bundle,
            })
            .await?;
        let value: Export = serde_json::from_value(reply.result)?;
        let evidence =
            federation_authority::verify_export(&self.treaty, &admission, &value.export, now()?)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            value.descriptor == descriptor
                && evidence.descriptor == descriptor
                && evidence.source_profile == self.profile,
            "federation publication changed during transfer"
        );
        let share =
            federation_authority::verify_share(&self.treaty, &descriptor, &value.author_share)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            share == evidence.author_share_digest,
            "source author permission does not match export"
        );
        ensure!(
            !include_bundle || value.bundle.is_some(),
            "source omitted the approved bundle"
        );
        if let Some(bundle) = &value.bundle {
            page_authority::verify_bundle(&self.treaty.source_network, &descriptor, bundle)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(Fetched {
            admission,
            value,
            evidence,
        })
    }

    async fn import(&self, fetched: Fetched) -> Result<(types::PageDescriptor, u64)> {
        let now = now()?;
        ensure!(
            now < fetched.evidence.valid_until,
            "export expired before destination import"
        );
        let descriptor = fetched.value.descriptor;
        let reply = self
            .destination
            .request(types::Command::FederationImport {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
                admission: fetched.admission,
                export: fetched.value.export,
                bundle: fetched.value.bundle,
                author_share: Some(fetched.value.author_share),
            })
            .await?;
        let imported: Imported = serde_json::from_value(reply.result)?;
        ensure!(
            imported.page_id == descriptor.page_id
                && imported.version > 0
                && ["Pending", "Approved", "Suppressed"].contains(&imported.state.as_str()),
            "invalid destination import acknowledgement"
        );
        Ok((descriptor, fetched.evidence.valid_until))
    }

    fn media_operation(
        &self,
        descriptor: &types::PageDescriptor,
        asset: &crate::markup::media::Asset,
        route: &super::media::Route,
        action: &str,
        offset: u64,
    ) -> Result<crate::media_types::Operation> {
        let mut nonce = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(crate::media_types::Operation {
            version: 1,
            agreement_id: Some(self.treaty.agreement_id.clone()),
            admission: None,
            network: route.endpoint.network.clone(),
            operation_id: hex::encode(nonce),
            issued_at: now()?,
            host_key: route.endpoint.host_key.clone(),
            page_id: descriptor.page_id.clone(),
            revision: descriptor.revision,
            asset_id: asset.id.clone(),
            source_digest: descriptor.digest.clone(),
            action: action.into(),
            offset,
            chunk_bytes: if matches!(action, "Put" | "Fetch") {
                crate::media_types::CHUNK.min(asset.bytes.saturating_sub(offset))
            } else {
                0
            },
            chunk_digest: None,
        })
    }
    async fn renew_media_reference(&self, descriptor: &types::PageDescriptor) -> Result<()> {
        let renewed = self.fetch(descriptor.clone(), false).await?;
        self.import(renewed).await?;
        Ok(())
    }
    async fn copy_media(
        &self,
        descriptor: &types::PageDescriptor,
        assets: &[crate::markup::media::Asset],
    ) -> Result<()> {
        use crate::{mail_authority, media_types as media};
        ensure!(
            assets.iter().map(|a| a.bytes).sum::<u64>() <= self.treaty.media_max_bytes,
            "media treaty quota exceeded"
        );
        for asset in assets {
            let source = self
                .media
                .iter()
                .find(|r| {
                    r.endpoint.network == self.treaty.source_network
                        && asset.hosts.contains(&r.endpoint.host_key)
                })
                .ok_or_else(|| anyhow::anyhow!("no consented source media route"))?;
            let mut bytes = Vec::with_capacity(asset.bytes as usize);
            while (bytes.len() as u64) < asset.bytes {
                let mut op =
                    self.media_operation(descriptor, asset, source, "Fetch", bytes.len() as u64)?;
                op.admission = Some(self.permit().await?.0);
                let (receipt, chunk) = source.execute(&self.source, &op, None).await?;
                let value: media::StoreReceipt =
                    mail_authority::verify(media::RECEIPT, &receipt, &op.network)
                        .map_err(anyhow::Error::msg)?;
                ensure!(
                    value.status == "Complete"
                        && value.digest == asset.digest
                        && value.bytes == asset.bytes,
                    "source media receipt differs"
                );
                bytes.extend(chunk.ok_or_else(|| anyhow::anyhow!("source omitted media bytes"))?);
            }
            crate::markup::media::validate_asset_bytes(asset, &bytes)
                .map_err(anyhow::Error::msg)?;
            for destination in self.media.iter().filter(|r| {
                r.endpoint.network == self.treaty.destination_network
                    && self
                        .treaty
                        .media_destination_hosts
                        .contains(&r.endpoint.host_key)
            }) {
                self.renew_media_reference(descriptor).await?;
                let op = self.media_operation(descriptor, asset, destination, "Status", 0)?;
                let (receipt, _) = destination.execute(&self.destination, &op, None).await?;
                let status: media::StoreReceipt =
                    mail_authority::verify(media::RECEIPT, &receipt, &op.network)
                        .map_err(anyhow::Error::msg)?;
                ensure!(
                    status.digest == asset.digest
                        && status.bytes == asset.bytes
                        && status.stored_bytes <= asset.bytes,
                    "destination media receipt differs"
                );
                let mut offset = status.stored_bytes;
                while offset < asset.bytes {
                    self.renew_media_reference(descriptor).await?;
                    let mut op =
                        self.media_operation(descriptor, asset, destination, "Put", offset)?;
                    let chunk = &bytes[offset as usize..(offset + op.chunk_bytes) as usize];
                    op.chunk_digest = Some(mail_authority::hash(chunk));
                    destination
                        .execute(&self.destination, &op, Some(chunk))
                        .await?;
                    offset += op.chunk_bytes;
                }
                self.renew_media_reference(descriptor).await?;
                let op = self.media_operation(descriptor, asset, destination, "Seal", 0)?;
                let (receipt, _) = destination.execute(&self.destination, &op, None).await?;
                self.destination
                    .request(types::Command::PageMediaReceipt {
                        agreement_id: Some(self.treaty.agreement_id.clone()),
                        page_id: descriptor.page_id.clone(),
                        revision: descriptor.revision,
                        asset_id: asset.id.clone(),
                        receipt,
                    })
                    .await?;
            }
        }
        Ok(())
    }

    async fn synchronise(
        &self,
        known: &mut BTreeMap<String, types::PageDescriptor>,
        shared: &Arc<Self>,
    ) -> Result<(usize, u64)> {
        let inventory = self.inventory().await?;
        known.retain(|id, descriptor| {
            inventory
                .entries
                .iter()
                .any(|entry| &entry.page_id == id && entry == descriptor)
        });
        let mut until = if inventory.entries.is_empty() {
            inventory.valid_until
        } else {
            u64::MAX
        };
        let mut count = 0;
        for batch in inventory.entries.chunks(CONCURRENT_FETCHES) {
            let mut tasks = JoinSet::new();
            for descriptor in batch {
                let transfer = Arc::clone(shared);
                let descriptor = descriptor.clone();
                let include_bundle = known.get(&descriptor.page_id) != Some(&descriptor);
                tasks.spawn(async move { transfer.fetch(descriptor, include_bundle).await });
            }
            let mut fetched = Vec::with_capacity(batch.len());
            while let Some(result) = tasks.join_next().await {
                fetched.push(result??);
            }
            // The destination rejects source revision rollback across the whole agreement.
            fetched.sort_by_key(|item| item.evidence.authority_revision);
            for value in fetched {
                let assets = value
                    .value
                    .bundle
                    .as_ref()
                    .map(|b| {
                        page_authority::verify_bundle(
                            &self.treaty.source_network,
                            &value.value.descriptor,
                            b,
                        )
                        .and_then(|body| crate::markup::parse(&body).map(|d| d.assets))
                    })
                    .transpose()
                    .map_err(anyhow::Error::msg)?
                    .unwrap_or_default();
                let (descriptor, mut expires) = self.import(value).await?;
                if !assets.is_empty() {
                    self.copy_media(&descriptor, &assets).await?;
                    let renewed = self.fetch(descriptor.clone(), false).await?;
                    expires = self.import(renewed).await?.1;
                }
                until = until.min(expires);
                known.insert(descriptor.page_id.clone(), descriptor);
                count += 1;
            }
        }
        ensure!(
            until > now()?,
            "federation refresh exceeded its freshness bound"
        );
        Ok((count, until))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status<'a> {
    active: bool,
    code: &'a str,
    agreement_id: &'a str,
    profile: &'a str,
    objects: usize,
    lease_expires: u64,
    source_epoch: u64,
    destination_epoch: u64,
    confinement: &'a confinement::Profile,
}

fn status(directory: &Path, value: &Status<'_>) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    fs::write(directory.join("Status.new"), &bytes)?;
    fs::rename(directory.join("Status.new"), directory.join("Status.json"))?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

pub(super) async fn run(config: BridgeConfig, confinement: confinement::Profile) -> Result<()> {
    let transfer = Arc::new(Transfer {
        source: Connection::new(config.source)?,
        destination: Connection::new(config.destination)?,
        treaty: config.treaty,
        profile: config.profile,
        media: config.media,
    });
    let mut known = BTreeMap::new();
    let mut previous_time = now()?;
    loop {
        let current = now()?;
        ensure!(current >= previous_time, "clock rollback stops federation");
        previous_time = current;
        let result = if current < config.consent.expires {
            transfer.synchronise(&mut known, &transfer).await.ok()
        } else {
            None
        };
        let completed = now()?;
        ensure!(
            completed >= previous_time,
            "clock rollback stops federation"
        );
        previous_time = completed;
        let (objects, expires) = result
            .filter(|(_, expires)| *expires > completed && *expires <= config.consent.expires)
            .unwrap_or_default();
        let active = expires > completed;
        if !active {
            known.clear();
        }
        status(
            &config.state_directory,
            &Status {
                active,
                code: if active {
                    "Active"
                } else {
                    "AuthorityUnavailableOrDenied"
                },
                agreement_id: &transfer.treaty.agreement_id,
                profile: &transfer.profile,
                objects,
                lease_expires: expires,
                source_epoch: transfer
                    .source
                    .epoch
                    .load(std::sync::atomic::Ordering::Acquire),
                destination_epoch: transfer
                    .destination
                    .epoch
                    .load(std::sync::atomic::Ordering::Acquire),
                confinement: &confinement,
            },
        )?;
        if completed >= config.consent.expires {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
