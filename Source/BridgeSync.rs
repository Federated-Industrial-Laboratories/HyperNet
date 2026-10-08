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
                let (descriptor, expires) = self.import(value).await?;
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
