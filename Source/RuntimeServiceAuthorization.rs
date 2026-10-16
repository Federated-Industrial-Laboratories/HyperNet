// SPDX-License-Identifier: MIT
// Service activation retains exact operator consent, fixed artifact hashes and a non-extendable local lifetime.
use crate::{
    authority_clock_handoff::Source,
    authority_proof::{Digest, Key},
    runtime_authorization::public_read,
    runtime_manifest::Manifest,
    trust_bootstrap::{self, Verified},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub struct Guard {
    pub manifest: Manifest,
    pub bootstrap: Verified,
    pub role: u64,
    pub generation: u64,
    directory: PathBuf,
    consent: Digest,
    local_consent: Digest,
    clock: Source,
    last_wall: Cell<u64>,
    boot_deadline: u64,
    artifacts: BTreeMap<String, Digest>,
}
fn artifact_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_uppercase()
        && name.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'.')
        && !name.contains("..")
}
pub fn local_consent(
    manifest: &Manifest,
    role: u64,
    generation: u64,
    artifacts: &BTreeMap<String, Digest>,
) -> Result<Vec<u8>> {
    manifest.validate()?;
    ensure!(
        (1..=8).contains(&role)
            && generation == manifest.generation
            && manifest.services().contains_key(&role)
            && (4..=32).contains(&artifacts.len())
            && artifacts.keys().all(|n| artifact_name(n))
            && artifacts.values().all(|d| *d != [0; 32])
            && [
                "Bootstrap.cbor",
                "Manifest.cbor",
                "Service.key",
                "ServiceConfig.json"
            ]
            .iter()
            .all(|n| artifacts.contains_key(*n)),
        "local service consent requires its fixed identity, configuration and bootstrap artifacts"
    );
    wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("RuntimeLocalConsent".into()),
        V::Bytes(wire::digest(&manifest.encode()?).to_vec()),
        V::Uint(role),
        V::Uint(generation),
        V::Array(
            artifacts
                .iter()
                .map(|(n, d)| V::Array(vec![V::Text(n.clone()), V::Bytes(d.to_vec())]))
                .collect(),
        ),
    ]))
}
fn verify_artifacts(config: &Path, artifacts: &BTreeMap<String, Digest>) -> Result<()> {
    let present = std::fs::read_dir(config)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid configuration filename"))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        present == artifacts.keys().cloned().collect(),
        "service configuration has missing or unconsented artifacts"
    );
    for (name, expected) in artifacts {
        let bytes = crate::authority_files::read(&config.join(name), wire::MAXIMUM, true)?;
        ensure!(
            wire::digest(&bytes) == *expected,
            "service configuration artifact differs from local consent"
        );
    }
    Ok(())
}
fn verify_local(
    directory: &Path,
    operator: Key,
    generation: u64,
    local_consent: Digest,
    consent: Digest,
    boot_deadline: u64,
    boot_ms: u64,
) -> Result<()> {
    ensure!(
        boot_ms < boot_deadline,
        "original service consent lifetime expired"
    );
    let withdrawal: u64 =
        serde_json::from_slice(&public_read(&directory.join("Withdrawal.json"), 64)?)?;
    ensure!(withdrawal == 0, "local service consent is withdrawn");
    let current_generation: u64 =
        serde_json::from_slice(&public_read(&directory.join("Generation.json"), 64)?)?;
    ensure!(
        current_generation == generation,
        "local service generation changed"
    );
    let (local, sigs) = wire::envelope(
        &public_read(&directory.join("LocalConsent.cbor"), wire::MAXIMUM)?,
        1,
    )?;
    ensure!(
        sigs.len() == 1 && sigs[0].0 == operator && wire::digest(&local) == local_consent,
        "local workload consent changed"
    );
    let (current_consent, sigs) = wire::envelope(
        &public_read(&directory.join("HostConsent.cbor"), wire::MAXIMUM)?,
        1,
    )?;
    ensure!(
        sigs.len() == 1 && sigs[0].0 == operator && wire::digest(&current_consent) == consent,
        "host consent changed"
    );
    Ok(())
}
impl Guard {
    pub fn load(directory: &Path, config: &Path, role: u64) -> Result<Self> {
        ensure!(
            directory == Path::new("/Authorization") && config == Path::new("/Config"),
            "service authorization requires its fixed read-only mounts"
        );
        let manifest = Manifest::parse(&public_read(
            &directory.join("Manifest.cbor"),
            crate::runtime_manifest::MAXIMUM,
        )?)?;
        let expected = manifest.unsigned_consent(0)?;
        let (consent, signatures) = wire::envelope(
            &public_read(&directory.join("HostConsent.cbor"), wire::MAXIMUM)?,
            1,
        )?;
        ensure!(
            consent == expected && signatures.len() == 1 && signatures[0].0 == manifest.operator,
            "host consent differs from the exact signed service manifest"
        );
        let (local, signatures) = wire::envelope(
            &public_read(&directory.join("LocalConsent.cbor"), wire::MAXIMUM)?,
            1,
        )?;
        ensure!(
            signatures.len() == 1 && signatures[0].0 == manifest.operator,
            "local workload consent has another operator"
        );
        let value = wire::decode(&local)?;
        let f = value.array(7)?;
        let generation = f[5].uint()?;
        let mut artifacts = BTreeMap::new();
        let mut previous = None;
        for row in f[6].list(32)? {
            let row = row.array(2)?;
            let name = row[0].text()?.to_string();
            ensure!(
                previous.as_ref().is_none_or(|p| p < &name),
                "artifact names are repeated or unsorted"
            );
            previous = Some(name.clone());
            artifacts.insert(name, row[1].fixed()?);
        }
        ensure!(
            local == local_consent(&manifest, role, generation, &artifacts)?,
            "local consent differs from the exact role and artifacts"
        );
        verify_artifacts(config, &artifacts)?;
        let bootstrap_bytes =
            crate::authority_files::read(&config.join("Bootstrap.cbor"), wire::MAXIMUM, true)?;
        let bootstrap = trust_bootstrap::inspect(&bootstrap_bytes, true)?;
        ensure!(
            bootstrap.file_digest() == manifest.bootstrap_digest
                && bootstrap.descriptor().scope().network == manifest.network
                && bootstrap.descriptor().scope().incarnation == manifest.incarnation,
            "service bootstrap differs from local consent"
        );
        let clock = Source::Signed {
            path: Path::new("/Clock").join(&manifest.clock.witness_file_name),
            public_key: hex::encode(manifest.clock.monitor_key),
            kernel_boot: manifest.clock.kernel_boot.clone(),
        };
        let observation = clock.health()?.observe()?;
        ensure!(
            observation
                .wall_ms
                .checked_sub(crate::authority_challenge::DELTA_MS)
                .is_some_and(|t| t >= manifest.validity.0)
                && observation
                    .wall_ms
                    .checked_add(crate::authority_challenge::DELTA_MS)
                    .is_some_and(|t| t < manifest.validity.1),
            "service consent is outside its validity interval"
        );
        let boot_deadline = observation
            .boot_ms
            .checked_add(
                manifest.validity.1 - observation.wall_ms - crate::authority_challenge::DELTA_MS,
            )
            .context("service lifetime overflow")?;
        let out = Self {
            manifest,
            bootstrap,
            role,
            generation,
            directory: directory.into(),
            consent: wire::digest(&consent),
            local_consent: wire::digest(&local),
            clock,
            last_wall: Cell::new(observation.wall_ms),
            boot_deadline,
            artifacts,
        };
        out.check()?;
        Ok(out)
    }
    pub fn key(&self) -> Key {
        self.manifest.services()[&self.role]
    }
    pub fn consent(&self) -> Digest {
        self.consent
    }
    pub fn health(&self) -> Result<crate::authority_challenge::ClockHealth> {
        self.clock.health()
    }
    pub(crate) fn check_configuration(&self) -> Result<()> {
        verify_artifacts(Path::new("/Config"), &self.artifacts)
    }
    pub(crate) fn check_local(&self) -> Result<()> {
        verify_local(
            &self.directory,
            self.manifest.operator,
            self.generation,
            self.local_consent,
            self.consent,
            self.boot_deadline,
            crate::authority_challenge::boot_time_ms()?,
        )
    }
    pub fn check(&self) -> Result<()> {
        self.check_local()?;
        let observation = self.health()?.observe()?;
        ensure!(
            observation.wall_ms >= self.last_wall.get()
                && observation
                    .wall_ms
                    .checked_add(crate::authority_challenge::DELTA_MS)
                    .is_some_and(|t| t < self.manifest.validity.1)
                && observation.boot_ms < self.boot_deadline,
            "service consent expired or clock regressed"
        );
        self.last_wall.set(observation.wall_ms);
        Ok(())
    }
}

#[cfg(test)]
#[path = "RuntimeServiceAuthorizationTests.rs"]
mod tests;
