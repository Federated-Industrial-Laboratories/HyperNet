// SPDX-License-Identifier: MIT
// Certified route metadata and spent connection identifiers survive service restarts.
use crate::{
    authority_domains::{self as domains, State},
    authority_files as files,
    authority_proof::Digest,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
pub struct Disk {
    directory: File,
    state: State,
    records: Vec<Vec<u8>>,
    spent: BTreeMap<Digest, u64>,
    maximum_bytes: usize,
    persisted: Option<Vec<u8>>,
}
impl Disk {
    pub fn open(
        path: &Path,
        network: Digest,
        incarnation: Digest,
        maximum_bytes: usize,
    ) -> Result<Self> {
        ensure!(
            (65536..=domains::MAXIMUM_BYTES * 4).contains(&maximum_bytes),
            "route metadata admission exceeds its bound"
        );
        let directory = files::private_directory(path)?;
        let mut out = Self {
            directory,
            state: State::empty(network, incarnation),
            records: vec![],
            spent: BTreeMap::new(),
            maximum_bytes,
            persisted: None,
        };
        let file = path.join("RouteState.cbor");
        if file.try_exists()? {
            let bytes = files::read(&file, maximum_bytes, true)?;
            let value = wire::decode_state(&bytes)?;
            let f = value.array(6)?;
            ensure!(
                f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "RouteState",
                "route state schema differs"
            );
            out.state = State::parse_context(&f[3], network, incarnation)?;
            out.records = f[4]
                .list(domains::MAXIMUM_RECORDS)?
                .iter()
                .map(|v| Ok(v.bytes()?.to_vec()))
                .collect::<Result<_>>()?;
            crate::authority_governance::Governance::record_versions(
                network,
                incarnation,
                &out.records,
            )?;
            for v in f[5].list(32768)? {
                let row = v.array(2)?;
                ensure!(
                    out.spent.insert(row[0].fixed()?, row[1].uint()?).is_none(),
                    "spent route connection repeats"
                );
            }
            ensure!(out.encode()? == bytes, "route state is not canonical");
            out.persisted = Some(bytes);
        } else {
            out.save()?;
        }
        Ok(out)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = wire::encode_state(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RouteState".into()),
            self.state.value(),
            V::Array(self.records.iter().map(|r| V::Bytes(r.clone())).collect()),
            V::Array(
                self.spent
                    .iter()
                    .map(|(id, expiry)| V::Array(vec![V::Bytes(id.to_vec()), V::Uint(*expiry)]))
                    .collect(),
            ),
        ]))?;
        ensure!(
            bytes.len() <= self.maximum_bytes,
            "route metadata storage admission exhausted"
        );
        Ok(bytes)
    }
    fn save(&mut self) -> Result<()> {
        let bytes = self.encode()?;
        if self.persisted.as_ref() == Some(&bytes) {
            return Ok(());
        }
        // A failed replacement may have renamed the file without completing directory sync.
        self.persisted = None;
        files::atomic_at(&self.directory, OsStr::new("RouteState.cbor"), &bytes, true)?;
        self.persisted = Some(bytes);
        Ok(())
    }
    pub fn context(&self) -> (&State, &[Vec<u8>]) {
        (&self.state, &self.records)
    }
    pub fn publish(&mut self, state: State, records: Vec<Vec<u8>>) -> Result<()> {
        ensure!(
            state.network == self.state.network && state.incarnation == self.state.incarnation,
            "route state network changed"
        );
        self.state = state;
        self.records = records;
        self.save()
    }
    pub fn consume(&mut self, connection: Digest, now: u64, expires: u64) -> Result<()> {
        ensure!(
            connection != [0; 32] && now < expires,
            "route consumption lifetime is invalid"
        );
        ensure!(
            !self.spent.contains_key(&connection),
            "route connection was already consumed"
        );
        self.spent.retain(|_, expiry| *expiry > now);
        ensure!(
            self.spent.len() < 32768,
            "route consumption admission exhausted"
        );
        self.spent.insert(connection, expires);
        // A failed publication stops serving; the caller must not release any destination bytes.
        self.save().context("persist one-use route admission")
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteStateUnitTests.rs"]
mod tests;
