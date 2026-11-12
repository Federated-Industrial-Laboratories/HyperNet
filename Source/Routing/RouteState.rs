// SPDX-License-Identifier: MIT
// Certified route metadata and spent connection identifiers survive service restarts.
use crate::{
    authority_domains::{self as domains, State},
    authority_files as files,
    authority_floor::Store,
    authority_proof::{Digest, Intent},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};
#[path = "RouteCacheRepair.rs"]
mod repair;
#[path = "RouteCacheTransaction.rs"]
mod transaction;
const FILE: &str = "RouteState.cbor";
const MAX_SPENT: usize = 32768;
const CHUNK: usize = 4096;

struct Snapshot {
    state: State,
    records: Vec<Vec<u8>>,
    spent: BTreeMap<Digest, u64>,
}
impl Snapshot {
    fn decode(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        let value = wire::decode_state(bytes)?;
        let f = value.array(6)?;
        let schema = f[1].uint()?;
        ensure!(
            f[0].uint()? == 200 && matches!(schema, 1 | 2) && f[2].text()? == "RouteState",
            "route state schema differs"
        );
        let state = State::parse_context(&f[3], network, incarnation)?;
        let records: Vec<Vec<u8>> = f[4]
            .list(domains::MAXIMUM_RECORDS)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<_>>()?;
        crate::authority_governance::Governance::record_versions(network, incarnation, &records)?;
        let chunks = if schema == 1 {
            vec![f[5].list(CHUNK)?]
        } else {
            f[5].list(MAX_SPENT / CHUNK)?
                .iter()
                .map(|chunk| chunk.list(CHUNK))
                .collect::<Result<Vec<_>>>()?
        };
        let mut spent = BTreeMap::new();
        for row in chunks.into_iter().flatten() {
            let row = row.array(2)?;
            ensure!(
                spent.insert(row[0].fixed()?, row[1].uint()?).is_none(),
                "spent route connection repeats"
            );
        }
        let out = Self {
            state,
            records,
            spent,
        };
        ensure!(out.encode(schema)? == bytes, "route state is not canonical");
        Ok(out)
    }
    fn encode(&self, schema: u64) -> Result<Vec<u8>> {
        ensure!(
            self.spent.len() <= MAX_SPENT,
            "route consumption admission exhausted"
        );
        let rows = self
            .spent
            .iter()
            .map(|(id, expiry)| V::Array(vec![V::Bytes(id.to_vec()), V::Uint(*expiry)]))
            .collect::<Vec<_>>();
        let spent = if schema == 1 {
            V::Array(rows)
        } else {
            V::Array(
                rows.chunks(CHUNK)
                    .map(|chunk| V::Array(chunk.to_vec()))
                    .collect(),
            )
        };
        wire::encode_state(&V::Array(vec![
            V::Uint(200),
            V::Uint(schema),
            V::Text("RouteState".into()),
            self.state.value(),
            V::Array(self.records.iter().map(|r| V::Bytes(r.clone())).collect()),
            spent,
        ]))
    }
    fn authenticate(&self, store: &Store) -> Result<()> {
        let scope = store.descriptor().scope();
        ensure!(
            self.state.network == scope.network && self.state.incarnation == scope.incarnation,
            "Route cache scope differs"
        );
        let mut refs = crate::authority_governance::Governance::record_versions(
            scope.network,
            scope.incarnation,
            &self.records,
        )?;
        refs.extend(self.state.records.values().map(|r| r.reference.clone()));
        let pending = store
            .resume_ordinary()?
            .map(|r| Intent::from_signed(r.signed()))
            .transpose()?;
        let historical = store.historical_cache_references()?;
        for r in refs {
            ensure!(
                store.generations().contains(&r)
                    || historical.contains(&r)
                    || pending
                        .as_ref()
                        .is_some_and(|p| p.action == "AuthorityDomain" && p.expected.contains(&r)),
                "Route cache lacks retained quorum authentication"
            );
        }
        Ok(())
    }
}

pub struct Disk {
    directory: File,
    snapshot: Snapshot,
    maximum_bytes: usize,
    persisted: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
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
            snapshot: Snapshot {
                state: State::empty(network, incarnation),
                records: vec![],
                spent: BTreeMap::new(),
            },
            maximum_bytes,
            persisted: None,
            pending: None,
        };
        if path.join(FILE).try_exists()? {
            let bytes = files::read_at(&out.directory, OsStr::new(FILE), maximum_bytes, true)?;
            out.snapshot = Snapshot::decode(&bytes, network, incarnation)?;
            out.persisted = Some(bytes);
        } else {
            ensure!(
                !path.join(transaction::FILE).try_exists()?,
                "route state is missing during cache recovery"
            );
            out.save()?;
        }
        if path.join(transaction::FILE).try_exists()? {
            out.pending = Some(files::read_at(
                &out.directory,
                OsStr::new(transaction::FILE),
                maximum_bytes + 256,
                true,
            )?);
        }
        Ok(out)
    }
    fn bounded(&self, snapshot: &Snapshot) -> Result<Vec<u8>> {
        let bytes = snapshot.encode(2)?;
        ensure!(
            bytes.len() <= self.maximum_bytes,
            "route metadata storage admission exhausted"
        );
        Ok(bytes)
    }
    fn save(&mut self) -> Result<()> {
        let bytes = self.bounded(&self.snapshot)?;
        self.replace(bytes)
    }
    fn replace(&mut self, bytes: Vec<u8>) -> Result<()> {
        if self.persisted.as_ref() == Some(&bytes) {
            return Ok(());
        }
        // A failed replacement may have renamed the file without completing directory sync.
        self.persisted = None;
        files::atomic_at(&self.directory, OsStr::new(FILE), &bytes, true)?;
        self.persisted = Some(bytes);
        Ok(())
    }
    pub fn context(&self) -> (&State, &[Vec<u8>]) {
        (&self.snapshot.state, &self.snapshot.records)
    }
    pub fn check(&self, store: &Store) -> Result<()> {
        self.snapshot.authenticate(store)
    }
    #[cfg(test)]
    fn publish(&mut self, state: State, records: Vec<Vec<u8>>) -> Result<()> {
        self.snapshot.state = state;
        self.snapshot.records = records;
        self.save()
    }
    fn connection_admission_bytes(&self) -> usize {
        self.maximum_bytes - (self.maximum_bytes / 4).min(wire::MAXIMUM) - 256
    }
    pub fn consume(&mut self, connection: Digest, now: u64, expires: u64) -> Result<()> {
        ensure!(
            self.pending.is_none(),
            "route cache publication requires recovery"
        );
        ensure!(
            connection != [0; 32] && now < expires,
            "route consumption lifetime is invalid"
        );
        ensure!(
            !self.snapshot.spent.contains_key(&connection),
            "route connection was already consumed"
        );
        let mut spent = self.snapshot.spent.clone();
        spent.retain(|_, expiry| *expiry > now);
        ensure!(
            spent.len() < MAX_SPENT,
            "route consumption admission exhausted"
        );
        spent.insert(connection, expires);
        let prior = std::mem::replace(&mut self.snapshot.spent, spent);
        // Leave room for a bounded metadata update and its journal after reader admission fills.
        let admission = self.bounded(&self.snapshot).and_then(|bytes| {
            ensure!(
                bytes.len() <= self.connection_admission_bytes(),
                "route connection storage admission exhausted; metadata reserve retained"
            );
            Ok(bytes)
        });
        let bytes = match admission {
            Ok(bytes) => bytes,
            Err(error) => {
                self.snapshot.spent = prior;
                return Err(error);
            }
        };
        // A failed publication stops serving; the caller must not release any destination bytes.
        self.replace(bytes)
            .context("persist one-use route admission")
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteStateUnitTests.rs"]
mod tests;
