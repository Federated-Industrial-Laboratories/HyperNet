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
        };
        let file = path.join("RouteState.cbor");
        if file.try_exists()? {
            let value = wire::decode_state(&files::read(&file, maximum_bytes, true)?)?;
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
            ensure!(
                out.encode()? == files::read(&file, maximum_bytes, true)?,
                "route state is not canonical"
            );
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
    fn save(&self) -> Result<()> {
        files::atomic_at(
            &self.directory,
            OsStr::new("RouteState.cbor"),
            &self.encode()?,
            true,
        )
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
mod tests {
    use super::*;
    #[test]
    fn private_route_spent_connection_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "HyperNetRouteState{}",
            hex::encode(crate::route_protocol::random().unwrap())
        ));
        files::create_directory(&path).unwrap();
        let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
        disk.consume([3; 32], 100, 120000).unwrap();
        drop(disk);
        let mut disk = Disk::open(&path, [1; 32], [2; 32], 65536).unwrap();
        // Restart cannot resurrect a stream after its short proof has expired.
        assert!(disk.consume([3; 32], 6000, 120000).is_err());
        disk.consume([4; 32], 6000, 120000).unwrap();
        drop(disk);
        std::fs::remove_dir_all(path).unwrap();
    }
}
