// SPDX-License-Identifier: MIT
// A staged cache survives floor advancement without granting live forwarding permission.
use super::*;
pub(super) const FILE: &str = "RouteCachePending.cbor";

impl Disk {
    pub fn stage(&mut self, state: State, records: Vec<Vec<u8>>, store: &Store) -> Result<()> {
        ensure!(
            self.pending.is_none(),
            "route cache transaction already exists"
        );
        ensure!(
            state.network == self.snapshot.state.network
                && state.incarnation == self.snapshot.state.incarnation,
            "route state network changed"
        );
        let floor = store.cache_checkpoint()?;
        let wall = store.cache_wall_floor()?;
        let prior = self
            .persisted
            .as_ref()
            .context("route cache durability is uncertain")?;
        let candidate = Snapshot {
            state,
            records,
            spent: self
                .snapshot
                .spent
                .iter()
                .filter(|(_, expiry)| **expiry > wall)
                .map(|(id, expiry)| (*id, *expiry))
                .collect(),
        };
        // Encode and reserve metadata before the authority floor can advance.
        let bytes = self.bounded(&candidate)?;
        // Already durable identical bytes need no cross-file publication transaction.
        if prior == &bytes {
            return Ok(());
        }
        let pending = wire::encode_state(&V::Array(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RouteCacheTransaction".into()),
            V::Bytes(wire::digest(prior).to_vec()),
            V::Bytes(floor.to_vec()),
            V::Uint(wall),
            V::Bytes(bytes),
        ]))?;
        ensure!(
            pending.len() <= self.maximum_bytes,
            "route cache transaction storage admission exhausted"
        );
        // Keep the candidate on an uncertain fsync outcome and refuse another operation.
        self.pending = Some(pending.clone());
        files::atomic_at(&self.directory, OsStr::new(FILE), &pending, false)
            .context("persist certified route cache candidate")
    }
    pub fn recover(&mut self, store: &Store) -> Result<()> {
        let Some(pending) = &self.pending else {
            return Ok(());
        };
        let decoded = wire::decode_state(pending)?;
        let f = decoded.array(7)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "RouteCacheTransaction",
            "route cache transaction schema differs"
        );
        let prior: Digest = f[3].fixed()?;
        let floor: Digest = f[4].fixed()?;
        let wall = f[5].uint()?;
        let bytes = f[6].bytes()?.to_vec();
        ensure!(
            bytes.len() <= self.maximum_bytes,
            "route cache candidate exceeds admission"
        );
        let candidate = Snapshot::decode(
            &bytes,
            self.snapshot.state.network,
            self.snapshot.state.incarnation,
        )?;
        let current = files::read_at(
            &self.directory,
            OsStr::new(super::FILE),
            self.maximum_bytes,
            true,
        )?;
        let same_prior = wire::digest(&current) == prior;
        ensure!(
            same_prior || current == bytes,
            "route cache differs from both transaction states"
        );
        ensure!(
            wall <= store.cache_wall_floor()?,
            "cache pruning time exceeds durable authority floor"
        );
        if store.cache_checkpoint()? == floor {
            ensure!(
                same_prior,
                "route cache advanced before its authority floor"
            );
            self.snapshot.authenticate(store)?;
        } else {
            // Only exact authenticated record bytes may complete a staged publication.
            candidate.authenticate(store)?;
            if same_prior {
                let expected = self
                    .snapshot
                    .spent
                    .iter()
                    .filter(|(_, expiry)| **expiry > wall)
                    .map(|(id, expiry)| (*id, *expiry))
                    .collect::<BTreeMap<_, _>>();
                ensure!(
                    candidate.spent == expected,
                    "route cache candidate changes unexpired replay protection"
                );
            }
            self.replace(bytes)?;
            self.snapshot = candidate;
        }
        files::remove_private_at(&self.directory, OsStr::new(FILE))?;
        self.pending = None;
        Ok(())
    }
}
