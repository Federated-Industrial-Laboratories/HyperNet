// SPDX-License-Identifier: MIT
// Stopped repair replaces only stale records with exact bytes from a retained certified result.
use super::*;
use crate::authority_proof::VersionRef;
use serde_json::{Value, json};
const BACKUP: &str = "RouteState.before-repair.cbor";

impl Snapshot {
    fn stale(&self, floor: &[VersionRef]) -> Result<usize> {
        let mut refs = crate::authority_governance::Governance::record_versions(
            self.state.network,
            self.state.incarnation,
            &self.records,
        )?;
        refs.extend(self.state.records.values().map(|r| r.reference.clone()));
        Ok(refs
            .iter()
            .filter(|r| floor.iter().any(|f| f.index() == r.index() && f != *r))
            .count())
    }
    pub(super) fn repaired(
        &self,
        result: &crate::authority_proof::OperationResult,
        floor: &[VersionRef],
        wall: u64,
    ) -> Result<Self> {
        ensure!(
            result.action == "AuthorityDomain"
                && result.disposition == crate::authority_proof::Disposition::Permit,
            "cache repair requires the retained domain Permit"
        );
        let value = wire::decode(&result.value)?;
        let f = value.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
            "cache repair result schema differs"
        );
        let refs = f[3]
            .list(64)?
            .iter()
            .map(domains::version)
            .collect::<Result<Vec<_>>>()?;
        crate::authority_proof::validate_versions(&refs, 64)?;
        let body = f[4].array(4)?;
        let returned = body[1]
            .list(domains::MAXIMUM_RECORDS)?
            .iter()
            .map(|r| domains::Record::parse(r.bytes()?, self.state.network, self.state.incarnation))
            .collect::<Result<Vec<_>>>()?;
        let records = body[2]
            .list(64)?
            .iter()
            .map(|r| Ok(r.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let governance = crate::authority_governance::Governance::record_versions(
            self.state.network,
            self.state.incarnation,
            &records,
        )?;
        let mut exact = governance.clone();
        exact.extend(returned.iter().map(|r| r.reference.clone()));
        exact.sort_by_key(VersionRef::index);
        ensure!(exact == refs, "cache repair result closure differs");
        let mut state = self.state.clone();
        for record in state.records.values_mut() {
            if let Some(current) = floor
                .iter()
                .find(|r| r.index() == record.reference.index() && *r != &record.reference)
            {
                ensure!(
                    current.generation > record.reference.generation,
                    "cache repair cannot lower or conflict with a record"
                );
                *record = returned
                    .iter()
                    .find(|r| &r.reference == current)
                    .context("retained result cannot repair the stale domain record")?
                    .clone();
            }
        }
        let old = crate::authority_governance::Governance::record_versions(
            self.state.network,
            self.state.incarnation,
            &self.records,
        )?;
        let mut selected = self.records.clone();
        for (record, prior) in selected.iter_mut().zip(old) {
            if let Some(current) = floor
                .iter()
                .find(|r| r.index() == prior.index() && *r != &prior)
            {
                ensure!(
                    current.generation > prior.generation,
                    "cache repair cannot lower or conflict with governance"
                );
                let index = governance
                    .iter()
                    .position(|r| r == current)
                    .context("retained result cannot repair stale governance")?;
                *record = records[index].clone();
            }
        }
        let out = Self {
            state,
            records: selected,
            spent: self
                .spent
                .iter()
                .filter(|(_, expiry)| **expiry > wall)
                .map(|(id, expiry)| (*id, *expiry))
                .collect(),
        };
        // Reparse the entire candidate before any durable replacement.
        Self::decode(&out.encode(2)?, self.state.network, self.state.incarnation)
    }
}
impl Disk {
    fn repair_candidate(&self, store: &Store) -> Result<Snapshot> {
        let result = store
            .retained_cache_body()?
            .context("no certified domain body is retained for cache repair")?;
        let candidate =
            self.snapshot
                .repaired(&result, store.generations(), store.cache_wall_floor()?)?;
        candidate.authenticate(store)?;
        self.bounded(&candidate)?;
        Ok(candidate)
    }
    pub fn inspect(&self, store: &Store) -> Result<Value> {
        store.cache_checkpoint()?;
        let stale = self.snapshot.stale(store.generations())?;
        Ok(
            json!({"status":"RouteCacheInspected", "currentPermission":false,
            "pendingPublication":self.pending.is_some(), "authenticated":self.check(store).is_ok(),
            "staleRecords":stale, "spentConnections":self.snapshot.spent.len(),
            "maximumSpentConnections":MAX_SPENT, "metadataBytes":self.persisted.as_ref().map(Vec::len),
            "maximumMetadataBytes":self.maximum_bytes,
            "connectionAdmissionBytes":self.connection_admission_bytes(),
            "retainedBodyRepairAvailable":self.pending.is_none() && stale > 0 && self.repair_candidate(store).is_ok()}),
        )
    }
    pub fn repair(&mut self, store: &Store) -> Result<Value> {
        self.recover(store)?;
        if self.snapshot.stale(store.generations())? > 0 {
            let candidate = self.repair_candidate(store)?;
            let bytes = self.bounded(&candidate)?;
            let prior =
                files::read_at(&self.directory, OsStr::new(FILE), self.maximum_bytes, true)?;
            ensure!(
                self.persisted.as_ref() == Some(&prior),
                "route cache changed before repair"
            );
            // A single private backup makes an explicit repair reviewable and repeatable.
            match files::read_at(
                &self.directory,
                OsStr::new(BACKUP),
                self.maximum_bytes,
                true,
            ) {
                Ok(saved) => ensure!(
                    saved == prior,
                    "a different cache repair backup already exists"
                ),
                Err(_) => files::atomic_at(&self.directory, OsStr::new(BACKUP), &prior, false)?,
            }
            store.cache_checkpoint()?;
            self.replace(bytes)?;
            self.snapshot = candidate;
        }
        self.check(store)?;
        let mut report = self.inspect(store)?;
        report["status"] = json!("RouteCacheRepaired");
        Ok(report)
    }
}
