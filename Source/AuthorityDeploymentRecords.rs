// SPDX-License-Identifier: MIT
//! Permanent deployment ownership, exact consent references and restrictive withdrawal.
use crate::{
    authority_membership::{Reservations, Snapshot, version},
    authority_proof::{Digest, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

pub fn reference(bytes: &[u8]) -> Result<VersionRef> {
    let value = wire::decode(bytes)?;
    let f = value.list(32)?;
    ensure!(f.len() >= 7, "truncated deployment record");
    Ok(VersionRef {
        kind: f[0].uint()?,
        id: if f[0].uint()? == 105 {
            f[7].fixed()?
        } else {
            f[6].fixed()?
        },
        generation: f[4].uint()?,
        digest: wire::digest(bytes),
    })
}
fn prefix(value: &V, kind: u64, count: usize, n: Digest, i: Digest) -> Result<&[V]> {
    let f = value.array(count)?;
    ensure!(
        f[0].uint()? == kind
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == n
            && f[3].fixed::<32>()? == i
            && f[4].uint()? == 1
            && f[5] == V::Null,
        "deployment record context differs"
    );
    Ok(f)
}
#[derive(Clone, Debug)]
pub struct Registration {
    pub deployment: Digest,
    pub host: Digest,
    pub operator: Key,
    pub services: BTreeMap<u64, Key>,
    pub transports: BTreeMap<Key, Key>,
    pub monitor: Key,
    pub profile: VersionRef,
    pub consent: VersionRef,
    pub registrar: Key,
    pub grant: VersionRef,
    pub reference: VersionRef,
    pub bytes: Vec<u8>,
}
impl Registration {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = prefix(&value, 129, 17, n, i)?;
        let deployment = f[6].fixed()?;
        let host = f[7].fixed()?;
        let operator = f[8].fixed()?;
        ensure!(
            deployment != [0; 32] && host != [0; 32],
            "zero deployment or host identifier"
        );
        wire::valid_key(&operator)?;
        let mut services = BTreeMap::new();
        let mut previous = None;
        for v in f[9].list(9)? {
            let a = v.array(2)?;
            let role = a[0].uint()?;
            let key = a[1].fixed()?;
            wire::valid_key(&key)?;
            ensure!(
                role <= 8 && previous.is_none_or(|p| p < role),
                "unsorted service bindings"
            );
            services.insert(role, key);
            previous = Some(role);
        }
        ensure!(!services.is_empty(), "deployment has no services");
        let mut transports = BTreeMap::new();
        let mut previous = None;
        for v in f[10].list(9)? {
            let a = v.array(2)?;
            let service = a[0].fixed()?;
            let key = a[1].fixed()?;
            wire::valid_key(&key)?;
            ensure!(
                services.values().any(|s| *s == service) && previous.is_none_or(|p| p < service),
                "transport has no unique local service"
            );
            transports.insert(service, key);
            previous = Some(service);
        }
        let monitor = f[11].fixed()?;
        let registrar = f[14].fixed()?;
        wire::valid_key(&monitor)?;
        wire::valid_key(&registrar)?;
        let profile = version(&f[12])?;
        let consent = version(&f[13])?;
        let grant = version(&f[15])?;
        ensure!(
            profile.kind == 117
                && consent.kind == 105
                && profile.id == deployment
                && consent.id == deployment
                && grant.kind == 102,
            "deployment reference kind or identity differs"
        );
        Snapshot::parse(&f[16])?;
        Ok(Self {
            deployment,
            host,
            operator,
            services,
            transports,
            monitor,
            profile,
            consent,
            registrar,
            grant,
            reference: reference(bytes)?,
            bytes: bytes.to_vec(),
        })
    }
    pub fn streams(&self) -> BTreeSet<Key> {
        std::iter::once(self.operator)
            .chain(
                self.services
                    .iter()
                    .filter(|(role, _)| **role != 0)
                    .map(|(_, key)| *key),
            )
            .collect()
    }
}
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub deployment: Digest,
    pub admission: VersionRef,
    pub operator: Key,
    pub reference: VersionRef,
    pub bytes: Vec<u8>,
}
impl Withdrawal {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = prefix(&value, 130, 11, n, i)?;
        let admission = version(&f[7])?;
        let deployment = f[6].fixed()?;
        let operator = f[8].fixed()?;
        wire::valid_key(&operator)?;
        let generation = f[9].uint()?;
        ensure!(
            admission.kind == 129 && admission.id == deployment && generation > 0,
            "invalid deployment withdrawal target"
        );
        Snapshot::parse(&f[10])?;
        Ok(Self {
            deployment,
            admission,
            operator,
            reference: reference(bytes)?,
            bytes: bytes.to_vec(),
        })
    }
}
#[derive(Default)]
pub struct Index {
    pub deployments: BTreeMap<Digest, Registration>,
    pub withdrawals: BTreeMap<Digest, Withdrawal>,
    pub reserved: BTreeSet<Key>,
}
impl Index {
    pub fn parse(
        records: &[Vec<u8>],
        reservations: &Reservations,
        n: Digest,
        i: Digest,
    ) -> Result<Self> {
        let mut index = Self::default();
        let mut versions = BTreeMap::new();
        let mut ordinary = BTreeSet::new();
        let mut roots = None;
        for bytes in records {
            let value = wire::decode(bytes)?;
            let f = value.list(32)?;
            let kind = f[0].uint()?;
            if matches!(kind, 105 | 117 | 129 | 130) {
                let r = reference(bytes)?;
                ensure!(
                    versions.insert(r.index(), (r, bytes.as_slice())).is_none(),
                    "duplicate deployment record"
                );
            }
            match kind {
                102 => {
                    ordinary.insert(f[8].fixed::<32>()?);
                }
                125 => {
                    ordinary.insert(f[7].fixed::<32>()?);
                }
                127 => {
                    ordinary.insert(f[6].fixed::<32>()?);
                }
                129 => {
                    let r = Registration::parse(bytes, n, i)?;
                    ensure!(
                        index.deployments.insert(r.deployment, r).is_none(),
                        "duplicate deployment"
                    );
                }
                130 => {
                    let w = Withdrawal::parse(bytes, n, i)?;
                    ensure!(
                        index.withdrawals.insert(w.deployment, w).is_none(),
                        "duplicate deployment withdrawal"
                    );
                }
                131 => roots = Some(crate::runtime_bootstrap_keys::Keys::parse(bytes, n, i)?),
                _ => {}
            }
        }
        let base: BTreeMap<Key, u64> = reservations
            .0
            .iter()
            .map(|(role, key)| (*key, *role))
            .collect();
        let mut classes: BTreeMap<Key, (u64, Option<Digest>)> = BTreeMap::new();
        let mut claim =
            |key: Key, class: u64, owner: Option<Digest>, allowed: Option<u64>| -> Result<()> {
                ensure!(
                    !ordinary.contains(&key)
                        && base.get(&key).is_none_or(|role| Some(*role) == allowed),
                    "deployment reuses another permanent identity class"
                );
                if let Some(old) = classes.insert(key, (class, owner)) {
                    ensure!(
                        old == (class, owner) && matches!(class, 7 | 10),
                        "deployment key has another owner or role"
                    );
                }
                Ok(())
            };
        for r in index.deployments.values() {
            claim(r.operator, 7, None, None)?;
            for (role, key) in &r.services {
                claim(*key, 8, Some(r.deployment), (*role == 0).then_some(0))?;
            }
            for (service, key) in &r.transports {
                let allowed = if r.services.get(&0) == Some(service) {
                    if let Some(roots) = &roots {
                        if let Some(expected) = roots.authority_transports.get(service) {
                            ensure!(
                                expected == key,
                                "appointed authority transport differs from bootstrap"
                            );
                            Some(5)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else if r.services.get(&5) == Some(service) {
                    roots.as_ref().and_then(|roots| {
                        roots
                            .route_transports
                            .iter()
                            .find(|(_, (_, transport))| transport == key)
                            .map(|(class, _)| *class)
                    })
                } else {
                    None
                };
                claim(*key, 9, Some(r.deployment), allowed)?;
            }
            claim(r.monitor, 10, None, Some(6))?;
            for expected in [&r.profile, &r.consent] {
                ensure!(
                    versions
                        .get(&expected.index())
                        .is_some_and(|(v, _)| v == expected),
                    "deployment has missing or conflicting local approval"
                );
            }
            let consent = wire::decode(versions[&r.consent.index()].1)?;
            let c = consent.array(19)?;
            ensure!(
                c[6].fixed::<32>()? == r.host
                    && c[8].fixed::<32>()? == r.operator
                    && c[17].fixed::<32>()? == r.profile.digest
                    && c[18].uint()? == 0,
                "deployment consent ownership differs"
            );
        }
        for w in index.withdrawals.values() {
            let r = index
                .deployments
                .get(&w.deployment)
                .context("withdrawal lacks registration")?;
            ensure!(
                w.admission == r.reference && w.operator == r.operator,
                "withdrawal does not belong to deployment operator"
            );
        }
        for (kind, id) in versions.keys() {
            if matches!(*kind, 105 | 117) {
                ensure!(
                    index.deployments.contains_key(id),
                    "orphaned local approval record"
                );
            }
        }
        index.reserved = classes.into_keys().collect();
        Ok(index)
    }
    pub fn streams(&self) -> BTreeSet<Key> {
        self.deployments
            .values()
            .flat_map(Registration::streams)
            .collect()
    }
    pub fn open_count(&self) -> usize {
        self.deployments
            .keys()
            .filter(|d| !self.withdrawals.contains_key(*d))
            .count()
    }
    pub fn open_operators(&self) -> BTreeSet<Key> {
        self.deployments
            .iter()
            .filter(|(d, _)| !self.withdrawals.contains_key(*d))
            .map(|(_, r)| r.operator)
            .collect()
    }
    pub fn extend_reservations(&self, base: &Reservations) -> Reservations {
        let mut output = base.clone();
        for key in &self.reserved {
            if !output.contains(key) {
                output.0.push((7, *key));
            }
        }
        output
    }
}
