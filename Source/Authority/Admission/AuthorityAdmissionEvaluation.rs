// SPDX-License-Identifier: MIT
// The authority enforces registrar purpose, capacity and current candidate acceptance.
use super::*;
use crate::{authority_membership::Reservations, authority_proof::Intent};

pub struct Outcome {
    pub records: Vec<Vec<u8>>,
    pub dependencies: Vec<VersionRef>,
    pub created: VersionRef,
}
impl Operation {
    pub fn authorise(
        &self,
        records: &[Vec<u8>],
        reserved: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
    ) -> Result<Outcome> {
        let n = intent.network;
        let i = intent.incarnation;
        let g = Governance::parse(n, i, records)?;
        let index = Index::parse(records, n, i)?;
        let p = Policy::parse(&self.policy, n, i)?;
        let created = record_reference(&self.next, n, i)?;
        let current = records
            .iter()
            .find(|x| record_reference(x, n, i).is_ok_and(|r| r.index() == created.index()));
        if replay {
            ensure!(current == Some(&self.next), "admission result superseded");
        } else {
            ensure!(
                current == self.previous.as_ref(),
                "admission predecessor is stale"
            );
        }
        let mut dependencies = if self.transition == Transition::Policy && !p.enabled {
            let old = Policy::parse(
                self.previous
                    .as_ref()
                    .context("policy withdrawal lacks predecessor")?,
                n,
                i,
            )?;
            ensure!(
                intent.requester == old.owner,
                "policy withdrawal belongs to another owner"
            );
            vec![old.reference]
        } else if self.transition == Transition::Retire {
            ensure!(
                index
                    .policies
                    .get(&p.reference.id)
                    .is_some_and(|old| old.bytes == p.bytes),
                "admission policy changed"
            );
            vec![p.reference.clone()]
        } else {
            p.authorise(&g, n, at)?
        };
        if self.transition == Transition::Policy {
            if self.previous.is_none() && !replay {
                ensure!(
                    index.policies.len() < MAX_POLICIES && p.enabled,
                    "admission policy capacity or creation differs"
                );
                for legacy in &p.legacy {
                    let bytes = g.record_bytes(125, legacy.id)?;
                    ensure!(
                        Governance::record_versions(n, i, &[bytes.to_vec()])? == [legacy.clone()]
                            && !wire::decode(bytes)?.array(12)?[9].boolean()?,
                        "legacy roster differs from current manual membership"
                    );
                }
                let occupied = known_keys(&g, &index)?;
                ensure!(
                    !reserved.contains(&p.registrar)
                        && !reserved.contains(&p.descriptor)
                        && !occupied.contains(&p.registrar)
                        && !occupied.contains(&p.descriptor),
                    "admission policy reuses a dedicated or admitted identity"
                );
            }
        } else {
            ensure!(
                index
                    .policies
                    .get(&p.reference.id)
                    .is_some_and(|old| old.bytes == p.bytes),
                "admission policy changed"
            );
            dependencies.push(p.reference.clone());
            let s = Slot::parse(&self.next, n, i)?;
            ensure!(
                s.slot < p.maximum_slots,
                "admission slot exceeds policy quota"
            );
            let old = self
                .previous
                .as_ref()
                .map(|x| Slot::parse(x, n, i))
                .transpose()?;
            if !replay {
                match self.transition {
                    Transition::Reserve => {
                        ensure!(
                            s.ordinal > index.claim_floor(p.reference.id)
                                && !index
                                    .slots
                                    .values()
                                    .any(|x| x.policy == p.reference.id && x.claim == s.claim),
                            "admission claim is retired or already allocated"
                        );
                        if let Some(old) = &old {
                            ensure!(
                                old.state == 3
                                    || old.state == 0
                                        && at > old.challenge_until.saturating_add(1250),
                                "admission slot is occupied"
                            );
                        }
                        ensure!(
                            s.challenge_until > at.saturating_add(1250)
                                && s.challenge_until <= at.saturating_add(CHALLENGE_MS),
                            "admission challenge deadline exceeds finite bound"
                        );
                        let occupied = known_keys(&g, &index)?;
                        for role in &s.roles {
                            ensure!(
                                !reserved.contains(&role.member)
                                    && !reserved.contains(&role.relay)
                                    && (!occupied.contains(&role.member)
                                        || p.legacy.iter().any(|r| g
                                            .record_bytes(125, r.id)
                                            .is_ok_and(|bytes| wire::digest(bytes) == r.digest
                                                && wire::decode(bytes).is_ok_and(|v| v
                                                    .array(12)
                                                    .is_ok_and(|f| f[7].fixed::<32>().ok()
                                                        == Some(role.member))))))
                                    && !occupied.contains(&role.relay),
                                "admission candidate reuses an existing identity"
                            );
                        }
                    }
                    Transition::Enrol | Transition::Adopt => {
                        let old = old
                            .as_ref()
                            .context("admission enrolment lacks reservation")?;
                        ensure!(
                            old.challenge_until > at.saturating_add(1250),
                            "admission acceptance expired"
                        );
                        let parent = wire::decode(g.record_bytes(102, p.parent.id)?)?;
                        let tier = crate::authority_membership::version(&parent.array(17)?[9])?;
                        ensure!(
                            s.material == enrol_material(&p, old, &tier, &self.snapshot, n, i)?,
                            "admission material differs from fixed derived grants"
                        );
                        let legacy_members = self
                            .legacy
                            .iter()
                            .map(|bytes| key(&wire::decode(bytes)?.array(12)?[7]))
                            .collect::<Result<Vec<_>>>()?;
                        for role in &s.roles {
                            let existing = g.versions().iter().any(|r| {
                                r.kind == 125
                                    && !index
                                        .slots
                                        .values()
                                        .any(|s| s.owned().is_ok_and(|v| v.contains(&r.index())))
                                    && g.record_bytes(125, r.id).is_ok_and(|bytes| {
                                        wire::decode(bytes).is_ok_and(|v| {
                                            v.array(12).is_ok_and(|f| {
                                                f[7].fixed::<32>().ok() == Some(role.member)
                                                    && f[9].boolean().ok() == Some(false)
                                            })
                                        })
                                    })
                            });
                            ensure!(
                                !existing
                                    || self.transition == Transition::Adopt
                                        && legacy_members.contains(&role.member),
                                "existing manual identity requires explicit adoption"
                            );
                        }
                        for bytes in &self.legacy {
                            let r = Governance::record_versions(n, i, std::slice::from_ref(bytes))?
                                .remove(0);
                            ensure!(
                                g.record_bytes(125, r.id)? == bytes,
                                "legacy membership already changed"
                            );
                            dependencies.push(r);
                        }
                    }
                    Transition::RenewalChallenge => ensure!(
                        s.challenge_until > at.saturating_add(1250)
                            && s.challenge_until <= at.saturating_add(CHALLENGE_MS),
                        "admission renewal challenge exceeds finite bound"
                    ),
                    Transition::Renew => ensure!(
                        old.as_ref()
                            .context("renewal lacks challenge")?
                            .challenge_until
                            > at.saturating_add(1250),
                        "admission renewal acceptance expired"
                    ),
                    Transition::Retire => (),
                    Transition::Policy => unreachable!(),
                }
            }
            if let Some(old) = old {
                dependencies.push(old.reference);
            }
        }
        dependencies.sort_by_key(VersionRef::index);
        dependencies.dedup();
        if !replay {
            for r in &dependencies {
                ensure!(
                    self.snapshot.references.contains(r),
                    "admission snapshot omits current authority"
                );
            }
        }
        let mut next = records.to_vec();
        if !replay {
            let owned = if self.transition == Transition::Policy {
                vec![created.index()]
            } else {
                let mut owned = Slot::parse(&self.next, n, i)?.owned()?;
                owned.push(created.index());
                owned
            };
            next.retain(|x| {
                !wire::decode(x).is_ok_and(|v| {
                    v.list(32).is_ok_and(|f| {
                        f[0].uint()
                            .ok()
                            .zip(f[6].fixed::<32>().ok())
                            .is_some_and(|id| owned.contains(&id))
                    })
                })
            });
            for legacy in self.retired_legacy(n, i)? {
                let reference =
                    Governance::record_versions(n, i, std::slice::from_ref(&legacy))?.remove(0);
                next.retain(|bytes| {
                    !wire::decode(bytes).is_ok_and(|v| {
                        v.list(32).is_ok_and(|f| {
                            f[0].uint().ok() == Some(125)
                                && f[6].fixed::<32>().ok() == Some(reference.id)
                        })
                    })
                });
                next.push(legacy);
            }
            next.extend(self.derive(n, i)?);
            next.sort_by_key(|x| {
                let v = wire::decode(x).expect("validated record");
                let f = v.list(32).expect("array");
                let kind = f[0].uint().expect("kind");
                let lookup = if matches!(kind, 100 | 114 | 131) {
                    n
                } else if kind == 105 {
                    f[7].fixed().expect("id")
                } else if matches!(kind, 126 | 128) {
                    f[6].array(4).expect("reference")[1].fixed().expect("id")
                } else {
                    f[6].fixed().expect("id")
                };
                (kind, lookup)
            });
            Governance::parse(n, i, &next)?;
        }
        Ok(Outcome {
            records: next,
            dependencies,
            created,
        })
    }
}
fn known_keys(g: &Governance, index: &Index) -> Result<BTreeSet<Key>> {
    let mut keys = BTreeSet::new();
    let retired = g
        .versions()
        .iter()
        .filter(|r| r.kind == 125 && r.generation > 1)
        .filter_map(|r| g.record_bytes(125, r.id).ok())
        .filter_map(|bytes| {
            let v = wire::decode(bytes).ok()?;
            let f = v.array(12).ok()?;
            f[9].boolean()
                .ok()?
                .then(|| f[7].fixed::<32>().ok())
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    for r in g.versions() {
        let v = wire::decode(g.record_bytes(r.kind, r.id)?)?;
        let f = v.list(32)?;
        let owned = index
            .slots
            .values()
            .any(|s| s.owned().is_ok_and(|v| v.contains(&r.index())));
        if owned {
            continue;
        }
        match r.kind {
            102 => {
                let key = f[8].fixed()?;
                if !retired.contains(&key) {
                    keys.insert(key);
                }
            }
            125 => {
                let key = f[7].fixed()?;
                if !retired.contains(&key) {
                    keys.insert(key);
                }
            }
            127 => {
                keys.insert(f[6].fixed()?);
            }
            _ => (),
        }
    }
    for p in index.policies.values() {
        keys.extend([p.registrar, p.descriptor]);
    }
    for s in index.slots.values().filter(|s| s.state != 3) {
        for r in &s.roles {
            keys.extend([r.member, r.relay]);
        }
    }
    Ok(keys)
}
