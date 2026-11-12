// SPDX-License-Identifier: MIT
// Every slot transition compares its exact predecessor and derives its owned effects.
use super::*;
use crate::authority_proof::Intent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Policy,
    Reserve,
    Enrol,
    RenewalChallenge,
    Renew,
    Retire,
    Adopt,
}
impl Transition {
    pub fn number(self) -> u64 {
        match self {
            Self::Policy => 0,
            Self::Reserve => 1,
            Self::Enrol => 2,
            Self::RenewalChallenge => 3,
            Self::Renew => 4,
            Self::Retire => 5,
            Self::Adopt => 6,
        }
    }
    fn parse(v: &V) -> Result<Self> {
        Ok(match v.uint()? {
            0 => Self::Policy,
            1 => Self::Reserve,
            2 => Self::Enrol,
            3 => Self::RenewalChallenge,
            4 => Self::Renew,
            5 => Self::Retire,
            6 => Self::Adopt,
            _ => anyhow::bail!("unknown admission transition"),
        })
    }
}
#[derive(Clone)]
pub struct Operation {
    pub transition: Transition,
    pub policy: Vec<u8>,
    pub previous: Option<Vec<u8>>,
    pub next: Vec<u8>,
    pub acceptance: Vec<Vec<u8>>,
    pub legacy: Vec<Vec<u8>>,
    pub snapshot: Snapshot,
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        action == "AuthorityAdmission"
    }
    pub fn parameters(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityAdmission".into()),
            V::Uint(self.transition.number()),
            b(&self.policy),
            self.previous.as_ref().map_or(V::Null, |x| b(x)),
            b(&self.next),
            a(self.acceptance.iter().map(|x| b(x)).collect()),
            a(self.legacy.iter().map(|x| b(x)).collect()),
            self.snapshot.value.clone(),
        ]))
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        ensure!(
            Self::handles(&intent.action) && intent.profile_generation == 0,
            "admission intent differs"
        );
        let v = wire::decode(&intent.parameters)?;
        let f = v.array(10)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "AuthorityAdmission",
            "admission operation schema differs"
        );
        let op = Self {
            transition: Transition::parse(&f[3])?,
            policy: f[4].bytes()?.to_vec(),
            previous: if f[5] == V::Null {
                None
            } else {
                Some(f[5].bytes()?.to_vec())
            },
            next: f[6].bytes()?.to_vec(),
            acceptance: f[7]
                .list(MAX_ROLES)?
                .iter()
                .map(|x| Ok(x.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
            legacy: f[8]
                .list(MAX_ROLES)?
                .iter()
                .map(|x| Ok(x.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
            snapshot: Snapshot::parse(&f[9])?,
        };
        let p = Policy::parse(&op.policy, intent.network, intent.incarnation)?;
        let created = record_reference(&op.next, intent.network, intent.incarnation)?;
        ensure!(
            intent.resource == created.id
                && intent.revision == created.generation
                && intent.minimum_policy_epoch == op.snapshot.epoch
                && intent.minimum_policy_height == op.snapshot.height,
            "admission intent resource or floor differs"
        );
        let n = wire::decode(&op.next)?;
        let nf = n.array(9)?;
        ensure!(
            nf[8] == op.snapshot.value,
            "admission record snapshot differs"
        );
        if let Some(old) = &op.previous {
            let r = record_reference(old, intent.network, intent.incarnation)?;
            ensure!(
                r.index() == created.index()
                    && r.generation.checked_add(1) == Some(created.generation)
                    && nf[5].fixed::<32>()? == r.digest,
                "admission successor differs from exact predecessor"
            );
        } else {
            ensure!(
                created.generation == 1 && nf[5] == V::Null,
                "admission creation has predecessor"
            );
        }
        if op.transition == Transition::Policy {
            let next = Policy::parse(&op.next, intent.network, intent.incarnation)?;
            ensure!(
                op.policy == op.next && intent.requester == next.owner && op.acceptance.is_empty(),
                "admission policy belongs to another owner"
            );
            if let Some(old) = &op.previous {
                next.successor_of(&Policy::parse(old, intent.network, intent.incarnation)?)?;
            }
        } else {
            let s = Slot::parse(&op.next, intent.network, intent.incarnation)?;
            ensure!(
                s.policy == p.reference.id
                    && (intent.requester == p.registrar
                        || op.transition == Transition::Retire && intent.requester == p.owner),
                "admission transition belongs to another registrar"
            );
            op.structure(&p, &s, intent.network, intent.incarnation)?;
        }
        ensure!(
            op.legacy.is_empty() || op.transition == Transition::Adopt,
            "legacy evidence belongs only to explicit adoption"
        );
        if op.transition == Transition::Adopt {
            op.retired_legacy(intent.network, intent.incarnation)?;
        }
        ensure!(
            op.parameters()? == intent.parameters,
            "admission operation canonical encoding differs"
        );
        ensure!(
            op.updates(intent.network, intent.incarnation)?
                .iter()
                .all(|(old, new)| old.generation.checked_add(1) == Some(new.generation)),
            "admission material successor skips generation"
        );
        Ok(op)
    }
    fn structure(&self, p: &Policy, s: &Slot, n: Digest, i: Digest) -> Result<()> {
        let old = self
            .previous
            .as_ref()
            .map(|x| Slot::parse(x, n, i))
            .transpose()?;
        if self.transition == Transition::Reserve {
            ensure!(
                s.state == 0
                    && s.challenge_until > 0
                    && s.legacy_streams.is_empty()
                    && self.acceptance.is_empty(),
                "admission reservation state differs"
            );
            if let Some(old) = &old {
                ensure!(
                    s.slot == old.slot
                        && s.policy == old.policy
                        && s.assignment
                            == old
                                .assignment
                                .checked_add(1)
                                .context("assignment exhausted")?
                        && s.ordinal > old.ordinal
                        && s.material == old.material,
                    "admission reassignment changes retained material or skips generation"
                );
            } else {
                ensure!(
                    s.assignment == 1 && s.material.is_empty(),
                    "new admission slot contains retained authority"
                );
            }
        } else {
            let old = old
                .as_ref()
                .context("admission transition lacks current slot")?;
            ensure!(
                s.policy == old.policy
                    && s.slot == old.slot
                    && s.assignment == old.assignment
                    && s.claim == old.claim
                    && s.request == old.request
                    && s.application == old.application
                    && a(s.roles.iter().map(Role::value).collect())
                        == a(old.roles.iter().map(Role::value).collect()),
                "admission transition changes candidate or claim"
            );
            match self.transition {
                Transition::Enrol | Transition::Adopt => {
                    ensure!(
                        old.state == 0
                            && s.state == 1
                            && s.challenge_until == 0
                            && s.nonce == old.nonce,
                        "admission enrolment state differs"
                    );
                    old.verify_acceptance(n, i, &self.acceptance)?;
                    let mut legacy = self
                        .legacy
                        .iter()
                        .map(|bytes| key(&wire::decode(bytes)?.array(12)?[7]))
                        .collect::<Result<Vec<_>>>()?;
                    legacy.sort();
                    ensure!(
                        s.legacy_streams == legacy,
                        "legacy stream retention differs from explicit adoption"
                    );
                }
                Transition::RenewalChallenge => ensure!(
                    old.active()
                        && s.state == 2
                        && s.challenge_until > 0
                        && s.nonce != old.nonce
                        && self.acceptance.is_empty()
                        && s.material == old.material
                        && s.legacy_streams == old.legacy_streams,
                    "admission renewal challenge differs"
                ),
                Transition::Renew => {
                    ensure!(
                        old.state == 2
                            && s.state == 1
                            && s.challenge_until == 0
                            && s.nonce == old.nonce
                            && s.material == old.material
                            && s.legacy_streams == old.legacy_streams,
                        "admission renewal state differs"
                    );
                    old.verify_acceptance(n, i, &self.acceptance)?;
                }
                Transition::Retire => ensure!(
                    old.state != 3
                        && s.state == 3
                        && s.challenge_until == 0
                        && s.nonce == old.nonce
                        && self.acceptance.is_empty()
                        && s.material == old.material
                        && s.legacy_streams == old.legacy_streams,
                    "admission retirement changes retained evidence"
                ),
                _ => unreachable!(),
            }
        }
        ensure!(
            s.roles
                .iter()
                .all(|r| p.templates.iter().any(|t| t.role == r.role)),
            "admission role exceeds policy"
        );
        Ok(())
    }
    pub fn derive(&self, n: Digest, i: Digest) -> Result<Vec<Vec<u8>>> {
        let mut out = if self.transition == Transition::Policy {
            vec![]
        } else {
            Slot::parse(&self.next, n, i)?.material
        };
        out.push(self.next.clone());
        Ok(out)
    }
    pub fn retired_legacy(&self, n: Digest, i: Digest) -> Result<Vec<Vec<u8>>> {
        if self.transition != Transition::Adopt {
            return Ok(vec![]);
        }
        let p = Policy::parse(&self.policy, n, i)?;
        let s = Slot::parse(&self.next, n, i)?;
        ensure!(
            !self.legacy.is_empty(),
            "legacy adoption lacks owner-rostered memberships"
        );
        let mut seen = BTreeSet::new();
        let mut result = vec![];
        for bytes in &self.legacy {
            let refs = Governance::record_versions(n, i, std::slice::from_ref(bytes))?;
            let r = &refs[0];
            ensure!(
                p.legacy.contains(r) && seen.insert(r.id),
                "legacy adoption is outside the owner roster or repeated"
            );
            let v = wire::decode(bytes)?;
            let mut f = v.array(12)?.to_vec();
            let member = key(&f[7])?;
            ensure!(
                !f[9].boolean()? && s.roles.iter().any(|r| r.member == member),
                "legacy adoption differs from candidate keys"
            );
            f[4] = V::Uint(2);
            f[5] = b(&r.digest);
            f[9] = V::Bool(true);
            f[11] = self.snapshot.value.clone();
            result.push(wire::encode(&a(f))?);
        }
        Ok(result)
    }
    pub fn result_references(
        &self,
        dependencies: &[VersionRef],
        n: Digest,
        i: Digest,
    ) -> Result<Vec<VersionRef>> {
        let mut refs = dependencies
            .iter()
            .map(|r| (r.index(), r.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut created = self.derive(n, i)?;
        created.extend(self.retired_legacy(n, i)?);
        for bytes in created {
            let r = Governance::record_versions(n, i, &[bytes])?.remove(0);
            refs.insert(r.index(), r);
        }
        let refs = refs.into_values().collect::<Vec<_>>();
        crate::authority_proof::validate_versions(&refs, 64)?;
        Ok(refs)
    }
    pub fn updates(&self, n: Digest, i: Digest) -> Result<Vec<(VersionRef, VersionRef)>> {
        let mut previous = vec![];
        if let Some(old) = &self.previous {
            previous.push(old.clone());
            if self.transition != Transition::Policy {
                previous.extend(Slot::parse(old, n, i)?.material);
            }
        }
        previous.extend(self.legacy.clone());
        let mut next = self.derive(n, i)?;
        next.extend(self.retired_legacy(n, i)?);
        let mut out = vec![];
        for bytes in previous {
            let old = Governance::record_versions(n, i, &[bytes])?.remove(0);
            if let Some(new) = next.iter().find_map(|bytes| {
                Governance::record_versions(n, i, std::slice::from_ref(bytes))
                    .ok()
                    .and_then(|mut r| r.pop())
                    .filter(|r| r.index() == old.index() && *r != old)
            }) {
                out.push((old, new));
            }
        }
        out.sort_by_key(|(old, _)| old.index());
        Ok(out)
    }
    pub fn previous_reference(&self, n: Digest, i: Digest) -> Result<Option<VersionRef>> {
        self.previous
            .as_ref()
            .map(|x| record_reference(x, n, i))
            .transpose()
    }
}
