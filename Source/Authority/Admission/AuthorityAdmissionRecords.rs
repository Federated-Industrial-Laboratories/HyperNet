// SPDX-License-Identifier: MIT
// Admission records carry fixed grants and finite candidate possession challenges.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub role: u64,
    pub destination: Digest,
    pub application: Option<Digest>,
    pub page: Option<Key>,
    pub limits: Limits,
    pub connections: u64,
    pub bytes: u64,
    pub voucher_ms: u64,
}
impl Template {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.list(8)?;
        ensure!(
            f.len() == 7 || f.len() == 8,
            "admission template version differs"
        );
        let t = Self {
            role: f[0].uint()?,
            destination: id(&f[1])?,
            application: if f[2] == V::Null {
                None
            } else {
                Some(id(&f[2])?)
            },
            page: if f.len() == 8 {
                let extension = f[7].array(2)?;
                ensure!(
                    extension[0].uint()? == 1,
                    "admission Page target version differs"
                );
                Some(key(&extension[1])?)
            } else {
                None
            },
            limits: limits(&f[3])?,
            connections: f[4].uint()?,
            bytes: f[5].uint()?,
            voucher_ms: f[6].uint()?,
        };
        ensure!(
            t.role < 2
                && (t.role == 1) == t.application.is_some()
                && (t.page.is_none() || t.role == 0)
                && (1..=4096).contains(&t.connections)
                && t.bytes > 0
                && (120_000..=MAX_VOUCHER_MS).contains(&t.voucher_ms),
            "admission template bounds differ"
        );
        Ok(t)
    }
    pub fn value(&self) -> V {
        let mut fields = vec![
            V::Uint(self.role),
            b(&self.destination),
            self.application.map_or(V::Null, |x| b(&x)),
            a(self.limits.iter().map(|x| V::Uint(*x)).collect()),
            V::Uint(self.connections),
            V::Uint(self.bytes),
            V::Uint(self.voucher_ms),
        ];
        if let Some(page) = self.page {
            fields.push(a(vec![V::Uint(1), b(&page)]));
        }
        a(fields)
    }
}
#[derive(Clone, Debug)]
pub struct Policy {
    pub reference: VersionRef,
    pub owner: Key,
    pub parent: VersionRef,
    pub registrar: Key,
    pub descriptor: Key,
    pub enabled: bool,
    pub maximum_slots: u64,
    pub validity: Validity,
    pub relay: Digest,
    pub authority: Digest,
    pub templates: Vec<Template>,
    pub legacy: Vec<VersionRef>,
    pub bytes: Vec<u8>,
}
impl Policy {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let reference = record_reference(bytes, n, i)?;
        ensure!(reference.kind == POLICY, "admission policy kind differs");
        let v = wire::decode(bytes)?;
        let f = v.array(9)?[7].array(11)?;
        let p = Self {
            reference,
            owner: key(&f[0])?,
            parent: crate::authority_membership::version(&f[1])?,
            registrar: key(&f[2])?,
            descriptor: key(&f[3])?,
            enabled: f[4].boolean()?,
            maximum_slots: f[5].uint()?,
            validity: Validity::parse(&f[6])?,
            relay: id(&f[7])?,
            authority: id(&f[8])?,
            templates: f[9]
                .list(MAX_ROLES)?
                .iter()
                .map(Template::parse)
                .collect::<Result<_>>()?,
            legacy: f[10]
                .list(128)?
                .iter()
                .map(crate::authority_membership::version)
                .collect::<Result<_>>()?,
            bytes: bytes.to_vec(),
        };
        ensure!(
            p.parent.kind == 102
                && p.owner != p.registrar
                && p.owner != p.descriptor
                && p.registrar != p.descriptor
                && (1..=MAX_SLOTS).contains(&p.maximum_slots)
                && !p.templates.is_empty()
                && p.templates.windows(2).all(|x| x[0].role < x[1].role)
                && p.relay != p.authority
                && p.templates
                    .iter()
                    .all(|t| t.destination != p.relay && t.destination != p.authority),
            "admission policy identity or role separation differs"
        );
        crate::authority_proof::validate_versions(&p.legacy, 128)?;
        ensure!(
            p.legacy.iter().all(|r| r.kind == 125 && r.generation == 1),
            "legacy roster must pin initial manual memberships"
        );
        Ok(p)
    }
    pub fn payload(&self) -> V {
        a(vec![
            b(&self.owner),
            reference(&self.parent),
            b(&self.registrar),
            b(&self.descriptor),
            V::Bool(self.enabled),
            V::Uint(self.maximum_slots),
            self.validity.value(),
            b(&self.relay),
            b(&self.authority),
            a(self.templates.iter().map(Template::value).collect()),
            a(self.legacy.iter().map(reference).collect()),
        ])
    }
    pub fn template(&self, role: u64) -> Result<&Template> {
        self.templates
            .iter()
            .find(|t| t.role == role)
            .context("admission role unavailable")
    }
    pub fn authorise(&self, g: &Governance, n: Digest, at: u64) -> Result<Vec<VersionRef>> {
        ensure!(
            self.enabled && crate::authority_membership::current(at, self.validity),
            "admission policy disabled or expired"
        );
        let parent = wire::decode(g.record_bytes(102, self.parent.id)?)?;
        let f = parent.array(17)?;
        ensure!(
            g.versions().contains(&self.parent),
            "admission parent changed"
        );
        ensure!(
            f[8].fixed::<32>()? == self.owner && f[14].uint()? > 0,
            "admission parent owner or delegation differs"
        );
        let span = g.grant_validity(self.parent.id)?;
        ensure!(
            self.validity.0 >= span.0 && self.validity.1 <= span.1,
            "admission policy exceeds parent validity"
        );
        let mut actions = vec![0, 10, 11];
        if self.templates.iter().any(|t| t.role == 1) {
            actions.push(30);
        }
        let d = g.current_capability(
            self.parent.id,
            &Requirement {
                subject: self.owner,
                actions: &actions,
                scope: (0, n),
                namespace: None,
                usage: [0; 4],
                evaluated_at_ms: at,
                expected: &[],
            },
        )?;
        ensure!(
            self.validity.0 >= d.validity.0 && self.validity.1 <= d.validity.1,
            "admission policy exceeds current parent membership or capability lifetime"
        );
        let parent_limits = limits(&f[15])?;
        for t in &self.templates {
            ensure!(
                t.limits.iter().zip(parent_limits).all(|(x, y)| *x <= y),
                "admission template exceeds parent limits"
            );
        }
        Ok(d.dependencies)
    }
    pub fn successor_of(&self, old: &Self) -> Result<()> {
        let mut next = self.payload().array(11)?.to_vec();
        let mut prior = old.payload().array(11)?.to_vec();
        next[4] = V::Null;
        prior[4] = V::Null;
        ensure!(
            self.reference.id == old.reference.id
                && self.reference.generation
                    == old
                        .reference
                        .generation
                        .checked_add(1)
                        .context("admission policy generation exhausted")?
                && next == prior
                && !self.enabled
                && old.enabled,
            "admission policy successor may only withdraw its immutable purpose"
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Role {
    pub role: u64,
    pub member: Key,
    pub relay: Key,
    pub request: Vec<u8>,
}
impl Role {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(4)?;
        let r = Self {
            role: f[0].uint()?,
            member: key(&f[1])?,
            relay: key(&f[2])?,
            request: f[3].bytes()?.to_vec(),
        };
        ensure!(
            r.role < 2 && r.member != r.relay && r.request.len() <= 4096,
            "admission role identity differs"
        );
        let (payload, signatures) = wire::envelope(&r.request, 1)?;
        let v = wire::decode(&payload)?;
        let f = v.array(10)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "HyperNetJoinRequest"
                && id(&f[3])? == n
                && id(&f[4])? == i
                && id(&f[5])? != [0; 32]
                && id(&f[6])? != [0; 32]
                && key(&f[7])? == r.member
                && key(&f[8])? == r.relay
                && f[9].uint()? <= 1
                && signatures.len() == 1
                && signatures[0].0 == r.member,
            "admission role request signature or public fields differ"
        );
        Ok(r)
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(self.role),
            b(&self.member),
            b(&self.relay),
            b(&self.request),
        ])
    }
    pub fn grants(&self, policy: Digest, slot: u64) -> Vec<Digest> {
        (1..=if self.role == 1 { 3 } else { 2 })
            .map(|p| identifier(policy, slot, self.role, p).expect("validated slot"))
            .collect()
    }
}
#[derive(Clone, Debug)]
pub struct Slot {
    pub reference: VersionRef,
    pub policy: Digest,
    pub slot: u64,
    pub assignment: u64,
    pub claim: Digest,
    pub ordinal: u64,
    pub request: Digest,
    pub application: Digest,
    /// 0 reserved, 1 enrolled, 2 renewal challenge, 3 retired.
    pub state: u64,
    pub challenge_until: u64,
    pub roles: Vec<Role>,
    pub nonce: Digest,
    pub material: Vec<Vec<u8>>,
    pub legacy_streams: Vec<Key>,
    pub bytes: Vec<u8>,
}
impl Slot {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let reference = record_reference(bytes, n, i)?;
        ensure!(reference.kind == SLOT, "admission slot kind differs");
        let v = wire::decode(bytes)?;
        let f = v.array(9)?[7].array(13)?;
        let claim = id(&f[3])?;
        let s = Self {
            reference,
            policy: id(&f[0])?,
            slot: f[1].uint()?,
            assignment: f[2].uint()?,
            claim,
            ordinal: claim_ordinal(&claim)?,
            request: id(&f[4])?,
            application: id(&f[5])?,
            state: f[6].uint()?,
            challenge_until: f[7].uint()?,
            roles: f[8]
                .list(MAX_ROLES)?
                .iter()
                .map(|v| Role::parse(v, n, i))
                .collect::<Result<_>>()?,
            nonce: id(&f[9])?,
            material: f[11]
                .list(7)?
                .iter()
                .map(|x| Ok(x.bytes()?.to_vec()))
                .collect::<Result<_>>()?,
            legacy_streams: f[12]
                .list(MAX_ROLES)?
                .iter()
                .map(key)
                .collect::<Result<_>>()?,
            bytes: bytes.to_vec(),
        };
        ensure!(
            s.legacy_streams.windows(2).all(|x| x[0] < x[1])
                && s.legacy_streams
                    .iter()
                    .all(|key| s.roles.iter().any(|r| r.member == *key)),
            "legacy stream ownership differs"
        );
        ensure!(
            f[10].uint()? == 1
                && s.slot < MAX_SLOTS
                && s.assignment > 0
                && s.state <= 3
                && !s.roles.is_empty()
                && s.roles.windows(2).all(|r| r[0].role < r[1].role)
                && s.reference.id == identifier(s.policy, s.slot, 0, 0)?
                && ((s.state == 0 || s.state == 2) == (s.challenge_until > 0)),
            "admission slot schema, assignment or challenge differs"
        );
        let keys = s
            .roles
            .iter()
            .flat_map(|r| [r.member, r.relay])
            .collect::<BTreeSet<_>>();
        ensure!(
            keys.len() == s.roles.len() * 2,
            "admission role keys overlap"
        );
        Ok(s)
    }
    pub fn payload(&self) -> V {
        a(vec![
            b(&self.policy),
            V::Uint(self.slot),
            V::Uint(self.assignment),
            b(&self.claim),
            b(&self.request),
            b(&self.application),
            V::Uint(self.state),
            V::Uint(self.challenge_until),
            a(self.roles.iter().map(Role::value).collect()),
            b(&self.nonce),
            V::Uint(1),
            a(self.material.iter().map(|x| b(x)).collect()),
            a(self.legacy_streams.iter().map(|x| b(x)).collect()),
        ])
    }
    pub fn active(&self) -> bool {
        matches!(self.state, 1 | 2)
    }
    pub fn owned(&self) -> Result<Vec<(u64, Digest)>> {
        let mut owned = vec![];
        for role in 0..2 {
            owned.push((125, identifier(self.policy, self.slot, role, 0)?));
            for purpose in 1..=if role == 1 { 3 } else { 2 } {
                owned.push((102, identifier(self.policy, self.slot, role, purpose)?));
            }
        }
        Ok(owned)
    }
    pub fn acceptance_payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("HyperNetAdmissionAcceptance".into()),
            b(&n),
            b(&i),
            reference(&self.reference),
            self.payload(),
        ]))
    }
    pub fn verify_acceptance(&self, n: Digest, i: Digest, acceptances: &[Vec<u8>]) -> Result<()> {
        ensure!(
            acceptances.len() == self.roles.len(),
            "admission acceptance role count differs"
        );
        let expected = self.acceptance_payload(n, i)?;
        for (r, signed) in self.roles.iter().zip(acceptances) {
            let (payload, signatures) = wire::envelope(signed, 1)?;
            ensure!(
                payload == expected && signatures.len() == 1 && signatures[0].0 == r.member,
                "admission acceptance signature differs"
            );
        }
        Ok(())
    }
}
