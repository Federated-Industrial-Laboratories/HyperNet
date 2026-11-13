// SPDX-License-Identifier: MIT
// Fresh admission disclosure binds policy purpose, bounded slot selection and exact route material.
use super::*;
use crate::authority_domains;

pub struct Disclosure {
    pub policy: Policy,
    pub selected: Option<Slot>,
    pub claim_floor: u64,
    pub available: Option<u64>,
    pub records: Vec<Vec<u8>>,
    pub domains: Vec<Vec<u8>>,
    pub versions: Vec<VersionRef>,
}
impl Disclosure {
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(201),
            V::Uint(1),
            V::Text("AuthorityAdmissionContext".into()),
            a(self.versions.iter().map(reference).collect()),
            a(vec![
                b(&self.policy.reference.id),
                V::Uint(self.claim_floor),
                self.selected
                    .as_ref()
                    .map_or(V::Null, |s| b(&s.reference.id)),
                a(self.records.iter().map(|r| b(r)).collect()),
                a(self.domains.iter().map(|r| b(r)).collect()),
                self.available.map_or(V::Null, V::Uint),
            ]),
        ])
    }
    pub fn parse(
        v: &V,
        n: Digest,
        i: Digest,
        requester: Key,
        policy: Digest,
        claim: Option<Digest>,
        at: u64,
    ) -> Result<Self> {
        let f = v.array(5)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityAdmissionContext",
            "admission context schema differs"
        );
        let body = f[4].array(6)?;
        let available = if body[5] == V::Null {
            None
        } else {
            Some(body[5].uint()?)
        };
        ensure!(
            id(&body[0])? == policy,
            "admission context has another policy"
        );
        let claim_floor = body[1].uint()?;
        let selected = if body[2] == V::Null {
            None
        } else {
            Some(id(&body[2])?)
        };
        let records = body[3]
            .list(64)?
            .iter()
            .map(|x| Ok(x.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let domains = body[4]
            .list(16)?
            .iter()
            .map(|x| Ok(x.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let g = Governance::parse(n, i, &records)?;
        let p = g
            .admission()
            .policies
            .get(&policy)
            .context("admission policy absent from proof")?
            .clone();
        // Status remains inspectable after withdrawal; usable route results require current authority.
        if !domains.is_empty() {
            p.authorise(&g, n, at)?;
        }
        let selected = selected
            .map(|id| {
                g.admission()
                    .slots
                    .get(&id)
                    .cloned()
                    .context("admission slot absent from proof")
            })
            .transpose()?;
        ensure!(
            available.is_none_or(|s| s < p.maximum_slots)
                && (claim.is_some() || available.is_none()),
            "admission available slot differs"
        );
        if let Some(s) = &selected {
            ensure!(
                available == Some(s.slot) && s.policy == policy && s.ordinal <= claim_floor,
                "admission slot or claim floor differs"
            );
            ensure!(
                requester == p.registrar
                    || requester == p.owner
                    || s.roles.iter().any(|r| r.member == requester),
                "admission slot disclosure belongs to another identity"
            );
            if claim != Some(s.claim) {
                ensure!(
                    requester == p.registrar
                        && (s.state == 3
                            || s.state == 0 && at > s.challenge_until.saturating_add(1250)),
                    "admission selected another live claim"
                );
            }
        }
        let mut versions = Governance::record_versions(n, i, &records)?;
        let mut domain_refs = vec![];
        for bytes in &domains {
            let r = authority_domains::Record::parse(bytes, n, i)?;
            ensure!(
                matches!(r.reference.kind, 147 | 165 | 166),
                "admission disclosure includes unrelated domain data"
            );
            domain_refs.push(r.reference);
        }
        crate::authority_proof::validate_versions(&domain_refs, 16)?;
        versions.extend(domain_refs);
        versions.sort_by_key(VersionRef::index);
        crate::authority_proof::validate_versions(&versions, 64)?;
        ensure!(
            f[3] == a(versions.iter().map(reference).collect()),
            "admission context references differ from exact returned records"
        );
        if let Some(slot) = selected
            .as_ref()
            .filter(|s| s.active() && !domains.is_empty())
        {
            verify_routes(&p, slot, &domains, n, i, at)?;
            verify_page_targets(&p, slot, &domains, &records, n, i, at)?;
        }
        Ok(Self {
            policy: p,
            selected,
            claim_floor,
            available,
            records,
            domains,
            versions,
        })
    }
}
fn verify_routes(
    p: &Policy,
    s: &Slot,
    domains: &[Vec<u8>],
    n: Digest,
    i: Digest,
    at: u64,
) -> Result<()> {
    let records = domains
        .iter()
        .map(|b| authority_domains::Record::parse(b, n, i))
        .collect::<Result<Vec<_>>>()?;
    for role in &s.roles {
        for (purpose, destination) in [(4, p.authority), (5, p.template(role.role)?.destination)] {
            let id = identifier(s.policy, s.slot, role.role, purpose)?;
            let v = records
                .iter()
                .find(|r| r.reference.kind == 166 && r.reference.id == id)
                .context("scoped voucher absent")?;
            let voucher = authority_domains::routes::Voucher::parse(&v.payload)?;
            let relay = records
                .iter()
                .find(|r| r.reference == voucher.relay)
                .context("scoped relay absent")?;
            let target = records
                .iter()
                .find(|r| r.reference == voucher.destination)
                .context("scoped destination absent")?;
            let relay = authority_domains::routes::Service::parse(&relay.payload, n, i)?;
            let target = authority_domains::routes::Service::parse(&target.payload, n, i)?;
            relay.profile.manifest.current_transport(at)?;
            target.profile.manifest.current_transport(at)?;
            let template = p.template(role.role)?;
            ensure!(
                !relay.withdrawn
                    && !target.withdrawn
                    && relay.profile.mode == 1
                    && target.profile.mode != 1
                    && voucher.relay.id == p.relay
                    && voucher.destination.id == destination
                    && voucher.sponsor == role.member
                    && voucher.possession == role.relay
                    && voucher.grant.id == identifier(s.policy, s.slot, role.role, 2)?
                    && voucher.action == 0
                    && voucher.scope == (3, destination)
                    && voucher.connections == template.connections
                    && voucher.bytes == template.bytes
                    && voucher.expires > at.saturating_add(1250),
                "scoped route differs from current member or fixed template"
            );
        }
    }
    Ok(())
}
#[allow(
    clippy::too_many_arguments,
    reason = "The authority read binds independent authenticated context and query inputs."
)]
pub fn disclose(
    records: &[Vec<u8>],
    domains: &authority_domains::State,
    reserved: &crate::authority_membership::Reservations,
    requester: Key,
    policy: Digest,
    claim: Option<Digest>,
    n: Digest,
    i: Digest,
    at: u64,
) -> Result<Disclosure> {
    let g = Governance::parse(n, i, records)?;
    let index = g.admission();
    let p = index
        .policies
        .get(&policy)
        .context("admission policy absent")?
        .clone();
    let mut dependencies = p.authorise(&g, n, at).unwrap_or_default();
    // Retain the parent chain and its terminal state even when current permission
    // is gone. This read is not admission authority, and retirement is intrinsic.
    let mut parent = p.parent.clone();
    for depth in 0..=8 {
        let value = wire::decode(g.record_bytes(102, parent.id)?)?;
        let fields = value.array(17)?;
        dependencies.push(parent.clone());
        dependencies.push(crate::authority_membership::version(&fields[9])?);
        if let Some(revoked) = g
            .versions()
            .into_iter()
            .find(|r| r.kind == 126 && r.id == parent.id)
        {
            dependencies.push(revoked);
        }
        if fields[13] == V::Null {
            break;
        }
        ensure!(depth < 8, "admission parent chain exceeds its bound");
        parent = crate::authority_membership::version(&fields[13])?;
    }
    for r in g
        .versions()
        .into_iter()
        .filter(|r| matches!(r.kind, 125 | 127 | 128))
    {
        let value = wire::decode(g.record_bytes(r.kind, r.id)?)?;
        let fields = value.list(32)?;
        if fields[if r.kind == 125 { 7 } else { 6 }].fixed::<32>().ok() == Some(p.owner) {
            dependencies.push(r);
        }
    }
    dependencies.push(p.reference.clone());
    let mut available = None;
    let selected = if let Some(claim) = claim {
        if let Some(found) = index
            .slots
            .values()
            .find(|s| s.policy == policy && s.claim == claim)
        {
            available = Some(found.slot);
            Some(found.clone())
        } else {
            ensure!(
                requester == p.registrar && claim_ordinal(&claim)? > index.claim_floor(policy),
                "admission claim is retired or belongs to another requester"
            );
            let mut selected = None;
            for slot in 0..p.maximum_slots {
                let id = identifier(policy, slot, 0, 0)?;
                let old = index.slots.get(&id);
                if old.is_none() {
                    available = Some(slot);
                    break;
                }
                if let Some(old) = old.filter(|s| {
                    s.state == 3 || s.state == 0 && at > s.challenge_until.saturating_add(1250)
                }) {
                    available = Some(slot);
                    selected = Some(old.clone());
                    break;
                }
            }
            selected
        }
    } else {
        None
    };
    let mut domain_records = vec![];
    if let Some(s) = &selected {
        ensure!(
            requester == p.registrar
                || requester == p.owner
                || s.roles.iter().any(|r| r.member == requester),
            "admission slot belongs to another identity"
        );
        dependencies.push(s.reference.clone());
        dependencies.extend(Governance::record_versions(n, i, &s.material)?);
        for legacy in &p.legacy {
            let bytes = g.record_bytes(125, legacy.id)?;
            let v = wire::decode(bytes)?;
            let f = v.array(12)?;
            if s.roles
                .iter()
                .any(|r| f[7].fixed::<32>().ok() == Some(r.member))
            {
                dependencies.extend(Governance::record_versions(n, i, &[bytes.to_vec()])?);
            }
        }
        if s.active()
            && let Ok((refs, values)) =
                authority_domains::routes::admission_routes(domains, records, reserved, s, at)
        {
            dependencies.extend(refs);
            domain_records = values;
        }
    }
    let policy_bytes = g.record_bytes(100, n)?;
    let policy_value = wire::decode(policy_bytes)?;
    for (root, _) in crate::authority_governance::policy_roots(policy_value.array(17)?)? {
        let root_bytes = g.record_bytes(102, root)?;
        let value = wire::decode(root_bytes)?;
        dependencies.extend(Governance::record_versions(n, i, &[root_bytes.to_vec()])?);
        dependencies.push(crate::authority_membership::version(&value.array(17)?[9])?);
    }
    dependencies.extend(Governance::record_versions(
        n,
        i,
        &[
            g.record_bytes(100, n)?.to_vec(),
            g.record_bytes(114, n)?.to_vec(),
        ],
    )?);
    dependencies.sort_by_key(VersionRef::index);
    dependencies.dedup();
    let result_records = dependencies
        .iter()
        .filter(|r| r.kind < 132 || matches!(r.kind, 180 | 181))
        .map(
            |r| match selected.as_ref().filter(|slot| slot.reference == *r) {
                Some(slot) => Ok(slot.bytes.clone()),
                None => Ok(g.record_bytes(r.kind, r.id)?.to_vec()),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    let mut versions = Governance::record_versions(n, i, &result_records)?;
    versions.extend(
        domain_records
            .iter()
            .map(|bytes| Ok(authority_domains::Record::parse(bytes, n, i)?.reference))
            .collect::<Result<Vec<_>>>()?,
    );
    versions.sort_by_key(VersionRef::index);
    crate::authority_proof::validate_versions(&versions, 64)?;
    let out = Disclosure {
        policy: p,
        selected,
        claim_floor: index.claim_floor(policy),
        available,
        records: result_records,
        domains: domain_records,
        versions,
    };
    Disclosure::parse(&out.value(), n, i, requester, policy, claim, at)
}

fn verify_page_targets(
    p: &Policy,
    slot: &Slot,
    domains: &[Vec<u8>],
    records: &[Vec<u8>],
    n: Digest,
    i: Digest,
    at: u64,
) -> Result<()> {
    let mut state = authority_domains::State::empty(n, i);
    for bytes in domains {
        state.put(authority_domains::Record::parse(bytes, n, i)?)?;
    }
    for role in &slot.roles {
        let template = p.template(role.role)?;
        if let Some(host) = template.page {
            let target = state.record(165, template.destination)?;
            let target = authority_domains::routes::Service::parse(&target.payload, n, i)?;
            ensure!(
                target.profile.protocol == 2,
                "Admission Page destination protocol differs"
            );
            // These are already quorum-certified registrations, not new key admissions.
            authority_domains::page::admission_host(
                &state,
                records,
                &crate::authority_membership::Reservations(vec![]),
                host,
                at,
            )?;
        }
    }
    Ok(())
}
