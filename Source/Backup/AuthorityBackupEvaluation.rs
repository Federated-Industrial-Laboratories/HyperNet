// SPDX-License-Identifier: MIT
// Archive placement and restore recheck current owner policy without reviving archived authority.
use super::*;
use crate::{
    authority_deployment_records::Index, authority_governance::Governance,
    authority_membership::current,
};
use page::{Evaluation, content};
fn grant(op: &Operation) -> Result<&VersionRef> {
    op.grant
        .as_ref()
        .context("backup operation requires a capability")
}
fn profile(c: &mut Evaluation<'_>, p: &Profile) -> Result<()> {
    let r = c
        .index
        .deployments
        .get(&p.manifest.deployment)
        .context("backup deployment absent")?
        .clone();
    r.manifest.permits_definition(&p.manifest)?;
    ensure!(
        r.manifest.host == p.manifest.host
            && r.operator == p.manifest.operator
            && current(c.at, r.manifest.validity)
            && !c.index.withdrawals.contains_key(&p.manifest.deployment)
            && c.governance.record_bytes(117, p.manifest.deployment)? == r.manifest.desired()?
            && c.governance.record_bytes(105, p.manifest.deployment)?
                == r.manifest.unsigned_consent(0)?,
        "backup deployment is expired, withdrawn or changed"
    );
    c.dependencies.extend([r.reference, r.profile, r.consent]);
    c.expires = c.expires.min(r.manifest.validity.1);
    c.capability(
        &r.grant,
        r.registrar,
        &[13],
        (5, p.manifest.deployment),
        None,
        0,
    )
}
fn destination(c: &mut Evaluation<'_>, r: &VersionRef, live: bool) -> Result<Destination> {
    let record = c.exact(r)?;
    let d = Destination::parse(&record.payload, c.state.network, c.state.incarnation)?;
    if live {
        ensure!(!d.withdrawn, "backup destination withdrawn");
        profile(c, &d.profile)?;
        c.capability(&d.grant, d.manager, &[5], (3, d.profile.id), None, 0)?;
    }
    Ok(d)
}
pub(crate) fn sealed_destination(c: &mut Evaluation<'_>, id: Digest, reviewer: Key) -> Result<()> {
    let r = c.select(DESTINATION, id)?;
    let d = destination(c, &r.reference, true)?;
    ensure!(
        d.profile.opaque
            && d.profile
                .manifest
                .consent_policy
                .reviewer_roots
                .contains(&reviewer),
        "backup destination did not consent to opaque content from this reviewer"
    );
    Ok(())
}
fn source(
    c: &mut Evaluation<'_>,
    placement: &VersionRef,
    destination_ref: &VersionRef,
    requester: Key,
    grant: &VersionRef,
) -> Result<Vec<VersionRef>> {
    let p = content::live(c, placement)?;
    let d = destination(c, destination_ref, true)?;
    ensure!(
        p.owner == requester && d.profile.owners.contains(&requester),
        "backup requires the content owner and destination acceptance"
    );
    let mut assets = vec![];
    if p.opaque {
        let (outer, _, policy) = sealed_publication::live(c, &p.revision)?;
        ensure!(
            d.profile.opaque
                && outer.placement.backups.contains(&destination_ref.id)
                && policy.placement.backups.contains(&destination_ref.id),
            "sealed backup destination is outside exact owner and outer placement"
        );
        sealed_destination(c, destination_ref.id, outer.reviewer)?;
        c.capability(
            grant,
            requester,
            &[2],
            (2, outer.object),
            Some(&p.namespace),
            0,
        )?;
    } else {
        let revision = c.revision(&p.revision, true)?;
        let (_, ledger, _, _) = c.publication(revision.author.raw_page)?;
        ensure!(
            ledger
                .published
                .as_ref()
                .is_some_and(|r| r.id == p.revision.id),
            "backup content is not currently published"
        );
        c.capability(
            grant,
            requester,
            &[2],
            (2, revision.author.intent.resource),
            Some(&p.namespace),
            0,
        )?;
        c.media_metadata(&p.revision, &revision)?;
        let records = c
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 144)
            .cloned()
            .collect::<Vec<_>>();
        for r in records {
            let asset = page::Asset::parse(&r.payload)?;
            if asset.revision == p.revision {
                c.exact(&r.reference)?;
                assets.push(r.reference.clone());
            }
        }
        assets.sort_by_key(VersionRef::index);
        ensure!(
            assets.len() == revision.assets.len(),
            "backup must include every associated canonical media asset"
        );
    }
    Ok(assets)
}
fn archived(c: &mut Evaluation<'_>, id: Digest, owner: Key) -> Result<(Record, Archive)> {
    let r = c.select(ARCHIVE, id)?;
    let p = Archive::parse(r.payload.bytes()?, c.state.network, c.state.incarnation)?;
    ensure!(p.owner == owner, "backup belongs to another owner");
    if c.state.records.contains_key(&(TOMBSTONE, id)) {
        c.select(TOMBSTONE, id)?;
    }
    let dr = c.select(DESTINATION, p.destination.id)?;
    destination(c, &dr.reference, false)?;
    Ok((r, p))
}
fn put(
    c: &mut Evaluation<'_>,
    next: &mut State,
    kind: u64,
    id: Digest,
    payload: V,
    replay: bool,
) -> Result<()> {
    if replay {
        let r = c.select(kind, id)?;
        ensure!(r.payload == payload, "backup mutation replay differs");
    } else {
        let r = Record::next(next, kind, id, payload)?;
        next.put(r.clone())?;
        c.selected.insert(r.reference.index(), r);
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    op: &Operation,
    command: &Command,
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
    exact: bool,
) -> Result<Decision> {
    let mut c = Evaluation {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        index: Index::parse(records, reserved, state.network, state.incarnation)?,
        at,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    let mut next = state.clone();
    let mut continuation = None;
    let outcome = (|| -> Result<()> {
        ensure!(
            c.governance.record_bytes(127, intent.requester).is_err(),
            "backup management requires its owning principal"
        );
        match command {
            Command::InspectConsent { profile: p } => {
                profile(&mut c, p)?;
                c.capability(grant(op)?, intent.requester, &[5], (3, p.id), None, 0)?;
            }
            Command::Register { profile: p } => {
                profile(&mut c, p)?;
                c.capability(grant(op)?, intent.requester, &[5], (3, p.id), None, 0)?;
                if !replay {
                    ensure!(
                        !state.records.contains_key(&(DESTINATION, p.id)),
                        "backup destination cannot be replaced"
                    );
                }
                let total = state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == DESTINATION)
                    .map(|r| Destination::parse(&r.payload, state.network, state.incarnation))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|d| {
                        d.profile.id != p.id
                            && d.profile.manifest.host == p.manifest.host
                            && d.profile.volume == p.volume
                    })
                    .try_fold(p.bytes, |sum, d| {
                        sum.checked_add(d.profile.bytes)
                            .context("backup capacity overflow")
                    })?;
                let v = p
                    .manifest
                    .volumes
                    .iter()
                    .find(|v| v.volume_id == p.volume)
                    .unwrap();
                let role = p
                    .manifest
                    .roles
                    .iter()
                    .filter(|r| r.volume_ids.contains(&p.volume))
                    .map(|r| r.state_admission_bytes)
                    .sum::<u64>();
                ensure!(
                    total <= v.storage_admission_bytes - role,
                    "backup destinations exceed their shared volume surplus"
                );
                put(
                    &mut c,
                    &mut next,
                    DESTINATION,
                    p.id,
                    Destination {
                        profile: p.clone(),
                        manager: intent.requester,
                        grant: grant(op)?.clone(),
                        withdrawn: false,
                    }
                    .value(),
                    replay,
                )?;
            }
            Command::Destination { destination: id } => {
                let r = c.select(DESTINATION, *id)?;
                let d = destination(&mut c, &r.reference, false)?;
                ensure!(
                    d.profile.owners.contains(&intent.requester) || d.manager == intent.requester,
                    "backup destination is not shared with this principal"
                );
            }
            Command::Destinations { after } => {
                for r in state.records.values().filter(|r| {
                    r.reference.kind == DESTINATION && after.is_none_or(|a| r.reference.id > a)
                }) {
                    let d = Destination::parse(&r.payload, state.network, state.incarnation)?;
                    if d.manager != intent.requester
                        && !d.profile.owners.contains(&intent.requester)
                    {
                        continue;
                    }
                    if c.selected.len() >= 8 {
                        continuation = c.selected.values().last().map(|r| r.reference.id);
                        break;
                    }
                    c.select(DESTINATION, r.reference.id)?;
                }
            }
            Command::WithdrawDestination { destination: r } => {
                let actual = if replay {
                    c.select(DESTINATION, r.id)?
                } else {
                    c.exact(r)?
                };
                let mut d = Destination::parse(&actual.payload, state.network, state.incarnation)?;
                ensure!(
                    d.manager == intent.requester && (replay || !d.withdrawn),
                    "backup withdrawal requires its operator"
                );
                if replay {
                    ensure!(
                        actual.predecessor == Some(r.digest)
                            && actual.reference.generation == r.generation + 1,
                        "backup withdrawal predecessor differs"
                    );
                }
                d.withdrawn = true;
                put(&mut c, &mut next, DESTINATION, r.id, d.value(), replay)?;
            }
            Command::Prepare {
                placement,
                destination,
            } => {
                source(&mut c, placement, destination, intent.requester, grant(op)?)?;
            }
            Command::Create { archive: p } => {
                ensure!(p.owner == intent.requester, "backup archive signer differs");
                let assets = source(
                    &mut c,
                    &p.placement,
                    &p.destination,
                    intent.requester,
                    grant(op)?,
                )?;
                let d = destination(&mut c, &p.destination, true)?;
                p.admitted(&d.profile, at)?;
                let placement =
                    content::Placement::parse(&state.record(159, p.placement.id)?.payload)?;
                ensure!(
                    p.assets == assets && p.opaque == placement.opaque && p.created_ms <= at,
                    "backup source closure or creation time differs"
                );
                if !replay {
                    ensure!(
                        !state.records.contains_key(&(ARCHIVE, p.id)),
                        "backup archive identifier already exists"
                    );
                }
                let mut bytes = p.bytes;
                let mut count = 1u64;
                for r in state
                    .records
                    .values()
                    .filter(|r| r.reference.kind == ARCHIVE && r.reference.id != p.id)
                {
                    let old = Archive::parse(r.payload.bytes()?, state.network, state.incarnation)?;
                    if old.destination.id == p.destination.id && old.expires_ms > at {
                        bytes = bytes
                            .checked_add(old.bytes)
                            .context("backup byte quota overflow")?;
                        count += 1;
                    }
                }
                ensure!(
                    bytes <= d.profile.bytes && count <= d.profile.objects,
                    "backup destination logical quota exhausted"
                );
                put(&mut c, &mut next, ARCHIVE, p.id, b(&p.envelope), replay)?;
            }
            Command::Get { archive: id } => {
                archived(&mut c, *id, intent.requester)?;
            }
            Command::List { after } => {
                let mut last = None;
                for r in state.records.values().filter(|r| {
                    r.reference.kind == ARCHIVE && after.is_none_or(|a| r.reference.id > a)
                }) {
                    let p = Archive::parse(r.payload.bytes()?, state.network, state.incarnation)?;
                    if p.owner != intent.requester {
                        continue;
                    }
                    if c.selected.len() >= 12 {
                        continuation = last;
                        break;
                    }
                    archived(&mut c, r.reference.id, intent.requester)?;
                    last = Some(r.reference.id);
                }
            }
            Command::Restore { archive: r } => {
                let (record, p) = archived(&mut c, r.id, intent.requester)?;
                ensure!(
                    record.reference == *r
                        && p.expires_ms > at
                        && !state.records.contains_key(&(TOMBSTONE, r.id)),
                    "backup archive expired, withdrawn or changed"
                );
                let assets = source(
                    &mut c,
                    &p.placement,
                    &p.destination,
                    intent.requester,
                    grant(op)?,
                )?;
                ensure!(p.assets == assets, "backup asset closure no longer current");
            }
            Command::Withdraw { archive: r } => {
                let (record, _) = archived(&mut c, r.id, intent.requester)?;
                ensure!(record.reference == *r, "backup archive changed");
                let payload = if replay {
                    c.select(TOMBSTONE, r.id)?.payload
                } else {
                    a(vec![reference(r), V::Uint(at)])
                };
                put(&mut c, &mut next, TOMBSTONE, r.id, payload, replay)?;
            }
        }
        Ok(())
    })();
    if outcome.is_err() {
        return Ok(Decision::refused(3));
    }
    sorted(&mut c.dependencies)?;
    if exact
        && !replay
        && ((op.mutation() && intent.expected != c.dependencies)
            || (!op.mutation() && intent.expected.iter().any(|r| !c.dependencies.contains(r))))
    {
        return Ok(Decision::refused(12));
    }
    let mut versions = c
        .dependencies
        .iter()
        .filter(|r| !c.selected.contains_key(&r.index()))
        .cloned()
        .collect::<Vec<_>>();
    versions.extend(c.selected.values().map(|r| r.reference.clone()));
    sorted(&mut versions)?;
    let governance = c
        .dependencies
        .iter()
        .filter(|r| !c.selected.contains_key(&r.index()))
        .map(|r| Ok(b(c.governance.record_bytes(r.kind, r.id)?)))
        .collect::<Result<Vec<_>>>()?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(c.selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance),
            continuation.map_or(V::Null, |v| b(&v)),
        ]),
    ]);
    wire::encode(&value)?;
    next.charge()?;
    Ok(Decision {
        state: command.mutation().then_some(next),
        value,
        versions,
        dependencies: c.dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
