// SPDX-License-Identifier: MIT
// Ordered sealed effects recheck current recipient state, exact consent and durable placement.
use super::*;
use crate::{
    authority_deployment_records::Index,
    authority_governance::Governance,
    authority_membership::{Reservations, current},
    authority_proof::Intent,
};
use domains::{
    Decision, Operation, State,
    page::{self, Evaluation, content},
    sealed_identity as identity, sorted,
};
use std::collections::{BTreeMap, BTreeSet};

fn grant(operation: &Operation) -> Result<&VersionRef> {
    operation
        .grant
        .as_ref()
        .context("sealed operation requires explicit capability")
}
fn snapshot(actual: &Snapshot, expected: &Snapshot, exact: bool) -> Result<()> {
    ensure!(
        actual.epoch == expected.epoch
            && actual.height == expected.height
            && actual.state == expected.state
            && (!exact || actual.references == expected.references),
        "sealed signed snapshot differs"
    );
    Ok(())
}
fn network(c: &mut Evaluation<'_>) -> Result<()> {
    let p = wire::decode(c.governance.record_bytes(100, c.state.network)?)?;
    ensure!(
        p.array(17)?[10]
            .list(2)?
            .iter()
            .any(|v| v.uint().ok() == Some(1)),
        "network does not permit sealed publications"
    );
    c.dependencies.push(
        c.governance
            .versions()
            .into_iter()
            .find(|r| r.kind == 100)
            .context("network policy reference absent")?,
    );
    Ok(())
}
fn policy(c: &mut Evaluation<'_>, reference: &VersionRef) -> Result<ObjectPolicy> {
    let record = c.exact(reference)?;
    let p = ObjectPolicy::parse(&payload(&record)?, c.state.network, c.state.incarnation)?;
    ensure!(
        p.modes.contains(&1) && !p.public_audience && p.disclosure.is_none(),
        "object policy does not permit confidential sealed content"
    );
    network(c)?;
    Ok(p)
}
fn recipient_context(c: &mut Evaluation<'_>, audience: &identity::Audience) -> Result<()> {
    for root in &audience.allowed_roots {
        c.exact(root)?;
        c.dependencies.extend(identity::member_evidence(
            &c.governance,
            c.state.network,
            root.id,
        )?);
        if c.state.records.contains_key(&(158, root.digest)) {
            c.select(158, root.digest)?;
        }
        let bindings = c
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 108)
            .filter_map(|r| {
                identity::Binding::parse(
                    &identity::payload(r).ok()?,
                    c.state.network,
                    c.state.incarnation,
                )
                .ok()
                .filter(|b| b.root == *root)
                .map(|_| r.reference.clone())
            })
            .collect::<Vec<_>>();
        for binding in bindings {
            c.exact(&binding)?;
            if c.state.records.contains_key(&(158, binding.digest)) {
                c.select(158, binding.digest)?;
            }
            if c.state.records.contains_key(&(109, binding.digest)) {
                let r = c.select(109, binding.digest)?;
                if c.state.records.contains_key(&(158, r.reference.digest)) {
                    c.select(158, r.reference.digest)?;
                }
            }
        }
    }
    Ok(())
}
fn object_context(c: &mut Evaluation<'_>, object: Digest) -> Result<ObjectPolicy> {
    let r = c.select(104, object)?;
    let p = ObjectPolicy::parse(&payload(&r)?, c.state.network, c.state.incarnation)?;
    let ar = c.exact(&p.audience)?;
    let audience = identity::Audience::parse(
        &identity::payload(&ar)?,
        c.state.network,
        c.state.incarnation,
    )?;
    ensure!(
        audience.publisher == p.publisher,
        "sealed audience owner differs"
    );
    recipient_context(c, &audience)?;
    if c.state.records.contains_key(&(164, p.namespace)) {
        c.select(164, p.namespace)?;
    }
    for host in &p.placement.hosts {
        let r = c.select(147, *host)?;
        let h = c.host(&r.reference, None, true)?;
        ensure!(
            h.profile
                .namespaces
                .iter()
                .any(|n| page::namespace_id(n).ok() == Some(p.namespace)),
            "sealed host namespace differs"
        );
    }
    Ok(p)
}
fn roster(c: &mut Evaluation<'_>, o: &Outer, p: &ObjectPolicy) -> Result<()> {
    let ar = c.exact(&o.audience)?;
    let audience = identity::Audience::parse(
        &identity::payload(&ar)?,
        c.state.network,
        c.state.incarnation,
    )?;
    ensure!(
        audience.publisher == p.publisher && p.audience == o.audience && !audience.public_audience,
        "sealed author audience changed"
    );
    recipient_context(c, &audience)?;
    let rr = c.select(111, o.publication)?;
    let r = identity::Roster::parse(
        &identity::payload(&rr)?,
        c.state.network,
        c.state.incarnation,
    )?;
    identity::signer(&rr, o.reviewer)?;
    ensure!(
        r.reference.digest == o.roster
            && r.publication == o.publication
            && r.audience == o.audience
            && r.revision == o.revision
            && r.encryption_generation == o.encryption_generation,
        "sealed frozen roster differs"
    );
    let selection = identity::roster(c.state, &c.governance, &audience, c.at, (2, o.object))?;
    c.dependencies.extend(selection.dependencies);
    c.expires = c.expires.min(selection.expires_ms);
    let (roots, devices) = (selection.roots, selection.devices);
    ensure!(
        r.roots == roots && r.devices == devices,
        "sealed roster changed after finalisation"
    );
    for root in &audience.allowed_roots {
        c.exact(root)?;
    }
    for (_, binding, admission) in &devices {
        let br = c
            .state
            .records
            .values()
            .find(|r| r.reference.kind == 108 && r.reference.digest == *binding)
            .context("sealed binding absent")?
            .reference
            .clone();
        c.exact(&br)?;
        let ar = c.select(109, *binding)?;
        ensure!(
            ar.reference.digest == *admission,
            "sealed admission changed"
        );
        let b = identity::Binding::parse(
            &identity::payload(c.state.record(br.kind, br.id)?)?,
            c.state.network,
            c.state.incarnation,
        )?;
        let a = identity::Admission::parse(
            &identity::payload(&ar)?,
            c.state.network,
            c.state.incarnation,
        )?;
        c.expires = c.expires.min(b.validity.1).min(a.validity.1);
    }
    Ok(())
}
fn hosts(
    c: &mut Evaluation<'_>,
    o: &Outer,
    p: &ObjectPolicy,
    namespace: &str,
) -> Result<(Vec<VersionRef>, BTreeSet<Digest>)> {
    ensure!(
        o.placement.within(&p.placement),
        "sealed placement exceeds author restriction"
    );
    for destination in &o.placement.backups {
        domains::backup::sealed_destination(c, *destination, o.reviewer)?;
    }
    let mut refs = Vec::new();
    let mut consents = Vec::new();
    let mut domains = BTreeSet::new();
    for host in &o.placement.hosts {
        let r = c.select(147, *host)?;
        let h = c.host(&r.reference, Some(namespace), true)?;
        let cp = h
            .profile
            .content
            .as_ref()
            .context("sealed host has no durable partition")?;
        ensure!(
            cp.opaque
                && cp.reviewers.contains(&o.reviewer)
                && o.bytes <= h.profile.maximum_asset_bytes
                && o.placement.volumes.contains(&h.profile.volume),
            "sealed host did not consent to this reviewer, extent or volume"
        );
        consents.push(wire::digest(&h.profile.envelope));
        domains.insert(cp.failure_domain);
        refs.push(r.reference);
    }
    refs.sort_by_key(VersionRef::index);
    consents.sort();
    ensure!(consents == o.opaque_consents, "sealed host consent changed");
    Ok((refs, domains))
}
pub(crate) fn live(
    c: &mut Evaluation<'_>,
    reference: &VersionRef,
) -> Result<(Outer, PublicationState, ObjectPolicy)> {
    let r = c.exact(reference)?;
    let o = Outer::parse(&r.bytes, c.state.network, c.state.incarnation)?;
    let s = c.select(PUBLICATION_STATE, o.publication)?;
    let s = PublicationState::parse(&s.payload)?;
    let h = c.select(OBJECT_HEAD, o.object)?;
    let h = Head::parse(&h.payload)?;
    ensure!(
        s.outer == *reference
            && s.status < 2
            && (h.pending.as_ref() == Some(reference) || h.published.as_ref() == Some(reference)),
        "sealed publication is withdrawn or superseded"
    );
    let p = policy(c, &s.policy)?;
    domains::publication_modes::permitted(c, &s.namespace, Some(o.object), 1)?;
    ensure!(
        p.object == o.object && page::namespace_id(&s.namespace)? == p.namespace,
        "sealed publication policy scope changed"
    );
    c.capability(
        &s.author_grant,
        p.publisher,
        &[2, 4],
        (2, o.object),
        Some(&s.namespace),
        o.bytes,
    )?;
    c.capability(
        &s.reviewer_grant,
        o.reviewer,
        &[29, 30],
        (2, o.object),
        Some(&s.namespace),
        o.bytes,
    )?;
    roster(c, &o, &p)?;
    Ok((o, s, p))
}
fn reader(
    c: &mut Evaluation<'_>,
    o: &Outer,
    s: &PublicationState,
    requester: Key,
    grant: &VersionRef,
    device: Option<&VersionRef>,
) -> Result<()> {
    ensure!(
        s.status == 1,
        "sealed publication has not committed serving authority"
    );
    let r = if let Some(device) = device {
        c.exact(device)?
    } else {
        let r = c
            .state
            .records
            .values()
            .filter(|r| r.reference.kind == 108)
            .find(|r| {
                identity::Binding::parse(
                    &identity::payload(r).unwrap_or_default(),
                    c.state.network,
                    c.state.incarnation,
                )
                .is_ok_and(|d| d.signing_key == requester)
            })
            .context("sealed reader device absent")?
            .reference
            .clone();
        c.exact(&r)?
    };
    let d = identity::Binding::parse(
        &identity::payload(&r)?,
        c.state.network,
        c.state.incarnation,
    )?;
    ensure!(
        d.signing_key == requester
            && current(c.at, d.validity)
            && !identity::revoked(c.state, &r.reference),
        "sealed reader does not own a current device"
    );
    let rr = c.select(111, o.publication)?;
    let roster = identity::Roster::parse(
        &identity::payload(&rr)?,
        c.state.network,
        c.state.incarnation,
    )?;
    let admission = c.select(109, r.reference.digest)?;
    ensure!(
        roster.devices.contains(&(
            d.root.digest,
            d.reference.digest,
            admission.reference.digest
        )),
        "sealed reader is not in the approved roster"
    );
    // The device proves possession while its member's explicit capability controls reading.
    let member_key = if let Ok(bytes) = c.governance.record_bytes(125, d.member) {
        let v = wire::decode(bytes)?;
        let f = v.array(12)?;
        let validity = f[8].array(2)?;
        let lifetime = (validity[0].uint()?, validity[1].uint()?);
        ensure!(
            !f[9].boolean()? && current(c.at, lifetime),
            "sealed reader member is revoked or expired"
        );
        c.dependencies.push(
            c.governance
                .versions()
                .into_iter()
                .find(|r| r.kind == 125 && r.id == d.member)
                .context("sealed member reference absent")?,
        );
        c.expires = c.expires.min(lifetime.1);
        key(&f[7])?
    } else {
        d.member
    };
    c.capability(
        grant,
        member_key,
        &[0],
        (2, o.object),
        Some(&s.namespace),
        o.bytes,
    )?;
    Ok(())
}
pub(crate) fn local_search(
    c: &mut Evaluation<'_>,
    outer: &VersionRef,
    device: &VersionRef,
    requester: Key,
    grant: &VersionRef,
) -> Result<()> {
    let (o, s, _) = live(c, outer)?;
    reader(c, &o, &s, requester, grant, Some(device))?;
    let bytes = c.governance.record_bytes(102, grant.id)?;
    let v = wire::decode(bytes)?;
    let subject = v.array(17)?[8].fixed()?;
    c.capability(
        grant,
        subject,
        &[0, 1],
        (2, o.object),
        Some(&s.namespace),
        o.bytes,
    )?;
    c.exact(&s.placement)?;
    Ok(())
}
pub(crate) fn content_access(
    c: &mut Evaluation<'_>,
    p: &content::Placement,
    effect: content::Effect,
    requester: Key,
    grant: &VersionRef,
) -> Result<()> {
    let (o, s, policy) = live(c, &p.revision)?;
    ensure!(
        s.placement.id == p.identity()?
            && p.owner == policy.publisher
            && p.digest == o.ciphertext
            && p.bytes == o.bytes
            && p.opaque
            && p.namespace == s.namespace,
        "sealed content placement differs"
    );
    match effect {
        content::Effect::Upload | content::Effect::Inspect => {
            ensure!(
                s.status == 0 && requester == o.reviewer && *grant == s.reviewer_grant,
                "sealed staging requires its trusted finaliser"
            );
        }
        content::Effect::Repair => {
            ensure!(
                s.status == 1
                    && ((requester == o.reviewer && *grant == s.reviewer_grant)
                        || requester == policy.publisher),
                "sealed repair requires its trusted finaliser or owning publisher"
            );
            if requester == policy.publisher {
                c.capability(
                    grant,
                    requester,
                    &[2],
                    (2, o.object),
                    Some(&s.namespace),
                    o.bytes,
                )?;
            }
        }
        content::Effect::Read if requester == policy.publisher => {
            ensure!(
                s.status == 1,
                "publisher ciphertext access requires current publication"
            );
            c.capability(
                grant,
                requester,
                &[2],
                (2, o.object),
                Some(&s.namespace),
                o.bytes,
            )?;
        }
        content::Effect::Read => reader(c, &o, &s, requester, grant, None)?,
        content::Effect::Purge => anyhow::bail!("sealed purge requires exact tombstone"),
        content::Effect::Search => anyhow::bail!("sealed bodies cannot enter server search"),
    }
    Ok(())
}
fn insert(next: &mut State, r: Record, replay: bool) -> Result<()> {
    if replay {
        ensure!(
            next.record(r.reference.kind, r.reference.id)?.bytes == r.bytes,
            "sealed replay differs"
        );
    } else {
        next.put(r)?;
    }
    Ok(())
}
fn save(next: &mut State, kind: u64, id: Digest, value: V, replay: bool) -> Result<()> {
    if replay {
        ensure!(
            next.record(kind, id)?.payload == value,
            "sealed state replay differs"
        );
        Ok(())
    } else {
        let r = Record::next(next, kind, id, value)?;
        next.put(r)
    }
}
fn withdraw(
    c: &mut Evaluation<'_>,
    next: &mut State,
    outer: &VersionRef,
    replay: bool,
) -> Result<()> {
    let r = c.select(PUBLICATION_STATE, outer.id)?;
    let mut s = PublicationState::parse(&r.payload)?;
    s.status = 2;
    let r = c.exact(&s.placement)?;
    save(next, PUBLICATION_STATE, outer.id, s.value(), replay)?;
    if !next
        .records
        .contains_key(&(content::TOMBSTONE_KIND, r.reference.id))
    {
        ensure!(!replay, "sealed replay lacks tombstone");
        save(
            next,
            content::TOMBSTONE_KIND,
            r.reference.id,
            content::Tombstone {
                placement: r.reference,
                withdrawn_ms: c.at,
            }
            .value(),
            false,
        )?;
    } else {
        let tombstone = c.select(content::TOMBSTONE_KIND, r.reference.id)?;
        ensure!(
            content::Tombstone::parse(&tombstone.payload)?.placement == r.reference,
            "sealed tombstone names another placement"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    operation: &Operation,
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
    let outcome = (|| -> Result<()> {
        match command {
            Command::Prepare {
                object,
                roster: roster_ref,
                author_grant,
                namespace,
            } => {
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[29, 30],
                    (2, *object),
                    Some(namespace),
                    0,
                )?;
                let p = object_context(&mut c, *object)?;
                for destination in &p.placement.backups {
                    domains::backup::sealed_destination(&mut c, *destination, intent.requester)?;
                }
                ensure!(
                    p.namespace == page::namespace_id(namespace)?,
                    "sealed preparation namespace differs"
                );
                domains::publication_modes::permitted(&mut c, namespace, Some(*object), 1)?;
                c.capability(
                    author_grant,
                    p.publisher,
                    &[2, 4],
                    (2, *object),
                    Some(namespace),
                    0,
                )?;
                let r = c.exact(roster_ref)?;
                identity::signer(&r, intent.requester)?;
                let r = identity::Roster::parse(
                    &identity::payload(&r)?,
                    state.network,
                    state.incarnation,
                )?;
                let ar = c.exact(&p.audience)?;
                let a = identity::Audience::parse(
                    &identity::payload(&ar)?,
                    state.network,
                    state.incarnation,
                )?;
                let selection = identity::roster(state, &c.governance, &a, at, (2, *object))?;
                c.dependencies.extend(selection.dependencies);
                c.expires = c.expires.min(selection.expires_ms);
                let (roots, devices) = (selection.roots, selection.devices);
                ensure!(
                    r.audience == p.audience && r.roots == roots && r.devices == devices,
                    "sealed preparation roster changed"
                );
                if state.records.contains_key(&(OBJECT_HEAD, *object)) {
                    let head = c.select(OBJECT_HEAD, *object)?;
                    if let Some(previous) = Head::parse(&head.payload)?.published {
                        c.exact(&previous)?;
                        c.select(PUBLICATION_STATE, previous.id)?;
                    }
                }
            }
            Command::Namespace { namespace, modes } => domains::publication_modes::update(
                &mut c,
                &mut next,
                namespace,
                modes,
                intent.requester,
                grant(operation)?,
                replay,
            )?,
            Command::Policy { policy: record } => {
                let p = ObjectPolicy::parse(&payload(record)?, state.network, state.incarnation)?;
                ensure!(
                    p.publisher == intent.requester
                        && p.modes.contains(&1)
                        && !p.public_audience
                        && p.disclosure.is_none(),
                    "sealed policy author or mode differs"
                );
                network(&mut c)?;
                c.capability(
                    grant(operation)?,
                    p.publisher,
                    &[2, 4],
                    (2, p.object),
                    None,
                    0,
                )?;
                let ar = c.exact(&p.audience)?;
                let audience = identity::Audience::parse(
                    &identity::payload(&ar)?,
                    state.network,
                    state.incarnation,
                )?;
                ensure!(
                    audience.publisher == p.publisher && !audience.public_audience,
                    "object policy audience is not owned by publisher"
                );
                snapshot(&p.snapshot, &operation.snapshot, exact || replay)?;
                ensure!(
                    p.minimum_state == (p.snapshot.epoch, p.snapshot.height, p.snapshot.state),
                    "object policy minimum state differs"
                );
                if let Some(old) = state.records.get(&record.reference.index()) {
                    c.select(104, p.object)?;
                    let old =
                        ObjectPolicy::parse(&payload(old)?, state.network, state.incarnation)?;
                    ensure!(
                        old.publisher == p.publisher && old.namespace == p.namespace,
                        "object owner or namespace changed"
                    );
                    ensure!(
                        replay || !p.modes.contains(&0) || old.modes.contains(&0),
                        "sealed disclosure requires a separate exact reviewed publication"
                    );
                }
                insert(&mut next, record.clone(), replay)?;
            }
            Command::Stage {
                outer: record,
                policy: reference,
                author_grant,
                namespace,
                failure_domains,
                expires_ms,
            } => {
                let o = Outer::parse(&record.bytes, state.network, state.incarnation)?;
                let p = policy(&mut c, reference)?;
                domains::publication_modes::permitted(&mut c, namespace, Some(o.object), 1)?;
                ensure!(
                    o.reviewer == intent.requester
                        && p.object == o.object
                        && p.namespace == page::namespace_id(namespace)?,
                    "sealed finaliser or object scope differs"
                );
                snapshot(&o.snapshot, &operation.snapshot, exact || replay)?;
                ensure!(
                    o.minimum_state == (o.snapshot.epoch, o.snapshot.height, o.snapshot.state),
                    "sealed prior policy state differs"
                );
                c.capability(
                    author_grant,
                    p.publisher,
                    &[2, 4],
                    (2, o.object),
                    Some(namespace),
                    o.bytes,
                )?;
                c.capability(
                    grant(operation)?,
                    o.reviewer,
                    &[29, 30],
                    (2, o.object),
                    Some(namespace),
                    o.bytes,
                )?;
                roster(&mut c, &o, &p)?;
                let (hosts, domains) = hosts(&mut c, &o, &p, namespace)?;
                ensure!(
                    *failure_domains > 0
                        && *failure_domains <= o.placement.copies
                        && *failure_domains <= domains.len() as u64
                        && *expires_ms > at.saturating_add(1250)
                        && *expires_ms <= c.expires,
                    "sealed placement lifetime or failure domains differ"
                );
                let mut h = if let Some(r) = state.records.get(&(OBJECT_HEAD, o.object)) {
                    c.select(OBJECT_HEAD, o.object)?;
                    Head::parse(&r.payload)?
                } else {
                    Head {
                        object: o.object,
                        revision: o.revision,
                        encryption_generation: 0,
                        pending: None,
                        published: None,
                    }
                };
                if !replay {
                    ensure!(
                        o.revision >= h.revision
                            && o.encryption_generation > h.encryption_generation
                            && !state.records.contains_key(&record.reference.index()),
                        "sealed revision or encryption generation reused"
                    );
                }
                if let Some(old) = &h.published {
                    let previous =
                        Outer::parse(&c.exact(old)?.bytes, state.network, state.incarnation)?;
                    ensure!(
                        o.revision > previous.revision,
                        "sealed publication revision did not advance"
                    );
                }
                let placement = content::Placement {
                    revision: o.reference.clone(),
                    owner: p.publisher,
                    grant: author_grant.clone(),
                    namespace: namespace.clone(),
                    digest: o.ciphertext,
                    bytes: o.bytes,
                    opaque: true,
                    hosts,
                    copies: o.placement.copies,
                    failure_domains: *failure_domains,
                    expires_ms: *expires_ms,
                };
                for host in &placement.hosts {
                    let h = c.host(host, Some(namespace), true)?;
                    let cp = h
                        .profile
                        .content
                        .as_ref()
                        .context("sealed durable consent absent")?;
                    ensure!(
                        *expires_ms <= at.saturating_add(h.profile.retention_ms),
                        "sealed retention exceeds host consent"
                    );
                    let used = state
                        .records
                        .values()
                        .filter(|r| {
                            r.reference.kind == 159
                                && !state.records.contains_key(&(161, r.reference.id))
                                && (!replay
                                    || r.reference.id != placement.identity().unwrap_or([0; 32]))
                        })
                        .map(|r| content::Placement::parse(&r.payload))
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .filter(|p| p.expires_ms > at && p.hosts.iter().any(|r| r.id == host.id))
                        .try_fold(0u64, |sum, p| {
                            sum.checked_add(p.bytes).context("sealed capacity overflow")
                        })?;
                    ensure!(
                        used.checked_add(o.bytes)
                            .is_some_and(|n| n <= cp.data_bytes),
                        "sealed host capacity reached"
                    );
                }
                let placement_id = placement.identity()?;
                save(&mut next, 159, placement_id, placement.value(), replay)?;
                let s = PublicationState {
                    outer: o.reference.clone(),
                    policy: reference.clone(),
                    author_grant: author_grant.clone(),
                    reviewer_grant: grant(operation)?.clone(),
                    namespace: namespace.clone(),
                    placement: next.record(159, placement_id)?.reference.clone(),
                    status: 0,
                    supersedes: h.published.clone(),
                };
                save(
                    &mut next,
                    PUBLICATION_STATE,
                    o.publication,
                    s.value(),
                    replay,
                )?;
                h.revision = o.revision;
                h.encryption_generation = o.encryption_generation;
                h.pending = Some(o.reference.clone());
                save(&mut next, OBJECT_HEAD, o.object, h.value(), replay)?;
                insert(&mut next, record.clone(), replay)?;
            }
            Command::Commit { outer } => {
                let (o, mut s, policy) = live(&mut c, outer)?;
                hosts(&mut c, &o, &policy, &s.namespace)?;
                ensure!(
                    intent.requester == o.reviewer
                        && *grant(operation)? == s.reviewer_grant
                        && (s.status == 0 || replay && s.status == 1),
                    "sealed commit finaliser differs"
                );
                let pr = c.exact(&s.placement)?;
                let p = content::Placement::parse(&pr.payload)?;
                ensure!(
                    p.expires_ms > at.saturating_add(1250)
                        && !state.records.contains_key(&(161, pr.reference.id)),
                    "sealed placement expired or withdrawn"
                );
                c.expires = c.expires.min(p.expires_ms);
                let copies = c.select(160, pr.reference.id)?;
                let copies =
                    content::Copies::parse(&copies.payload, state.network, state.incarnation)?;
                ensure!(
                    copies.placement == s.placement,
                    "sealed copy evidence selects another placement"
                );
                let mut count = 0;
                let mut domains = BTreeSet::new();
                for copy in copies.copies {
                    if let Some(h) = c.optional(|c| c.host(&copy.host, Some(&s.namespace), true)) {
                        ensure!(
                            p.hosts.contains(&copy.host)
                                && copy.digest == o.ciphertext
                                && copy.bytes == o.bytes,
                            "sealed copy evidence differs"
                        );
                        if copy.expires_ms > at.saturating_add(1250) {
                            count += 1;
                            domains.insert(
                                h.profile
                                    .content
                                    .as_ref()
                                    .context("sealed copy consent absent")?
                                    .failure_domain,
                            );
                            c.expires = c.expires.min(copy.expires_ms);
                        }
                    }
                }
                ensure!(
                    count >= p.copies && domains.len() as u64 >= p.failure_domains,
                    "sealed publication lacks required durable copies"
                );
                let hr = c.select(OBJECT_HEAD, o.object)?;
                let mut h = Head::parse(&hr.payload)?;
                if !replay {
                    ensure!(
                        h.pending.as_ref() == Some(outer),
                        "sealed finalisation has been superseded"
                    );
                    ensure!(
                        h.published == s.supersedes,
                        "sealed replacement no longer names the current publication"
                    );
                }
                if let Some(old) = &s.supersedes {
                    withdraw(&mut c, &mut next, old, replay)?;
                }
                s.status = 1;
                h.pending = None;
                h.published = Some(outer.clone());
                save(
                    &mut next,
                    PUBLICATION_STATE,
                    o.publication,
                    s.value(),
                    replay,
                )?;
                save(&mut next, OBJECT_HEAD, o.object, h.value(), replay)?;
            }
            Command::Read { outer, device } => {
                let (o, s, _) = live(&mut c, outer)?;
                reader(
                    &mut c,
                    &o,
                    &s,
                    intent.requester,
                    grant(operation)?,
                    Some(device),
                )?;
                c.exact(&s.placement)?;
                if state.records.contains_key(&(160, s.placement.id)) {
                    c.select(160, s.placement.id)?;
                }
            }
            Command::ReaderContext { object, device } => {
                let r = c.select(OBJECT_HEAD, *object)?;
                let h = Head::parse(&r.payload)?;
                let published = h
                    .published
                    .context("sealed object has no current publication")?;
                let (o, s, _) = live(&mut c, &published)?;
                reader(
                    &mut c,
                    &o,
                    &s,
                    intent.requester,
                    grant(operation)?,
                    Some(device),
                )?;
                c.exact(&s.placement)?;
                if state.records.contains_key(&(160, s.placement.id)) {
                    c.select(160, s.placement.id)?;
                }
            }
            Command::Context { object } => {
                if c.optional(|c| {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[29, 30],
                        (2, *object),
                        None,
                        0,
                    )
                })
                .is_none()
                {
                    c.capability(
                        grant(operation)?,
                        intent.requester,
                        &[4],
                        (2, *object),
                        None,
                        0,
                    )?;
                }
                if state.records.contains_key(&(104, *object)) {
                    object_context(&mut c, *object)?;
                }
                if state.records.contains_key(&(OBJECT_HEAD, *object)) {
                    let r = c.select(OBJECT_HEAD, *object)?;
                    let h = Head::parse(&r.payload)?;
                    for r in h.pending.iter().chain(h.published.iter()) {
                        c.exact(r)?;
                        let r = c.select(PUBLICATION_STATE, r.id)?;
                        let s = PublicationState::parse(&r.payload)?;
                        c.exact(&s.placement)?;
                    }
                }
            }
            Command::Withdraw { outer } => {
                let r = c.exact(outer)?;
                let o = Outer::parse(&r.bytes, state.network, state.incarnation)?;
                let p = c.select(104, o.object)?;
                let p = ObjectPolicy::parse(&payload(&p)?, state.network, state.incarnation)?;
                ensure!(
                    p.publisher == intent.requester,
                    "sealed withdrawal requires owner"
                );
                c.capability(
                    grant(operation)?,
                    intent.requester,
                    &[2],
                    (2, o.object),
                    None,
                    0,
                )?;
                withdraw(&mut c, &mut next, outer, replay)?;
                let r = c.select(OBJECT_HEAD, o.object)?;
                let mut h = Head::parse(&r.payload)?;
                if h.pending.as_ref() == Some(outer) {
                    h.pending = None;
                }
                if h.published.as_ref() == Some(outer) {
                    h.published = None;
                }
                save(&mut next, OBJECT_HEAD, o.object, h.value(), replay)?;
            }
        }
        Ok(())
    })();
    if outcome.is_err() {
        return Ok(Decision::refused(3));
    }
    if sorted(&mut c.dependencies).is_err() {
        return Ok(Decision::refused(2));
    }
    if command.mutation() && !replay && exact && c.dependencies != intent.expected {
        return Ok(Decision::refused(12));
    }
    let indices = command.mutation_indices(state)?;
    for index in indices {
        if let Some(r) = next.records.get(&index) {
            c.selected.insert(index, r.clone());
        }
    }
    let governance = c
        .dependencies
        .iter()
        .filter(|r| !c.selected.contains_key(&r.index()))
        .map(|r| Ok(c.governance.record_bytes(r.kind, r.id)?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let mut versions = c
        .dependencies
        .iter()
        .filter(|r| !c.selected.contains_key(&r.index()))
        .cloned()
        .collect::<Vec<_>>();
    versions.extend(c.selected.values().map(|r| r.reference.clone()));
    if sorted(&mut versions).is_err() {
        return Ok(Decision::refused(2));
    }
    next.charge()?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(c.selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance.iter().map(|v| b(v)).collect()),
            V::Null,
        ]),
    ]);
    if wire::encode(&value).is_err() {
        return Ok(Decision::refused(2));
    }
    Ok(Decision {
        state: (command.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies: c.dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
