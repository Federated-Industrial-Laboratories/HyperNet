// SPDX-License-Identifier: MIT
// Ordered recipient admission rechecks independent ownership, possession and current policy.
use super::*;
use anyhow::Context as _;

#[derive(Debug)]
struct Refusal(u64);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recipient refusal {}", self.0)
    }
}
impl std::error::Error for Refusal {}
fn require(valid: bool, code: u64, detail: &'static str) -> Result<()> {
    if !valid {
        return Err(anyhow::Error::new(Refusal(code)).context(detail));
    }
    Ok(())
}

pub fn validate_state(state: &State, partial: bool) -> Result<()> {
    for (public, (class, _)) in &state.keys {
        if *class == ENCRYPTION_KEY {
            validate_encryption_key(*public)?;
        }
    }
    let mut roots = BTreeSet::new();
    let mut devices = BTreeSet::new();
    for r in state
        .records
        .values()
        .filter(|r| persistent_kind(r.reference.kind))
    {
        ensure!(
            signed_record(&r.bytes, state.network, state.incarnation)?.reference == r.reference,
            "recipient record identity differs"
        );
        match r.reference.kind {
            107 => {
                let p = Root::parse(&payload(r)?, state.network, state.incarnation)?;
                signer(r, p.key)?;
                ensure!(roots.insert(p.key), "recipient root key reused");
                ensure!(
                    partial || state.keys.get(&p.key) == Some(&(ROOT_KEY, p.member)),
                    "recipient root reservation absent"
                );
            }
            108 => {
                let p = Binding::parse(&payload(r)?, state.network, state.incarnation)?;
                ensure!(
                    devices.insert(p.signing_key) && devices.insert(p.encryption_key),
                    "recipient device keys reused"
                );
                ensure!(
                    partial
                        || state.keys.get(&p.signing_key) == Some(&(SIGNING_KEY, p.member))
                            && state.keys.get(&p.encryption_key)
                                == Some(&(ENCRYPTION_KEY, p.member)),
                    "recipient device reservation absent"
                );
            }
            109 => {
                let p = Admission::parse(&payload(r)?, state.network, state.incarnation)?;
                if let Some(binding) = state.records.get(&p.binding.index()) {
                    let binding =
                        Binding::parse(&payload(binding)?, state.network, state.incarnation)?;
                    ensure!(
                        binding.member == p.member,
                        "recipient admission member differs"
                    );
                }
            }
            110 => {
                let p = Audience::parse(&payload(r)?, state.network, state.incarnation)?;
                if p.sharing_delegate.is_none() {
                    signer(r, p.publisher)?;
                }
            }
            158 => {
                let p = Revocation::parse(&payload(r)?, state.network, state.incarnation)?;
                signer(r, p.signer)?;
            }
            _ => (),
        }
    }
    ensure!(
        roots.is_disjoint(&devices),
        "recipient root reused as device key"
    );
    Ok(())
}

struct Context<'a> {
    state: &'a State,
    governance: Governance,
    at: u64,
    dependencies: Vec<VersionRef>,
    selected: BTreeMap<(u64, Digest), Record>,
    expires: u64,
}
impl Context<'_> {
    fn select(&mut self, kind: u64, lookup: Digest) -> Result<Record> {
        let r = self
            .state
            .record(kind, lookup)
            .context(Refusal(34))?
            .clone();
        self.dependencies.push(r.reference.clone());
        self.selected.insert(r.reference.index(), r.clone());
        Ok(r)
    }
    fn exact(&mut self, r: &VersionRef) -> Result<Record> {
        let record = self.select(r.kind, r.id)?;
        require(record.reference == *r, 12, "recipient dependency is stale")?;
        Ok(record)
    }
    fn capability(
        &mut self,
        grant: &VersionRef,
        subject: Key,
        action: u64,
        scope: (u64, Digest),
    ) -> Result<()> {
        ensure!(
            grant.kind == 102 && self.governance.versions().contains(grant),
            "recipient capability changed"
        );
        if crate::trust_action_scope::collides(action) {
            self.governance.require_action_purpose(
                grant.id,
                crate::trust_action_scope::ActionPurpose::SealedPublication,
            )?;
        }
        let permission = self.governance.current_capability(
            grant.id,
            &Requirement {
                subject,
                actions: &[action],
                scope,
                namespace: None,
                usage: [0, 1, 1, 1],
                evaluated_at_ms: self.at,
                expected: &[],
            },
        )?;
        self.dependencies.extend(permission.dependencies);
        self.expires = self.expires.min(permission.expires_ms);
        Ok(())
    }
    fn member_evidence(&mut self, member: Digest) -> Result<()> {
        self.dependencies.extend(super::member_evidence(
            &self.governance,
            self.state.network,
            member,
        )?);
        Ok(())
    }
    fn member(&mut self, member: Digest) -> Result<Key> {
        let admitted =
            super::current_member(&self.governance, self.state.network, member, self.at)?;
        self.dependencies.extend(admitted.dependencies);
        self.expires = self.expires.min(admitted.expires_ms);
        Ok(admitted.key)
    }
    fn active_root(&mut self, r: &VersionRef) -> Result<Root> {
        let record = self.exact(r)?;
        require(!revoked(self.state, r), 15, "recipient root revoked")?;
        Root::parse(
            &payload(&record)?,
            self.state.network,
            self.state.incarnation,
        )
    }
    fn old(&mut self, record: &Record, replay: bool) -> Result<()> {
        if replay {
            let old = self.select(record.reference.kind, record.reference.id)?;
            ensure!(old.bytes == record.bytes, "recipient replay differs");
            return Ok(());
        }
        if let Some(old) = self.state.records.get(&record.reference.index()) {
            let old = self.select(old.reference.kind, old.reference.id)?;
            ensure!(
                old.reference.generation.checked_add(1) == Some(record.reference.generation)
                    && record.predecessor == Some(old.reference.digest),
                "recipient predecessor changed"
            );
        } else {
            ensure!(
                record.reference.generation == 1 && record.predecessor.is_none(),
                "recipient initial generation differs"
            );
        }
        Ok(())
    }
}
fn put(next: &mut State, record: &Record, replay: bool) -> Result<()> {
    if !replay {
        next.put(record.clone())?;
        reserve_record(next, record)?;
    }
    Ok(())
}
fn exact_snapshot(actual: &Snapshot, expected: &Snapshot, exact: bool) -> Result<()> {
    require(
        actual.epoch == expected.epoch
            && actual.height == expected.height
            && actual.state == expected.state
            && (!exact || actual.references == expected.references),
        12,
        "recipient signed snapshot differs",
    )?;
    Ok(())
}
fn required_grant(operation: &Operation) -> Result<&VersionRef> {
    operation
        .grant
        .as_ref()
        .context("recipient operation requires a capability")
}
fn belongs(state: &State, record: &Record, member: Digest) -> Result<bool> {
    if !persistent_kind(record.reference.kind) {
        return Ok(false);
    }
    let bytes = payload(record)?;
    Ok(match record.reference.kind {
        107 => Root::parse(&bytes, state.network, state.incarnation)?.member == member,
        108 => Binding::parse(&bytes, state.network, state.incarnation)?.member == member,
        109 => Admission::parse(&bytes, state.network, state.incarnation)?.member == member,
        158 => {
            let r = Revocation::parse(&bytes, state.network, state.incarnation)?;
            state
                .records
                .get(&r.target.index())
                .filter(|target| target.reference == r.target)
                .map(|target| belongs(state, target, member))
                .transpose()?
                .unwrap_or(false)
        }
        _ => false,
    })
}
fn directory_permission(
    c: &mut Context<'_>,
    operation: &Operation,
    intent: &Intent,
    member: Digest,
) -> Result<()> {
    let grant = required_grant(operation)?;
    if c.capability(grant, intent.requester, 23, (4, member))
        .is_err()
    {
        c.capability(grant, intent.requester, 4, (4, member))?;
    }
    c.member_evidence(member)?;
    Ok(())
}
pub fn verify_directory_result(
    operation: &Operation,
    state: &State,
    records: &[Vec<u8>],
    intent: &Intent,
    at: u64,
    value: &V,
) -> Result<Decision> {
    let super::super::Command::SealedIdentity(Command::Directory {
        member,
        view,
        after,
    }) = &operation.command
    else {
        anyhow::bail!("not a recipient directory command")
    };
    let mut c = Context {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        at,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    directory_permission(&mut c, operation, intent, *member)?;
    let fields = value.array(5)?;
    let body = fields[4].array(4)?;
    let marker = body[3].array(2)?;
    let current_view = id(&marker[0])?;
    ensure!(
        view.is_none_or(|expected| expected == current_view),
        "recipient directory view changed"
    );
    let mut last = None;
    for bytes in body[1].list(16)? {
        let record = Record::parse(bytes.bytes()?, state.network, state.incarnation)?;
        ensure!(
            belongs(state, &record, *member)?
                && after.is_none_or(|cursor| record.reference.index() > cursor),
            "recipient directory record exceeds exact member or cursor"
        );
        last = Some(record.reference.index());
        c.selected.insert(record.reference.index(), record);
    }
    if marker[1] != V::Null {
        let p = marker[1].array(2)?;
        ensure!(
            last == Some((p[0].uint()?, id(&p[1])?)) && c.selected.len() == 16,
            "recipient directory continuation differs"
        );
    }
    sorted(&mut c.dependencies)?;
    let mut versions = c.dependencies.clone();
    versions.extend(c.selected.values().map(|r| r.reference.clone()));
    sorted(&mut versions)?;
    let expected_governance = c
        .dependencies
        .iter()
        .map(|r| Ok(b(c.governance.record_bytes(r.kind, r.id)?)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        body[2] == a(expected_governance),
        "recipient directory capability evidence differs"
    );
    Ok(Decision {
        state: None,
        value: value.clone(),
        versions,
        dependencies: c.dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
fn signed_acceptance(
    bytes: &[u8],
    root: &VersionRef,
    contact: Digest,
    signing: Key,
    n: Digest,
    i: Digest,
) -> Result<Acceptance> {
    let (p, s) = wire::envelope(bytes, 1)?;
    let a = Acceptance::parse(&p, n, i)?;
    require(
        a.accepted_root == *root && a.contact == contact && s[0].0 == signing,
        25,
        "recipient acceptance differs from independent contact authority",
    )?;
    Ok(a)
}
fn fresh_key(
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    public: Key,
) -> Result<()> {
    require(
        !state.keys.contains_key(&public) && !reserved.contains(&public),
        38,
        "recipient key was already reserved",
    )?;
    let g = Governance::parse(state.network, state.incarnation, records)?;
    for r in g.versions() {
        let v = wire::decode(g.record_bytes(r.kind, r.id)?)?;
        let f = v.list(32)?;
        let candidate = match r.kind {
            102 => Some(f[8].fixed::<32>()?),
            125 => Some(f[7].fixed()?),
            127 => Some(f[6].fixed()?),
            _ => None,
        };
        require(
            candidate != Some(public),
            38,
            "recipient key reuses an admitted principal",
        )?;
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
    let mut c = Context {
        state,
        governance: Governance::parse(state.network, state.incarnation, records)?,
        at,
        dependencies: vec![],
        selected: BTreeMap::new(),
        expires: u64::MAX,
    };
    let mut next = state.clone();
    let mut continuation = V::Null;
    let n = state.network;
    let i = state.incarnation;
    let result = (|| -> Result<()> {
        match command {
            Command::Directory {
                member,
                view,
                after,
            } => {
                directory_permission(&mut c, operation, intent, *member)?;
                let all = state
                    .records
                    .values()
                    .filter_map(|r| match belongs(state, r, *member) {
                        Ok(true) => Some(Ok(r)),
                        Ok(false) => None,
                        Err(e) => Some(Err(e)),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let current_view = wire::digest(&wire::encode(&a(all
                    .iter()
                    .map(|r| reference(&r.reference))
                    .collect()))?);
                ensure!(
                    view.is_none_or(|expected| expected == current_view),
                    "recipient directory view changed"
                );
                let window = all
                    .into_iter()
                    .filter(|r| after.is_none_or(|cursor| r.reference.index() > cursor))
                    .collect::<Vec<_>>();
                let mut last = None;
                for r in window.iter().take(16) {
                    c.select(r.reference.kind, r.reference.id)?;
                    last = Some(r.reference.index());
                }
                continuation = a(vec![
                    b(&current_view),
                    if window.len() > 16 {
                        let (kind, id) = last.context("directory continuation absent")?;
                        a(vec![V::Uint(kind), b(&id)])
                    } else {
                        V::Null
                    },
                ]);
            }
            Command::Context { kind, lookup } => {
                let record = c.select(*kind, *lookup)?;
                let member = match kind {
                    107 => Root::parse(&payload(&record)?, n, i)?.member,
                    108 => Binding::parse(&payload(&record)?, n, i)?.member,
                    109 => Admission::parse(&payload(&record)?, n, i)?.member,
                    _ => *lookup,
                };
                if let Some(grant) = &operation.grant {
                    let scope = if matches!(kind, 107..=109) {
                        (4, member)
                    } else {
                        (2, *lookup)
                    };
                    if c.capability(grant, intent.requester, 23, scope).is_err() {
                        c.capability(grant, intent.requester, 4, scope)?;
                    }
                } else {
                    let owned = match kind {
                        107 => Root::parse(&payload(&record)?, n, i)?.key == intent.requester,
                        108 => {
                            let binding = Binding::parse(&payload(&record)?, n, i)?;
                            let root = c.active_root(&binding.root)?;
                            root.key == intent.requester || binding.signing_key == intent.requester
                        }
                        109 => {
                            let admission = Admission::parse(&payload(&record)?, n, i)?;
                            let binding_record = c.exact(&admission.binding)?;
                            let binding = Binding::parse(&payload(&binding_record)?, n, i)?;
                            let root = c.active_root(&binding.root)?;
                            root.key == intent.requester || binding.signing_key == intent.requester
                        }
                        158 => {
                            Revocation::parse(&payload(&record)?, n, i)?.signer == intent.requester
                        }
                        _ => false,
                    };
                    ensure!(owned, "recipient context is not owned by this requester");
                }
                if matches!(kind, 107..=109) {
                    c.member_evidence(member)?;
                }
                if *kind != 158
                    && let Some(revocation) = state.records.get(&(158, record.reference.digest))
                {
                    c.select(158, revocation.reference.id)?;
                }
            }
            Command::Root {
                root,
                acceptance,
                custody,
                recovery,
            } => {
                let r = Root::parse(&payload(root)?, n, i)?;
                let member_key = c.member(r.member)?;
                c.capability(
                    required_grant(operation)?,
                    intent.requester,
                    23,
                    (4, r.member),
                )?;
                signer(root, r.key)?;
                let policy = Custody::parse(custody, n, i)?;
                ensure!(
                    policy.member == r.member && policy.digest == r.recovery_policy,
                    "recipient custody differs from root commitment"
                );
                let accepted =
                    signed_acceptance(acceptance, &r.reference, r.member, member_key, n, i)?;
                ensure!(
                    r.valid_from
                        == (
                            operation.snapshot.epoch,
                            operation.snapshot.height,
                            operation.snapshot.state
                        ),
                    "recipient root does not bind the committed pre-state"
                );
                if !replay {
                    fresh_key(state, records, reserved, r.key)?;
                    if let Some(previous) = state.records.get(&r.reference.index()) {
                        let old = Root::parse(&payload(previous)?, n, i)?;
                        ensure!(
                            accepted.previous_root.as_ref() == Some(&old.reference),
                            "recipient replacement acceptance omits old root"
                        );
                        verify_successor(
                            &old,
                            &r,
                            &root.bytes,
                            recovery.as_deref(),
                            recovery.as_ref().map(|_| custody.as_slice()),
                            n,
                            i,
                        )
                        .context(Refusal(14))?;
                        if let Some(recovery) = recovery {
                            let (p, _) = wire::envelope(recovery, 3)?;
                            let declaration = Recovery::parse(&p, n, i)?;
                            exact_snapshot(
                                &declaration.snapshot,
                                &operation.snapshot,
                                exact || replay,
                            )?;
                            ensure!(
                                accepted.recovery_declaration == Some(wire::digest(&p))
                                    && accepted.operation == declaration.operation,
                                "recipient acceptance names another recovery"
                            );
                        } else {
                            ensure!(
                                accepted.recovery_declaration.is_none()
                                    && !revoked(state, &old.reference),
                                "recipient continuity uses revoked root"
                            );
                        }
                    } else {
                        ensure!(
                            accepted.previous_root.is_none()
                                && accepted.recovery_declaration.is_none()
                                && recovery.is_none(),
                            "first recipient root claims prior continuity"
                        );
                    }
                }
                c.old(root, replay)?;
                put(&mut next, root, replay)?;
            }
            Command::Device {
                binding,
                admission,
                challenge,
                possession,
                delegate,
            } => {
                let device = Binding::parse(&payload(binding)?, n, i)?;
                let admitted = Admission::parse(&payload(admission)?, n, i)?;
                let root = c.active_root(&device.root)?;
                c.member(device.member)?;
                c.capability(
                    required_grant(operation)?,
                    intent.requester,
                    23,
                    (4, device.member),
                )?;
                if let Some(delegate) = delegate {
                    let record = c.exact(delegate)?;
                    let d = Binding::parse(&payload(&record)?, n, i)?;
                    ensure!(
                        d.root == device.root
                            && d.purposes.contains(&1)
                            && current(at, d.validity)
                            && !revoked(state, &d.reference),
                        "device enrolment delegate is not active"
                    );
                    let a = c.select(109, d.reference.digest)?;
                    let a = Admission::parse(&payload(&a)?, n, i)?;
                    ensure!(
                        current(at, a.validity) && !revoked(state, &a.reference),
                        "device enrolment delegate lacks admission"
                    );
                    signer(binding, d.signing_key)?;
                } else {
                    signer(binding, root.key)?;
                }
                signer(admission, intent.requester)?;
                exact_snapshot(&admitted.snapshot, &operation.snapshot, exact || replay)?;
                ensure!(
                    admitted.member == device.member
                        && admitted.binding == device.reference
                        && current(at, device.validity)
                        && current(at, admitted.validity)
                        && admitted.validity.0 >= device.validity.0
                        && admitted.validity.1 <= device.validity.1
                        && admitted.validity.1 <= c.expires,
                    "recipient device admission exceeds current authority"
                );
                let (ch, cs) = wire::envelope(challenge, 1)?;
                let chv = Challenge::parse(&ch, n, i)?;
                let (proof, ps) = wire::envelope(possession, 1)?;
                let proofv = Possession::parse(&proof, n, i)?;
                require(
                    cs[0].0 == intent.requester
                        && ps[0].0 == device.signing_key
                        && chv.endpoint == intent.requester
                        && proofv.endpoint == chv.endpoint
                        && proofv.operation == chv.operation
                        && proofv.binding == device.reference.digest
                        && chv.binding == device.reference.digest
                        && proofv.challenge == wire::digest(&ch)
                        && admitted.possession == wire::digest(&proof)
                        && proofv.expires_ms == chv.expires_ms
                        && chv.expires_ms > at.saturating_add(1250)
                        && chv.expires_ms <= at.saturating_add(30_000),
                    16,
                    "recipient key possession evidence differs or expired",
                )?;
                if !replay {
                    fresh_key(state, records, reserved, device.signing_key)?;
                    fresh_key(state, records, reserved, device.encryption_key)?;
                    if let Some(old) = state.records.get(&device.reference.index()) {
                        ensure!(
                            revoked(state, &old.reference),
                            "active device cannot be silently replaced"
                        );
                        c.select(158, old.reference.digest)?;
                    }
                    ensure!(
                        !state.records.contains_key(&admission.reference.index()),
                        "recipient possession has already been admitted"
                    );
                }
                c.old(binding, replay)?;
                c.old(admission, replay)?;
                put(&mut next, binding, replay)?;
                put(&mut next, admission, replay)?;
                c.expires = c.expires.min(admitted.validity.1);
            }
            Command::Audience {
                audience,
                acceptances,
            } => {
                let a = Audience::parse(&payload(audience)?, n, i)?;
                let grant = required_grant(operation)?;
                c.capability(grant, intent.requester, 4, (2, a.reference.id))?;
                signer(audience, intent.requester)?;
                exact_snapshot(&a.snapshot, &operation.snapshot, exact || replay)?;
                if intent.requester != a.publisher {
                    let prior = c.select(110, a.reference.id)?;
                    let prior = Audience::parse(&payload(&prior)?, n, i)?;
                    ensure!(
                        prior.publisher == a.publisher
                            && prior.sharing_delegate.as_ref() == Some(grant)
                            && a.sharing_delegate == prior.sharing_delegate,
                        "sharing delegate exceeds publisher authority"
                    );
                }
                ensure!(
                    acceptances.len() == a.allowed_roots.len(),
                    "audience lacks exact independent root acceptances"
                );
                for (root, acceptance) in a.allowed_roots.iter().zip(acceptances) {
                    c.active_root(root)?;
                    signed_acceptance(acceptance, root, a.publisher, a.publisher, n, i)?;
                }
                if let Some(old) = state.records.get(&a.reference.index()) {
                    ensure!(
                        Audience::parse(&payload(old)?, n, i)?.publisher == a.publisher,
                        "audience publisher changed"
                    );
                }
                c.old(audience, replay)?;
                put(&mut next, audience, replay)?;
            }
            Command::Freeze {
                roster: record,
                scope,
            } => {
                let r = Roster::parse(&payload(record)?, n, i)?;
                let audience = c.exact(&r.audience)?;
                let audience = Audience::parse(&payload(&audience)?, n, i)?;
                c.capability(required_grant(operation)?, intent.requester, 30, *scope)?;
                signer(record, intent.requester)?;
                exact_snapshot(&r.snapshot, &operation.snapshot, exact || replay)?;
                let CurrentRoster {
                    roots,
                    devices,
                    dependencies,
                    expires_ms,
                } = roster(state, &c.governance, &audience, at, *scope).context(Refusal(17))?;
                c.dependencies.extend(dependencies);
                c.expires = c.expires.min(expires_ms);
                require(
                    r.roots == roots && r.devices == devices,
                    17,
                    "recipient roster differs from complete current directory",
                )?;
                for root in &audience.allowed_roots {
                    c.exact(root)?;
                }
                for (_, binding, admission) in &devices {
                    let record = state
                        .records
                        .values()
                        .find(|record| {
                            record.reference.kind == 108 && record.reference.digest == *binding
                        })
                        .context(Refusal(34))?;
                    c.exact(&record.reference)?;
                    let admitted = c.select(109, *binding)?;
                    require(
                        admitted.reference.digest == *admission,
                        12,
                        "recipient admission changed during roster selection",
                    )?;
                }
                if !replay {
                    ensure!(
                        !state.records.contains_key(&record.reference.index()),
                        "publication roster is immutable"
                    );
                }
                c.old(record, replay)?;
                put(&mut next, record, replay)?;
            }
            Command::Revoke { revocation } => {
                let r = Revocation::parse(&payload(revocation)?, n, i)?;
                let target = c.exact(&r.target)?;
                signer(revocation, r.signer)?;
                exact_snapshot(&r.snapshot, &operation.snapshot, exact || replay)?;
                ensure!(
                    r.signer == intent.requester,
                    "recipient revocation requester differs"
                );
                let (member, owner) = match target.reference.kind {
                    107 => {
                        let root = Root::parse(&payload(&target)?, n, i)?;
                        (root.member, root.key)
                    }
                    108 => {
                        let device = Binding::parse(&payload(&target)?, n, i)?;
                        let root = c.active_root(&device.root)?;
                        (device.member, root.key)
                    }
                    109 => {
                        let admission = Admission::parse(&payload(&target)?, n, i)?;
                        (admission.member, intent.requester)
                    }
                    _ => anyhow::bail!("invalid recipient revocation target"),
                };
                if target.reference.kind == 109 {
                    c.capability(
                        required_grant(operation)?,
                        intent.requester,
                        23,
                        (4, member),
                    )?;
                } else {
                    ensure!(
                        r.signer == owner,
                        "network administration cannot revoke user root ownership"
                    );
                    ensure!(
                        operation.grant.is_none(),
                        "root revocation cannot borrow network capability"
                    );
                }
                c.old(revocation, replay)?;
                put(&mut next, revocation, replay)?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        return Ok(Decision::refused(
            error
                .downcast_ref::<Refusal>()
                .map_or(3, |refusal| refusal.0),
        ));
    }
    if sorted(&mut c.dependencies).is_err() {
        return Ok(Decision::refused(2));
    }
    if command.mutation() && !replay && exact && c.dependencies != intent.expected {
        return Ok(Decision::refused(12));
    }
    for index in command.mutation_indices() {
        if let Some(r) = next.records.get(&index) {
            c.selected.insert(index, r.clone());
        }
    }
    let governance = c
        .dependencies
        .iter()
        .filter(|r| !persistent_kind(r.kind))
        .map(|r| Ok(c.governance.record_bytes(r.kind, r.id)?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let mut versions = c
        .dependencies
        .iter()
        .filter(|r| !persistent_kind(r.kind))
        .cloned()
        .collect::<Vec<_>>();
    versions.extend(c.selected.values().map(|r| r.reference.clone()));
    if c.selected.len() > 64 || sorted(&mut versions).is_err() {
        return Ok(Decision::refused(2));
    }
    next.charge()?;
    validate_state(&next, false)?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(c.selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance.iter().map(|v| b(v)).collect()),
            continuation,
        ]),
    ]);
    Ok(Decision {
        state: (command.mutation() && !replay).then_some(next),
        value,
        versions,
        dependencies: c.dependencies,
        code: 0,
        expires_ms: c.expires,
    })
}
