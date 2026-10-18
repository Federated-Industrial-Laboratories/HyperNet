// SPDX-License-Identifier: MIT
// Recipient encryption requires current network membership as well as exact user-owned devices.
use super::*;

pub struct CurrentRoster {
    pub roots: Vec<Digest>,
    pub devices: Vec<DeviceEvidence>,
    pub dependencies: Vec<VersionRef>,
    pub expires_ms: u64,
}
pub struct CurrentMember {
    pub key: Key,
    pub dependencies: Vec<VersionRef>,
    pub expires_ms: u64,
}
fn governance_reference(governance: &Governance, kind: u64, lookup: Digest) -> Result<VersionRef> {
    governance
        .versions()
        .into_iter()
        .find(|r| r.kind == kind && r.id == lookup)
        .context("recipient membership dependency absent")
}
fn bootstrap_grant(
    governance: &Governance,
    network: Digest,
    member: Digest,
) -> Result<Option<VersionRef>> {
    let policy = wire::decode(governance.record_bytes(100, network)?)?;
    for root in policy.array(17)?[15].list(16)? {
        let lookup = id(root)?;
        let value = wire::decode(governance.record_bytes(102, lookup)?)?;
        let fields = value.array(17)?;
        if fields[8].fixed::<32>()? == member && fields[13] == V::Null {
            return Ok(Some(governance_reference(governance, 102, lookup)?));
        }
    }
    Ok(None)
}
/// Discovery retains exact inactive membership or bootstrap restrictions without granting authority.
pub fn member_evidence(
    governance: &Governance,
    network: Digest,
    member: Digest,
) -> Result<Vec<VersionRef>> {
    if governance.record_bytes(125, member).is_ok() {
        return Ok(vec![governance_reference(governance, 125, member)?]);
    }
    let Some(grant) = bootstrap_grant(governance, network, member)? else {
        return Ok(vec![]);
    };
    let value = wire::decode(governance.record_bytes(102, grant.id)?)?;
    let tier = version(&value.array(17)?[9])?;
    let mut dependencies = vec![
        governance_reference(governance, 100, network)?,
        governance_reference(governance, 101, tier.id)?,
        grant.clone(),
    ];
    if governance.record_bytes(126, grant.id).is_ok() {
        dependencies.push(governance_reference(governance, 126, grant.id)?);
    }
    sorted(&mut dependencies)?;
    Ok(dependencies)
}
pub fn current_member(
    governance: &Governance,
    network: Digest,
    member: Digest,
    at: u64,
) -> Result<CurrentMember> {
    if let Ok(bytes) = governance.record_bytes(125, member) {
        let value = wire::decode(bytes)?;
        let fields = value.array(12)?;
        let lifetime = validity(&fields[8])?;
        ensure!(
            !fields[9].boolean()? && current(at, lifetime),
            "recipient member is not active"
        );
        return Ok(CurrentMember {
            key: key(&fields[7])?,
            dependencies: vec![governance_reference(governance, 125, member)?],
            expires_ms: lifetime.1,
        });
    }
    let grant = bootstrap_grant(governance, network, member)?
        .context("recipient member is not admitted")?;
    let value = wire::decode(governance.record_bytes(102, grant.id)?)?;
    let fields = value.array(17)?;
    // Check a capability already present in the initial grant, not an invented object read grant.
    let action = fields[10]
        .list(32)?
        .first()
        .context("bootstrap grant has no current authority")?
        .uint()?;
    let scope = fields[11]
        .list(64)?
        .first()
        .context("bootstrap grant has no current scope")?
        .array(2)?;
    let permission = governance.current_capability(
        grant.id,
        &Requirement {
            subject: member,
            actions: &[action],
            scope: (scope[0].uint()?, id(&scope[1])?),
            namespace: None,
            usage: [0; 4],
            evaluated_at_ms: at,
            expected: &[],
        },
    )?;
    Ok(CurrentMember {
        key: member,
        dependencies: permission.dependencies,
        expires_ms: permission.expires_ms,
    })
}

/// Select an exact current device admission independently of any publication audience.
pub fn admitted_device(
    state: &State,
    root: &Root,
    device: &Binding,
    at: u64,
    scope: (u64, Digest),
) -> Result<Option<Admission>> {
    if state.record(107, root.member)?.reference != root.reference
        || state.record(108, device.device)?.reference != device.reference
        || device.member != root.member
        || device.root != root.reference
        || !device.purposes.contains(&0)
        || !current(at, device.validity)
        || revoked(state, &root.reference)
        || revoked(state, &device.reference)
    {
        return Ok(None);
    }
    let Some(record) = state.records.get(&(109, device.reference.digest)) else {
        return Ok(None);
    };
    let admitted = Admission::parse(&payload(record)?, state.network, state.incarnation)?;
    if admitted.member != root.member
        || admitted.binding != device.reference
        || !current(at, admitted.validity)
        || revoked(state, &admitted.reference)
        || !(admitted.scopes.contains(&(0, state.network)) || admitted.scopes.contains(&scope))
    {
        return Ok(None);
    }
    Ok(Some(admitted))
}

pub fn roster(
    state: &State,
    governance: &Governance,
    audience: &Audience,
    at: u64,
    scope: (u64, Digest),
) -> Result<CurrentRoster> {
    let mut roots = Vec::new();
    let mut devices = Vec::new();
    let mut dependencies = Vec::new();
    let mut expires_ms = u64::MAX;
    for accepted in &audience.allowed_roots {
        let record = state.record(107, accepted.id)?;
        ensure!(
            record.reference == *accepted && !revoked(state, accepted),
            "recipient audience root changed or revoked"
        );
        let root = Root::parse(&payload(record)?, state.network, state.incarnation)?;
        let member = current_member(governance, state.network, root.member, at)?;
        dependencies.extend(member.dependencies);
        expires_ms = expires_ms.min(member.expires_ms);
        let mut count = 0;
        for binding in state.records.values().filter(|r| r.reference.kind == 108) {
            let device = Binding::parse(&payload(binding)?, state.network, state.incarnation)?;
            if device.root != root.reference || audience.excluded_devices.contains(&device.device) {
                continue;
            }
            let Some(admitted) = admitted_device(state, &root, &device, at, scope)? else {
                continue;
            };
            expires_ms = expires_ms.min(device.validity.1).min(admitted.validity.1);
            count += 1;
            ensure!(count <= 16, "recipient root exceeds active device bound");
            devices.push((
                root.reference.digest,
                device.reference.digest,
                admitted.reference.digest,
            ));
        }
        ensure!(count > 0, "audience root has no current admitted device");
        roots.push(root.reference.digest);
    }
    roots.sort();
    devices.sort();
    ensure!(
        !devices.is_empty() && devices.len() <= 1024,
        "recipient roster exceeds its bound"
    );
    sorted(&mut dependencies)?;
    Ok(CurrentRoster {
        roots,
        devices,
        dependencies,
        expires_ms,
    })
}
