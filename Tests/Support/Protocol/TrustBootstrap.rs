// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
use ed25519_dalek::SigningKey;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg(test)]
pub struct DraftSpec {
    pub voters: Vec<String>,
    pub authority_transports: BTreeMap<String, String>,
    pub clock_monitors: Vec<String>,
    pub administrator: String,
    pub administrator_actions: Vec<u64>,
    pub enrolment: String,
    pub public_reading: bool,
    pub minimum_route: Assurance,
    pub publication_modes: Vec<String>,
    pub default_publication_mode: String,
    pub limits: [u64; 4],
    pub recovery: RecoverySpec,
    pub route: RouteSpec,
}

#[cfg(test)]
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}

#[cfg(test)]
fn u(value: u64) -> V {
    V::Uint(value)
}

#[cfg(test)]
fn array(values: impl IntoIterator<Item = V>) -> V {
    V::Array(values.into_iter().collect())
}

#[cfg(test)]
fn mode_number(name: &str) -> Result<u64> {
    match name {
        "HostReadable" => Ok(0),
        "Sealed" => Ok(1),
        _ => bail!("unknown publication mode"),
    }
}

#[cfg(test)]
pub fn check(bytes: &[u8], require_acceptance: bool, time: u64) -> Result<Verified> {
    verify(bytes, require_acceptance, Some(time))
}

#[cfg(test)]
pub fn draft(spec: DraftSpec, identities: [[u8; 32]; 4], time: u64) -> Result<Vec<u8>> {
    let [network, incarnation, tier_id, grant_id] = identities;
    let common = |kind| vec![u(kind), u(1), b(&network), b(&incarnation), u(1), V::Null];
    let as_bytes = |text: &str| -> Result<V> { Ok(b(&hex32(text)?)) };
    let version = |kind, lookup: &[u8], payload: &[u8]| {
        array([u(kind), b(lookup), u(1), b(&wire::digest(payload))])
    };
    let limit = array(spec.limits.into_iter().map(u));
    let scope = array([array([u(0), b(&network)])]);
    let actions = array(spec.administrator_actions.into_iter().map(u));
    let custody = match spec.recovery.custody.as_str() {
        "OwnerSingle" => 0,
        "OwnerThreshold" => 1,
        "SharedThreshold" => 2,
        _ => bail!("invalid recovery custody"),
    };
    let principals = spec
        .recovery
        .keys
        .iter()
        .map(|v| hex32(&v.principal))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut recovery = common(114);
    let mut fingerprints = spec
        .recovery
        .accepted_keys
        .iter()
        .map(|v| Ok(Sha256::digest(hex32(v)?).to_vec()))
        .collect::<Result<Vec<_>>>()?;
    fingerprints.sort();
    let recovery_keys = spec
        .recovery
        .keys
        .iter()
        .map(|v| Ok(array([as_bytes(&v.principal)?, as_bytes(&v.public_key)?])))
        .collect::<Result<Vec<_>>>()?;
    recovery.extend([
        u(custody),
        u(if custody == 0 { 1 } else { 2 }),
        array(principals.iter().map(|v| b(v))),
        array(recovery_keys),
        V::Bool(spec.recovery.immutable_shared),
        array(fingerprints.iter().map(|v| b(v))),
        V::Null,
    ]);
    let recovery_bytes = wire::encode(&array(recovery))?;
    let mut tier = common(101);
    tier.extend([
        b(&tier_id),
        u(0),
        V::Text("Administrator".into()),
        actions.clone(),
        scope.clone(),
        u(8),
        limit.clone(),
        V::Null,
    ]);
    let tier_bytes = wire::encode(&array(tier))?;
    let mut grant = common(102);
    grant.extend([
        b(&grant_id),
        as_bytes(&spec.administrator)?,
        as_bytes(&spec.administrator)?,
        version(101, &tier_id, &tier_bytes),
        actions,
        scope,
        array([u(spec.route.not_before_ms), u(spec.route.expires_ms)]),
        V::Null,
        u(8),
        limit.clone(),
        V::Null,
    ]);
    let grant_bytes = wire::encode(&array(grant))?;
    let mut policy = common(100);
    let enrolment = match spec.enrolment.as_str() {
        "InvitationOnly" => 0,
        "ApprovedApplications" => 1,
        _ => bail!("invalid enrolment"),
    };
    let modes = spec
        .publication_modes
        .iter()
        .map(|v| Ok(u(mode_number(v)?)))
        .collect::<Result<Vec<_>>>()?;
    policy.extend([
        u(enrolment),
        V::Bool(spec.public_reading),
        u(spec.minimum_route.number()),
        array([as_bytes(&spec.route.relay_domain)?]),
        array(modes),
        u(mode_number(&spec.default_publication_mode)?),
        version(114, &network, &recovery_bytes),
        limit,
        V::Bool(true),
        array([b(&grant_id)]),
        V::Null,
    ]);
    let policy_bytes = wire::encode(&array(policy))?;
    let runtime_keys = crate::runtime_bootstrap_keys::Keys {
        route_transports: [
            (
                2,
                (
                    hex32(&spec.route.relay_service)?,
                    hex32(&spec.route.relay_transport_key)?,
                ),
            ),
            (
                3,
                (
                    hex32(&spec.route.admission_service)?,
                    hex32(&spec.route.admission_transport_key)?,
                ),
            ),
        ]
        .into_iter()
        .collect(),
        authority_transports: spec
            .authority_transports
            .iter()
            .map(|(voter, transport)| Ok((hex32(voter)?, hex32(transport)?)))
            .collect::<Result<_>>()?,
        clock_monitors: spec
            .clock_monitors
            .iter()
            .map(|key| hex32(key))
            .collect::<Result<_>>()?,
    };
    ensure!(
        runtime_keys.clock_monitors.len() == spec.clock_monitors.len(),
        "Repeated bootstrap clock monitor"
    );
    let runtime_bytes = runtime_keys.encode(network, incarnation)?;

    let mut reservations = BTreeSet::new();
    for key in &spec.voters {
        reservations.insert((0, hex32(key)?));
    }
    for key in &spec.recovery.keys {
        reservations.insert((1, hex32(&key.public_key)?));
    }
    reservations.insert((2, hex32(&spec.route.relay_transport_key)?));
    reservations.insert((3, hex32(&spec.route.admission_transport_key)?));
    reservations.insert((4, hex32(&spec.administrator)?));
    reservations.extend(runtime_keys.reservations());
    let governance = wire::encode(&array([
        u(15),
        u(1),
        b(&network),
        b(&incarnation),
        array([
            b(&policy_bytes),
            b(&tier_bytes),
            b(&grant_bytes),
            b(&recovery_bytes),
            b(&runtime_bytes),
        ]),
        array(
            reservations
                .into_iter()
                .map(|(role, key)| array([u(role), b(&key)])),
        ),
    ]))?;
    let descriptor = wire::encode(&array([
        u(10),
        u(1),
        b(&network),
        b(&incarnation),
        u(0),
        array(
            spec.voters
                .iter()
                .map(|v| as_bytes(v))
                .collect::<Result<Vec<_>>>()?,
        ),
        b(&wire::digest(&policy_bytes)),
        b(&wire::digest(&recovery_bytes)),
        b(&wire::digest(&governance)),
        u(time),
        V::Text("BasicHotStuff".into()),
    ]))?;
    let r = &spec.route;
    let route = wire::encode(&array([
        u(31),
        u(1),
        b(&network),
        b(&incarnation),
        as_bytes(&r.relay_service)?,
        V::Text(r.relay_origin.clone()),
        as_bytes(&r.relay_transport_key)?,
        as_bytes(&r.relay_domain)?,
        as_bytes(&r.admission_service)?,
        V::Text(r.admission_origin.clone()),
        as_bytes(&r.admission_transport_key)?,
        as_bytes(&r.admission_domain)?,
        u(r.assurance.number()),
        u(r.not_before_ms),
        u(r.expires_ms),
    ]))?;
    let result = wire::encode(&array([
        u(30),
        u(1),
        b(&descriptor),
        b(&governance),
        V::Null,
        b(&route),
    ]))?;
    check(&result, false, time)?;
    Ok(result)
}

#[cfg(test)]
pub fn accept(bytes: &[u8], signing: &SigningKey, time: u64) -> Result<Vec<u8>> {
    let checked = check(bytes, false, time)?;
    ensure!(
        checked.summary.draft
            && checked
                .accepted_keys
                .contains(&signing.verifying_key().to_bytes()),
        "key is not a selected draft recovery signer"
    );
    wire::sign_envelope(&checked.recovery_payload, signing)
}

#[cfg(test)]
pub fn assemble(bytes: &[u8], acceptances: &[Vec<u8>], time: u64) -> Result<Vec<u8>> {
    let checked = check(bytes, false, time)?;
    ensure!(
        checked.summary.draft && (1..=3).contains(&acceptances.len()),
        "expected an unsigned draft and bounded acceptances"
    );
    let mut signatures = BTreeMap::new();
    for envelope in acceptances {
        let (payload, pairs) = wire::envelope(envelope, 1)?;
        ensure!(
            payload == checked.recovery_payload,
            "acceptance signed a different policy"
        );
        for (key, signature) in pairs {
            ensure!(
                checked.accepted_keys.contains(&key) && signatures.insert(key, signature).is_none(),
                "unknown or duplicate recovery signer"
            );
        }
    }
    let envelope = wire::encode(&array([
        u(0),
        u(1),
        b(&checked.recovery_payload),
        array(signatures.iter().map(|(key, sig)| array([b(key), b(sig)]))),
    ]))?;
    let mut value = wire::decode(bytes)?.array(6)?.to_vec();
    value[4] = b(&envelope);
    let complete = wire::encode(&array(value))?;
    check(&complete, true, time)?;
    Ok(complete)
}

impl Assurance {
    #[cfg(test)]
    pub fn number(self) -> u64 {
        if self == Self::Independent { 1 } else { 0 }
    }
}
