// SPDX-License-Identifier: MIT
// Offline bootstrap plans bind complete genesis governance and explicit custody acceptance.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Result, bail, ensure};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[path = "TrustSummary.rs"]
mod summary;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Assurance {
    Organisational,
    Independent,
}
impl Assurance {
    fn parse(value: &V) -> Result<Self> {
        match value.uint()? {
            0 => Ok(Self::Organisational),
            1 => Ok(Self::Independent),
            _ => bail!("invalid route assurance"),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryKey {
    pub principal: String,
    pub public_key: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverySpec {
    pub custody: String,
    pub keys: Vec<RecoveryKey>,
    pub accepted_keys: Vec<String>,
    pub immutable_shared: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteSpec {
    pub relay_service: String,
    pub relay_origin: String,
    pub relay_transport_key: String,
    pub relay_domain: String,
    pub admission_service: String,
    pub admission_origin: String,
    pub admission_transport_key: String,
    pub admission_domain: String,
    pub assurance: Assurance,
    pub not_before_ms: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub fingerprint: String,
    pub descriptor_digest: String,
    pub network: String,
    pub incarnation: String,
    pub epoch: u64,
    pub protocol: String,
    pub bootstrap_time_ms: u64,
    pub genesis_governance: summary::Genesis,
    pub voters: Vec<String>,
    pub authority_transports: BTreeMap<String, String>,
    pub clock_monitors: Vec<String>,
    pub administrators: Vec<String>,
    pub enrolment: String,
    pub public_reading: bool,
    pub minimum_route: Assurance,
    pub publication_modes: Vec<String>,
    pub default_publication_mode: String,
    pub allowed_relay_domains: Vec<String>,
    pub recovery: RecoverySpec,
    pub route: RouteSpec,
    pub draft: bool,
}
pub struct Verified {
    pub summary: Summary,
    #[cfg(test)]
    pub recovery_payload: Vec<u8>,
    #[cfg(test)]
    pub accepted_keys: BTreeSet<[u8; 32]>,
    fingerprint: [u8; 32],
    file_digest: [u8; 32],
    descriptor: crate::authority_proof::TrustDescriptor,
    governance_records: Vec<Vec<u8>>,
    fully_accepted: bool,
    reservations: Vec<(u64, [u8; 32])>,
}
impl Verified {
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// SHA-256 of the exact accepted bootstrap file, used by installation manifests.
    pub fn file_digest(&self) -> [u8; 32] {
        self.file_digest
    }
    /// Exact descriptor verified together with the complete bootstrap; diagnostic summaries are not trust state.
    pub fn descriptor(&self) -> &crate::authority_proof::TrustDescriptor {
        &self.descriptor
    }
    pub fn governance_records(&self) -> &[Vec<u8>] {
        &self.governance_records
    }
    pub fn reservations(&self) -> &[(u64, [u8; 32])] {
        &self.reservations
    }
    pub fn fully_accepted(&self) -> bool {
        self.fully_accepted
    }
}

pub fn hex32(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "expected 32-byte lowercase hexadecimal"
    );
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

fn id(value: &V) -> Result<[u8; 32]> {
    let id = value.fixed::<32>()?;
    ensure!(id != [0; 32], "zero identifier");
    Ok(id)
}
fn key(value: &V) -> Result<[u8; 32]> {
    let key = value.fixed::<32>()?;
    wire::valid_key(&key)?;
    Ok(key)
}
fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let values = value.array(arity)?;
    ensure!(
        values[0].uint()? == kind && values[1].uint()? == 1,
        "incorrect record kind or version"
    );
    Ok(values)
}
fn sorted<T: Ord>(values: &[T]) -> Result<()> {
    ensure!(
        values.windows(2).all(|v| v[0] < v[1]),
        "unsorted or duplicate set entry"
    );
    Ok(())
}
fn ids(value: &V, maximum: usize, nonempty: bool) -> Result<Vec<[u8; 32]>> {
    let list = value.list(maximum)?;
    ensure!(!nonempty || !list.is_empty(), "empty identity set");
    let list = list.iter().map(id).collect::<Result<Vec<_>>>()?;
    sorted(&list)?;
    Ok(list)
}
fn numbers(value: &V, maximum: usize, largest: u64, nonempty: bool) -> Result<Vec<u64>> {
    let values = value
        .list(maximum)?
        .iter()
        .map(V::uint)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        (!nonempty || !values.is_empty()) && values.iter().all(|v| *v <= largest),
        "invalid enum set"
    );
    sorted(&values)?;
    Ok(values)
}
fn limits(value: &V) -> Result<[u64; 4]> {
    let v = value.array(4)?;
    Ok([v[0].uint()?, v[1].uint()?, v[2].uint()?, v[3].uint()?])
}
fn scopes(value: &V, network: &[u8; 32]) -> Result<Vec<(u64, [u8; 32])>> {
    let list = value
        .list(64)?
        .iter()
        .map(|v| {
            let pair = v.array(2)?;
            let kind = pair[0].uint()?;
            let subject = id(&pair[1])?;
            ensure!(
                kind <= 5 && (kind != 0 || subject == *network),
                "invalid resource scope"
            );
            Ok((kind, subject))
        })
        .collect::<Result<Vec<_>>>()?;
    sorted(&list)?;
    Ok(list)
}
fn scope_subset(child: &[(u64, [u8; 32])], parent: &[(u64, [u8; 32])], network: &[u8; 32]) -> bool {
    child
        .iter()
        .all(|v| parent.contains(v) || parent.contains(&(0, *network)))
}
fn validity(value: &V, time: u64) -> Result<()> {
    let pair = value.array(2)?;
    ensure!(
        pair[0].uint()? <= time && time < pair[1].uint()?,
        "bootstrap validity is not current"
    );
    Ok(())
}
fn version_ref(value: &V, kind: u64, lookup: &[u8; 32], bytes: &[u8]) -> Result<()> {
    let v = value.array(4)?;
    ensure!(
        v[0].uint()? == kind
            && id(&v[1])? == *lookup
            && v[2].uint()? == 1
            && v[3].fixed::<32>()? == wire::digest(bytes),
        "genesis reference mismatch"
    );
    Ok(())
}
fn mode(number: u64) -> String {
    if number == 0 {
        "HostReadable"
    } else {
        "Sealed"
    }
    .into()
}

fn origin(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 1024 && value.bytes().all(|v| v.is_ascii_graphic()),
        "invalid route origin"
    );
    let url = reqwest::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.port_or_known_default() != Some(0),
        "route requires an HTTPS origin without credentials or path"
    );
    Ok(())
}

pub fn inspect(bytes: &[u8], require_acceptance: bool) -> Result<Verified> {
    verify(bytes, require_acceptance, None)
}

fn verify(bytes: &[u8], require_acceptance: bool, time: Option<u64>) -> Result<Verified> {
    let value = wire::decode(bytes)?;
    let bundle = record(&value, 30, 6)?;
    let descriptor_bytes = bundle[2].bytes()?;
    let descriptor_value = wire::decode(descriptor_bytes)?;
    let descriptor = record(&descriptor_value, 10, 11)?;
    let network = id(&descriptor[2])?;
    let incarnation = id(&descriptor[3])?;
    ensure!(
        network != incarnation
            && descriptor[4].uint()? == 0
            && descriptor[10].text()? == "BasicHotStuff",
        "unsupported genesis descriptor"
    );
    let voters = descriptor[5]
        .array(4)?
        .iter()
        .map(key)
        .collect::<Result<Vec<_>>>()?;
    sorted(&voters)?;
    let bootstrap_time = descriptor[9].uint()?;
    ensure!(
        time.is_none_or(|time| bootstrap_time <= time),
        "bootstrap timestamp is in the future"
    );
    let governance_bytes = bundle[3].bytes()?;
    ensure!(
        wire::digest(governance_bytes) == descriptor[8].fixed::<32>()?,
        "genesis governance digest mismatch"
    );
    let governance_value = wire::decode(governance_bytes)?;
    let governance = record(&governance_value, 15, 6)?;
    ensure!(
        id(&governance[2])? == network && id(&governance[3])? == incarnation,
        "genesis network mismatch"
    );
    let mut records = BTreeMap::new();
    let mut previous = None;
    for value in governance[4].list(35)? {
        let bytes = value.bytes()?;
        let value = wire::decode(bytes)?;
        let values = value.list(32)?;
        ensure!(!values.is_empty(), "empty genesis record");
        let kind = values[0].uint()?;
        let arity = match kind {
            100 | 102 => 17,
            101 => 14,
            114 => 13,
            131 => 9,
            _ => bail!("unexpected genesis record kind"),
        };
        let values = record(&value, kind, arity)?;
        ensure!(
            id(&values[2])? == network && id(&values[3])? == incarnation && values[4].uint()? == 1,
            "genesis context mismatch"
        );
        values[5].null()?;
        if kind != 131 {
            values[arity - 1].null()?;
        }
        let lookup = if kind == 100 || kind == 114 || kind == 131 {
            network
        } else {
            id(&values[6])?
        };
        ensure!(
            previous.is_none_or(|prior| prior < (kind, lookup)),
            "unsorted or duplicate genesis records"
        );
        previous = Some((kind, lookup));
        records.insert((kind, lookup), (bytes.to_vec(), value));
    }
    let (runtime_bytes, _) = records
        .get(&(131, network))
        .ok_or_else(|| anyhow::anyhow!("missing runtime bootstrap keys"))?;
    let runtime_keys =
        crate::runtime_bootstrap_keys::Keys::parse(runtime_bytes, network, incarnation)?;
    runtime_keys.validate_voters(&voters)?;
    let (policy_bytes, policy_value) = records
        .get(&(100, network))
        .ok_or_else(|| anyhow::anyhow!("missing network policy"))?;
    let (recovery_bytes, recovery_value) = records
        .get(&(114, network))
        .ok_or_else(|| anyhow::anyhow!("missing recovery policy"))?;
    ensure!(
        wire::digest(policy_bytes) == descriptor[6].fixed::<32>()?
            && wire::digest(recovery_bytes) == descriptor[7].fixed::<32>()?,
        "descriptor policy digest mismatch"
    );
    let policy = policy_value.array(17)?;
    let recovery = recovery_value.array(13)?;
    let enrolment = match policy[6].uint()? {
        0 => "InvitationOnly",
        1 => "ApprovedApplications",
        _ => bail!("invalid enrolment policy"),
    };
    let public_reading = policy[7].boolean()?;
    let minimum_route = Assurance::parse(&policy[8])?;
    let relay_domains = ids(&policy[9], 16, true)?;
    let modes = numbers(&policy[10], 2, 1, true)?;
    let default_mode = policy[11].uint()?;
    ensure!(
        modes.contains(&default_mode),
        "default publication mode is not permitted"
    );
    version_ref(&policy[12], 114, &network, recovery_bytes)?;
    limits(&policy[13])?;
    ensure!(
        policy[14].boolean()?,
        "genesis requires manual review; automated-review namespace authority is absent"
    );
    let policy_authorities = ids(&policy[15], 16, true)?;

    let custody = recovery[6].uint()?;
    let threshold = recovery[7].uint()?;
    let principals = ids(&recovery[8], 3, true)?;
    let count = match custody {
        0 => 1,
        1 | 2 => 3,
        _ => bail!("invalid recovery custody"),
    };
    ensure!(
        threshold == if custody == 0 { 1 } else { 2 },
        "invalid recovery threshold"
    );
    ensure!(
        principals.len() == if custody == 2 { 3 } else { 1 },
        "invalid recovery principals"
    );
    ensure!(
        !recovery[10].boolean()? || custody == 2,
        "immutable custody requires shared recovery"
    );
    let mut recovery_keys = Vec::new();
    let mut public_keys = BTreeSet::new();
    let mut key_principals = BTreeSet::new();
    for value in recovery[9].array(count)? {
        let pair = value.array(2)?;
        let principal = id(&pair[0])?;
        let public = key(&pair[1])?;
        ensure!(
            principals.contains(&principal)
                && public_keys.insert(public)
                && !voters.contains(&public),
            "invalid or reused recovery key"
        );
        key_principals.insert(principal);
        recovery_keys.push((principal, public));
    }
    sorted(&recovery_keys)?;
    ensure!(
        key_principals.len() == principals.len(),
        "recovery principal lacks a distinct key"
    );
    let accepted_fingerprints = ids(&recovery[11], 3, true)?;
    ensure!(
        accepted_fingerprints.len() >= threshold as usize,
        "recovery acceptance threshold missing"
    );
    let accepted_keys = public_keys
        .iter()
        .filter(|public| {
            let fingerprint: [u8; 32] = Sha256::digest(public).into();
            accepted_fingerprints.contains(&fingerprint)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    ensure!(
        accepted_keys.len() == accepted_fingerprints.len(),
        "unknown recovery acceptance fingerprint"
    );

    let tiers = records.keys().filter(|(kind, _)| *kind == 101).count();
    let grants = records.keys().filter(|(kind, _)| *kind == 102).count();
    ensure!(
        (1..=16).contains(&tiers)
            && (1..=16).contains(&grants)
            && grants == policy_authorities.len(),
        "invalid genesis tier or root-grant count"
    );
    for ((kind, _), (_, value)) in &records {
        if *kind != 101 {
            continue;
        }
        let tier = value.array(14)?;
        ensure!(
            tier[7].uint()? <= 65535 && tier[11].uint()? <= 8,
            "invalid tier rank or delegation depth"
        );
        let label = tier[8].text()?;
        ensure!(
            !label.is_empty()
                && label.len() <= 128
                && !label.chars().any(|c| c.is_control()
                    || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}')
                    || ('\u{202a}'..='\u{202e}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)),
            "unsafe tier display label"
        );
        numbers(&tier[9], 32, 31, false)?;
        scopes(&tier[10], &network)?;
        limits(&tier[12])?;
    }
    let mut administrators = BTreeSet::new();
    for ((kind, lookup), (_, value)) in &records {
        if *kind != 102 {
            continue;
        }
        ensure!(
            policy_authorities.contains(lookup),
            "unlisted genesis root grant"
        );
        let grant = value.array(17)?;
        let administrator = key(&grant[7])?;
        ensure!(
            key(&grant[8])? == administrator
                && !voters.contains(&administrator)
                && !public_keys.contains(&administrator),
            "genesis administrator reuses another role key"
        );
        administrators.insert(administrator);
        let reference = grant[9].array(4)?;
        let tier_id = id(&reference[1])?;
        let (tier_bytes, tier_value) = records
            .get(&(101, tier_id))
            .ok_or_else(|| anyhow::anyhow!("missing grant tier"))?;
        version_ref(&grant[9], 101, &tier_id, tier_bytes)?;
        let tier = tier_value.array(14)?;
        let actions = numbers(&grant[10], 32, 31, false)?;
        let allowed = numbers(&tier[9], 32, 31, false)?;
        ensure!(
            actions.iter().all(|v| allowed.contains(v)),
            "root actions exceed tier"
        );
        ensure!(
            scope_subset(
                &scopes(&grant[11], &network)?,
                &scopes(&tier[10], &network)?,
                &network
            ),
            "root scopes exceed tier"
        );
        validity(&grant[12], bootstrap_time)?;
        if let Some(time) = time {
            validity(&grant[12], time)?;
        }
        grant[13].null()?;
        ensure!(
            grant[14].uint()? <= tier[11].uint()? && grant[14].uint()? <= 8,
            "root delegation exceeds tier"
        );
        ensure!(
            limits(&grant[15])?
                .iter()
                .zip(limits(&tier[12])?)
                .all(|(v, cap)| *v <= cap),
            "root limits exceed tier"
        );
    }

    let route_value = wire::decode(bundle[5].bytes()?)?;
    let route = record(&route_value, 31, 15)?;
    ensure!(
        id(&route[2])? == network && id(&route[3])? == incarnation,
        "route network mismatch"
    );
    let relay_service = id(&route[4])?;
    let admission_service = id(&route[8])?;
    let relay_key = key(&route[6])?;
    let admission_key = key(&route[10])?;
    ensure!(
        runtime_keys.route_transports.get(&2) == Some(&(relay_service, relay_key))
            && runtime_keys.route_transports.get(&3) == Some(&(admission_service, admission_key)),
        "Bootstrap route differs from its immutable runtime identity mapping"
    );
    ensure!(
        relay_service != admission_service && relay_key != admission_key,
        "relay and admission identities must differ"
    );
    ensure!(
        !voters.contains(&relay_key)
            && !voters.contains(&admission_key)
            && !public_keys.contains(&relay_key)
            && !public_keys.contains(&admission_key)
            && !administrators.contains(&relay_key)
            && !administrators.contains(&admission_key),
        "route transport key reuses governance identity"
    );
    let mut reserved = BTreeSet::new();
    reserved.extend(voters.iter().map(|key| (0, *key)));
    reserved.extend(public_keys.iter().map(|key| (1, *key)));
    reserved.insert((2, relay_key));
    reserved.insert((3, admission_key));
    reserved.extend(administrators.iter().map(|key| (4, *key)));
    reserved.extend(runtime_keys.reservations());
    let declared = governance[5]
        .list(64)?
        .iter()
        .map(|entry| {
            let entry = entry.array(2)?;
            let role = entry[0].uint()?;
            ensure!(role <= 6, "unknown genesis role reservation");
            Ok((role, key(&entry[1])?))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        declared == reserved.into_iter().collect::<Vec<_>>()
            && declared
                .iter()
                .map(|(_, key)| *key)
                .collect::<BTreeSet<_>>()
                .len()
                == declared.len(),
        "genesis role reservations differ from authenticated roles"
    );
    origin(route[5].text()?)?;
    origin(route[9].text()?)?;
    let relay_domain = id(&route[7])?;
    let admission_domain = id(&route[11])?;
    let assurance = Assurance::parse(&route[12])?;
    ensure!(
        relay_domains.contains(&relay_domain) && assurance >= minimum_route,
        "route violates network privacy policy"
    );
    ensure!(
        assurance != Assurance::Independent || relay_domain != admission_domain,
        "independent route declares shared control"
    );
    ensure!(
        route[13].uint()? < route[14].uint()?
            && time.is_none_or(
                |time| route[13].uint().unwrap() <= time && time < route[14].uint().unwrap()
            ),
        "bootstrap route is not current"
    );
    let draft = bundle[4] == V::Null;
    ensure!(
        !require_acceptance || !draft,
        "draft lacks recovery acceptance"
    );
    if !draft {
        let (payload, signatures) = wire::envelope(bundle[4].bytes()?, 3)?;
        ensure!(
            payload == *recovery_bytes
                && signatures.len() == accepted_keys.len()
                && signatures
                    .iter()
                    .all(|(key, _)| accepted_keys.contains(key)),
            "recovery acceptance does not match exact proposed custody"
        );
    }
    let recovery = RecoverySpec {
        custody: match custody {
            0 => "OwnerSingle",
            1 => "OwnerThreshold",
            _ => "SharedThreshold",
        }
        .into(),
        keys: recovery_keys
            .iter()
            .map(|(principal, public)| RecoveryKey {
                principal: hex::encode(principal),
                public_key: hex::encode(public),
            })
            .collect(),
        accepted_keys: accepted_keys.iter().map(hex::encode).collect(),
        immutable_shared: recovery[10].boolean()?,
    };
    Ok(Verified {
        summary: Summary {
            fingerprint: hex::encode(wire::digest(bytes)),
            descriptor_digest: hex::encode(wire::digest(descriptor_bytes)),
            network: hex::encode(network),
            incarnation: hex::encode(incarnation),
            epoch: descriptor[4].uint()?,
            protocol: descriptor[10].text()?.into(),
            bootstrap_time_ms: bootstrap_time,
            genesis_governance: summary::describe(&records, &network, governance_bytes)?,
            voters: voters.iter().map(hex::encode).collect(),
            authority_transports: runtime_keys
                .authority_transports
                .iter()
                .map(|(voter, transport)| (hex::encode(voter), hex::encode(transport)))
                .collect(),
            clock_monitors: runtime_keys
                .clock_monitors
                .iter()
                .map(hex::encode)
                .collect(),
            administrators: administrators.iter().map(hex::encode).collect(),
            enrolment: enrolment.into(),
            public_reading,
            minimum_route,
            publication_modes: modes.into_iter().map(mode).collect(),
            default_publication_mode: mode(default_mode),
            allowed_relay_domains: relay_domains.iter().map(hex::encode).collect(),
            recovery,
            route: RouteSpec {
                relay_service: hex::encode(relay_service),
                relay_origin: route[5].text()?.into(),
                relay_transport_key: hex::encode(relay_key),
                relay_domain: hex::encode(relay_domain),
                admission_service: hex::encode(admission_service),
                admission_origin: route[9].text()?.into(),
                admission_transport_key: hex::encode(admission_key),
                admission_domain: hex::encode(admission_domain),
                assurance,
                not_before_ms: route[13].uint()?,
                expires_ms: route[14].uint()?,
            },
            draft,
        },
        #[cfg(test)]
        recovery_payload: recovery_bytes.clone(),
        #[cfg(test)]
        accepted_keys,
        fingerprint: wire::digest(bytes),
        file_digest: Sha256::digest(bytes).into(),
        descriptor: crate::authority_proof::TrustDescriptor::from_canonical(descriptor_bytes)?,
        governance_records: governance[4]
            .list(35)?
            .iter()
            .map(|v| Ok(v.bytes()?.to_vec()))
            .collect::<Result<Vec<_>>>()?,
        fully_accepted: !draft,
        reservations: declared,
    })
}

#[cfg(test)]
#[path = "../../Tests/Unit/Protocol/TrustBootstrapUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Protocol/TrustBootstrap.rs");
