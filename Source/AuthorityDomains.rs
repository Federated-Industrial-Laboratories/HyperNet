// SPDX-License-Identifier: MIT
// Ordered domain metadata has finite schemas and permanent native-key ownership.
use crate::{
    authority_membership::{Reservations, Snapshot, reference, version as governance_version},
    authority_proof::{Digest, Intent, Key, VersionRef, validate_versions},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;

#[path = "AuthorityBackup.rs"]
pub mod backup;
#[path = "AuthorityDomainFederation.rs"]
pub mod federation;
#[path = "AuthorityDomainMail.rs"]
pub mod mail;
#[path = "AuthorityDomainPage.rs"]
pub mod page;
#[path = "AuthorityPublicationModes.rs"]
pub mod publication_modes;
#[path = "AuthorityDomainResult.rs"]
pub mod result;
#[path = "AuthorityRoutes.rs"]
pub mod routes;
#[path = "AuthoritySealedIdentity.rs"]
pub mod sealed_identity;
#[path = "AuthoritySealedPublication.rs"]
pub mod sealed_publication;
#[path = "AuthorityDomainSsh.rs"]
pub mod ssh;
#[path = "AuthorityDomainTransfer.rs"]
pub mod transfer;

pub const MAXIMUM_BYTES: usize = 1024 * 1024;
pub const MAXIMUM_RECORDS: usize = 2048;
pub const MAXIMUM_KEYS: usize = 4096;
pub(crate) fn a(values: Vec<V>) -> V {
    V::Array(values)
}
pub(crate) fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
pub(crate) fn id(value: &V) -> Result<Digest> {
    let value = value.fixed()?;
    ensure!(value != [0; 32], "zero domain identifier");
    Ok(value)
}
/// Domain references extend governance only with explicitly implemented record kinds.
pub fn version(value: &V) -> Result<VersionRef> {
    let fields = value.array(4)?;
    if !matches!(fields[0].uint()?, 104 | 107..=111 | 113 | 132..=171) {
        return governance_version(value);
    }
    let reference = VersionRef {
        kind: fields[0].uint()?,
        id: id(&fields[1])?,
        generation: fields[2].uint()?,
        digest: id(&fields[3])?,
    };
    validate_versions(std::slice::from_ref(&reference), 1)?;
    Ok(reference)
}
pub fn snapshot(value: &V) -> Result<Snapshot> {
    let fields = value.array(2)?;
    let point = fields[0].array(3)?;
    let references = fields[1]
        .list(64)?
        .iter()
        .map(version)
        .collect::<Result<Vec<_>>>()?;
    validate_versions(&references, 64)?;
    Ok(Snapshot {
        epoch: point[0].uint()?,
        height: point[1].uint()?,
        state: id(&point[2])?,
        references,
        value: value.clone(),
    })
}
pub(crate) fn key(value: &V) -> Result<Key> {
    let value = id(value)?;
    wire::valid_key(&value)?;
    Ok(value)
}
pub(crate) fn label(value: &V, maximum: usize) -> Result<String> {
    let text = value.text()?;
    ensure!(
        !text.is_empty()
            && text.len() <= maximum
            && !text
                .chars()
                .any(|c| c.is_control() || matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069)),
        "invalid domain label"
    );
    Ok(text.into())
}

#[derive(Clone, Debug)]
pub struct Record {
    pub reference: VersionRef,
    pub predecessor: Option<Digest>,
    pub payload: V,
    pub bytes: Vec<u8>,
}
impl Record {
    pub fn parse(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        if value
            .list(32)?
            .first()
            .is_some_and(|v| v.uint().ok() == Some(0))
        {
            let (payload, _) = wire::envelope(bytes, 4)?;
            let kind = wire::decode(&payload)?.list(32)?[0].uint()?;
            return if matches!(kind, 104 | 113) {
                sealed_publication::signed_record(bytes, network, incarnation)
            } else {
                sealed_identity::signed_record(bytes, network, incarnation)
            };
        }
        let f = value.array(8)?;
        let kind = f[0].uint()?;
        ensure!(
            f[1].uint()? == 1 && id(&f[2])? == network && id(&f[3])? == incarnation,
            "domain record context differs"
        );
        let generation = f[4].uint()?;
        let predecessor = if f[5] == V::Null {
            None
        } else {
            Some(id(&f[5])?)
        };
        ensure!(
            generation > 0 && (generation == 1) == predecessor.is_none(),
            "domain record predecessor differs"
        );
        let lookup = id(&f[6])?;
        match kind {
            132 => ssh::validate_service(&f[7], network, incarnation, lookup, generation)?,
            133 => ssh::validate_grant(&f[7], network, incarnation, lookup, generation)?,
            134 => transfer::validate_service(&f[7], network, incarnation, lookup, generation)?,
            135 => transfer::validate_agreement(&f[7], network, incarnation, lookup, generation)?,
            136..=139 => {
                mail::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            140..=149 => {
                page::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            150..=157 => {
                federation::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            169..=171 => {
                backup::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            164 => publication_modes::validate(&f[7], lookup)?,
            165..=168 => {
                routes::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            162..=163 => sealed_publication::validate_record(kind, &f[7], lookup)?,
            159..=161 => {
                page::validate_record(kind, &f[7], network, incarnation, lookup, generation)?
            }
            _ => anyhow::bail!("unsupported domain record kind"),
        }
        Ok(Self {
            reference: VersionRef {
                kind,
                id: lookup,
                generation,
                digest: wire::digest(bytes),
            },
            predecessor,
            payload: f[7].clone(),
            bytes: bytes.to_vec(),
        })
    }
    pub fn next(state: &State, kind: u64, id: Digest, payload: V) -> Result<Self> {
        ensure!(
            !sealed_identity::persistent_kind(kind) && !matches!(kind, 104 | 113),
            "recipient records require their retained signed envelope"
        );
        let previous = state.records.get(&(kind, id));
        let generation = previous.map_or(Ok(1), |r| {
            r.reference
                .generation
                .checked_add(1)
                .context("domain generation exhausted")
        })?;
        let bytes = wire::encode(&a(vec![
            V::Uint(kind),
            V::Uint(1),
            b(&state.network),
            b(&state.incarnation),
            V::Uint(generation),
            previous.map_or(V::Null, |r| b(&r.reference.digest)),
            b(&id),
            payload,
        ]))?;
        Self::parse(&bytes, state.network, state.incarnation)
    }
}

#[derive(Clone, Debug)]
pub struct State {
    pub network: Digest,
    pub incarnation: Digest,
    pub records: BTreeMap<(u64, Digest), Record>,
    pub keys: BTreeMap<Key, (u64, Key)>,
}
impl State {
    pub fn empty(network: Digest, incarnation: Digest) -> Self {
        Self {
            network,
            incarnation,
            records: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }
    pub fn parse(value: &V, network: Digest, incarnation: Digest) -> Result<Self> {
        Self::parse_inner(value, network, incarnation, false)
    }
    /// A requester retains only metadata disclosed by its individually certified results.
    pub fn parse_context(value: &V, network: Digest, incarnation: Digest) -> Result<Self> {
        Self::parse_inner(value, network, incarnation, true)
    }
    fn parse_inner(value: &V, network: Digest, incarnation: Digest, partial: bool) -> Result<Self> {
        let f = value.array(7)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "AuthorityDomainState"
                && id(&f[3])? == network
                && id(&f[4])? == incarnation,
            "domain state context differs"
        );
        let mut state = Self::empty(network, incarnation);
        let mut previous = None;
        for item in f[5].list(MAXIMUM_RECORDS)? {
            let record = Record::parse(item.bytes()?, network, incarnation)?;
            let index = record.reference.index();
            ensure!(
                previous.is_none_or(|p| p < index),
                "domain records are not sorted and unique"
            );
            previous = Some(index);
            state.records.insert(index, record);
        }
        let mut previous = None;
        for item in f[6].list(MAXIMUM_KEYS)? {
            let f = item.array(3)?;
            let class = f[0].uint()?;
            let public = if class == sealed_identity::ENCRYPTION_KEY {
                id(&f[1])?
            } else {
                key(&f[1])?
            };
            let owner = if class >= sealed_identity::ROOT_KEY {
                id(&f[2])?
            } else {
                key(&f[2])?
            };
            ensure!(
                class <= sealed_identity::ENCRYPTION_KEY
                    && public != owner
                    && previous.is_none_or(|p| p < public),
                "invalid domain key ownership"
            );
            previous = Some(public);
            state.keys.insert(public, (class, owner));
        }
        state.charge()?;
        ssh::validate_state(&state)?;
        transfer::validate_state(&state)?;
        mail::validate_state(&state)?;
        if partial {
            page::validate_context(&state)?;
        } else {
            page::validate_state(&state)?;
        }
        federation::validate_state(&state, partial)?;
        backup::validate_state(&state, partial)?;
        sealed_identity::validate_state(&state, partial)?;
        Ok(state)
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomainState".into()),
            b(&self.network),
            b(&self.incarnation),
            a(self.records.values().map(|r| b(&r.bytes)).collect()),
            a(self
                .keys
                .iter()
                .map(|(k, (class, owner))| a(vec![V::Uint(*class), b(k), b(owner)]))
                .collect()),
        ])
    }
    pub fn charge(&self) -> Result<usize> {
        let bytes = wire::encode_state(&self.value())?.len();
        ensure!(
            self.records.len() <= MAXIMUM_RECORDS
                && self.keys.len() <= MAXIMUM_KEYS
                && bytes <= MAXIMUM_BYTES,
            "domain metadata capacity reached"
        );
        Ok(bytes)
    }
    pub fn record(&self, kind: u64, id: Digest) -> Result<&Record> {
        self.records
            .get(&(kind, id))
            .context("domain object unavailable")
    }
    pub fn put(&mut self, record: Record) -> Result<()> {
        let previous = self.records.get(&record.reference.index());
        ensure!(
            match previous {
                None => record.reference.generation == 1 && record.predecessor.is_none(),
                Some(p) =>
                    p.reference.generation.checked_add(1) == Some(record.reference.generation)
                        && record.predecessor == Some(p.reference.digest),
            },
            "domain update differs from its exact predecessor"
        );
        self.records.insert(record.reference.index(), record);
        self.charge()?;
        Ok(())
    }
    pub fn reserve(&mut self, class: u64, public: Key, owner: Key) -> Result<()> {
        ensure!(
            self.keys
                .get(&public)
                .is_none_or(|old| *old == (class, owner)),
            "native key already has another role or owner"
        );
        self.keys.insert(public, (class, owner));
        self.charge()?;
        Ok(())
    }
    pub fn requesters(&self) -> Vec<Key> {
        let mut requesters: Vec<_> = self
            .keys
            .iter()
            .filter_map(|(key, (class, _))| {
                matches!(
                    *class,
                    3 | sealed_identity::ROOT_KEY | sealed_identity::SIGNING_KEY
                )
                .then_some(*key)
            })
            .collect();
        requesters.extend(routes::requesters(self).expect("validated invitation records"));
        requesters.sort();
        requesters.dedup();
        requesters
    }
    pub fn extend_reservations(&self, base: &Reservations) -> Reservations {
        let mut reserved = base.clone();
        for key in self.keys.keys() {
            if !reserved.contains(key) {
                reserved.0.push((7, *key));
            }
        }
        reserved
    }
    pub fn validate_roles(&self, records: &[Vec<u8>], base: &Reservations) -> Result<()> {
        let deployments = crate::authority_deployment_records::Index::parse(
            records,
            base,
            self.network,
            self.incarnation,
        )?;
        for native in self.keys.keys() {
            ensure!(
                !base.contains(native) && !deployments.reserved.contains(native),
                "native domain key conflicts with a reserved role"
            );
            for bytes in records {
                let value = wire::decode(bytes)?;
                let f = value.list(32)?;
                let subject = match f[0].uint()? {
                    102 => Some(key(&f[8])?),
                    125 => Some(key(&f[7])?),
                    127 => Some(key(&f[6])?),
                    _ => None,
                };
                ensure!(
                    subject != Some(*native),
                    "native domain key conflicts with an admitted principal"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum Command {
    Backup(backup::Command),
    Route(routes::Command),
    SealedIdentity(sealed_identity::Command),
    SealedPublication(sealed_publication::Command),
    Ssh(ssh::Command),
    Transfer(transfer::Command),
    Mail(mail::Command),
    Page(page::Command),
    Federation(federation::Command),
}
impl From<backup::Command> for Command {
    fn from(c: backup::Command) -> Self {
        Self::Backup(c)
    }
}
impl From<routes::Command> for Command {
    fn from(c: routes::Command) -> Self {
        Self::Route(c)
    }
}
impl From<sealed_publication::Command> for Command {
    fn from(c: sealed_publication::Command) -> Self {
        Self::SealedPublication(c)
    }
}
impl From<sealed_identity::Command> for Command {
    fn from(c: sealed_identity::Command) -> Self {
        Self::SealedIdentity(c)
    }
}
impl From<ssh::Command> for Command {
    fn from(c: ssh::Command) -> Self {
        Self::Ssh(c)
    }
}
impl From<transfer::Command> for Command {
    fn from(c: transfer::Command) -> Self {
        Self::Transfer(c)
    }
}
impl From<mail::Command> for Command {
    fn from(c: mail::Command) -> Self {
        Self::Mail(c)
    }
}
impl From<page::Command> for Command {
    fn from(c: page::Command) -> Self {
        Self::Page(c)
    }
}
impl From<federation::Command> for Command {
    fn from(c: federation::Command) -> Self {
        Self::Federation(c)
    }
}
impl Command {
    pub fn command_inputs(&self) -> Vec<crate::authority_objects::Reference> {
        match self {
            Self::Page(c) => c.command_inputs(),
            Self::Federation(c) => c.command_inputs(),
            _ => vec![],
        }
    }
    pub fn required_inputs(
        &self,
        state: &State,
    ) -> Result<Vec<crate::authority_objects::Reference>> {
        match self {
            Self::Page(c) => c.required_inputs(state),
            Self::Federation(c) => c.required_inputs(state),
            _ => Ok(vec![]),
        }
    }
    pub fn parse(value: &V, n: Digest, i: Digest) -> Result<Self> {
        let fields = value.list(10)?;
        let name = fields.first().context("empty domain command")?.text()?;
        if name.starts_with("Backup") {
            Ok(Self::Backup(backup::Command::parse(value, n, i)?))
        } else if name.starts_with("Route") {
            Ok(Self::Route(routes::Command::parse(value, n, i)?))
        } else if name.starts_with("SealedPublication") {
            Ok(Self::SealedPublication(sealed_publication::Command::parse(
                value, n, i,
            )?))
        } else if name.starts_with("SealedIdentity") {
            Ok(Self::SealedIdentity(sealed_identity::Command::parse(
                value, n, i,
            )?))
        } else if name.starts_with("Federation") {
            Ok(Self::Federation(federation::Command::parse(value, n, i)?))
        } else if name.starts_with("Page") {
            Ok(Self::Page(page::Command::parse(value, n, i)?))
        } else if name.starts_with("Ssh") {
            Ok(Self::Ssh(ssh::Command::parse(value, n, i)?))
        } else if name.starts_with("Mail") {
            Ok(Self::Mail(mail::Command::parse(value, n, i)?))
        } else {
            Ok(Self::Transfer(transfer::Command::parse(value, n, i)?))
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::Backup(c) => c.name(),
            Self::Route(c) => c.name(),
            Self::SealedPublication(c) => c.name(),
            Self::SealedIdentity(c) => c.name(),
            Self::Ssh(c) => c.name(),
            Self::Transfer(c) => c.name(),
            Self::Mail(c) => c.name(),
            Self::Page(c) => c.name(),
            Self::Federation(c) => c.name(),
        }
    }
    pub fn value(&self) -> V {
        match self {
            Self::Backup(c) => c.value(),
            Self::Route(c) => c.value(),
            Self::SealedPublication(c) => c.value(),
            Self::SealedIdentity(c) => c.value(),
            Self::Ssh(c) => c.value(),
            Self::Transfer(c) => c.value(),
            Self::Mail(c) => c.value(),
            Self::Page(c) => c.value(),
            Self::Federation(c) => c.value(),
        }
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Backup(c) => c.resource(),
            Self::Route(c) => c.resource(),
            Self::SealedPublication(c) => c.resource(),
            Self::SealedIdentity(c) => c.resource(),
            Self::Ssh(c) => c.resource(),
            Self::Transfer(c) => c.resource(),
            Self::Mail(c) => c.resource(),
            Self::Page(c) => c.resource(),
            Self::Federation(c) => c.resource(),
        }
    }
    pub fn mutation(&self) -> bool {
        match self {
            Self::Backup(c) => c.mutation(),
            Self::Route(c) => c.mutation(),
            Self::SealedPublication(c) => c.mutation(),
            Self::SealedIdentity(c) => c.mutation(),
            Self::Ssh(c) => c.mutation(),
            Self::Transfer(c) => c.mutation(),
            Self::Mail(c) => c.mutation(),
            Self::Page(c) => c.mutation(),
            Self::Federation(c) => c.mutation(),
        }
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Backup(c) => c.mutation_kind(),
            Self::Route(c) => c.mutation_kind(),
            Self::Ssh(c) => {
                if c.mutation() {
                    Some(
                        if matches!(
                            c,
                            ssh::Command::Register { .. } | ssh::Command::Withdraw { .. }
                        ) {
                            132
                        } else {
                            133
                        },
                    )
                } else {
                    None
                }
            }
            Self::Transfer(c) => c.mutation_kind(),
            Self::Mail(c) => c.mutation_kind(),
            Self::Page(_)
            | Self::Federation(_)
            | Self::SealedIdentity(_)
            | Self::SealedPublication(_) => None,
        }
    }
    pub fn serving(&self) -> bool {
        matches!(
            self,
            Self::Transfer(transfer::Command::Execute { .. })
                | Self::Mail(mail::Command::Execute { .. })
                | Self::Page(page::Command::MediaAuthorise { .. })
                | Self::Page(page::Command::Content(
                    page::content::Command::Authorise { .. }
                ))
                | Self::Federation(federation::Command::MediaAuthorise { .. })
                | Self::Federation(federation::Command::ContentAuthorise { .. })
        )
    }
}

#[derive(Clone, Debug)]
pub struct Operation {
    pub grant: Option<VersionRef>,
    pub command: Command,
    pub snapshot: Snapshot,
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        action == "AuthorityDomain"
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        ensure!(
            Self::handles(&intent.action),
            "unsupported domain operation"
        );
        let value = wire::decode(&intent.parameters)?;
        let f = value.array(6)?;
        ensure!(
            f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == intent.action,
            "domain parameters differ from signed action"
        );
        let grant = if f[3] == V::Null {
            None
        } else {
            Some(version(&f[3])?)
        };
        ensure!(
            grant.as_ref().is_none_or(|g| g.kind == 102),
            "invalid domain grant kind"
        );
        let command = Command::parse(&f[4], intent.network, intent.incarnation)?;
        let snapshot = snapshot(&f[5])?;
        ensure!(
            intent.resource == command.resource()
                && intent.profile_generation == 0
                && intent.revision == u64::from(command.mutation())
                && intent.expected == snapshot.references
                && intent.minimum_policy_epoch == snapshot.epoch
                && intent.minimum_policy_height == snapshot.height,
            "domain request differs from its signed snapshot"
        );
        Ok(Self {
            grant,
            command,
            snapshot,
        })
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn mutation(&self) -> bool {
        self.command.mutation()
    }
    pub fn expected_recipient(
        &self,
        state: &State,
        records: &[Vec<u8>],
        reserved: &Reservations,
        intent: &Intent,
    ) -> Result<Key> {
        match &self.command {
            Command::SealedPublication(_) | Command::SealedIdentity(_) => Ok(intent.requester),
            Command::Ssh(_) | Command::Route(_) | Command::Backup(_) => Ok(intent.requester),
            Command::Mail(c) => mail::expected_recipient(c, state, records, reserved, intent),
            Command::Page(c) => page::expected_recipient(c, state, records, reserved, intent),
            Command::Federation(c) => {
                federation::expected_recipient(c, state, records, reserved, intent)
            }
            Command::Transfer(c) => {
                transfer::expected_recipient(c, state, records, reserved, intent)
            }
        }
    }
    pub fn parameters(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDomain".into()),
            self.grant.as_ref().map_or(V::Null, reference),
            self.command.value(),
            self.snapshot.value.clone(),
        ]))
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "The evaluator explicitly separates the command, prior state, policy, identity, time and replay mode."
    )]
    pub fn prepare(
        &self,
        state: &State,
        records: &[Vec<u8>],
        reserved: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        exact: bool,
    ) -> Result<Decision> {
        self.prepare_with_inputs(
            state,
            records,
            reserved,
            intent,
            at,
            replay,
            exact,
            &crate::authority_objects::Resolved::default(),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_inputs(
        &self,
        state: &State,
        records: &[Vec<u8>],
        reserved: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        exact: bool,
        inputs: &crate::authority_objects::Resolved,
    ) -> Result<Decision> {
        ensure!(
            inputs.references() == self.command.required_inputs(state)?,
            "domain evaluation input closure differs"
        );
        match &self.command {
            Command::Backup(c) => {
                backup::evaluate(self, c, state, records, reserved, intent, at, replay, exact)
            }
            Command::Route(c) => {
                routes::evaluate(self, c, state, records, reserved, intent, at, replay, exact)
            }
            Command::SealedPublication(c) => sealed_publication::evaluate(
                self, c, state, records, reserved, intent, at, replay, exact,
            ),
            Command::SealedIdentity(c) => sealed_identity::evaluate(
                self, c, state, records, reserved, intent, at, replay, exact,
            ),
            Command::Federation(c) => federation::evaluate(
                self, c, state, records, reserved, intent, at, replay, exact, inputs,
            ),
            Command::Page(c) => page::evaluate(
                self, c, state, records, reserved, intent, at, replay, exact, inputs,
            ),
            Command::Mail(c) => {
                mail::evaluate(self, c, state, records, reserved, intent, at, replay, exact)
            }
            Command::Ssh(c) => {
                ssh::evaluate(self, c, state, records, reserved, intent, at, replay, exact)
            }
            Command::Transfer(c) => {
                transfer::evaluate(self, c, state, records, reserved, intent, at, replay, exact)
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct Decision {
    pub state: Option<State>,
    pub value: V,
    pub versions: Vec<VersionRef>,
    pub dependencies: Vec<VersionRef>,
    pub code: u64,
    pub expires_ms: u64,
}
impl Decision {
    pub fn refused(code: u64) -> Self {
        Self {
            state: None,
            value: a(vec![]),
            versions: vec![],
            dependencies: vec![],
            code,
            expires_ms: u64::MAX,
        }
    }
    pub fn refuse(&mut self, code: u64) {
        self.code = if self.code == 0 {
            code
        } else {
            self.code.min(code)
        };
        self.state = None;
    }
}
#[cfg(test)]
pub fn evaluate(
    state: &State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    intent: &Intent,
    at: u64,
    replay: bool,
) -> Result<Decision> {
    Operation::parse(intent)?.prepare(state, records, reserved, intent, at, replay, true)
}
pub fn response_inputs(
    intent: &Intent,
    value: &V,
) -> Result<Vec<crate::authority_objects::Reference>> {
    match Operation::parse(intent)?.command {
        Command::Page(_) => page::response_inputs(intent, value),
        Command::Federation(_) => federation::response_inputs(intent, value),
        _ => Ok(vec![]),
    }
}
pub(crate) fn sorted(references: &mut Vec<VersionRef>) -> Result<()> {
    references.sort_by_key(VersionRef::index);
    references.dedup();
    validate_versions(references, 64)
}
#[cfg(test)]
#[path = "AuthorityDomainTests.rs"]
mod tests;

pub fn retained_inputs(state: &State) -> Result<Vec<crate::authority_objects::Reference>> {
    let mut refs = page::retained_inputs(state)?;
    refs.extend(federation::retained_inputs(state)?);
    refs.sort();
    refs.dedup();
    Ok(refs)
}
