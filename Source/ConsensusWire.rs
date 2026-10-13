// SPDX-License-Identifier: MIT
//! Fixed-committee records; transport authentication never replaces these signatures.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, SigningKey};
use serde::{Deserialize, Serialize};

#[path = "ConsensusSignatureCache.rs"]
mod signature_cache;

pub type Digest = [u8; 32];
pub type Key = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub network: Digest,
    pub incarnation: Digest,
    pub configuration: Digest,
    pub epoch: u64,
}
impl Scope {
    pub fn value(&self) -> V {
        V::Array(vec![
            bytes(&self.network),
            bytes(&self.incarnation),
            bytes(&self.configuration),
            V::Uint(self.epoch),
        ])
    }
    pub fn parse(value: &V) -> Result<Self> {
        let a = value.array(4)?;
        Ok(Self {
            network: nonzero(&a[0])?,
            incarnation: nonzero(&a[1])?,
            configuration: nonzero(&a[2])?,
            epoch: a[3].uint()?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Configuration {
    pub bytes: Vec<u8>,
    pub scope: Scope,
    pub voters: [Key; 4],
    pub bootstrap_time: u64,
    pub genesis_governance: Digest,
    pub bootstrap_anchor: Digest,
    pub bootstrap_origin_time: u64,
    pub historical_epochs: std::collections::BTreeMap<u64, (u64, u64)>,
    descriptor: crate::authority_proof::TrustDescriptor,
    pub(super) predecessor: Option<Box<Configuration>>,
}
impl Configuration {
    /// The caller independently authenticates the complete bootstrap before this call.
    pub fn trusted(bytes: &[u8]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let a = record(&value, 10, 11)?;
        ensure!(
            a[10].text()? == "BasicHotStuff" && a[4].uint()? == 0,
            "Unsupported fixed committee descriptor"
        );
        let mut voters = Vec::new();
        for value in a[5].list(4)? {
            let key = value.fixed::<32>()?;
            wire::valid_key(&key)?;
            ensure!(
                voters.last().is_none_or(|previous| previous < &key),
                "Voters are repeated or unordered"
            );
            voters.push(key);
        }
        let voters: [Key; 4] = voters
            .try_into()
            .map_err(|_| anyhow::anyhow!("Exactly four voters are required"))?;
        nonzero(&a[6])?;
        nonzero(&a[7])?;
        Ok(Self {
            bytes: bytes.to_vec(),
            scope: Scope {
                network: nonzero(&a[2])?,
                incarnation: nonzero(&a[3])?,
                configuration: wire::digest(bytes),
                epoch: a[4].uint()?,
            },
            voters,
            bootstrap_time: a[9].uint()?,
            genesis_governance: nonzero(&a[8])?,
            bootstrap_anchor: nonzero(&a[8])?,
            bootstrap_origin_time: a[9].uint()?,
            historical_epochs: Default::default(),
            predecessor: None,
            descriptor: crate::authority_proof::TrustDescriptor::from_canonical(bytes)?,
        })
    }
    pub(crate) fn historical_voter(&self, key: &Key) -> bool {
        self.voters.contains(key)
            || self
                .predecessor
                .as_ref()
                .is_some_and(|old| old.historical_voter(key))
    }
    pub fn descriptor(&self) -> &crate::authority_proof::TrustDescriptor {
        &self.descriptor
    }
    pub(crate) fn successor(
        &self,
        terminal: &crate::authority_epoch::ValidatedTerminal,
    ) -> Result<Self> {
        let old = terminal.old_descriptor().scope();
        ensure!(
            self.scope.network == old.network
                && self.scope.incarnation == old.incarnation
                && self.scope.configuration == old.configuration
                && self.scope.epoch == old.epoch,
            "Epoch preparation has another predecessor"
        );
        let descriptor = crate::authority_proof::TrustDescriptor::from_epoch_preparation(terminal)?;
        let scope = terminal.successor_scope();
        let mut historical_epochs = self.historical_epochs.clone();
        historical_epochs.insert(
            self.scope.epoch,
            (
                terminal.checkpoint().height(),
                terminal.checkpoint().prefix().evaluated_at_ms(),
            ),
        );
        Ok(Self {
            bytes: terminal.successor_bytes().to_vec(),
            scope: Scope {
                network: scope.network,
                incarnation: scope.incarnation,
                configuration: scope.configuration,
                epoch: scope.epoch,
            },
            voters: terminal
                .declaration()
                .nominations
                .iter()
                .map(|n| n.voter)
                .collect::<Vec<_>>()
                .try_into()
                .expect("four validated nominations"),
            bootstrap_time: terminal.checkpoint().prefix().evaluated_at_ms(),
            genesis_governance: terminal.successor_state(),
            bootstrap_anchor: self.bootstrap_anchor,
            bootstrap_origin_time: self.bootstrap_origin_time,
            historical_epochs,
            descriptor,
            predecessor: Some(Box::new(self.clone())),
        })
    }
    pub(crate) fn evidence_context(
        &self,
        epoch: u64,
        height: u64,
        at: u64,
        current_height: u64,
    ) -> Result<Self> {
        let (maximum_height, maximum_time) = if epoch == self.scope.epoch {
            (current_height, u64::MAX)
        } else {
            *self
                .historical_epochs
                .get(&epoch)
                .context("Mutation provenance has no authenticated epoch boundary")?
        };
        ensure!(
            height > 0
                && height <= maximum_height
                && at >= self.bootstrap_origin_time
                && at <= maximum_time,
            "Mutation provenance exceeds its authenticated epoch"
        );
        let mut context = self.clone();
        context.scope.epoch = epoch;
        Ok(context)
    }
    pub fn member(&self, key: &Key) -> Result<usize> {
        self.voters
            .binary_search(key)
            .map_err(|_| anyhow::anyhow!("Signer is outside the fixed committee"))
    }
    pub fn leader(&self, view: u64) -> Result<Key> {
        ensure!(view > 0, "Genesis has no proposing leader");
        Ok(self.voters[((view - 1) % 4) as usize])
    }
    pub fn genesis(&self) -> Node {
        Node {
            scope: self.scope.clone(),
            view: 0,
            height: 0,
            parent: None,
            command: None,
            evaluated_at: self.bootstrap_time,
            justify: None,
        }
    }
    pub fn genesis_qc(&self) -> Result<Certificate> {
        Certificate::parse(
            self,
            &wire::encode(&V::Array(vec![
                V::Uint(12),
                V::Uint(1),
                self.scope.value(),
                V::Null,
                V::Array(vec![]),
            ]))?,
        )
    }
}
pub fn bytes(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
pub fn nonzero(value: &V) -> Result<Digest> {
    let result = value.fixed::<32>()?;
    ensure!(result != [0; 32], "Zero identifier");
    Ok(result)
}
pub fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let a = value.array(arity)?;
    ensure!(
        a[0].uint()? == kind && a[1].uint()? == 1,
        "Unexpected record kind or version"
    );
    Ok(a)
}
fn optional(value: &V) -> Result<Option<Digest>> {
    if *value == V::Null {
        Ok(None)
    } else {
        Ok(Some(nonzero(value)?))
    }
}
fn option(value: &Option<Digest>) -> V {
    value.as_ref().map_or(V::Null, |v| bytes(v))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Prepare,
    PreCommit,
    Commit,
}
impl Phase {
    pub fn number(self) -> u64 {
        match self {
            Self::Prepare => 0,
            Self::PreCommit => 1,
            Self::Commit => 2,
        }
    }
    pub fn parse(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Prepare),
            1 => Ok(Self::PreCommit),
            2 => Ok(Self::Commit),
            _ => anyhow::bail!("Unknown voting phase"),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub scope: Scope,
    pub view: u64,
    pub phase: Phase,
    pub node: Digest,
}
impl Vote {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.view > 0, "Genesis cannot receive votes");
        wire::encode(&V::Array(vec![
            V::Uint(11),
            V::Uint(1),
            self.scope.value(),
            V::Uint(self.view),
            V::Uint(self.phase.number()),
            bytes(&self.node),
        ]))
    }
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let v = wire::decode(input)?;
        let a = record(&v, 11, 6)?;
        let result = Self {
            scope: Scope::parse(&a[2])?,
            view: a[3].uint()?,
            phase: Phase::parse(a[4].uint()?)?,
            node: nonzero(&a[5])?,
        };
        ensure!(
            result.scope == config.scope && result.view > 0,
            "Vote scope or view differs"
        );
        Ok(result)
    }
}
#[derive(Clone, Debug)]
pub struct SignedVote {
    pub vote: Vote,
    pub signer: Key,
    pub signature: [u8; 64],
    pub envelope: Vec<u8>,
}
impl SignedVote {
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let (payload, signatures) = wire::envelope(input, 1)?;
        ensure!(signatures.len() == 1, "A vote has one signer");
        let (signer, signature) = signatures[0];
        config.member(&signer)?;
        Ok(Self {
            vote: Vote::parse(config, &payload)?,
            signer,
            signature,
            envelope: input.to_vec(),
        })
    }
    pub fn sign(config: &Configuration, vote: Vote, key: &SigningKey) -> Result<Self> {
        Self::parse(config, &wire::sign_envelope(&vote.encode()?, key)?)
    }
}
#[derive(Clone, Debug)]
pub struct Certificate {
    identity: Digest,
    pub bytes: Vec<u8>,
    pub vote: Option<Vote>,
    pub node: Digest,
    pub view: u64,
    pub phase: Phase,
}
#[cfg(test)]
thread_local! {
    static CERTIFICATE_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CERTIFICATE_SIGNATURE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
impl Certificate {
    /// Quorum membership changes the proof bytes, not the certified vote's identity.
    pub(super) fn vote_digest(vote: &Vote) -> Result<Digest> {
        Ok(wire::digest(&wire::encode(&V::Array(vec![
            V::Uint(12),
            V::Uint(1),
            vote.scope.value(),
            bytes(&vote.encode()?),
            V::Array(vec![]),
        ]))?))
    }
    #[cfg(test)]
    pub(super) fn parse_count() -> usize {
        CERTIFICATE_PARSES.get()
    }
    #[cfg(test)]
    pub(super) fn signature_check_count() -> usize {
        CERTIFICATE_SIGNATURE_CHECKS.get()
    }
    pub fn digest(&self) -> Digest {
        self.identity
    }
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        #[cfg(test)]
        CERTIFICATE_PARSES.set(CERTIFICATE_PARSES.get() + 1);
        let v = wire::decode(input)?;
        let a = record(&v, 12, 5)?;
        ensure!(
            Scope::parse(&a[2])? == config.scope,
            "Certificate scope differs"
        );
        let pairs = a[4].list(4)?;
        if a[3] == V::Null {
            ensure!(pairs.is_empty(), "Genesis certificate has no signatures");
            return Ok(Self {
                identity: wire::digest(input),
                bytes: input.to_vec(),
                vote: None,
                node: config.genesis().digest()?,
                view: 0,
                phase: Phase::Prepare,
            });
        }
        let payload = a[3].bytes()?;
        let vote = Vote::parse(config, payload)?;
        ensure!(pairs.len() >= 3, "Certificate quorum is missing");
        let verified = signature_cache::contains(input);
        let mut prior = None;
        for pair in pairs {
            let pair = pair.array(2)?;
            let signer = pair[0].fixed::<32>()?;
            config.member(&signer)?;
            ensure!(
                prior.is_none_or(|p| p < signer),
                "Certificate signers are repeated or unordered"
            );
            let key = wire::valid_key(&signer)?;
            let signature = Signature::from_bytes(&pair[1].fixed::<64>()?);
            if !verified {
                let start = std::time::Instant::now();
                let result =
                    key.verify_strict(&wire::signature_message(payload, &signer), &signature);
                super::timing::certificate_signature(start.elapsed());
                #[cfg(test)]
                CERTIFICATE_SIGNATURE_CHECKS.set(CERTIFICATE_SIGNATURE_CHECKS.get() + 1);
                result?;
            }
            prior = Some(signer);
        }
        let certificate = Self {
            identity: Self::vote_digest(&vote)?,
            bytes: input.to_vec(),
            node: vote.node,
            view: vote.view,
            phase: vote.phase,
            vote: Some(vote),
        };
        if verified {
            super::timing::certificate_cache_hit();
        } else {
            signature_cache::remember(input);
        }
        Ok(certificate)
    }
    pub fn collect(config: &Configuration, votes: &[SignedVote]) -> Result<Self> {
        ensure!(
            (3..=4).contains(&votes.len()),
            "Certificate needs three or four votes"
        );
        let first = &votes[0].vote;
        let mut sorted = votes.to_vec();
        sorted.sort_by_key(|v| v.signer);
        ensure!(
            sorted.iter().all(|v| &v.vote == first),
            "Certificate mixes vote statements"
        );
        Self::parse(
            config,
            &wire::encode(&V::Array(vec![
                V::Uint(12),
                V::Uint(1),
                config.scope.value(),
                bytes(&first.encode()?),
                V::Array(
                    sorted
                        .iter()
                        .map(|v| V::Array(vec![bytes(&v.signer), bytes(&v.signature)]))
                        .collect(),
                ),
            ]))?,
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub scope: Scope,
    pub view: u64,
    pub height: u64,
    pub parent: Option<Digest>,
    pub command: Option<Digest>,
    pub evaluated_at: u64,
    pub justify: Option<Digest>,
}
impl Node {
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(14),
            V::Uint(1),
            self.scope.value(),
            V::Uint(self.view),
            V::Uint(self.height),
            option(&self.parent),
            option(&self.command),
            V::Uint(self.evaluated_at),
            option(&self.justify),
        ]))
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(wire::digest(&self.encode()?))
    }
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let v = wire::decode(input)?;
        let a = record(&v, 14, 9)?;
        let result = Self {
            scope: Scope::parse(&a[2])?,
            view: a[3].uint()?,
            height: a[4].uint()?,
            parent: optional(&a[5])?,
            command: optional(&a[6])?,
            evaluated_at: a[7].uint()?,
            justify: optional(&a[8])?,
        };
        ensure!(result.scope == config.scope, "Node scope differs");
        if result.height == 0 || result.view == 0 {
            ensure!(
                result == config.genesis(),
                "Only the pinned genesis may have zero position"
            );
        } else {
            ensure!(
                result.parent.is_some() && result.command.is_some() && result.justify.is_some(),
                "Node dependencies are missing"
            );
        }
        Ok(result)
    }
}
#[derive(Clone, Debug)]
pub struct NewView {
    pub view: u64,
    pub prepare: Digest,
    pub signer: Key,
    pub envelope: Vec<u8>,
}
impl NewView {
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let (payload, signatures) = wire::envelope(input, 1)?;
        let a = wire::decode(&payload)?;
        let a = record(&a, 13, 5)?;
        ensure!(
            Scope::parse(&a[2])? == config.scope && a[3].uint()? > 0,
            "New-view scope or view differs"
        );
        let signer = signatures.first().context("New-view signer missing")?.0;
        config.member(&signer)?;
        Ok(Self {
            view: a[3].uint()?,
            prepare: nonzero(&a[4])?,
            signer,
            envelope: input.to_vec(),
        })
    }
    pub fn sign(
        config: &Configuration,
        view: u64,
        prepare: Digest,
        key: &SigningKey,
    ) -> Result<Self> {
        Self::parse(
            config,
            &wire::sign_envelope(
                &wire::encode(&V::Array(vec![
                    V::Uint(13),
                    V::Uint(1),
                    config.scope.value(),
                    V::Uint(view),
                    bytes(&prepare),
                ]))?,
                key,
            )?,
        )
    }
}

/// The inert command is consensus progress only and carries no user authority.
pub enum Command {
    Ordered(OrderedRequest),
    Inert,
    Noop(Digest),
}
impl Command {
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let value = wire::decode(input)?;
        let values = value.list(23)?;
        match values.first().context("Command kind missing")?.uint()? {
            22 => Ok(Self::Ordered(OrderedRequest::parse(config, input)?)),
            53 => {
                let a = record(&value, 53, 4)?;
                ensure!(
                    Scope::parse(&a[2])? == config.scope,
                    "Inert command scope differs"
                );
                if a[3] == V::Null {
                    Ok(Self::Inert)
                } else {
                    Ok(Self::Noop(nonzero(&a[3])?))
                }
            }
            _ => anyhow::bail!("Unsupported consensus command"),
        }
    }
    pub fn inert(config: &Configuration) -> Result<Vec<u8>> {
        wire::encode(&V::Array(vec![
            V::Uint(53),
            V::Uint(1),
            config.scope.value(),
            V::Null,
        ]))
    }
    pub fn minimum_height(&self) -> u64 {
        match self {
            Self::Ordered(request) => request.minimum_height,
            Self::Inert | Self::Noop(_) => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OrderedRequest {
    pub intent: Digest,
    pub challenge: Digest,
    pub requester: Key,
    pub recipient: Key,
    pub action: String,
    pub resource: Digest,
    pub revision: u64,
    pub profile_generation: u64,
    pub minimum_height: u64,
    pub expires: u64,
}
impl OrderedRequest {
    pub fn parse(config: &Configuration, input: &[u8]) -> Result<Self> {
        let value = wire::decode(input)?;
        let a = record(&value, 22, 6)?;
        ensure!(
            Scope::parse(&a[2])? == config.scope,
            "Ordered request scope differs"
        );
        let request = crate::authority_proof::SignedRequest::from_signed(a[3].bytes()?)?;
        let challenge = crate::authority_proof::Challenge::from_signed(a[4].bytes()?)?;
        challenge.validate_request(&request)?;
        if request.action() == "Reconfigure" {
            crate::authority_epoch::Declaration::from_intent(request.ordinary()?)?;
        }
        ensure!(
            request.network() == config.scope.network
                && request.incarnation() == config.scope.incarnation
                && challenge.network == config.scope.network
                && challenge.incarnation == config.scope.incarnation,
            "Request or challenge network differs"
        );
        ensure!(
            challenge.intent == request.digest(),
            "Challenge names another request"
        );
        let expires = a[5].uint()?;
        ensure!(
            expires > challenge.created_at_ms && expires <= challenge.expires_at_ms,
            "Ordered challenge deadline differs"
        );
        Ok(Self {
            intent: request.digest(),
            challenge: challenge.digest,
            requester: request.requester(),
            recipient: challenge.recipient,
            action: request.action().into(),
            resource: request.resource(),
            revision: request.revision(),
            profile_generation: request.profile_generation(),
            minimum_height: request.minimum_policy_height(),
            expires,
        })
    }
}

#[cfg(test)]
#[path = "ConsensusCertificateTests.rs"]
mod certificate_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn federation_freshness_ordered_parser_enforces_the_exact_request_profile() {
        for (duration, maintenance, accepted) in [
            (5000, false, true),
            (5001, false, false),
            (15000, true, true),
        ] {
            let f = crate::authority_challenge::profile_tests::fixture(duration, maintenance);
            let config = Configuration::trusted(f.descriptor.canonical()).unwrap();
            assert_eq!(OrderedRequest::parse(&config, &f.ordered).is_ok(), accepted);
        }
    }
    pub fn initial() -> Vec<u8> {
        wire::encode(&V::Array(vec![
            V::Uint(15),
            V::Uint(1),
            bytes(&[7; 32]),
            bytes(&[8; 32]),
            V::Array(vec![]),
        ]))
        .unwrap()
    }
    pub fn fixture() -> (Configuration, [SigningKey; 4]) {
        let mut keys = [1, 2, 3, 4].map(|v| SigningKey::from_bytes(&[v; 32]));
        keys.sort_by_key(|k| k.verifying_key().to_bytes());
        let descriptor = wire::encode(&V::Array(vec![
            V::Uint(10),
            V::Uint(1),
            bytes(&[7; 32]),
            bytes(&[8; 32]),
            V::Uint(0),
            V::Array(
                keys.iter()
                    .map(|k| bytes(k.verifying_key().as_bytes()))
                    .collect(),
            ),
            bytes(&[9; 32]),
            bytes(&[10; 32]),
            bytes(&wire::digest(&initial())),
            V::Uint(10000),
            V::Text("BasicHotStuff".into()),
        ]))
        .unwrap();
        (Configuration::trusted(&descriptor).unwrap(), keys)
    }
    #[test]
    fn quorum_requires_exact_phase_node_scope_and_distinct_members() {
        let (config, keys) = fixture();
        let vote = Vote {
            scope: config.scope.clone(),
            view: 1,
            phase: Phase::Prepare,
            node: [12; 32],
        };
        let mut votes = keys[..3]
            .iter()
            .map(|key| SignedVote::sign(&config, vote.clone(), key).unwrap())
            .collect::<Vec<_>>();
        assert!(Certificate::collect(&config, &votes).is_ok());
        votes[2] = votes[1].clone();
        assert!(Certificate::collect(&config, &votes).is_err());
        votes[2] = SignedVote::sign(
            &config,
            Vote {
                phase: Phase::Commit,
                ..vote.clone()
            },
            &keys[2],
        )
        .unwrap();
        assert!(Certificate::collect(&config, &votes).is_err());
        assert!(SignedVote::sign(&config, vote, &SigningKey::from_bytes(&[22; 32])).is_err());
    }
}
