// SPDX-License-Identifier: MIT
// Canonical executed-result evidence binds one exact request to a certified prefix.
use crate::trust_wire::{self as wire, Value as V};
use anyhow::{Result, ensure};

pub type Digest = [u8; 32];
pub type Key = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub network: Digest,
    pub incarnation: Digest,
    pub configuration: Digest,
    pub epoch: u64,
}

fn record(value: &V, kind: u64, arity: usize) -> Result<&[V]> {
    let fields = value.array(arity)?;
    ensure!(
        fields[0].uint()? == kind && fields[1].uint()? == 1,
        "wrong record kind or version"
    );
    Ok(fields)
}
fn id(value: &V) -> Result<Digest> {
    let value = value.fixed::<32>()?;
    ensure!(value != [0; 32], "zero identifier");
    Ok(value)
}
fn key(value: &V) -> Result<Key> {
    let value = value.fixed::<32>()?;
    wire::valid_key(&value)?;
    Ok(value)
}
fn label(value: &V) -> Result<String> {
    let value = value.text()?;
    ensure!(
        (1..=64).contains(&value.len())
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid action label"
    );
    Ok(value.to_owned())
}
fn optional_digest(value: &V) -> Result<Option<Digest>> {
    if *value == V::Null {
        Ok(None)
    } else {
        Ok(Some(value.fixed::<32>()?))
    }
}
impl Scope {
    pub fn parse(value: &V) -> Result<Self> {
        let v = value.array(4)?;
        Ok(Self {
            network: id(&v[0])?,
            incarnation: id(&v[1])?,
            configuration: v[2].fixed()?,
            epoch: v[3].uint()?,
        })
    }
    pub fn value(&self) -> V {
        V::Array(vec![
            V::Bytes(self.network.to_vec()),
            V::Bytes(self.incarnation.to_vec()),
            V::Bytes(self.configuration.to_vec()),
            V::Uint(self.epoch),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct TrustDescriptor {
    canonical: Vec<u8>,
    scope: Scope,
    voters: [Key; 4],
    genesis_governance: Digest,
    bootstrap_time_ms: u64,
}
impl TrustDescriptor {
    /// Parsing establishes structure. The caller must independently authenticate this descriptor.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        Self::parse_epoch(bytes, 0)
    }
    pub(crate) fn from_epoch_preparation(
        terminal: &crate::authority_epoch::ValidatedTerminal,
    ) -> Result<Self> {
        Self::parse_epoch(terminal.successor_bytes(), terminal.successor_scope().epoch)
    }
    pub(crate) fn from_activation(
        activation: &crate::authority_epoch::ValidatedActivation,
    ) -> Result<Self> {
        Self::parse_epoch(
            activation.descriptor_bytes(),
            activation.terminal().successor_scope().epoch,
        )
    }
    fn parse_epoch(bytes: &[u8], epoch: u64) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let v = record(&value, 10, 11)?;
        let voters: Vec<_> = v[5].array(4)?.iter().map(key).collect::<Result<_>>()?;
        ensure!(
            voters.windows(2).all(|p| p[0] < p[1]),
            "unsorted or repeated voter"
        );
        ensure!(
            v[10].text()? == "BasicHotStuff" && v[4].uint()? == epoch,
            "unsupported authority configuration"
        );
        let network = id(&v[2])?;
        let incarnation = id(&v[3])?;
        ensure!(
            network != incarnation,
            "network and incarnation must differ"
        );
        v[6].fixed::<32>()?;
        v[7].fixed::<32>()?;
        Ok(Self {
            canonical: bytes.to_vec(),
            scope: Scope {
                network,
                incarnation,
                configuration: wire::digest(bytes),
                epoch,
            },
            voters: voters.try_into().expect("four voters"),
            genesis_governance: v[8].fixed()?,
            bootstrap_time_ms: v[9].uint()?,
        })
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    #[cfg(test)]
    pub fn voters(&self) -> &[Key; 4] {
        &self.voters
    }
    pub fn genesis(&self) -> Result<Prefix> {
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(14),
            V::Uint(1),
            self.scope.value(),
            V::Uint(0),
            V::Uint(0),
            V::Null,
            V::Null,
            V::Uint(self.bootstrap_time_ms),
            V::Null,
        ]))?;
        Ok(Prefix {
            scope: self.scope.clone(),
            height: 0,
            node: wire::digest(&bytes),
            policy_state: self.genesis_governance,
            view: 0,
            evaluated_at_ms: self.bootstrap_time_ms,
        })
    }
    pub(crate) fn quorum(&self, envelope: &[u8]) -> Result<Vec<u8>> {
        let (payload, signatures) = wire::envelope(envelope, 4)?;
        ensure!(
            signatures.len() >= 3 && signatures.iter().all(|(key, _)| self.voters.contains(key)),
            "authority statement requires three distinct enrolled voters"
        );
        Ok(payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionRef {
    pub kind: u64,
    pub id: Digest,
    pub generation: u64,
    pub digest: Digest,
}
impl VersionRef {
    fn parse(value: &V) -> Result<Self> {
        let v = value.array(4)?;
        let value = Self {
            kind: v[0].uint()?,
            id: id(&v[1])?,
            generation: v[2].uint()?,
            digest: v[3].fixed()?,
        };
        ensure!(value.generation > 0, "zero record generation");
        Ok(value)
    }
    pub fn index(&self) -> (u64, Digest) {
        (self.kind, self.id)
    }
}
pub fn validate_versions(values: &[VersionRef], maximum: usize) -> Result<()> {
    ensure!(
        values.len() <= maximum
            && values.windows(2).all(|p| p[0].index() < p[1].index())
            && values.iter().all(|v| v.id != [0; 32] && v.generation > 0),
        "invalid generation floor set"
    );
    Ok(())
}

#[path = "AuthorityRequest.rs"]
mod request;
pub use request::{Intent, SignedRequest};
#[path = "AuthorityStreamProof.rs"]
mod stream_proof;
#[cfg(test)]
pub use stream_proof::initial_generation_id;
pub use stream_proof::{CompletionMetadata, FenceOutcome, OwnStreamMetadata, StreamResponse};
pub(crate) fn validate_stream_response(
    request: &SignedRequest,
    result: &OperationResult,
    executed: &ExecutedResult,
    expected_stream: Option<&[u8]>,
) -> Result<StreamResponse> {
    stream_proof::validate(request, result, executed, expected_stream)
}

#[path = "AuthorityContinuity.rs"]
mod continuity;
pub use continuity::{ContinuityEvidence, validate_continuity};

#[derive(Clone, Debug)]
pub struct Challenge {
    pub network: Digest,
    pub incarnation: Digest,
    pub recipient: Key,
    pub boot_id: Digest,
    pub nonce: Digest,
    pub intent: Digest,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub maximum_duration_ms: u64,
    pub digest: Digest,
}
impl Challenge {
    pub fn validate_request(&self, request: &SignedRequest) -> Result<()> {
        ensure!(
            self.network == request.network()
                && self.incarnation == request.incarnation()
                && self.intent == request.digest()
                && self.maximum_duration_ms
                    <= crate::authority_challenge::maximum_duration_ms(request),
            "challenge exceeds its exact request's freshness profile"
        );
        Ok(())
    }
    /// Same-recipient completion times preserve causal order and conservative expiry.
    /// A historical completion does not establish fresh permission.
    pub fn completion_within_interval(&self, completed_at: u64, expires_at: u64) -> bool {
        completed_at >= self.created_at_ms
            && completed_at
                .checked_add(crate::authority_challenge::DELTA_MS)
                .is_some_and(|upper| upper < expires_at.min(self.expires_at_ms))
    }
    /// Challenge creation is a freshness claim, not a credential activation time.
    /// The cap starts at the earliest possible honest proposal admission.
    pub fn evaluation_expiry(&self, evaluated_at: u64, requested_expiry: u64) -> Result<u64> {
        let uncertainty = crate::authority_governance::UNCERTAINTY_MS;
        let lower = evaluated_at
            .checked_sub(uncertainty)
            .ok_or_else(|| anyhow::anyhow!("evaluation time underflow"))?;
        let upper = evaluated_at
            .checked_add(uncertainty)
            .ok_or_else(|| anyhow::anyhow!("evaluation time overflow"))?;
        ensure!(
            self.created_at_ms <= upper
                && requested_expiry <= self.expires_at_ms
                && upper < requested_expiry,
            "challenge timestamp or original expiry differs"
        );
        let cap = lower
            .checked_add(self.maximum_duration_ms)
            .ok_or_else(|| anyhow::anyhow!("evaluation expiry overflow"))?;
        let expires = requested_expiry.min(cap);
        ensure!(
            upper < expires,
            "challenge has no conservative validity remaining"
        );
        Ok(expires)
    }
    /// Parse the signed interval; validate_request enforces its exact operation's profile.
    pub fn from_signed(bytes: &[u8]) -> Result<Self> {
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        let value = wire::decode(&payload)?;
        let v = record(&value, 21, 12)?;
        id(&v[8])?;
        let recipient = key(&v[4])?;
        ensure!(
            signatures[0].0 == recipient,
            "challenge signer differs from recipient"
        );
        let c = Self {
            network: id(&v[2])?,
            incarnation: id(&v[3])?,
            recipient,
            boot_id: id(&v[5])?,
            nonce: id(&v[6])?,
            intent: v[7].fixed()?,
            created_at_ms: v[9].uint()?,
            expires_at_ms: v[10].uint()?,
            maximum_duration_ms: v[11].uint()?,
            digest: wire::digest(&payload),
        };
        ensure!(
            (1..=crate::authority_challenge::FEDERATION_DURATION_MS)
                .contains(&c.maximum_duration_ms)
                && c.expires_at_ms > c.created_at_ms
                && c.expires_at_ms
                    <= c.created_at_ms
                        .checked_add(c.maximum_duration_ms)
                        .ok_or_else(|| anyhow::anyhow!("challenge time overflow"))?,
            "invalid challenge interval"
        );
        Ok(c)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Permit,
    Refuse,
    Pending,
}
#[derive(Debug)]
pub struct OperationResult {
    pub action: String,
    pub disposition: Disposition,
    pub code: u64,
    pub value: Vec<u8>,
}
impl OperationResult {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let v = record(&value, 24, 6)?;
        let code = v[4].uint()?;
        let disposition = match (v[3].uint()?, code) {
            (0, 0) => Disposition::Permit,
            (1, 1..=38) => Disposition::Refuse,
            (2, 25 | 27 | 30) => Disposition::Pending,
            _ => anyhow::bail!("invalid result disposition or code"),
        };
        let bytes = v[5].bytes()?.to_vec();
        wire::decode(&bytes)?;
        Ok(Self {
            action: label(&v[2])?,
            disposition,
            code,
            value: bytes,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restrictions {
    pub consent: Option<Digest>,
    pub placement: Option<Digest>,
    pub route: Option<Digest>,
}
#[derive(Clone, Debug)]
pub struct ExecutedResult {
    pub scope: Scope,
    pub height: u64,
    pub committed_node: Digest,
    pub ordered_request: Digest,
    pub intent: Digest,
    pub challenge: Digest,
    pub requester: Key,
    pub recipient: Key,
    pub action: String,
    pub resource: Digest,
    pub revision: u64,
    pub profile_generation: u64,
    pub maximum_effect: u64,
    pub result: Digest,
    pub policy_state: Digest,
    pub minimum_policy_height: u64,
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
    pub restrictions: Restrictions,
}
impl ExecutedResult {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self> {
        let value = wire::decode(payload)?;
        let v = record(&value, 23, 23)?;
        Ok(Self {
            scope: Scope::parse(&v[2])?,
            height: v[3].uint()?,
            committed_node: v[4].fixed()?,
            ordered_request: v[5].fixed()?,
            intent: v[6].fixed()?,
            challenge: v[7].fixed()?,
            requester: key(&v[8])?,
            recipient: key(&v[9])?,
            action: label(&v[10])?,
            resource: id(&v[11])?,
            revision: v[12].uint()?,
            profile_generation: v[13].uint()?,
            maximum_effect: v[14].uint()?,
            result: v[15].fixed()?,
            policy_state: v[16].fixed()?,
            minimum_policy_height: v[17].uint()?,
            evaluated_at_ms: v[18].uint()?,
            expires_at_ms: v[19].uint()?,
            restrictions: Restrictions {
                consent: optional_digest(&v[20])?,
                placement: optional_digest(&v[21])?,
                route: optional_digest(&v[22])?,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    scope: Scope,
    height: u64,
    node: Digest,
    policy_state: Digest,
    view: u64,
    evaluated_at_ms: u64,
}
impl Prefix {
    pub(crate) fn checkpoint(anchor: &Node, state: Digest) -> Self {
        Self {
            scope: anchor.scope.clone(),
            height: anchor.height,
            node: anchor.digest,
            policy_state: state,
            view: anchor.view,
            evaluated_at_ms: anchor.evaluated_at_ms,
        }
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn node(&self) -> &Digest {
        &self.node
    }
    pub fn policy_state(&self) -> &Digest {
        &self.policy_state
    }
    pub(crate) fn view(&self) -> u64 {
        self.view
    }
    pub(crate) fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }
}
#[derive(Clone)]
pub(crate) struct Node {
    canonical: Vec<u8>,
    digest: Digest,
    scope: Scope,
    view: u64,
    height: u64,
    parent: Digest,
    command: Digest,
    evaluated_at_ms: u64,
}
impl Node {
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }
    pub(crate) fn height(&self) -> u64 {
        self.height
    }
    pub(crate) fn view(&self) -> u64 {
        self.view
    }
    pub(crate) fn parent(&self) -> &Digest {
        &self.parent
    }
    pub(crate) fn digest(&self) -> &Digest {
        &self.digest
    }
    pub(crate) fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let v = record(&value, 14, 9)?;
        let n = Self {
            canonical: bytes.to_vec(),
            digest: wire::digest(bytes),
            scope: Scope::parse(&v[2])?,
            view: v[3].uint()?,
            height: v[4].uint()?,
            parent: v[5].fixed()?,
            command: v[6].fixed()?,
            evaluated_at_ms: v[7].uint()?,
        };
        v[8].fixed::<32>()?;
        ensure!(
            n.height > 0 && n.view > 0,
            "non-genesis node requires positive position"
        );
        Ok(n)
    }
}

#[derive(Clone)]
pub struct CertifiedPoint {
    prefix: Prefix,
    certificate: Vec<u8>,
    tip: Node,
}
impl CertifiedPoint {
    pub fn from_evidence(
        descriptor: &TrustDescriptor,
        certificate: &[u8],
        node: &[u8],
    ) -> Result<Self> {
        let result = ExecutedResult::parse(&descriptor.quorum(certificate)?)?;
        let node = Node::parse(node)?;
        ensure!(
            result.scope == *descriptor.scope()
                && node.scope == result.scope
                && result.height == node.height
                && result.committed_node == node.digest
                && result.ordered_request == node.command
                && result.evaluated_at_ms == node.evaluated_at_ms,
            "certificate does not bind this committed node"
        );
        Ok(Self {
            prefix: Prefix {
                scope: node.scope.clone(),
                height: node.height,
                node: node.digest,
                policy_state: result.policy_state,
                view: node.view,
                evaluated_at_ms: node.evaluated_at_ms,
            },
            certificate: certificate.to_vec(),
            tip: node,
        })
    }
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    pub fn node(&self) -> &[u8] {
        &self.tip.canonical
    }
}

pub struct ProofContext<'a> {
    pub intent: &'a [u8],
    pub challenge: &'a [u8],
    pub restrictions: Restrictions,
    pub minimum_height: u64,
    pub maximum_effect: u64,
    /// Exact verified metadata retained before signing a fence; absent for other requests.
    pub expected_stream: Option<&'a [u8]>,
}
pub struct Response<'a> {
    pub ordered_request: &'a [u8],
    pub operation_result: &'a [u8],
    pub certificate: &'a [u8],
    /// Contiguous nodes ending at the certified point; at most 128 per bounded repair.
    pub ancestry: &'a [Vec<u8>],
}
pub struct ActionValidation {
    generations: Vec<VersionRef>,
    updates: Vec<(VersionRef, VersionRef)>,
}
impl ActionValidation {
    /// These exact generations must be established by the action's typed result schema.
    pub fn new(generations: Vec<VersionRef>) -> Result<Self> {
        validate_versions(&generations, 64)?;
        Ok(Self {
            generations,
            updates: Vec::new(),
        })
    }
    /// The typed action validator has checked each exact predecessor and canonical successor record.
    pub fn mutation(
        generations: Vec<VersionRef>,
        updates: Vec<(VersionRef, VersionRef)>,
    ) -> Result<Self> {
        let mut result = Self::new(generations)?;
        ensure!(
            updates.len() <= 64 && updates.windows(2).all(|w| w[0].0.index() < w[1].0.index()),
            "mutation transitions must be bounded, sorted and unique"
        );
        for (old, new) in &updates {
            ensure!(
                old.index() == new.index()
                    && old.generation.checked_add(1) == Some(new.generation)
                    && old.digest != new.digest
                    && result.generations.contains(new),
                "mutation transition is not an exact consecutive certified update"
            );
        }
        result.updates = updates;
        Ok(result)
    }
    /// A complete owner application list carries only bounded lifecycle metadata.
    #[cfg(test)]
    pub fn application_list(generations: Vec<VersionRef>) -> Result<Self> {
        validate_versions(&generations, 192)?;
        ensure!(
            generations
                .iter()
                .all(|v| matches!(v.kind, 102 | 127 | 128)),
            "application list contains an unsupported record kind"
        );
        Ok(Self {
            generations,
            updates: Vec::new(),
        })
    }
}
pub struct VerifiedResult {
    pub(crate) point: CertifiedPoint,
    pub(crate) request: SignedRequest,
    pub(crate) challenge: Challenge,
    pub(crate) executed: ExecutedResult,
    pub(crate) result: OperationResult,
    pub(crate) generations: Vec<VersionRef>,
    updates: Vec<(VersionRef, VersionRef)>,
    canonical_result: Vec<u8>,
    stream_response: Option<StreamResponse>,
    ancestry: Vec<Node>,
    history: Option<crate::authority_history::ValidatedHistory>,
}
impl VerifiedResult {
    pub(crate) fn validates_update(&self, old: &VersionRef, new: &VersionRef) -> bool {
        self.updates.iter().any(|(a, b)| a == old && b == new)
    }
    pub fn request(&self) -> &SignedRequest {
        &self.request
    }
    pub fn stream_response(&self) -> Option<&StreamResponse> {
        self.stream_response.as_ref()
    }
    pub(crate) fn operation_result_bytes(&self) -> &[u8] {
        &self.canonical_result
    }
    pub fn continuity(&self) -> ContinuityEvidence {
        ContinuityEvidence {
            ancestry: self.ancestry.iter().map(|n| n.canonical.clone()).collect(),
            history: self.history.as_ref().map(|h| h.canonical().to_vec()),
        }
    }
    pub fn disposition(&self) -> Disposition {
        self.result.disposition
    }
    pub fn code(&self) -> u64 {
        self.result.code
    }
    pub fn point(&self) -> &CertifiedPoint {
        &self.point
    }
    pub(crate) fn history(&self) -> Option<&crate::authority_history::ValidatedHistory> {
        self.history.as_ref()
    }
    pub(crate) fn attach_history(
        mut self,
        history: crate::authority_history::ValidatedHistory,
    ) -> Result<Self> {
        ensure!(
            self.history.is_none(),
            "authority history is already attached"
        );
        self.extends_contiguous(&history.ordinary_checkpoint()?.prefix())?;
        self.history = Some(history);
        Ok(self)
    }
    pub fn extends(&self, floor: &Prefix) -> Result<()> {
        if self.point.prefix == *floor {
            return Ok(());
        }
        if let Some(history) = &self.history {
            ensure!(
                history.from() == floor,
                "history transition starts at another retained prefix"
            );
            self.extends_contiguous(&history.ordinary_checkpoint()?.prefix())
        } else {
            self.extends_contiguous(floor)
        }
    }
    fn extends_contiguous(&self, floor: &Prefix) -> Result<()> {
        continuity::extends(&self.point, &self.ancestry, floor)
    }
}

/// Ordinary actions require their typed validator; named stream controls use the fixed built-in schema.
pub fn verify_response(
    descriptor: &TrustDescriptor,
    expected: ProofContext<'_>,
    response: Response<'_>,
    validate_action: impl FnOnce(&Intent, &OperationResult, &ExecutedResult) -> Result<ActionValidation>,
) -> Result<VerifiedResult> {
    ensure!(
        !response.ancestry.is_empty()
            && response.ancestry.len() <= 128
            && response
                .ancestry
                .iter()
                .try_fold(0usize, |sum, b| sum.checked_add(b.len()))
                .is_some_and(|n| n <= wire::MAXIMUM),
        "ancestry exceeds bounded repair limit"
    );
    let request = SignedRequest::from_signed(expected.intent)?;
    let challenge = Challenge::from_signed(expected.challenge)?;
    challenge.validate_request(&request)?;
    let value = wire::decode(response.ordered_request)?;
    let ordered = record(&value, 22, 6)?;
    let scope = Scope::parse(&ordered[2])?;
    let ordered_expiry = ordered[5].uint()?;
    ensure!(
        scope == *descriptor.scope()
            && ordered[3].bytes()? == expected.intent
            && ordered[4].bytes()? == expected.challenge
            && ordered_expiry <= challenge.expires_at_ms,
        "ordered request differs from exact local request context"
    );
    ensure!(
        request.network() == scope.network
            && request.incarnation() == scope.incarnation
            && challenge.network == scope.network
            && challenge.incarnation == scope.incarnation
            && challenge.intent == request.digest(),
        "intent or challenge belongs to another request"
    );
    let result = OperationResult::parse(response.operation_result)?;
    let executed = ExecutedResult::parse(&descriptor.quorum(response.certificate)?)?;
    ensure!(
        executed.scope == scope
            && executed.ordered_request == wire::digest(response.ordered_request)
            && executed.intent == request.digest()
            && executed.challenge == challenge.digest
            && executed.requester == request.requester()
            && executed.recipient == challenge.recipient
            && executed.action == request.action()
            && result.action == request.action()
            && executed.resource == request.resource()
            && executed.revision == request.revision()
            && executed.profile_generation == request.profile_generation()
            && executed.minimum_policy_height == request.minimum_policy_height()
            && executed.height >= expected.minimum_height
            && executed.result == wire::digest(response.operation_result)
            && executed.restrictions == expected.restrictions
            && executed.maximum_effect <= expected.maximum_effect
            && executed.expires_at_ms <= ordered_expiry,
        "executed result differs from exact request, result or restrictions"
    );
    ensure!(
        result.disposition == Disposition::Permit || executed.maximum_effect == 0,
        "non-permit result cannot authorise an effect"
    );
    if result.disposition == Disposition::Permit {
        ensure!(
            executed.evaluated_at_ms < executed.expires_at_ms,
            "permit is already expired at evaluation"
        );
    }
    if result.disposition == Disposition::Permit {
        ensure!(
            request.minimum_policy_epoch() == scope.epoch
                && executed.height >= request.minimum_policy_height(),
            "permit belongs to another minimum policy epoch"
        );
    }
    let ancestry = continuity::ancestry(&scope, response.ancestry)?;
    let tip = ancestry.last().expect("nonempty ancestry");
    let point = CertifiedPoint::from_evidence(descriptor, response.certificate, &tip.canonical)?;
    if result.disposition == Disposition::Permit {
        ensure!(
            executed.expires_at_ms
                == challenge.evaluation_expiry(executed.evaluated_at_ms, executed.expires_at_ms)?,
            "permit exceeds its conservative challenge expiry"
        );
    }
    let (action, stream_response) = match &request {
        SignedRequest::Intent(intent) => {
            ensure!(
                expected.expected_stream.is_none(),
                "ordinary intent cannot name expected fence metadata"
            );
            (validate_action(intent, &result, &executed)?, None)
        }
        SignedRequest::StreamStatus(_) | SignedRequest::StreamFence(_) => (
            ActionValidation::new(Vec::new())?,
            Some(stream_proof::validate(
                &request,
                &result,
                &executed,
                expected.expected_stream,
            )?),
        ),
    };
    ensure!(
        action.updates.is_empty()
            || result.disposition == Disposition::Permit
                && action
                    .updates
                    .iter()
                    .all(|(old, _)| request.expected().contains(old)),
        "mutation transition lacks its exact successful signed precondition"
    );
    Ok(VerifiedResult {
        point,
        request,
        challenge,
        executed,
        result,
        generations: action.generations,
        updates: action.updates,
        canonical_result: response.operation_result.to_vec(),
        stream_response,
        ancestry,
        history: None,
    })
}

#[cfg(test)]
#[path = "AuthorityProofTests.rs"]
pub(crate) mod tests;
