// SPDX-License-Identifier: MIT
//! Authenticated peer records and TLS bindings for the fixed authority committee.
use super::{
    archive, checkpoint,
    records::{
        self, Certificate, Command, Configuration, Digest, Key, NewView, Node, OrderedRequest,
        Scope, SignedVote,
    },
    repair::{Item, Reference},
    synchronizer,
};
use crate::{
    authority_files as files,
    authority_objects::Reference as InputReference,
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

/// These anchors only identify already verified local evidence; parsing grants no trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputAnchor {
    Certificate(Digest),
    Checkpoint(Digest),
}
impl InputAnchor {
    pub fn value(&self) -> V {
        let (kind, digest) = match self {
            Self::Certificate(d) => (0, d),
            Self::Checkpoint(d) => (1, d),
        };
        V::Array(vec![V::Uint(kind), V::Bytes(digest.to_vec())])
    }
    pub fn parse(value: &V) -> Result<Self> {
        let fields = value.array(2)?;
        let digest = fields[1].fixed()?;
        ensure!(digest != [0; 32], "zero input repair anchor");
        match fields[0].uint()? {
            0 => Ok(Self::Certificate(digest)),
            1 => Ok(Self::Checkpoint(digest)),
            _ => anyhow::bail!("unknown input repair anchor"),
        }
    }
}

pub const MAX_PAYLOAD: usize = 196608;
pub const MAX_REPAIR_RECORDS: usize = 16;
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Wish(Vec<u8>),
    NewView(Vec<u8>, Vec<u8>),
    Proposal(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    Vote(Vec<u8>),
    Certificate(Vec<u8>),
    RepairRequest(Digest, Vec<Reference>),
    RepairResponse(Digest, Vec<Item>),
    Execution(Vec<u8>, Vec<u8>, Vec<u8>),
    Submit(Vec<u8>, Vec<u8>),
    Query(Digest),
    Ack(Digest, u64),
    CheckpointShare(Vec<u8>),
    CheckpointProof(Vec<u8>),
    StateRequest(Digest, Digest, u64),
    StateResponse(Digest, Vec<u8>),
    ArchiveRequest(Digest, Digest, u64, u64),
    ArchiveResponse(Digest, Digest, u64, Vec<Digest>),
    CheckpointSuperseded(Digest, Digest, Vec<u8>),
    InputRequest(Digest, InputAnchor, InputReference),
    InputResponse(Digest, InputAnchor, InputReference, Option<Vec<u8>>),
}
impl Message {
    pub fn number(&self) -> u64 {
        match self {
            Self::Wish(_) => 0,
            Self::NewView(..) => 1,
            Self::Proposal(..) => 2,
            Self::Vote(_) => 3,
            Self::Certificate(_) => 4,
            Self::RepairRequest(..) => 5,
            Self::RepairResponse(..) => 6,
            Self::Execution(..) => 7,
            Self::Submit(..) => 8,
            Self::Query(_) => 9,
            Self::Ack(..) => 10,
            Self::CheckpointShare(..) => 11,
            Self::CheckpointProof(..) => 12,
            Self::StateRequest(..) => 13,
            Self::StateResponse(..) => 14,
            Self::ArchiveRequest(..) => 15,
            Self::ArchiveResponse(..) => 16,
            Self::CheckpointSuperseded(..) => 17,
            Self::InputRequest(..) => 18,
            Self::InputResponse(..) => 19,
        }
    }
    pub fn payload(&self) -> Result<Vec<u8>> {
        let b = records::bytes;
        match self {
            Self::Wish(v)
            | Self::Vote(v)
            | Self::Certificate(v)
            | Self::CheckpointShare(v)
            | Self::CheckpointProof(v) => Ok(v.clone()),
            Self::NewView(report, qc) => wire::encode(&V::Array(vec![b(report), b(qc)])),
            Self::Execution(node, command, qc) => {
                wire::encode(&V::Array(vec![b(node), b(command), b(qc)]))
            }
            Self::Submit(command, inputs) => {
                wire::encode(&V::Array(vec![b(command), wire::decode(inputs)?]))
            }
            Self::Proposal(node, command, qc, inputs) => wire::encode(&V::Array(vec![
                b(node),
                b(command),
                b(qc),
                wire::decode(inputs)?,
            ])),
            Self::InputRequest(id, anchor, reference) => {
                wire::encode(&V::Array(vec![b(id), anchor.value(), reference.value()]))
            }
            Self::InputResponse(id, anchor, reference, bytes) => wire::encode(&V::Array(vec![
                b(id),
                anchor.value(),
                reference.value(),
                bytes.as_ref().map_or(V::Null, |body| b(body)),
            ])),
            Self::RepairRequest(id, refs) => wire::encode(&V::Array(vec![
                b(id),
                V::Array(refs.iter().map(reference_value).collect()),
            ])),
            Self::RepairResponse(id, items) => wire::encode(&V::Array(vec![
                b(id),
                V::Array(
                    items
                        .iter()
                        .map(|item| {
                            let mut r = match reference_value(&item.reference) {
                                V::Array(v) => v,
                                _ => unreachable!(),
                            };
                            r.push(b(&item.bytes));
                            V::Array(r)
                        })
                        .collect(),
                ),
            ])),
            Self::StateRequest(id, checkpoint, index) => {
                wire::encode(&V::Array(vec![b(id), b(checkpoint), V::Uint(*index)]))
            }
            Self::StateResponse(id, chunk) => wire::encode(&V::Array(vec![b(id), b(chunk)])),
            Self::CheckpointSuperseded(id, checkpoint, proof) => {
                wire::encode(&V::Array(vec![b(id), b(checkpoint), b(proof)]))
            }
            Self::ArchiveRequest(id, checkpoint, index, count) => wire::encode(&V::Array(vec![
                b(id),
                b(checkpoint),
                V::Uint(*index),
                V::Uint(*count),
            ])),
            Self::ArchiveResponse(id, checkpoint, index, leaves) => wire::encode(&V::Array(vec![
                b(id),
                b(checkpoint),
                V::Uint(*index),
                V::Array(leaves.iter().map(|d| b(d)).collect()),
            ])),
            Self::Query(id) => wire::encode(&V::Array(vec![b(id)])),
            Self::Ack(id, disposition) => {
                wire::encode(&V::Array(vec![b(id), V::Uint(*disposition)]))
            }
        }
    }
    pub fn parse(config: &Configuration, kind: u64, input: &[u8]) -> Result<Self> {
        ensure!(input.len() <= MAX_PAYLOAD, "Peer payload exceeds its bound");
        let value = wire::decode(input)?;
        Ok(match kind {
            0 => {
                synchronizer::verify(config, input)?;
                Self::Wish(input.to_vec())
            }
            1 => {
                let a = value.array(2)?;
                let report = NewView::parse(config, a[0].bytes()?)?;
                let qc = Certificate::parse(config, a[1].bytes()?)?;
                ensure!(
                    qc.phase == records::Phase::Prepare
                        && qc.digest() == report.prepare
                        && qc.view < report.view,
                    "NewView evidence differs"
                );
                Self::NewView(a[0].bytes()?.to_vec(), a[1].bytes()?.to_vec())
            }
            2 => {
                let a = value.array(4)?;
                let (payload, signatures) = wire::envelope(a[0].bytes()?, 1)?;
                let node = Node::parse(config, &payload)?;
                ensure!(
                    signatures.len() == 1 && signatures[0].0 == config.leader(node.view)?,
                    "Proposal signer differs"
                );
                Command::parse(config, a[1].bytes()?)?;
                let qc = Certificate::parse(config, a[2].bytes()?)?;
                ensure!(
                    node.command == Some(wire::digest(a[1].bytes()?))
                        && node.justify == Some(qc.digest())
                        && node.parent == Some(qc.node)
                        && qc.phase == records::Phase::Prepare
                        && qc.view < node.view,
                    "Proposal bindings differ"
                );
                Self::Proposal(
                    a[0].bytes()?.to_vec(),
                    a[1].bytes()?.to_vec(),
                    a[2].bytes()?.to_vec(),
                    wire::encode(&a[3])?,
                )
            }
            3 => {
                SignedVote::parse(config, input)?;
                Self::Vote(input.to_vec())
            }
            4 => {
                Certificate::parse(config, input)?;
                Self::Certificate(input.to_vec())
            }
            5 => {
                let a = value.array(2)?;
                let id = records::nonzero(&a[0])?;
                let mut seen = BTreeSet::new();
                let refs = a[1]
                    .list(MAX_REPAIR_RECORDS)?
                    .iter()
                    .map(|v| {
                        let r = parse_reference(config, v.array(3)?)?;
                        ensure!(seen.insert(r.clone()), "Repeated repair reference");
                        Ok(r)
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(!refs.is_empty(), "Empty repair request");
                Self::RepairRequest(id, refs)
            }
            6 => {
                let a = value.array(2)?;
                let id = records::nonzero(&a[0])?;
                let mut seen = BTreeSet::new();
                let items = a[1]
                    .list(MAX_REPAIR_RECORDS)?
                    .iter()
                    .map(|v| {
                        let a = v.array(4)?;
                        let reference = parse_reference(config, &a[..3])?;
                        ensure!(seen.insert(reference.clone()), "Repeated repair item");
                        let item = Item {
                            reference,
                            bytes: a[3].bytes()?.to_vec(),
                        };
                        validate_item(config, &item)?;
                        Ok(item)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Self::RepairResponse(id, items)
            }
            7 => {
                let a = value.array(3)?;
                let node = Node::parse(config, a[0].bytes()?)?;
                let (statement, signatures) = wire::envelope(a[1].bytes()?, 1)?;
                ensure!(
                    signatures.len() == 1,
                    "Execution share has more than one signer"
                );
                config.member(&signatures[0].0)?;
                let statement = wire::decode(&statement)?;
                let s = records::record(&statement, 23, 23)?;
                ensure!(
                    Scope::parse(&s[2])? == config.scope
                        && s[3].uint()? == node.height
                        && s[4].fixed::<32>()? == node.digest()?
                        && Some(s[5].fixed::<32>()?) == node.command
                        && s[18].uint()? == node.evaluated_at
                        && s[15].fixed::<32>()? == wire::digest(a[2].bytes()?),
                    "Execution context differs"
                );
                let result = wire::decode(a[2].bytes()?)?;
                let r = records::record(&result, 24, 6)?;
                ensure!(
                    r[2].text()? == s[10].text()? && r[3].uint()? <= 2 && r[4].uint()? <= 255,
                    "Execution result differs"
                );
                wire::decode(r[5].bytes()?)?;
                Self::Execution(
                    a[0].bytes()?.to_vec(),
                    a[1].bytes()?.to_vec(),
                    a[2].bytes()?.to_vec(),
                )
            }
            8 => {
                let fields = value.array(2)?;
                OrderedRequest::parse(config, fields[0].bytes()?)?;
                Self::Submit(fields[0].bytes()?.to_vec(), wire::encode(&fields[1])?)
            }
            9 => {
                let a = value.array(1)?;
                Self::Query(records::nonzero(&a[0])?)
            }
            10 => {
                let a = value.array(2)?;
                ensure!(a[1].uint()? <= 2, "Unknown transport disposition");
                Self::Ack(records::nonzero(&a[0])?, a[1].uint()?)
            }
            11 => {
                checkpoint::share(config, input)?;
                Self::CheckpointShare(input.to_vec())
            }
            12 => {
                checkpoint::verified(config, input)?;
                Self::CheckpointProof(input.to_vec())
            }
            13 => {
                let a = value.array(3)?;
                ensure!(a[2].uint()? < 16, "State chunk index exceeds bound");
                Self::StateRequest(
                    records::nonzero(&a[0])?,
                    records::nonzero(&a[1])?,
                    a[2].uint()?,
                )
            }
            14 => {
                let a = value.array(2)?;
                checkpoint::chunk(a[1].bytes()?)?;
                Self::StateResponse(records::nonzero(&a[0])?, a[1].bytes()?.to_vec())
            }
            15 => {
                let a = value.array(4)?;
                let index = a[2].uint()?;
                let count = a[3].uint()?;
                ensure!(
                    (1..=512).contains(&count)
                        && index < archive::MAX_LEAVES as u64
                        && index + count <= archive::MAX_LEAVES as u64,
                    "Archive request range exceeds bound"
                );
                Self::ArchiveRequest(
                    records::nonzero(&a[0])?,
                    records::nonzero(&a[1])?,
                    index,
                    count,
                )
            }
            16 => {
                let a = value.array(4)?;
                let index = a[2].uint()?;
                let leaves = a[3]
                    .list(512)?
                    .iter()
                    .map(V::fixed)
                    .collect::<Result<Vec<Digest>>>()?;
                ensure!(
                    !leaves.is_empty()
                        && index < archive::MAX_LEAVES as u64
                        && index + leaves.len() as u64 <= archive::MAX_LEAVES as u64,
                    "Archive response range exceeds bound"
                );
                Self::ArchiveResponse(
                    records::nonzero(&a[0])?,
                    records::nonzero(&a[1])?,
                    index,
                    leaves,
                )
            }
            17 => {
                let a = value.array(3)?;
                checkpoint::verified(config, a[2].bytes()?)?;
                Self::CheckpointSuperseded(
                    records::nonzero(&a[0])?,
                    records::nonzero(&a[1])?,
                    a[2].bytes()?.to_vec(),
                )
            }
            18 => {
                let fields = value.array(3)?;
                Self::InputRequest(
                    records::nonzero(&fields[0])?,
                    InputAnchor::parse(&fields[1])?,
                    InputReference::parse(&fields[2])?,
                )
            }
            19 => {
                let fields = value.array(4)?;
                let reference = InputReference::parse(&fields[2])?;
                let bytes = if fields[3] == V::Null {
                    None
                } else {
                    reference.verify(fields[3].bytes()?)?;
                    Some(fields[3].bytes()?.to_vec())
                };
                Self::InputResponse(
                    records::nonzero(&fields[0])?,
                    InputAnchor::parse(&fields[1])?,
                    reference,
                    bytes,
                )
            }
            _ => anyhow::bail!("Unknown peer message type"),
        })
    }
}
fn reference_value(r: &Reference) -> V {
    V::Array(vec![
        V::Uint(r.kind),
        records::bytes(&r.digest),
        r.signer.as_ref().map_or(V::Null, |s| records::bytes(s)),
    ])
}
fn parse_reference(config: &Configuration, a: &[V]) -> Result<Reference> {
    let kind = a[0].uint()?;
    ensure!(matches!(kind, 11 | 12 | 14 | 22), "Unsupported repair kind");
    let signer = if a[2] == V::Null {
        None
    } else {
        Some(a[2].fixed::<32>()?)
    };
    ensure!(signer.is_some() == (kind == 11), "Repair signer differs");
    if let Some(key) = signer {
        config.member(&key)?;
    }
    Ok(Reference {
        kind,
        digest: records::nonzero(&a[1])?,
        signer,
    })
}
pub fn validate_item(config: &Configuration, item: &Item) -> Result<()> {
    let digest = match item.reference.kind {
        11 => {
            let vote = SignedVote::parse(config, &item.bytes)?;
            ensure!(
                Some(vote.signer) == item.reference.signer,
                "Repair vote signer differs"
            );
            wire::digest(&vote.vote.encode()?)
        }
        12 => Certificate::parse(config, &item.bytes)?.digest(),
        14 => Node::parse(config, &item.bytes)?.digest()?,
        22 => {
            Command::parse(config, &item.bytes)?;
            wire::digest(&item.bytes)
        }
        _ => anyhow::bail!("Unsupported repair kind"),
    };
    ensure!(
        digest == item.reference.digest
            && item.reference.signer.is_some() == (item.reference.kind == 11),
        "Repair identity differs"
    );
    Ok(())
}
pub fn payload(config: &Configuration, signer: Key, message: &Message) -> Result<Vec<u8>> {
    config.member(&signer)?;
    let body = message.payload()?;
    Message::parse(config, message.number(), &body)?;
    wire::encode(&V::Array(vec![
        V::Uint(40),
        V::Uint(1),
        config.scope.value(),
        records::bytes(&signer),
        V::Uint(message.number()),
        records::bytes(&body),
    ]))
}
pub fn decode(config: &Configuration, transport_sender: Key, input: &[u8]) -> Result<Message> {
    config.member(&transport_sender)?;
    let (body, signatures) = wire::envelope(input, 1)?;
    ensure!(
        signatures.len() == 1 && signatures[0].0 == transport_sender,
        "Peer signature differs from TLS identity"
    );
    let value = wire::decode(&body)?;
    let a = records::record(&value, 40, 6)?;
    ensure!(
        Scope::parse(&a[2])? == config.scope && a[3].fixed::<32>()? == transport_sender,
        "Peer context differs"
    );
    Message::parse(config, a[4].uint()?, a[5].bytes()?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub key: Key,
    pub origin: String,
    pub certificate_sha256: Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Credentials {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub certificate_authority: PathBuf,
}
#[derive(Debug)]
struct PinnedVerifier {
    standard: Arc<WebPkiServerVerifier>,
    pin: Digest,
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(leaf.as_ref()).as_slice() != self.pin.as_slice() {
            return Err(rustls::Error::General(
                "Peer certificate pin differs".into(),
            ));
        }
        self.standard
            .verify_server_cert(leaf, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard
            .verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard
            .verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}
pub struct Transport {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub clients: Vec<(Key, String, reqwest::Client)>,
    pub pins: Vec<(Digest, Key)>,
}
pub fn transport(
    config: &Configuration,
    own: Key,
    endpoints: &[Endpoint; 4],
    credentials: &Credentials,
) -> Result<Transport> {
    let provider = Arc::new(crate::transport::tls_provider());
    let certs =
        CertificateDer::pem_slice_iter(&files::read(&credentials.certificate, 65536, false)?)
            .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "TLS certificate is absent");
    let key = PrivateKeyDer::from_pem_slice(&files::read(&credentials.private_key, 16384, true)?)?;
    let roots_bytes = files::read(&credentials.certificate_authority, 65536, false)?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&roots_bytes) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "TLS trust root is absent");
    let roots = Arc::new(roots);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        roots.clone(),
        provider.clone(),
    )
    .build()?;
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs.clone(), key.clone_key())?;
    let own_endpoint = endpoints
        .iter()
        .find(|e| e.key == own)
        .context("Local TLS endpoint is absent")?;
    ensure!(
        Sha256::digest(certs[0].as_ref()).as_slice() == own_endpoint.certificate_sha256.as_slice(),
        "Local TLS leaf differs from its configured pin"
    );
    let mut keys = BTreeSet::new();
    let mut pins = BTreeSet::new();
    let mut origins = BTreeSet::new();
    let mut clients = Vec::new();
    for endpoint in endpoints {
        config.member(&endpoint.key)?;
        ensure!(
            keys.insert(endpoint.key)
                && pins.insert(endpoint.certificate_sha256)
                && endpoint.certificate_sha256 != [0; 32],
            "Repeated TLS identity"
        );
        let origin = reqwest::Url::parse(&endpoint.origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/"
                && origins.insert(origin.to_string()),
            "Peer requires a distinct HTTPS origin"
        );
        let standard =
            WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone()).build()?;
        let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                standard,
                pin: endpoint.certificate_sha256,
            }))
            .with_client_auth_cert(certs.clone(), key.clone_key())?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(HTTP_TIMEOUT)
            .pool_max_idle_per_host(2)
            .build()?;
        clients.push((endpoint.key, origin.join("V1/Peer")?.to_string(), client));
    }
    Ok(Transport {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server)),
        clients,
        pins: endpoints
            .iter()
            .map(|e| (e.certificate_sha256, e.key))
            .collect(),
    })
}
