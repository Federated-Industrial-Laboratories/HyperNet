// SPDX-License-Identifier: MIT
//! Shared deployment admission vectors exercise consent, possession and permanent ownership.
use crate::{
    authority_deployment_records::{Index, Registration},
    authority_deployments::{Offer, Operation},
    authority_governance::Governance,
    authority_membership::{self as members, Reservations, reference},
    authority_proof::{Challenge, Intent, Key, Scope, VersionRef},
    runtime_manifest::{
        AuthorityConfig, Clock, ConsentPolicy, Endpoint, Manifest, Placement, Role, Volume,
    },
    trust_bootstrap::{
        self as bootstrap, Assurance, DraftSpec, RecoveryKey, RecoverySpec, RouteSpec,
    },
    trust_wire::{self as wire, Value as V},
};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, fs, net::Ipv4Addr, process::Command, sync::OnceLock};
fn a(values: Vec<V>) -> V {
    V::Array(values)
}
fn b(value: &[u8]) -> V {
    V::Bytes(value.to_vec())
}
pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> Key {
    key(seed).verifying_key().to_bytes()
}
fn hex(seed: u8) -> String {
    hex::encode(public(seed))
}
const N: Key = [20; 32];
const I: Key = [21; 32];
const DEPLOYMENT: Key = [60; 32];
pub(crate) fn leaf(seed: u8) -> Vec<u8> {
    static LEAVES: OnceLock<BTreeMap<u8, Vec<u8>>> = OnceLock::new();
    LEAVES
        .get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "HyperNetDeploymentLeaves{}",
                hex::encode(rand::random::<[u8; 16]>())
            ));
            fs::create_dir(&root).unwrap();
            let mut leaves = BTreeMap::new();
            for seed in (31..=34).chain(110..=117) {
                let mut private = vec![
                    0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ];
                private.extend([seed; 32]);
                fs::write(root.join("Key.der"), private).unwrap();
                let output = Command::new("openssl")
                    .args(["req", "-x509", "-keyform", "DER", "-key"])
                    .arg(root.join("Key.der"))
                    .args(["-outform", "DER", "-out"])
                    .arg(root.join("Leaf.der"))
                    .args(["-days", "1", "-subj", "/CN=HyperNetDeploymentTest"])
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                leaves.insert(seed, fs::read(root.join("Leaf.der")).unwrap());
            }
            fs::remove_dir_all(root).unwrap();
            leaves
        })
        .get(&seed)
        .unwrap()
        .clone()
}
pub(crate) fn manifest() -> Manifest {
    let mut endpoints = Vec::new();
    let mut roles = Vec::new();
    let mut volumes = Vec::new();
    for role in 0..9u8 {
        let service_seed = if role == 0 { 1 } else { 99 + role };
        let transport_seed = if role == 0 { 31 } else { 109 + role };
        let endpoint = [80 + role; 32];
        let volume = [100 + role; 32];
        endpoints.push(Endpoint {
            endpoint_id: endpoint,
            service_key: public(service_seed),
            address: Ipv4Addr::new(192, 0, 2, 10).into(),
            port: 24000 + u16::from(role),
            transport_key: public(transport_seed),
            leaf_der: leaf(transport_seed),
        });
        roles.push(Role {
            role: u64::from(role),
            service_key: public(service_seed),
            image_digest: [70 + role; 32],
            memory_bytes: 536870912,
            pids: 128,
            cpu_quota: 200000,
            cpu_period: 100000,
            state_admission_bytes: 1073741824,
            bind_endpoint_ids: vec![endpoint],
            outbound_endpoint_ids: vec![],
            volume_ids: vec![volume],
        });
        volumes.push(Volume {
            volume_id: volume,
            read_only: false,
            storage_admission_bytes: 1073741824,
        });
    }
    for seed in 2..=4u8 {
        endpoints.push(Endpoint {
            endpoint_id: [87 + seed; 32],
            service_key: public(seed),
            address: Ipv4Addr::new(192, 0, 2, 10 + seed).into(),
            port: 24000,
            transport_key: public(30 + seed),
            leaf_der: leaf(30 + seed),
        });
    }
    let peers = vec![[80; 32], [89; 32], [90; 32], [91; 32]];
    roles[0].outbound_endpoint_ids = peers.clone();
    Manifest {
        network: N,
        incarnation: I,
        deployment: DEPLOYMENT,
        host: [61; 32],
        operator: public(90),
        bootstrap_digest: [62; 32],
        software_digest: [63; 32],
        validity: (1000, 20000),
        session_mode: 0,
        roles,
        volumes: volumes.clone(),
        endpoints,
        clock: Clock {
            monitor_key: public(91),
            kernel_boot: "12345678-1234-1234-1234-123456789abc".into(),
            witness_file_name: "ClockHealth.cbor".into(),
            maximum_error_ms: 250,
            maximum_observation_age_ms: 1000,
        },
        placement: Placement {
            hosts: vec![[61; 32]],
            volumes: volumes.iter().map(|v| v.volume_id).collect(),
            backups: vec![],
            copies: 1,
        },
        limits: [268435456, 20480, 16, 32],
        consent_policy: ConsentPolicy {
            allow_opaque: false,
            reviewer_roots: vec![],
        },
        authority_config: Some(AuthorityConfig {
            listen_address: Ipv4Addr::UNSPECIFIED.into(),
            listen_port: 24000,
            ordered_peer_endpoint_ids: peers,
            tls_file_digests: [[64; 32], [65; 32], [66; 32]],
            subnet_address: Ipv4Addr::new(10, 91, 128, 0).into(),
            subnet_prefix: 24,
        }),
    }
}
pub(crate) fn offer(manifest: Manifest) -> Offer {
    let consent = wire::sign_envelope(&manifest.unsigned_consent(0).unwrap(), &key(90)).unwrap();
    let mut signers = vec![(0, 1), (2, 91)];
    signers.extend((100..=107).map(|seed| (0, seed)));
    signers.push((1, 31));
    signers.extend((110..=117).map(|seed| (1, seed)));
    signers.sort_by_key(|(class, seed)| (*class, public(*seed)));
    let possessions = signers
        .iter()
        .map(|(class, seed)| {
            wire::sign_envelope(
                &Offer::possession(
                    &manifest,
                    *class,
                    public(*seed),
                    [120 + *seed % 100; 32],
                    manifest.validity,
                )
                .unwrap(),
                &key(*seed),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    Offer::parse(
        &manifest.encode().unwrap(),
        &consent,
        &a(possessions.iter().map(|bytes| b(bytes)).collect()),
    )
    .unwrap()
}
pub(crate) struct Fixture {
    pub records: Vec<Vec<u8>>,
    pub reservations: Reservations,
    pub grant: VersionRef,
    pub scope: Scope,
    pub bootstrap: Vec<u8>,
}
impl Fixture {
    pub fn new() -> Self {
        Self::with_actions(vec![0, 10, 11, 12, 13, 26])
    }
    pub fn with_actions(administrator_actions: Vec<u64>) -> Self {
        Self::with_network(administrator_actions, N, I)
    }
    pub fn with_network(administrator_actions: Vec<u64>, n: Key, i: Key) -> Self {
        let mut voters = (1..=4).map(hex).collect::<Vec<_>>();
        voters.sort();
        let mut recoveries = (6..=8).collect::<Vec<_>>();
        recoveries.sort_by_key(|seed| public(*seed));
        let spec = DraftSpec {
            voters,
            authority_transports: (1..=4).map(|seed| (hex(seed), hex(30 + seed))).collect(),
            clock_monitors: vec![hex(40)],
            administrator: hex(5),
            administrator_actions,
            enrolment: "InvitationOnly".into(),
            public_reading: false,
            minimum_route: Assurance::Independent,
            publication_modes: vec!["HostReadable".into()],
            default_publication_mode: "HostReadable".into(),
            limits: [268435456, 20480, 128, 32],
            recovery: RecoverySpec {
                custody: "OwnerThreshold".into(),
                keys: recoveries
                    .iter()
                    .map(|seed| RecoveryKey {
                        principal: "11".repeat(32),
                        public_key: hex(*seed),
                    })
                    .collect(),
                accepted_keys: recoveries[..2].iter().map(|seed| hex(*seed)).collect(),
                immutable_shared: false,
            },
            route: RouteSpec {
                relay_service: "12".repeat(32),
                relay_origin: "https://relay.invalid/".into(),
                relay_transport_key: hex(9),
                relay_domain: "13".repeat(32),
                admission_service: "14".repeat(32),
                admission_origin: "https://admission.invalid/".into(),
                admission_transport_key: hex(10),
                admission_domain: "15".repeat(32),
                assurance: Assurance::Independent,
                not_before_ms: 500,
                expires_ms: 900000,
            },
        };
        let draft = bootstrap::draft(spec, [n, i, [22; 32], [23; 32]], 1000).unwrap();
        let accepts = recoveries[..2]
            .iter()
            .map(|seed| bootstrap::accept(&draft, &key(*seed), 1000).unwrap())
            .collect::<Vec<_>>();
        let complete = bootstrap::assemble(&draft, &accepts, 1000).unwrap();
        let verified = bootstrap::check(&complete, true, 1000).unwrap();
        let bundle = wire::decode(&complete).unwrap();
        let genesis = wire::decode(bundle.array(6).unwrap()[3].bytes().unwrap()).unwrap();
        let genesis = genesis.array(6).unwrap();
        let mut records = genesis[4]
            .list(35)
            .unwrap()
            .iter()
            .map(|v| v.bytes().unwrap().to_vec())
            .collect::<Vec<_>>();
        let reservations = Reservations::parse(&genesis[5]).unwrap();
        let g = Governance::parse(n, i, &records).unwrap();
        let root = g.versions().into_iter().find(|v| v.kind == 102).unwrap();
        let tier = g.versions().into_iter().find(|v| v.kind == 101).unwrap();
        let child = wire::encode(&a(vec![
            V::Uint(102),
            V::Uint(1),
            b(&n),
            b(&i),
            V::Uint(1),
            V::Null,
            b(&[24; 32]),
            b(&public(5)),
            b(&public(5)),
            reference(&tier),
            a(vec![V::Uint(13)]),
            a(vec![a(vec![V::Uint(5), b(&DEPLOYMENT)])]),
            a(vec![V::Uint(1000), V::Uint(800000)]),
            reference(&root),
            V::Uint(0),
            a(vec![
                V::Uint(268435456),
                V::Uint(20480),
                V::Uint(128),
                V::Uint(32),
            ]),
            snapshot(&[]),
        ]))
        .unwrap();
        records.push(child);
        members::sort_records(&mut records).unwrap();
        let grant = Governance::parse(n, i, &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|v| v.kind == 102 && v.id == [24; 32])
            .unwrap();
        Self {
            records,
            reservations,
            grant,
            scope: verified.descriptor().scope().clone(),
            bootstrap: complete,
        }
    }
    pub fn parameters(&self, offer: &Offer, refs: &[VersionRef]) -> V {
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentRegister".into()),
            reference(&self.grant),
            b(&offer.manifest_bytes),
            b(&offer.consent),
            offer.possessions_value(),
            snapshot(refs),
        ])
    }
    pub fn register(&self, offer: &Offer) -> (Vec<u8>, Intent, Operation) {
        let provisional = signed(
            &key(5),
            "AuthorityDeploymentRegister",
            DEPLOYMENT,
            1,
            self.parameters(offer, &[]),
            vec![],
        );
        let intent = Intent::from_signed(&provisional).unwrap();
        let op = Operation::parse(&intent).unwrap();
        let decision = op
            .prepare(
                &self.records,
                &self.reservations,
                &intent,
                5000,
                false,
                None,
            )
            .unwrap();
        assert_eq!(decision.code, 0);
        let refs = decision
            .dependencies
            .into_iter()
            .filter(|r| !matches!(r.kind, 105 | 117 | 129))
            .collect::<Vec<_>>();
        let bytes = signed(
            &key(5),
            "AuthorityDeploymentRegister",
            DEPLOYMENT,
            1,
            self.parameters(offer, &refs),
            refs,
        );
        let intent = Intent::from_signed(&bytes).unwrap();
        let operation = Operation::parse(&intent).unwrap();
        (bytes, intent, operation)
    }
}
pub(crate) fn snapshot(refs: &[VersionRef]) -> V {
    a(vec![
        a(vec![V::Uint(0), V::Uint(0), b(&[55; 32])]),
        a(refs.iter().map(reference).collect()),
    ])
}
pub(crate) fn signed(
    signer: &SigningKey,
    action: &str,
    resource: Key,
    revision: u64,
    parameters: V,
    refs: Vec<VersionRef>,
) -> Vec<u8> {
    wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(20),
            V::Uint(1),
            b(&N),
            b(&I),
            V::Uint(1),
            b(&[54; 32]),
            V::Uint(1),
            V::Uint(0),
            b(&signer.verifying_key().to_bytes()),
            V::Text(action.into()),
            b(&resource),
            V::Uint(revision),
            V::Uint(0),
            V::Uint(0),
            V::Uint(0),
            a(refs.iter().map(reference).collect()),
            b(&wire::encode(&parameters).unwrap()),
        ]))
        .unwrap(),
        signer,
    )
    .unwrap()
}
pub(crate) fn admitted(
    f: &Fixture,
    offer: &Offer,
) -> (Vec<Vec<u8>>, Registration, Intent, Operation) {
    let (_, intent, op) = f.register(offer);
    let decision = op
        .authorise(&f.records, &f.reservations, &intent, 5000, false, None)
        .unwrap();
    assert_eq!(decision.code, 0);
    assert_eq!(decision.admissions.len(), 9);
    assert!(!decision.admissions.contains(&public(1)));
    let registration = Registration::parse(decision.records.last().unwrap(), N, I).unwrap();
    let mut entries = f.records.clone();
    entries.extend(decision.records);
    members::sort_records(&mut entries).unwrap();
    (entries, registration, intent, op)
}
#[test]
fn full_role_registration_fits_the_actual_signed_ordered_request_bound() {
    let f = Fixture::new();
    let offer = offer(manifest());
    let (request, intent, op) = f.register(&offer);
    let challenge = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(21),
            V::Uint(1),
            b(&N),
            b(&I),
            b(&public(5)),
            b(&[51; 32]),
            b(&[52; 32]),
            b(&intent.digest),
            b(&[53; 32]),
            V::Uint(4000),
            V::Uint(9000),
            V::Uint(5000),
        ]))
        .unwrap(),
        &key(5),
    )
    .unwrap();
    assert_eq!(
        Challenge::from_signed(&challenge).unwrap().intent,
        intent.digest
    );
    let ordered = wire::encode(&a(vec![
        V::Uint(22),
        V::Uint(1),
        f.scope.value(),
        b(&request),
        b(&challenge),
        V::Uint(9000),
    ]))
    .unwrap();
    assert!(
        ordered.len() <= 98303,
        "ordered request is {} bytes",
        ordered.len()
    );
    assert_eq!(
        wire::decode(&ordered).unwrap().array(6).unwrap()[3]
            .bytes()
            .unwrap(),
        request
    );
    assert_eq!(offer.possessions.len(), 19);
    assert_eq!(offer.manifest.roles.len(), 9);
    let decision = op
        .authorise(&f.records, &f.reservations, &intent, 5000, false, None)
        .unwrap();
    assert_eq!(decision.code, 0);
    assert_eq!(decision.records.len(), 3);
    for kind in [105, 117, 129] {
        assert!(
            decision
                .dependencies
                .iter()
                .any(|v| v.kind == kind && v.id == DEPLOYMENT)
        );
    }
    assert!(offer.manifest_bytes.len() > 4096);
}
#[test]
fn registration_requires_exact_grant_snapshot_scope_and_operator_possession() {
    let f = Fixture::new();
    let offer = offer(manifest());
    let (_, intent, op) = f.register(&offer);
    let mut changed = intent.clone();
    changed.expected.pop();
    assert!(Operation::parse(&changed).is_err());
    let mut refs = intent.expected.clone();
    refs.pop();
    let bytes = signed(
        &key(5),
        &intent.action,
        DEPLOYMENT,
        1,
        f.parameters(&offer, &refs),
        refs,
    );
    let changed = Intent::from_signed(&bytes).unwrap();
    let changed_op = Operation::parse(&changed).unwrap();
    assert_eq!(
        changed_op
            .authorise(&f.records, &f.reservations, &changed, 5000, false, None)
            .unwrap()
            .code,
        12
    );
    let mut wrong = f.parameters(&offer, &intent.expected);
    if let V::Array(fields) = &mut wrong {
        let mut grant = f.grant.clone();
        grant.digest = [99; 32];
        fields[3] = reference(&grant);
    }
    let bytes = signed(
        &key(5),
        &intent.action,
        DEPLOYMENT,
        1,
        wrong,
        intent.expected.clone(),
    );
    let changed = Intent::from_signed(&bytes).unwrap();
    assert_ne!(
        Operation::parse(&changed)
            .unwrap()
            .authorise(&f.records, &f.reservations, &changed, 5000, false, None)
            .unwrap()
            .code,
        0
    );
    let forged =
        wire::sign_envelope(&offer.manifest.unsigned_consent(0).unwrap(), &key(92)).unwrap();
    assert!(Offer::parse(&offer.manifest_bytes, &forged, &offer.possessions_value()).is_err());
    let mut possessions = offer.possessions.clone();
    possessions.pop();
    assert!(
        Offer::parse(
            &offer.manifest_bytes,
            &offer.consent,
            &a(possessions.iter().map(|v| b(v)).collect())
        )
        .is_err()
    );
    assert_eq!(
        op.authorise(&f.records, &f.reservations, &intent, 21000, false, None)
            .unwrap()
            .code,
        7
    );
    let mut outside = offer.manifest.clone();
    outside.deployment = [59; 32];
    let outside = offer_for_same_keys(outside);
    let parameters = a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text(intent.action.clone()),
        reference(&f.grant),
        b(&outside.manifest_bytes),
        b(&outside.consent),
        outside.possessions_value(),
        snapshot(&[]),
    ]);
    let bytes = signed(&key(5), &intent.action, [59; 32], 1, parameters, vec![]);
    let changed = Intent::from_signed(&bytes).unwrap();
    assert_eq!(
        Operation::parse(&changed)
            .unwrap()
            .prepare(&f.records, &f.reservations, &changed, 5000, false, None)
            .unwrap()
            .code,
        3
    );
}
fn offer_for_same_keys(manifest: Manifest) -> Offer {
    offer(manifest)
}
#[test]
fn deployment_ownership_is_permanent_and_reserved_classes_are_symmetric() {
    let f = Fixture::new();
    let offer = offer(manifest());
    let (entries, registration, _, _) = admitted(&f, &offer);
    let index = Index::parse(&entries, &f.reservations, N, I).unwrap();
    let extended = index.extend_reservations(&f.reservations);
    for identity in [
        registration.operator,
        registration.services[&1],
        registration.transports[&registration.services[&1]],
        registration.monitor,
    ] {
        assert!(extended.contains(&identity));
        let governance = Governance::parse(N, I, &entries).unwrap();
        let root = governance
            .versions()
            .into_iter()
            .find(|v| v.kind == 102 && v.id == [23; 32])
            .unwrap();
        let tier = governance
            .versions()
            .into_iter()
            .find(|v| v.kind == 101)
            .unwrap();
        let child = a(vec![
            b(&[145; 32]),
            b(&identity),
            reference(&tier),
            a(vec![V::Uint(13)]),
            a(vec![a(vec![V::Uint(5), b(&DEPLOYMENT)])]),
            a(vec![V::Uint(1000), V::Uint(20000)]),
            V::Uint(0),
            a(vec![
                V::Uint(268435456),
                V::Uint(20480),
                V::Uint(128),
                V::Uint(32),
            ]),
        ]);
        let parameters = a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDelegateGrant".into()),
            reference(&root),
            child,
            snapshot(&[]),
        ]);
        let attempted = signed(
            &key(5),
            "AuthorityDelegateGrant",
            [145; 32],
            1,
            parameters,
            vec![],
        );
        let attempted = Intent::from_signed(&attempted).unwrap();
        let mutation = members::Mutation::parse(&attempted).unwrap();
        assert_eq!(
            mutation
                .prepare(&entries, &extended, &attempted, 5000, false)
                .unwrap()
                .code,
            38
        );
        let ordinary = vec![
            V::Uint(125),
            V::Uint(1),
            b(&N),
            b(&I),
            V::Uint(1),
            V::Null,
            b(&[140; 32]),
            b(&identity),
            a(vec![V::Uint(1000), V::Uint(800000)]),
            V::Bool(false),
            reference(&f.grant),
            snapshot(&[]),
        ];
        let record = wire::encode(&a(ordinary.clone())).unwrap();
        let mut first = entries.clone();
        first.push(record.clone());
        assert!(Index::parse(&first, &f.reservations, N, I).is_err());
        let application = wire::encode(&a(vec![
            V::Uint(127),
            V::Uint(1),
            b(&N),
            b(&I),
            V::Uint(1),
            V::Null,
            b(&identity),
            b(&public(5)),
            reference(&f.grant),
            a(vec![V::Uint(1000), V::Uint(800000)]),
            snapshot(&[]),
        ]))
        .unwrap();
        let mut first = f.records.clone();
        first.push(application);
        first.extend(
            entries
                .iter()
                .filter(|bytes| !f.records.contains(bytes))
                .cloned(),
        );
        assert!(Index::parse(&first, &f.reservations, N, I).is_err());
    }
    let mut other = registration.clone();
    let value = wire::decode(&other.bytes).unwrap();
    let mut row = value.array(17).unwrap().to_vec();
    row[6] = b(&[141; 32]);
    other.bytes = wire::encode(&a(row)).unwrap();
    let mut changed = entries.clone();
    changed.push(other.bytes);
    assert!(Index::parse(&changed, &f.reservations, N, I).is_err());
    let mut changed = manifest();
    changed.operator = public(40);
    let consent = wire::sign_envelope(&changed.unsigned_consent(0).unwrap(), &key(40)).unwrap();
    assert_ne!(consent, offer.consent);
    let mut conflicting = entries.clone();
    let mut row = wire::decode(&registration.bytes)
        .unwrap()
        .array(17)
        .unwrap()
        .to_vec();
    row[8] = b(&public(40));
    conflicting.retain(|bytes| bytes != &registration.bytes);
    conflicting.push(wire::encode(&a(row)).unwrap());
    assert!(Index::parse(&conflicting, &f.reservations, N, I).is_err());
}
#[test]
fn intrinsic_withdrawal_survives_revoked_registration_authority_and_expired_consent() {
    let f = Fixture::new();
    let offer = offer(manifest());
    let (mut entries, registration, _, _) = admitted(&f, &offer);
    let revoked = wire::encode(&a(vec![
        V::Uint(126),
        V::Uint(1),
        b(&N),
        b(&I),
        V::Uint(1),
        V::Null,
        reference(&f.grant),
        b(&public(5)),
        snapshot(&[]),
    ]))
    .unwrap();
    entries.push(revoked);
    members::sort_records(&mut entries).unwrap();
    let refs = vec![registration.reference.clone()];
    let parameters = a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityDeploymentWithdraw".into()),
        reference(&registration.reference),
        V::Uint(1),
        snapshot(&refs),
    ]);
    let bytes = signed(
        &key(90),
        "AuthorityDeploymentWithdraw",
        DEPLOYMENT,
        1,
        parameters.clone(),
        refs.clone(),
    );
    let intent = Intent::from_signed(&bytes).unwrap();
    let op = Operation::parse(&intent).unwrap();
    let decision = op
        .authorise(&entries, &f.reservations, &intent, 30000, false, None)
        .unwrap();
    assert_eq!(decision.code, 0);
    assert_eq!(decision.records.len(), 1);
    let bad = signed(
        &key(92),
        "AuthorityDeploymentWithdraw",
        DEPLOYMENT,
        1,
        parameters,
        refs,
    );
    let bad = Intent::from_signed(&bad).unwrap();
    assert_eq!(
        Operation::parse(&bad)
            .unwrap()
            .authorise(&entries, &f.reservations, &bad, 30000, false, None)
            .unwrap()
            .code,
        3
    );
    entries.extend(decision.records);
    members::sort_records(&mut entries).unwrap();
    let index = Index::parse(&entries, &f.reservations, N, I).unwrap();
    assert_eq!(index.open_count(), 0);
    assert!(index.reserved.contains(&registration.services[&1]));
    assert!(index.streams().contains(&registration.operator));
    assert_eq!(
        op.authorise(&entries, &f.reservations, &intent, 30000, true, None)
            .unwrap()
            .code,
        0
    );
    assert_eq!(
        op.authorise(&entries, &f.reservations, &intent, 30000, false, None)
            .unwrap()
            .code,
        28
    );
}
#[test]
fn exact_replay_and_known_deployment_reads_do_not_transfer_ownership() {
    let f = Fixture::new();
    let offer = offer(manifest());
    let (entries, registration, intent, op) = admitted(&f, &offer);
    let replay = op
        .authorise(&entries, &f.reservations, &intent, 5000, true, None)
        .unwrap();
    assert_eq!(replay.code, 0);
    assert!(replay.records.is_empty());
    assert!(replay.admissions.is_empty());
    assert_eq!(
        op.authorise(&entries, &f.reservations, &intent, 5000, false, None)
            .unwrap()
            .code,
        28
    );
    let parameters = a(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("AuthorityDeploymentGet".into()),
        b(&DEPLOYMENT),
        V::Null,
        a(vec![]),
    ]);
    for (seed, expected) in [(90, 0), (92, 3)] {
        let bytes = signed(
            &key(seed),
            "AuthorityDeploymentGet",
            DEPLOYMENT,
            0,
            parameters.clone(),
            vec![],
        );
        let intent = Intent::from_signed(&bytes).unwrap();
        let get = Operation::parse(&intent).unwrap();
        let result = get
            .authorise(
                &entries,
                &f.reservations,
                &intent,
                30000,
                false,
                Some((&offer.manifest_bytes, &offer.consent)),
            )
            .unwrap();
        assert_eq!(result.code, expected);
        if expected == 0 {
            assert_eq!(
                result.value.array(9).unwrap()[4].bytes().unwrap(),
                registration.bytes
            );
        }
    }
}

/// Execute-result vectors use the independently accepted deployment committee and the actual store challenge.
pub(crate) fn serving_result(
    bootstrap: &bootstrap::Verified,
    signed: &[u8],
    value: &V,
    service_seed: u8,
) -> crate::authority_proof::tests::Fixture {
    use ed25519_dalek::Signer;
    let mut fixture = crate::authority_proof::tests::Fixture::new(5000);
    fixture.descriptor = bootstrap.descriptor().clone();
    fixture.intent = signed.to_vec();
    fixture.recipient = key(service_seed);
    let intent = Intent::from_signed(signed).unwrap();
    fixture.challenge = wire::sign_envelope(
        &wire::encode(&a(vec![
            V::Uint(21),
            V::Uint(1),
            b(&intent.network),
            b(&intent.incarnation),
            b(&public(service_seed)),
            b(&[211; 32]),
            b(&[212; 32]),
            b(&intent.digest),
            b(&[213; 32]),
            V::Uint(3500),
            V::Uint(8500),
            V::Uint(5000),
        ]))
        .unwrap(),
        &fixture.recipient,
    )
    .unwrap();
    fixture.operation = wire::encode(&a(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(intent.action),
        V::Uint(0),
        V::Uint(0),
        b(&wire::encode(value).unwrap()),
    ]))
    .unwrap();
    fixture.rebuild();
    let (payload, _) = wire::envelope(&fixture.certificate, 4).unwrap();
    let mut fields = wire::decode(&payload).unwrap().array(23).unwrap().to_vec();
    fields[14] = V::Uint(1);
    fields[19] = V::Uint(8000);
    fields[20] = V::Null;
    fields[21] = V::Null;
    fields[22] = V::Null;
    let payload = wire::encode(&a(fields)).unwrap();
    let mut keys = (1..=4).map(key).collect::<Vec<_>>();
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    fixture.certificate = wire::encode(&a(vec![
        V::Uint(0),
        V::Uint(1),
        b(&payload),
        a(keys[..3]
            .iter()
            .map(|key| {
                let public = key.verifying_key().to_bytes();
                a(vec![
                    b(&public),
                    b(&key
                        .sign(&wire::signature_message(&payload, &public))
                        .to_bytes()),
                ])
            })
            .collect()),
    ]))
    .unwrap();
    fixture
}
/// Remove an exact live record and its reference while keeping the response schema self-consistent.
pub(crate) fn without_live_consent(value: &V) -> V {
    let mut fields = value.array(5).unwrap().to_vec();
    fields[3] = a(fields[3]
        .list(64)
        .unwrap()
        .iter()
        .filter(|r| r.array(4).unwrap()[0].uint().unwrap() != 105)
        .cloned()
        .collect());
    let mut body = fields[4].array(4).unwrap().to_vec();
    body[2] = a(body[2]
        .list(64)
        .unwrap()
        .iter()
        .filter(|r| {
            wire::decode(r.bytes().unwrap()).unwrap().list(32).unwrap()[0]
                .uint()
                .unwrap()
                != 105
        })
        .cloned()
        .collect());
    fields[4] = a(body);
    a(fields)
}
