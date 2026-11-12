// SPDX-License-Identifier: MIT
// Route authority checks use admitted services, signed consent and exact current dependencies.
use super::*;
use crate::{
    authority_deployment_records::{Index, Registration},
    authority_deployment_tests as deployment,
    authority_deployments::{Offer, Operation as DeploymentOperation},
    authority_governance::Governance,
    authority_membership::{self as members, Reservations},
};
use base64::{Engine, engine::general_purpose::STANDARD};

const N: Digest = [20; 32];
const I: Digest = [21; 32];
const RELAY: Digest = [171; 32];
const DESTINATION: Digest = [172; 32];
const CHARGE: u64 = 65536;

#[test]
fn route_successor_preserves_identity_and_consumes_one_certified_generation() {
    let mut f = Fixture::new();
    f.register();
    let previous = f.state.record(165, RELAY).unwrap().reference.clone();
    let profile = f.consent_successor(0);
    f.apply(
        Command::Register {
            profile: Box::new(profile.clone()),
        },
        5,
        Some(f.root.clone()),
    );
    let current = f.state.record(165, RELAY).unwrap();
    assert_eq!(current.reference.generation, previous.generation + 1);
    assert_eq!(
        Service::parse(&current.payload, N, I)
            .unwrap()
            .profile
            .envelope,
        profile.envelope
    );
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(f.profiles[0].clone())
            },
            5,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(profile.clone())
            },
            5,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
    let (intent, operation, _) = f.apply(
        Command::Withdraw {
            service: RELAY,
            generation: 2,
        },
        90,
        None,
    );
    let replay = operation
        .prepare(&f.state, &f.records, &f.reserved, &intent, 5000, true, true)
        .unwrap();
    assert_eq!(replay.code, 0);
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(profile)
            },
            5,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
}

#[test]
fn route_successor_cannot_widen_substitute_manager_or_revive_withdrawal() {
    let mut f = Fixture::new();
    f.register();
    let profile = f.consent_successor(0);
    let mut wider = profile.clone();
    wider.limits.bytes += 1;
    seal(&mut wider, 90);
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(wider)
            },
            5,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(profile.clone())
            },
            90,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
    let generation = f.state.record(165, RELAY).unwrap().reference.generation;
    f.apply(
        Command::Withdraw {
            service: RELAY,
            generation,
        },
        90,
        None,
    );
    assert_ne!(
        f.request(
            Command::Register {
                profile: Box::new(profile)
            },
            5,
            Some(f.root.clone())
        )
        .2
        .code,
        0
    );
}

fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
fn seal(profile: &mut RegisteredProfile, operator: u8) {
    let bytes =
        wire::sign_envelope(&profile.payload(N, I).unwrap(), &deployment::key(operator)).unwrap();
    *profile = RegisteredProfile::parse(&bytes, N, I).unwrap();
}

struct Fixture {
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    state: State,
    bootstrap: Vec<u8>,
    root: VersionRef,
    reader: VersionRef,
    profiles: [RegisteredProfile; 2],
}
impl Fixture {
    fn new() -> Self {
        Self::with_operator_separation(true)
    }
    fn with_operator_separation(separate: bool) -> Self {
        Self::with_route_transport(separate, None)
    }
    fn with_route_transport(separate: bool, relay: Option<(u8, Vec<u8>)>) -> Self {
        Self::with_route_validity(separate, relay, (1000, 20000).into())
    }
    fn with_route_validity(
        separate: bool,
        relay: Option<(u8, Vec<u8>)>,
        validity: crate::trust_validity::Validity,
    ) -> Self {
        let f = deployment::Fixture::with_actions(vec![0, 6, 10, 11, 12, 13, 26, 29, 30]);
        let governance = Governance::parse(N, I, &f.records).unwrap();
        let root = governance
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let mut reader = wire::decode(governance.record_bytes(102, root.id).unwrap())
            .unwrap()
            .array(17)
            .unwrap()
            .to_vec();
        reader[6] = b(&[170; 32]);
        reader[10] = a(vec![V::Uint(0)]);
        reader[13] = reference(&root);
        reader[14] = V::Uint(0);
        reader[16] = deployment::snapshot(&[]);
        let mut records = f.records;
        records.push(wire::encode(&a(reader)).unwrap());
        members::sort_records(&mut records).unwrap();
        let reader = Governance::parse(N, I, &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [170; 32])
            .unwrap();
        let profiles = [0, 1].map(|index| {
            Self::admit_with_validity(
                &mut records,
                &f.reservations,
                &root,
                index,
                separate,
                relay.as_ref().filter(|_| index == 0),
                validity,
            )
        });
        Self {
            records,
            reserved: f.reservations,
            state: State::empty(N, I),
            bootstrap: f.bootstrap,
            root,
            reader,
            profiles,
        }
    }
    fn admit_with_validity(
        records: &mut Vec<Vec<u8>>,
        reserved: &Reservations,
        grant: &VersionRef,
        index: u8,
        separate: bool,
        reserved_transport: Option<&(u8, Vec<u8>)>,
        validity: crate::trust_validity::Validity,
    ) -> RegisteredProfile {
        let service = 160 + index;
        let transport = reserved_transport.map_or(110 + index, |(seed, _)| *seed);
        let operator = 90 + index * 2 * u8::from(separate);
        let mut manifest = deployment::manifest();
        manifest.validity = validity;
        manifest.deployment = [60 + index; 32];
        manifest.operator = public(operator);
        manifest.authority_config = None;
        manifest.roles.retain(|r| r.role == 5);
        manifest.roles[0].service_key = public(service);
        manifest.volumes.retain(|v| v.volume_id == [105; 32]);
        manifest.placement.volumes = vec![[105; 32]];
        manifest.endpoints.retain(|e| e.endpoint_id == [85; 32]);
        manifest.endpoints[0].service_key = public(service);
        manifest.endpoints[0].transport_key = public(transport);
        manifest.endpoints[0].leaf_der = reserved_transport
            .map(|(_, leaf)| leaf.clone())
            .unwrap_or_else(|| deployment::leaf(transport));
        manifest.endpoints[0].port += u16::from(index);
        let consent = wire::sign_envelope(
            &manifest.unsigned_consent(0).unwrap(),
            &deployment::key(operator),
        )
        .unwrap();
        let possessions = [(0, service), (1, transport), (2, 91)].map(|(class, seed)| {
            b(&wire::sign_envelope(
                &Offer::possession(
                    &manifest,
                    class,
                    public(seed),
                    [180 + index; 32],
                    manifest.validity,
                )
                .unwrap(),
                &deployment::key(seed),
            )
            .unwrap())
        });
        let offer = Offer::parse(
            &manifest.encode().unwrap(),
            &consent,
            &a(possessions.to_vec()),
        )
        .unwrap();
        let request = |refs: &[VersionRef]| {
            let parameters = a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("AuthorityDeploymentRegister".into()),
                reference(grant),
                b(&offer.manifest_bytes),
                b(&offer.consent),
                offer.possessions_value(),
                deployment::snapshot(refs),
                V::Bool(false),
            ]);
            Intent::from_signed(&deployment::signed(
                &deployment::key(5),
                "AuthorityDeploymentRegister",
                manifest.deployment,
                1,
                parameters,
                refs.to_vec(),
            ))
            .unwrap()
        };
        let intent = request(&[]);
        let preflight = DeploymentOperation::parse(&intent)
            .unwrap()
            .prepare(records, reserved, &intent, 5000, false, None)
            .unwrap();
        assert_eq!(preflight.code, 0);
        let refs = preflight
            .dependencies
            .into_iter()
            .filter(|r| !matches!(r.kind, 105 | 117 | 129))
            .collect::<Vec<_>>();
        let intent = request(&refs);
        let admitted = DeploymentOperation::parse(&intent)
            .unwrap()
            .authorise(records, reserved, &intent, 5000, false, None)
            .unwrap();
        assert_eq!(admitted.code, 0);
        assert!(admitted.admissions.contains(&public(service)));
        let registration = Registration::parse(admitted.records.last().unwrap(), N, I).unwrap();
        records.extend(admitted.records);
        members::sort_records(records).unwrap();
        let endpoint = &manifest.endpoints[0];
        let mut profile = RegisteredProfile {
            manifest: manifest.clone(),
            deployment: manifest.deployment,
            service: public(service),
            operator: public(operator),
            deployment_profile: registration.profile,
            consent: registration.consent,
            endpoint: endpoint.endpoint_id,
            identity: Identity {
                service: if reserved_transport.is_some() {
                    [0x12; 32]
                } else if index == 0 {
                    RELAY
                } else {
                    DESTINATION
                },
                server_name: "route.invalid".into(),
                transport_key: public(transport),
                leaf_der: endpoint.leaf_der.clone(),
                certificate_authority_pem: format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    STANDARD.encode(&endpoint.leaf_der)
                ),
            },
            address: Some((endpoint.address, endpoint.port).into()),
            domain: if index == 0 { "13" } else { "15" }.repeat(32),
            protocol: u64::from(index != 0),
            mode: if index == 0 { 1 } else { 2 },
            relay: None,
            limits: Limits {
                bytes: CHARGE,
                duration_ms: 5000,
                idle_ms: 1000,
            },
            maximum_connections: 4,
            assurance: Assurance::Independent,
            validity: manifest.validity,
            envelope: vec![],
        };
        seal(&mut profile, operator);
        profile
    }
    fn request(
        &self,
        command: Command,
        signer: u8,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        self.request_at(command, signer, grant, 5000)
    }
    fn request_at(
        &self,
        command: Command,
        signer: u8,
        grant: Option<VersionRef>,
        at: u64,
    ) -> (Intent, Operation, Decision) {
        let mut operation = Operation {
            grant,
            command: super::super::Command::Route(command),
            snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        let sign = |operation: &Operation, refs: Vec<VersionRef>| {
            Intent::from_signed(&deployment::signed(
                &deployment::key(signer),
                "AuthorityDomain",
                operation.command.resource(),
                u64::from(operation.mutation()),
                wire::decode(&operation.parameters().unwrap()).unwrap(),
                refs,
            ))
            .unwrap()
        };
        let mut intent = sign(&operation, vec![]);
        let mut decision = operation
            .prepare(
                &self.state,
                &self.records,
                &self.reserved,
                &intent,
                at,
                false,
                false,
            )
            .unwrap();
        if decision.code == 0 {
            operation.snapshot = snapshot(&deployment::snapshot(&decision.dependencies)).unwrap();
            intent = sign(&operation, decision.dependencies);
            operation = Operation::parse(&intent).unwrap();
            decision = operation
                .prepare(
                    &self.state,
                    &self.records,
                    &self.reserved,
                    &intent,
                    at,
                    false,
                    true,
                )
                .unwrap();
        }
        (intent, operation, decision)
    }
    fn apply(
        &mut self,
        command: Command,
        signer: u8,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        let result = self.request(command, signer, grant);
        assert_eq!(result.2.code, 0);
        if let Some(state) = &result.2.state {
            self.state = state.clone();
        }
        State::parse(&self.state.value(), N, I).unwrap();
        result
    }
    fn register(&mut self) {
        for profile in self.profiles.clone() {
            self.apply(
                Command::Register {
                    profile: Box::new(profile),
                },
                5,
                Some(self.root.clone()),
            );
        }
    }
    fn consent_successor(&mut self, index: usize) -> RegisteredProfile {
        let old = &self.profiles[index];
        let mut manifest = old.manifest.clone();
        manifest.generation += 1;
        manifest.previous_profile = Some(wire::digest(&old.manifest.desired().unwrap()));
        manifest.previous_consent = Some(wire::digest(&old.manifest.unsigned_consent(0).unwrap()));
        manifest.validity.1 = (manifest.validity.1.finite().unwrap() + 10000).into();
        self.admit_successor(index, manifest)
    }
    fn admit_successor(
        &mut self,
        index: usize,
        manifest: crate::runtime_manifest::Manifest,
    ) -> RegisteredProfile {
        let old = &self.profiles[index];
        let operator = 90 + index as u8 * 2;
        let consent = wire::sign_envelope(
            &manifest.unsigned_consent(0).unwrap(),
            &deployment::key(operator),
        )
        .unwrap();
        let offer = Offer::parse(&manifest.encode().unwrap(), &consent, &a(vec![])).unwrap();
        let previous_bytes = old.manifest.encode().unwrap();
        let previous_consent = wire::sign_envelope(
            &old.manifest.unsigned_consent(0).unwrap(),
            &deployment::key(operator),
        )
        .unwrap();
        let request = |refs: &[VersionRef]| {
            Intent::from_signed(&deployment::signed(
                &deployment::key(5),
                "AuthorityDeploymentRegister",
                manifest.deployment,
                1,
                a(vec![
                    V::Uint(200),
                    V::Uint(1),
                    V::Text("AuthorityDeploymentRegister".into()),
                    reference(&self.root),
                    b(&offer.manifest_bytes),
                    b(&offer.consent),
                    offer.possessions_value(),
                    deployment::snapshot(refs),
                    V::Bool(false),
                ]),
                refs.to_vec(),
            ))
            .unwrap()
        };
        let index = Index::parse(&self.records, &self.reserved, N, I).unwrap();
        let prior = &index.deployments[&manifest.deployment];
        let mut preceding = vec![
            prior.reference.clone(),
            prior.profile.clone(),
            prior.consent.clone(),
        ];
        preceding.sort_by_key(VersionRef::index);
        let initial = request(&preceding);
        let before = Some((previous_bytes.as_slice(), previous_consent.as_slice()));
        let preflight = DeploymentOperation::parse(&initial)
            .unwrap()
            .prepare(&self.records, &self.reserved, &initial, 5000, false, before)
            .unwrap();
        assert_eq!(preflight.code, 0);
        let mut dependencies = preflight
            .dependencies
            .into_iter()
            .filter(|r| r.id != manifest.deployment || !matches!(r.kind, 105 | 117 | 129))
            .collect::<Vec<_>>();
        dependencies.extend(preceding);
        dependencies.sort_by_key(VersionRef::index);
        let intent = request(&dependencies);
        let admitted = DeploymentOperation::parse(&intent)
            .unwrap()
            .authorise(&self.records, &self.reserved, &intent, 5000, false, before)
            .unwrap();
        assert_eq!(admitted.code, 0);
        self.records.retain(|bytes| {
            crate::authority_deployment_records::reference(bytes).map_or(true, |r| {
                r.id != manifest.deployment || !matches!(r.kind, 105 | 117 | 129)
            })
        });
        self.records.extend(admitted.records);
        members::sort_records(&mut self.records).unwrap();
        let mut profile = old.clone();
        profile.manifest = manifest;
        if let Some(transport) = &profile.manifest.transport_certificates {
            profile.identity.certificate_authority_pem = transport.issuer_pem.clone();
            profile.identity.leaf_der = profile
                .manifest
                .endpoints
                .iter()
                .find(|e| e.endpoint_id == profile.endpoint)
                .unwrap()
                .leaf_der
                .clone();
        }
        profile.validity = profile.manifest.validity;
        profile.deployment_profile =
            crate::authority_deployment_records::reference(&profile.manifest.desired().unwrap())
                .unwrap();
        profile.consent = crate::authority_deployment_records::reference(
            &profile.manifest.unsigned_consent(0).unwrap(),
        )
        .unwrap();
        seal(&mut profile, operator);
        profile
    }
    fn issue_command(&self, connections: u64, bytes: u64) -> Command {
        Command::Issue {
            id: [201; 32],
            relay: RELAY,
            destination: DESTINATION,
            possession: public(200),
            action: 0,
            scope: (0, N),
            connections,
            bytes,
            expires: 15000,
        }
    }
    fn issue(&mut self, connections: u64, bytes: u64) -> VersionRef {
        self.apply(
            self.issue_command(connections, bytes),
            5,
            Some(self.reader.clone()),
        );
        self.state.record(166, [201; 32]).unwrap().reference.clone()
    }
    fn permit(voucher: &VersionRef, nonce: u8) -> Command {
        Command::Permit {
            voucher: voucher.clone(),
            connection: [nonce; 32],
            transcript: [nonce + 1; 32],
        }
    }
    fn withdraw_deployment(&mut self) {
        let registration = Index::parse(&self.records, &self.reserved, N, I)
            .unwrap()
            .deployments[&self.profiles[1].deployment]
            .reference
            .clone();
        let refs = vec![registration.clone()];
        let intent = Intent::from_signed(&deployment::signed(
            &deployment::key(92),
            "AuthorityDeploymentWithdraw",
            registration.id,
            1,
            a(vec![
                V::Uint(200),
                V::Uint(1),
                V::Text("AuthorityDeploymentWithdraw".into()),
                reference(&registration),
                V::Uint(1),
                deployment::snapshot(&refs),
            ]),
            refs,
        ))
        .unwrap();
        let decision = DeploymentOperation::parse(&intent)
            .unwrap()
            .authorise(&self.records, &self.reserved, &intent, 5000, false, None)
            .unwrap();
        assert_eq!(decision.code, 0);
        self.records.extend(decision.records);
        members::sort_records(&mut self.records).unwrap();
    }
}

#[test]
fn certified_routes_reserve_before_use_and_replay_without_charging_again() {
    let mut f = Fixture::new();
    f.register();
    let lookup = f
        .request(
            Command::Lookup {
                service: DESTINATION,
            },
            5,
            Some(f.reader.clone()),
        )
        .2;
    assert_eq!(lookup.code, 0);
    assert!(
        lookup
            .versions
            .iter()
            .any(|r| r.kind == 165 && r.id == DESTINATION)
    );
    assert_eq!(
        f.request(
            Command::Lookup {
                service: DESTINATION
            },
            200,
            None
        )
        .2
        .code,
        3
    );
    let voucher = f.issue(4, 4 * CHARGE);
    let command = Command::VoucherContext {
        voucher: voucher.clone(),
    };
    assert_eq!(f.request(command.clone(), 160, None).2.code, 0);
    assert_eq!(f.request(command, 161, None).2.code, 3);
    let (intent, operation, _) = f.apply(Fixture::permit(&voucher, 210), 160, None);
    let charged = f.state.record(167, voucher.id).unwrap().clone();
    let usage = Usage::parse(&charged.payload).unwrap();
    assert_eq!((usage.connections, usage.bytes), (1, CHARGE));
    let replay = operation
        .prepare(&f.state, &f.records, &f.reserved, &intent, 5000, true, true)
        .unwrap();
    assert_eq!(replay.code, 0);
    assert!(replay.state.is_none());
    assert!(replay.versions.contains(&charged.reference));
    assert_eq!(
        f.request(Fixture::permit(&voucher, 210), 160, None).2.code,
        3
    );
    let (stale_intent, stale_operation, prepared) =
        f.request(Fixture::permit(&voucher, 220), 160, None);
    assert_eq!(prepared.code, 0);
    f.apply(Fixture::permit(&voucher, 230), 160, None);
    assert_eq!(
        stale_operation
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &stale_intent,
                5000,
                false,
                true
            )
            .unwrap()
            .code,
        12
    );
    let mut altered = intent;
    altered.digest = [245; 32];
    assert_eq!(
        operation
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &altered,
                5000,
                true,
                true
            )
            .unwrap()
            .code,
        3
    );
}

#[test]
fn certified_route_connection_and_byte_budgets_are_independent() {
    for (connections, bytes) in [(2, 3 * CHARGE), (3, 2 * CHARGE)] {
        let mut f = Fixture::new();
        f.register();
        let voucher = f.issue(connections, bytes);
        f.apply(Fixture::permit(&voucher, 210), 160, None);
        f.apply(Fixture::permit(&voucher, 220), 160, None);
        assert_eq!(
            f.request(Fixture::permit(&voucher, 230), 160, None).2.code,
            3
        );
        let usage = Usage::parse(&f.state.record(167, voucher.id).unwrap().payload).unwrap();
        assert_eq!((usage.connections, usage.bytes), (2, 2 * CHARGE));
    }
}

#[test]
fn certified_routes_recheck_consent_and_sponsor_before_each_connection() {
    for restriction in 0..3 {
        let mut f = Fixture::new();
        f.register();
        let voucher = f.issue(4, 4 * CHARGE);
        f.apply(Fixture::permit(&voucher, 210), 160, None);
        match restriction {
            0 => f.withdraw_deployment(),
            1 => {
                f.apply(
                    Command::Withdraw {
                        service: DESTINATION,
                        generation: 1,
                    },
                    92,
                    None,
                );
            }
            _ => {
                f.records.push(
                    wire::encode(&a(vec![
                        V::Uint(126),
                        V::Uint(1),
                        b(&N),
                        b(&I),
                        V::Uint(1),
                        V::Null,
                        reference(&f.reader),
                        b(&public(5)),
                        deployment::snapshot(&[]),
                    ]))
                    .unwrap(),
                );
                members::sort_records(&mut f.records).unwrap();
                assert_eq!(
                    f.request(Command::Lookup { service: RELAY }, 160, None)
                        .2
                        .code,
                    0
                );
            }
        }
        assert_eq!(
            f.request(
                Command::VoucherContext {
                    voucher: voucher.clone()
                },
                160,
                None
            )
            .2
            .code,
            3
        );
        assert_eq!(
            f.request(Fixture::permit(&voucher, 220), 160, None).2.code,
            3
        );
        assert_eq!(
            f.state
                .record(167, voucher.id)
                .unwrap()
                .reference
                .generation,
            1
        );
    }
}

#[test]
fn certified_routes_require_a_separate_possession_key_and_current_privacy_policy() {
    let mut f = Fixture::new();
    f.register();
    for seed in [5, 31, 110, 160] {
        let mut command = f.issue_command(1, CHARGE);
        if let Command::Issue { possession, .. } = &mut command {
            *possession = public(seed);
        }
        assert_eq!(f.request(command, 5, Some(f.reader.clone())).2.code, 3);
    }
    for change in 0..3 {
        let mut f = Fixture::new();
        match change {
            0 => f.profiles[0].assurance = Assurance::Organisation,
            1 => f.profiles[0].domain = "16".repeat(32),
            _ => f.profiles[1].domain = f.profiles[0].domain.clone(),
        }
        seal(&mut f.profiles[0], 90);
        seal(&mut f.profiles[1], 92);
        f.register();
        assert_eq!(
            f.request(f.issue_command(1, CHARGE), 5, Some(f.reader.clone()))
                .2
                .code,
            3
        );
    }
    let mut f = Fixture::with_operator_separation(false);
    f.register();
    assert_eq!(
        f.request(f.issue_command(1, CHARGE), 5, Some(f.reader.clone()))
            .2
            .code,
        3
    );
}

fn verified_context(
    f: &Fixture,
    intent: &Intent,
    decision: &Decision,
    at: u64,
) -> super::super::result::Candidate {
    use crate::authority_proof::{Disposition, ExecutedResult, OperationResult, Restrictions};
    let bootstrap = crate::trust_bootstrap::check(&f.bootstrap, true, at).unwrap();
    let result = OperationResult {
        action: intent.action.clone(),
        disposition: Disposition::Permit,
        code: 0,
        value: wire::encode(&decision.value).unwrap(),
    };
    let executed = ExecutedResult {
        scope: bootstrap.descriptor().scope().clone(),
        height: 1,
        committed_node: [202; 32],
        ordered_request: [203; 32],
        intent: intent.digest,
        challenge: [204; 32],
        requester: intent.requester,
        recipient: intent.requester,
        action: intent.action.clone(),
        resource: intent.resource,
        revision: intent.revision,
        profile_generation: 0,
        maximum_effect: 1,
        result: wire::digest(&result.value),
        policy_state: [205; 32],
        minimum_policy_height: 0,
        evaluated_at_ms: at,
        expires_at_ms: decision.expires_ms.min(at + 5000),
        restrictions: Restrictions::default(),
    };
    super::super::result::verify(
        &bootstrap,
        &State::empty(N, I),
        &[],
        intent,
        &result,
        &executed,
        &[],
    )
    .unwrap()
}

#[test]
fn certified_route_context_is_independently_verified_from_an_empty_cache() {
    let mut f = Fixture::new();
    f.register();
    let voucher = f.issue(2, 2 * CHARGE);
    let (intent, _, decision) = f.request(Command::VoucherContext { voucher }, 160, None);
    assert_eq!(decision.code, 0);
    let candidate = verified_context(&f, &intent, &decision, 5000);
    assert_eq!(
        candidate.state.record(165, RELAY).unwrap().reference,
        f.state.record(165, RELAY).unwrap().reference
    );
    assert_eq!(
        candidate.state.record(166, [201; 32]).unwrap().reference,
        f.state.record(166, [201; 32]).unwrap().reference
    );
}

#[test]
fn renewed_voucher_refreshes_retained_context_without_bypassing_admission() {
    use crate::{route_authority::retained_voucher, route_protocol::Open};
    let mut f = Fixture::new();
    f.register();
    let old = f.issue(2, 2 * CHARGE);
    f.apply(Fixture::permit(&old, 210), 160, None);
    let retained = f.state.clone();
    let charged = retained.record(167, old.id).unwrap().clone();
    let mut renewal = f.issue_command(2, 2 * CHARGE);
    if let Command::Issue { expires, .. } = &mut renewal {
        *expires = 19000;
    }
    let renewed = f.request_at(renewal, 5, Some(f.reader.clone()), 15000).2;
    assert_eq!(renewed.code, 0);
    f.state = renewed.state.unwrap();
    State::parse(&f.state.value(), N, I).unwrap();
    let current = f.state.record(166, old.id).unwrap().reference.clone();
    assert_eq!(current.generation, old.generation + 1);
    let open = Open {
        network: N,
        incarnation: I,
        relay: RELAY,
        service: DESTINATION,
        voucher: wire::encode(&reference(&current)).unwrap(),
        nonce: [215; 32],
        attachment: false,
    };
    assert!(
        retained_voucher(&retained, &current, &open, public(200))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        retained.record(167, old.id).unwrap().reference,
        charged.reference
    );

    // A claimed newer generation requests context; the authority still refuses unissued bytes.
    let mut forged = current.clone();
    forged.generation += 1;
    for reference in [
        forged,
        VersionRef {
            digest: [216; 32],
            ..current.clone()
        },
    ] {
        assert!(
            retained_voucher(&retained, &reference, &open, public(200))
                .unwrap()
                .is_none()
        );
        let denied = f
            .request_at(
                Command::VoucherContext {
                    voucher: reference.clone(),
                },
                160,
                None,
                15000,
            )
            .2;
        assert_eq!(denied.code, 3);
        assert!(denied.state.is_none());
        assert_eq!(
            f.request_at(Fixture::permit(&reference, 220), 160, None, 15000)
                .2
                .code,
            3
        );
    }
    assert_eq!(
        f.state.record(167, old.id).unwrap().reference,
        charged.reference
    );
    let (intent, _, context) = f.request_at(
        Command::VoucherContext {
            voucher: current.clone(),
        },
        160,
        None,
        15000,
    );
    assert_eq!(context.code, 0);
    assert!(context.state.is_none());
    let refreshed = verified_context(&f, &intent, &context, 15000).state;
    assert_eq!(
        refreshed.record(167, old.id).unwrap().reference,
        charged.reference
    );
    assert!(
        retained_voucher(&refreshed, &current, &open, public(200))
            .unwrap()
            .is_some()
    );
    assert!(retained_voucher(&refreshed, &old, &open, public(200)).is_err());
    let mut conflict = current.clone();
    conflict.digest = [217; 32];
    assert!(retained_voucher(&refreshed, &conflict, &open, public(200)).is_err());
    assert!(retained_voucher(&refreshed, &current, &open, public(199)).is_err());
    for field in [false, true] {
        let mut changed = open.clone();
        if field {
            changed.relay = [218; 32];
        } else {
            changed.service = [218; 32];
        }
        assert!(retained_voucher(&refreshed, &current, &changed, public(200)).is_err());
    }
    assert_eq!(
        f.request_at(Fixture::permit(&old, 220), 160, None, 15000)
            .2
            .code,
        3
    );
    let (intent, operation, permit) =
        f.request_at(Fixture::permit(&current, 220), 160, None, 15000);
    assert_eq!(permit.code, 0);
    f.state = permit.state.unwrap();
    let usage = Usage::parse(&f.state.record(167, current.id).unwrap().payload).unwrap();
    assert_eq!((usage.connections, usage.bytes), (2, 2 * CHARGE));
    let replay = operation
        .prepare(
            &f.state,
            &f.records,
            &f.reserved,
            &intent,
            15000,
            true,
            true,
        )
        .unwrap();
    assert_eq!(replay.code, 0);
    assert!(replay.state.is_none());
    assert_eq!(
        f.request_at(Fixture::permit(&current, 220), 160, None, 15000)
            .2
            .code,
        3
    );
}

#[test]
fn certified_attachment_lookup_covers_current_relay_and_endpoint() {
    let mut f = Fixture::new();
    f.profiles[1].mode = 3;
    f.profiles[1].relay = Some(RELAY);
    f.profiles[1].address = None;
    seal(&mut f.profiles[1], 92);
    f.register();
    let command = Command::Lookup {
        service: DESTINATION,
    };
    let (intent, _, decision) = f.request(command.clone(), 160, None);
    assert_eq!(decision.code, 0);
    let candidate = verified_context(&f, &intent, &decision, 5000);
    for profile in &f.profiles {
        let record = candidate
            .state
            .record(165, profile.identity.service)
            .unwrap();
        assert!(candidate.versions.contains(&record.reference));
        let current = Service::parse(&record.payload, N, I).unwrap();
        assert_eq!(current.profile.envelope, profile.envelope);
        assert!(!current.withdrawn);
        assert!(candidate.versions.contains(&profile.consent));
    }
    f.apply(
        Command::Withdraw {
            service: RELAY,
            generation: 1,
        },
        90,
        None,
    );
    assert_eq!(f.request(command, 160, None).2.code, 3);
}

#[test]
fn registered_route_merges_immutable_transport_roots_after_lookup_projection() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command as Process};
    let leaf = |seed: u8| {
        let path = std::env::temp_dir().join(format!(
            "HyperNetReservedRoute{}",
            hex::encode(crate::route_protocol::random().unwrap())
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut secret = vec![
            0x30, 0x2e, 0x02, 0x01, 0, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
            0x20,
        ];
        secret.extend([seed; 32]);
        fs::write(path.join("Key.der"), secret).unwrap();
        let output = Process::new("openssl")
            .args(["req", "-x509", "-keyform", "DER", "-key"])
            .arg(path.join("Key.der"))
            .args(["-outform", "DER", "-out"])
            .arg(path.join("Leaf.der"))
            .args(["-days", "1", "-subj", "/CN=HyperNetReservedRoute"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let bytes = fs::read(path.join("Leaf.der")).unwrap();
        fs::remove_dir_all(path).unwrap();
        bytes
    };
    let mut f = Fixture::with_route_transport(true, Some((9, leaf(9))));
    let profile = f.profiles[0].clone();
    let service = profile.identity.service;
    f.apply(
        Command::Register {
            profile: Box::new(profile.clone()),
        },
        5,
        Some(f.root.clone()),
    );
    let decision = f.request(Command::Lookup { service }, 160, None).2;
    assert_eq!(decision.code, 0);
    let value = decision.value.array(5).unwrap();
    let cached = value[4].array(4).unwrap()[2]
        .list(64)
        .unwrap()
        .iter()
        .map(|v| v.bytes().unwrap().to_vec())
        .collect::<Vec<_>>();
    assert!(
        Governance::record_versions(N, I, &cached)
            .unwrap()
            .iter()
            .all(|r| r.kind != 131)
    );
    assert!(Index::parse(&cached, &f.reserved, N, I).is_err());
    let bootstrap = crate::trust_bootstrap::check(&f.bootstrap, true, 1000).unwrap();
    let retained =
        crate::route_authority::registered(&bootstrap, &f.state, &cached, service, 5000).unwrap();
    assert_eq!(retained.envelope, profile.envelope);

    let changed = Fixture::with_route_transport(true, Some((10, leaf(10))));
    assert_eq!(
        changed
            .request(
                Command::Register {
                    profile: Box::new(changed.profiles[0].clone()),
                },
                5,
                Some(changed.root.clone()),
            )
            .2
            .code,
        3
    );
    assert!(
        crate::route_authority::registered(&bootstrap, &f.state, &changed.records, service, 5000,)
            .is_err()
    );
}

#[test]
fn certified_routes_bind_bootstrap_identifiers_and_exact_admitted_transport() {
    let f = Fixture::new();
    for id in [[0x12; 32], [0x14; 32]] {
        let mut profile = f.profiles[0].clone();
        profile.identity.service = id;
        seal(&mut profile, 90);
        assert_eq!(
            f.request(
                Command::Register {
                    profile: Box::new(profile)
                },
                5,
                Some(f.root.clone())
            )
            .2
            .code,
            3
        );
    }
    for change in 0..4 {
        let mut profile = f.profiles[0].clone();
        match change {
            0 => {
                profile.identity.transport_key = public(112);
                profile.identity.leaf_der = deployment::leaf(112);
            }
            1 => profile.consent.digest = [246; 32],
            2 => profile.address = Some("192.0.2.200:24005".parse().unwrap()),
            _ => profile.identity.leaf_der = deployment::leaf(111),
        }
        let signed =
            wire::sign_envelope(&profile.payload(N, I).unwrap(), &deployment::key(90)).unwrap();
        assert!(RegisteredProfile::parse(&signed, N, I).is_err());
    }
}

#[test]
fn fresh_route_reads_match_ordered_checks_without_consuming_voucher() {
    let mut f = Fixture::new();
    f.register();
    let voucher = f.issue(2, 2 * CHARGE);
    let cases = [
        (
            Command::Lookup {
                service: DESTINATION,
            },
            5,
            Some(f.reader.clone()),
        ),
        (
            Command::VoucherContext {
                voucher: voucher.clone(),
            },
            160,
            None,
        ),
    ];
    for (command, signer, grant) in cases {
        let (intent, op, ordered) = f.request(command, signer, grant);
        assert_eq!(ordered.code, 0);
        let before = wire::encode(&f.state.value()).unwrap();
        let fresh = crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            intent.requester,
            5000,
        )
        .unwrap();
        assert_eq!(
            (fresh.code, &fresh.value, &fresh.versions, fresh.expires_ms),
            (
                ordered.code,
                &ordered.value,
                &ordered.versions,
                ordered.expires_ms
            )
        );
        assert!(fresh.state.is_none());
        assert_eq!(wire::encode(&f.state.value()).unwrap(), before);
        assert!(!f.state.records.contains_key(&(167, voucher.id)));
    }
    let (_, op, _) = f.request(Fixture::permit(&voucher, 181), 160, None);
    assert!(
        crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            public(160),
            5000
        )
        .is_err()
    );
    let (_, op, _) = f.request(
        Command::VoucherContext {
            voucher: voucher.clone(),
        },
        160,
        None,
    );
    f.withdraw_deployment();
    assert_eq!(
        crate::authority_read::evaluate_domain(
            &op,
            &f.state,
            &f.records,
            &f.reserved,
            public(160),
            5000
        )
        .unwrap()
        .code,
        3
    );
}

#[path = "ApplicationStreamsTests.rs"]
mod application_stream_tests;

#[test]
fn early_handover_preserves_existing_charge_and_current_context_without_reopening_old_credentials()
{
    let mut f = Fixture::new();
    f.register();
    let old = f.issue(2, 2 * CHARGE);
    f.apply(Fixture::permit(&old, 210), 160, None);
    let old_voucher = Voucher::parse(&f.state.record(166, old.id).unwrap().payload).unwrap();
    let usage = f.state.record(167, old.id).unwrap().clone();
    let mut renewal = f.issue_command(2, 2 * CHARGE);
    if let Command::Issue { expires, .. } = &mut renewal {
        *expires = 19000;
    }
    let renewed = f.request_at(renewal, 5, Some(f.reader.clone()), 10000).2;
    assert_eq!(renewed.code, 0);
    f.state = renewed.state.unwrap();
    let current = f.state.record(166, old.id).unwrap().reference.clone();
    let replacement = Voucher::parse(&f.state.record(166, old.id).unwrap().payload).unwrap();
    assert!(replacement.continues(&old_voucher));
    assert_eq!(
        f.state.record(167, old.id).unwrap().reference,
        usage.reference
    );
    assert_eq!(
        f.request_at(
            Command::VoucherContext {
                voucher: old.clone()
            },
            160,
            None,
            10000
        )
        .2
        .code,
        0
    );
    assert_ne!(
        f.request_at(Fixture::permit(&old, 211), 160, None, 10000)
            .2
            .code,
        0
    );
    let allowed = f
        .request_at(Fixture::permit(&current, 212), 160, None, 10000)
        .2;
    assert_eq!(allowed.code, 0);
    f.state = allowed.state.unwrap();
    assert_ne!(
        f.request_at(Fixture::permit(&current, 213), 160, None, 10000)
            .2
            .code,
        0
    );
    let mut changed = replacement.clone();
    changed.possession = public(201);
    assert!(!changed.continues(&old_voucher));
}

#[test]
fn scoped_voucher_issuance_checks_real_service_consent_and_member_capability() {
    for expires in [20_000, 500_000] {
        let validity = (1000, expires).into();
        let mut f = Fixture::with_route_validity(true, None, validity);
        f.register();
        let authority = [173; 32];
        let mut profile = Fixture::admit_with_validity(
            &mut f.records,
            &f.reserved,
            &f.root,
            2,
            true,
            None,
            validity,
        );
        profile.identity.service = authority;
        seal(&mut profile, 94);
        f.apply(
            Command::Register {
                profile: Box::new(profile),
            },
            5,
            Some(f.root.clone()),
        );
        let slot = crate::authority_admission::tests::append_route_slot(
            &mut f.records,
            &f.reserved,
            RELAY,
            authority,
            DESTINATION,
        );
        let result = scoped_vouchers(&f.state, &f.records, &f.reserved, &slot, 5000, [199; 32]);
        if expires == 20_000 {
            assert_eq!(
                result.err().unwrap().to_string(),
                "scoped route consent has insufficient finite headroom"
            );
        } else {
            let state = result.unwrap();
            let vouchers = state
                .records
                .values()
                .filter(|r| r.reference.kind == 166)
                .map(|r| Voucher::parse(&r.payload).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(vouchers.len(), 4);
            assert!(vouchers.iter().all(|v| v.expires == 125_000));
            let mut depleted = state.clone();
            let exhausted = depleted
                .records
                .values()
                .find(|r| r.reference.kind == 166)
                .unwrap()
                .clone();
            let allowance = Voucher::parse(&exhausted.payload).unwrap();
            let usage = Usage {
                connections: 1,
                bytes: allowance.bytes,
                connection: [222; 32],
                transcript: [223; 32],
                creation: [224; 32],
            };
            depleted
                .put(Record::next(&depleted, 167, exhausted.reference.id, usage.value()).unwrap())
                .unwrap();
            let refreshed = scoped_vouchers(
                &depleted,
                &f.records,
                &f.reserved,
                &slot,
                100_000,
                [200; 32],
            )
            .unwrap();
            assert_eq!(
                refreshed.record(166, exhausted.reference.id).unwrap().bytes,
                exhausted.bytes,
                "refreshing another role must not postpone exhausted route recovery"
            );
            assert!(refreshed.records.values().any(|r| r.reference.kind == 166
                && Voucher::parse(&r.payload).unwrap().expires > 125_000));
            let recovered = scoped_vouchers(
                &refreshed,
                &f.records,
                &f.reserved,
                &slot,
                125_000,
                [201; 32],
            )
            .unwrap();
            let renewed = Voucher::parse(
                &recovered
                    .record(166, exhausted.reference.id)
                    .unwrap()
                    .payload,
            )
            .unwrap();
            assert_eq!(renewed.baseline, Some((usage.connections, usage.bytes)));
            assert_eq!(renewed.connections, allowance.connections);
            assert_eq!(renewed.bytes, allowance.bytes);
            assert!(renewed.expires > 125_000);
            assert_eq!(recovered.records.len(), refreshed.records.len());
            let already_expanded = Index::parse(&f.records, &f.reserved, N, I)
                .unwrap()
                .extend_reservations(&f.reserved);
            assert!(
                scoped_vouchers(
                    &f.state,
                    &f.records,
                    &already_expanded,
                    &slot,
                    5000,
                    [199; 32]
                )
                .is_err(),
                "deployment-derived keys cannot be reclassified as bootstrap reservations"
            );
        }
    }
}

#[test]
fn exact_live_handover_refuses_delayed_expiry_and_replays_without_resetting_usage() {
    let mut f = Fixture::new();
    f.register();
    let previous = f.issue(2, 2 * CHARGE);
    f.apply(Fixture::permit(&previous, 210), 160, None);
    let old = Voucher::parse(&f.state.record(166, previous.id).unwrap().payload).unwrap();
    let usage = f.state.record(167, previous.id).unwrap().reference.clone();
    let handover = Command::Handover {
        voucher: previous.clone(),
        expires: 19000,
    };
    let encoded = handover.value();
    assert_eq!(
        Command::parse(&encoded, N, I).unwrap().name(),
        "RouteHandover"
    );
    assert!(
        Command::parse(
            &a(vec![
                V::Text("RouteHandover".into()),
                V::Uint(2),
                reference(&previous),
                V::Uint(19000)
            ]),
            N,
            I
        )
        .is_err()
    );
    let (intent, operation, decision) =
        f.request_at(handover.clone(), 5, Some(f.reader.clone()), 10000);
    assert_eq!(decision.code, 0);
    // A queued signed handover must not turn into post-expiry allowance renewal.
    assert_ne!(
        operation
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &intent,
                old.expires,
                false,
                true
            )
            .unwrap()
            .code,
        0
    );
    f.state = decision.state.unwrap();
    let current = Voucher::parse(&f.state.record(166, previous.id).unwrap().payload).unwrap();
    assert!(current.continues(&old));
    assert_eq!(f.state.record(167, previous.id).unwrap().reference, usage);
    assert_eq!(
        operation
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &intent,
                10000,
                true,
                true
            )
            .unwrap()
            .code,
        0
    );
    assert_ne!(
        f.request_at(handover, 5, Some(f.reader.clone()), 10000)
            .2
            .code,
        0
    );
}

#[test]
fn depleted_handover_preserves_expiry_until_normal_post_expiry_renewal() {
    let mut f = Fixture::new();
    f.register();
    let previous = f.issue(1, CHARGE);
    f.apply(Fixture::permit(&previous, 210), 160, None);
    let before = f.state.record(166, previous.id).unwrap().clone();
    assert_ne!(
        f.request_at(
            Command::Handover {
                voucher: previous.clone(),
                expires: 19000
            },
            5,
            Some(f.reader.clone()),
            10000
        )
        .2
        .code,
        0
    );
    assert_eq!(
        f.state.record(166, previous.id).unwrap().bytes,
        before.bytes
    );
    let mut issue = f.issue_command(1, CHARGE);
    if let Command::Issue { expires, .. } = &mut issue {
        *expires = 19000;
    }
    let renewed = f.request_at(issue, 5, Some(f.reader.clone()), 15000).2;
    assert_eq!(renewed.code, 0);
    let record = renewed
        .state
        .unwrap()
        .record(166, previous.id)
        .unwrap()
        .clone();
    let voucher = Voucher::parse(&record.payload).unwrap();
    assert_eq!(voucher.baseline, Some((1, CHARGE)));
    assert_eq!(voucher.connections, 1);
    assert_eq!(voucher.bytes, CHARGE);
}

// Real certificates exercise the independent route decoder without synthetic TLS pins.
pub(crate) fn certificate_profiles() -> (RegisteredProfile, RegisteredProfile) {
    let (issuer, next_issuer, leaf, next_leaf) =
        crate::runtime_manifest::certificates::tests::route_certificates();
    let mut before = Fixture::with_route_transport(true, Some((110, leaf))).profiles[0].clone();
    before.manifest.validity =
        crate::trust_validity::Validity(1000, crate::trust_validity::End::UntilWithdrawn);
    before.validity = before.manifest.validity;
    before.identity.service = RELAY;
    before.identity.certificate_authority_pem = issuer.clone();
    before.identity.server_name = "192.0.2.10".into();
    let bind = |profile: &mut RegisteredProfile| {
        profile.deployment_profile =
            crate::authority_deployment_records::reference(&profile.manifest.desired().unwrap())
                .unwrap();
        profile.consent = crate::authority_deployment_records::reference(
            &profile.manifest.unsigned_consent(0).unwrap(),
        )
        .unwrap();
        seal(profile, 90);
    };
    bind(&mut before);
    let mut after = before.clone();
    after.manifest.generation += 1;
    after.manifest.previous_profile = Some(wire::digest(&before.manifest.desired().unwrap()));
    after.manifest.previous_consent =
        Some(wire::digest(&before.manifest.unsigned_consent(0).unwrap()));
    after
        .manifest
        .adopt_certificates(
            &before.manifest,
            next_issuer.clone(),
            &[(before.endpoint, next_leaf.clone())].into_iter().collect(),
            issuer,
        )
        .unwrap();
    after.identity.leaf_der = next_leaf;
    after.identity.certificate_authority_pem = next_issuer;
    bind(&mut after);
    (before, after)
}

#[test]
fn permanent_route_accepts_only_actual_same_key_certificate_successor() {
    let (before, after) = certificate_profiles();
    after.successor_of(&before).unwrap();
    assert_eq!(after.validity, before.validity);
    assert_eq!(
        after.manifest.operational_digest().unwrap(),
        before.manifest.operational_digest().unwrap()
    );
    let mut no_change = before.clone();
    no_change.manifest.generation += 1;
    assert!(no_change.successor_of(&before).is_err());
    for change in 0..5 {
        let mut changed = after.clone();
        match change {
            0 => changed.identity.transport_key = [222; 32],
            1 => changed.identity.server_name = "unrelated.invalid".into(),
            2 => changed.limits.bytes += 1,
            3 => changed.identity.certificate_authority_pem = String::new(),
            _ => changed.validity.0 += 1,
        }
        assert!(
            changed.successor_of(&before).is_err(),
            "certificate route change {change}"
        );
    }
}

#[test]
fn certified_certificate_refresh_preserves_live_voucher_usage_and_exact_handover_fence() {
    let (issuer, new_issuer, leaf, new_leaf) =
        crate::runtime_manifest::certificates::tests::route_certificates();
    let mut f = Fixture::with_route_transport(true, Some((110, leaf)));
    f.profiles[0].identity.service = RELAY;
    f.profiles[0].identity.server_name = "192.0.2.10".into();
    f.profiles[0].identity.certificate_authority_pem = issuer.clone();
    seal(&mut f.profiles[0], 90);
    f.register();
    let previous = f.issue(2, 2 * CHARGE);
    f.apply(Fixture::permit(&previous, 210), 160, None);
    let usage = f.state.record(167, previous.id).unwrap().clone();
    let old = Voucher::parse(&f.state.record(166, previous.id).unwrap().payload).unwrap();
    let mut manifest = f.profiles[0].manifest.clone();
    manifest.generation += 1;
    manifest.previous_profile = Some(wire::digest(&f.profiles[0].manifest.desired().unwrap()));
    manifest.previous_consent = Some(wire::digest(
        &f.profiles[0].manifest.unsigned_consent(0).unwrap(),
    ));
    manifest
        .adopt_certificates(
            &f.profiles[0].manifest,
            new_issuer,
            &[(f.profiles[0].endpoint, new_leaf)].into_iter().collect(),
            issuer,
        )
        .unwrap();
    let profile = f.admit_successor(0, manifest);
    f.apply(
        Command::Register {
            profile: Box::new(profile),
        },
        5,
        Some(f.root.clone()),
    );
    assert_ne!(
        f.request(
            Command::Handover {
                voucher: previous.clone(),
                expires: 19000
            },
            5,
            Some(f.reader.clone())
        )
        .2
        .code,
        0,
        "exact live handover cannot silently switch its service certificate reference"
    );
    let mut command = f.issue_command(2, 2 * CHARGE);
    if let Command::Issue { expires, .. } = &mut command {
        *expires = old.expires;
    }
    f.apply(command, 5, Some(f.reader.clone()));
    let record = f.state.record(166, previous.id).unwrap();
    let refreshed = Voucher::parse(&record.payload).unwrap();
    assert!(refreshed.relay.generation > old.relay.generation);
    assert_eq!(refreshed.destination, old.destination);
    assert_eq!(refreshed.baseline, Some(old.baseline.unwrap_or((0, 0))));
    assert_eq!(f.state.record(167, previous.id).unwrap().bytes, usage.bytes);
    let reference = record.reference.clone();
    f.apply(Fixture::permit(&reference, 211), 160, None);
    assert_ne!(
        f.request(Fixture::permit(&reference, 212), 160, None)
            .2
            .code,
        0,
        "certificate refresh cannot refill the live allowance"
    );
}
