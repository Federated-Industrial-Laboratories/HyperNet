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
        let f = deployment::Fixture::with_actions(vec![0, 6, 10, 11, 12, 13, 26]);
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
        let profiles =
            [0, 1].map(|index| Self::admit(&mut records, &f.reservations, &root, index, separate));
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
    fn admit(
        records: &mut Vec<Vec<u8>>,
        reserved: &Reservations,
        grant: &VersionRef,
        index: u8,
        separate: bool,
    ) -> RegisteredProfile {
        let service = 160 + index;
        let transport = 110 + index;
        let operator = 90 + index * 2 * u8::from(separate);
        let mut manifest = deployment::manifest();
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
        manifest.endpoints[0].leaf_der = deployment::leaf(transport);
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
                service: if index == 0 { RELAY } else { DESTINATION },
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
                5000,
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
                    5000,
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
) -> super::super::result::Candidate {
    use crate::authority_proof::{Disposition, ExecutedResult, OperationResult, Restrictions};
    let bootstrap = crate::trust_bootstrap::check(&f.bootstrap, true, 5000).unwrap();
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
        evaluated_at_ms: 5000,
        expires_at_ms: 14000,
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
    let candidate = verified_context(&f, &intent, &decision);
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
    let candidate = verified_context(&f, &intent, &decision);
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
