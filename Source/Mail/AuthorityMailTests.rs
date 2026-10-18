// SPDX-License-Identifier: MIT
// One-use packages, owner-selected placement and identity removal remain effective across exact retries.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_governance::Governance};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::Signer;
fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
struct Fixture {
    state: State,
    bootstrap: crate::trust_bootstrap::Verified,
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    grant: VersionRef,
    profile: Profile,
    sequence: u64,
}
impl Fixture {
    fn new() -> Self {
        let f = deployment::Fixture::with_actions(vec![0, 10, 11, 12, 13, 14, 15, 16, 26]);
        let mut manifest = deployment::manifest();
        manifest.consent_policy.allow_opaque = true;
        let (records, _, _, _) = deployment::admitted(&f, &deployment::offer(manifest.clone()));
        let grant = Governance::parse(manifest.network, manifest.incarnation, &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let mut profile = Profile {
            manifest: manifest.clone(),
            service: public(102),
            endpoint: Some([83; 32]),
            volume: [103; 32],
            state_bytes: 8 * 1024 * 1024,
            maximum_payload: MAXIMUM_PAYLOAD,
            maximum_lifetime_ms: MAXIMUM_LIFETIME_MS,
            envelope: vec![],
        };
        profile.envelope =
            wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
        profile =
            Profile::parse(&profile.envelope, manifest.network, manifest.incarnation).unwrap();
        Self {
            state: State::empty(manifest.network, manifest.incarnation),
            bootstrap: crate::trust_bootstrap::check(&f.bootstrap, true, 1000).unwrap(),
            records,
            reserved: f.reservations,
            grant,
            profile,
            sequence: 1,
        }
    }
    fn request(
        &self,
        seed: u8,
        command: Command,
        grant: Option<VersionRef>,
        exact: bool,
    ) -> (Intent, Operation) {
        let mut operation = Operation {
            grant,
            command: command.into(),
            snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        let mut intent = Intent {
            network: self.state.network,
            incarnation: self.state.incarnation,
            generation: 1,
            generation_id: [182; 32],
            sequence: self.sequence,
            acknowledged_through: self.sequence - 1,
            requester: public(seed),
            action: "AuthorityDomain".into(),
            resource: operation.command.resource(),
            revision: u64::from(operation.mutation()),
            profile_generation: 0,
            minimum_policy_epoch: 0,
            minimum_policy_height: 0,
            expected: vec![],
            parameters: operation.parameters().unwrap(),
            digest: wire::digest(&[seed, self.sequence as u8]),
        };
        if exact {
            let d = operation
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
            assert_eq!(d.code, 0);
            intent.expected = d.dependencies;
            operation.snapshot = snapshot(&deployment::snapshot(&intent.expected)).unwrap();
            intent.parameters = operation.parameters().unwrap();
        }
        (intent, operation)
    }
    fn apply(
        &mut self,
        seed: u8,
        command: Command,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        let (i, o) = self.request(seed, command, grant, true);
        let d = evaluate(
            &o,
            &match &o.command {
                super::super::Command::Mail(c) => c.clone(),
                _ => unreachable!(),
            },
            &self.state,
            &self.records,
            &self.reserved,
            &i,
            5000,
            false,
            true,
        )
        .unwrap();
        assert_eq!(d.code, 0);
        if let Some(s) = &d.state {
            self.state = s.clone();
        }
        self.sequence += 1;
        State::parse(
            &self.state.value(),
            self.state.network,
            self.state.incarnation,
        )
        .unwrap();
        (i, o, d)
    }
    fn denied(&self, seed: u8, command: Command, grant: Option<VersionRef>) {
        let (i, o) = self.request(seed, command, grant, false);
        assert_ne!(
            o.prepare(
                &self.state,
                &self.records,
                &self.reserved,
                &i,
                5000,
                false,
                false
            )
            .unwrap()
            .code,
            0
        );
    }
    fn register(&mut self) {
        self.apply(
            5,
            Command::Register {
                profile: self.profile.clone(),
            },
            Some(self.grant.clone()),
        );
    }
    fn publication(&self, owner: u8, request: u8, signer: u8) -> objects::Publication {
        let n = self.state.network;
        let address = objects::address(n, public(owner));
        let m = objects::Manifest {
            version: 1,
            network: hex::encode(n),
            address_id: hex::encode(address),
            owner_key: hex::encode(public(owner)),
            generation: 1,
            previous_digest: None,
            expires: 18,
            devices: vec![objects::Device {
                device_id: hex::encode(objects::device(address, public(request))),
                request_key: hex::encode(public(request)),
                mls_signature_key: hex::encode(public(signer)),
                permissions: vec!["Read".into(), "Send".into(), "Delete".into()],
                expires: 17,
            }],
            storage_hosts: vec![hex::encode(self.profile.service)],
            required_copies: 1,
            retention_seconds: 60,
            deleted: false,
        };
        self.sign(owner, m)
    }
    fn sign(&self, owner: u8, manifest: objects::Manifest) -> objects::Publication {
        let payload = serde_json::to_vec(&manifest).unwrap();
        let mut bytes = objects::MANIFEST_DOMAIN.to_vec();
        bytes.extend(self.state.network);
        bytes.extend(public(owner));
        bytes.extend(&payload);
        let signed = objects::Signed {
            network: hex::encode(self.state.network),
            public_key: hex::encode(public(owner)),
            payload: B64.encode(payload),
            signature: hex::encode(deployment::key(owner).sign(&bytes).to_bytes()),
        };
        objects::Publication::parse(&serde_json::to_vec(&signed).unwrap(), self.state.network)
            .unwrap()
    }
    fn publish(&mut self, p: objects::Publication) {
        self.apply(
            5,
            Command::Publish {
                publication: p,
                private: true,
            },
            Some(self.grant.clone()),
        );
    }
}
#[test]
fn mail_claims_consume_packages_once_and_bind_only_one_ciphertext() {
    let mut f = Fixture::new();
    f.register();
    let sender = f.publication(170, 171, 172);
    let recipient = f.publication(173, 174, 175);
    let source = sender.id().unwrap();
    let target = recipient.id().unwrap();
    f.publish(sender);
    f.publish(recipient.clone());
    assert_eq!(f.state.requesters().len(), 2);
    assert!(!f.state.requesters().contains(&public(170)));
    let package = objects::Package {
        device_id: recipient.manifest.devices[0].device_id.clone(),
        reference: B64.encode([190; 32]),
        expires: 16,
        package: B64.encode([1, 2, 3, 4]),
    };
    f.apply(
        174,
        Command::Package {
            address: target,
            package: package.clone(),
        },
        None,
    );
    let p = f
        .state
        .record(
            138,
            package
                .id(f.state.network, f.state.incarnation, target)
                .unwrap(),
        )
        .unwrap()
        .reference
        .clone();
    let claim = Command::Claim {
        id: [191; 32],
        sender: source,
        recipient: target,
        packages: vec![p.clone()],
        expires: 14000,
    };
    let (i, o, _) = f.apply(171, claim.clone(), None);
    assert_eq!(
        o.prepare(&f.state, &f.records, &f.reserved, &i, 5000, true, true)
            .unwrap()
            .code,
        0
    );
    f.denied(
        171,
        Command::Claim {
            id: [192; 32],
            sender: source,
            recipient: target,
            packages: vec![p],
            expires: 14000,
        },
        None,
    );
    let ciphertext = b"Opaque encrypted message";
    f.apply(
        171,
        Command::Bind {
            id: [191; 32],
            bytes: ciphertext.len() as u64,
            digest: wire::digest(ciphertext),
        },
        None,
    );
    f.denied(
        171,
        Command::Bind {
            id: [191; 32],
            bytes: 4,
            digest: [193; 32],
        },
        None,
    );
    let put = Command::Execute {
        address: target,
        service: f.profile.service,
        effect: Effect::Put,
        message: Some([191; 32]),
        claim: Some([191; 32]),
        bytes: ciphertext.len() as u64,
        digest: Some(wire::digest(ciphertext)),
        after: None,
    };
    let (_, operation, decision) = f.apply(171, put.clone(), None);
    let signed = deployment::signed(
        &deployment::key(171),
        "AuthorityDomain",
        operation.command.resource(),
        0,
        wire::decode(&operation.parameters().unwrap()).unwrap(),
        operation.snapshot.references.clone(),
    );
    let request = Request::parse(&signed).unwrap();
    let records = decision.value.array(5).unwrap()[4].array(4).unwrap()[2]
        .list(64)
        .unwrap()
        .iter()
        .map(|v| v.bytes().unwrap().to_vec())
        .collect::<Vec<_>>();
    assert!(
        !Governance::record_versions(f.state.network, f.state.incarnation, &records)
            .unwrap()
            .iter()
            .any(|r| r.kind == 114)
    );
    assert!(Governance::parse(f.state.network, f.state.incarnation, &records).is_err());
    for (value, allowed) in [
        (&decision.value, true),
        (&deployment::without_live_consent(&decision.value), false),
    ] {
        let proof = deployment::serving_result(&f.bootstrap, &signed, value, 102);
        let verified = request.verify(
            &f.bootstrap,
            f.bootstrap.descriptor(),
            &proof.challenge,
            &proof.ordered,
            &proof.operation,
            &proof.certificate,
            &proof.ancestry,
            &[],
        );
        assert_eq!(
            verified.is_ok(),
            allowed,
            "serving Put must use accepted bootstrap and exact live consent: {:?}",
            verified.as_ref().err()
        );
    }
    let mut wrong = put.clone();
    if let Command::Execute { service, .. } = &mut wrong {
        *service = public(194);
    }
    f.denied(171, wrong, None);
    // Removing a recipient device races with delivery by advancing the exact signed mailbox revision.
    let mut m = recipient.manifest.clone();
    m.generation = 2;
    m.previous_digest = Some(hex::encode(recipient.digest));
    m.devices[0].permissions = vec!["Send".into()];
    let revoked = f.sign(173, m);
    f.publish(revoked);
    assert!(f.state.requesters().contains(&public(174)));
    f.denied(171, put, None);
    f.denied(
        174,
        Command::Package {
            address: target,
            package,
        },
        None,
    );
    assert_eq!(
        Claim::parse(&f.state.record(139, [191; 32]).unwrap().payload)
            .unwrap()
            .packages
            .len(),
        1
    );
}
#[test]
fn mail_placement_and_owner_continuity_cannot_be_overridden_by_manager() {
    let mut f = Fixture::new();
    f.register();
    let p = f.publication(170, 171, 172);
    let address = p.id().unwrap();
    f.publish(p.clone());
    let mut m = p.manifest.clone();
    m.generation = 2;
    m.previous_digest = Some(hex::encode(p.digest));
    m.storage_hosts.push(hex::encode(public(180)));
    m.required_copies = 2;
    let two = f.sign(170, m);
    let value = Mailbox {
        publication: two,
        manager: public(5),
        grant: f.grant.clone(),
        private: true,
        creation: [181; 32],
    }
    .value();
    assert!(Mailbox::parse(&value, f.state.network).is_err());
    let mut wrong = p.manifest.clone();
    wrong.generation = 2;
    wrong.previous_digest = Some(hex::encode([182; 32]));
    let wrong = f.sign(170, wrong);
    f.denied(
        5,
        Command::Publish {
            publication: wrong,
            private: true,
        },
        Some(f.grant.clone()),
    );
    assert_eq!(
        Mailbox::parse(
            &f.state.record(137, address).unwrap().payload,
            f.state.network
        )
        .unwrap()
        .publication
        .bytes,
        p.bytes
    );
    // Device keys are dedicated and cannot coincide with an admitted member or later become one.
    let invalid = f.publication(176, 5, 177);
    f.denied(
        5,
        Command::Publish {
            publication: invalid,
            private: true,
        },
        Some(f.grant.clone()),
    );
}

pub(crate) fn storage_fixture() -> (Profile, Mailbox, Claim, Command) {
    let mut f = Fixture::new();
    f.register();
    let publication = f.publication(170, 171, 172);
    let address = publication.id().unwrap();
    f.publish(publication);
    let r = f.state.record(137, address).unwrap();
    let mailbox = Mailbox::parse(&r.payload, f.state.network).unwrap();
    let payload = b"retained ciphertext";
    let claim = Claim {
        sender: r.reference.clone(),
        recipient: r.reference.clone(),
        device: public(171),
        packages: vec![],
        expires: 20_000,
        creation: [190; 32],
        payload_digest: Some(wire::digest(payload)),
        payload_bytes: payload.len() as u64,
        binding: Some([191; 32]),
        placement: vec![
            f.state
                .record(136, f.profile.service)
                .unwrap()
                .reference
                .clone(),
        ],
        created_ms: 5_000,
    };
    let command = Command::Execute {
        address,
        service: f.profile.service,
        effect: Effect::Put,
        message: Some([192; 32]),
        claim: Some([192; 32]),
        bytes: payload.len() as u64,
        digest: Some(wire::digest(payload)),
        after: None,
    };
    (f.profile, mailbox, claim, command)
}

#[test]
fn full_mail_inventory_refuses_new_publication_atomically() {
    let mut f = Fixture::new();
    f.register();
    let publication = f.publication(170, 171, 172);
    let address = publication.id().unwrap();
    f.publish(publication.clone());
    let mailbox = f.state.record(137, address).unwrap().reference.clone();
    let package = |number: u64| {
        let mut reference = [0; 32];
        reference[..8].copy_from_slice(&number.to_be_bytes());
        objects::Package {
            device_id: publication.manifest.devices[0].device_id.clone(),
            reference: B64.encode(reference),
            expires: 16,
            package: B64.encode([1, 2, 3, 4]),
        }
    };
    for number in 1..=(super::super::MAXIMUM_RECORDS - f.state.records.len()) as u64 {
        let package = package(number);
        let key = package
            .id(f.state.network, f.state.incarnation, address)
            .unwrap();
        let record = Record::next(
            &f.state,
            138,
            key,
            Inventory {
                mailbox: mailbox.clone(),
                package,
                creation: [196; 32],
            }
            .value()
            .unwrap(),
        )
        .unwrap();
        f.state.records.insert(record.reference.index(), record);
    }
    State::parse(&f.state.value(), f.state.network, f.state.incarnation).unwrap();
    let before = f.state.value();
    let cmd = Command::Package {
        address,
        package: package(u64::MAX),
    };
    let (intent, op) = f.request(171, cmd, None, false);
    let d = op
        .prepare(
            &f.state,
            &f.records,
            &f.reserved,
            &intent,
            5000,
            false,
            false,
        )
        .unwrap();
    assert_eq!(d.code, 2);
    assert!(d.state.is_none());
    assert_eq!(d.value, a(vec![]));
    assert_eq!(f.state.value(), before);
}

#[test]
fn mail_device_refresh_carries_manager_capability_for_refill() {
    let mut f = Fixture::new();
    f.register();
    let publication = f.publication(173, 174, 175);
    let address = publication.id().unwrap();
    let governance = Governance::parse(f.state.network, f.state.incarnation, &f.records).unwrap();
    let V::Array(mut fields) =
        wire::decode(governance.record_bytes(102, f.grant.id).unwrap()).unwrap()
    else {
        unreachable!()
    };
    fields[6] = b(&[25; 32]);
    fields[10] = a(vec![V::Uint(15), V::Uint(16)]);
    fields[13] = reference(&f.grant);
    fields[14] = V::Uint(0);
    fields[16] = deployment::snapshot(&[]);
    let delegated = wire::encode(&a(fields)).unwrap();
    let grant = Governance::record_versions(
        f.state.network,
        f.state.incarnation,
        std::slice::from_ref(&delegated),
    )
    .unwrap()
    .remove(0);
    f.records.push(delegated);
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    f.apply(
        5,
        Command::Publish {
            publication: publication.clone(),
            private: true,
        },
        Some(grant.clone()),
    );
    let (_, _, refreshed) = f.apply(
        174,
        Command::Get {
            address,
            source: None,
        },
        None,
    );
    let body = refreshed.value.array(5).unwrap()[4].array(4).unwrap();
    let records = body[2]
        .list(MAXIMUM_CONTEXT_RECORDS)
        .unwrap()
        .iter()
        .map(|v| v.bytes().unwrap().to_vec())
        .collect::<Vec<_>>();
    assert!(
        Governance::record_versions(f.state.network, f.state.incarnation, &records)
            .unwrap()
            .contains(&grant)
    );
    assert!(!f.bootstrap.governance_records().iter().any(|bytes| {
        Governance::record_versions(
            f.state.network,
            f.state.incarnation,
            std::slice::from_ref(bytes),
        )
        .unwrap()
        .contains(&grant)
    }));
    let records = super::super::result::merge(&f.bootstrap, &records).unwrap();
    let mut state = State::empty(f.state.network, f.state.incarnation);
    for value in body[1].list(MAXIMUM_CONTEXT_RECORDS).unwrap() {
        let record =
            Record::parse(value.bytes().unwrap(), state.network, state.incarnation).unwrap();
        state.records.insert(record.reference.index(), record);
    }
    let (intent, operation) = f.request(
        174,
        Command::Package {
            address,
            package: objects::Package {
                device_id: publication.manifest.devices[0].device_id.clone(),
                reference: B64.encode([190; 32]),
                expires: 16,
                package: B64.encode([1, 2, 3, 4]),
            },
        },
        None,
        false,
    );
    let prepared = operation
        .prepare(&state, &records, &f.reserved, &intent, 5000, false, false)
        .unwrap();
    assert_eq!(
        prepared.code, 0,
        "a fresh device can refill from its authenticated refresh alone"
    );
}
