// SPDX-License-Identifier: MIT
// Complete metadata lifecycles reject substituted storage, stale acceptance and revoked sender authority.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_governance::Governance};
use ed25519_dalek::SigningKey;
fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
struct Fixture {
    state: State,
    bootstrap: crate::trust_bootstrap::Verified,
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    root: VersionRef,
    reader: VersionRef,
    profile: Profile,
    sequence: u64,
}
impl Fixture {
    fn new() -> Self {
        let f = deployment::Fixture::with_actions(vec![0, 10, 11, 12, 13, 18, 19, 26]);
        let mut m = deployment::manifest();
        m.consent_policy.allow_opaque = true;
        let off = deployment::offer(m.clone());
        let (mut records, _, _, _) = deployment::admitted(&f, &off);
        let g = Governance::parse(m.network, m.incarnation, &records).unwrap();
        let root = g
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let tier = g.versions().into_iter().find(|r| r.kind == 101).unwrap();
        let reader = wire::encode(&a(vec![
            V::Uint(102),
            V::Uint(1),
            b(&m.network),
            b(&m.incarnation),
            V::Uint(1),
            V::Null,
            b(&[29; 32]),
            b(&public(5)),
            b(&public(150)),
            reference(&tier),
            a(vec![V::Uint(0), V::Uint(19)]),
            a(vec![a(vec![V::Uint(0), b(&m.network)])]),
            a(vec![V::Uint(1000), V::Uint(800000)]),
            reference(&root),
            V::Uint(0),
            a(vec![
                V::Uint(268435456),
                V::Uint(20480),
                V::Uint(128),
                V::Uint(32),
            ]),
            deployment::snapshot(&[]),
        ]))
        .unwrap();
        records.push(reader);
        crate::authority_membership::sort_records(&mut records).unwrap();
        let reader = Governance::parse(m.network, m.incarnation, &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [29; 32])
            .unwrap();
        records.push(
            wire::encode(&a(vec![
                V::Uint(125),
                V::Uint(1),
                b(&m.network),
                b(&m.incarnation),
                V::Uint(1),
                V::Null,
                b(&[28; 32]),
                b(&public(150)),
                a(vec![V::Uint(1000), V::Uint(800000)]),
                V::Bool(false),
                reference(&reader),
                deployment::snapshot(&[]),
            ]))
            .unwrap(),
        );
        crate::authority_membership::sort_records(&mut records).unwrap();
        let mut profile = Profile {
            manifest: m.clone(),
            service: public(103),
            endpoint: Some([84; 32]),
            volume: [104; 32],
            state_bytes: 32 * 1024 * 1024,
            maximum_payload: MAXIMUM_PAYLOAD,
            maximum_lifetime_ms: MAXIMUM_LIFETIME_MS,
            envelope: vec![],
        };
        profile.envelope =
            wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
        profile = Profile::parse(&profile.envelope, m.network, m.incarnation).unwrap();
        Self {
            bootstrap: crate::trust_bootstrap::check(&f.bootstrap, true, 1000).unwrap(),
            state: State::empty(m.network, m.incarnation),
            records,
            reserved: f.reservations,
            root,
            reader,
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
        let mut op = Operation {
            grant,
            command: command.into(),
            snapshot: snapshot(&deployment::snapshot(&[])).unwrap(),
        };
        let mut intent = Intent {
            network: self.state.network,
            incarnation: self.state.incarnation,
            generation: 1,
            generation_id: [180; 32],
            sequence: self.sequence,
            acknowledged_through: self.sequence - 1,
            requester: public(seed),
            action: "AuthorityDomain".into(),
            resource: op.command.resource(),
            revision: u64::from(op.mutation()),
            profile_generation: 0,
            minimum_policy_epoch: 0,
            minimum_policy_height: 0,
            expected: vec![],
            parameters: op.parameters().unwrap(),
            digest: wire::digest(&[seed, self.sequence as u8]),
        };
        if exact {
            let d = op
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
            op.snapshot = snapshot(&deployment::snapshot(&intent.expected)).unwrap();
            intent.parameters = op.parameters().unwrap();
        }
        (intent, op)
    }
    fn apply(
        &mut self,
        seed: u8,
        command: Command,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        let (i, o) = self.request(seed, command, grant, true);
        let d = o
            .prepare(
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
        (i, o, d)
    }
    fn offer(&self, id: u8) -> Offer {
        let mut o = Offer {
            network: self.state.network,
            incarnation: self.state.incarnation,
            id: [id; 32],
            sender: public(5),
            recipient: public(150),
            encryption_key: bech32::encode("age", vec![173; 32].to_base32(), Variant::Bech32)
                .unwrap(),
            payload_bytes: 1024,
            payload_digest: [174; 32],
            file_bytes: 100,
            label: "Document".into(),
            expires: 15000,
            envelope: vec![],
        };
        o.envelope = wire::sign_envelope(&o.payload().unwrap(), &deployment::key(5)).unwrap();
        Offer::parse(&o.envelope, o.network, o.incarnation).unwrap()
    }
    fn setup(&mut self) {
        self.apply(
            5,
            Command::Register {
                profile: self.profile.clone(),
            },
            Some(self.root.clone()),
        );
        self.apply(
            5,
            Command::Offer {
                offer: self.offer(175),
            },
            Some(self.root.clone()),
        );
    }
    fn accept(&mut self) {
        self.apply(
            150,
            Command::Accept {
                id: [175; 32],
                service: self.profile.service,
                destination: "Downloads".into(),
                expires: 14000,
            },
            Some(self.reader.clone()),
        );
    }
}
#[test]
fn offer_accept_selected_recipient_effect_and_cancel_preserve_exact_generations() {
    let mut f = Fixture::new();
    f.setup();
    let (i, o) = f.request(
        5,
        Command::Execute {
            id: [175; 32],
            effect: Effect::Put,
            offset: 0,
            bytes: 1024,
            digest: Some([176; 32]),
        },
        None,
        false,
    );
    assert!(
        o.expected_recipient(&f.state, &f.records, &f.reserved, &i)
            .is_err()
    );
    f.accept();
    let (i, o, d) = f.apply(
        5,
        Command::Execute {
            id: [175; 32],
            effect: Effect::Put,
            offset: 0,
            bytes: 1024,
            digest: Some([176; 32]),
        },
        None,
    );
    assert_eq!(
        o.expected_recipient(&f.state, &f.records, &f.reserved, &i)
            .unwrap(),
        f.profile.service
    );
    assert!(d.state.is_none());
    let signed = deployment::signed(
        &deployment::key(5),
        "AuthorityDomain",
        o.command.resource(),
        0,
        wire::decode(&o.parameters().unwrap()).unwrap(),
        o.snapshot.references.clone(),
    );
    let request = Request::parse(&signed).unwrap();
    let records = d.value.array(5).unwrap()[4].array(4).unwrap()[2]
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
    for (value, allowed) in [
        (&d.value, true),
        (&deployment::without_live_consent(&d.value), false),
    ] {
        let proof = deployment::serving_result(&f.bootstrap, &signed, value, 103);
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
            "serving transfer must use accepted bootstrap and exact live consent: {:?}",
            verified.as_ref().err()
        );
    }
    let (short, short_operation) = f.request(
        5,
        Command::Execute {
            id: [175; 32],
            effect: Effect::Put,
            offset: 0,
            bytes: 64,
            digest: Some([176; 32]),
        },
        None,
        false,
    );
    assert_eq!(
        short_operation
            .prepare(
                &f.state,
                &f.records,
                &f.reserved,
                &short,
                5000,
                false,
                false
            )
            .unwrap()
            .code,
        3
    );
    let bad = Intent {
        requester: public(150),
        ..i.clone()
    };
    assert_eq!(
        o.prepare(&f.state, &f.records, &f.reserved, &bad, 5000, false, true)
            .unwrap()
            .code,
        3
    );
    let (i, o, d) = f.apply(150, Command::Cancel { id: [175; 32] }, None);
    assert!(
        d.versions
            .iter()
            .any(|v| v.kind == 135 && v.generation == 3)
    );
    assert_eq!(
        o.prepare(&f.state, &f.records, &f.reserved, &i, 5000, true, true)
            .unwrap()
            .value,
        d.value
    );
    let state = State::parse(&f.state.value(), f.state.network, f.state.incarnation).unwrap();
    assert_eq!(
        wire::encode_state(&state.value()).unwrap(),
        wire::encode_state(&f.state.value()).unwrap()
    );
}
#[test]
fn offer_signatures_key_binding_expiry_and_withdrawal_fail_closed() {
    let mut f = Fixture::new();
    f.setup();
    let (mut i, o) = f.request(
        150,
        Command::Accept {
            id: [175; 32],
            service: f.profile.service,
            destination: "Downloads".into(),
            expires: 14000,
        },
        Some(f.reader.clone()),
        true,
    );
    let mut changed = f.offer(176);
    changed.recipient = public(151);
    assert!(
        Offer::parse(
            &wire::sign_envelope(
                &changed.payload().unwrap(),
                &SigningKey::from_bytes(&[150; 32])
            )
            .unwrap(),
            f.state.network,
            f.state.incarnation
        )
        .is_err()
    );
    f.apply(
        90,
        Command::Withdraw {
            service: f.profile.service,
            generation: 1,
        },
        None,
    );
    assert_ne!(
        o.prepare(&f.state, &f.records, &f.reserved, &i, 5000, false, true)
            .unwrap()
            .code,
        0
    );
    i.expected.clear();
    assert_ne!(
        o.prepare(&f.state, &f.records, &f.reserved, &i, 25000, false, false)
            .unwrap()
            .code,
        0
    );
}
#[test]
fn sender_revocation_invalidates_already_accepted_transfer_and_quota_is_explicit() {
    let mut f = Fixture::new();
    f.setup();
    f.accept();
    let (i, o) = f.request(
        150,
        Command::Execute {
            id: [175; 32],
            effect: Effect::Fetch,
            offset: 0,
            bytes: 64,
            digest: None,
        },
        None,
        true,
    );
    f.records.push(
        wire::encode(&a(vec![
            V::Uint(126),
            V::Uint(1),
            b(&f.state.network),
            b(&f.state.incarnation),
            V::Uint(1),
            V::Null,
            reference(&f.root),
            b(&public(5)),
            deployment::snapshot(&[]),
        ]))
        .unwrap(),
    );
    crate::authority_membership::sort_records(&mut f.records).unwrap();
    assert_eq!(
        o.prepare(&f.state, &f.records, &f.reserved, &i, 5000, false, true)
            .unwrap()
            .code,
        3
    );
    let mut p = f.profile.clone();
    p.state_bytes =
        2 * (BANK_HEADER + disk_header_bytes() + reservation_bytes(MAXIMUM_PAYLOAD).unwrap());
    p.envelope = wire::sign_envelope(&p.payload().unwrap(), &deployment::key(90)).unwrap();
    assert!(Profile::parse(&p.envelope, f.state.network, f.state.incarnation).is_ok());
    p.state_bytes -= 2;
    p.envelope = wire::sign_envelope(&p.payload().unwrap(), &deployment::key(90)).unwrap();
    assert!(Profile::parse(&p.envelope, f.state.network, f.state.incarnation).is_err());
}
