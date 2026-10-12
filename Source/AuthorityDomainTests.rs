// SPDX-License-Identifier: MIT
// SSH lifecycle checks use real key possession, scoped capabilities and retained restrictions.
use super::*;
use crate::{authority_deployment_tests as deployment, authority_governance::Governance};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest as _, Sha512};

fn public(seed: u8) -> Key {
    deployment::key(seed).verifying_key().to_bytes()
}
fn native_proof(network: Digest, member: Key, signer: &SigningKey) -> String {
    fn field(bytes: &mut Vec<u8>, value: &[u8]) {
        bytes.extend((value.len() as u32).to_be_bytes());
        bytes.extend(value);
    }
    let mut hash = Sha512::new();
    hash.update(b"HyperNet/SshKeyProof/1\0");
    hash.update(network);
    hash.update(member);
    hash.update(signer.verifying_key().to_bytes());
    let mut signed = b"SSHSIG".to_vec();
    for value in [
        b"HyperNetSshKey1".as_slice(),
        b"",
        b"sha512",
        &hash.finalize(),
    ] {
        field(&mut signed, value);
    }
    let mut public = vec![];
    field(&mut public, b"ssh-ed25519");
    field(&mut public, signer.verifying_key().as_bytes());
    let mut signature = vec![];
    field(&mut signature, b"ssh-ed25519");
    field(&mut signature, &signer.sign(&signed).to_bytes());
    let mut proof = b"SSHSIG".to_vec();
    proof.extend(1u32.to_be_bytes());
    for value in [
        public.as_slice(),
        b"HyperNetSshKey1",
        b"",
        b"sha512",
        signature.as_slice(),
    ] {
        field(&mut proof, value);
    }
    URL_SAFE_NO_PAD.encode(proof)
}
struct Fixture {
    records: Vec<Vec<u8>>,
    reserved: Reservations,
    state: State,
    root: VersionRef,
    profile: ssh::Profile,
}
impl Fixture {
    fn new() -> Self {
        let fixture = deployment::Fixture::with_actions(vec![0, 10, 11, 12, 13, 20, 26]);
        let manifest = deployment::manifest();
        let offer = deployment::offer(manifest.clone());
        let (records, registration, _, _) = deployment::admitted(&fixture, &offer);
        let root = Governance::parse(manifest.network, manifest.incarnation, &records)
            .unwrap()
            .versions()
            .into_iter()
            .find(|r| r.kind == 102 && r.id == [23; 32])
            .unwrap();
        let mut profile = ssh::Profile {
            network: manifest.network,
            incarnation: manifest.incarnation,
            deployment: manifest.deployment,
            service: public(107),
            operator: public(90),
            native: public(170),
            command_digest: [171; 32],
            endpoint: [88; 32],
            purpose: "InspectFiles".into(),
            maximum_seconds: 30,
            validity: manifest.validity,
            deployment_profile: registration.profile,
            consent: registration.consent,
            envelope: vec![],
        };
        profile.envelope =
            wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
        Self {
            records,
            reserved: fixture.reservations,
            state: State::empty(manifest.network, manifest.incarnation),
            root,
            profile,
        }
    }
    fn request(
        &self,
        signer: u8,
        command: ssh::Command,
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
            generation_id: [181; 32],
            sequence: 1,
            acknowledged_through: 0,
            requester: public(signer),
            action: "AuthorityDomain".into(),
            resource: operation.command.resource(),
            revision: u64::from(operation.mutation()),
            profile_generation: 0,
            minimum_policy_epoch: 0,
            minimum_policy_height: 0,
            expected: vec![],
            parameters: operation.parameters().unwrap(),
            digest: [182; 32],
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
        signer: u8,
        command: ssh::Command,
        grant: Option<VersionRef>,
    ) -> (Intent, Operation, Decision) {
        let (intent, operation) = self.request(signer, command, grant, true);
        let d = evaluate(
            &self.state,
            &self.records,
            &self.reserved,
            &intent,
            5000,
            false,
        )
        .unwrap();
        assert_eq!(d.code, 0);
        if let Some(state) = &d.state {
            self.state = state.clone();
        }
        State::parse(
            &self.state.value(),
            self.state.network,
            self.state.incarnation,
        )
        .unwrap();
        (intent, operation, d)
    }
    fn register(&mut self) {
        self.apply(
            5,
            ssh::Command::Register {
                profile: self.profile.clone(),
            },
            Some(self.root.clone()),
        );
    }
    fn create(&mut self) {
        self.apply(
            5,
            ssh::Command::Create {
                id: [180; 32],
                service: self.profile.service,
                native: public(172),
                proof: native_proof(self.state.network, public(5), &deployment::key(172)),
                purpose: self.profile.purpose.clone(),
                expires: 15000,
            },
            Some(self.root.clone()),
        );
    }
}
#[test]
fn ssh_requires_member_capability_and_separate_operator_acceptance() {
    let mut f = Fixture::new();
    f.register();
    f.create();
    let command = ssh::Command::Authorise {
        service: f.profile.service,
        id: [180; 32],
    };
    let (intent, _) = f.request(107, command.clone(), None, false);
    assert_ne!(
        evaluate(&f.state, &f.records, &f.reserved, &intent, 5000, false)
            .unwrap()
            .code,
        0
    );
    let (forged, _) = f.request(5, ssh::Command::Accept { id: [180; 32] }, None, false);
    assert_ne!(
        evaluate(&f.state, &f.records, &f.reserved, &forged, 5000, false)
            .unwrap()
            .code,
        0
    );
    f.apply(90, ssh::Command::Accept { id: [180; 32] }, None);
    f.apply(107, command, None);
    let (wrong, _) = f.request(
        90,
        ssh::Command::Authorise {
            service: f.profile.service,
            id: [180; 32],
        },
        None,
        false,
    );
    assert_ne!(
        evaluate(&f.state, &f.records, &f.reserved, &wrong, 5000, false)
            .unwrap()
            .code,
        0
    );
    let (original, _, result) = f.apply(5, ssh::Command::Revoke { id: [180; 32] }, None);
    assert_eq!(
        evaluate(&f.state, &f.records, &f.reserved, &original, 5000, true)
            .unwrap()
            .value,
        result.value
    );
    let (intent, _) = f.request(
        107,
        ssh::Command::Authorise {
            service: f.profile.service,
            id: [180; 32],
        },
        None,
        false,
    );
    assert_ne!(
        evaluate(&f.state, &f.records, &f.reserved, &intent, 5000, false)
            .unwrap()
            .code,
        0
    );
}
#[test]
fn ssh_native_keys_and_local_withdrawal_survive_expiry_and_restart() {
    let mut f = Fixture::new();
    f.register();
    f.create();
    f.apply(107, ssh::Command::Accept { id: [180; 32] }, None);
    let reserved = f.state.keys.clone();
    let (withdraw, _) = f.request(
        90,
        ssh::Command::Withdraw {
            service: f.profile.service,
            generation: 1,
        },
        None,
        true,
    );
    let d = evaluate(&f.state, &f.records, &f.reserved, &withdraw, 50000, false).unwrap();
    assert_eq!(d.code, 0);
    f.state = d.state.unwrap();
    assert_eq!(f.state.keys, reserved);
    let reopened = State::parse(&f.state.value(), f.state.network, f.state.incarnation).unwrap();
    assert_eq!(reopened.keys, reserved);
    let (intent, _) = f.request(
        107,
        ssh::Command::Authorise {
            service: f.profile.service,
            id: [180; 32],
        },
        None,
        false,
    );
    assert_ne!(
        evaluate(&reopened, &f.records, &f.reserved, &intent, 5000, false)
            .unwrap()
            .code,
        0
    );
    let mut damaged = reopened.value();
    if let V::Array(f) = &mut damaged {
        f[6] = a(vec![]);
    }
    assert!(State::parse(&damaged, f.state.network, f.state.incarnation).is_err());
    assert!(State::parse(&reopened.value(), f.state.network, [250; 32]).is_err());
}
#[test]
fn ssh_refuses_changed_consent_proof_and_stale_exact_versions() {
    let mut f = Fixture::new();
    f.register();
    let command = ssh::Command::Create {
        id: [180; 32],
        service: f.profile.service,
        native: public(172),
        proof: native_proof(f.state.network, public(5), &deployment::key(172)),
        purpose: f.profile.purpose.clone(),
        expires: 15000,
    };
    let (mut intent, _) = f.request(5, command, Some(f.root.clone()), true);
    intent.expected.pop();
    let operation = Operation::parse(&intent).unwrap_err();
    assert!(!operation.to_string().is_empty());
    let mut value = wire::decode(&intent.parameters).unwrap();
    if let V::Array(fields) = &mut value {
        fields[5] = deployment::snapshot(&intent.expected);
    }
    intent.parameters = wire::encode(&value).unwrap();
    assert_eq!(
        evaluate(&f.state, &f.records, &f.reserved, &intent, 5000, false)
            .unwrap()
            .code,
        12
    );
    let mut profile = f.profile.clone();
    profile.envelope[20] ^= 1;
    assert!(ssh::Profile::parse(&profile.envelope, f.state.network, f.state.incarnation).is_err());
}
