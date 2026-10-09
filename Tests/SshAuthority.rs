// SPDX-License-Identifier: MIT
use super::*;
use crate::types::{Member, Request};
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().as_bytes())
}
fn native(k: &SigningKey) -> String {
    let mut bytes = vec![0, 0, 0, 11];
    bytes.extend(b"ssh-ed25519");
    bytes.extend([0, 0, 0, 32]);
    bytes.extend(k.verifying_key().as_bytes());
    format!("ssh-ed25519 {}", STANDARD.encode(bytes))
}
fn request(key: &str, id: u8, command: Command) -> VerifiedRequest {
    VerifiedRequest {
        key: key.into(),
        digest: format!("Digest{id}"),
        request: Request {
            version: 1,
            request_id: hex::encode([id; 16]),
            issued_at: 100,
            command,
        },
        envelope: Envelope {
            network: "09".repeat(32),
            public_key: key.into(),
            payload: String::new(),
            signature: String::new(),
        },
    }
}
struct Fixture {
    state: State,
    signer: SigningKey,
    member: String,
    host: String,
    body: SshConsent,
}
impl Fixture {
    fn new() -> Self {
        let signer = key(9);
        let member = public(&key(1));
        let host = public(&key(2));
        let mut state = State::initial("09".repeat(32), member.clone(), 100);
        state.members.insert(
            host.clone(),
            Member {
                grants: 3,
                expires: 1000,
                revoked: false,
            },
        );
        let body = SshConsent {
            version: 1,
            network: state.network.clone(),
            service_key: host.clone(),
            generation: 1,
            endpoint: "ssh://ssh.test:2222/".into(),
            address: "127.0.0.1:2222".parse().unwrap(),
            ssh_host_key: native(&key(3)),
            account: "HyperNetService".into(),
            purpose: "Diagnostics".into(),
            command_digest: "05".repeat(32),
            image_digest: "06".repeat(32),
            authority_endpoint: "https://authority.test:8443/".into(),
            authority_address: "127.0.0.1:8443".parse().unwrap(),
            authority_signer: public(&signer),
            certificate_digest: "02".repeat(32),
            memory_bytes: 536870912,
            pids: 64,
            cpu_quota: 100000,
            cpu_period: 100000,
            state_bytes: 8388608,
            maximum_session_seconds: 300,
            expires: 900,
        };
        let object = sign(CONSENT, &state.network, &body, &key(2)).unwrap();
        apply(
            &mut state,
            &request(&host, 1, Command::SshServiceRegister { consent: object }),
            Some(&"02".repeat(32)),
            100,
            Some(&signer),
        )
        .unwrap();
        Self {
            state,
            signer,
            member,
            host,
            body,
        }
    }
    fn apply(&mut self, actor: &str, id: u8, command: Command) -> Result<Reply, Failure> {
        let mut state = self.state.clone();
        let result = apply(
            &mut state,
            &request(actor, id, command),
            Some(&"02".repeat(32)),
            100,
            Some(&self.signer),
        )?;
        self.state = state;
        Ok(result)
    }
    fn grant(&self, id: u8) -> Command {
        Command::SshGrantCreate {
            grant_id: hex::encode([id; 16]),
            service_key: self.host.clone(),
            service_generation: 1,
            ssh_public_key: native(&key(4)),
            ssh_key_proof: crate::ssh_proof::proof(&self.state.network, &self.member, &key(4)),
            account: "HyperNetService".into(),
            purpose: "Diagnostics".into(),
            expires: 300,
        }
    }
    fn lease(&self, id: u8, now: u64) -> Result<Reply, Failure> {
        authorise(
            &self.state,
            &request(
                &self.host,
                10,
                Command::SshAuthorise {
                    service_key: self.host.clone(),
                    grant_id: hex::encode([id; 16]),
                },
            ),
            Some(&"02".repeat(32)),
            now,
            88,
            Some(&self.signer),
        )
    }
}
#[test]
fn explicit_operator_acceptance_and_current_grants_control_sessions() {
    let mut f = Fixture::new();
    f.apply(&f.member.clone(), 2, f.grant(2)).unwrap();
    assert!(f.lease(2, 100).is_err());
    assert!(
        f.apply(
            &f.member.clone(),
            3,
            Command::SshGrantAccept {
                grant_id: hex::encode([2; 16])
            }
        )
        .is_err()
    );
    f.apply(
        &f.host.clone(),
        4,
        Command::SshGrantAccept {
            grant_id: hex::encode([2; 16]),
        },
    )
    .unwrap();
    let before = serde_json::to_vec(&f.state).unwrap();
    let reply = f.lease(2, 100).unwrap();
    let lease: Lease = verify(
        LEASE,
        &serde_json::from_value(reply.result["lease"].clone()).unwrap(),
        &f.state.network,
    )
    .unwrap();
    assert_eq!(lease.expires, 105);
    assert_eq!(lease.authority_revision, 88);
    assert_eq!(before, serde_json::to_vec(&f.state).unwrap());
    f.apply(&f.member.clone(), 5, f.grant(5)).unwrap();
    assert_eq!(
        f.apply(
            &f.host.clone(),
            6,
            Command::SshGrantAccept {
                grant_id: hex::encode([5; 16])
            }
        )
        .err(),
        Some("SshServiceBusy")
    );
    f.apply(
        &f.member.clone(),
        7,
        Command::SshGrantRevoke {
            grant_id: hex::encode([2; 16]),
        },
    )
    .unwrap();
    assert!(f.lease(2, 100).is_err());
    assert!(
        f.apply(
            &f.host.clone(),
            8,
            Command::SshGrantAccept {
                grant_id: hex::encode([2; 16])
            }
        )
        .is_err()
    );
    assert!(f.lease(5, 301).is_err());
}
#[test]
fn pending_invites_cannot_turn_native_ssh_keys_into_general_members() {
    let mut f = Fixture::new();
    let target = public(&key(4));
    let secret = [17; 32];
    authority::apply(
        &mut f.state,
        &request(
            &f.member,
            2,
            Command::Invite {
                verifier: mail_authority::hash(&secret),
                device_key: target.clone(),
                grants: 1,
                expires: 500,
            },
        ),
        None,
        100,
        1,
    )
    .unwrap();
    f.apply(&f.member.clone(), 3, f.grant(3)).unwrap();
    f.apply(
        &f.host.clone(),
        6,
        Command::SshGrantAccept {
            grant_id: hex::encode([3; 16]),
        },
    )
    .unwrap();
    assert!(
        authority::apply(
            &mut f.state,
            &request(
                &target,
                4,
                Command::Redeem {
                    secret: hex::encode(secret)
                }
            ),
            None,
            100,
            2
        )
        .is_err()
    );
    assert!(!f.state.members.contains_key(&target));
    assert!(mail_authority::reserved_identity_conflict(
        &f.state, &target
    ));
    f.apply(
        &f.member.clone(),
        5,
        Command::SshGrantRevoke {
            grant_id: hex::encode([3; 16]),
        },
    )
    .unwrap();
    assert!(f.state.ssh.key_history.contains(&target));
}
#[test]
fn renewal_and_withdrawal_revoke_existing_session_grants() {
    let mut f = Fixture::new();
    f.apply(&f.member.clone(), 2, f.grant(2)).unwrap();
    f.apply(
        &f.host.clone(),
        3,
        Command::SshGrantAccept {
            grant_id: hex::encode([2; 16]),
        },
    )
    .unwrap();
    f.body.generation = 2;
    let object = sign(CONSENT, &f.state.network, &f.body, &key(2)).unwrap();
    f.apply(
        &f.host.clone(),
        4,
        Command::SshServiceRegister { consent: object },
    )
    .unwrap();
    assert!(f.state.ssh.grants[&hex::encode([2; 16])].revoked);
    assert!(f.lease(2, 100).is_err());
    f.apply(
        &f.host.clone(),
        5,
        Command::SshServiceWithdraw {
            service_key: f.host.clone(),
            expected_generation: 2,
        },
    )
    .unwrap();
    assert!(service(&f.state, &f.host, 100).is_err());
}
#[test]
fn ssh_key_parser_rejects_options_comments_and_other_key_types() {
    let value = native(&key(1));
    assert!(public_key(&value).is_ok());
    assert!(public_key(&format!("{value} Comment")).is_err());
    assert!(public_key(&format!("restrict {value}")).is_err());
    assert!(public_key(&value.replace("ssh-ed25519", "ssh-rsa")).is_err());
}

#[test]
fn consent_resources_match_the_supported_runtime_profile() {
    let mut f = Fixture::new();
    f.body.state_bytes = 1024 * 1024;
    let object = sign(CONSENT, &f.state.network, &f.body, &key(2)).unwrap();
    assert!(consent(&object, &f.state.network).is_err());
    f.body.state_bytes = 8388609;
    let object = sign(CONSENT, &f.state.network, &f.body, &key(2)).unwrap();
    assert!(consent(&object, &f.state.network).is_err());
    f.body.state_bytes = 8388608;
    f.body.maximum_session_seconds = 1;
    let object = sign(CONSENT, &f.state.network, &f.body, &key(2)).unwrap();
    assert!(consent(&object, &f.state.network).is_ok());
}

#[test]
fn pending_expired_grants_release_capacity_without_reserving_native_keys() {
    let mut f = Fixture::new();
    let history = f.state.ssh.key_history.clone();
    for id in 2..34 {
        let mut command = f.grant(id);
        if let Command::SshGrantCreate {
            ssh_public_key,
            ssh_key_proof,
            ..
        } = &mut command
        {
            *ssh_public_key = native(&key(id + 40));
            *ssh_key_proof = crate::ssh_proof::proof(&f.state.network, &f.member, &key(id + 40));
        }
        f.apply(&f.member.clone(), id, command).unwrap();
    }
    assert_eq!(f.state.ssh.key_history, history);
    assert!(f.state.ssh.key_owners.is_empty());
    assert_eq!(
        f.apply(&f.member.clone(), 34, f.grant(34)).err(),
        Some("CapacityExceeded")
    );
    let Command::SshGrantCreate {
        grant_id,
        service_key,
        service_generation,
        ssh_public_key,
        ssh_key_proof,
        account,
        purpose,
        ..
    } = f.grant(35)
    else {
        unreachable!()
    };
    let fresh = Command::SshGrantCreate {
        grant_id,
        service_key,
        service_generation,
        ssh_public_key: ssh_public_key.clone(),
        ssh_key_proof,
        account,
        purpose,
        expires: 500,
    };
    let mut operation = request(&f.member, 35, fresh.clone());
    operation.request.issued_at = 301;
    apply(&mut f.state, &operation, None, 301, Some(&f.signer)).unwrap();
    assert_eq!(f.state.ssh.grants.len(), 1);
    assert_eq!(f.state.ssh.key_history, history);
    assert!(f.state.ssh.key_owners.is_empty());
    let mut replay = request(&f.member, 36, f.grant(2));
    replay.request.issued_at = 301;
    assert_eq!(
        apply(&mut f.state, &replay, None, 301, Some(&f.signer)).err(),
        Some("SshPermissionDenied")
    );
    assert_eq!(
        apply(&mut f.state, &replay, None, 300, Some(&f.signer)).err(),
        Some("ClockRollback")
    );
    let other = public(&key(7));
    f.state.members.insert(
        other.clone(),
        Member {
            grants: 1,
            expires: 1000,
            revoked: false,
        },
    );
    let mut stolen_command = fresh;
    if let Command::SshGrantCreate { grant_id, .. } = &mut stolen_command {
        *grant_id = "37".repeat(16);
    }
    let mut stolen = request(&other, 37, stolen_command);
    stolen.request.issued_at = 301;
    assert!(apply(&mut f.state, &stolen, None, 301, Some(&f.signer)).is_err());
}

#[test]
fn accepted_key_ownership_survives_expiry_and_conflicts_are_rechecked_at_acceptance() {
    let mut f = Fixture::new();
    let other = public(&key(7));
    f.state.members.insert(
        other.clone(),
        Member {
            grants: 1,
            expires: 1000,
            revoked: false,
        },
    );
    f.apply(&f.member.clone(), 2, f.grant(2)).unwrap();
    let mut second = f.grant(3);
    if let Command::SshGrantCreate { ssh_key_proof, .. } = &mut second {
        *ssh_key_proof = crate::ssh_proof::proof(&f.state.network, &other, &key(4));
    }
    f.apply(&other, 3, second.clone()).unwrap();
    assert!(f.state.ssh.key_owners.is_empty());
    f.apply(
        &f.host.clone(),
        4,
        Command::SshGrantAccept {
            grant_id: hex::encode([2; 16]),
        },
    )
    .unwrap();
    f.apply(
        &f.member.clone(),
        5,
        Command::SshGrantRevoke {
            grant_id: hex::encode([2; 16]),
        },
    )
    .unwrap();
    assert_eq!(
        f.apply(
            &f.host.clone(),
            6,
            Command::SshGrantAccept {
                grant_id: hex::encode([3; 16])
            }
        )
        .err(),
        Some("SshPermissionDenied")
    );
    assert_eq!(
        f.apply(&other, 3, second).err(),
        Some("SshPermissionDenied")
    );
    let mut fresh = f.grant(7);
    if let Command::SshGrantCreate { expires, .. } = &mut fresh {
        *expires = 500;
    }
    let mut operation = request(&f.member, 7, fresh.clone());
    operation.request.issued_at = 301;
    apply(&mut f.state, &operation, None, 301, Some(&f.signer)).unwrap();
    assert_eq!(f.state.ssh.grants.len(), 1);
    assert_eq!(f.state.ssh.key_owners[&public(&key(4))], f.member);
    assert!(f.state.ssh.key_history.contains(&public(&key(4))));
    let mut accept = request(
        &f.host,
        8,
        Command::SshGrantAccept {
            grant_id: hex::encode([7; 16]),
        },
    );
    accept.request.issued_at = 301;
    apply(
        &mut f.state,
        &accept,
        Some(&"02".repeat(32)),
        301,
        Some(&f.signer),
    )
    .unwrap();
    if let Command::SshGrantCreate {
        grant_id,
        ssh_key_proof,
        ..
    } = &mut fresh
    {
        *grant_id = hex::encode([9; 16]);
        *ssh_key_proof = crate::ssh_proof::proof(&f.state.network, &other, &key(4));
    }
    let mut stolen = request(&other, 9, fresh);
    stolen.request.issued_at = 301;
    assert_eq!(
        apply(&mut f.state, &stolen, None, 301, Some(&f.signer)).err(),
        Some("SshPermissionDenied")
    );
}

#[test]
fn acceptance_rechecks_native_identity_and_invalid_proof_has_no_side_effects() {
    let mut f = Fixture::new();
    f.apply(&f.member.clone(), 2, f.grant(2)).unwrap();
    let before = serde_json::to_vec(&f.state).unwrap();
    let mut invalid = f.grant(3);
    if let Command::SshGrantCreate {
        ssh_key_proof,
        expires,
        ..
    } = &mut invalid
    {
        *ssh_key_proof = crate::ssh_proof::proof(&f.state.network, &public(&key(7)), &key(4));
        *expires = 500;
    }
    assert_eq!(
        apply(
            &mut f.state,
            &request(&f.member, 3, invalid),
            None,
            301,
            Some(&f.signer)
        )
        .err(),
        Some("SshInvalidKeyProof")
    );
    assert_eq!(before, serde_json::to_vec(&f.state).unwrap());
    // A pending invitation may be redeemed before service-operator consent.
    let secret = [17; 32];
    authority::apply(
        &mut f.state,
        &request(
            &f.member,
            4,
            Command::Invite {
                verifier: mail_authority::hash(&secret),
                device_key: public(&key(4)),
                grants: 1,
                expires: 500,
            },
        ),
        None,
        100,
        1,
    )
    .unwrap();
    authority::apply(
        &mut f.state,
        &request(
            &public(&key(4)),
            5,
            Command::Redeem {
                secret: hex::encode(secret),
            },
        ),
        None,
        100,
        2,
    )
    .unwrap();
    assert_eq!(
        f.apply(
            &f.host.clone(),
            6,
            Command::SshGrantAccept {
                grant_id: hex::encode([2; 16])
            }
        )
        .err(),
        Some("SshPermissionDenied")
    );
    assert!(f.state.ssh.key_owners.is_empty());
}
