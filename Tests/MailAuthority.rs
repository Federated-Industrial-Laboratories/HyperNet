// SPDX-License-Identifier: MIT
use super::*;
use crate::types::{Envelope, MEMBER, Member, Request};
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}
fn request(actor: &str, id: u8, command: Command) -> VerifiedRequest {
    VerifiedRequest {
        key: actor.into(),
        digest: format!("Digest{id}"),
        request: Request {
            version: 1,
            request_id: hex::encode([id; 16]),
            issued_at: 100,
            command,
        },
        envelope: Envelope {
            network: "09".repeat(32),
            public_key: actor.into(),
            payload: String::new(),
            signature: String::new(),
        },
    }
}
struct Fixture {
    state: State,
    signer: SigningKey,
    owner: SigningKey,
    device: SigningKey,
    host: String,
    address: AddressManifest,
}
impl Fixture {
    fn new() -> Self {
        Self::with_pending_invitations(false)
    }
    fn with_pending_invitations(pending: bool) -> Self {
        let signer = key(9);
        let member = public(&key(1));
        let owner = key(2);
        let device = key(3);
        let host = public(&key(6));
        let mut state = State::initial("09".repeat(32), member.clone(), 100);
        state.members.insert(
            host.clone(),
            Member {
                grants: MEMBER | types::HOST,
                expires: 1000,
                revoked: false,
            },
        );
        let consent = MailHostConsent {
            version: 1,
            network: state.network.clone(),
            host_key: host.clone(),
            generation: 1,
            services: vec!["Mail".into()],
            endpoint: "https://mail.test:8443/".into(),
            address: "127.0.0.1:8443".parse().unwrap(),
            ca_digest: "01".repeat(32),
            certificate_digest: "02".repeat(32),
            authority_endpoint: "https://authority.test:8443/".into(),
            authority_address: "127.0.0.1:8443".parse().unwrap(),
            authority_signer: public(&signer),
            memory_bytes: 536870912,
            pids: 64,
            cpu_quota: 100000,
            cpu_period: 100000,
            state_bytes: 8388608,
            expires: 900,
        };
        let object = sign(HOST, &state.network, &consent, &key(6)).unwrap();
        apply(
            &mut state,
            &request(&host, 1, Command::MailHostRegister { consent: object }),
            Some(&"02".repeat(32)),
            100,
            1,
            Some(&signer),
        )
        .unwrap();
        let address_id = address_id(&state.network, &public(&owner)).unwrap();
        let address = AddressManifest {
            version: 1,
            network: state.network.clone(),
            address_id: address_id.clone(),
            owner_key: public(&owner),
            generation: 1,
            previous_digest: None,
            expires: 800,
            devices: vec![DeviceBinding {
                device_id: device_id(&address_id, &public(&device)).unwrap(),
                request_key: public(&device),
                mls_signature_key: public(&key(4)),
                permissions: vec!["Read".into(), "Send".into(), "Delete".into()],
                expires: 800,
            }],
            storage_hosts: vec![host.clone()],
            required_copies: 1,
            retention_seconds: 600,
            deleted: false,
        };
        if pending {
            for (index, target) in [public(&owner), public(&device), public(&key(4))]
                .into_iter()
                .enumerate()
            {
                let secret = [10 + index as u8; 32];
                authority::apply(
                    &mut state,
                    &request(
                        &member,
                        10 + index as u8,
                        Command::Invite {
                            verifier: hash(&secret),
                            device_key: target,
                            grants: MEMBER | types::ADMIN,
                            expires: 800,
                        },
                    ),
                    None,
                    100,
                    3,
                )
                .unwrap();
            }
        }
        let manifest = sign(MANIFEST, &state.network, &address, &owner).unwrap();
        apply(
            &mut state,
            &request(&member, 2, Command::MailAddressCreate { manifest }),
            None,
            100,
            2,
            Some(&signer),
        )
        .unwrap();
        Self {
            state,
            signer,
            owner,
            device,
            host,
            address,
        }
    }
    fn apply(&mut self, actor: &str, id: u8, command: Command) -> Result<Reply, Failure> {
        // Mirror the store's candidate transaction: failed validation never commits partial changes.
        let mut candidate = self.state.clone();
        let reply = apply(
            &mut candidate,
            &request(actor, id, command),
            None,
            100,
            10,
            Some(&self.signer),
        )?;
        self.state = candidate;
        Ok(reply)
    }
    fn package(&self) -> MailKeyPackage {
        MailKeyPackage {
            device_id: self.address.devices[0].device_id.clone(),
            reference: URL_SAFE_NO_PAD.encode([7; 32]),
            expires: 700,
            package: URL_SAFE_NO_PAD.encode(b"OpaqueTlsEncodedKeyPackage"),
        }
    }
    fn publish(&self, package: MailKeyPackage) -> Command {
        Command::MailKeyPackagesPublish {
            address_id: self.address.address_id.clone(),
            device_id: self.address.devices[0].device_id.clone(),
            manifest_generation: 1,
            packages: vec![package],
        }
    }
}
#[test]
fn complete_claim_and_response_loss_cannot_republish_consumed_packages() {
    let mut f = Fixture::new();
    let actor = public(&f.device);
    let package = f.package();
    assert_eq!(
        f.apply(&actor, 3, f.publish(package.clone()))
            .unwrap()
            .result["published"],
        1
    );
    assert_eq!(
        f.apply(&actor, 4, f.publish(package.clone()))
            .unwrap()
            .result["published"],
        0
    );
    let claim = Command::MailKeyPackagesClaim {
        sender_address: f.address.address_id.clone(),
        sender_device: f.address.devices[0].device_id.clone(),
        recipient_address: f.address.address_id.clone(),
        recipient_manifest_digest: f.state.mail.addresses[&f.address.address_id].digest.clone(),
        claim_id: "05".repeat(16),
        expires: 600,
    };
    f.apply(&actor, 5, claim).unwrap();
    assert!(f.state.mail.packages.is_empty());
    let result = f.apply(&actor, 6, f.publish(package.clone())).unwrap();
    assert_eq!(result.result["consumedReferences"][0], package.reference);
    let mut alternate = package;
    alternate.reference = URL_SAFE_NO_PAD.encode([8; 32]);
    assert_eq!(
        f.apply(&actor, 7, f.publish(alternate)).err(),
        Some("MailKeyPackageConsumed")
    );
    assert!(f.state.mail.packages.is_empty());
}
#[test]
fn claim_missing_one_read_device_consumes_nothing() {
    let mut f = Fixture::new();
    let actor = public(&f.device);
    let mut updated = f.address.clone();
    updated.generation = 2;
    updated.previous_digest = Some(f.state.mail.addresses[&updated.address_id].digest.clone());
    updated.devices.push(DeviceBinding {
        device_id: device_id(&updated.address_id, &public(&key(7))).unwrap(),
        request_key: public(&key(7)),
        mls_signature_key: public(&key(8)),
        permissions: vec!["Read".into()],
        expires: 800,
    });
    let manifest = sign(MANIFEST, &f.state.network, &updated, &f.owner).unwrap();
    f.apply(
        &public(&f.owner),
        3,
        Command::MailAddressUpdate {
            address_id: updated.address_id.clone(),
            expected_generation: 1,
            manifest,
        },
    )
    .unwrap();
    let mut command = f.publish(f.package());
    if let Command::MailKeyPackagesPublish {
        manifest_generation,
        ..
    } = &mut command
    {
        *manifest_generation = 2;
    }
    f.apply(&actor, 4, command).unwrap();
    let before = serde_json::to_vec(&f.state.mail).unwrap();
    let claim = Command::MailKeyPackagesClaim {
        sender_address: updated.address_id.clone(),
        sender_device: updated.devices[0].device_id.clone(),
        recipient_address: updated.address_id.clone(),
        recipient_manifest_digest: f.state.mail.addresses[&updated.address_id].digest.clone(),
        claim_id: "05".repeat(16),
        expires: 600,
    };
    assert_eq!(
        f.apply(&actor, 5, claim).err(),
        Some("MailKeyPackagesUnavailable")
    );
    assert_eq!(serde_json::to_vec(&f.state.mail).unwrap(), before);
}
#[test]
fn fresh_permission_is_read_only_scoped_and_parent_revocation_wins() {
    let mut f = Fixture::new();
    let id = f.address.address_id.clone();
    let operation = MailOperation {
        version: 1,
        network: f.state.network.clone(),
        operation_id: "03".repeat(16),
        issued_at: 100,
        host_key: f.host.clone(),
        action: "List".into(),
        address_id: id.clone(),
        device_id: f.address.devices[0].device_id.clone(),
        message_id: None,
        manifest_generation: 1,
        manifest_digest: f.state.mail.addresses[&id].digest.clone(),
        payload_digest: None,
        payload_bytes: 0,
        after: None,
        route: None,
    };
    let object = sign(OPERATION, &f.state.network, &operation, &f.device).unwrap();
    let request = request(
        &f.host,
        3,
        Command::MailAuthorise {
            host_key: f.host.clone(),
            operation: object,
        },
    );
    let before = serde_json::to_vec(&f.state).unwrap();
    let result = authorise(
        &f.state,
        &request,
        Some(&"02".repeat(32)),
        100,
        12,
        Some(&f.signer),
    )
    .unwrap();
    let proof: SignedMailObject =
        serde_json::from_value(result.result["permission"].clone()).unwrap();
    let permission: MailPermission = verify(PERMISSION, &proof, &f.state.network).unwrap();
    assert_eq!(permission.expires, 105);
    assert_eq!(serde_json::to_vec(&f.state).unwrap(), before);
    assert_eq!(
        apply(
            &mut f.state,
            &request,
            Some(&"02".repeat(32)),
            100,
            12,
            Some(&f.signer)
        )
        .err(),
        Some("MailReadOnlyPathRequired")
    );
    assert!(page_authority::client(&f.state, &public(&f.device), 100).is_err());
    assert!(page_authority::client(&f.state, &f.host, 100).is_err());
    let parent = f.state.mail.addresses[&id].member.clone();
    f.state.members.get_mut(&parent).unwrap().revoked = true;
    assert!(
        authorise(
            &f.state,
            &request,
            Some(&"02".repeat(32)),
            100,
            13,
            Some(&f.signer)
        )
        .is_err()
    );
}
#[test]
fn expired_owner_can_recover_manifest_but_removed_keys_cannot_return() {
    let mut f = Fixture::new();
    let owner = public(&f.owner);
    let id = f.address.address_id.clone();
    assert!(
        apply(
            &mut f.state,
            &request(
                &owner,
                3,
                Command::MailAddressGet {
                    address_id: id.clone()
                }
            ),
            None,
            801,
            5,
            Some(&f.signer)
        )
        .is_ok()
    );
    let mut next = f.address.clone();
    next.generation = 2;
    next.previous_digest = Some(f.state.mail.addresses[&id].digest.clone());
    next.devices[0].request_key = public(&key(7));
    next.devices[0].mls_signature_key = public(&key(8));
    next.devices[0].device_id = device_id(&id, &next.devices[0].request_key).unwrap();
    // Use a fresh fixture so its persistent time floor has not advanced.
    let mut f = Fixture::new();
    let manifest = sign(MANIFEST, &f.state.network, &next, &f.owner).unwrap();
    f.apply(
        &owner,
        4,
        Command::MailAddressUpdate {
            address_id: id.clone(),
            expected_generation: 1,
            manifest,
        },
    )
    .unwrap();
    let mut old = f.address.clone();
    old.generation = 3;
    old.previous_digest = Some(f.state.mail.addresses[&id].digest.clone());
    let manifest = sign(MANIFEST, &f.state.network, &old, &f.owner).unwrap();
    assert_eq!(
        f.apply(
            &owner,
            5,
            Command::MailAddressUpdate {
                address_id: id,
                expected_generation: 2,
                manifest
            }
        )
        .err(),
        Some("SeparateMailIdentityRequired")
    );
}

#[test]
fn exhausted_host_generation_cannot_reuse_consent_version() {
    let mut f = Fixture::new();
    let old = f.state.mail.hosts.get_mut(&f.host).unwrap();
    old.body.generation = u64::MAX;
    let mut body = old.body.clone();
    body.generation = u64::MAX;
    let consent = sign(HOST, &f.state.network, &body, &key(6)).unwrap();
    assert_eq!(
        apply(
            &mut f.state,
            &request(&f.host, 6, Command::MailHostRegister { consent }),
            Some(&"02".repeat(32)),
            100,
            20,
            Some(&f.signer)
        )
        .err(),
        Some("MailQuotaExceeded")
    );
}

#[test]
fn existing_member_cannot_become_mail_authority_signer() {
    let f = Fixture::new();
    let request = request(
        &f.host,
        8,
        Command::MailPolicySync {
            host_key: f.host.clone(),
        },
    );
    assert_eq!(
        authorise(
            &f.state,
            &request,
            Some(&"02".repeat(32)),
            100,
            20,
            Some(&key(1))
        )
        .err(),
        Some("DedicatedAuthorityKeyRequired")
    );
    assert!(reserved_identity_conflict(&f.state, &public(&f.owner)));
    assert!(reserved_identity_conflict(&f.state, &public(&f.device)));
}

#[test]
fn pending_invitation_cannot_promote_current_or_deleted_mail_identities() {
    let mut f = Fixture::with_pending_invitations(true);
    for deleted in [false, true] {
        if deleted {
            let mut value = f.address.clone();
            value.generation = 2;
            value.previous_digest = Some(f.state.mail.addresses[&value.address_id].digest.clone());
            value.deleted = true;
            value.devices.clear();
            value.storage_hosts.clear();
            value.required_copies = 0;
            let manifest = sign(MANIFEST, &f.state.network, &value, &f.owner).unwrap();
            f.apply(
                &public(&f.owner),
                20,
                Command::MailAddressDelete {
                    address_id: value.address_id,
                    expected_generation: 1,
                    manifest,
                },
            )
            .unwrap();
        }
        for (index, target) in [public(&f.owner), public(&f.device), public(&key(4))]
            .into_iter()
            .enumerate()
        {
            let before = serde_json::to_vec(&f.state).unwrap();
            let request = request(
                &target,
                30 + index as u8,
                Command::Redeem {
                    secret: hex::encode([10 + index as u8; 32]),
                },
            );
            assert_eq!(
                authority::apply(&mut f.state, &request, None, 100, 30).err(),
                Some("SeparateMailIdentityRequired")
            );
            assert!(!f.state.members.contains_key(&target));
            assert_eq!(serde_json::to_vec(&f.state).unwrap(), before);
        }
    }
}
