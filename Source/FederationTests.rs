// SPDX-License-Identifier: MIT
use super::*;
use serde_json::Value;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}
fn request(network: &str, seed: u8, nonce: u8, command: Command) -> VerifiedRequest {
    let payload = serde_json::to_vec(&Request {
        version: 1,
        request_id: hex::encode([nonce; 16]),
        issued_at: 100,
        command,
    })
    .unwrap();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&protocol::fixed_hex::<32>(network).unwrap());
    message.extend_from_slice(key(seed).verifying_key().as_bytes());
    message.extend_from_slice(&payload);
    let envelope = Envelope {
        network: network.into(),
        public_key: public(seed),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: hex::encode(key(seed).sign(&message).to_bytes()),
    };
    protocol::verify_archived(&envelope, network).unwrap()
}

struct Fixture {
    source: State,
    destination: State,
    blobs: BTreeMap<String, Vec<u8>>,
    treaty: FederationTreaty,
    descriptor: PageDescriptor,
    profile: String,
    nonce: u8,
}

#[test]
fn source_share_capacity_preserves_existing_refresh_after_excess_admission() {
    let mut fixture = Fixture::new();
    for id in 1..32 {
        fixture.source.federation_shares.insert(
            object_key(&fixture.treaty.agreement_id, &hex::encode([id; 16])),
            FederationShareRecord {
                descriptor_digest: hex::encode([0; 32]),
                share_digest: hex::encode([0; 32]),
                allowed: false,
                generation: 0,
                last_withdrawal_generation: 0,
            },
        );
    }
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    assert_eq!(fixture.source.federation_shares.len(), 32);

    let additional_id = hex::encode([99; 16]);
    let mut additional = fixture.source.pages[&fixture.descriptor.page_id].clone();
    additional.published.as_mut().unwrap().descriptor.page_id = additional_id.clone();
    let additional_descriptor = additional.published.as_ref().unwrap().descriptor.clone();
    fixture
        .source
        .pages
        .insert(additional_id.clone(), additional);
    let excess = fixture.call(
        true,
        3,
        Command::FederationShare {
            agreement_id: fixture.treaty.agreement_id.clone(),
            agreement_digest: treaty_digest(&fixture.treaty).unwrap(),
            page_id: additional_id,
            publication_version: 2,
            descriptor_digest: descriptor_digest(&additional_descriptor).unwrap(),
            allow: true,
            expected_generation: Some(0),
        },
        100,
    );
    assert_eq!(excess.err(), Some("FederationQuotaExceeded"));
    assert_eq!(fixture.source.federation_shares.len(), 32);
    fixture.transfer(false).unwrap();
    fixture.call(true, 3, fixture.share(false), 100).unwrap();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let treaty = FederationTreaty {
            version: 1,
            agreement_id: hex::encode([44; 16]),
            source_network: hex::encode([11; 32]),
            destination_network: hex::encode([12; 32]),
            source_authority_key: public(7),
            destination_authority_key: public(8),
            source_bridge_key: public(5),
            destination_bridge_key: public(6),
            source_namespace: "Public".into(),
            destination_namespace: "Imported".into(),
            service: "Pages".into(),
            profile: "HyperNetPage/1".into(),
            expires: 1000,
        };
        let mut source = State::initial(treaty.source_network.clone(), public(1), 100);
        let mut destination = State::initial(treaty.destination_network.clone(), public(2), 100);
        for (state, seed, grants) in [(&mut source, 3, MEMBER), (&mut destination, 4, MEMBER)] {
            state.members.insert(
                public(seed),
                Member {
                    grants,
                    expires: 1000,
                    revoked: false,
                },
            );
        }
        source.members.insert(
            public(5),
            Member {
                grants: 9,
                expires: 1000,
                revoked: false,
            },
        );
        destination.members.insert(
            public(6),
            Member {
                grants: 9,
                expires: 1000,
                revoked: false,
            },
        );
        let body = "HyperNetPage/1\n# Notice\n: Shared by its author.\n";
        let page_id = hex::encode([42; 16]);
        let submission = request(
            &source.network,
            3,
            1,
            Command::PageSubmit {
                page_id: page_id.clone(),
                expected_version: 0,
                namespace: "Public".into(),
                audience: "Members".into(),
                profile: "HyperNetPage/1".into(),
                digest: hex::encode(Sha256::digest(body.as_bytes())),
                body: body.into(),
            },
        );
        let approval = request(
            &source.network,
            1,
            2,
            Command::PageReview {
                page_id: page_id.clone(),
                expected_version: 1,
                revision: 1,
                digest: hex::encode(Sha256::digest(body.as_bytes())),
                profile: "HyperNetPage/1".into(),
                author: public(3),
                namespace: "Public".into(),
                audience: "Members".into(),
                submission_digest: submission.digest.clone(),
                decision: "Approve".into(),
                application_policy_digest: None,
                application_review_mode: None,
                review_expires: None,
            },
        );
        let descriptor = PageDescriptor {
            page_id: page_id.clone(),
            publication_version: 2,
            revision: 1,
            author: public(3),
            reviewer: public(1),
            namespace: "Public".into(),
            audience: "Members".into(),
            profile: "HyperNetPage/1".into(),
            digest: hex::encode(Sha256::digest(body.as_bytes())),
            submission_digest: submission.digest,
            approval_digest: approval.digest,
        };
        let bundle = PageBundle {
            submission: submission.envelope,
            approval: approval.envelope,
        };
        let bytes = encoded(&bundle, page_authority::MAX_BUNDLE).unwrap();
        source.pages.insert(
            page_id,
            PageRecord {
                version: 2,
                author: public(3),
                namespace: "Public".into(),
                pending: None,
                published: Some(PublishedPage {
                    descriptor: descriptor.clone(),
                    bytes: bytes.len() as u64,
                }),
            },
        );
        let mut blobs = BTreeMap::new();
        blobs.insert(
            format!("Native/{}", page_authority::publication_key(&descriptor)),
            bytes,
        );
        let mut result = Self {
            source,
            destination,
            blobs,
            treaty,
            descriptor,
            profile: String::new(),
            nonce: 10,
        };
        result
            .call(
                true,
                1,
                Command::FederationAccept {
                    treaty: result.treaty.clone(),
                },
                100,
            )
            .unwrap();
        result
            .call(
                false,
                2,
                Command::FederationAccept {
                    treaty: result.treaty.clone(),
                },
                100,
            )
            .unwrap();
        let endpoint = |source: bool| {
            json!({"network":if source {&result.treaty.source_network}else{&result.treaty.destination_network},
            "deviceKey":if source {public(5)}else{public(6)},"authorityKey":if source{public(7)}else{public(8)},
            "authorityEndpoint":"https://Authority.example:8443/","authorityAddress":"192.0.2.1:8443","caCertificateDigest":hex::encode([33;32])})
        };
        let payload=serde_json::to_vec(&json!({"version":1,"service":"FederationPages","agreementId":result.treaty.agreement_id,
            "treatyDigest":treaty_digest(&result.treaty).unwrap(),"sourceNamespace":"Public","destinationNamespace":"Imported",
            "source":endpoint(true),"destination":endpoint(false),"expires":1000,"memoryBytes":67108864,"pids":32,
            "cpuQuota":100000,"cpuPeriod":100000,"stateBytes":1048576})).unwrap();
        let mut message = b"HyperNet/BridgeConsent/1\0".to_vec();
        message.extend_from_slice(&payload);
        let document=serde_json::to_vec(&json!({"payload":URL_SAFE_NO_PAD.encode(payload),
            "sourceSignature":hex::encode(key(5).sign(&message).to_bytes()),"destinationSignature":hex::encode(key(6).sign(&message).to_bytes())})).unwrap();
        result.profile = hex::encode(Sha256::digest(&document));
        for (source, seed) in [(true, 5), (false, 6)] {
            result
                .call(
                    source,
                    seed,
                    Command::BridgeConsent {
                        agreement_id: result.treaty.agreement_id.clone(),
                        profile: result.profile.clone(),
                        expires: 1000,
                        certificate: hex::encode([22; 32]),
                        document: URL_SAFE_NO_PAD.encode(&document),
                    },
                    100,
                )
                .unwrap();
        }
        result
    }

    fn call(
        &mut self,
        source: bool,
        seed: u8,
        command: Command,
        now: u64,
    ) -> Result<Reply, &'static str> {
        self.nonce = self.nonce.wrapping_add(1);
        let state = if source {
            &mut self.source
        } else {
            &mut self.destination
        };
        let request = request(&state.network, seed, self.nonce, command);
        let mut candidate = state.clone();
        let certificate = hex::encode([22; 32]);
        let change = apply(
            &mut candidate,
            &request,
            Some(&certificate),
            now,
            100,
            &self.blobs,
            Some(&key(if source { 7 } else { 8 })),
        )?;
        for (name, bytes) in change.puts {
            self.blobs.insert(name, bytes);
        }
        for name in change.deletes {
            self.blobs.remove(&name);
        }
        *state = candidate;
        Ok(change.reply)
    }

    fn share(&self, allow: bool) -> Command {
        let generation = self
            .source
            .federation_shares
            .get(&object_key(
                &self.treaty.agreement_id,
                &self.descriptor.page_id,
            ))
            .map_or(0, |value| value.generation);
        if !allow {
            return Command::FederationUnshare {
                agreement_id: self.treaty.agreement_id.clone(),
                page_id: self.descriptor.page_id.clone(),
                expected_generation: generation,
            };
        }
        Command::FederationShare {
            agreement_id: self.treaty.agreement_id.clone(),
            agreement_digest: treaty_digest(&self.treaty).unwrap(),
            page_id: self.descriptor.page_id.clone(),
            publication_version: 2,
            descriptor_digest: descriptor_digest(&self.descriptor).unwrap(),
            allow,
            expected_generation: Some(generation),
        }
    }

    fn transfer(&mut self, bundle: bool) -> Result<Value, &'static str> {
        let permit = self.call(
            false,
            6,
            Command::FederationPermit {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
            },
            100,
        )?;
        let admission: SignedEvidence =
            serde_json::from_value(permit.result["admission"].clone()).unwrap();
        let exported = self.call(
            true,
            5,
            Command::FederationExport {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
                admission: admission.clone(),
                page_id: Some(self.descriptor.page_id.clone()),
                include_bundle: bundle,
            },
            100,
        )?;
        self.call(
            false,
            6,
            Command::FederationImport {
                agreement_id: self.treaty.agreement_id.clone(),
                profile: self.profile.clone(),
                admission,
                export: serde_json::from_value(exported.result["export"].clone()).unwrap(),
                bundle: if bundle {
                    Some(serde_json::from_value(exported.result["bundle"].clone()).unwrap())
                } else {
                    None
                },
                author_share: if bundle {
                    Some(serde_json::from_value(exported.result["authorShare"].clone()).unwrap())
                } else {
                    None
                },
            },
            100,
        )
        .map(|reply| reply.result)
    }

    fn read(&self) -> Command {
        Command::FederationRead {
            agreement_id: self.treaty.agreement_id.clone(),
            page_id: self.descriptor.page_id.clone(),
        }
    }
    fn review(&self, digest: String) -> Command {
        Command::FederationReview {
            agreement_id: self.treaty.agreement_id.clone(),
            page_id: self.descriptor.page_id.clone(),
            expected_version: 1,
            descriptor_digest: digest,
            decision: "Approve".into(),
        }
    }
}

#[test]
fn bilateral_sharing_requires_author_opt_in_and_exact_local_review() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.transfer(true).err(), Some("AuthorShareRequired"));
    assert_eq!(
        fixture.call(true, 1, fixture.share(true), 100).err(),
        Some("PageOwnerMismatch")
    );
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    assert_eq!(
        fixture.transfer(false).err(),
        Some("FederationBundleRequired")
    );
    assert_eq!(fixture.transfer(true).unwrap()["state"], "Pending");
    assert!(fixture.call(false, 4, fixture.read(), 100).is_err());
    assert_eq!(
        fixture
            .call(false, 2, fixture.review(hex::encode([0; 32])), 100)
            .err(),
        Some("FederationVersionConflict")
    );
    fixture
        .call(
            false,
            2,
            fixture.review(descriptor_digest(&fixture.descriptor).unwrap()),
            100,
        )
        .unwrap();
    fixture.call(false, 4, fixture.read(), 100).unwrap();
    for _ in 0..70 {
        assert_eq!(fixture.transfer(false).unwrap()["version"], 2);
    }
    assert_eq!(fixture.destination.version, 4);
    fixture.call(true, 3, fixture.share(false), 100).unwrap();
    assert_eq!(fixture.transfer(false).err(), Some("AuthorShareRequired"));
    assert!(fixture.call(false, 4, fixture.read(), 105).is_err());
}

#[test]
fn withdrawal_and_service_history_cannot_be_bypassed() {
    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    fixture
        .call(
            false,
            2,
            fixture.review(descriptor_digest(&fixture.descriptor).unwrap()),
            100,
        )
        .unwrap();
    fixture
        .call(
            false,
            2,
            Command::FederationPageWithdraw {
                agreement_id: fixture.treaty.agreement_id.clone(),
                page_id: fixture.descriptor.page_id.clone(),
                expected_version: 2,
            },
            100,
        )
        .unwrap();
    assert_eq!(fixture.transfer(false).unwrap()["state"], "Suppressed");
    assert!(fixture.call(false, 4, fixture.read(), 100).is_err());
    fixture
        .destination
        .members
        .get_mut(&public(6))
        .unwrap()
        .grants = MEMBER;
    assert!(page_authority::client(&fixture.destination, &public(6), 100).is_err());
    assert!(authority::require(&fixture.destination, &public(6), ADMIN, 100).is_err());
    fixture.source.bridge_consents.remove(&public(5));
    assert!(page_authority::client(&fixture.source, &public(5), 100).is_err());
    let grant = request(
        &fixture.destination.network,
        2,
        220,
        Command::Grant {
            device_key: public(6),
            grants: 3,
            expires: 1000,
        },
    );
    assert_eq!(
        authority::apply(&mut fixture.destination, &grant, None, 100, 101).err(),
        Some("ServiceIdentity")
    );
}

#[test]
fn evidence_rejects_wrong_treaty_forged_share_expiry_and_ambiguous_fields() {
    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    let record = fixture
        .destination
        .federation_pages
        .values()
        .next()
        .unwrap();
    assert!(verify_export(&fixture.treaty, &record.admission, &record.export, 105).is_err());
    assert!(verify_export(&fixture.treaty, &record.admission, &record.export, 99).is_err());
    let mut wrong = fixture.treaty.clone();
    wrong.destination_network = hex::encode([13; 32]);
    assert!(verify_admission(&wrong, &record.admission, 100).is_err());
    let forged = request(&fixture.source.network, 1, 230, fixture.share(true));
    assert_eq!(
        verify_share(&fixture.treaty, &fixture.descriptor, &forged.envelope).err(),
        Some("InvalidAuthorShare")
    );
    let mut tampered = record.export.clone();
    tampered.signature = hex::encode([0; 64]);
    assert!(verify_export(&fixture.treaty, &record.admission, &tampered, 100).is_err());
    let mut duplicate = URL_SAFE_NO_PAD.decode(&record.admission.payload).unwrap();
    duplicate.splice(1..1, b"\"version\":1,".iter().copied());
    let mut message = ADMISSION.to_vec();
    message.extend_from_slice(&duplicate);
    let evidence = SignedEvidence {
        public_key: public(8),
        payload: URL_SAFE_NO_PAD.encode(duplicate),
        signature: hex::encode(key(8).sign(&message).to_bytes()),
    };
    assert!(verify_admission(&fixture.treaty, &evidence, 100).is_err());
    wrong = fixture.treaty.clone();
    wrong.source_authority_key = wrong.source_bridge_key.clone();
    assert!(treaty_digest(&wrong).is_err());
}

#[test]
fn either_authority_or_local_service_can_veto_delivery() {
    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    fixture
        .call(
            false,
            2,
            fixture.review(descriptor_digest(&fixture.descriptor).unwrap()),
            100,
        )
        .unwrap();
    fixture
        .destination
        .members
        .get_mut(&public(2))
        .unwrap()
        .revoked = true;
    assert!(fixture.call(false, 4, fixture.read(), 100).is_err());
    fixture
        .destination
        .members
        .get_mut(&public(2))
        .unwrap()
        .revoked = false;
    fixture.call(false, 4, fixture.read(), 100).unwrap();
    fixture
        .call(false, 6, Command::BridgeWithdraw, 100)
        .unwrap();
    assert!(fixture.call(false, 4, fixture.read(), 100).is_err());
    assert!(fixture.transfer(false).is_err());

    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    fixture
        .call(
            true,
            1,
            Command::FederationWithdraw {
                agreement_id: fixture.treaty.agreement_id.clone(),
                expected_version: 1,
            },
            100,
        )
        .unwrap();
    assert_eq!(fixture.transfer(false).err(), Some("FederationUnavailable"));
    assert_eq!(
        fixture
            .call(
                true,
                1,
                Command::FederationAccept {
                    treaty: fixture.treaty.clone()
                },
                100
            )
            .err(),
        Some("FederationAgreementExists")
    );

    let mut fixture = Fixture::new();
    fixture
        .call(
            false,
            2,
            Command::FederationWithdraw {
                agreement_id: fixture.treaty.agreement_id.clone(),
                expected_version: 1,
            },
            100,
        )
        .unwrap();
    assert_eq!(fixture.transfer(false).err(), Some("FederationUnavailable"));
}

#[test]
fn authority_signing_and_bilateral_consent_are_separate() {
    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    let record = fixture
        .destination
        .federation_pages
        .values()
        .next()
        .unwrap();
    let mut evidence =
        verify_export(&fixture.treaty, &record.admission, &record.export, 100).unwrap();
    evidence.source_profile = hex::encode([99; 32]);
    let different_profile = sign(EXPORT, &evidence, &key(7)).unwrap();
    assert!(verify_export(&fixture.treaty, &record.admission, &different_profile, 100).is_err());
    let mut permit = verify_admission(&fixture.treaty, &record.admission, 100).unwrap();
    permit.destination_profile = hex::encode([99; 32]);
    let other_profile = sign(ADMISSION, &permit, &key(8)).unwrap();
    assert_eq!(
        fixture
            .call(
                true,
                5,
                Command::FederationExport {
                    agreement_id: fixture.treaty.agreement_id.clone(),
                    profile: fixture.profile.clone(),
                    admission: other_profile,
                    page_id: None,
                    include_bundle: false
                },
                100
            )
            .err(),
        Some("BridgeConsentRequired")
    );
    let request = request(
        &fixture.source.network,
        1,
        240,
        Command::FederationAccept {
            treaty: fixture.treaty.clone(),
        },
    );
    assert_eq!(
        apply(
            &mut fixture.source,
            &request,
            None,
            100,
            100,
            &fixture.blobs,
            None
        )
        .err(),
        Some("FederationSigningKeyRequired")
    );
    assert_eq!(
        apply(
            &mut fixture.source,
            &request,
            None,
            100,
            100,
            &fixture.blobs,
            Some(&key(8))
        )
        .err(),
        Some("WrongFederationAuthority")
    );
    fixture.source.members.insert(
        public(7),
        Member {
            grants: MEMBER,
            expires: 1000,
            revoked: false,
        },
    );
    assert_eq!(
        apply(
            &mut fixture.source,
            &request,
            None,
            100,
            100,
            &fixture.blobs,
            Some(&key(7))
        )
        .err(),
        Some("DedicatedAuthorityKeyRequired")
    );
}

#[test]
fn withdrawal_survives_review_loss_inactive_treaty_and_delayed_consent() {
    let mut fixture = Fixture::new();
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    let delayed = fixture.share(true);
    let withdrawal = fixture.share(false);
    fixture.source.members.get_mut(&public(1)).unwrap().grants = MEMBER;
    assert!(fixture.transfer(true).is_err());
    let result = fixture.call(true, 3, withdrawal.clone(), 100).unwrap();
    assert_eq!(result.result["allowed"], false);
    assert_eq!(result.result["generation"], 2);
    fixture.source = serde_json::from_slice(&serde_json::to_vec(&fixture.source).unwrap()).unwrap();
    fixture.source.receipts.clear();
    fixture.source.members.get_mut(&public(1)).unwrap().grants = MEMBER | ADMIN;
    assert!(fixture.transfer(true).is_err());
    assert_eq!(
        fixture.call(true, 3, delayed, 100).err(),
        Some("ShareGenerationConflict")
    );
    fixture.call(true, 3, fixture.share(true), 100).unwrap();
    fixture.transfer(true).unwrap();
    let retried = fixture.call(true, 3, withdrawal, 100).unwrap();
    assert_eq!(retried.result["generation"], 3);
    assert_eq!(retried.result["lastWithdrawalGeneration"], 2);
    assert_eq!(retried.result["allowed"], true);
    fixture.transfer(false).unwrap();
    fixture
        .source
        .pages
        .get_mut(&fixture.descriptor.page_id)
        .unwrap()
        .published = None;
    fixture
        .source
        .federation_agreements
        .get_mut(&fixture.treaty.agreement_id)
        .unwrap()
        .active = false;
    let result = fixture.call(true, 3, fixture.share(false), 100).unwrap();
    assert_eq!(result.result["allowed"], false);
    assert_eq!(result.result["generation"], 4);
}

#[test]
fn withdrawal_requires_exact_live_owner_and_fences_concurrent_first_grant() {
    let mut fixture = Fixture::new();
    let delayed = fixture.share(true);
    assert_eq!(
        fixture.call(true, 1, fixture.share(false), 100).err(),
        Some("PageOwnerMismatch")
    );
    fixture.source.members.get_mut(&public(3)).unwrap().revoked = true;
    assert_eq!(
        fixture.call(true, 3, fixture.share(false), 100).err(),
        Some("PermissionDenied")
    );
    fixture.source.members.get_mut(&public(3)).unwrap().revoked = false;
    fixture
        .source
        .federation_agreements
        .get_mut(&fixture.treaty.agreement_id)
        .unwrap()
        .treaty
        .expires = 99;
    fixture.call(true, 3, fixture.share(false), 100).unwrap();
    fixture
        .source
        .federation_agreements
        .get_mut(&fixture.treaty.agreement_id)
        .unwrap()
        .treaty
        .expires = 1000;
    assert_eq!(
        fixture.call(true, 3, delayed, 100).err(),
        Some("ShareGenerationConflict")
    );
    let mut legacy = fixture.share(true);
    if let Command::FederationShare {
        expected_generation,
        ..
    } = &mut legacy
    {
        *expected_generation = None;
    }
    assert_eq!(
        fixture.call(true, 3, legacy, 100).err(),
        Some("ShareGenerationRequired")
    );
}
