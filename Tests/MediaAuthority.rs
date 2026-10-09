// SPDX-License-Identifier: MIT
use super::*;
use crate::types::{Member, PageRecord, PendingPage, Request};
fn signing(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> String {
    hex::encode(signing(n).verifying_key().as_bytes())
}
fn request(n: u8, id: u8, command: Command) -> VerifiedRequest {
    VerifiedRequest {
        key: public(n),
        digest: format!("Digest{id}"),
        request: Request {
            version: 1,
            request_id: hex::encode([id; 16]),
            issued_at: 100,
            command,
        },
        envelope: Envelope {
            network: "09".repeat(32),
            public_key: public(n),
            payload: String::new(),
            signature: String::new(),
        },
    }
}
struct Fixture {
    state: State,
    signer: SigningKey,
    asset: markup::media::Asset,
    page: String,
    source: String,
}
impl Fixture {
    fn new() -> Self {
        let signer = signing(9);
        let mut state = State::initial("09".repeat(32), public(1), 100);
        for (n, grants) in [(2, 1), (3, 1), (6, 3), (7, 3)] {
            state.members.insert(
                public(n),
                Member {
                    grants,
                    expires: 1000,
                    revoked: false,
                },
            );
        }
        for n in [6, 7] {
            let host = HostConsent {
                version: 1,
                network: state.network.clone(),
                host_key: public(n),
                generation: 1,
                services: vec!["PageMedia".into()],
                endpoint: format!("https://media{n}.test:8443/"),
                address: "127.0.0.1:8443".parse().unwrap(),
                ca_digest: "01".repeat(32),
                certificate_digest: "02".repeat(32),
                authority_endpoint: "https://authority.test:8443/".into(),
                authority_address: "127.0.0.1:8443".parse().unwrap(),
                authority_signer: public(9),
                memory_bytes: 536870912,
                pids: 64,
                cpu_quota: 100000,
                cpu_period: 100000,
                state_bytes: 8388608,
                expires: 900,
                namespaces: vec!["News".into()],
                retention_seconds: 600,
            };
            let consent = sign(HOST, &state.network, &host, &signing(n)).unwrap();
            apply(
                &mut state,
                &request(n, n, Command::PageMediaHostRegister { consent }),
                Some(&"02".repeat(32)),
                100,
                1,
                Some(&signer),
            )
            .unwrap();
        }
        let asset = markup::media::Asset {
            id: "Photo".into(),
            profile: "HyperNetRaster/1".into(),
            width: 1,
            height: 1,
            bytes: 3,
            digest: mail_authority::hash(&[1, 2, 3]),
            hosts: vec![public(6), public(7)],
            copies: 2,
        };
        let mut value = Self {
            state,
            signer,
            asset,
            page: "11".repeat(16),
            source: "22".repeat(32),
        };
        value.reserve();
        value
    }
    fn reserve(&mut self) {
        reserve(
            &mut self.state,
            &request(2, 10, Command::PageMediaHosts),
            100,
            1,
            &self.page,
            "News",
            &self.source,
            std::slice::from_ref(&self.asset),
        )
        .unwrap();
        self.state.pages.insert(
            self.page.clone(),
            PageRecord {
                version: 1,
                author: public(2),
                namespace: "News".into(),
                pending: Some(PendingPage {
                    revision: 1,
                    digest: self.source.clone(),
                    profile: markup::PROFILE.into(),
                    audience: "Members".into(),
                    submission_digest: "03".repeat(32),
                    bytes: 200,
                }),
                published: None,
            },
        );
    }
    fn receipt(&self, n: u8, actor: u8, action: &str) -> Envelope {
        sign(
            RECEIPT,
            &self.state.network,
            &StoreReceipt {
                agreement_id: None,
                version: 1,
                network: self.state.network.clone(),
                host_key: public(n),
                host_generation: 1,
                page_id: self.page.clone(),
                revision: 1,
                asset_id: self.asset.id.clone(),
                source_digest: self.source.clone(),
                digest: self.asset.digest.clone(),
                bytes: 3,
                stored_bytes: 3,
                status: "Complete".into(),
                requester_key: public(actor),
                action: action.into(),
                recorded_at: 100,
            },
            &signing(n),
        )
        .unwrap()
    }
    fn register(&mut self, n: u8, actor: u8, id: u8, action: &str) -> Result<Reply, Failure> {
        let receipt = self.receipt(n, actor, action);
        apply(
            &mut self.state,
            &request(
                actor,
                id,
                Command::PageMediaReceipt {
                    agreement_id: None,
                    page_id: self.page.clone(),
                    revision: 1,
                    asset_id: self.asset.id.clone(),
                    receipt,
                },
            ),
            None,
            100,
            2,
            Some(&self.signer),
        )
    }
    fn operation(&self, actor: u8, action: &str) -> Envelope {
        sign(
            OPERATION,
            &self.state.network,
            &Operation {
                admission: None,
                agreement_id: None,
                version: 1,
                network: self.state.network.clone(),
                operation_id: "33".repeat(16),
                issued_at: 100,
                host_key: public(6),
                page_id: self.page.clone(),
                revision: 1,
                asset_id: self.asset.id.clone(),
                source_digest: self.source.clone(),
                action: action.into(),
                offset: 0,
                chunk_bytes: if matches!(action, "Fetch" | "Put") {
                    3
                } else {
                    0
                },
                chunk_digest: (action == "Put").then(|| self.asset.digest.clone()),
            },
            &signing(actor),
        )
        .unwrap()
    }
    fn authorise(&self, actor: u8, action: &str) -> Result<Reply, Failure> {
        authorise(
            &self.state,
            &request(
                6,
                30,
                Command::PageMediaAuthorise {
                    host_key: public(6),
                    operation: self.operation(actor, action),
                },
            ),
            Some(&"02".repeat(32)),
            100,
            2,
            Some(&self.signer),
        )
    }
    fn permission_expiry(&self, actor: u8, action: &str) -> u64 {
        let reply = self.authorise(actor, action).unwrap();
        let envelope: Envelope =
            serde_json::from_value(reply.result["permission"].clone()).unwrap();
        verify::<Permission>(PERMISSION, &envelope, &self.state.network)
            .unwrap()
            .expires
    }
    fn publish(&mut self, reviewer: u8) {
        let page = self.state.pages.get_mut(&self.page).unwrap();
        page.pending = None;
        page.published = Some(types::PublishedPage {
            descriptor: types::PageDescriptor {
                page_id: self.page.clone(),
                publication_version: 2,
                revision: 1,
                author: public(2),
                reviewer: public(reviewer),
                namespace: "News".into(),
                audience: "Members".into(),
                profile: markup::PROFILE.into(),
                digest: self.source.clone(),
                submission_digest: "03".repeat(32),
                approval_digest: "04".repeat(32),
            },
            assets: vec![self.asset.clone()],
            bytes: 200,
        });
    }
}
#[test]
fn pending_media_permissions_end_with_the_upload_reference() {
    let mut f = Fixture::new();
    f.state
        .media
        .assets
        .values_mut()
        .next()
        .unwrap()
        .upload_expires = 101;
    for action in ["Put", "Seal", "Status", "Fetch"] {
        assert_eq!(f.permission_expiry(2, action), 101);
    }
    assert_eq!(f.permission_expiry(1, "Fetch"), 101);
    f.publish(1);
    assert_eq!(f.permission_expiry(3, "Fetch"), 105);
}
#[test]
fn published_media_permissions_end_with_both_publication_signers() {
    let mut f = Fixture::new();
    f.publish(1);
    f.state.members.get_mut(&public(1)).unwrap().expires = 103;
    assert_eq!(f.permission_expiry(3, "Fetch"), 103);
    f.state.members.get_mut(&public(2)).unwrap().expires = 102;
    assert_eq!(f.permission_expiry(3, "Fetch"), 102);
    f.state.members.get_mut(&public(3)).unwrap().expires = 101;
    assert_eq!(f.permission_expiry(3, "Fetch"), 101);
}
#[test]
fn published_media_permissions_include_reviewer_application_and_owner_expiry() {
    let mut f = Fixture::new();
    f.state.applications.insert(
        public(8),
        applications::ApplicationRecord {
            owner_key: public(1),
            application_key: public(8),
            grant: request(8, 50, Command::PageMediaHosts).envelope,
            grant_digest: "05".repeat(32),
            expires: 102,
            namespaces: vec!["News".into()],
            page_ids: Some(vec![f.page.clone()]),
            permissions: vec!["ReviewDecide".into()],
            review_policy_digest: None,
            review_mode: None,
            revoked: false,
        },
    );
    f.publish(8);
    assert_eq!(f.permission_expiry(3, "Fetch"), 102);
    f.state.members.get_mut(&public(1)).unwrap().expires = 101;
    assert_eq!(f.permission_expiry(3, "Fetch"), 101);
}
#[test]
fn reconsent_cannot_shorten_retention_below_existing_reservations() {
    let mut f = Fixture::new();
    let mut body = f.state.media.hosts[&public(6)].body.clone();
    body.generation = 2;
    body.retention_seconds = 598;
    let consent = sign(HOST, &f.state.network, &body, &signing(6)).unwrap();
    assert_eq!(
        apply(
            &mut f.state,
            &request(6, 40, Command::PageMediaHostRegister { consent }),
            Some(&"02".repeat(32)),
            101,
            2,
            Some(&f.signer),
        )
        .err()
        .unwrap(),
        "MediaQuotaExceeded"
    );
    assert_eq!(f.state.media.hosts[&public(6)].body.generation, 1);
    body.retention_seconds = 599;
    let consent = sign(HOST, &f.state.network, &body, &signing(6)).unwrap();
    apply(
        &mut f.state,
        &request(6, 41, Command::PageMediaHostRegister { consent }),
        Some(&"02".repeat(32)),
        101,
        2,
        Some(&f.signer),
    )
    .unwrap();
    assert_eq!(f.state.media.hosts[&public(6)].body.generation, 2);
}
#[test]
fn approval_requires_exact_live_copies_and_explicit_review_attestation() {
    let mut f = Fixture::new();
    let approve = |f: &Fixture| {
        approve(
            &f.state,
            &f.page,
            1,
            std::slice::from_ref(&f.asset),
            &public(1),
            100,
        )
    };
    assert_eq!(approve(&f), Err("MediaReviewRequired"));
    f.register(6, 2, 20, "Seal").unwrap();
    assert_eq!(approve(&f), Err("MediaReviewRequired"));
    assert!(f.register(6, 3, 21, "Fetch").is_err());
    f.register(6, 1, 22, "Fetch").unwrap();
    assert_eq!(approve(&f), Err("MediaIncomplete"));
    f.register(7, 2, 23, "Seal").unwrap();
    approve(&f).unwrap();
    f.state
        .media
        .hosts
        .get_mut(&public(7))
        .unwrap()
        .body
        .generation = 2;
    assert_eq!(approve(&f), Err("MediaIncomplete"));
}
#[test]
fn quarantine_current_reference_and_independent_domains_gate_bytes() {
    let mut f = Fixture::new();
    assert!(f.authorise(3, "Fetch").is_err());
    f.authorise(1, "Fetch").unwrap();
    f.authorise(2, "Status").unwrap();
    assert!(
        verify::<Operation>(
            crate::transfer_types::OPERATION,
            &f.operation(2, "Status"),
            &f.state.network
        )
        .is_err()
    );
    let reply = f.authorise(2, "Status").unwrap();
    let permission: Envelope = serde_json::from_value(reply.result["permission"].clone()).unwrap();
    assert!(
        verify::<Permission>(
            crate::transfer_types::PERMISSION,
            &permission,
            &f.state.network
        )
        .is_err()
    );
    f.state.pages.get_mut(&f.page).unwrap().pending = None;
    assert!(f.authorise(2, "Status").is_err());
    let policy = authorise(
        &f.state,
        &request(
            6,
            31,
            Command::PageMediaPolicySync {
                host_key: public(6),
            },
        ),
        Some(&"02".repeat(32)),
        100,
        3,
        Some(&f.signer),
    )
    .unwrap();
    let object: Envelope = serde_json::from_value(policy.result["policy"].clone()).unwrap();
    let policy: StorePolicy = verify(POLICY, &object, &f.state.network).unwrap();
    assert!(policy.assets.is_empty());
}
#[test]
fn reservation_rejects_unconsented_namespace_and_counts_logical_copies() {
    let mut f = Fixture::new();
    let mut wrong = f.state.clone();
    assert_eq!(
        reserve(
            &mut wrong,
            &request(2, 10, Command::PageMediaHosts),
            100,
            2,
            &f.page,
            "Private",
            &f.source,
            std::slice::from_ref(&f.asset)
        ),
        Err("MediaNamespaceDenied")
    );
    f.state.media.minimum_copies = 3;
    assert_eq!(
        reserve(
            &mut f.state,
            &request(2, 10, Command::PageMediaHosts),
            100,
            2,
            &f.page,
            "News",
            &f.source,
            std::slice::from_ref(&f.asset)
        ),
        Err("MediaCopiesRequired")
    );
}
#[test]
fn media_chunks_reject_overflow_misalignment_and_short_middle_chunks() {
    assert!(crate::policy::media_chunk(32769, 0, 32768));
    assert!(crate::policy::media_chunk(32769, 32768, 1));
    assert!(!crate::policy::media_chunk(32769, 0, 1));
    assert!(!crate::policy::media_chunk(32769, 1, 32768));
    assert!(!crate::policy::media_chunk(u64::MAX, u64::MAX - 1, 32768));
}

#[test]
fn registered_media_identity_cannot_become_a_transfer_host() {
    let mut f = Fixture::new();
    let mut body = serde_json::to_value(&f.state.media.hosts[&public(6)].body).unwrap();
    let fields = body.as_object_mut().unwrap();
    fields.remove("namespaces");
    fields.remove("retentionSeconds");
    fields.insert("services".into(), json!(["Transfer"]));
    let body: crate::transfer_types::HostConsent = serde_json::from_value(body).unwrap();
    let consent = sign(
        crate::transfer_types::HOST,
        &f.state.network,
        &body,
        &signing(6),
    )
    .unwrap();
    let result = crate::transfer_authority::apply(
        &mut f.state,
        &request(6, 44, Command::TransferHostRegister { consent }),
        Some(&"02".repeat(32)),
        100,
        Some(&f.signer),
    );
    assert_eq!(result.err(), Some("SeparateServiceIdentityRequired"));
}
