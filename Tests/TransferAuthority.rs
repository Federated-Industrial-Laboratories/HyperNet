// SPDX-License-Identifier: MIT
use super::*;
use crate::types::{Member, Request};
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
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
    host: SigningKey,
    sender: SigningKey,
    recipient: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let signer = key(9);
        let host = key(6);
        let sender = key(1);
        let recipient = key(2);
        let mut state = State::initial("09".repeat(32), public(&sender), 100);
        for (k, grants) in [(&host, 3), (&recipient, 1)] {
            state.members.insert(
                public(k),
                Member {
                    grants,
                    expires: 1000,
                    revoked: false,
                },
            );
        }
        let body = HostConsent {
            version: 1,
            network: state.network.clone(),
            host_key: public(&host),
            generation: 1,
            services: vec!["Transfer".into()],
            endpoint: "https://transfer.test:8443/".into(),
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
        let consent = sign(HOST, &state.network, &body, &host).unwrap();
        apply(
            &mut state,
            &request(&public(&host), 1, Command::TransferHostRegister { consent }),
            Some(&"02".repeat(32)),
            100,
            Some(&signer),
        )
        .unwrap();
        Self {
            state,
            signer,
            host,
            sender,
            recipient,
        }
    }
    fn offer(&self, n: u8, bytes: u64) -> Envelope {
        let body = Offer {
            version: 1,
            network: self.state.network.clone(),
            transfer_id: hex::encode([n; 16]),
            sender_key: public(&self.sender),
            recipient_key: public(&self.recipient),
            recipient_encryption_key: bech32::encode("age", [7u8; 32].to_base32(), Variant::Bech32)
                .unwrap(),
            payload_bytes: bytes,
            payload_digest: "03".repeat(32),
            file_bytes: bytes - 100,
            label: "Document".into(),
            expires: 700,
        };
        sign(OFFER, &self.state.network, &body, &self.sender).unwrap()
    }
    fn mutate(&mut self, actor: &str, id: u8, command: Command) -> Result<Reply, Failure> {
        let mut candidate = self.state.clone();
        let result = apply(
            &mut candidate,
            &request(actor, id, command),
            None,
            100,
            Some(&self.signer),
        )?;
        self.state = candidate;
        Ok(result)
    }
    fn create(&mut self, n: u8, bytes: u64) -> TransferRecord {
        let offer = self.offer(n, bytes);
        let reply = self
            .mutate(
                &public(&self.sender),
                n,
                Command::TransferOfferCreate { offer },
            )
            .unwrap();
        serde_json::from_value(reply.result["transfer"].clone()).unwrap()
    }
    fn acceptance(&self, r: &TransferRecord) -> Envelope {
        sign(
            ACCEPTANCE,
            &self.state.network,
            &Acceptance {
                version: 1,
                network: self.state.network.clone(),
                transfer_id: r.body.transfer_id.clone(),
                offer_digest: r.offer_digest.clone(),
                host_key: public(&self.host),
                destination: "Downloads".into(),
                expires: 700,
            },
            &self.recipient,
        )
        .unwrap()
    }
    fn permission(
        &self,
        r: &TransferRecord,
        actor: &SigningKey,
        action: &str,
    ) -> Result<Reply, Failure> {
        let op = Operation {
            version: 1,
            network: self.state.network.clone(),
            operation_id: "11".repeat(16),
            issued_at: 100,
            host_key: public(&self.host),
            transfer_id: r.body.transfer_id.clone(),
            offer_digest: r.offer_digest.clone(),
            action: action.into(),
            offset: 0,
            chunk_bytes: 0,
            chunk_digest: None,
        };
        let operation = sign(OPERATION, &self.state.network, &op, actor).unwrap();
        authorise(
            &self.state,
            &request(
                &public(&self.host),
                10,
                Command::TransferAuthorise {
                    host_key: public(&self.host),
                    operation,
                },
            ),
            Some(&"02".repeat(32)),
            100,
            77,
            Some(&self.signer),
        )
    }
}
#[test]
fn recipient_acceptance_precedes_upload_and_quota_is_reserved_atomically() {
    let mut f = Fixture::new();
    let r = f.create(2, 1500000);
    assert!(f.permission(&r, &f.sender, "Commit").is_err());
    let accept = f.acceptance(&r);
    assert!(
        f.mutate(
            &public(&f.sender),
            3,
            Command::TransferOfferAccept {
                acceptance: accept.clone()
            }
        )
        .is_err()
    );
    f.mutate(
        &public(&f.recipient),
        4,
        Command::TransferOfferAccept { acceptance: accept },
    )
    .unwrap();
    let before = serde_json::to_vec(&f.state).unwrap();
    let reply = f.permission(&r, &f.sender, "Commit").unwrap();
    let value: Permission = verify(
        PERMISSION,
        &serde_json::from_value(reply.result["permission"].clone()).unwrap(),
        &f.state.network,
    )
    .unwrap();
    assert_eq!(value.expires, 105);
    assert_eq!(value.authority_revision, 77);
    assert_eq!(before, serde_json::to_vec(&f.state).unwrap());
    assert!(f.permission(&r, &f.recipient, "Commit").is_err());
    let second = f.create(5, 1500000);
    assert_eq!(
        f.mutate(
            &public(&f.recipient),
            6,
            Command::TransferOfferAccept {
                acceptance: f.acceptance(&second)
            }
        )
        .err(),
        Some("TransferQuotaExceeded")
    );
}
#[test]
fn cancellation_and_host_withdrawal_do_not_revive_on_retries() {
    let mut f = Fixture::new();
    let r = f.create(2, 1000);
    f.mutate(
        &public(&f.recipient),
        3,
        Command::TransferOfferAccept {
            acceptance: f.acceptance(&r),
        },
    )
    .unwrap();
    f.mutate(
        &public(&f.sender),
        4,
        Command::TransferOfferCancel {
            transfer_id: r.body.transfer_id.clone(),
            offer_digest: r.offer_digest.clone(),
        },
    )
    .unwrap();
    assert!(f.permission(&r, &f.sender, "Status").is_err());
    assert!(
        f.mutate(
            &public(&f.sender),
            5,
            Command::TransferOfferCreate {
                offer: r.offer.clone()
            }
        )
        .is_err()
    );
    let second = f.create(6, 1000);
    f.mutate(
        &public(&f.recipient),
        7,
        Command::TransferOfferAccept {
            acceptance: f.acceptance(&second),
        },
    )
    .unwrap();
    f.mutate(
        &public(&f.host),
        8,
        Command::TransferHostWithdraw {
            host_key: public(&f.host),
            expected_generation: 1,
        },
    )
    .unwrap();
    assert!(f.state.transfers.offers[&second.body.transfer_id].cancelled);
    assert!(f.permission(&second, &f.sender, "Status").is_err());
}
#[test]
fn schema_six_survives_later_mail_reads_and_service_hosts_cannot_be_clients() {
    let mut f = Fixture::new();
    assert_eq!(f.state.version, crate::types::STATE_VERSION);
    assert!(page_authority::client(&f.state, &public(&f.host), 100).is_err());
    let mail_signer = key(8);
    mail_authority::apply(
        &mut f.state,
        &request(&public(&f.sender), 2, Command::MailHosts),
        None,
        100,
        2,
        Some(&mail_signer),
    )
    .unwrap();
    assert_eq!(f.state.version, crate::types::STATE_VERSION);
}

#[test]
fn transfer_listing_is_bounded_and_cursor_preserves_all_participant_records() {
    let mut f = Fixture::new();
    for id in 2..21 {
        f.create(id, 1000);
    }
    let first = f
        .mutate(
            &public(&f.sender),
            30,
            Command::TransferOfferList { after: None },
        )
        .unwrap();
    assert_eq!(first.result["transfers"].as_array().unwrap().len(), 16);
    assert!(serde_json::to_vec(&first).unwrap().len() < 65536);
    let cursor = first.result["next"].as_str().unwrap().to_string();
    let second = f
        .mutate(
            &public(&f.sender),
            31,
            Command::TransferOfferList {
                after: Some(cursor),
            },
        )
        .unwrap();
    assert_eq!(second.result["transfers"].as_array().unwrap().len(), 3);
    assert!(second.result["next"].is_null());
}

#[test]
fn malformed_age_recipients_cannot_poison_recipient_listing_or_cancellation() {
    let mut f = Fixture::new();
    let healthy = f.create(2, 1000);
    let signed = f.offer(3, 1000);
    let mut body: Offer = verify(OFFER, &signed, &f.state.network).unwrap();
    let original = body.recipient_encryption_key.clone();
    let mut bad_checksum = original.clone();
    bad_checksum.pop();
    bad_checksum.push(if original.ends_with('q') { 'p' } else { 'q' });
    let invalid = [
        bad_checksum,
        format!("age1{}", "q".repeat(58)),
        original.to_ascii_uppercase(),
        bech32::encode("age", [7u8; 32].to_base32(), Variant::Bech32m).unwrap(),
        bech32::encode("age", [7u8; 31].to_base32(), Variant::Bech32).unwrap(),
    ];
    for recipient in invalid {
        body.recipient_encryption_key = recipient;
        let offer = sign(OFFER, &f.state.network, &body, &f.sender).unwrap();
        let before = serde_json::to_vec(&f.state).unwrap();
        assert_eq!(
            f.mutate(
                &public(&f.sender),
                3,
                Command::TransferOfferCreate { offer }
            )
            .err(),
            Some("TransferInvalidObject")
        );
        assert_eq!(before, serde_json::to_vec(&f.state).unwrap());
    }
    let listed = f
        .mutate(
            &public(&f.recipient),
            4,
            Command::TransferOfferList { after: None },
        )
        .unwrap();
    let records: Vec<TransferRecord> =
        serde_json::from_value(listed.result["transfers"].clone()).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body.transfer_id, healthy.body.transfer_id);
    f.mutate(
        &public(&f.recipient),
        5,
        Command::TransferOfferCancel {
            transfer_id: healthy.body.transfer_id.clone(),
            offer_digest: healthy.offer_digest,
        },
    )
    .unwrap();
    assert!(f.state.transfers.offers[&healthy.body.transfer_id].cancelled);
}

#[test]
fn expired_offers_restore_capacity_without_reviving_signed_offers() {
    let mut f = Fixture::new();
    let original = f.create(2, 1000);
    for id in 3..34 {
        f.create(id, 1000);
    }
    assert_eq!(
        f.mutate(
            &public(&f.sender),
            40,
            Command::TransferOfferCreate {
                offer: f.offer(40, 1000)
            }
        )
        .err(),
        Some("CapacityExceeded")
    );
    f.mutate(
        &public(&f.sender),
        41,
        Command::TransferOfferCancel {
            transfer_id: original.body.transfer_id.clone(),
            offer_digest: original.offer_digest.clone(),
        },
    )
    .unwrap();
    assert_eq!(f.state.transfers.offers.len(), 32);
    let mut query = request(
        &public(&f.sender),
        42,
        Command::TransferOfferList { after: None },
    );
    query.request.issued_at = 701;
    apply(&mut f.state, &query, None, 701, Some(&f.signer)).unwrap();
    assert!(f.state.transfers.offers.is_empty());
    let mut replay = request(
        &public(&f.sender),
        43,
        Command::TransferOfferCreate {
            offer: original.offer,
        },
    );
    replay.request.issued_at = 701;
    assert_eq!(
        apply(&mut f.state, &replay, None, 701, Some(&f.signer)).err(),
        Some("InvalidExpiry")
    );
    assert_eq!(
        apply(&mut f.state, &replay, None, 700, Some(&f.signer)).err(),
        Some("ClockRollback")
    );
    let mut body = original.body;
    body.transfer_id = "44".repeat(16);
    body.expires = 800;
    let offer = sign(OFFER, &f.state.network, &body, &f.sender).unwrap();
    let mut fresh = request(
        &public(&f.sender),
        44,
        Command::TransferOfferCreate { offer },
    );
    fresh.request.issued_at = 701;
    apply(&mut f.state, &fresh, None, 701, Some(&f.signer)).unwrap();
    assert_eq!(f.state.transfers.offers.len(), 1);
}
