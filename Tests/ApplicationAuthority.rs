// SPDX-License-Identifier: MIT
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}
fn request(state: &State, signer: u8, nonce: u8, now: u64, command: Command) -> VerifiedRequest {
    let payload = serde_json::to_vec(&Request {
        version: 1,
        request_id: hex::encode([nonce; 16]),
        issued_at: now,
        command,
    })
    .unwrap();
    let key = SigningKey::from_bytes(&[signer; 32]);
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&protocol::fixed_hex::<32>(&state.network).unwrap());
    message.extend_from_slice(key.verifying_key().as_bytes());
    message.extend_from_slice(&payload);
    let envelope = Envelope {
        network: state.network.clone(),
        public_key: public(signer),
        payload: URL_SAFE_NO_PAD.encode(payload),
        signature: hex::encode(key.sign(&message).to_bytes()),
    };
    protocol::verify_archived(&envelope, &state.network).unwrap()
}
fn initial() -> State {
    let mut state = State::initial(hex::encode([99; 32]), public(1), 100);
    for signer in [2, 3] {
        state.members.insert(
            public(signer),
            Member {
                grants: MEMBER,
                expires: 10000,
                revoked: false,
            },
        );
    }
    state
}
fn consent(
    state: &State,
    owner: u8,
    app: u8,
    now: u64,
    expires: u64,
    permissions: &[&str],
) -> VerifiedRequest {
    let mut permissions: Vec<_> = permissions.iter().map(|s| s.to_string()).collect();
    permissions.sort();
    let review = permissions.iter().any(|p| p == "ReviewDecide");
    request(
        state,
        app,
        app,
        now,
        Command::ApplicationConsent {
            owner_key: public(owner),
            expires,
            namespaces: vec!["Board".into()],
            page_ids: None,
            permissions,
            review_policy_digest: review.then(|| hex::encode([9; 32])),
            review_mode: review.then(|| "Automatic".into()),
        },
    )
}
fn grant(
    state: &State,
    owner: u8,
    app: u8,
    now: u64,
    expires: u64,
    permissions: &[&str],
) -> VerifiedRequest {
    request(
        state,
        owner,
        app,
        now,
        Command::ApplicationGrantCreate {
            consent: consent(state, owner, app, now, expires, permissions).envelope,
        },
    )
}
fn perform(state: &mut State, req: &VerifiedRequest, now: u64) -> Result<Reply, Failure> {
    let mut candidate = state.clone();
    let reply = apply(&mut candidate, req, now, 10)?;
    *state = candidate;
    Ok(reply)
}
fn page(
    state: &mut State,
    blobs: &mut BTreeMap<String, Vec<u8>>,
    req: &VerifiedRequest,
    now: u64,
) -> Result<Reply, Failure> {
    let mut candidate = state.clone();
    let change = page_authority::apply(&mut candidate, req, None, now, 10, blobs)?;
    for key in change.deletes {
        blobs.remove(&key);
    }
    for (key, bytes) in change.puts {
        blobs.insert(key, bytes);
    }
    *state = candidate;
    Ok(change.reply)
}
fn submit(state: &State, signer: u8, nonce: u8, id: u8, namespace: &str) -> VerifiedRequest {
    let body = "HyperNetPage/2\n# Notice\n: Pending content.\n";
    request(
        state,
        signer,
        nonce,
        100,
        Command::PageSubmit {
            page_id: hex::encode([id; 16]),
            expected_version: 0,
            namespace: namespace.into(),
            audience: "Members".into(),
            profile: crate::markup::PROFILE.into(),
            digest: hex::encode(Sha256::digest(body)),
            body: body.into(),
        },
    )
}
fn review(state: &State, signer: u8, nonce: u8, id: u8) -> VerifiedRequest {
    let id = hex::encode([id; 16]);
    let p = &state.pages[&id];
    let pending = p.pending.as_ref().unwrap();
    request(
        state,
        signer,
        nonce,
        100,
        Command::PageReview {
            page_id: id,
            expected_version: p.version,
            revision: pending.revision,
            digest: pending.digest.clone(),
            profile: pending.profile.clone(),
            author: p.author.clone(),
            namespace: p.namespace.clone(),
            audience: pending.audience.clone(),
            submission_digest: pending.submission_digest.clone(),
            decision: "Approve".into(),
            application_policy_digest: state
                .applications
                .get(&public(signer))
                .and_then(|a| a.review_policy_digest.clone()),
            application_review_mode: state
                .applications
                .get(&public(signer))
                .and_then(|a| a.review_mode.clone()),
            review_expires: state
                .applications
                .contains_key(&public(signer))
                .then_some(400),
        },
    )
}
#[test]
fn possession_scope_and_receipts_bind_the_exact_owner_approval() {
    let mut state = initial();
    let good = grant(&state, 2, 10, 100, 1000, &["PagesRead"]);
    let mut wrong = good.envelope.clone();
    wrong.public_key = public(11);
    assert!(protocol::verify_archived(&wrong, &state.network).is_err());
    let substituted = request(&state, 3, 10, 100, good.request.command.clone());
    assert_eq!(
        perform(&mut state, &substituted, 100).err(),
        Some("InvalidApplicationConsent")
    );
    let receipt = perform(&mut state, &good, 100).unwrap();
    assert_eq!(receipt.result["application"]["applicationKey"], public(10));
    assert_eq!(
        serde_json::to_value(perform(&mut state, &good, 100).unwrap()).unwrap(),
        serde_json::to_value(receipt).unwrap()
    );
    let mut bad = consent(&state, 2, 11, 100, 1000, &["PagesRead"]);
    if let Command::ApplicationConsent { namespaces, .. } = &mut bad.request.command {
        *namespaces = vec!["Board".into(), "Board".into()];
    }
    let bad = request(&state, 11, 11, 100, bad.request.command);
    let bad = request(
        &state,
        2,
        11,
        100,
        Command::ApplicationGrantCreate {
            consent: bad.envelope,
        },
    );
    assert_eq!(
        perform(&mut state, &bad, 100).err(),
        Some("InvalidApplicationScope")
    );
    let bad = grant(&state, 2, 12, 100, 1000, &["ReviewDecide", "ReviewInspect"]);
    assert!(perform(&mut state, &bad, 100).is_err());
    let stale = consent(&state, 2, 13, 39, 1000, &["PagesRead"]);
    let stale = request(
        &state,
        2,
        13,
        100,
        Command::ApplicationGrantCreate {
            consent: stale.envelope,
        },
    );
    assert_eq!(perform(&mut state, &stale, 100).err(), Some("StaleRequest"));
    assert_eq!(state.applications.len(), 1);
}
#[test]
fn pages_use_exact_scope_actual_signers_and_current_review_policy() {
    let mut state = initial();
    let mut blobs = BTreeMap::new();
    for (owner, app, perms) in [
        (2, 10, vec!["PagesRead", "PagesSubmit"]),
        (1, 11, vec!["ReviewDecide", "ReviewInspect"]),
    ] {
        let req = grant(&state, owner, app, 100, 1000, &perms);
        perform(&mut state, &req, 100).unwrap();
    }
    let denied = submit(&state, 10, 20, 1, "Other");
    assert_eq!(
        page(&mut state, &mut blobs, &denied, 100).err(),
        Some("ApplicationPermissionDenied")
    );
    let req = submit(&state, 10, 21, 1, "Board");
    page(&mut state, &mut blobs, &req, 100).unwrap();
    let mut bad = review(&state, 11, 22, 1).request.command;
    if let Command::PageReview {
        application_policy_digest,
        ..
    } = &mut bad
    {
        *application_policy_digest = Some(hex::encode([8; 32]));
    }
    let bad = request(&state, 11, 22, 100, bad);
    assert_eq!(
        page(&mut state, &mut blobs, &bad, 100).err(),
        Some("ApplicationReviewMismatch")
    );
    let good = review(&state, 11, 23, 1);
    page(&mut state, &mut blobs, &good, 100).unwrap();
    let published = page_authority::published(&state, &hex::encode([1; 16]), 100).unwrap();
    assert_eq!(published.descriptor.author, public(10));
    assert_eq!(published.descriptor.reviewer, public(11));
    let req = request(
        &state,
        10,
        24,
        100,
        Command::PageRead {
            page_id: hex::encode([1; 16]),
        },
    );
    let read = page(&mut state, &mut blobs, &req, 100).unwrap();
    let bundle: PageBundle = serde_json::from_value(read.result["bundle"].clone()).unwrap();
    let descriptor: PageDescriptor =
        serde_json::from_value(read.result["descriptor"].clone()).unwrap();
    assert!(page_authority::verify_bundle(&state.network, &descriptor, &bundle).is_ok());
    assert_eq!(
        page_authority::until(&state, &public(3), Some(&descriptor), 998),
        1000
    );
    state.members.get_mut(&public(1)).unwrap().grants = MEMBER;
    assert!(page_authority::published(&state, &descriptor.page_id, 100).is_err());
    state.members.get_mut(&public(1)).unwrap().grants = MEMBER | ADMIN;
    let revoke = request(
        &state,
        11,
        25,
        100,
        Command::ApplicationGrantRevoke {
            application_key: public(11),
        },
    );
    perform(&mut state, &revoke, 100).unwrap();
    assert!(page_authority::published(&state, &descriptor.page_id, 100).is_err());
    assert!(page(&mut state, &mut blobs, &good, 100).is_err());
    assert!(page_authority::verify_bundle(&state.network, &descriptor, &bundle).is_ok());
}
#[test]
fn lists_and_queues_require_namespace_and_filter_page_identifiers() {
    let mut state = initial();
    let mut blobs = BTreeMap::new();
    for id in [1, 2] {
        let req = submit(&state, 2, 30 + id, id, "Board");
        page(&mut state, &mut blobs, &req, 100).unwrap();
    }
    let mut proof = consent(&state, 1, 10, 100, 1000, &["PagesRead", "ReviewInspect"])
        .request
        .command;
    if let Command::ApplicationConsent { page_ids, .. } = &mut proof {
        *page_ids = Some(vec![hex::encode([1; 16])]);
    }
    let proof = request(&state, 10, 10, 100, proof);
    let req = request(
        &state,
        1,
        10,
        100,
        Command::ApplicationGrantCreate {
            consent: proof.envelope,
        },
    );
    perform(&mut state, &req, 100).unwrap();
    for namespace in [None, Some("Other".into())] {
        let req = request(
            &state,
            10,
            33,
            100,
            Command::PageQueue {
                namespace,
                after: None,
            },
        );
        assert!(page(&mut state, &mut blobs, &req, 100).is_err());
    }
    let req = request(
        &state,
        10,
        34,
        100,
        Command::PageQueue {
            namespace: Some("Board".into()),
            after: None,
        },
    );
    let result = page(&mut state, &mut blobs, &req, 100).unwrap();
    assert_eq!(result.result["entries"].as_array().unwrap().len(), 1);
    assert_eq!(result.result["entries"][0]["pageId"], hex::encode([1; 16]));
    let req = request(
        &state,
        10,
        35,
        100,
        Command::PageInspect {
            page_id: hex::encode([2; 16]),
        },
    );
    assert!(page(&mut state, &mut blobs, &req, 100).is_err());
    for id in [1, 2] {
        let req = review(&state, 1, 40 + id, id);
        page(&mut state, &mut blobs, &req, 100).unwrap();
    }
    let req = request(
        &state,
        10,
        43,
        100,
        Command::PageList {
            namespace: Some("Board".into()),
            after: None,
        },
    );
    let result = page(&mut state, &mut blobs, &req, 100).unwrap();
    assert_eq!(result.result["entries"].as_array().unwrap().len(), 1);
}
#[test]
fn application_keys_cannot_enter_membership_services_or_replication() {
    let mut state = initial();
    let req = grant(&state, 2, 10, 100, 1000, &["PagesRead"]);
    perform(&mut state, &req, 100).unwrap();
    for command in [
        Command::Status { device_key: None },
        Command::Withdraw,
        Command::TransferHosts,
        Command::MailHosts,
        Command::SshServices,
        Command::FederationAgreements,
        Command::ApplicationGrantList { after: None },
        Command::PageReplicaRequest {
            page_id: hex::encode([1; 16]),
            replica_device_key: public(3),
            publication_version: 1,
        },
        Command::PageReplicaResult {
            ticket_id: hex::encode([1; 32]),
        },
        Command::PageSync {
            profile: hex::encode([1; 32]),
            known_inventory: None,
            fetch: None,
        },
    ] {
        let req = request(&state, 10, 20, 100, command);
        assert_eq!(
            admit(&state, &req).err(),
            Some("ApplicationPermissionDenied")
        );
    }
    let invite = request(
        &state,
        1,
        20,
        100,
        Command::Invite {
            verifier: hex::encode([1; 32]),
            device_key: public(10),
            grants: MEMBER,
            expires: 1000,
        },
    );
    assert!(authority::apply(&mut state, &invite, None, 100, 10).is_err());
    assert!(crate::mail_authority::reserved_identity_conflict(
        &state,
        &public(10)
    ));
    let proof = consent(&state, 2, 3, 100, 1000, &["PagesRead"]);
    let req = request(
        &state,
        2,
        21,
        100,
        Command::ApplicationGrantCreate {
            consent: proof.envelope,
        },
    );
    assert_eq!(
        perform(&mut state, &req, 100).err(),
        Some("SeparateApplicationIdentityRequired")
    );
    state.invitations.insert(
        hex::encode([4; 32]),
        Invitation {
            issuer: public(1),
            device_key: public(12),
            grants: MEMBER,
            expires: 1000,
            redeemed: false,
        },
    );
    let req = grant(&state, 2, 12, 100, 1000, &["PagesRead"]);
    assert!(perform(&mut state, &req, 100).is_err());
}
#[test]
fn expired_unreferenced_grants_recover_capacity_without_clock_revival() {
    let mut state = initial();
    for app in 10..18 {
        let req = grant(&state, 2, app, 100, 120, &["PagesRead"]);
        perform(&mut state, &req, 100).unwrap();
    }
    let full = grant(&state, 2, 18, 100, 120, &["PagesRead"]);
    assert_eq!(
        perform(&mut state, &full, 100).err(),
        Some("ApplicationQuotaExceeded")
    );
    let still_receipted = grant(&state, 2, 18, 121, 200, &["PagesRead"]);
    assert_eq!(
        perform(&mut state, &still_receipted, 121).err(),
        Some("ApplicationQuotaExceeded")
    );
    let recovered = grant(&state, 2, 18, 161, 200, &["PagesRead"]);
    perform(&mut state, &recovered, 161).unwrap();
    assert_eq!(state.applications.len(), 1);
    assert!(!state.applications.contains_key(&public(10)));
    assert_eq!(
        perform(&mut state, &recovered, 160).err(),
        Some("ClockRollback")
    );
    let decoded: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(decoded.version, crate::types::STATE_VERSION);
    assert_eq!(decoded.high_water_time, 161);
    assert_eq!(decoded.applications.len(), 1);
}
#[test]
fn references_reserve_expired_identity_and_revocation_survives_owner_loss() {
    let mut state = initial();
    let mut blobs = BTreeMap::new();
    let req = grant(&state, 2, 10, 100, 120, &["PagesSubmit"]);
    perform(&mut state, &req, 100).unwrap();
    let req = submit(&state, 10, 20, 1, "Board");
    page(&mut state, &mut blobs, &req, 100).unwrap();
    let req = grant(&state, 2, 11, 161, 200, &["PagesRead"]);
    perform(&mut state, &req, 161).unwrap();
    assert!(state.applications.contains_key(&public(10)));
    state.members.get_mut(&public(2)).unwrap().revoked = true;
    let req = request(
        &state,
        2,
        21,
        161,
        Command::ApplicationGrantRevoke {
            application_key: public(10),
        },
    );
    perform(&mut state, &req, 161).unwrap();
    assert!(state.applications[&public(10)].revoked);
    let req = request(
        &state,
        10,
        22,
        161,
        Command::ApplicationGrantGet {
            application_key: public(10),
        },
    );
    assert!(
        perform(&mut state, &req, 161).unwrap().result["application"]["revoked"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn global_capacity_and_explicit_review_attenuation_are_bounded() {
    let mut state = initial();
    for owner in 20..29 {
        state.members.insert(
            public(owner),
            Member {
                grants: MEMBER,
                expires: 1000,
                revoked: false,
            },
        );
    }
    for offset in 0..64 {
        let owner = 20 + offset / 8;
        let app = 80 + offset;
        let req = grant(&state, owner, app, 100, 200, &["PagesRead"]);
        perform(&mut state, &req, 100).unwrap();
    }
    let req = grant(&state, 28, 150, 100, 200, &["PagesRead"]);
    assert_eq!(
        perform(&mut state, &req, 100).err(),
        Some("ApplicationQuotaExceeded")
    );
    assert_eq!(state.applications.len(), 64);
    let mut state = initial();
    for (nonce, permissions, mode, policy) in [
        (
            10,
            vec!["ReviewDecide"],
            Some("Manual"),
            Some(hex::encode([1; 32])),
        ),
        (11, vec!["PagesRead"], Some("Automatic"), None),
        (
            12,
            vec!["ReviewDecide", "ReviewInspect"],
            Some("Unknown"),
            Some(hex::encode([1; 32])),
        ),
    ] {
        let proof = request(
            &state,
            nonce,
            nonce,
            100,
            Command::ApplicationConsent {
                owner_key: public(1),
                expires: 1000,
                namespaces: vec!["Board".into()],
                page_ids: None,
                permissions: permissions.into_iter().map(str::to_string).collect(),
                review_policy_digest: policy,
                review_mode: mode.map(str::to_string),
            },
        );
        let req = request(
            &state,
            1,
            nonce,
            100,
            Command::ApplicationGrantCreate {
                consent: proof.envelope,
            },
        );
        assert_eq!(
            perform(&mut state, &req, 100).err(),
            Some("InvalidApplicationScope")
        );
    }
    let req = grant(&state, 2, 13, 100, 10001, &["PagesRead"]);
    assert_eq!(perform(&mut state, &req, 100).err(), Some("InvalidExpiry"));
}

#[test]
fn signed_review_deadlines_are_required_for_apps_and_expire_before_publication() {
    let mut state = initial();
    let mut blobs = BTreeMap::new();
    let req = grant(&state, 1, 10, 100, 1000, &["ReviewDecide", "ReviewInspect"]);
    perform(&mut state, &req, 100).unwrap();
    let req = submit(&state, 2, 20, 1, "Board");
    page(&mut state, &mut blobs, &req, 100).unwrap();
    for (expires, now, code) in [
        (None, 100, "ApplicationReviewExpiryRequired"),
        (Some(100), 100, "InvalidReviewExpiry"),
        (Some(401), 100, "InvalidReviewExpiry"),
        (Some(120), 120, "InvalidReviewExpiry"),
    ] {
        let mut command = review(&state, 10, 21, 1).request.command;
        if let Command::PageReview { review_expires, .. } = &mut command {
            *review_expires = expires;
        }
        let req = request(&state, 10, 21, 100, command);
        assert_eq!(page(&mut state, &mut blobs, &req, now).err(), Some(code));
    }
    let mut command = review(&state, 1, 22, 1).request.command;
    if let Command::PageReview { review_expires, .. } = &mut command {
        *review_expires = Some(100);
    }
    let req = request(&state, 1, 22, 100, command);
    assert_eq!(
        page(&mut state, &mut blobs, &req, 100).err(),
        Some("InvalidReviewExpiry")
    );
    let req = review(&state, 10, 23, 1);
    page(&mut state, &mut blobs, &req, 100).unwrap();
    assert_eq!(
        page_authority::preflight(&state, &req, None, 400).err(),
        Some("InvalidReviewExpiry")
    );
}

#[test]
fn large_signed_grants_paginate_complete_replies_without_losing_proof_bytes() {
    let mut state = initial();
    for app in 10..14 {
        let proof = consent(&state, 2, app, 100, 1000, &["PagesRead"]);
        let mut payload = URL_SAFE_NO_PAD.decode(&proof.envelope.payload).unwrap();
        payload.resize(40000, b' ');
        let signing = SigningKey::from_bytes(&[app; 32]);
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&protocol::fixed_hex::<32>(&state.network).unwrap());
        signed.extend_from_slice(signing.verifying_key().as_bytes());
        signed.extend_from_slice(&payload);
        let envelope = Envelope {
            network: state.network.clone(),
            public_key: public(app),
            payload: URL_SAFE_NO_PAD.encode(&payload),
            signature: hex::encode(signing.sign(&signed).to_bytes()),
        };
        let proof =
            protocol::verify(&serde_json::to_vec(&envelope).unwrap(), &state.network, 100).unwrap();
        let req = request(
            &state,
            2,
            app,
            100,
            Command::ApplicationGrantCreate {
                consent: proof.envelope,
            },
        );
        let req = protocol::verify(
            &serde_json::to_vec(&req.envelope).unwrap(),
            &state.network,
            100,
        )
        .unwrap();
        perform(&mut state, &req, 100).unwrap();
    }
    assert!(serde_json::to_vec(&state).unwrap().len() < MAX_STATE);
    let expected: Vec<_> = state.applications.keys().cloned().collect();
    let mut seen = Vec::new();
    let mut after = None;
    let mut pages = 0;
    loop {
        let req = request(
            &state,
            2,
            30,
            100,
            Command::ApplicationGrantList {
                after: after.clone(),
            },
        );
        let reply = perform(&mut state, &req, 100).unwrap();
        assert!(serde_json::to_vec(&reply).unwrap().len() <= MAX_LIST_REPLY);
        let entries: Vec<ApplicationRecord> =
            serde_json::from_value(reply.result["entries"].clone()).unwrap();
        assert!(!entries.is_empty());
        for record in &entries {
            assert!(
                after
                    .as_ref()
                    .is_none_or(|cursor| record.application_key > *cursor)
            );
            assert_eq!(
                serde_json::to_value(&record.grant).unwrap(),
                serde_json::to_value(&state.applications[&record.application_key].grant).unwrap()
            );
            let outer = protocol::verify_archived(&record.grant, &state.network).unwrap();
            let Command::ApplicationGrantCreate { consent } = outer.request.command else {
                panic!("Wrong grant command")
            };
            let proof = protocol::verify_archived(&consent, &state.network).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(proof.envelope.payload)
                    .unwrap()
                    .len(),
                40000
            );
            seen.push(record.application_key.clone());
        }
        pages += 1;
        let next = reply.result["next"].as_str().map(str::to_string);
        if let Some(next) = &next {
            assert_eq!(next, &entries.last().unwrap().application_key);
        }
        after = next;
        if after.is_none() {
            break;
        }
        assert!(pages < 4);
    }
    assert_eq!(pages, 2);
    assert_eq!(seen, expected);
    let req = request(
        &state,
        2,
        31,
        100,
        Command::ApplicationGrantList {
            after: seen.last().cloned(),
        },
    );
    let empty = perform(&mut state, &req, 100).unwrap();
    assert_eq!(empty.result["entries"], json!([]));
    assert_eq!(empty.result["next"], Value::Null);
    assert!(serde_json::to_vec(&empty).unwrap().len() <= MAX_LIST_REPLY);
    let req = request(
        &state,
        3,
        32,
        100,
        Command::ApplicationGrantList { after: None },
    );
    assert_eq!(
        perform(&mut state, &req, 100).unwrap().result["entries"],
        json!([])
    );
}
