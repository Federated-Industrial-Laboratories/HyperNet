// SPDX-License-Identifier: MIT
use super::*;
use ed25519_dalek::SigningKey;

fn key(seed: u8) -> Key {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn scope() -> Scope {
    Scope {
        network: [11; 32],
        incarnation: [12; 32],
        configuration: [13; 32],
        epoch: 0,
    }
}
fn parsed(value: &V) -> Result<Streams> {
    Streams::parse(scope().network, scope().incarnation, value)
}
fn admit(streams: &mut Streams, key: Key) -> Result<()> {
    streams.admit(scope().network, scope().incarnation, key)
}
fn request(key: Key, sequence: u64, acknowledged_through: u64) -> Request {
    Request {
        requester: key,
        generation: 1,
        generation_id: initial_id(scope().network, scope().incarnation, key).unwrap(),
        sequence,
        acknowledged_through,
        intent: wire::digest(&sequence.to_be_bytes()),
    }
}
fn result(bytes: usize, refusal: bool) -> Vec<u8> {
    if refusal && bytes == 0 {
        return capacity_refusal("AuthorityInspect");
    }
    wire::encode(&V::Array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text("AuthorityInspect".into()),
        V::Uint(u64::from(refusal)),
        V::Uint(if refusal { 2 } else { 0 }),
        V::Bytes(wire::encode(&V::Bytes(vec![17; bytes])).unwrap()),
    ]))
    .unwrap()
}
#[test]
fn repeated_acknowledgement_retires_receipts_but_never_the_sequence_floor() {
    let mut streams = Streams::default();
    let signer = key(1);
    admit(&mut streams, signer).unwrap();
    let initial_charge = streams.charged_bytes().unwrap();
    let response = result(30, false);
    let refusal = result(0, true);
    for sequence in 1..=1024 {
        let mut request = request(signer, sequence, sequence - 1);
        request.intent = wire::digest(&sequence.to_be_bytes());
        let recorded = streams.record(&request, &response, &refusal).unwrap();
        assert!(recorded.proposed_result_retained);
        assert!(
            matches!(streams.classify(&request).unwrap(), Classification::Replay(v) if v == response)
        );
        streams = parsed(&streams.value()).unwrap();
        assert_eq!(streams.entries.len(), 1);
    }
    assert!(matches!(
        streams.classify(&request(signer, 1, 0)).unwrap(),
        Classification::Retired
    ));
    admit(&mut streams, signer).unwrap();
    assert_eq!(
        streams.metadata(&signer).unwrap().unwrap().retired_through,
        1023
    );
    assert_eq!(streams.charged_bytes().unwrap(), initial_charge);
}
#[test]
fn equivocation_gaps_and_explicit_abandonment_are_distinct() {
    let mut streams = Streams::default();
    let signer = key(2);
    admit(&mut streams, signer).unwrap();
    let one = request(signer, 1, 0);
    streams
        .record(&one, &result(12, false), &result(0, true))
        .unwrap();
    let mut changed = request(signer, 1, 0);
    changed.intent = [91; 32];
    assert!(matches!(
        streams.classify(&changed).unwrap(),
        Classification::Conflict
    ));
    assert!(matches!(
        streams.classify(&request(signer, 3, 0)).unwrap(),
        Classification::Gap
    ));
    // An explicitly signed acknowledgement may abandon a request whose reply was lost.
    let next = request(signer, 3, 2);
    streams
        .record(&next, &result(8, false), &result(0, true))
        .unwrap();
    assert!(matches!(
        streams.classify(&one).unwrap(),
        Classification::Retired
    ));
    assert!(matches!(
        streams.classify(&request(signer, 2, 1)).unwrap(),
        Classification::Retired
    ));
    assert!(streams.classify(&request(signer, 3, 3)).is_err());
    assert!(matches!(
        streams.classify(&request(key(3), 1, 0)).unwrap(),
        Classification::Missing
    ));
}
#[test]
fn saturated_receipts_preserve_small_refusals_and_each_owners_retirement() {
    let mut streams = Streams::default();
    for seed in 0..=255 {
        admit(&mut streams, key(seed)).unwrap();
    }
    let mut additional = [0; 32];
    additional[0] = 1;
    assert!(
        admit(
            &mut streams,
            SigningKey::from_bytes(&additional)
                .verifying_key()
                .to_bytes()
        )
        .is_err()
    );
    let large = result(97000, false);
    let refusal = result(0, true);
    assert!(
        streams
            .record(&request(key(1), 1, 0), &large, &refusal)
            .unwrap()
            .proposed_result_retained
    );
    for seed in 3..=255 {
        if !streams
            .record(&request(key(seed), 1, 0), &large, &refusal)
            .unwrap()
            .proposed_result_retained
        {
            break;
        }
    }
    let denied = streams
        .record(&request(key(2), 1, 0), &large, &refusal)
        .unwrap();
    assert!(!denied.proposed_result_retained);
    assert_eq!(denied.result, refusal);
    assert!(
        matches!(streams.classify(&request(key(2), 1, 0)).unwrap(), Classification::Replay(v) if v == refusal)
    );
    streams
        .record(&request(key(1), 2, 1), &result(1, false), &refusal)
        .unwrap();
    // Freeing capacity cannot turn the same previously refused request into permission.
    assert!(
        matches!(streams.classify(&request(key(2), 1, 0)).unwrap(), Classification::Replay(v) if v == refusal)
    );
    assert!(
        streams
            .record(&request(key(2), 2, 1), &large, &refusal)
            .unwrap()
            .proposed_result_retained
    );
    parsed(&streams.value()).unwrap();
}
#[test]
fn malformed_state_and_oversized_fallback_cannot_publish_partial_retirement() {
    let mut streams = Streams::default();
    let signer = key(7);
    admit(&mut streams, signer).unwrap();
    streams
        .record(&request(signer, 1, 0), &result(8, false), &result(0, true))
        .unwrap();
    let before = wire::encode_state(&streams.value()).unwrap();
    assert!(
        streams
            .record(
                &request(signer, 2, 1),
                &result(8, false),
                &result(600, true)
            )
            .is_err()
    );
    assert_eq!(wire::encode_state(&streams.value()).unwrap(), before);
    let mut invalid = streams.value();
    if let V::Array(entries) = &mut invalid
        && let V::Array(fields) = &mut entries[0]
    {
        fields[3] = V::Uint(1);
    }
    assert!(parsed(&invalid).is_err());
    let metadata = streams
        .metadata(&signer)
        .unwrap()
        .unwrap()
        .completion
        .unwrap();
    assert_eq!(metadata.sequence, 1);
    assert_eq!(metadata.intent, request(signer, 1, 0).intent);
    assert_eq!(metadata.disposition, Disposition::Permit);
    assert_eq!(metadata.reason, 0);
    assert_eq!(metadata.result_digest, wire::digest(&result(8, false)));
    assert!(streams.metadata(&key(8)).unwrap().is_none());
}

#[test]
fn valid_large_result_uses_the_reserved_refusal_without_exceeding_wire_bounds() {
    let mut streams = Streams::default();
    let signer = key(9);
    admit(&mut streams, signer).unwrap();
    let operation = request(signer, 1, 0);
    let refusal = result(0, true);
    let recorded = streams
        .record(&operation, &result(262000, false), &refusal)
        .unwrap();
    assert!(!recorded.proposed_result_retained);
    assert_eq!(recorded.result, refusal);
    assert!(matches!(
        streams.classify(&operation).unwrap(),
        Classification::Replay(v) if v == refusal
    ));
}

fn capacity_refusal(action: &str) -> Vec<u8> {
    wire::encode(&V::Array(vec![
        V::Uint(24),
        V::Uint(1),
        V::Text(action.into()),
        V::Uint(1),
        V::Uint(2),
        V::Bytes(
            wire::encode(&V::Array(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text(action.into()),
                V::Array(vec![]),
            ]))
            .unwrap(),
        ),
    ]))
    .unwrap()
}
fn fence(streams: &Streams, requester: Key, serial: u8) -> FenceRequest {
    fence_in(streams, &scope(), requester, serial)
}
fn fence_in(streams: &Streams, scope: &Scope, requester: Key, serial: u8) -> FenceRequest {
    let state = streams.metadata(&requester).unwrap().unwrap();
    let expected_metadata_digest =
        wire::digest(&streams.metadata_bytes(scope, &requester).unwrap());
    let payload = wire::encode(&V::Array(vec![
        V::Uint(57),
        V::Uint(1),
        V::Bytes(scope.network.to_vec()),
        V::Bytes(scope.incarnation.to_vec()),
        V::Bytes(requester.to_vec()),
        V::Bytes([serial; 32].to_vec()),
        V::Uint(scope.epoch),
        V::Uint(0),
        V::Uint(state.generation),
        V::Bytes(state.generation_id.to_vec()),
        V::Bytes(expected_metadata_digest.to_vec()),
    ]))
    .unwrap();
    FenceRequest {
        requester,
        digest: wire::digest(&payload),
        expected_generation: state.generation,
        expected_generation_id: state.generation_id,
        expected_metadata_digest,
    }
}
fn current_request(streams: &Streams, requester: Key, sequence: u64, acknowledged: u64) -> Request {
    let m = streams.metadata(&requester).unwrap().unwrap();
    Request {
        generation: m.generation,
        generation_id: m.generation_id,
        ..request(requester, sequence, acknowledged)
    }
}
fn snapshot(streams: &Streams) -> Vec<u8> {
    wire::encode_state(&streams.value()).unwrap()
}

#[test]
fn initial_id_and_restored_generations_are_bound_to_network_incarnation_and_signer() {
    let mut streams = Streams::default();
    let signer = key(20);
    admit(&mut streams, signer).unwrap();
    let initial = initial_id(scope().network, scope().incarnation, signer).unwrap();
    assert_ne!(
        initial,
        initial_id([21; 32], scope().incarnation, signer).unwrap()
    );
    assert_ne!(
        initial,
        initial_id(scope().network, [21; 32], signer).unwrap()
    );
    assert_ne!(
        initial,
        initial_id(scope().network, scope().incarnation, key(21)).unwrap()
    );
    assert_eq!(
        streams.metadata(&signer).unwrap().unwrap().generation_id,
        initial
    );
    assert!(Streams::parse([22; 32], scope().incarnation, &streams.value()).is_err());
    let mut changed = streams.value();
    let V::Array(entries) = &mut changed else {
        unreachable!()
    };
    let V::Array(fields) = &mut entries[0] else {
        unreachable!()
    };
    fields[2] = V::Bytes([23; 32].to_vec());
    assert!(parsed(&changed).is_err());
    let first = fence(&streams, signer, 24);
    streams.fence(&scope(), &first, None).unwrap();
    assert_eq!(
        snapshot(&parsed(&streams.value()).unwrap()),
        snapshot(&streams)
    );
    assert!(Streams::parse(scope().network, [25; 32], &streams.value()).is_err());
    let mut epoch = scope();
    epoch.epoch = 10;
    epoch.configuration = [26; 32];
    let before = streams.metadata(&signer).unwrap().unwrap();
    streams.metadata_bytes(&epoch, &signer).unwrap();
    admit(&mut streams, signer).unwrap();
    assert_eq!(streams.metadata(&signer).unwrap().unwrap(), before);
    for field in [0, 2, 3, 5] {
        let mut changed = streams.value();
        let V::Array(entries) = &mut changed else {
            unreachable!()
        };
        let V::Array(entry) = &mut entries[0] else {
            unreachable!()
        };
        let V::Array(f) = &mut entry[4] else {
            unreachable!()
        };
        f[field] = match field {
            0 | 3 => V::Bytes([27; 32].to_vec()),
            2 => V::Uint(2),
            _ => V::Array(vec![]),
        };
        assert!(parsed(&changed).is_err());
    }
}

#[test]
fn absent_status_and_refused_fences_never_admit_a_stream() {
    let mut streams = Streams::default();
    let requester = key(21);
    let absent = streams.metadata_bytes(&scope(), &requester).unwrap();
    let value = wire::decode(&absent).unwrap();
    let f = value.array(10).unwrap();
    assert_eq!(f[0], V::Uint(56));
    assert_eq!(f[4], V::Bool(false));
    assert_eq!(&f[5..], &[V::Null, V::Null, V::Uint(0), V::Null, V::Null]);
    let missing_fence = FenceRequest {
        requester,
        digest: [28; 32],
        expected_generation: 1,
        expected_generation_id: initial_id(scope().network, scope().incarnation, requester)
            .unwrap(),
        expected_metadata_digest: wire::digest(&absent),
    };
    let before = snapshot(&streams);
    let denied = streams
        .fence(&scope(), &missing_fence, Some(FenceRefusal::Expired))
        .unwrap();
    assert_eq!(denied.outcome, FenceOutcome::AttemptRefused);
    assert_eq!(denied.code, 3);
    assert_eq!(denied.metadata, absent);
    assert_eq!(snapshot(&streams), before);
    assert!(matches!(
        streams.classify(&request(requester, 1, 0)).unwrap(),
        Classification::Missing
    ));
}

#[test]
fn fencing_closes_delayed_sequences_and_mutation_before_fence_invalidates_its_comparison() {
    let mut streams = Streams::default();
    let signer = key(22);
    admit(&mut streams, signer).unwrap();
    let stale_fence = fence(&streams, signer, 29);
    streams
        .record(&request(signer, 1, 0), &result(8, false), &result(0, true))
        .unwrap();
    let before = snapshot(&streams);
    let refused = streams.fence(&scope(), &stale_fence, None).unwrap();
    assert_eq!(
        (refused.outcome, refused.code),
        (FenceOutcome::AttemptRefused, 12)
    );
    assert_eq!(snapshot(&streams), before);
    let delayed = request(signer, 1001, 1000);
    let fresh_fence = fence(&streams, signer, 30);
    let applied = streams.fence(&scope(), &fresh_fence, None).unwrap();
    assert_eq!((applied.outcome, applied.code), (FenceOutcome::Applied, 0));
    for old in [request(signer, 1, 0), request(signer, 2, 1), delayed] {
        assert!(matches!(
            streams.classify(&old).unwrap(),
            Classification::GenerationConflict
        ));
        assert!(
            streams
                .record(&old, &result(2, false), &result(0, true))
                .is_err()
        );
    }
    let current = streams.metadata(&signer).unwrap().unwrap();
    assert_eq!(current.generation, 2);
    assert_eq!(current.generation_id, fresh_fence.digest);
    assert_eq!(current.retired_through, 0);
    assert!(current.completion.is_none());
    assert_eq!(
        current
            .last_fence
            .unwrap()
            .previous_completion
            .unwrap()
            .result_digest,
        wire::digest(&result(8, false))
    );
}

#[test]
fn exact_fence_retry_preserves_later_work_and_competing_or_superseded_fences_never_repeat() {
    let mut streams = Streams::default();
    let signer = key(23);
    admit(&mut streams, signer).unwrap();
    let first = fence(&streams, signer, 31);
    let competing = fence(&streams, signer, 32);
    streams.fence(&scope(), &first, None).unwrap();
    let ordinary = current_request(&streams, signer, 1, 0);
    streams
        .record(&ordinary, &result(14, false), &result(0, true))
        .unwrap();
    let before = snapshot(&streams);
    let current = streams.metadata_bytes(&scope(), &signer).unwrap();
    assert_ne!(wire::digest(&current), first.expected_metadata_digest);
    let replay = streams.fence(&scope(), &first, None).unwrap();
    assert_eq!(
        (replay.outcome, replay.code),
        (FenceOutcome::AlreadyApplied, 0)
    );
    assert_eq!(replay.metadata, current);
    assert_eq!(snapshot(&streams), before);
    let outer = OperationResult::parse(&replay.result().unwrap()).unwrap();
    assert_eq!(
        (outer.action.as_str(), outer.disposition, outer.code),
        (FENCE_ACTION, Disposition::Permit, 0)
    );
    let value = wire::decode(&outer.value).unwrap();
    let f = value.array(7).unwrap();
    assert_eq!(f[0], V::Uint(58));
    assert_eq!(f[2], scope().value());
    assert_eq!(f[3], V::Bytes(signer.to_vec()));
    assert_eq!(f[4], V::Bytes(first.digest.to_vec()));
    assert_eq!(f[5], V::Uint(1));
    assert_eq!(f[6].bytes().unwrap(), current);
    for refusal in [
        FenceRefusal::Expired,
        FenceRefusal::BelowPolicyFloor,
        FenceRefusal::WrongContext,
    ] {
        let denied = streams.fence(&scope(), &first, Some(refusal)).unwrap();
        assert_eq!(
            (denied.outcome, denied.code),
            (FenceOutcome::AttemptRefused, refusal as u64)
        );
        assert_eq!(snapshot(&streams), before);
    }
    let denied = streams.fence(&scope(), &competing, None).unwrap();
    assert_eq!(
        (denied.outcome, denied.code),
        (FenceOutcome::AttemptRefused, 28)
    );
    let denied = streams
        .fence(&scope(), &competing, Some(FenceRefusal::Expired))
        .unwrap();
    assert_eq!(
        (denied.outcome, denied.code),
        (FenceOutcome::AttemptRefused, 7)
    );
    assert_eq!(snapshot(&streams), before);
    let second = fence(&streams, signer, 33);
    streams.fence(&scope(), &second, None).unwrap();
    let before = snapshot(&streams);
    let denied = streams.fence(&scope(), &first, None).unwrap();
    assert_eq!(
        (denied.outcome, denied.code),
        (FenceOutcome::Superseded, 28)
    );
    assert_eq!(snapshot(&streams), before);
    let state = streams.metadata(&signer).unwrap().unwrap();
    let f = state.last_fence.unwrap();
    assert_eq!(f.previous_generation, 2);
    assert_eq!(f.previous_generation_id, first.digest);
    assert_eq!(f.previous_completion.unwrap().intent, ordinary.intent);
    let persisted = streams.value();
    let entry = persisted.list(64).unwrap()[0].array(6).unwrap();
    assert_eq!(entry[4].array(6).unwrap().len(), 6);
    assert_eq!(snapshot(&parsed(&persisted).unwrap()), before);
}

#[test]
fn completion_metadata_preserves_original_success_despite_current_disclosure_refusal() {
    let mut streams = Streams::default();
    let signer = key(24);
    admit(&mut streams, signer).unwrap();
    let operation = request(signer, 1, 0);
    let original = result(18, false);
    streams
        .record(&operation, &original, &result(0, true))
        .unwrap();
    let before = streams.metadata(&signer).unwrap().unwrap();
    let mut denied = wire::decode(&result(0, true)).unwrap();
    let V::Array(fields) = &mut denied else {
        unreachable!()
    };
    fields[4] = V::Uint(6);
    let denied = wire::encode(&denied).unwrap();
    assert!(
        streams
            .record(&operation, &denied, &result(0, true))
            .is_err()
    );
    assert_eq!(streams.metadata(&signer).unwrap().unwrap(), before);
    let completion = before.completion.unwrap();
    assert_eq!(
        (completion.disposition, completion.reason),
        (Disposition::Permit, 0)
    );
    assert_eq!(completion.result_digest, wire::digest(&original));
    assert_ne!(completion.result_digest, wire::digest(&denied));
}

#[test]
fn worst_case_fence_and_refusal_fit_reserved_slots_at_receipt_saturation() {
    let mut streams = Streams::default();
    for seed in 1..=64 {
        admit(&mut streams, key(seed)).unwrap();
    }
    let signer = key(1);
    let maximum = u64::MAX;
    let mut context = scope();
    context.epoch = maximum;
    let action = "A".repeat(64);
    let refusal = capacity_refusal(&action);
    assert!(refusal.len() <= 145);
    let old = LastFence {
        digest: [34; 32],
        expected_metadata_digest: [35; 32],
        previous_generation: maximum - 2,
        previous_generation_id: [36; 32],
        previous_retired_through: maximum - 1,
        previous_completion: Some(CompletionMetadata {
            sequence: maximum,
            intent: [37; 32],
            disposition: Disposition::Refuse,
            reason: 38,
            result_digest: [38; 32],
        }),
    };
    assert!(wire::encode(&old.value()).unwrap().len() <= 202);
    streams.entries.insert(
        signer,
        Stream {
            generation: maximum - 1,
            generation_id: old.digest,
            retired: maximum - 2,
            last_fence: Some(old),
            completion: None,
        },
    );
    for seed in 2..=64 {
        if !streams
            .record(
                &request(key(seed), 1, 0),
                &result(97000, false),
                &result(0, true),
            )
            .unwrap()
            .proposed_result_retained
        {
            break;
        }
    }
    let ordinary = current_request(&streams, signer, maximum, maximum - 1);
    let mut large = wire::decode(&result(97000, false)).unwrap();
    let V::Array(fields) = &mut large else {
        unreachable!()
    };
    fields[2] = V::Text(action);
    let recorded = streams
        .record(&ordinary, &wire::encode(&large).unwrap(), &refusal)
        .unwrap();
    assert!(!recorded.proposed_result_retained);
    assert_eq!(recorded.result, refusal);
    assert!(streams.charged_bytes().unwrap() <= MAX_BYTES);
    assert!(
        wire::encode(&entry(&signer, &streams.entries[&signer]))
            .unwrap()
            .len()
            <= 480
    );
    assert!(streams.metadata_bytes(&context, &signer).unwrap().len() <= 486);
    let operation = fence_in(&streams, &context, signer, 39);
    let applied = streams.fence(&context, &operation, None).unwrap();
    assert_eq!((applied.outcome, applied.code), (FenceOutcome::Applied, 0));
    assert!(
        wire::encode(&entry(&signer, &streams.entries[&signer]))
            .unwrap()
            .len()
            <= 282
    );
    assert!(applied.value.len() <= 674);
    assert_eq!(
        streams.metadata(&signer).unwrap().unwrap().generation,
        maximum
    );
    assert_eq!(
        snapshot(&parsed(&streams.value()).unwrap()),
        snapshot(&streams)
    );
    let before = snapshot(&streams);
    let again = streams.fence(&context, &operation, None).unwrap();
    assert_eq!(again.outcome, FenceOutcome::AlreadyApplied);
    let exhausted = fence_in(&streams, &context, signer, 40);
    let refused = streams.fence(&context, &exhausted, None).unwrap();
    assert_eq!(
        (refused.outcome, refused.code),
        (FenceOutcome::AttemptRefused, 2)
    );
    assert_eq!(snapshot(&streams), before);
}

#[test]
fn terminal_withdrawal_reserve_survives_ordinary_receipt_pressure() {
    let mut streams = Streams::default();
    // Representative members, applications and eight complete deployments plus one registrar.
    for seed in 1..=201 {
        admit(&mut streams, key(seed)).unwrap();
    }
    let operators = (194..=201).map(key).collect::<BTreeSet<_>>();
    streams.validate_reserve(&operators).unwrap();
    let large = result(97000, false);
    let refusal = result(0, true);
    let mut saturated = false;
    for seed in 1..=193 {
        if !streams
            .record_reserved(&request(key(seed), 1, 0), &large, &refusal, &operators)
            .unwrap()
            .proposed_result_retained
        {
            saturated = true;
            break;
        }
    }
    assert!(saturated);
    let terminal = result(
        crate::authority_capacity::WITHDRAWAL_RESULT_RESERVE - 512,
        false,
    );
    for operator in &operators {
        assert!(
            streams
                .record_reserved(&request(*operator, 1, 0), &terminal, &refusal, &operators)
                .unwrap()
                .proposed_result_retained
        );
    }
    streams.validate_reserve(&operators).unwrap();
    let encoded = wire::encode_state(&streams.value()).unwrap();
    assert!(encoded.len() > wire::MAXIMUM);
    let restored = parsed(&wire::decode_state(&encoded).unwrap()).unwrap();
    assert_eq!(restored.keys(), streams.keys());
    for operator in operators {
        assert!(
            matches!(restored.classify(&request(operator,1,0)).unwrap(),Classification::Replay(v) if v==terminal)
        );
    }
}
