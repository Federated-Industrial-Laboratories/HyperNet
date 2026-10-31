// SPDX-License-Identifier: MIT
// Shared fixture in the including test module scope.
fn fixture() -> (local::Binding, ed25519_dalek::SigningKey, Ready, Request) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let binding = local::Binding {
        version: 1,
        id: [1; 32],
        network: [2; 32],
        incarnation: [3; 32],
        service: [4; 32],
        owner: key.verifying_key().to_bytes(),
        endpoint: key.verifying_key().to_bytes(),
        protocol: "test/1".into(),
    };
    let ready = Ready {
        challenge: Challenge {
            binding_digest: binding.digest().unwrap(),
            companion_instance: [5; 32],
            nonce: [6; 32],
            kernel_boot: "00112233-4455-6677-8899-aabbccddeeff".into(),
            control_generation: 1,
        },
        endpoint_instance: [7; 32],
        monotonic_offset_ns: 0,
        boottime_offset_ns: 0,
        capabilities: vec![control::CAPABILITY.into()],
        privacy: Privacy {
            transport_protection: control::TransportProtection::Tls13FinalService,
            endpoint_mode: 2,
            incoming_path: IncomingPath::PublicListener,
            attachment: None,
            physical_independence_verified: false,
            profile_currentness_asserted: false,
        },
    };
    let now = crate::authority_challenge::boot_time_ms().unwrap();
    let request = Request {
        binding_digest: binding.digest().unwrap(),
        companion_instance: [5; 32],
        endpoint_instance: [7; 32],
        control_generation: 1,
        local_connection_id: "incoming-1".into(),
        session: VersionRef {
            kind: 173,
            id: [8; 32],
            generation: 1,
            digest: [9; 32],
        },
        nonce: [10; 32],
        action_digest: [11; 32],
        caller_started_boot_ms: now,
        caller_deadline_boot_ms: now + 5000,
    };
    (binding, key, ready, request)
}
