// SPDX-License-Identifier: MIT
// Shared fixture in the including test module scope.
fn fixture() -> (Binding, ed25519_dalek::SigningKey, Ready, Request) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let binding = Binding {
        version: 1,
        id: [1; 32],
        network: [2; 32],
        incarnation: [4; 32],
        service: [5; 32],
        owner: key.verifying_key().to_bytes(),
        endpoint: key.verifying_key().to_bytes(),
        protocol: "hrc/1".into(),
    };
    let ready = Ready {
        challenge: Challenge {
            binding_digest: binding.digest().unwrap(),
            companion_instance: [6; 32],
            nonce: [7; 32],
            kernel_boot: "00112233-4455-6677-8899-aabbccddeeff".into(),
            control_generation: 1,
        },
        endpoint_instance: [8; 32],
        monotonic_offset_ns: 0,
        boottime_offset_ns: 0,
        capabilities: vec![CAPABILITY.into()],
        privacy: Privacy {
            transport_protection: TransportProtection::Tls13FinalService,
            endpoint_mode: 2,
            incoming_path: IncomingPath::PublicListener,
            attachment: None,
            physical_independence_verified: false,
            profile_currentness_asserted: false,
        },
    };
    let request = Request {
        binding_digest: ready.challenge.binding_digest,
        companion_instance: ready.challenge.companion_instance,
        endpoint_instance: ready.endpoint_instance,
        control_generation: 1,
        local_connection_id: "connection-1".into(),
        session: VersionRef {
            kind: 173,
            id: [9; 32],
            generation: 1,
            digest: [10; 32],
        },
        nonce: [11; 32],
        action_digest: [12; 32],
        caller_started_boot_ms: 100,
        caller_deadline_boot_ms: 5100,
    };
    (binding, key, ready, request)
}
