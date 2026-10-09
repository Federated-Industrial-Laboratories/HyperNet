// SPDX-License-Identifier: MIT
//! A pure SPARK evaluator. Callers establish signature, clock and state freshness.
#[derive(Clone, Copy, Debug)]
pub struct PolicyInput {
    pub requested: u64,
    pub network: u64,
    pub user: u64,
    pub host: u64,
    pub application: u64,
    pub now: u64,
    pub expires: u64,
    pub current_epoch: u64,
    pub minimum_epoch: u64,
    pub host_active: bool,
}

unsafe extern "C" {
    fn HyperNetMediaChunk(total: u64, offset: u64, count: u64) -> std::ffi::c_uint;
    fn HyperNetEffectivePolicy(
        requested: u64,
        network: u64,
        user: u64,
        host: u64,
        application: u64,
        now: u64,
        expires: u64,
        current_epoch: u64,
        minimum_epoch: u64,
        host_active: std::ffi::c_uint,
    ) -> u64;
}

pub fn effective(input: PolicyInput) -> u64 {
    // The boundary has no pointers, allocation, callbacks or mutable state.
    // Unsigned_64 and C.unsigned match uint64_t and unsigned int respectively.
    unsafe {
        HyperNetEffectivePolicy(
            input.requested,
            input.network,
            input.user,
            input.host,
            input.application,
            input.now,
            input.expires,
            input.current_epoch,
            input.minimum_epoch,
            input.host_active.into(),
        )
    }
}

pub fn media_chunk(total: u64, offset: u64, count: u64) -> bool {
    unsafe { HyperNetMediaChunk(total, offset, count) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ffi_enforces_each_boundary() {
        let input = PolicyInput {
            requested: u64::MAX,
            network: u64::MAX,
            user: u64::MAX,
            host: u64::MAX,
            application: u64::MAX,
            now: 4,
            expires: 5,
            current_epoch: 9,
            minimum_epoch: 9,
            host_active: true,
        };
        assert_eq!(effective(input), u64::MAX);
        for bit in 0..64 {
            let mask = !(1u64 << bit);
            assert_eq!(
                effective(PolicyInput {
                    requested: mask,
                    ..input
                }),
                mask
            );
            assert_eq!(
                effective(PolicyInput {
                    network: mask,
                    ..input
                }),
                mask
            );
            assert_eq!(
                effective(PolicyInput {
                    user: mask,
                    ..input
                }),
                mask
            );
            assert_eq!(
                effective(PolicyInput {
                    host: mask,
                    ..input
                }),
                mask
            );
            assert_eq!(
                effective(PolicyInput {
                    application: mask,
                    ..input
                }),
                mask
            );
        }
        assert_eq!(effective(PolicyInput { now: 5, ..input }), 0);
        assert_eq!(
            effective(PolicyInput {
                now: u64::MAX,
                ..input
            }),
            0
        );
        assert_eq!(
            effective(PolicyInput {
                minimum_epoch: 10,
                ..input
            }),
            0
        );
        assert_eq!(
            effective(PolicyInput {
                host_active: false,
                ..input
            }),
            0
        );
    }
}
