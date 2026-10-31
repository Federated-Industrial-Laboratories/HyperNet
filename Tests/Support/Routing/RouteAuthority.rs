// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
impl Renewal {
    pub(crate) fn fixture(voucher: VersionRef, target: Vec<u8>, total_expires: u64) -> Self {
        Self {
            voucher,
            target,
            relay: b"Exact relay envelope".to_vec(),
            total_expires,
        }
    }
}
