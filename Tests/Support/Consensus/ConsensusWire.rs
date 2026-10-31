// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
thread_local! {
    static CERTIFICATE_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CERTIFICATE_SIGNATURE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Certificate {
    #[cfg(test)]
    pub(super) fn parse_count() -> usize {
        CERTIFICATE_PARSES.get()
    }

    #[cfg(test)]
    pub(super) fn signature_check_count() -> usize {
        CERTIFICATE_SIGNATURE_CHECKS.get()
    }
}
