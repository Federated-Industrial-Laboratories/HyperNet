// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl PreparedRequest {
    #[cfg(test)]
    pub fn digest(&self) -> Digest {
        self.request.digest()
    }
}

impl Store {
    #[cfg(test)]
    pub fn initial_descriptor(&self) -> &TrustDescriptor {
        &self.initial_descriptor
    }

    #[cfg(test)]
    pub(crate) fn profile_directory(&self) -> &File {
        &self.directory
    }

    /// The lower bound is an independent credential start, or zero when none applies.
    /// The original live challenge already establishes causal issuance through BOOTTIME.
    #[cfg(test)]
    pub fn accept(
        &mut self,
        result: VerifiedResult,
        session: &mut Session,
        health: ClockHealth,
        not_before_ms: u64,
    ) -> Result<DurablePermit> {
        self.accept_with_clock(result, session, &mut || Ok(health), not_before_ms)
    }
}

impl DurablePermit {
    #[cfg(test)]
    pub fn perform<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        self.perform_with_clock(
            store,
            session,
            &mut || Ok(health),
            requested_effect,
            check_current_restrictions,
            effect,
        )
    }

    #[cfg(test)]
    pub fn perform_once<T>(
        self,
        store: &mut Store,
        session: &mut Session,
        health: ClockHealth,
        requested_effect: u64,
        check_current_restrictions: impl FnMut(&proof::Restrictions) -> Result<()>,
        effect: impl FnOnce(&OperationResult, &Store) -> Result<T>,
    ) -> Result<T> {
        self.perform_once_with_clock(
            store,
            session,
            &mut || Ok(health),
            requested_effect,
            check_current_restrictions,
            effect,
        )
    }
}
