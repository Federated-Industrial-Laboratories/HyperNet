// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn check_minima(
    policy: &[u8],
    recovery: &[u8],
    accepted_policy: &[u8],
    accepted_recovery: &[u8],
    n: Digest,
    i: Digest,
) -> Result<()> {
    let current = wire::decode(policy)?;
    let current = current.array(17)?;
    let prior = wire::decode(accepted_policy)?;
    let prior = prior.array(17)?;
    let current_policy = record_reference(policy, n, i, 100)?;
    let accepted_policy = record_reference(accepted_policy, n, i, 100)?;
    ensure!(
        current_policy.generation >= accepted_policy.generation
            && (current_policy.generation != accepted_policy.generation
                || current_policy.digest == accepted_policy.digest),
        "TrustChanged: current policy is below or conflicts with retained acceptance"
    );
    let new = Custody::parse(recovery, n, i)?;
    let old = Custody::parse(accepted_recovery, n, i)?;
    ensure!(
        new.reference.generation >= old.reference.generation
            && (new.reference.generation != old.reference.generation
                || new.reference.digest == old.reference.digest),
        "TrustChanged: recovery policy is below or conflicts with retained acceptance"
    );
    ensure!(
        current[8].uint()? >= prior[8].uint()?
            && current[9]
                .list(16)?
                .iter()
                .all(|v| prior[9].list(16).is_ok_and(|p| p.contains(v)))
            && prior[10]
                .list(2)?
                .iter()
                .all(|v| current[10].list(2).is_ok_and(|p| p.contains(v)))
            && !new.weaker_than(&old),
        "TrustChanged: current policy requires explicit acceptance; client minima remain mandatory"
    );
    Ok(())
}

impl Operation {
    #[cfg(test)]
    pub fn parameters(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityPolicyApply".into()),
            b(&self.grant),
            b(&self.previous_policy),
            b(&self.previous_recovery),
            b(&self.policy),
            b(&self.recovery),
            self.old_authorisation.as_ref().map_or(V::Null, |v| b(v)),
            self.new_acceptance.as_ref().map_or(V::Null, |v| b(v)),
            self.snapshot.value.clone(),
        ]))
    }

    #[cfg(test)]
    pub fn validate_unsigned(&self, n: Digest, i: Digest) -> Result<()> {
        self.validate_inner(n, i, false)
    }
}
