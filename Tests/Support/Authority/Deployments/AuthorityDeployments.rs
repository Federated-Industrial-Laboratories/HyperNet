// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Offer {
    #[cfg(test)]
    pub fn possessions_value(&self) -> V {
        a(self.possessions.iter().map(|p| b(p)).collect())
    }

    #[cfg(test)]
    pub fn possession(
        manifest: &Manifest,
        class: u64,
        key: Key,
        nonce: Digest,
        validity: (u64, u64),
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityDeploymentPossession".into()),
            b(&manifest.network),
            b(&manifest.incarnation),
            b(&manifest.deployment),
            V::Uint(class),
            b(&key),
            b(&wire::digest(&manifest.desired()?)),
            b(&wire::digest(&manifest.unsigned_consent(0)?)),
            b(&nonce),
            a(vec![V::Uint(validity.0), V::Uint(validity.1)]),
        ]))
    }
}

impl Operation {
    #[cfg(test)]
    pub fn prepare(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
        retained_offer: Option<(&[u8], &[u8])>,
    ) -> Result<Decision> {
        self.evaluate(
            records,
            reservations,
            intent,
            at,
            replay,
            retained_offer,
            false,
        )
    }
}
