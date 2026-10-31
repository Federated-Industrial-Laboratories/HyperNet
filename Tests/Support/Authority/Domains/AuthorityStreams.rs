// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn limits_value(l: Limits) -> V {
    a(vec![
        V::Uint(l.bytes),
        V::Uint(l.duration_ms),
        V::Uint(l.idle_ms),
    ])
}

impl Registration {
    #[cfg(test)]
    pub fn parse_offer(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        Self::parse_inner(bytes, n, i, false)
    }

    #[cfg(test)]
    pub fn payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ApplicationStreamService".into()),
            b(&n),
            b(&i),
            b(&self.id),
            reference(&self.route),
            b(&self.owner),
            b(&self.operator),
            V::Text(self.protocol.clone()),
            b(&self.binding),
            limits_value(self.limits),
            V::Uint(SLOTS),
            a(vec![V::Uint(self.validity.0), V::Uint(self.validity.1)]),
        ]))
    }
}

impl Proof {
    #[cfg(test)]
    pub fn payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("ApplicationStreamOpen".into()),
            b(&n),
            b(&i),
            reference(&self.service),
            b(&self.principal),
            reference(&self.grant),
            V::Text(self.protocol.clone()),
            V::Uint(self.slot),
            V::Uint(self.generation),
            b(&self.nonce),
            b(&self.challenge),
            b(&self.exporter),
            limits_value(self.limits),
            V::Uint(self.expires),
        ]))
    }
}
