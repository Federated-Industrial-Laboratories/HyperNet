// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Profile {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthoritySshProfile".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.deployment),
            b(&self.service),
            b(&self.operator),
            b(&self.native),
            b(&self.command_digest),
            b(&self.endpoint),
            V::Text(self.purpose.clone()),
            V::Uint(self.maximum_seconds),
            a(vec![V::Uint(self.validity.0), V::Uint(self.validity.1)]),
            reference(&self.deployment_profile),
            reference(&self.consent),
            b(&self.manifest.encode()?),
        ]))
    }
}
