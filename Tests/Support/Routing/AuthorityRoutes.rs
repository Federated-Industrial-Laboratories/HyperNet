// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
fn identity_value(i: &Identity) -> V {
    a(vec![
        b(&i.service),
        V::Text(i.server_name.clone()),
        b(&i.transport_key),
        b(&i.leaf_der),
        V::Text(i.certificate_authority_pem.clone()),
    ])
}

#[cfg(test)]
fn limits_value(l: Limits) -> V {
    a(vec![
        V::Uint(l.bytes),
        V::Uint(l.duration_ms),
        V::Uint(l.idle_ms),
    ])
}

impl RegisteredProfile {
    #[cfg(test)]
    pub fn payload(&self, network: Digest, incarnation: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityRouteProfile".into()),
            b(&network),
            b(&incarnation),
            b(&self.deployment),
            b(&self.service),
            b(&self.operator),
            reference(&self.deployment_profile),
            reference(&self.consent),
            b(&self.endpoint),
            identity_value(&self.identity),
            self.address.map_or(V::Null, |a| V::Text(a.to_string())),
            V::Text(self.domain.clone()),
            V::Uint(self.protocol),
            V::Uint(self.mode),
            self.relay.as_ref().map_or(V::Null, |r| b(r)),
            limits_value(self.limits),
            V::Uint(self.maximum_connections),
            V::Uint(u64::from(self.assurance == Assurance::Independent)),
            a(vec![V::Uint(self.validity.0), V::Uint(self.validity.1)]),
            b(&self.manifest.encode()?),
        ]))
    }
}
