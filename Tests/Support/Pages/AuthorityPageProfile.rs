// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl HostProfile {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityPageHostProfile".into()),
            b(&self.manifest.encode()?),
            V::Uint(self.role),
            b(&self.service),
            b(&self.volume),
            a(self.namespaces.iter().map(|n| V::Text(n.clone())).collect()),
            V::Uint(self.state_bytes),
            V::Uint(self.maximum_asset_bytes),
            V::Uint(self.retention_ms),
            self.content.as_ref().map_or(V::Null, ContentPolicy::value),
        ]))
    }
}

impl ApplicationPolicy {
    #[cfg(test)]
    pub fn payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityPageApplicationPolicy".into()),
            b(&n),
            b(&i),
            b(&self.application),
            b(&self.owner),
            reference(&self.registration),
            reference(&self.grant),
            a(self.namespaces.iter().map(|v| V::Text(v.clone())).collect()),
            self.pages
                .as_ref()
                .map_or(V::Null, |pages| a(pages.iter().map(|v| b(v)).collect())),
            a(self
                .permissions
                .iter()
                .map(|v| V::Text(v.clone()))
                .collect()),
            self.review
                .as_ref()
                .map_or(V::Null, |(mode, policy)| a(vec![V::Uint(*mode), b(policy)])),
            V::Uint(self.expires_ms),
            self.previous.as_ref().map_or(V::Null, reference),
        ]))
    }
}
