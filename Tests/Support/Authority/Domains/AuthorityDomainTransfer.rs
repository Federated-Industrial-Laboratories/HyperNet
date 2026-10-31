// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Profile {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityTransferProfile".into()),
            b(&self.manifest.encode()?),
            b(&self.service),
            self.endpoint.as_ref().map_or(V::Null, |v| b(v)),
            b(&self.volume),
            V::Uint(self.state_bytes),
            V::Uint(self.maximum_payload),
            V::Uint(self.maximum_lifetime_ms),
        ]))
    }
}

impl Offer {
    #[cfg(test)]
    pub fn payload(&self) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("AuthorityTransferOffer".into()),
            b(&self.network),
            b(&self.incarnation),
            b(&self.id),
            b(&self.sender),
            b(&self.recipient),
            V::Text(self.encryption_key.clone()),
            V::Uint(self.payload_bytes),
            b(&self.payload_digest),
            V::Uint(self.file_bytes),
            V::Text(self.label.clone()),
            V::Uint(self.expires),
        ]))
    }
}
