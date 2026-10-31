// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Archive {
    #[cfg(test)]
    pub fn payload(&self, n: Digest, i: Digest) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("BackupArchive".into()),
            b(&n),
            b(&i),
            b(&self.id),
            b(&self.owner),
            reference(&self.destination),
            reference(&self.placement),
            a(self.assets.iter().map(reference).collect()),
            b(&self.digest),
            V::Uint(self.bytes),
            V::Uint(self.created_ms),
            V::Uint(self.expires_ms),
            V::Bool(self.opaque),
        ]))
    }
}
