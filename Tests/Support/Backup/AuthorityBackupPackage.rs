// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Package {
    #[cfg(test)]
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode_bounded(
            &a(vec![
                V::Uint(201),
                V::Uint(1),
                V::Text("BackupPackage".into()),
                b(&self.profile.envelope),
                b(&self.archive.envelope),
                b(&self.ciphertext),
            ]),
            PACKAGE_LIMIT,
        )
    }
}
