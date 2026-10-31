// SPDX-License-Identifier: MIT
// A cold package contains only exact consent, a signed manifest and encrypted content bytes.
use super::*;
pub const PACKAGE_LIMIT: usize = MAXIMUM_ARCHIVE + MAXIMUM_PROFILE + MAXIMUM_MANIFEST + 1024;
pub struct Package {
    pub profile: Profile,
    pub archive: Archive,
    pub ciphertext: Vec<u8>,
}
impl Package {
    pub fn parse(bytes: &[u8], n: Digest, i: Digest) -> Result<Self> {
        let v = wire::decode_bounded(bytes, PACKAGE_LIMIT)?;
        let f = v.array(6)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BackupPackage",
            "backup package tag differs"
        );
        let p = Self {
            profile: Profile::parse(f[3].bytes()?, n, i)?,
            archive: Archive::parse(f[4].bytes()?, n, i)?,
            ciphertext: f[5].bytes()?.to_vec(),
        };
        ensure!(
            p.archive.destination.id == p.profile.id
                && p.ciphertext.len() as u64 == p.archive.bytes
                && wire::digest(&p.ciphertext) == p.archive.digest
                && p.ciphertext.starts_with(b"age-encryption.org/v1\n"),
            "backup package differs from encrypted manifest"
        );
        Ok(p)
    }
}

#[cfg(test)]
include!("../../Tests/Support/Backup/AuthorityBackupPackage.rs");
