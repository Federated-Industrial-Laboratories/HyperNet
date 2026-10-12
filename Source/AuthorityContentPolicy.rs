// SPDX-License-Identifier: MIT
// The operator binds content capacity, opaque-storage consent and failure-domain claims to one volume.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentPolicy {
    pub metadata_bytes: u64,
    pub data_bytes: u64,
    pub staging_bytes: u64,
    pub quarantine_bytes: u64,
    pub maximum_objects: u64,
    pub opaque: bool,
    pub failure_domain: Digest,
    pub reviewers: Vec<Key>,
}
impl ContentPolicy {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(8)?;
        let p = Self {
            metadata_bytes: f[0].uint()?,
            data_bytes: f[1].uint()?,
            staging_bytes: f[2].uint()?,
            quarantine_bytes: f[3].uint()?,
            maximum_objects: f[4].uint()?,
            opaque: f[5].boolean()?,
            failure_domain: id(&f[6])?,
            reviewers: f[7].list(16)?.iter().map(key).collect::<Result<_>>()?,
        };
        ensure!(
            p.metadata_bytes >= 8192
                && p.metadata_bytes.is_multiple_of(2)
                && p.data_bytes > 0
                && p.staging_bytes > 0
                && p.staging_bytes <= p.data_bytes
                && p.quarantine_bytes <= p.data_bytes
                && (1..=MAXIMUM_RECORDS as u64).contains(&p.maximum_objects),
            "invalid content storage partitions"
        );
        ensure!(
            p.reviewers.windows(2).all(|w| w[0] < w[1]) && (!p.opaque || !p.reviewers.is_empty()),
            "opaque hosting requires exact trusted reviewers"
        );
        p.admission_bytes()?;
        Ok(p)
    }
    #[cfg(test)]
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(self.metadata_bytes),
            V::Uint(self.data_bytes),
            V::Uint(self.staging_bytes),
            V::Uint(self.quarantine_bytes),
            V::Uint(self.maximum_objects),
            V::Bool(self.opaque),
            b(&self.failure_domain),
            a(self.reviewers.iter().map(|r| b(r)).collect()),
        ])
    }
    pub fn admission_bytes(&self) -> Result<u64> {
        // Payload rounding and per-file filesystem overhead are reserved separately from logical bytes.
        self.maximum_objects
            .checked_mul(8192)
            .and_then(|n| n.checked_add(self.metadata_bytes))
            .and_then(|n| n.checked_add(self.data_bytes))
            .context("content storage admission overflow")
    }
}
