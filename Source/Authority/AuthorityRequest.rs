// SPDX-License-Identifier: MIT
// Request variants bind ordinary sequences and finite own-stream control operations.
use super::{Digest, Key, VersionRef, id, key, label, record, validate_versions};
use crate::trust_wire as wire;
use anyhow::{Result, ensure};

#[derive(Clone, Debug)]
pub struct Intent {
    pub network: Digest,
    pub incarnation: Digest,
    pub generation: u64,
    pub generation_id: Digest,
    pub sequence: u64,
    pub acknowledged_through: u64,
    pub requester: Key,
    pub action: String,
    pub resource: Digest,
    pub revision: u64,
    pub profile_generation: u64,
    pub minimum_policy_epoch: u64,
    pub minimum_policy_height: u64,
    pub expected: Vec<VersionRef>,
    pub parameters: Vec<u8>,
    pub digest: Digest,
}
impl Intent {
    pub fn from_signed(bytes: &[u8]) -> Result<Self> {
        match SignedRequest::from_signed(bytes)? {
            SignedRequest::Intent(intent) => Ok(intent),
            _ => anyhow::bail!("ordinary authority intent required"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StreamStatus {
    pub network: Digest,
    pub incarnation: Digest,
    pub requester: Key,
    pub minimum_policy_epoch: u64,
    pub minimum_policy_height: u64,
    pub digest: Digest,
}
#[derive(Clone, Debug)]
pub struct StreamFence {
    pub network: Digest,
    pub incarnation: Digest,
    pub requester: Key,
    pub minimum_policy_epoch: u64,
    pub minimum_policy_height: u64,
    pub expected_generation: u64,
    pub expected_generation_id: Digest,
    pub expected_metadata_digest: Digest,
    pub digest: Digest,
}

#[derive(Clone, Debug)]
pub enum SignedRequest {
    Intent(Intent),
    StreamStatus(StreamStatus),
    StreamFence(StreamFence),
}
impl SignedRequest {
    pub fn from_signed(bytes: &[u8]) -> Result<Self> {
        let (payload, signatures) = wire::envelope(bytes, 1)?;
        ensure!(signatures.len() == 1, "one requester signature required");
        let value = wire::decode(&payload)?;
        let fields = value.list(17)?;
        let kind = fields
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty authority request"))?
            .uint()?;
        let digest = wire::digest(&payload);
        let request = match kind {
            20 => {
                let f = record(&value, 20, 17)?;
                let generation = f[4].uint()?;
                let sequence = f[6].uint()?;
                let acknowledged_through = f[7].uint()?;
                ensure!(
                    generation > 0 && sequence > 0 && acknowledged_through < sequence,
                    "invalid stream generation, sequence or acknowledgement"
                );
                let expected = f[15]
                    .list(64)?
                    .iter()
                    .map(VersionRef::parse)
                    .collect::<Result<Vec<_>>>()?;
                validate_versions(&expected, 64)?;
                let parameters = f[16].bytes()?.to_vec();
                wire::decode(&parameters)?;
                let action = label(&f[9])?;
                ensure!(
                    !matches!(
                        action.as_str(),
                        "AuthorityStreamStatus" | "AuthorityStreamFence"
                    ),
                    "stream controls require their own request kind"
                );
                Self::Intent(Intent {
                    network: id(&f[2])?,
                    incarnation: id(&f[3])?,
                    generation,
                    generation_id: id(&f[5])?,
                    sequence,
                    acknowledged_through,
                    requester: key(&f[8])?,
                    action,
                    resource: id(&f[10])?,
                    revision: f[11].uint()?,
                    profile_generation: f[12].uint()?,
                    minimum_policy_epoch: f[13].uint()?,
                    minimum_policy_height: f[14].uint()?,
                    expected,
                    parameters,
                    digest,
                })
            }
            55 => {
                let f = record(&value, 55, 8)?;
                id(&f[5])?;
                Self::StreamStatus(StreamStatus {
                    network: id(&f[2])?,
                    incarnation: id(&f[3])?,
                    requester: key(&f[4])?,
                    minimum_policy_epoch: f[6].uint()?,
                    minimum_policy_height: f[7].uint()?,
                    digest,
                })
            }
            57 => {
                let f = record(&value, 57, 11)?;
                let expected_generation = f[8].uint()?;
                ensure!(expected_generation > 0, "zero expected stream generation");
                id(&f[5])?;
                Self::StreamFence(StreamFence {
                    network: id(&f[2])?,
                    incarnation: id(&f[3])?,
                    requester: key(&f[4])?,
                    minimum_policy_epoch: f[6].uint()?,
                    minimum_policy_height: f[7].uint()?,
                    expected_generation,
                    expected_generation_id: id(&f[9])?,
                    expected_metadata_digest: id(&f[10])?,
                    digest,
                })
            }
            _ => anyhow::bail!("unsupported authority request kind"),
        };
        ensure!(
            request.requester() == signatures[0].0,
            "request signer differs from requester"
        );
        ensure!(
            request.network() != request.incarnation(),
            "network and incarnation must differ"
        );
        Ok(request)
    }
    pub fn ordinary(&self) -> Result<&Intent> {
        match self {
            Self::Intent(intent) => Ok(intent),
            _ => anyhow::bail!("ordinary authority intent required"),
        }
    }
    pub fn network(&self) -> Digest {
        match self {
            Self::Intent(v) => v.network,
            Self::StreamStatus(v) => v.network,
            Self::StreamFence(v) => v.network,
        }
    }
    pub fn incarnation(&self) -> Digest {
        match self {
            Self::Intent(v) => v.incarnation,
            Self::StreamStatus(v) => v.incarnation,
            Self::StreamFence(v) => v.incarnation,
        }
    }
    pub fn requester(&self) -> Key {
        match self {
            Self::Intent(v) => v.requester,
            Self::StreamStatus(v) => v.requester,
            Self::StreamFence(v) => v.requester,
        }
    }
    pub fn digest(&self) -> Digest {
        match self {
            Self::Intent(v) => v.digest,
            Self::StreamStatus(v) => v.digest,
            Self::StreamFence(v) => v.digest,
        }
    }
    pub fn minimum_policy_epoch(&self) -> u64 {
        match self {
            Self::Intent(v) => v.minimum_policy_epoch,
            Self::StreamStatus(v) => v.minimum_policy_epoch,
            Self::StreamFence(v) => v.minimum_policy_epoch,
        }
    }
    pub fn minimum_policy_height(&self) -> u64 {
        match self {
            Self::Intent(v) => v.minimum_policy_height,
            Self::StreamStatus(v) => v.minimum_policy_height,
            Self::StreamFence(v) => v.minimum_policy_height,
        }
    }
    pub fn action(&self) -> &str {
        match self {
            Self::Intent(v) => &v.action,
            Self::StreamStatus(_) => "AuthorityStreamStatus",
            Self::StreamFence(_) => "AuthorityStreamFence",
        }
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Intent(v) => v.resource,
            Self::StreamStatus(v) => v.requester,
            Self::StreamFence(v) => v.requester,
        }
    }
    pub fn revision(&self) -> u64 {
        match self {
            Self::Intent(v) => v.revision,
            Self::StreamStatus(_) => 0,
            Self::StreamFence(v) => v.expected_generation,
        }
    }
    pub fn profile_generation(&self) -> u64 {
        match self {
            Self::Intent(v) => v.profile_generation,
            Self::StreamStatus(_) | Self::StreamFence(_) => 0,
        }
    }
    pub fn expected(&self) -> &[VersionRef] {
        match self {
            Self::Intent(v) => &v.expected,
            Self::StreamStatus(_) | Self::StreamFence(_) => &[],
        }
    }
}

#[cfg(test)]
#[path = "AuthorityRequestTests.rs"]
mod tests;
