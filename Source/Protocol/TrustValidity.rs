// SPDX-License-Identifier: MIT
//! Explicit revocable entitlement lifetime; connection proofs retain finite deadlines.
use crate::trust_wire::Value;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// The permanent variant has its own versioned wire and JSON representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum End {
    At(u64),
    UntilWithdrawn,
}
#[derive(Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum JsonEnd {
    At(u64),
    Permanent {
        #[serde(rename = "untilWithdrawn")]
        version: u8,
    },
}
impl Serialize for End {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::At(value) => JsonEnd::At(*value),
            Self::UntilWithdrawn => JsonEnd::Permanent { version: 1 },
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for End {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match JsonEnd::deserialize(deserializer)? {
            JsonEnd::At(value) => Ok(Self::At(value)),
            JsonEnd::Permanent { version: 1 } => Ok(Self::UntilWithdrawn),
            JsonEnd::Permanent { .. } => Err(serde::de::Error::custom(
                "Unsupported permanent validity version",
            )),
        }
    }
}
impl End {
    pub fn selected(expires: Option<u64>, until_withdrawn: bool) -> Result<Self> {
        match (expires, until_withdrawn) {
            (Some(end), false) => Ok(Self::At(end)),
            (None, true) => Ok(Self::UntilWithdrawn),
            _ => anyhow::bail!("Select one finite expiry or until-withdrawn lifetime"),
        }
    }
    pub fn parse(value: &Value) -> Result<Self> {
        match value {
            Value::Uint(value) => Ok(Self::At(*value)),
            Value::Array(values) if values.as_slice() == [Value::Uint(1)] => {
                Ok(Self::UntilWithdrawn)
            }
            _ => anyhow::bail!("Unsupported entitlement validity end"),
        }
    }
    pub fn value(self) -> Value {
        match self {
            Self::At(value) => Value::Uint(value),
            Self::UntilWithdrawn => Value::Array(vec![Value::Uint(1)]),
        }
    }
    /// Restrict an already finite proof. This never creates an infinite proof.
    pub fn bound(self, deadline: u64) -> u64 {
        match self {
            Self::At(value) => deadline.min(value),
            Self::UntilWithdrawn => deadline,
        }
    }
    /// Finite consent remaining time; None means no consent timer.
    pub fn remaining(self, now: u64) -> Result<Option<u64>> {
        match self {
            Self::At(end) => Ok(Some(
                end.checked_sub(now)
                    .filter(|v| *v > 0)
                    .ok_or_else(|| anyhow::anyhow!("Consent expired"))?,
            )),
            Self::UntilWithdrawn => Ok(None),
        }
    }
    pub fn finite(self) -> Result<u64> {
        match self {
            Self::At(value) => Ok(value),
            Self::UntilWithdrawn => anyhow::bail!("A finite proof deadline is required"),
        }
    }
    pub fn contains(self, instant: u64) -> bool {
        match self {
            Self::At(value) => instant < value,
            Self::UntilWithdrawn => true,
        }
    }
    pub fn scaled(self, scale: u64) -> Result<Self> {
        match self {
            Self::At(value) => Ok(Self::At(
                value
                    .checked_mul(scale)
                    .ok_or_else(|| anyhow::anyhow!("Validity overflow"))?,
            )),
            Self::UntilWithdrawn => Ok(self),
        }
    }
    pub fn divided(self, scale: u64) -> Result<Self> {
        match self {
            Self::At(value) if value.is_multiple_of(scale) => Ok(Self::At(value / scale)),
            Self::UntilWithdrawn => Ok(self),
            _ => anyhow::bail!("Validity unit differs"),
        }
    }
}
impl From<u64> for End {
    fn from(value: u64) -> Self {
        Self::At(value)
    }
}
impl PartialEq<u64> for End {
    fn eq(&self, other: &u64) -> bool {
        *self == Self::At(*other)
    }
}
impl PartialOrd<u64> for End {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.partial_cmp(&Self::At(*other))
    }
}
impl PartialEq<End> for u64 {
    fn eq(&self, other: &End) -> bool {
        End::At(*self) == *other
    }
}
impl PartialOrd<End> for u64 {
    fn partial_cmp(&self, other: &End) -> Option<Ordering> {
        End::At(*self).partial_cmp(other)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity(pub u64, pub End);
impl From<(u64, u64)> for Validity {
    fn from(value: (u64, u64)) -> Self {
        Self(value.0, End::At(value.1))
    }
}
impl Validity {
    pub fn parse(value: &Value) -> Result<Self> {
        let fields = value.array(2)?;
        let result = Self(fields[0].uint()?, End::parse(&fields[1])?);
        ensure!(result.0 < result.1, "Invalid entitlement validity");
        Ok(result)
    }
    pub fn value(self) -> Value {
        Value::Array(vec![Value::Uint(self.0), self.1.value()])
    }
    pub fn current(self, at: u64, uncertainty: u64) -> bool {
        at.checked_sub(uncertainty)
            .is_some_and(|lower| lower >= self.0)
            && at
                .checked_add(uncertainty)
                .is_some_and(|upper| self.1.contains(upper))
    }
    pub fn bounded_duration(self, maximum: u64) -> bool {
        match self.1 {
            End::At(end) => end > self.0 && end - self.0 <= maximum,
            End::UntilWithdrawn => true,
        }
    }
}

impl std::str::FromStr for End {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        if value == "until-withdrawn" {
            return Ok(Self::UntilWithdrawn);
        }
        let end: u64 = value.parse()?;
        ensure!(end.to_string() == value, "Noncanonical lifetime");
        Ok(Self::At(end))
    }
}
impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::At(value) => value.fmt(f),
            Self::UntilWithdrawn => f.write_str("until-withdrawn"),
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Protocol/TrustValidityTests.rs"]
mod tests;

pub fn features() -> serde_json::Value {
    serde_json::json!({"schema":"HyperNetProtocolFeatures/1","features":["UntilWithdrawn/1","PersistentActivation/2","RouteHandover/1","PersistentRootPolicy/2","DiscoveryPolicy/1","PrivateAuthorityRouting/1","ManagedAuthoritySession/1"]})
}
