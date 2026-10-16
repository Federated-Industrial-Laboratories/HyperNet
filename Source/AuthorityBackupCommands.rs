// SPDX-License-Identifier: MIT
// Backup commands select exact consent and immutable content identities.
use super::*;
#[derive(Clone, Debug)]
pub enum Command {
    InspectConsent {
        profile: Profile,
    },
    Register {
        profile: Profile,
    },
    Destination {
        destination: Digest,
    },
    Destinations {
        after: Option<Digest>,
    },
    WithdrawDestination {
        destination: VersionRef,
    },
    Prepare {
        placement: VersionRef,
        destination: VersionRef,
    },
    Create {
        archive: Archive,
    },
    Get {
        archive: Digest,
    },
    List {
        after: Option<Digest>,
    },
    Restore {
        archive: VersionRef,
    },
    Withdraw {
        archive: VersionRef,
    },
}
impl Command {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.list(3)?;
        let name = f.first().context("empty backup command")?.text()?;
        Ok(match name {
            "BackupInspectConsent" => {
                v.array(2)?;
                Self::InspectConsent {
                    profile: Profile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "BackupRegister" => {
                v.array(2)?;
                Self::Register {
                    profile: Profile::parse(f[1].bytes()?, n, i)?,
                }
            }
            "BackupDestination" => {
                v.array(2)?;
                Self::Destination {
                    destination: id(&f[1])?,
                }
            }
            "BackupDestinations" => {
                v.array(2)?;
                Self::Destinations {
                    after: optional(&f[1])?,
                }
            }
            "BackupWithdrawDestination" => {
                v.array(2)?;
                Self::WithdrawDestination {
                    destination: required(&f[1], DESTINATION)?,
                }
            }
            "BackupPrepare" => {
                v.array(3)?;
                Self::Prepare {
                    placement: required(&f[1], 159)?,
                    destination: required(&f[2], DESTINATION)?,
                }
            }
            "BackupCreate" => {
                v.array(2)?;
                Self::Create {
                    archive: Archive::parse(f[1].bytes()?, n, i)?,
                }
            }
            "BackupGet" => {
                v.array(2)?;
                Self::Get {
                    archive: id(&f[1])?,
                }
            }
            "BackupList" => {
                v.array(2)?;
                Self::List {
                    after: optional(&f[1])?,
                }
            }
            "BackupRestore" => {
                v.array(2)?;
                Self::Restore {
                    archive: required(&f[1], ARCHIVE)?,
                }
            }
            "BackupWithdraw" => {
                v.array(2)?;
                Self::Withdraw {
                    archive: required(&f[1], ARCHIVE)?,
                }
            }
            _ => anyhow::bail!("unknown backup command"),
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::InspectConsent { .. } => "BackupInspectConsent",
            Self::Register { .. } => "BackupRegister",
            Self::Destination { .. } => "BackupDestination",
            Self::Destinations { .. } => "BackupDestinations",
            Self::WithdrawDestination { .. } => "BackupWithdrawDestination",
            Self::Prepare { .. } => "BackupPrepare",
            Self::Create { .. } => "BackupCreate",
            Self::Get { .. } => "BackupGet",
            Self::List { .. } => "BackupList",
            Self::Restore { .. } => "BackupRestore",
            Self::Withdraw { .. } => "BackupWithdraw",
        }
    }
    pub fn value(&self) -> V {
        let mut f = vec![V::Text(self.name().into())];
        match self {
            Self::Register { profile } | Self::InspectConsent { profile } => {
                f.push(b(&profile.envelope))
            }
            Self::Destination { destination } => f.push(b(destination)),
            Self::Destinations { after } | Self::List { after } => {
                f.push(after.as_ref().map_or(V::Null, |v| b(v)))
            }
            Self::WithdrawDestination { destination } => f.push(reference(destination)),
            Self::Prepare {
                placement,
                destination,
            } => f.extend([reference(placement), reference(destination)]),
            Self::Create { archive } => f.push(b(&archive.envelope)),
            Self::Get { archive } => f.push(b(archive)),
            Self::Restore { archive } | Self::Withdraw { archive } => f.push(reference(archive)),
        }
        a(f)
    }
    pub fn resource(&self) -> Digest {
        match self {
            Self::Register { profile } | Self::InspectConsent { profile } => profile.id,
            Self::Destination { destination } => *destination,
            Self::Destinations { .. } | Self::List { .. } => wire::digest(self.name().as_bytes()),
            Self::WithdrawDestination { destination } => destination.id,
            Self::Prepare { placement, .. } => placement.id,
            Self::Create { archive } => archive.id,
            Self::Get { archive } => *archive,
            Self::Restore { archive } | Self::Withdraw { archive } => archive.id,
        }
    }
    pub fn mutation(&self) -> bool {
        matches!(
            self,
            Self::Register { .. }
                | Self::WithdrawDestination { .. }
                | Self::Create { .. }
                | Self::Withdraw { .. }
        )
    }
    pub fn mutation_kind(&self) -> Option<u64> {
        match self {
            Self::Register { .. } | Self::WithdrawDestination { .. } => Some(DESTINATION),
            Self::Create { .. } => Some(ARCHIVE),
            Self::Withdraw { .. } => Some(TOMBSTONE),
            _ => None,
        }
    }
}
fn optional(v: &V) -> Result<Option<Digest>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}
