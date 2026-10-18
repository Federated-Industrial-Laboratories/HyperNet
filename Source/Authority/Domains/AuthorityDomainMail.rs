// SPDX-License-Identifier: MIT
// Mailbox revisions and one-use encryption packages remain certified domain state.
use super::*;
#[path = "../../Mail/AuthorityMailObjects.rs"]
pub mod objects;
#[path = "../../Mail/AuthorityMailProfile.rs"]
mod profile;
pub use profile::{Profile, Service, validate_service};
#[path = "../../Mail/AuthorityMailCommands.rs"]
mod commands;
pub use commands::{Command, Effect};
#[path = "../../Mail/AuthorityMailEvaluation.rs"]
mod evaluation;
pub use evaluation::{disk_header_bytes, evaluate, expected_recipient, reservation_bytes};
#[path = "../../Mail/AuthorityMailRequest.rs"]
mod request;
pub use request::Request;
#[path = "../../Mail/AuthorityMailReceipt.rs"]
mod receipt;
pub use receipt::{RECEIPT_LIMIT, Receipt};
// Two mailboxes, eight packages, twelve current or retained stores and one claim.
pub const MAXIMUM_CONTEXT_RECORDS: usize = 23;
pub const MAXIMUM_PAYLOAD: u64 = 128 * 1024;
pub const MAXIMUM_LIFETIME_MS: u64 = 7 * 24 * 3600 * 1000;
pub const BANK_HEADER: u64 = 64;
#[derive(Clone, Debug)]
pub struct Mailbox {
    pub publication: objects::Publication,
    pub manager: Key,
    pub grant: VersionRef,
    pub private: bool,
    pub creation: Digest,
}
impl Mailbox {
    pub fn parse(v: &V, n: Digest) -> Result<Self> {
        let f = v.array(5)?;
        let out = Self {
            publication: objects::Publication::parse(f[0].bytes()?, n)?,
            manager: key(&f[1])?,
            grant: version(&f[2])?,
            private: f[3].boolean()?,
            creation: id(&f[4])?,
        };
        ensure!(
            out.grant.kind == 102 && out.manager != out.publication.owner()?,
            "invalid mailbox owner or manager grant"
        );
        // A private mailbox has one explicitly selected opaque store. No network default expands placement.
        ensure!(
            !out.private
                || out.publication.manifest.deleted
                || (out.publication.manifest.storage_hosts.len() == 1
                    && out.publication.manifest.required_copies == 1),
            "private mailbox requires exactly one selected store"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.publication.bytes),
            b(&self.manager),
            reference(&self.grant),
            V::Bool(self.private),
            b(&self.creation),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Inventory {
    pub mailbox: VersionRef,
    pub package: objects::Package,
    pub creation: Digest,
}
impl Inventory {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(3)?;
        let out = Self {
            mailbox: version(&f[0])?,
            package: objects::Package::parse(f[1].bytes()?)?,
            creation: id(&f[2])?,
        };
        ensure!(
            out.mailbox.kind == 137,
            "mail package lacks its exact mailbox"
        );
        Ok(out)
    }
    pub fn value(&self) -> Result<V> {
        Ok(a(vec![
            reference(&self.mailbox),
            b(&serde_json::to_vec(&self.package)?),
            b(&self.creation),
        ]))
    }
}
#[derive(Clone, Debug)]
pub struct Claim {
    pub sender: VersionRef,
    pub recipient: VersionRef,
    pub device: Key,
    pub packages: Vec<VersionRef>,
    pub expires: u64,
    pub creation: Digest,
    pub payload_digest: Option<Digest>,
    pub payload_bytes: u64,
    pub binding: Option<Digest>,
    pub placement: Vec<VersionRef>,
    pub created_ms: u64,
}
impl Claim {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(11)?;
        let out = Self {
            sender: version(&f[0])?,
            recipient: version(&f[1])?,
            device: key(&f[2])?,
            packages: f[3].list(8)?.iter().map(version).collect::<Result<_>>()?,
            expires: f[4].uint()?,
            creation: id(&f[5])?,
            payload_digest: if f[6] == V::Null {
                None
            } else {
                Some(id(&f[6])?)
            },
            payload_bytes: f[7].uint()?,
            binding: if f[8] == V::Null {
                None
            } else {
                Some(id(&f[8])?)
            },
            placement: f[9].list(4)?.iter().map(version).collect::<Result<_>>()?,
            created_ms: f[10].uint()?,
        };
        ensure!(
            out.sender.kind == 137
                && out.recipient.kind == 137
                && !out.packages.is_empty()
                && out.packages.iter().all(|p| p.kind == 138)
                && out.expires > out.created_ms,
            "invalid mail claim"
        );
        ensure!(
            match (out.payload_digest, out.binding) {
                (Some(_), Some(_)) => (1..=MAXIMUM_PAYLOAD).contains(&out.payload_bytes),
                (None, None) => out.payload_bytes == 0,
                _ => false,
            },
            "mail claim payload binding differs"
        );
        validate_versions(&out.packages, 8)?;
        validate_versions(&out.placement, 4)?;
        ensure!(
            !out.placement.is_empty() && out.placement.iter().all(|r| r.kind == 136),
            "mail claim placement differs"
        );
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.sender),
            reference(&self.recipient),
            b(&self.device),
            a(self.packages.iter().map(reference).collect()),
            V::Uint(self.expires),
            b(&self.creation),
            self.payload_digest.as_ref().map_or(V::Null, |d| b(d)),
            V::Uint(self.payload_bytes),
            self.binding.as_ref().map_or(V::Null, |d| b(d)),
            a(self.placement.iter().map(reference).collect()),
            V::Uint(self.created_ms),
        ])
    }
}
pub fn validate_record(
    kind: u64,
    v: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    match kind {
        136 => validate_service(v, n, i, lookup, generation),
        137 => {
            let m = Mailbox::parse(v, n)?;
            ensure!(
                m.publication.id()? == lookup && m.publication.manifest.generation == generation,
                "mailbox revision differs"
            );
            Ok(())
        }
        138 => {
            let p = Inventory::parse(v)?;
            ensure!(
                generation == 1 && p.package.id(n, i, p.mailbox.id)? == lookup,
                "mail inventory identity differs"
            );
            Ok(())
        }
        139 => {
            let c = Claim::parse(v)?;
            ensure!(
                generation == 1 + u64::from(c.binding.is_some()),
                "mail claim binding generation differs"
            );
            Ok(())
        }
        _ => anyhow::bail!("invalid mail record kind"),
    }
}
pub fn reserve(state: &mut State, m: &Mailbox) -> Result<()> {
    state.reserve(2, m.publication.owner()?, m.manager)?;
    for d in &m.publication.manifest.devices {
        state.reserve(3, objects::native(&d.request_key)?, m.manager)?;
        state.reserve(4, objects::native(&d.mls_signature_key)?, m.manager)?;
    }
    Ok(())
}
pub fn validate_state(state: &State) -> Result<()> {
    let mut used = std::collections::BTreeSet::new();
    for r in state.records.values() {
        match r.reference.kind {
            137 => {
                let m = Mailbox::parse(&r.payload, state.network)?;
                let mut expected = vec![(2, m.publication.owner()?)];
                for d in &m.publication.manifest.devices {
                    expected.push((3, objects::native(&d.request_key)?));
                    expected.push((4, objects::native(&d.mls_signature_key)?));
                }
                for (class, key) in expected {
                    ensure!(
                        state.keys.get(&key) == Some(&(class, m.manager)),
                        "mail identity reservation missing or substituted"
                    );
                }
                for host in &m.publication.manifest.storage_hosts {
                    state.record(136, objects::native(host)?)?;
                }
            }
            138 => {
                let p = Inventory::parse(&r.payload)?;
                let m = state.record(137, p.mailbox.id)?;
                ensure!(
                    m.reference.generation >= p.mailbox.generation
                        && (m.reference.generation != p.mailbox.generation
                            || m.reference == p.mailbox),
                    "mail package mailbox revision conflicts"
                );
            }
            139 => {
                let c = Claim::parse(&r.payload)?;
                for h in &c.placement {
                    let r = state.record(136, h.id)?;
                    ensure!(
                        r.reference.generation >= h.generation
                            && (r.reference.generation != h.generation || r.reference == *h),
                        "claimed mail store revision conflicts"
                    );
                }
                for p in &c.packages {
                    ensure!(
                        state.record(138, p.id)?.reference == *p && used.insert(p.id),
                        "mail package is missing or claimed more than once"
                    );
                }
                for m in [&c.sender, &c.recipient] {
                    let r = state.record(137, m.id)?;
                    ensure!(
                        r.reference.generation >= m.generation
                            && (r.reference.generation != m.generation || r.reference == *m),
                        "mail claim mailbox revision conflicts"
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Mail/AuthorityMailTests.rs"]
pub(crate) mod tests;
