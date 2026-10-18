// SPDX-License-Identifier: MIT
// Foreign provenance is network-qualified and never creates local membership.
use super::*;
use crate::{
    authority_epoch::archive,
    authority_history::ValidatedCheckpoint,
    authority_proof::{Prefix, TrustDescriptor},
    trust_bootstrap,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkIdentity {
    pub network: Digest,
    pub incarnation: Digest,
    pub file_digest: Digest,
    pub fingerprint: Digest,
}
impl NetworkIdentity {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(4)?;
        let s = Self {
            network: id(&f[0])?,
            incarnation: id(&f[1])?,
            file_digest: id(&f[2])?,
            fingerprint: id(&f[3])?,
        };
        ensure!(
            s.network != s.incarnation,
            "federation network equals incarnation"
        );
        Ok(s)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.network),
            b(&self.incarnation),
            b(&self.file_digest),
            b(&self.fingerprint),
        ])
    }
    pub fn verified(v: &trust_bootstrap::Verified) -> Self {
        let s = v.descriptor().scope();
        Self {
            network: s.network,
            incarnation: s.incarnation,
            file_digest: v.file_digest(),
            fingerprint: v.fingerprint(),
        }
    }
    pub fn matches(&self, n: Digest, i: Digest) -> bool {
        self.network == n && self.incarnation == i
    }
}
#[derive(Clone, Debug)]
pub struct ForeignTrust {
    pub bootstrap: Vec<u8>,
    pub identity: NetworkIdentity,
    pub approver: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl ForeignTrust {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(5)?;
        let out = Self {
            bootstrap: f[0].bytes()?.to_vec(),
            identity: NetworkIdentity::parse(&f[1])?,
            approver: key(&f[2])?,
            grant: exact_ref(&f[3], 102)?,
            withdrawn: f[4].boolean()?,
        };
        let accepted = out.verified()?;
        ensure!(
            accepted.fully_accepted()
                && out.identity == NetworkIdentity::verified(&accepted)
                && !out.identity.matches(n, i),
            "foreign bootstrap or independently accepted pins differ"
        );
        Ok(out)
    }
    pub fn verified(&self) -> Result<trust_bootstrap::Verified> {
        trust_bootstrap::inspect(&self.bootstrap, true)
    }
    pub fn identity(&self) -> Result<Digest> {
        identity(
            "ForeignTrust",
            vec![b(&self.identity.network), b(&self.identity.incarnation)],
        )
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.bootstrap),
            self.identity.value(),
            b(&self.approver),
            reference(&self.grant),
            V::Bool(self.withdrawn),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Treaty {
    pub id: Digest,
    pub source: NetworkIdentity,
    pub destination: NetworkIdentity,
    pub source_bridge: Key,
    pub destination_bridge: Key,
    pub source_namespace: String,
    pub destination_namespace: String,
    pub media_profiles: Vec<String>,
    pub source_hosts: Vec<Key>,
    pub destination_hosts: Vec<Key>,
    pub media_bytes: u64,
    pub copies: u64,
    pub expires_ms: u64,
}
impl Treaty {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(13)?;
        ensure!(
            f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == "FederationTreaty"
                && f[10].text()? == markup::PROFILE,
            "federation treaty format differs"
        );
        let keys = |v: &V| -> Result<Vec<Key>> {
            let k = v.list(3)?.iter().map(key).collect::<Result<Vec<_>>>()?;
            ensure!(
                k.windows(2).all(|p| p[0] < p[1]),
                "federation hosts repeat or reorder"
            );
            Ok(k)
        };
        let media = f[11].array(5)?;
        let out = Self {
            id: id(&f[3])?,
            source: NetworkIdentity::parse(&f[4])?,
            destination: NetworkIdentity::parse(&f[5])?,
            source_bridge: key(&f[6])?,
            destination_bridge: key(&f[7])?,
            source_namespace: namespace(&f[8])?,
            destination_namespace: namespace(&f[9])?,
            media_profiles: media[0]
                .list(2)?
                .iter()
                .map(|p| Ok(p.text()?.into()))
                .collect::<Result<_>>()?,
            source_hosts: keys(&media[1])?,
            destination_hosts: keys(&media[2])?,
            media_bytes: media[3].uint()?,
            copies: media[4].uint()?,
            expires_ms: f[12].uint()?,
        };
        ensure!(
            out.source.network != out.destination.network
                && out.source_bridge != out.destination_bridge
                && out.expires_ms > 0
                && out.media_profiles.windows(2).all(|p| p[0] < p[1])
                && out
                    .media_profiles
                    .iter()
                    .all(|p| matches!(p.as_str(), "HyperNetRaster/1" | "HyperNetVector/1")),
            "federation treaty identity or media profile differs"
        );
        if out.media_profiles.is_empty() {
            ensure!(
                out.source_hosts.is_empty()
                    && out.destination_hosts.is_empty()
                    && out.media_bytes == 0
                    && out.copies == 0,
                "disabled federation media has placement"
            )
        } else {
            ensure!(
                !out.source_hosts.is_empty()
                    && !out.destination_hosts.is_empty()
                    && out.media_bytes > 0
                    && out.media_bytes <= markup::media::MAX_PAGE_BYTES
                    && out.copies > 0
                    && out.copies <= out.destination_hosts.len() as u64,
                "federation media bounds differ"
            )
        };
        Ok(out)
    }
    pub fn value(&self) -> V {
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("FederationTreaty".into()),
            b(&self.id),
            self.source.value(),
            self.destination.value(),
            b(&self.source_bridge),
            b(&self.destination_bridge),
            V::Text(self.source_namespace.clone()),
            V::Text(self.destination_namespace.clone()),
            V::Text(markup::PROFILE.into()),
            a(vec![
                a(self
                    .media_profiles
                    .iter()
                    .map(|s| V::Text(s.clone()))
                    .collect()),
                a(self.source_hosts.iter().map(|k| b(k)).collect()),
                a(self.destination_hosts.iter().map(|k| b(k)).collect()),
                V::Uint(self.media_bytes),
                V::Uint(self.copies),
            ]),
            V::Uint(self.expires_ms),
        ])
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(wire::digest(&wire::encode(&self.value())?))
    }
    pub fn source_side(&self, n: Digest, i: Digest) -> Result<bool> {
        if self.source.matches(n, i) {
            Ok(true)
        } else {
            ensure!(
                self.destination.matches(n, i),
                "local network is not a treaty party"
            );
            Ok(false)
        }
    }
    pub fn local(&self, source: bool) -> &NetworkIdentity {
        if source {
            &self.source
        } else {
            &self.destination
        }
    }
    pub fn foreign(&self, source: bool) -> &NetworkIdentity {
        self.local(!source)
    }
    pub fn bridge(&self, source: bool) -> Key {
        if source {
            self.source_bridge
        } else {
            self.destination_bridge
        }
    }
}
#[derive(Clone, Debug)]
pub struct Agreement {
    pub treaty: Treaty,
    pub foreign: VersionRef,
    pub approver: Key,
    pub grant: VersionRef,
    pub withdrawn: bool,
}
impl Agreement {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(5)?;
        let s = Self {
            treaty: Treaty::parse(&f[0])?,
            foreign: exact_ref(&f[1], 150)?,
            approver: key(&f[2])?,
            grant: exact_ref(&f[3], 102)?,
            withdrawn: f[4].boolean()?,
        };
        s.treaty.source_side(n, i)?;
        Ok(s)
    }
    pub fn value(&self) -> V {
        a(vec![
            self.treaty.value(),
            reference(&self.foreign),
            b(&self.approver),
            reference(&self.grant),
            V::Bool(self.withdrawn),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Share {
    pub agreement: Digest,
    pub page: [u8; 16],
    pub publication: VersionRef,
    pub revision: VersionRef,
    pub author: Key,
    pub grant: VersionRef,
    pub statement: Vec<u8>,
    pub allowed: bool,
    pub withdrawal_generation: u64,
}
impl Share {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(9)?;
        let out = Self {
            agreement: id(&f[0])?,
            page: f[1].fixed()?,
            publication: exact_ref(&f[2], 142)?,
            revision: exact_ref(&f[3], 141)?,
            author: key(&f[4])?,
            grant: exact_ref(&f[5], 102)?,
            statement: f[6].bytes()?.to_vec(),
            allowed: f[7].boolean()?,
            withdrawal_generation: f[8].uint()?,
        };
        let intent = Intent::from_signed(&out.statement)?;
        ensure!(
            out.publication.id == out.revision.id
                && intent.network == n
                && intent.incarnation == i
                && intent.requester == out.author
                && intent.action == "FederationShareStatement"
                && intent.resource == out.identity()?
                && intent.expected.is_empty()
                && intent.profile_generation == 0
                && intent.parameters == wire::encode(&out.statement_value())?,
            "author share statement differs"
        );
        Ok(out)
    }
    pub fn identity(&self) -> Result<Digest> {
        share_id(self.agreement, self.page)
    }
    pub fn statement_value(&self) -> V {
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("FederationShareStatement".into()),
            b(&self.agreement),
            b(&self.page),
            reference(&self.publication),
            reference(&self.revision),
            reference(&self.grant),
        ])
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.agreement),
            b(&self.page),
            reference(&self.publication),
            reference(&self.revision),
            b(&self.author),
            reference(&self.grant),
            b(&self.statement),
            V::Bool(self.allowed),
            V::Uint(self.withdrawal_generation),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct ForeignPage {
    pub agreement: Digest,
    pub source: NetworkIdentity,
    pub raw_page: [u8; 16],
    pub observed: VersionRef,
    pub source_share: VersionRef,
    pub pending: Option<VersionRef>,
    pub published: Option<VersionRef>,
    pub withdrawn: bool,
}
impl ForeignPage {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(8)?;
        Ok(Self {
            agreement: id(&f[0])?,
            source: NetworkIdentity::parse(&f[1])?,
            raw_page: f[2].fixed()?,
            observed: exact_ref(&f[3], 141)?,
            source_share: exact_ref(&f[4], 153)?,
            pending: optional_ref(&f[5], 155)?,
            published: optional_ref(&f[6], 156)?,
            withdrawn: f[7].boolean()?,
        })
    }
    pub fn identity(&self) -> Result<Digest> {
        qualified_page(self.agreement, &self.source, self.raw_page)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.agreement),
            self.source.value(),
            b(&self.raw_page),
            reference(&self.observed),
            reference(&self.source_share),
            self.pending.as_ref().map_or(V::Null, reference),
            self.published.as_ref().map_or(V::Null, reference),
            V::Bool(self.withdrawn),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct ForeignRevision {
    pub page: Digest,
    pub agreement: Digest,
    pub source: NetworkIdentity,
    pub native: VersionRef,
    pub share: VersionRef,
    pub bundle: Reference,
    pub imported_at_ms: u64,
    pub evidence: Digest,
    pub metadata: page::Revision,
}
impl ForeignRevision {
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(9)?;
        let s = Self {
            page: id(&f[0])?,
            agreement: id(&f[1])?,
            source: NetworkIdentity::parse(&f[2])?,
            native: exact_ref(&f[3], 141)?,
            share: exact_ref(&f[4], 153)?,
            bundle: Reference::parse(&f[5])?,
            imported_at_ms: f[6].uint()?,
            evidence: id(&f[7])?,
            metadata: {
                let origin = NetworkIdentity::parse(&f[2])?;
                page::Revision::parse(&f[8], origin.network, origin.incarnation)?
            },
        };
        ensure!(
            s.bundle.class() == crate::authority_objects::Class::PageBundle && s.imported_at_ms > 0,
            "foreign revision bundle, assets or time differs"
        );
        ensure!(
            s.native.id == s.metadata.identity()?
                && s.page == qualified_page(s.agreement, &s.source, s.metadata.author.raw_page)?
                && s.share.id == share_id(s.agreement, s.metadata.author.raw_page)?,
            "foreign revision source identity differs"
        );
        Ok(s)
    }
    pub fn identity(&self) -> Result<Digest> {
        revision_id(self.page, &self.native, &self.share)
    }
    pub fn value(&self) -> V {
        a(vec![
            b(&self.page),
            b(&self.agreement),
            self.source.value(),
            reference(&self.native),
            reference(&self.share),
            self.bundle.value(),
            V::Uint(self.imported_at_ms),
            b(&self.evidence),
            self.metadata.value(),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct ForeignReview {
    pub revision: VersionRef,
    pub reviewer: Key,
    pub grant: VersionRef,
    pub application: Option<VersionRef>,
    pub mode: u64,
    pub policy: Option<Digest>,
    pub approve: bool,
    pub statement: Vec<u8>,
    pub decided_at_ms: u64,
}
impl ForeignReview {
    pub fn parse(v: &V, n: Digest, i: Digest) -> Result<Self> {
        let f = v.array(9)?;
        let s = Self {
            revision: exact_ref(&f[0], 155)?,
            reviewer: key(&f[1])?,
            grant: exact_ref(&f[2], 102)?,
            application: optional_ref(&f[3], 148)?,
            approve: f[4].boolean()?,
            statement: f[5].bytes()?.to_vec(),
            decided_at_ms: f[6].uint()?,
            mode: f[7].uint()?,
            policy: if f[8] == V::Null {
                None
            } else {
                Some(id(&f[8])?)
            },
        };
        let intent = Intent::from_signed(&s.statement)?;
        ensure!(
            intent.network == n
                && intent.incarnation == i
                && intent.requester == s.reviewer
                && intent.action == "FederationReviewStatement"
                && intent.resource == s.revision.id
                && intent.expected.is_empty()
                && intent.parameters == wire::encode(&s.statement_value())?
                && intent.profile_generation == 0
                && s.decided_at_ms > 0
                && s.mode <= 1
                && (s.application.is_some() == s.policy.is_some())
                && (s.application.is_some() || s.mode == 0),
            "local foreign review statement differs"
        );
        Ok(s)
    }
    pub fn statement_value(&self) -> V {
        a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("FederationReviewStatement".into()),
            reference(&self.revision),
            reference(&self.grant),
            self.application.as_ref().map_or(V::Null, reference),
            V::Bool(self.approve),
            V::Uint(self.mode),
            self.policy.as_ref().map_or(V::Null, |v| b(v)),
        ])
    }
    pub fn value(&self) -> V {
        a(vec![
            reference(&self.revision),
            b(&self.reviewer),
            reference(&self.grant),
            self.application.as_ref().map_or(V::Null, reference),
            V::Bool(self.approve),
            b(&self.statement),
            V::Uint(self.decided_at_ms),
            V::Uint(self.mode),
            self.policy.as_ref().map_or(V::Null, |v| b(v)),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct ForeignFloor {
    pub trust: Digest,
    pub epochs: Vec<archive::Activated>,
    pub retained: archive::Retained,
    pub sealed: Option<archive::Seal>,
}
pub struct ResolvedFloor {
    pub descriptor: TrustDescriptor,
    pub prefix: Prefix,
    pub checkpoint: Option<ValidatedCheckpoint>,
}
impl ForeignFloor {
    pub fn initial(trust: Digest) -> Self {
        Self {
            trust,
            epochs: vec![],
            retained: archive::Retained {
                certificate: None,
                node: None,
                checkpoint: None,
            },
            sealed: None,
        }
    }
    pub fn parse(v: &V) -> Result<Self> {
        let f = v.array(4)?;
        let epochs = serde_json::from_slice(f[1].bytes()?)?;
        let retained = serde_json::from_slice(f[2].bytes()?)?;
        let sealed = optional_bytes(&f[3])?
            .map(|b| serde_json::from_slice(&b))
            .transpose()?;
        let s = Self {
            trust: id(&f[0])?,
            epochs,
            retained,
            sealed,
        };
        ensure!(s.value()? == *v, "foreign floor encoding is not canonical");
        Ok(s)
    }
    pub fn value(&self) -> Result<V> {
        Ok(a(vec![
            b(&self.trust),
            b(&serde_json::to_vec(&self.epochs)?),
            b(&serde_json::to_vec(&self.retained)?),
            self.sealed
                .as_ref()
                .map(|s| serde_json::to_vec(s).map(V::Bytes))
                .transpose()?
                .unwrap_or(V::Null),
        ]))
    }
    pub fn resolve(&self, trust: &ForeignTrust) -> Result<ResolvedFloor> {
        ensure!(
            trust.identity()? == self.trust,
            "foreign floor selects another trust identity"
        );
        let initial = trust.verified()?;
        let descriptor = archive::resolve(initial.descriptor(), &self.epochs)?.descriptor;
        let (prefix, checkpoint) = self.retained.verify(&descriptor)?;
        if let Some(seal) = &self.sealed {
            let terminal = seal.verify(&descriptor)?;
            ensure!(
                terminal.history().from() == &prefix
                    && terminal.history().prior() == checkpoint.as_ref().map(|c| c.head()),
                "foreign seal does not extend actual retained floor"
            );
        }
        Ok(ResolvedFloor {
            descriptor,
            prefix,
            checkpoint,
        })
    }
}
