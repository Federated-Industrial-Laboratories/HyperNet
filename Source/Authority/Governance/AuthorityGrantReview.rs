// SPDX-License-Identifier: MIT
// Reviewed grant mutations retain their original capability and exact snapshot contracts.
use crate::{
    authority_membership::Snapshot,
    authority_proof::{Digest, Intent},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
#[derive(Clone, Debug)]
pub struct Operation {
    pub inner: Intent,
    pub token: Option<Digest>,
    pub apply: bool,
}
impl Operation {
    pub fn handles(action: &str) -> bool {
        matches!(action, "AuthorityGrantPreview" | "AuthorityGrantApply")
    }
    pub fn parse(intent: &Intent) -> Result<Self> {
        let decoded = wire::decode(&intent.parameters)?;
        let f = decoded.array(5)?;
        ensure!(
            Self::handles(&intent.action)
                && f[0].uint()? == 200
                && f[1].uint()? == 1
                && f[2].text()? == intent.action,
            "grant review wrapper differs"
        );
        let parameters = f[3].bytes()?.to_vec();
        let source = wire::decode(&parameters)?;
        let source = source.array(6)?;
        let action = source[2].text()?;
        ensure!(
            source[0].uint()? == 200
                && source[1].uint()? == 1
                && matches!(action, "AuthorityDelegateGrant" | "AuthorityRevokeGrant"),
            "unsupported reviewed grant operation"
        );
        Snapshot::parse(&source[5])?;
        let mut inner = intent.clone();
        inner.action = action.into();
        inner.parameters = parameters;
        let token = if f[4] == V::Null {
            None
        } else {
            Some(f[4].fixed()?)
        };
        Ok(Self {
            inner,
            token,
            apply: intent.action == "AuthorityGrantApply",
        })
    }
    pub fn request_digest(&self) -> Result<Digest> {
        let value = wire::decode(&self.inner.parameters)?;
        let mut f = value.array(6)?.to_vec();
        let snapshot = Snapshot::parse(&f[5])?;
        f[5] = V::Array(
            snapshot
                .references
                .iter()
                .map(crate::authority_membership::reference)
                .collect(),
        );
        Ok(wire::digest(&wire::encode(&V::Array(vec![
            V::Text("GrantProposal".into()),
            V::Bytes(self.inner.network.to_vec()),
            V::Bytes(self.inner.incarnation.to_vec()),
            V::Bytes(self.inner.requester.to_vec()),
            V::Array(f),
        ]))?))
    }
}
