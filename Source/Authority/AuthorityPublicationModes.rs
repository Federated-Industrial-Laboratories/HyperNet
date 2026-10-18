// SPDX-License-Identifier: MIT
// Namespace and object restrictions intersect with network policy before content admission.
use crate::{
    authority_domains::{self as domains, Record, State, page::Evaluation, sealed_publication},
    authority_membership::reference,
    authority_proof::{Digest, Key, VersionRef},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Context, Result, ensure};
pub const KIND: u64 = 164;
#[derive(Clone, Debug)]
pub struct Policy {
    pub namespace: String,
    pub modes: Vec<u64>,
    pub administrator: Key,
    pub grant: VersionRef,
}
pub fn modes(value: &V) -> Result<Vec<u64>> {
    let m = value
        .list(2)?
        .iter()
        .map(V::uint)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !m.is_empty() && m.iter().all(|v| *v <= 1) && m.windows(2).all(|w| w[0] < w[1]),
        "invalid publication mode set"
    );
    Ok(m)
}
impl Policy {
    pub fn parse(value: &V) -> Result<Self> {
        let f = value.array(4)?;
        let p = Self {
            namespace: f[0].text()?.into(),
            modes: modes(&f[1])?,
            administrator: domains::key(&f[2])?,
            grant: domains::version(&f[3])?,
        };
        ensure!(
            crate::markup::namespace(&p.namespace) && p.grant.kind == 102,
            "publication namespace policy differs"
        );
        Ok(p)
    }
    pub fn value(&self) -> V {
        V::Array(vec![
            V::Text(self.namespace.clone()),
            V::Array(self.modes.iter().map(|m| V::Uint(*m)).collect()),
            V::Bytes(self.administrator.to_vec()),
            reference(&self.grant),
        ])
    }
}
pub fn validate(value: &V, lookup: Digest) -> Result<()> {
    ensure!(
        domains::page::namespace_id(&Policy::parse(value)?.namespace)? == lookup,
        "publication namespace lookup differs"
    );
    Ok(())
}
pub(crate) fn permitted(
    c: &mut Evaluation<'_>,
    namespace: &str,
    object: Option<Digest>,
    mode: u64,
) -> Result<()> {
    let n = wire::decode(c.governance.record_bytes(100, c.state.network)?)?;
    ensure!(
        modes(&n.array(17)?[10])?.contains(&mode),
        "network does not permit this publication mode"
    );
    c.dependencies.push(
        c.governance
            .versions()
            .into_iter()
            .find(|r| r.kind == 100)
            .context("network policy absent")?,
    );
    let id = domains::page::namespace_id(namespace)?;
    if c.state.records.contains_key(&(KIND, id)) {
        let r = c.select(KIND, id)?;
        ensure!(
            Policy::parse(&r.payload)?.modes.contains(&mode),
            "namespace refuses this publication mode"
        );
    }
    if let Some(object) = object
        && c.state.records.contains_key(&(104, object))
    {
        let r = c.select(104, object)?;
        let p = sealed_publication::ObjectPolicy::parse(
            &sealed_publication::payload(&r)?,
            c.state.network,
            c.state.incarnation,
        )?;
        ensure!(
            p.namespace == id && p.modes.contains(&mode),
            "object refuses this publication mode"
        );
    }
    Ok(())
}
pub(crate) fn update(
    c: &mut Evaluation<'_>,
    next: &mut State,
    namespace: &str,
    allowed: &[u64],
    requester: Key,
    grant: &VersionRef,
    replay: bool,
) -> Result<()> {
    let id = domains::page::namespace_id(namespace)?;
    c.capability(grant, requester, &[9], (1, id), Some(namespace), 0)?;
    let network = wire::decode(c.governance.record_bytes(100, c.state.network)?)?;
    let permitted = modes(&network.array(17)?[10])?;
    ensure!(
        allowed.iter().all(|m| permitted.contains(m)),
        "namespace cannot enable a forbidden network mode"
    );
    if c.state.records.contains_key(&(KIND, id)) {
        c.select(KIND, id)?;
    }
    let value = Policy {
        namespace: namespace.into(),
        modes: allowed.to_vec(),
        administrator: requester,
        grant: grant.clone(),
    }
    .value();
    validate(&value, id)?;
    if replay {
        ensure!(
            next.record(KIND, id)?.payload == value,
            "namespace publication policy replay differs"
        );
    } else {
        next.put(Record::next(next, KIND, id, value)?)?;
    }
    Ok(())
}
