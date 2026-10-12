// SPDX-License-Identifier: MIT
// Bilateral publication rights retain independently accepted authority identities and foreign floors.
use super::*;
use crate::{
    authority_objects::{Reference, Resolved},
    markup,
};
use std::collections::BTreeSet;

#[path = "AuthorityFederationRecords.rs"]
mod records;
pub use records::*;
#[path = "AuthorityFederationProfile.rs"]
mod profile;
pub use profile::*;
#[path = "AuthorityFederationCommands.rs"]
mod commands;
pub use commands::Command;
#[path = "AuthorityFederationProof.rs"]
mod proof;
pub use proof::{ForeignProof, VerifiedForeign};
#[path = "AuthorityFederationContext.rs"]
mod context;
#[path = "AuthorityFederationEvaluation.rs"]
mod evaluation;
pub use evaluation::{evaluate, expected_recipient};

pub const MAXIMUM_CONTEXT_RECORDS: usize = 64;
fn identity(name: &str, values: Vec<V>) -> Result<Digest> {
    let mut f = vec![V::Uint(200), V::Uint(1), V::Text(name.into())];
    f.extend(values);
    Ok(wire::digest(&wire::encode(&a(f))?))
}
fn namespace(v: &V) -> Result<String> {
    let s = v.text()?;
    ensure!(markup::namespace(s), "invalid federation namespace");
    Ok(s.into())
}
fn exact_ref(v: &V, kind: u64) -> Result<VersionRef> {
    let r = version(v)?;
    ensure!(r.kind == kind, "federation reference has another kind");
    Ok(r)
}
fn optional_ref(v: &V, kind: u64) -> Result<Option<VersionRef>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(exact_ref(v, kind)?))
    }
}
fn optional_bytes(v: &V) -> Result<Option<Vec<u8>>> {
    if *v == V::Null {
        Ok(None)
    } else {
        Ok(Some(v.bytes()?.to_vec()))
    }
}
pub fn qualified_page(
    agreement: Digest,
    source: &NetworkIdentity,
    page: [u8; 16],
) -> Result<Digest> {
    identity(
        "FederatedPage",
        vec![
            b(&agreement),
            b(&source.network),
            b(&source.incarnation),
            b(&page),
        ],
    )
}
pub fn revision_id(page: Digest, source: &VersionRef, share: &VersionRef) -> Result<Digest> {
    ensure!(
        source.kind == 141 && share.kind == 153,
        "foreign revision requires native source provenance"
    );
    identity(
        "FederatedRevision",
        vec![b(&page), reference(source), reference(share)],
    )
}
pub fn share_id(agreement: Digest, page: [u8; 16]) -> Result<Digest> {
    identity("FederationShare", vec![b(&agreement), b(&page)])
}
pub fn validate_record(
    kind: u64,
    value: &V,
    n: Digest,
    i: Digest,
    lookup: Digest,
    generation: u64,
) -> Result<()> {
    let actual = match kind {
        150 => ForeignTrust::parse(value, n, i)?.identity()?,
        151 => Agreement::parse(value, n, i)?.treaty.id,
        152 => Bridge::parse(value, n, i)?.profile.service,
        153 => Share::parse(value, n, i)?.identity()?,
        154 => ForeignPage::parse(value)?.identity()?,
        155 => ForeignRevision::parse(value)?.identity()?,
        156 => ForeignReview::parse(value, n, i)?.revision.id,
        157 => ForeignFloor::parse(value)?.trust,
        _ => anyhow::bail!("unsupported federation record"),
    };
    ensure!(
        actual == lookup && generation > 0 && (kind != 155 || generation == 1),
        "federation record identity or generation differs"
    );
    Ok(())
}
pub fn validate_state(state: &State, partial: bool) -> Result<()> {
    for r in state
        .records
        .values()
        .filter(|r| matches!(r.reference.kind, 150..=157))
    {
        let required = match r.reference.kind {
            151 => vec![(
                150,
                Agreement::parse(&r.payload, state.network, state.incarnation)?
                    .foreign
                    .id,
            )],
            154 => {
                let p = ForeignPage::parse(&r.payload)?;
                let mut refs = vec![(151, p.agreement)];
                refs.extend(p.pending.as_ref().map(VersionRef::index));
                refs.extend(p.published.as_ref().map(VersionRef::index));
                refs
            }
            155 => vec![(154, ForeignRevision::parse(&r.payload)?.page)],
            156 => vec![(
                155,
                ForeignReview::parse(&r.payload, state.network, state.incarnation)?
                    .revision
                    .id,
            )],
            157 => vec![(150, ForeignFloor::parse(&r.payload)?.trust)],
            _ => vec![],
        };
        ensure!(
            partial || required.iter().all(|k| state.records.contains_key(k)),
            "federation retained context is incomplete"
        );
        if r.reference.kind == 157 {
            let floor = ForeignFloor::parse(&r.payload)?;
            if let Some(trust) = state.records.get(&(150, floor.trust)) {
                floor.resolve(&ForeignTrust::parse(
                    &trust.payload,
                    state.network,
                    state.incarnation,
                )?)?;
            }
        }
    }
    Ok(())
}
pub fn retained_inputs(state: &State) -> Result<Vec<Reference>> {
    let mut out = vec![];
    for record in state.records.values().filter(|r| r.reference.kind == 155) {
        out.push(ForeignRevision::parse(&record.payload)?.bundle);
    }
    out.sort();
    out.dedup();
    Ok(out)
}
pub fn response_inputs(intent: &Intent, value: &V) -> Result<Vec<Reference>> {
    let Operation {
        command: super::Command::Federation(command),
        ..
    } = Operation::parse(intent)?
    else {
        return Ok(vec![]);
    };
    if !command.returns_bundle() {
        return Ok(vec![]);
    }
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
        "invalid federation result"
    );
    let body = f[4].array(4)?;
    ensure!(
        body[0].text()? == command.name(),
        "federation result action differs"
    );
    let mut refs = vec![];
    for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
        let r = Record::parse(bytes.bytes()?, intent.network, intent.incarnation)?;
        if r.reference.kind == 155 {
            let revision = ForeignRevision::parse(&r.payload)?;
            ensure!(
                command.selected_page() == Some(revision.page),
                "federation output names another page"
            );
            refs.push(revision.bundle);
        } else if r.reference.kind == 142
            && matches!(
                command,
                Command::Export {
                    include_bundle: true,
                    ..
                }
            )
        {
            let review = page::Review::parse(&r.payload, intent.network, intent.incarnation)?;
            if let Some(bundle) = review.bundle {
                refs.push(bundle)
            }
        }
    }
    refs.sort();
    refs.dedup();
    ensure!(refs.len() == 1, "federation output bundle is not exact");
    Ok(refs)
}

#[cfg(test)]
#[path = "AuthorityFederationTests.rs"]
mod tests;
