// SPDX-License-Identifier: MIT
// Native publications retain exact inert source, explicit reviews and current host consent.
use super::*;
use crate::{
    authority_objects::{Class, Reference, Resolved},
    markup,
};
use std::collections::BTreeSet;

pub const MAXIMUM_PROVENANCE: usize = 4096;
pub const MAXIMUM_LIFETIME_MS: u64 = 604800000;
pub const REVIEW_LIFETIME_MS: u64 = 300000;
// A ticket reserves the multi-operation delivery workflow; each proof remains short-lived.
pub const TICKET_LIFETIME_MS: u64 = 60_000;
// A certified result has at most 64 exact version references.
pub const MAXIMUM_CONTEXT_RECORDS: usize = 64;

#[path = "AuthorityPageObjects.rs"]
pub mod objects;
#[path = "AuthorityPageProfile.rs"]
mod profile;
pub use profile::{ApplicationPolicy, Host, HostProfile, PlacementPolicy};
#[path = "AuthorityPageStorage.rs"]
mod storage;
pub use storage::{
    STORAGE_BANK_HEADER_BYTES, media_storage_budget, media_storage_charge, serialized_bank_bytes,
};
#[path = "AuthorityPageRecords.rs"]
mod records;
pub use records::retained_inputs;
pub use records::*;
#[path = "AuthorityPageCommands.rs"]
mod commands;
pub use commands::{Command, MediaEffect};
#[path = "AuthorityPageEvaluation.rs"]
mod evaluation;
pub(crate) use evaluation::context::Evaluation;
pub use evaluation::{evaluate, expected_recipient};
#[path = "AuthorityPageResponse.rs"]
mod response;
pub use response::response_inputs;
#[path = "AuthorityPageMediaRequest.rs"]
mod media_request;
pub use media_request::Request as MediaRequest;
#[path = "AuthorityPageMediaReceipt.rs"]
mod media_receipt;
pub use media_receipt::{MEDIA_RECEIPT_LIMIT, Receipt as MediaReceipt, Report as MediaReport};

pub fn page_id(raw: &[u8; 16]) -> Result<Digest> {
    ensure!(*raw != [0; 16], "zero Page identity");
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Uint(202),
        V::Uint(1),
        V::Uint(2),
        V::Text("Page".into()),
        b(raw),
    ]))?))
}
pub fn namespace_id(name: &str) -> Result<Digest> {
    ensure!(markup::namespace(name), "invalid Page namespace");
    Ok(wire::digest(&wire::encode(&a(vec![
        V::Uint(202),
        V::Uint(1),
        V::Uint(1),
        V::Text("Namespace".into()),
        V::Text(name.into()),
    ]))?))
}
fn namespace(value: &V) -> Result<String> {
    let name = value.text()?;
    ensure!(markup::namespace(name), "invalid Page namespace");
    Ok(name.into())
}
fn optional_version(value: &V, kind: u64) -> Result<Option<VersionRef>> {
    if *value == V::Null {
        return Ok(None);
    }
    let r = version(value)?;
    ensure!(r.kind == kind, "Page reference kind differs");
    Ok(Some(r))
}
fn required_version(value: &V, kind: u64) -> Result<VersionRef> {
    optional_version(value, kind)?.context("Page reference is absent")
}
fn optional_id(value: &V) -> Result<Option<Digest>> {
    if *value == V::Null {
        Ok(None)
    } else {
        Ok(Some(id(value)?))
    }
}
fn source(value: &V) -> Result<Reference> {
    let reference = Reference::parse(value)?;
    ensure!(
        reference.class() == Class::PageSource,
        "Page source input class differs"
    );
    Ok(reference)
}
fn bundle(value: &V) -> Result<Reference> {
    let reference = Reference::parse(value)?;
    ensure!(
        reference.class() == Class::PageBundle,
        "Page bundle input class differs"
    );
    Ok(reference)
}
fn names(value: &V, maximum: usize) -> Result<Vec<String>> {
    let names = value
        .list(maximum)?
        .iter()
        .map(namespace)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !names.is_empty() && names.windows(2).all(|w| w[0] < w[1]),
        "Page names are not sorted and unique"
    );
    Ok(names)
}
fn identity(label: &str, fields: Vec<V>) -> Result<Digest> {
    let mut row = vec![V::Uint(200), V::Uint(1), V::Text(label.into())];
    row.extend(fields);
    Ok(wire::digest(&wire::encode(&a(row))?))
}

#[cfg(test)]
#[path = "AuthorityPageTests.rs"]
mod tests;
