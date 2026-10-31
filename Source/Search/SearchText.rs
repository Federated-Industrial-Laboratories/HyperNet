// SPDX-License-Identifier: MIT
// Literal search derives bounded text only from an exact inert approved source.
use crate::{
    authority_proof::Digest,
    markup::{self, Kind, Node, TextKind},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use unicode_segmentation::UnicodeSegmentation;

pub const MAXIMUM_REQUEST: usize = 16384;
pub const MAXIMUM_RESULTS: usize = 100;

#[derive(Clone)]
pub struct Request {
    pub network: Digest,
    pub incarnation: Digest,
    pub operation: Digest,
    pub scope: u64,
    pub terms: Vec<String>,
    pub combination: u64,
    pub namespaces: Vec<Digest>,
    pub limit: usize,
    pub cursor: Option<Digest>,
    pub historical: bool,
    pub snapshot: V,
}
fn bytes(value: &Digest) -> V {
    V::Bytes(value.to_vec())
}
fn identifier(value: &V) -> Result<Digest> {
    let value = value.fixed()?;
    ensure!(value != [0; 32], "zero search identifier");
    Ok(value)
}
fn safe(c: char) -> bool {
    !c.is_control()
        && !matches!(c as u32, 0x00ad | 0x061c | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f | 0xfeff | 0xfdd0..=0xfdef | 0xe0000..=0xe007f)
        && c as u32 & 0xffff < 0xfffe
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAXIMUM_REQUEST,
            "search request exceeds its bound"
        );
        let value = wire::decode(bytes)?;
        let f = value.array(15)?;
        ensure!(
            f[0].uint()? == 119 && f[1].uint()? == 1 && f[4].uint()? == 0,
            "search request format differs"
        );
        f[5].null()?;
        let out = Self {
            network: identifier(&f[2])?,
            incarnation: identifier(&f[3])?,
            operation: identifier(&f[6])?,
            scope: f[7].uint()?,
            terms: f[8]
                .list(16)?
                .iter()
                .map(|v| Ok(v.text()?.to_owned()))
                .collect::<Result<_>>()?,
            combination: f[9].uint()?,
            namespaces: f[10]
                .list(64)?
                .iter()
                .map(identifier)
                .collect::<Result<_>>()?,
            limit: usize::try_from(f[11].uint()?)?,
            cursor: if f[12] == V::Null {
                None
            } else {
                Some(identifier(&f[12])?)
            },
            historical: match f[13].uint()? {
                0 => false,
                1 => true,
                _ => anyhow::bail!("invalid retained search view"),
            },
            snapshot: f[14].clone(),
        };
        out.validate()?;
        Ok(out)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            [self.network, self.incarnation, self.operation]
                .iter()
                .all(|v| *v != [0; 32])
                && self.scope <= 1
                && self.combination <= 1
                && (!self.historical || self.scope == 0)
                && (1..=MAXIMUM_RESULTS).contains(&self.limit)
                && self.namespaces.len() <= 64
                && self.namespaces.iter().all(|v| *v != [0; 32])
                && self.namespaces.windows(2).all(|p| p[0] < p[1])
                && self.cursor.is_none_or(|v| v != [0; 32]),
            "invalid search scope or extent"
        );
        let mut unique = BTreeSet::new();
        let mut size = 0usize;
        ensure!(self.terms.len() <= 16, "too many search terms");
        for term in &self.terms {
            ensure!(
                !term.trim().is_empty()
                    && term.len() <= 128
                    && term.chars().all(safe)
                    && term.graphemes(true).all(|g| g.chars().count() <= 16)
                    && unique.insert(term.to_lowercase()),
                "invalid or repeated literal search term"
            );
            size += term.len();
        }
        ensure!(size <= 1024, "search term bytes exceed their bound");
        crate::authority_domains::snapshot(&self.snapshot)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = wire::encode(&V::Array(vec![
            V::Uint(119),
            V::Uint(1),
            bytes(&self.network),
            bytes(&self.incarnation),
            V::Uint(0),
            V::Null,
            bytes(&self.operation),
            V::Uint(self.scope),
            V::Array(self.terms.iter().cloned().map(V::Text).collect()),
            V::Uint(self.combination),
            V::Array(self.namespaces.iter().map(bytes).collect()),
            V::Uint(self.limit as u64),
            self.cursor.as_ref().map_or(V::Null, bytes),
            V::Uint(u64::from(self.historical)),
            self.snapshot.clone(),
        ]))?;
        ensure!(
            bytes.len() <= MAXIMUM_REQUEST,
            "search request exceeds its bound"
        );
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(wire::digest(&self.encode()?))
    }
    pub fn network_scope(
        &self,
        network: Digest,
        incarnation: Digest,
        namespace: Digest,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.network == network
                && self.incarnation == incarnation
                && self.scope == 1
                && !self.historical
                && (self.namespaces.is_empty() || self.namespaces.contains(&namespace)),
            "search request has another network, namespace or scope"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Match {
    pub title: String,
    pub snippet: String,
    pub tags: Vec<String>,
    pub score: u64,
}
impl Match {
    pub fn value(&self) -> V {
        V::Array(vec![
            V::Text(self.title.clone()),
            V::Text(self.snippet.clone()),
            V::Array(self.tags.iter().cloned().map(V::Text).collect()),
            V::Uint(self.score),
        ])
    }
}
fn collect(nodes: &[Node], headings: &mut Vec<String>, text: &mut Vec<String>) {
    for node in nodes {
        match &node.kind {
            Kind::Text {
                text: value,
                kind: TextKind::Heading2 | TextKind::Heading3,
            } => headings.push(value.clone()),
            Kind::Text { text: value, .. } => text.push(value.clone()),
            Kind::Image { alt, .. } => text.push(alt.clone()),
            Kind::Panel { label, .. }
            | Kind::ScrollBox { label, .. }
            | Kind::Button { label, .. }
            | Kind::Progress { label, .. } => text.push(label.clone()),
            // Form field values, defaults and schemas are outside the publication search corpus.
            Kind::Field { .. } | Kind::Form { .. } => continue,
            _ => {}
        }
        collect(&node.children, headings, text);
    }
}
pub fn snippet(value: &str) -> String {
    let mut out = String::new();
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    for grapheme in collapsed.graphemes(true).take(180) {
        if out.len() + grapheme.len() > 768 {
            break;
        }
        if grapheme.chars().all(safe) {
            out.push_str(grapheme);
        }
    }
    out
}
pub fn matching(request: &Request, source: &[u8]) -> Result<Option<Match>> {
    request.validate()?;
    let document = markup::parse(std::str::from_utf8(source)?).map_err(anyhow::Error::msg)?;
    let mut headings = Vec::new();
    let mut text = Vec::new();
    collect(&document.nodes, &mut headings, &mut text);
    let title = document.title.to_lowercase();
    let folded_headings = headings
        .iter()
        .map(|v| v.to_lowercase())
        .collect::<Vec<_>>();
    let folded_tags = document
        .tags
        .iter()
        .map(|v| v.to_lowercase())
        .collect::<Vec<_>>();
    let folded_text = text.iter().map(|v| v.to_lowercase()).collect::<Vec<_>>();
    let terms = request
        .terms
        .iter()
        .map(|v| v.to_lowercase())
        .collect::<Vec<_>>();
    let mut score = 0;
    let mut matches = 0;
    for term in &terms {
        let points = u64::from(title.contains(term)) * 8
            + u64::from(folded_headings.iter().any(|v| v.contains(term))) * 4
            + u64::from(folded_tags.iter().any(|v| v.contains(term))) * 6
            + u64::from(folded_text.iter().any(|v| v.contains(term)));
        score += points;
        matches += usize::from(points > 0);
    }
    if !terms.is_empty() && (matches == 0 || request.combination == 0 && matches != terms.len()) {
        return Ok(None);
    }
    let selected = headings
        .iter()
        .chain(&text)
        .find(|v| terms.iter().any(|term| v.to_lowercase().contains(term)))
        .or_else(|| text.first())
        .unwrap_or(&document.title);
    let excerpt = snippet(selected);
    Ok(Some(Match {
        title: document.title,
        snippet: excerpt,
        tags: document.tags,
        score,
    }))
}
pub fn response(request: &Request, source: &[u8]) -> Result<Vec<u8>> {
    let found = matching(request, source)?;
    wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("PageSearchResult".into()),
        bytes(&request.digest()?),
        V::Bytes(source.to_vec()),
        found.as_ref().map_or(V::Null, Match::value),
    ]))
}

#[cfg(test)]
#[path = "../../Tests/Unit/Search/SearchTextTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Search/SearchText.rs");
