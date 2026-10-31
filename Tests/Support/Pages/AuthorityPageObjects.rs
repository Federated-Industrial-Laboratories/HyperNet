// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl Author {
    #[cfg(test)]
    pub fn parameters(
        raw_page: [u8; 16],
        namespace: &str,
        source: &[u8],
        grant: &VersionRef,
        application: Option<&VersionRef>,
        expires_ms: u64,
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageAuthorStatement".into()),
            b(&raw_page),
            V::Text(namespace.into()),
            V::Uint(0),
            V::Text(markup::PROFILE.into()),
            Reference::for_bytes(Class::PageSource, source)?.value(),
            reference(grant),
            application.map_or(V::Null, reference),
            V::Uint(expires_ms),
            SourceMetadata::from_source(source)?.value(),
        ]))
    }
}

impl Reviewer {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn parameters(
        revision: &VersionRef,
        source: &Reference,
        author: Key,
        author_statement: Digest,
        grant: &VersionRef,
        application: Option<&VersionRef>,
        approve: bool,
        mode: u64,
        policy: Option<Digest>,
        expires_ms: u64,
    ) -> Result<Vec<u8>> {
        wire::encode(&a(vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("PageReviewStatement".into()),
            reference(revision),
            source.value(),
            b(&author),
            b(&author_statement),
            reference(grant),
            application.map_or(V::Null, reference),
            V::Bool(approve),
            V::Uint(mode),
            policy.as_ref().map_or(V::Null, |v| b(v)),
            V::Uint(expires_ms),
        ]))
    }
}
