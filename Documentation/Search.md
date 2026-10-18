# Catalogue and search

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Search selects one explicit network or an explicitly retained local corpus. An
empty literal-term list requests the permitted catalogue. There is no implicit
network fallback, combined local/network mode or query fan-out to other networks.
The separate Suite supplies the requester workflow; Core supplies finite current
permissions and exact content exchanges.

Every network candidate requires current ReadPage0 and SearchCatalogue1 for its
exact Page and namespace. An application additionally needs PagesRead and
PagesSearch. Native PageSearchList and imported FederationSearchList return only
permitted current publications. Their catalogue metadata and pagination use the
same current authorisation as the individual objects. A withdrawal, changed
policy, unavailable source authority or changed corpus invalidates continuation.

Native PageSearchList includes a complete certified PageView closure for every
returned Page, in addition to its current search capability and application
checks. Unusable or inaccessible items roll back their entire selected closure;
they disclose neither partial metadata nor a count. Complete closures consume
the existing record and encoded-result bounds, and continuation follows the last
included Page. No result limit is enlarged for this combined operation.

## Host-readable sources

A native host explicitly enables the final `search` boolean in its signed
ContentPolicy. Its current managing grant must permit IndexPages7. An imported
destination bridge separately enables the final `search` boolean in its signed
AuthorityBridgeProfile and requires IndexPages7 in the destination namespace.
Ordinary hosting does not grant either indexing permission. Sealed source and
recipient-private metadata are never network-search input.

Native search uses Content protocol2 and PageContentAuthorise effect5. Its durable
intent binds the exact requester, publication, placement, host and full source
size, with zero offset and no upload digest. It contains no query, query digest
or guessable term-derived identifier. The encrypted final-service exchange carries
the bounded SearchRequest. The service rechecks exact source approval and returns
`[201,1,"PageSearchResult",requestDigest,sourceBytes,matchOrNull]`. The requester
verifies the exact certified source digest and reproduces matching from that
source before disclosing a result. The outer content response digest covers the
complete encoded search result, and retains the exact complete-copy receipt.

Imported search uses destination Bridge protocol6. The encrypted request is
`[200,1,"RouteBridgeSearch",readerEnvelopeBytes,SearchRequestBytes]`. Only the
query-free action1 reader envelope reaches authority replication. The destination
bridge renews an ordinary metadata-only foreign export, checks its retained exact
imported source, and searches that local source. No term is sent to the source
network. The response is
`[201,1,"BridgeSearch",foreignProofBytes,resolvedObjects,SearchResultBytes]`.
Clients verify the current source export, local import approval, exact retained
bundle and source, then reproduce matching. Either side's revocation refuses.

Matching uses bounded literal Unicode lowercase terms. Each requested term must
occur for All; at least one must occur for Any. Empty terms return the catalogue.
Title, headings, tags and body contribute fixed per-document weights. Counts and
ranking never depend on inaccessible documents. Snippets are safe bounded plain
text. The exact inert source is already limited by the HyperPage parser. No query
language, SQL, external dictionary, script or persistent server text index runs.

## Explicit local retention

A local query performs no network activity. Explicit synchronisation can fetch
permitted exact native source, imported source or sealed ciphertext into a
requester-owned encrypted corpus. Sealed matching decrypts only in memory with
the recipient's separate vault and key. This local derivation does not require a host
indexing role. It never gives a storage host the sealed plaintext.

PageLocalSearchLease refreshes native and sealed retained permissions together:
`["PageLocalSearchLease",[[publicationReference,deviceReferenceOrNull],...]]`.
Items are sorted by exact publication index, with no duplicates. Native entries
name exact review142 and null; sealed entries name exact publication113 and the
reader's device108. The combined certified dependency set must fit64 references;
there is no partial success when one item is stale or outside authority. A device
may read native Pages through its exact current root107, binding108, admission109
and member-to-grant mapping. The device cannot borrow an arbitrary member's grant.

Imported local retention uses ordinary action0 BridgeLease plus
FederationLocalSearchRead: it rechecks current ReadPage and SearchCatalogue on the
exact approved import and fresh foreign export, without requesting server indexing.
The normal five-second operation freshness is never extended by retention. Current
local results require a still-live verified permission and matching retained
versions. Historical mode is a separate explicit choice with no current-access
claim. Neither failure nor expiration causes an automatic query-time refresh.

Network cursors belong to the requester and bind the explicit query, scope,
network, verified policy and complete selected corpus. Cursor storage and local
retention are Suite responsibilities. Default diagnostics omit query terms,
query-derived identifiers, source snippets and sealed metadata.
