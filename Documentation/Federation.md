# Federation

Federation copies explicitly shared native Pages between two independently
administered HyperNets. Each network accepts the other's complete bootstrap
through an independently authenticated channel and admits its own role7 bridge.
Both administrators accept the identical treaty. The source author shares one
exact approved revision; the destination reviews that imported revision before
local reading. Federation grants no foreign membership, local administration,
reviewer capability or onward export authority.

Use the Suite `federation` commands for trust, treaties, bridge profiles, author
sharing, local review and reading. [Bridge.md](Bridge.md) describes installation.
The only network transport in this contract connects the two consented bridges.
Local operator control does not provide a remote reader route.

## Acceptance and publication

1. Exchange each network ID, incarnation, bootstrap file SHA256 and bootstrap
   fingerprint independently. `trust inspect` verifies the accepted recovery
   signatures and reports these distinct pins. `trust accept` requires current
   local capability22. A bootstrap naming a different incarnation is a new trust
   decision, not an epoch update.
2. Create one treaty with source/destination bootstrap identities, distinct
   bridge keys, exact namespaces, expiry and media placement consent. Each
   administrator accepts the same canonical bytes with capability22. Each
   bridge remains an intrinsic service identity in its own network.
3. Admit the dedicated role7 manifest and register its operator-signed bridge
   profile. Registration requires both the current manager capability26 and
   the original deployment admission. Local runtime consent and activation are
   separate requirements.
4. The source author signs `FederationShareStatement` for the current native
   publication142 and revision141. Ordering `FederationShare` requires the
   current author, capability4 and applicable application restrictions.
5. The source bridge first obtains certified metadata for the exact shared Page
   or bounded inventory window. The destination bridge then obtains its own
   certified Admission and a certified source Export. It verifies the complete quorum, current accepted foreign
   floor, exact treaty and current source sharing. Import preserves the native
   source bundle reference and signed metadata in qualified records154/155.
   The body travels directly from its consented source content host through the
   Bridges, outside authority objects. Media is copied through
   separately consented role2 stores and decoded again there.
6. A destination reviewer inspects the exact imported bundle and any media.
   A saved review decision binds immutable155, reviewer capability, application
   mode and policy. Submitting the decision obtains a new bilateral lease for
   the same native141. Human review has no five-second reading deadline.
7. Read, listing and media effects obtain fresh bilateral evidence and recheck
   current local rights. An imported bundle or historical approval alone never
   grants current access.

Removing a share, grant, agreement, host consent or trust stops subsequent
protected effects. It cannot erase bytes previously disclosed to an authorised
reader or host. Re-sharing the same native revision uses a new sharing153
reference and therefore a new155 identity requiring local review again.

## Canonical records

The canonical encoding, signed Intent20, VersionRef and domain result201 follow
[WireContract.md](WireContract.md) and [PolicyContract.md](PolicyContract.md).
`B32` means exactly32 bytes, `Page16` exactly16 bytes, `RefK` a VersionRef of kindK,
`Bytes` a CBOR byte string and `?` a value or CBOR null. No JSON compatibility
representation substitutes for the canonical record bytes.

Every domain record uses:

```text
[kind,1,networkB32,incarnationB32,generation,previousDigest?,idB32,payload]
```

The following are payloads in exact field order:

| Kind | Name | Payload |
|---|---|---|
|150|Foreign trust|`[bootstrapBytes,networkIdentity,approverKey,grant102,withdrawn]`|
|151|Agreement|`[treaty,foreign150,approverKey,grant102,withdrawn]`|
|152|Bridge|`[signedProfileBytes,managerKey,grant102,withdrawn]`|
|153|Author share|`[agreementId,Page16,publication142,revision141,authorKey,grant102,statementBytes,allowed,withdrawalGeneration]`|
|154|Qualified Page|`[agreementId,sourceIdentity,Page16,observed141,sourceShare153,pending155?,published156?,withdrawn]`|
|155|Imported revision|`[qualifiedPageId,agreementId,sourceIdentity,native141,share153,bundle203,importedAtMs,exportProofDigest,nativeRevisionPayload]`|
|156|Local review|`[revision155,reviewerKey,grant102,application148?,approve,statementBytes,decidedAtMs,mode,policyDigest?]`|
|157|Foreign floor|`[trustId,activatedEpochsJsonBytes,retainedJsonBytes,sealJsonBytes?]`|

`networkIdentity` is `[network,incarnation,bootstrapFileSha256,bootstrapFingerprint]`.
The file digest is raw SHA256; the fingerprint and record digests use the
purpose-separated wire digest. The JSON byte strings in157 use the existing
strict epoch archive schemas and canonical reserialization. They are not
unverified descriptor replacements. A157 resolves the accepted initial
bootstrap through each validated healthy transition, then verifies its retained
quorum/checkpoint and optional terminal seal.

The treaty is:

```text
[200,1,"FederationTreaty",agreementId,sourceIdentity,destinationIdentity,
 sourceBridge,destinationBridge,sourceNamespace,destinationNamespace,
 "HyperNetPage/2",
 [mediaProfiles,sourceHostKeys,destinationHostKeys,mediaBytes,copies],expiresMs]
```

The bridge profile's operator-signed payload is:

```text
[200,1,"AuthorityBridgeProfile",manifestBytes,serviceKey,volumeId,
 [[agreementId,treatyDigest],...],physicalStateBytes]
```

Agreement/profile lists are sorted and unique. Empty media consent uses empty
profile/host lists and zero media bytes/copies. Native media limits and exact
signed physical storage limits still apply.

Qualified Page IDs hash `"FederatedPage"` plus agreement, source network,
source incarnation and Page16 through the canonical domain identity function.
Imported revision IDs hash `"FederatedRevision"` plus qualified Page ID,
exact native141 and exact sharing153 references. Immutable155 has generation1.
The original source141 metadata, author statement, approved bundle and asset
SHA256 remain unchanged. Destination placement is separate local metadata.

## Finite operations

All operations are ordinary signed `AuthorityDomain` Intents. Their parameters
remain `[200,1,"AuthorityDomain",grant102?,command,snapshot]`. The following
command arrays give the exact fields after the string command name:

| Command name | Remaining fields |
|---|---|
|FederationContext|`action,resource,namespace?`|
|FederationSourceContext|`agreementId,Page16?,afterShareId?`|
|FederationInventoryContext|`agreementId,action`|
|FederationPageContext|`agreementId,Page16,action`|
|FederationTrustAccept|`bootstrapBytes,networkIdentity`|
|FederationTrustGet|`trustId`|
|FederationTrustWithdraw|`trust150`|
|FederationAccept|`treaty,foreign150`|
|FederationGet|`agreementId`|
|FederationAgreements|`afterId?`|
|FederationWithdraw|`agreement151`|
|FederationBridgeRegister|`signedProfileBytes`|
|FederationBridgeGet|`serviceKey`|
|FederationBridgeWithdraw|`bridge152`|
|FederationShare|`sharePayload`|
|FederationShareStatus|`agreementId,Page16`|
|FederationUnshare|`share153`|
|FederationAdmission|`agreement151,bridge152,Page16?,exchangeNonce,native141?,afterShareId?`|
|FederationExport|`agreement151,bridge152,admissionProofBytes,includeBundle,inventorySelection?`|
|FederationImport|`agreement151,bridge152,exportProofBytes,bundle203`|
|FederationQueue|`agreementId,afterId?`|
|FederationInspect|`qualifiedPageId,exportProofBytes`|
|FederationReview|`reviewPayload,exportProofBytes`|
|FederationList|`agreementId,exportProofBytes`|
|FederationRead|`qualifiedPageId,exportProofBytes`|
|FederationPageWithdraw|`page154`|
|FederationContentAuthorise|`placement159,host147,1,offset,count,admissionProofBytes`|
|FederationMediaGet|`asset144,proofBytes`|
|FederationMediaAuthorise|`asset144,host143,effect,offset,count,rawChunkSha256?,proofBytes`|
|FederationMediaReceipt|`copyReceiptBytes,proofBytes`|
|FederationMediaInspect|`asset144,copyReceiptBytes,expiresMs,proofBytes`|
|FederationForeignSeal|`trust150,floor157,terminalEvidenceBytes,historyBytes`|
|FederationForeignActivate|`trust150,floor157,readyBytes`|

SourceContext is metadata-only maintenance by the exact current source role7
bridge. It selects either one Page or an inventory after-cursor and returns the
current agreement, bridge, accepted trust, foreign floor, native publication,
author share and all relevant rights and media metadata. It accepts no borrowed
member capability. It requires no immutable input and releases no Page body.
Export, Import, Inspect and Read carry metadata only. The includeBundle field
requests a separate direct Bridge body transfer; it never adds an authority
input or output object. Source context includes current159/160/161 placement,
acknowledgement and withdrawal metadata. A destination namespace that permits
only sealed content refuses host-readable Admission and Import before caching.
Sealed publications have no confidential Federation export protocol here.

An inventory Export signs `inventorySelection = [throughShareId?, [shareId,...]]`.
The IDs are the exact sorted unique selection returned by SourceContext, each
strictly after Admission's cursor. The end equals the final selected ID; both
are empty/null for an empty selection. A Page Export requires null selection.
Export evaluates only those IDs against current authority and exact dependencies.
Its actual result budget, including the successor157, may select a smaller
complete prefix. Nonempty results continue at the last admitted ID; an empty
round terminates discovery. A cached, omitted share cannot expand the selection.
The context verifier reconstructs this result from its exact returned records
and independently checked governance, then merges verified records into the
cache without removing omitted records or lowering retained versions.

InventoryContext supports read0 or review3 in the destination namespace.
PageContext supports read0, review/withdrawal3 or source share4. These operations
return required metadata only. Destination Page context includes the selected
revision's media placements, retained copy and inspection evidence, relevant host
authority and namespace placement policy. This lets a cold reviewer or reader
prepare the next exact operation from certified records. Metadata does not grant
media access or publication approval; those operations recheck current authority,
host consent, required copies and exact inspections.
A grantless restrictive metadata lookup is
limited to the exact recorded owner; it does not expose Page bodies or create
new permission. Bridge maintenance has no member grant and must match its
current registered role7 and treaty. Broad membership never implies these rights.

Admission selects either an exact Page, optionally exact141, or an inventory
cursor; the two selectors cannot be mixed. Page-specific Admission also selects
the agreed destination media hosts and their current consent and governance,
namespace placement policy, and retained state for that exact qualified Page.
Its certified result supplies a cold Bridge cache with the dependencies needed
for first import and subsequent synchronisation. Inventory Admission does not
export unrelated imported Pages. Existing result and proof size limits apply.
Inventory continuation is derived
from the actual encoded result and its64-version budget. A complex item does
not bypass proof closure, and an unfit first item is unavailable rather than
silently skipped. A refused domain result retains its usual finite refusal
schema and cannot carry a renderable object sidecar.

## Portable proofs and freshness

The proof envelope is:

```text
[200,1,"FederationProof",localTrust150,localFloor157,exactLocal157Bytes,
 remoteOrdered22Bytes,remoteResult24Bytes,remoteExecutedQuorumEnvelope,
 ancestryNodeBytes,checkpointProofBytes?,historyProofBytes?,
 exactRemotePredecessor157RecordBytes]
```

Only an Admission leaf and an Export containing that leaf are legal. Arbitrary
recursive proofs or another action label fail before recursive evaluation.
The accepted local150 selects the foreign initial bootstrap. Actual local157
selects its current descriptor and retained prefix. Verification checks the
executed quorum, ordinary request/result/challenge binding, current epoch,
ancestry or checkpoint/history continuity, exact predecessor references,
complete returned dependency records and independently evaluated finite result.
Three detached signatures are insufficient.

Each protected operation uses the existing bounded monotonic challenge and
conservative clock uncertainty. Parsing or fetching bytes cannot extend that
deadline. A stale cached lease cannot authorise review, reading or media. Exact
original-result recovery can recognise only the immediate correctly derived157
successor; an arbitrary newer floor never repairs a stale signed precondition.

Healthy foreign replacement uses explicit ForeignSeal and ForeignActivate with
terminal history and Ready evidence. Exceptional recovery changing network or
incarnation requires independently accepted new trust. An old bootstrap pin or
same public key does not establish continuity automatically.

## Media and persistence

A foreign asset144 refers to immutable155 instead of native141. Its original
canonical media descriptor still binds source bytes with raw SHA256. Destination
host references must come from the exact treaty and current role2 consent.
Source fetch requires a fresh exact destination Admission and current source
share. Destination upload and copy receipts require a fresh source Export and
current pending155. Local inspection and reading also check their respective
current local capability/application rules.

`FederationMediaAuthorise` uses the existing typed MediaRequest, recipient
challenge, claimed single effect, complete decoder and signed MediaReceipt.
Normalization selects only the finite media effect; the signed operation stays
FederationMediaAuthorise and its157 mutation is independently verified. The
recipient is the exact currently registered host143 service, never a caller
selected arbitrary key. Media receipt recovery retains only certified monotone
metadata from the exact original request before publishing its cache and
acknowledging completion.

Consensus retains signed Page metadata and exact permission/receipt closure;
PageSource, PageBundle, bitmap/vector bodies and animation frames stay outside it.
FederationContentAuthorise is a distinct source-only action with effect1 (read)
and a1..32768-byte extent. It transfers only HostReadable native publications. It requires the exact current native159 placement, selected
role1 host, current author share/treaty/Bridge consent, and fresh exact destination
Admission for that native141. Its signed action remains distinct while using the
existing ContentExchange recipient claim and receipt verifier. The source is at
most16384bytes and must rebuild the exact approved bundle from signed metadata.
Treaty media host lists still describe role2 assets; they do not replace the
author's body placement or infer a route to its role1 hosts.

Bridge storage uses a preallocated two-bank file within its signed physical
budget. Direct bundle cache entries may expire or be evicted and do not count
as durable body copies. Imports preserve their reference without requiring the
body in authority state. Upload payloads are
retained before preparing their exact outgoing request. Uncertain effects retain
that request for explicit reconciliation; they do not allocate a new stream or
silently substitute a new proof. Local activation consent, withdrawal and clock
health continue to apply to every new action and service loop.
