# Authority wire contract

This document specifies the replacement authority contract for HyperNet 0.8.0.
The native offline trust tools implement the bootstrap subset described below.
Serving authority still uses the existing trusted backend. A specification or a
valid signature does not establish an operational Byzantine network. Activation requires the
complete authority, consumer, routing and runtime contracts.

Core and Suite distribute the same specification and conformance vectors.
Each product builds independently. Neither requires a sibling source checkout.
There is no negotiated fallback from this contract to a single-signer authority.

## Encoding

Use the deterministic CBOR rules of RFC 8949 section 4.2.1, restricted as below.
The binary record is the signed object; JSON is only a diagnostic/vector view.

- Records are definite-length arrays with a fixed field order and exact arity.
  The first two fields are the unsigned record kind and contract version `1`.
- Integers are unsigned, at most `2^64-1`, encoded with the shortest argument.
  Arithmetic overflow fails. Negative integers, floats, tags and maps are refused.
- Byte strings and text strings have definite lengths and shortest length headers.
  Text is strict UTF-8. Identity and digest fields are byte strings, never text.
- Booleans and null are permitted only where the field schema allows them.
  There are no implicit defaults, coercions, extensions or trailing bytes.
- A decoder rejects noncanonical encodings before signature verification. It
  never normalises an alternative encoding into an accepted signed object.
- Maximum encoded record size is 262144 bytes, nesting depth 16, array length
  4096 and individual text length 1024 UTF-8 bytes. Field-specific limits can
  only narrow these ceilings. Embedded encoded records count toward all limits.
- Ordered sets are lexicographically sorted by their canonical identifier bytes,
  with no duplicates. Sequences preserve their declared order. A parser cannot
  silently reorder a set supplied in the wrong order.

An unsigned integer in a JSON fixture is a decimal string without a leading zero,
except `"0"`. Byte strings use lowercase even-length hexadecimal. The fixture
type determines conversion; text resembling hexadecimal is not converted by
guessing. JSON fixtures are not themselves signature messages.

`Scope` is the fixed nested array
`[network, incarnation, configurationDigest, epoch]`. The first three values are
32-byte strings; epoch is unsigned. Other primitive types are `Id` and `Digest`
(32 bytes), `Key` (32-byte Ed25519 public key), `Signature` (64 bytes), `U64`,
`Bool`, and `Label` (ASCII `[A-Za-z][A-Za-z0-9]{0,63}`). They retain distinct
semantic types even where their encodings match. All-zero Id and nonce values
are refused. Empty keys and all-zero keys
are not placeholders for missing authority. Nullable fields use actual null.

## Digests and signatures

Let `P` be the complete canonical payload record and `L` its byte length encoded
as four unsigned big-endian bytes. Record identity is:

```text
SHA256(ASCII("HyperNet/RecordDigest/1") || 00 || L || P)
```

An Ed25519 signature by public key `K` covers exactly:

```text
ASCII("HyperNet/RecordSignature/1") || 00 || L || P || K
```

The record kind, version and field bindings are inside `P`. A verifier requires
the expected kind and checks key authority for that kind. A recipient signature
cannot become a recovery signature or a consensus vote by changing the caller.
Use strict verification, including canonical signature scalar and public-key
checks supplied by the maintained Ed25519 implementation. No algorithm choice
or alternate digest is carried in untrusted input.

A signed envelope is `[0, 1, payloadBytes, signatures]`, where signatures is a
sorted list of `[Key, Signature]`, at most four for authority records and at most
three for recovery records. An ordinary device record has exactly one signature.
Unknown, repeated, extraneous or unauthorised signers cause rejection; they are
not silently discarded. A valid signer counts once. This wrapper is not itself
signed. Its signatures all cover the same exact `P`, each bound to its own `K`.

Raw content SHA-256 remains distinct from a record digest. The outer publication
names the exact stored ciphertext digest; inner approvals name exact plaintext
and media digests. No record includes its own digest or signature recursively.

## Consensus records

These arrays specify order after the kind and version prefix. All digests below
are record digests unless explicitly identified as content digests.

| Kind | Name | Fields in order |
| --- | --- | --- |
| 10 | TrustDescriptor | network:Id, incarnation:Id, epoch:U64, voters:list(Key), policy:Digest, recoveryPolicy:Digest, genesisGovernance:Digest, bootstrapTimeMs:U64, protocol:Label |
| 11 | Vote | scope:Scope, view:U64, phase:U64, node:Digest |
| 12 | QuorumCertificate | scope:Scope, vote:bytes-or-null, signatures:list([Key,Signature]) |
| 13 | NewView | scope:Scope, targetView:U64, highestPrepareQc:Digest |
| 14 | Node | scope:Scope, view:U64, height:U64, parent:Digest-or-null, command:Digest-or-null, evaluatedAtMs:U64, justifyPrepareQc:Digest-or-null |

Quorum-certificate references are the sole exception to the full-record digest
rule. After verifying a complete kind-12 certificate, compute its identity as
`RecordDigest(CBOR([12,1,Scope,votePayloadOrNull,[]]))`. This canonical projection
is only a digest preimage: it is never an accepted non-genesis certificate with
an empty proof. Non-null votes still require three or four verified, distinct,
eligible signatures in the transmitted certificate. Node justification,
NewView Prepare references and kind-12 repair references use this identity, so
signer subsets or alternate valid proof signatures cannot create new stored
certificate identities. Retain the first valid proof for an existing identity;
never replace it with an unverified or empty projection. Scope, vote phase,
view and node remain inside the identity. Genesis keeps its existing identity.
Other record identities and transport-message digests continue to hash their
complete canonical bytes.

GenesisGovernance is kind 15:
`[15, 1, network:Id, incarnation:Id, records:list(bytes), roleReservations]`. Records contains the
exact canonical unsigned payloads for one initial NetworkPolicy, one
RecoveryPolicy, one RuntimeBootstrapKeys131, 1-16 initial TierPolicy records and
1-16 root Grant records.
They are sorted uniquely by `(kind, record lookup Id)` as defined in
PolicyContract. No other kind is allowed. Every record has the same network and
incarnation, generation one and null predecessor. Policy records have null
expectedSnapshot; immutable131 has no Snapshot field. The
whole bundle obeys the 262144-byte record ceiling. Its record digest is the
descriptor's `genesisGovernance`. The separately named policy and recoveryPolicy
digests must equal their exact records in this bundle.

Role reservations are sorted unique `[role, Ed25519Key]` pairs, at most64,
with no key shared between roles. Roles0-4 are authority voter, recovery,
relay transport, admission transport and genesis governance administrator.
Roles5/6 are the distinct authority transport and clock monitor keys in131.
The exact set must match the descriptor voters, recovery keys, accepted route
transport keys, root-grant subjects and131 bindings. The genesis digest commits this set.
Reservations persist after role changes and cannot become ordinary membership
or delegation subjects. A reservation grants no runtime capability.

Verify complete references, grant/tier limits, roles and proposed recovery-policy
acceptance before accepting bootstrap. NetworkPolicy.policyAuthority names exactly
the supplied root Grant IDs. Root grants name exact administrator public keys,
actions, scopes, validity and tiers; their issuer equals their subject at genesis.
Those exact subjects receive initial governance admission for the listed grant
capabilities. No ordinary reader membership, hosting consent, recipient access,
service registration or voting authority is derived from it. Administrator keys
must be distinct from voting and offline recovery keys. The descriptor-pinned
bundle authorises only these genesis records; an ordinary command cannot use null
snapshots to create additional root authority.

The accepted genesis policy state is this bundle's digest at height zero. It is
computed before the descriptor and contains no configurationDigest, descriptor
hash or self-reference. Subsequent state and grants require ordered commands and
certified snapshots. Independently authenticated descriptor acceptance pins the
entire initial governance state, not merely names that a broker may fill later.

The initial descriptor has exactly four sorted unique voters, epoch zero and
protocol `BasicHotStuff`. Its record digest is `configurationDigest`. All fields
are pinned through independently authenticated bootstrap; a timestamp alone does
not establish a current bootstrap. The descriptor never stores its own digest.
Network and incarnation are fresh independent random identifiers. Genesis is the
unique Node with this Scope, view and height zero, null parent/command/justify,
and `evaluatedAtMs` equal to `bootstrapTimeMs`. Normal views/heights start at one.

Vote phase is `0=Prepare`, `1=PreCommit`, `2=Commit`; other values fail.
A normal QC embeds the canonical kind-11 vote payload, plus three or four valid
signatures over that payload. Its Scope must equal the vote Scope. The only QC
with a null vote has no signatures and denotes genesis in the independently
pinned configuration. It cannot authorise a non-genesis decision or result.

NewView carries its referenced complete prepare QC as a separately bounded
sidecar. The digest, Scope, phase and target-view relation must all match. Nodes
carry their referenced parent/command/justification as bounded sidecars or obtain
them through authenticated bounded retrieval. Missing dependencies prevent voting.
An envelope digest never substitutes for a verified payload or chain.

The phase, persistence and view rules are in [AuthorityContract.md](AuthorityContract.md).
A prepare QC or commit vote by itself does not certify an executed result.

## Offline bootstrap preparation

Offline preparation uses two additional canonical records:

| Kind | Name | Fields in order |
| --- | --- | --- |
| 30 | Bootstrap | descriptor:bytes, genesis:bytes, recoveryAcceptance:bytes-or-null, route:bytes |
| 31 | BootstrapRoute | network:Id, incarnation:Id, relayService:Id, relayOrigin:text, relayTransport:Key, relayDomain:Id, admissionService:Id, admissionOrigin:text, admissionTransport:Key, admissionDomain:Id, assurance:U64, notBeforeMs:U64, expiresMs:U64 |

Descriptor, genesis and route contain their complete canonical record bytes.
RecoveryAcceptance is the signed envelope over the exact genesis RecoveryPolicy
payload, verified against that policy's proposed custody threshold. It is not a
kind-116 successor-recovery acceptance. Null is permitted only in an unaccepted
local draft. A client refuses a draft as prepared trust.

The independently authenticated fingerprint is the kind-30 **record digest of
this entire bundle**. Pinning only the descriptor does not authenticate route
metadata. Clients also retain the descriptor digest for subsequent authority
verification. All nested records retain their normal size, type and depth bounds.
Network/incarnation and every governance reference must agree before acceptance.
Voter, administrator, recovery and transport roles use distinct identities.

Assurance is Organisational=0 or Independent=1, as in NetworkPolicy. Origins are bounded HTTPS origins,
with no credentials, query, fragment or application path. Both service identities,
transport keys and declared control domains are pinned. Independent mode requires
different declared relay and admission domains. The stronger network/client
privacy minimum prevails. A signature authenticates a declaration; it cannot prove
independent operators or absence of collusion.

This is an offline route plan. It carries no invitation, relay voucher, service
registration, current quorum evidence or membership. Expired route material is
refused. Preparation produces `OfflinePrepared`, not a live connection. Online
joining remains unavailable until the mandatory relay connector is implemented.
The current trusted authority backend cannot serve as a BasicHotStuff network
merely because such a draft was prepared. Runtime setup and offline trust drafting
remain separate until the replacement authority and route consumers are integrated.

## Requests, recipient challenges and executed results

An immutable intent is created before a recipient issues a challenge. This avoids
a circular dependency between request identity and challenge identity.

| Kind | Name | Fields in order |
| --- | --- | --- |
| 20 | Intent | network:Id, incarnation:Id, generation:U64, generationId:Digest, sequence:U64, acknowledgedThrough:U64, requester:Key, action:Label, resource:Id, revision:U64, profileGeneration:U64, minimumPolicyEpoch:U64, minimumPolicyHeight:U64, expected:list([U64,Id,U64,Digest]), parameters:bytes |
| 21 | Challenge | network:Id, incarnation:Id, recipient:Key, bootId:Id, nonce:Id, intent:Digest, clientNonce:Id, createdAtMs:U64, expiresAtMs:U64, maximumDurationMs:U64 |
| 22 | OrderedRequest | scope:Scope, intent:bytes, challenge:bytes, expiresAtMs:U64 |
| 23 | ExecutedResult | scope:Scope, height:U64, committedNode:Digest, orderedRequest:Digest, intent:Digest, challenge:Digest, requester:Key, recipient:Key, action:Label, resource:Id, revision:U64, profileGeneration:U64, maximumEffect:U64, result:Digest, policyState:Digest, minimumPolicyHeight:U64, evaluatedAtMs:U64, expiresAtMs:U64, consent:Digest-or-null, placement:Digest-or-null, route:Digest-or-null |
| 24 | OperationResult | action:Label, disposition:U64, code:U64, value:bytes |

Intent and Challenge are signed by their named requester and recipient. Their
signed envelopes are embedded in OrderedRequest. Intent expected records are sorted
by `(kind,Id)` and unique, at most 64. Each tuple binds an exact generation and
digest, including all relevant policy, audience, device, consent and placement
records. A missing required expectation is refusal, not an unconditional update.
The Node command digest is the digest of this exact OrderedRequest payload.
The broker cannot edit the signed expectations. OrderedRequest expiry may only
narrow the signed challenge expiry and applicable credential deadlines. It cannot
extend authority. A reply includes this exact OrderedRequest and its result
certificate binds its digest; consumers check the embedded signed intent,
challenge and expiry relationship before accepting it.

`parameters` and `value` contain one canonical action-specific typed record.
Only an explicitly implemented action schema may be accepted. Unknown labels,
opaque unchecked extensions and arbitrary executable commands are refused.
Action schemas define the resource type and the unit of `maximumEffect` (for
example, bytes or one mutation). Zero is zero; no numeric sentinel means unlimited.
All dispositions bind the same request context. Disposition is Permit=0,
Refuse=1 or Pending=2; only Permit with code zero permits an effect. Refuse and
Pending require `maximumEffect=0`. Codes are the finite values in PolicyContract;
unknown or inconsistent code/disposition combinations fail.

Each honest replica signs the same ExecutedResult only after commitment and
durable deterministic execution. The application response supplies its complete
OperationResult; consumers verify its exact digest and action before using it.
The authority proof requires three or four distinct signatures from the pinned
current descriptor. Endpoint TLS and one broker signature cannot replace it.

The consumer checks all of the following before releasing an effect:

1. Canonical bytes, exact kinds, signatures, pinned Scope and voter membership.
2. Requester proof of possession, intended recipient, exact intent/challenge,
   boot identifier, nonce, action, resource, revision and profile generation.
3. Persisted configuration/height floors and current object minimum policy height.
   Permit evaluation follows the signed preceding-state floor and every retained floor.
   A finite refusal can report an unmet requested floor. A recent old permission cannot
   authorise content created under a later policy state.
4. Challenge deadline, signed expiry and known revocations. The original deadline
   includes verification and buffering; relays and retries cannot restart it.
5. Actual current local consent, client route minima, placement and object
   restrictions. Their required digests must match; null is legal only when the
   action schema establishes that the restriction is inapplicable.
6. Exact result bytes, signed maximum effect and durable idempotency state.
   Persist increased trust floors before acting. If persistence fails, refuse.

Challenge IDs and client nonces are 32 random bytes from an OS CSPRNG. Boot IDs
change on each process start. A process restart invalidates outstanding challenges;
restoring a saved deadline cannot create a live permission. An honest consumer
checks elapsed time with a suspend-aware monotonic clock such as Linux
`CLOCK_BOOTTIME`. Ordinary challenges have a maximum 5000-ms interval from local
creation. The finite federation maintenance operations in AuthorityContract.md
have a separate 15000-ms maximum, derived from the exact signed request.
Every dependent step inherits the earliest applicable expiry. A delayed
operation fails rather than extending an existing permission interval.
Long streams and supervised services revalidate before this original interval
ends; no new application bytes or subprocess activity may be authorised afterward.

Client and service consumers with independent freshness needs each originate a
challenge. A service challenge alone cannot convince a reader of freshness. Each
required proof binds the same exact intent and publication; the effective deadline
is the earliest. Challenge creation and early route admission confer no read right.
Absolute time validation and clock-health refusals follow AuthorityContract.md.

## Consumers and replacement

The same evidence checks apply to admission, directory, Pages, media, mail,
transfers, SSH, storage, bridges, search, route registration and policy changes.
An unconverted consumer cannot participate in the replacement deployment.
Historical publication signatures prove content provenance; they are never live
read permissions. Search indexes, cache entries and restored backups have no
independent authority. A stale or unavailable quorum produces refusal.

No current endpoint accepts this future contract until its complete consuming
workflow is implemented. A fresh deployment has one active authority contract.
Old deployments keep their own binaries/state. Inert content import revalidates
bytes and obtains fresh approval; it does not import old keys, permissions,
consents, recipient continuity or federation authority.

Canonical byte examples and rejection cases are in
[WireVectors.json](WireVectors.json). Policy transitions and field schemas are in
[PolicyContract.md](PolicyContract.md). These documents are specifications;
executable conformance and installed Byzantine qualification are distinct evidence.

Encoding reference: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).

## Replica transport and local inspection

The synchroniser WISH payload is `[16,1,Scope,targetView]`. One eligible
replica signs it with the common envelope. A receiver retains each peer's
maximum target view. For four replicas, the third-highest maximum determines
`view`; the second-highest determines `viewPlus`. A view is entered only when
these values coincide above the previously entered view. Advance, relay and
periodic resend follow the multi-shot synchroniser in Figure 3 of
[Bravo, Chockler and Gotsman](https://arxiv.org/pdf/2202.06679).
State is persisted before its WISH or NewView is sent.

Each peer message is `[40,1,Scope,senderKey,messageType,payloadBytes]`, signed
by that eligible sender. TLS 1.3 mutual authentication verifies an independently
configured certificate chain and exact SHA256 leaf pin before application data.
The leaf pin maps to the same replica key as the signed envelope. Redirects,
proxy discovery and early data are disabled. TLS identity is not a consensus vote.

| Type | Exact decoded payload |
| --- | --- |
| 0 | Signed WISH envelope |
| 1 | `[signedNewView, prepareQc]` |
| 2 | `[signedLeaderNode, orderedRequest, justifyPrepareQc, inputSidecar]` |
| 3 | Signed Vote envelope |
| 4 | QuorumCertificate |
| 5 | `[repairId, [[kind,digest,signerOrNull],...]]` |
| 6 | `[repairId, [[kind,digest,signerOrNull,recordBytes],...]]` |
| 7 | `[nodeBytes, signedExecutedResult, operationResult]` |
| 8 | `[orderedRequest, inputSidecar]` |
| 9 | `[orderedRequestDigest]` |
| 10 | `[peerRecordDigest, transportStatus]` |
| 11 | `[singleSignedCheckpoint,anchorNode]` |
| 12 | Complete kind46 CheckpointProof |
| 13 | `[transferId,checkpointDigest,stateChunkIndex]` |
| 14 | `[transferId,checkpointChunkBytes]` |
| 15 | `[transferId,checkpointDigest,firstLeafIndex,count]` |
| 16 | `[transferId,checkpointDigest,firstLeafIndex,[nodeDigest,...]]` |
| 17 | `[transferId,oldCheckpointDigest,newCheckpointProofBytes]` |
| 18 | `[requestId,inputAnchor,reference203]` |
| 19 | `[requestId,inputAnchor,reference203,bodyBytesOrNull]` |

Embedded records use their exact canonical bytes. Transport status is 0 for
accepted or duplicate and 2 for refusal. It confers no authority. Repair imports
only complete dependency closures rooted in verified quorum certificates and
previously requested from that peer. Raw votes and executed shares cannot
authorise persistent dependencies. Unsolicited records, unrelated records,
duplicate references and mismatched response identifiers fail. Learning a
committed branch through repair does not create an old-view vote. A type-9 query
returns the retained deciding Commit certificate as type 4 before its type-7
executed share, allowing certified ancestry repair.

Per-peer requested repair retains at most32 active records and1MiB of active
record bytes, with at most16 requested records per packet. Up to eight original
QC goals and eight waiting messages remain separately bounded. If backwards
discovery would exceed the staging budget, it pivots to a verified parent
PrepareQC, discards only transient upper bodies and later re-fetches the original
goals. Only complete independently QC-rooted subclosures become durable; a
partial import cannot replace the original goal. At most65536 such pivots are
permitted per repair. Existing response identity, peer, reference and stale-node
checks apply unchanged.

The owner-only Unix control socket checks the connecting UID. A frame is a
four-byte big-endian length followed by a canonical record, bounded by the
common maximum. Requests are `[41,1,Scope,operation,payloadBytes]`:

| Operation | Decoded payload |
| --- | --- |
| 0 | `[orderedRequest,inputSidecar]` |
| 1 | Exact 32-byte OrderedRequest digest |
| 2 | Empty array |
| 3 | `[floorHeight,floorNodeDigest,targetNodeDigest]` |
| 4 | `[floorHeight,floorNodeDigest,targetNodeDigest,priorTreeSize,priorTreeRootOrNull]` |
| 5 | Empty array; local signer status only |

Ordinary replies are
`[42,1,Scope,status,code,orderedRequestOrNull,nodeOrNull,executedCertificateOrNull,operationResultOrNull,outputSidecar]`.
Status is Pending=0, Certified=1 or Refused=2. Code is None=0, Unavailable=1,
Malformed=2, Capacity=3, ClockUnknown=4 or HistoryOvertaken=5. Only a complete quorum-certified
kind 23 result over the supplied kind 24 bytes can authorise a consumer effect.
A Pending acknowledgement, process status or local diagnostic cannot do so.
An exact request may be queried through another replica after its reply is lost.
Its original recipient challenge and deadline remain unchanged.

The mandatory output sidecar retains its exact reference/body framing. Native
and federated Page authority results carry metadata and an empty object sidecar.
Page source and ciphertext travel through separately authorised finite content
exchanges to exact consented hosts. Clients verify current publication metadata,
content placement, host identity and hashes before reconstructing a viewer bundle.
No authority object-get operation supplies Page bodies or bypasses this boundary.

Successful operation 3 returns `[43,1,Scope,[nodeBytes,...]]`, containing at most
128 contiguous nodes strictly after the named floor through the named target.
The floor must be an exact ancestor at the stated height. Unknown ancestry or
exceeded bounds refuse; a client cannot skip from its floor to an unlinked node.
These unsigned local bytes gain meaning only when independently verified against
the client's durable floor and the target's executed-result quorum certificate.

Successful operation 5 returns
`[59,1,Scope,signer,generation,view,committedHeight,appliedHeight,clockReady]`.
These are unsigned local diagnostics for the same-UID operator. A retained height
or healthy clock does not prove current quorum availability or authorise an
effect. The normal local client reports quorum as `NotProbed`, checks the exact
scope and signer against its retained deployment, enforces the independent signer
generation floor, and limits the response to 4096 bytes within one five-second
deadline. It does not acquire the active signer's exclusive journal lock.

## Finite operation payloads

Kind 200 parameters are `[200,1,action,...fields]`. Each native action has one
finite, fixed-order typed schema. Parsers reject unknown commands, incorrect
arity, field types and alternate encodings. Domain parameters are
`[200,1,"AuthorityDomain",grant102|null,command,Snapshot]`; the typed command
must match the signed resource, revision and snapshot. Embedded owner provenance
retains its exact preimage and domain signature. It never supplies a live
authority result. Bulk Page source and publication bundles remain outside the
ordered log.

For Domain execution, Snapshot's point is a causal floor in the current epoch.
Its height cannot exceed the committed pre-state height. At equal height its
state digest must equal that pre-state; at an earlier height the historical
digest does not authorise the operation or assert that the current state is
unchanged. Every fresh Domain mutation recomputes its complete current dependency
set and requires exact equality with the signed expected versions. It also
rechecks current authority, expiry, consent, target identity and generation,
absence constraints and available capacity. Unrelated read or receipt commits
therefore do not invalidate a mutation; a relevant change still refuses. The
result remains bound to its actual committed state and the consumer verifies
continuity from its own retained floor. Delegation, member admission,
application/deployment registration and withdrawal, and grant revocation use
the same causal-point rule with their complete current dependency and identity
checks. Reconfiguration retains its explicitly defined snapshot requirements.

Kind 201 results are `[201,1,action,versions,...fields]`. Versions is the exact
sorted, unique bounded VersionRef list certified for the action. Every action
has an explicit result shape and disposition. Refusal contains no protected
record or effect. Pending requires its action's explicit pending shape; an
unknown mapping refuses rather than forwarding a legacy authority signature.
Semantic result shape alone is insufficient: the consumer also checks the exact
retained action, resource, revision, profile, restrictions and current versions.

A native Page identifier is the common record digest of
`[202,1,2,"Page",rawPage16]`, where the 16-byte identity is nonzero. A namespace
identifier is the common record digest of `[202,1,1,"Namespace",name]`. Its name
contains 1-32 ASCII alphanumeric bytes, begins with a letter and is case-sensitive.
The scope kinds are Object=2 and Namespace=1 from PolicyContract.

A foreign Page uses the common record digest of
`[200,1,"FederatedPage",agreement,sourceNetwork,sourceIncarnation,rawPage16]`.
Its source and agreement remain part of the identity; it cannot become a native
Page by reusing the short Page identifier. No generic resource-class decoder
creates identities for other domains.

A staged object reference is `[203,1,class,contentSha256,byteLength]`.
`contentSha256` is raw SHA256 over exactly `byteLength` bytes, not the common
record digest. A consumer verifies both before parsing. References cannot
instruct a consumer to fetch an arbitrary URL or path. Domain-specific parsing,
permission and content approval still apply after the digest check.

The immutable input sidecar is the sorted unique array
`[[reference203,bodyBytes],...]`. It contains exactly the references declared by
that signed operation. Native Page submission, review, read, replica delivery and
federated publication commands are metadata-only and use an empty array.
PageSource is at most16384bytes; PageBundle is at most57344bytes. These references
identify exact content without retaining its body in authority history.

Content placement159 binds an exact revision or outer113, owner capability,
namespace, raw SHA256, length, opaque flag, selected host147 references, required
copies, failure-domain count and expiry. Upload, inspect, read, repair and purge
are separate finite actions. Each signed content request binds placement, exact
host, effect, offset, length and an upload digest where applicable. A chunk is
at most32768bytes. Recipient challenges, current authority and durable requester
floors apply to each exchange, including retries. Filenames, arbitrary URLs and
network-supplied host paths are not transport parameters.

Complete-copy160 receipts are signed only after exact body verification and
local durable storage. Tombstone161 stops serving independently of physical
cleanup. Approved source is retrieved directly and checked against its signed
author metadata; the viewer constructs the approved bundle locally. Bitmap and
vector bodies remain on explicitly consented hosts. Animation frames are
produced by the viewing client and are not replicated as authority data.

The generic authority input repair transport remains bounded to explicitly
referenced objects in a verified command or checkpoint closure. Missing bytes
prevent voting or execution; they do not create an ordered refusal. Type18 names
`[0,quorumCertificateDigest]` or `[1,checkpointDigest]`; type19 must match the
active request, anchor, exact reference and deadline. This transport does not
make Page bodies part of consensus history or grant a content read permission.

The local policy-inspection action uses
`[200,1,"AuthorityInspect",grantId,recordKind,lookupId]`. The resource is the
exact lookup ID, revision is the exact requested generation, and profile is
zero. The requester supplies its own recipient challenge and an explicit
InspectAudit capability. It has no content retrieval, hosting, placement or
reader-routing effect. Applicable governance dependencies must match the signed
intent; tier rank supplies no authority.

A permitted inspection value is
`[201,1,"AuthorityInspect",versions,recordBytes]`, where versions is the sorted
union of the complete capability dependencies and exact target VersionRef.
The returned canonical record must match that reference and the requested kind,
network, incarnation and generation. A refusal value is
`[201,1,"AuthorityInspect",[]]`. The maximum semantic effect is one for Permit
and zero for Refuse. The consumer persists its certified floor and consumes its
fresh challenge before displaying the verified record.

## Current governance and exact revocation

Explicit context discovery uses
`[200,1,"AuthorityContext",grantId,knownPoint,cursorOrNull]`.
Point is `[epoch,height,policyStateDigest]`; its height is intent minimumPolicyHeight.
Resource is network, revision/profile are zero and intent expected is empty.
The executor checks current network-scoped InspectAudit authority. A current-height
point must match the exact pre-state; an earlier point supplies a causal floor.

The permitted value is
`[201,1,"AuthorityContext",pageVersions,[recordsRoot,totalCount,startIndex,nextIndexOrNull,recordBytes]]`.
Each page contains at most64 whole records and32768 encoded result bytes. The
complete set has at most2048 records of kinds100,101,102,105,114,117,125-131.
The root is RecordDigest of
`[200,1,"AuthorityRecordsView",[N,I,epoch],allSortedVersionRefs]`.
A non-null cursor is `[recordsRoot,totalCount,nextIndex]`. Every continuation
rechecks current authority and root/count; a changed view refuses StaleSnapshot.
Receipt-only state changes do not change this records root.

The consumer privately stages consecutive pages, validates each proof and exact
record references, and persists its certified floor. It installs complete context
only after verifying the full root and all locally retained minimum versions.
It does not transmit the complete retained minima with every page. Partial context
is never presented as complete. Exact pending requests remain resumable; explicit
discovery restart requires an unresolved request to be resolved or fenced first.

Exact revocation uses
`[200,1,"AuthorityRevokeGrant",grantId,targetGrant,expectedSnapshot]`.
TargetGrant is an exact kind102 VersionRef. Intent resource/revision name its
ID/generation; profile is zero. Snapshot dependencies equal intent expected
and contain the exact pre-state capability dependencies plus target. Its Point
is a causal floor in the current application epoch; an equal-height point must
match the complete state digest. Its height is the intent minimumPolicyHeight.

Current network-scoped RevokeGrant authority is required. The transition
inserts the immutable kind126 tombstone defined in PolicyContract, with the
requester as revoker and this exact expectedSnapshot. Its result is
`[201,1,"AuthorityRevokeGrant",dependenciesAndTombstone,tombstoneBytes,creationHeight]`.
The consumer independently constructs those bytes from its retained pre-state.
The result may revoke its own authorising grant; authorisation is checked
against the pre-state, and subsequent requests observe the revocation.
No new request can replace a tombstone or reuse its grant ID. An exact recorded
retry never reapplies the mutation and still requires current authority.

Both actions use the requester's own fresh recipient challenge. Refuse has
`[201,1,action,[]]` and effect zero; Permit has effect one. The journal commits
changed records, durable mutation evidence and the exact operation receipt together. Capacity refusal
cannot apply a partial mutation or discard replay history. A mutation timeout
is an unknown outcome, not proof that the change did not occur. The client
never automatically changes its target, snapshot or authorising grant.

## Grant delegation and member acceptance

Create-only delegation uses
`[200,1,"AuthorityDelegateGrant",parentGrant,childSpec,expectedSnapshot]`.
ParentGrant is an exact kind102 VersionRef. ChildSpec is
`[grantId,subjectKey,tierVersionRef,actions,scopes,validity,remainingDepth,limits]`.
The executor derives the kind102 issuer from the requester and includes this
exact parent and Snapshot. The complete current parent chain must permit
DelegateGrant and every child restriction. A grant for an unadmitted candidate
is inert; creating it does not create membership or a request stream.

Create-only admission uses
`[200,1,"AuthorityAdmitMember",admitGrantId,acceptedOfferEnvelope,expectedSnapshot]`.
The inert acceptance payload is
`[200,1,"AuthorityMemberAcceptance",network,incarnation,memberId,candidateKey,memberValidity,readerGrant,administratorKey,offerNonce,acceptanceValidity]`.
Its envelope contains exactly the administrator and candidate signatures over
identical bytes. The envelope is at most1024bytes. OfferNonce is a nonzero
32-byte value; acceptance validity is at most86400000milliseconds and is
contained in member validity. Both intervals conservatively cover execution.
Acceptance contains no mutable snapshot or stream identity.

The offline offer artifact is
`[200,1,"AuthorityMemberOffer",offerEnvelope,readerGrantBytes]`, at most8192bytes.
The administrator-only envelope becomes a dual-signed envelope on acceptance;
the reader-grant bytes remain identical. A candidate authenticates the inviter
through the accepted genesis or an independently verified inviter key.

Historical confirmation is
`[201,1,"AuthorityMemberConfirmation",signedIntent,signedChallenge,orderedRequest,operationResult,executedResultCertificate,committedNode]`,
at most65536bytes. The client reserves this output capacity before submission.
The certificate proves either original execution or later exact disclosure of
the retained admission. Its reported certifiedHeight belongs to that certificate.
It is not necessarily the original admission height. Confirmation verifies the
quorum and exact accepted terms but never supplies a current permit or updates a
requester floor. Expired or revoked grants do not erase historical evidence.

Admission requires current network-scoped AdmitMember authority and the exact
existing reader grant for the candidate. That grant must permit ReadPage through
its complete current chain. Only this transaction's prospective membership may
supply the new candidate's admission while validating that chain. Other subjects
still require their own current admission. Additional actions need explicit grants.

Both intents name the created record ID and revision1, with profile0. Their
minimumPolicyHeight equals the Snapshot point's height. Expected versions equal
the exact pre-state dependencies. Permit is
`[201,1,action,dependenciesAndCreatedRecord,createdRecordBytes,creationHeight]`; Refuse is
`[201,1,action,[]]`. Consumers independently derive the created record. Neither
action returns Pending or changes its target after a timeout.

For these member mutations, application/deployment registration and withdrawal,
and grant revocation, Permit has exactly six fields. CreationHeight is the U64
height of the original committed mutation. The authority derives it from durable
mutation evidence and certifies identical result bytes on every exact replay.
It must satisfy `Snapshot.height < creationHeight <= ExecutedResult.height`.
Equality with ExecutedResult.height denotes first execution even when unrelated
commits followed the signed Snapshot. The first execution must validate consent
and acceptance at its actual evaluation time. A later certified execution of
that immutable result denotes replay and may disclose a committed admission after
its original acceptance window has expired, subject to current disclosure checks.
A local cached record never changes this classification. Missing, extra, invalid
or contradictory height metadata refuses; no five-field mutation reader exists.
Context, Get, List and refusal results keep their own explicit shapes.

The canonical applied state is
`[250,1,network,incarnation,epoch,height,records,streams,roleReservations,mutationEvidence,domainState,terminalDeclaration,epochOrigin]`.
Each sorted mutation-evidence entry is
`[createdVersionRef,signedIntent,committedHeight,evaluatedAtMs]`.
Every non-genesis grant, membership, revocation, application admission and
application withdrawal has exactly one entry. Deployment129 has one entry that
derives its exact117,105 and129; withdrawal130 has its own entry. Orphaned or
conflicting records refuse checkpoint loading.
The signed admission intent retains the dual-signed acceptance. Evidence remains
through checkpoints and receipt retirement. It permits historical inspection,
not current authority. Bounds are2048entries,80KiB per129entry,16KiB per other
entry and4MiB aggregate evidence. Records, evidence and terminal withdrawal
reserves fit6MiB; the encoded state fits8MiB under a separate retained-state
codec. Individual wire records retain their256KiB bound. Every open deployment
reserves one130 record,8KiB record space and16KiB evidence; each open operator
reserves at least16KiB of receipt capacity.

Admission commits membership, evidence, one candidate stream and the original
administrator completion atomically. Capacity refusal leaves no partial effect.
Exact retry never resets an existing candidate stream. A new sequence cannot
reuse an admitted member ID or acceptance. Expiry and revocation never free
permanent stream capacity. The stream set is exactly root subjects, member
subjects, application keys, registered operators and non-authority services.
Delegation and membership admission reject reserved-role keys.
The prior private genesis and applied-state shapes are not accepted.

## Request streams and explicit generation fencing

Kinds 20, 55 and 57 each carry one strict requester signature. Kind 22 embeds
one of those exact alternatives and its fresh recipient challenge. Kind 20 has
17 fields; the previous nonce-based shape is not accepted. Generation and
sequence are positive; acknowledgement is less than sequence. Minimum policy
epoch and height bind the preceding applied state. A new challenge preserves
the exact immutable request identity and never repeats its original mutation.

```text
55 = [55,1,network,incarnation,requester,clientNonce,minimumPolicyEpoch,minimumPolicyHeight]
C = [sequence,intentDigest,disposition,reason,resultDigest]
F = [fenceDigest,expectedMetadataDigest,previousGeneration,previousGenerationId,previousRetiredThrough,previousCompletionOrNull]
56 = [56,1,Scope,requester,present,generationOrNull,generationIdOrNull,retiredThrough,completionOrNull,lastFenceOrNull]
57 = [57,1,network,incarnation,requester,clientNonce,minimumPolicyEpoch,minimumPolicyHeight,expectedGeneration,expectedGenerationId,expectedMetadataDigest]
58 = [58,1,Scope,requester,fenceDigest,outcome,currentMetadataBytes]
```

Generation 1 uses
`RecordDigest(CBOR(["HyperNet/StreamInitial",1,network,incarnation,requester]))`.
Its last fence is null. An absent stream has null generation, generation ID,
completion and fence, with retirement zero. A completion has sequence exactly
one above retirement and commits to the original complete kind 24 result.
Later generations retain one nonrecursive last-fence tuple. Its previous
generation plus one equals the current generation; its fence digest is the
current generation ID. Kind 56 is at most 486 bytes; kind 58 is at most 674.

Kind 55 derives action `AuthorityStreamStatus`, resource=requester, revision=0
and profileGeneration=0. Its kind 24 value is exact kind 56 metadata. It neither
allocates a stream nor consumes an ordinary sequence. It permits only Permit/0
or Refuse with code 7, 21 or 37. Even an unknown requester receives the absent
shape. This confers no domain right and contains no protected result body.

Kind 57 derives action `AuthorityStreamFence`, resource=requester,
revision=expectedGeneration and profileGeneration=0. Its kind 24 value is kind
58 with exact canonical kind 56 bytes. The recipient must be the requester.
The prepared comparison retains that complete verified metadata, not just its
digest. Applied=0 and AlreadyApplied=1 require Permit/0 and maximumEffect=1.
Applied starts the exact next generation with retirement zero and no completion.
AlreadyApplied preserves any later ordinary work. Both require exact predecessor
fields in F. AttemptRefused=2 permits only Refuse codes 2, 3, 7, 12, 21, 28 or 37.
Superseded=3 requires Refuse/28 and current generation greater than the expected
next generation. Every refusal has maximumEffect=0; Pending is unsupported.

A successful fence sets generationId to the unsigned kind 57 payload digest.
It closes every sequence in the previous generation. A committed old-generation
request subsequently receives a finite refusal without changing domain state.
An exact last-fence retry is recognised before metadata comparison and cannot
clear later work. A superseded fence cannot repeat its transition; its historical
outcome can remain unknown. Fencing is explicit and is never a timeout response.

The application retains at most256 permanent admitted streams and1048576 ledger
bytes. A stream holds one original unacknowledged result and one bounded last
fence. Acknowledgement and the following ordinary receipt are atomic with any
domain mutation. Admission, revocation and restart never reset a stream. Status
and invalid requests cannot allocate permanent slots. Retired sequences refuse
with code 21; gaps use 12; generation or occupied-sequence conflicts use 28.
Current disclosure authority is checked again for an exact replay. A fresh
disclosure refusal never changes the original completion metadata.

## Local application consent and lifecycle

ApplicationAdmission127 and ApplicationWithdrawal128 use the persistent records
in PolicyContract. They retain separate application identity, exact accepted
kind102 grant and permanent request streams. The owner and application sign the
same kind200 AuthorityApplicationAcceptance payload, bounded to1024bytes. It
names both keys, N/I, exact grant, application validity, nonce and consent window.
Application validity is at most seven days; consent is at most24hours within it.

AuthorityDelegationContext selects an owned parent, child tier and optional owned
child. Current DelegateGrant authorises its exact64-reference closure without
InspectAudit. Its scoped cache is distinct from complete AuthorityContext.
AuthorityApplicationRegister adds a certified Snapshot to accepted immutable
terms and atomically creates admission, stream, evidence and completion.
AuthorityApplicationGet discloses127, exact102 and optional128 only to the owner
or application. AuthorityApplicationList returns complete sorted owner metadata
without grant bodies or pagination, at most63 rows and192 certified references.
Other dependency and expectation bounds remain64. Lifecycle metadata never
conveys a domain permission. The result value bound remains98304bytes.

AuthorityApplicationWithdraw is a restrictive veto by either recorded party,
including after grant or ordinary admission expiry. It requires the exact target
and a same-epoch causal Snapshot but no separate RevokeGrant capability. Retries use normal
permanent stream receipts; they preserve a subsequently fenced application stream
and all withdrawals. Expired acceptance does not invalidate historical evidence
of a completed registration or authorise its repetition. Registration and
withdrawal Permit results are
`[201,1,action,dependenciesAndCreatedRecord,createdRecordBytes,creationHeight]`.

AuthorityDeploymentRegister and AuthorityDeploymentWithdraw apply the same
causal-point and immutable creation-height rules. They recheck the exact current
registration authority, operator consent, identities and reservations, or the
exact admitted deployment and owner's restrictive withdrawal authority. Their
Permit result is `[201,1,action,dependenciesAndCreatedRecords,createdRecordBytesList,creationHeight]`.
Registration creates the exact kind117,105 and129 records together; withdrawal
creates kind130. The metadata does not confer runtime activation authority.

## Host clock observation

Kind 44 is a host-local monitor observation, not an authority decision:
`[44, 1, kernelBoot, sampleWallMs, sampleBootMs, validUntilBootMs,
maximumErrorMs, sourceAddress]`. The boot identifier and canonical numeric IP
address are Text; the four time/error values are U64 milliseconds. The ordinary
kind 0 signed envelope contains exactly one monitor signature. Its key is pinned
independently in the local deployment configuration and is never a voter key.
The consumer also pins the current host kernel boot. Validity is exactly
1000 milliseconds after sampleBootMs, and total clock error remains at most
250 milliseconds. This record conveys clock health only, with no membership,
permission, quorum or network authority.

## Inert consensus progress

Kind53 is `[53,1,Scope,null]` for ordinary inert progress, or
`[53,1,Scope,terminalCandidateNodeDigest]` for one exact reconfiguration branch.
It is an internal command, never a client intent or an authority permit. Its
canonical bytes are bounded to256 bytes. It advances only the deterministic
application height and committed history: no domain mutation, receipt or result
attestation is created. A correct leader emits it only to finish an unfinished
certified prepared branch. Followers validate scope, leader, safety, time and
normal phase evidence independently of their own application lag. A non-null tag
must name the first unresolved Reconfigure node on that verified branch. No ordinary
command or second declaration may follow it before its outcome is applied. A refused
declaration permits its retained exact no-ops to finish, then ordinary work resumes.
An accepted declaration stops applied state at that terminal node, including when
its deciding CommitQC names a later targeted no-op. The deciding suffix has at
most128 nodes; unrelated commands and unsupported targets refuse before voting.
The peer Proposal command field and kind22 repair-reference slot can carry either
an OrderedRequest or these exact inert bytes; the referenced digest binds those
complete bytes. Administrative Submit continues to require an OrderedRequest.

## Certified checkpoints and history

The checkpoint identity is the record digest of its unsigned kind45 statement.
Alternate signature subsets do not change that identity. These records have exact
fixed field order:

| Kind | Name | Fields after kind and version |
| --- | --- | --- |
| 45 | Checkpoint | Scope, height, nodeDigest, evaluatedAtMs, stateDigest, treeSize, treeRoot, terminal |
| 46 | CheckpointProof | checkpointEnvelope, anchorNode |
| 47 | HistoryProof | Scope, fromHeight, fromNode, toCheckpointDigest, [inclusionHashes], priorTreeSize, priorTreeRootOrNull, [consistencyHashes] |
| 48 | CheckpointChunk | checkpointDigest, totalBytes, index, chunkBytes |
| 54 | HistoryReply | Scope, targetNodeDigest, checkpointProofBytes, historyProofBytes, [checkpointExclusiveToTargetNodes] |

A normal checkpoint occurs at a positive height divisible by32. Tree size equals
height. Its three or four distinct eligible signatures bind the exact complete
canonical application state digest and committed Node. Kind46 has exactly four
fields: kind, version, the quorum envelope and the exact applied anchor bytes.
The anchor must match the statement's scope, height, node digest and evaluation
time. Each signer first verifies an actual deciding Commit QC and complete
ancestry, then durably applies and records the exact state and archive commitment.
The public checkpoint certificate does not carry that deciding QC or ancestry;
it is never a phase QC. Extra fields, including a deciding attachment, refuse.
Ordinary installation refuses terminal=true; terminal checkpoints require a
qualified epoch activation.

The history tree uses SHA256 and the RFC9162 section2.1 leaf/node prefixes. Leaf
data is the32-byte canonical Node record digest at index height minus one. Genesis
is separately pinned and has no leaf. Each inclusion or consistency path has at
most64 hashes, with exact consumption required. An existing client tree head must
match the prior size and root exactly; size zero requires null root and no prior
consistency hashes. A history relation grants no permission by itself.

Successful private operation4 returns kind54. The target must extend the supplied
checkpoint through at most128 exact nodes. The proof binds the client's exact
retained position and optional retained tree head. Clients verify this evidence
independently and durably retain the new head, result position and restrictive
policy floors before releasing an effect. Ordinary operation3 remains available
for short contiguous ancestry. Unknown positions, roots and suffixes refuse.

Operation4 accepts `[fromHeight,fromNode,targetNodeOrNull,priorTreeSize,priorTreeRootOrNull]`.
A null target requests the latest usable nonterminal certified checkpoint, with
that exact anchor as the reply target and an empty suffix. An unavailable
checkpoint returns Refused/Unavailable with null optional fields and an empty
sidecar. This query cannot grant permission or advance a client's trusted floor.
A client can verify and retain this evidence before creating its application
challenge, within the original transport limits. After the fresh result, it
verifies the exact short suffix and rechecks continuity from its retained floor
before normal durable acceptance. Invalid evidence fails closed.

If the exact target is in the certified archive before the latest checkpoint,
operation4 returns Refused/HistoryOvertaken with all optional fields null and an
empty output sidecar. The retained position and prior root must still validate.
This reply grants no permission and cannot replace history evidence. Installed
service activation may discard that attempt's challenge and issue a fresh one
for the same immutable intent within the original monotonic startup deadline.
Malformed history and proof data never trigger this refresh. Ordinary request
recovery does not automatically retry a mutation with a different challenge.

State has at most262144 bytes. Kind48 uses at most16 chunks of16384 bytes, with
zero-based exact indices and only the final chunk shorter. Archive requests name
one exact range of1-512 leaves; their first index is zero-based. The archive has at
most131072 leaves, approximately4MiB of raw Node digests. Request identifiers,
checkpoint identities, expected indices and counts must all match. Duplicate,
unrequested and unrelated responses refuse. Transport authentication does not
make a partial chunk authoritative.

A replica stages at most one transfer per eligible remote peer in bounded private
memory, with a120-second transfer lifetime. It checks canonical state, the complete
state digest, its concrete application's state validator and the full certified
archive root before publication. Its existing archive prefix must match exactly.
A donor pins at most one served state per eligible remote peer, at most three
states of8388608 bytes each. A fixed120-second lease binds the transfer ID and
checkpoint digest; repeated requests do not renew it. The archive remains one
append-only store, and each served range must match the pinned certified prefix.
Checkpoint publication cannot replace a pinned state. The additional24MiB of
state bodies is charged to the existing maintenance staging allowance.

If the requested checkpoint is unavailable before pinning or after donor restart,
type17 carries its current verified checkpoint. Only the exact active transfer ID
and old digest can accept this response, and the new checkpoint must be strictly
higher. The receiver allocates a fresh transfer ID, retains its original deadline
and discards prior partial bytes. Stale replies cannot advance the replacement.
An unsolicited newer type12 proof cannot reset a working transfer. Expiry refuses
progress; these finite leases do not promise completion under arbitrary delay.

The local signer journal, votes, locks, synchronizer and generation are retained;
checkpoint transfer cannot recreate a missing signer journal. A divergent local
safety branch retains its exact QC and complete bounded ancestry to an
authenticated common prefix; it is never relabelled as canonical history.
Installation preserves exact own votes and the retired-view floor. Only normal
phase processing can move a lock. One of the existing4096 node slots is reserved
for the imported anchor; a closure exceeding that bound refuses installation.
Single checkpoint shares are collected only for an exact locally durable applied candidate. An
unknown single share cannot allocate a persistent candidate or initiate transfer.

Archive additions are synchronized before the journal publishes their exact size
and root. Restart checks that committed prefix and truncates only an uncommitted
suffix. Corruption within the journal-bound prefix refuses restart. Compaction
retains verified safety ancestry and records a retired-view floor before removing
old votes. Entered view v retires signatures through max(previousFloor,v-2),
including before the first checkpoint; this does not retire valid quorum
certificates or discard rooted safety dependencies. Two pending checkpoint states
and the latest certified checkpoint are retained. Application pauses while both
candidates await certification. Voting and certified repair retain their separate
finite pending capacity:4096 nodes,20480 objects and256MiB, with ordinary admission
limited to3584 nodes,17920 objects and224MiB. The durable application cursor scans
at most64 ancestry headers per turn and executes at most one position per turn.
It retains actual deciding evidence until application completes. At most64
executed reply bundles are retained; each exact peer tuple must fit196608 bytes,
including a node of at most1024 bytes and signed kind23 of at most4096 bytes.
Canonical kind24 result bytes are limited to188416 bytes. Application receipts
and their separate capacity limits remain part of the complete application state.

Outbound per-peer scheduling has one aggregate128-message/4MiB mailbox. A
recovery lane reserves16 slots and2MiB within that limit and uses the second
existing permitted peer connection. Queue pruning follows the current live
broadcast, submission and exact repair/transfer request sets. Requested response
slots are distinct for repair, state and archive replies; unsent responses expire
after the existing3-second transport interval and are regenerated on an exact
repeated request. Queue expiry never changes proof validity or client deadlines.

## Canonical runtime resources

RuntimeManifest is a canonical CBOR20-field array, bounded to49152 bytes:

```
[200,1,"HyperNetRuntimeManifest",N,I,deployment,host,operator,
 bootstrapDigest,softwareDigest,validityMs,sessionMode,roles,volumes,
 endpoints,clock,placement,limits,consentPolicy,authorityConfigOrNull]
role = [role,serviceKey,imageDigest,memoryBytes,pids,cpuQuota,cpuPeriod,
        stateAdmissionBytes,bindEndpointIds,outboundEndpointIds,volumeIds]
volume = [volumeId,readOnly,storageAdmissionBytes]
endpoint = [endpointId,serviceKey,addressFamily,addressBytes,port,
            transportPublicKey,leafDER]
clock = [monitorPublicKey,kernelBoot,witnessFileName,250,1000]
consentPolicy = [allowOpaque,reviewerRoots]
authorityConfig = [listenFamily,listenAddress,listenPort,
                   orderedPeerEndpointIds,tlsFileDigests,
                   subnetFamily,subnetAddress,subnetPrefix]
```

The bootstrapDigest is raw SHA-256 of the complete independently accepted
bootstrap file. It is distinct from the domain-separated RecordDigest used for
protocol identity. Installation, profile signing and activation compare the
exact file pin.

The sets contain at most9 roles,16 volumes and16 endpoints. Sort role rows by
role number and volume/endpoint rows by their IDs. Sort reference sets; preserve
the explicit four-entry authority peer order. Every declared resource is used and
every reference resolves. Bind endpoints name their owning role's service key;
outbound endpoints identify remote references without claiming their ownership.
IDs and public keys are32 bytes. Literal address family4/6 requires4/16 address
bytes. A leaf is at most4096 bytes and its parsed Ed25519 SPKI must match the
explicit transport key. The complete manifest bound also applies to certificate
bytes. No executable field, URL, arbitrary mount path or DNS hook is accepted.

SessionMode is0, the Session lifecycle. Clock age/error limits remain1000/250ms.
WitnessFileName is one basename beneath `/Clock`. Authority configuration uses
fixed `/Config/Tls/{Authority,Certificate,PrivateKey}.pem` credentials and
`/State/Control/Control.sock`. TLS file digests follow that named order. Installed
authorities use a private IPv4/24 subnet and one writable state volume. State
admission is available-space admission, not a filesystem quota. The authority
minimum is1GiB, including journal replacement and pending-object headroom.

Immutable RuntimeBootstrapKeys is kind131, lookup N:

```
[131,1,N,I,1,null,authorityTransports,clockMonitors,routeTransports]
authorityTransports = sorted four [voterKey,transportKey] pairs
clockMonitors = sorted one through four monitor keys
routeTransports = [[2,relayServiceId,relayTransportKey],[3,admissionServiceId,admissionTransportKey]]
```

The voter keys equal the genesis descriptor's four voters. All transport and
monitor keys are distinct from each other and existing bootstrap identity
classes. Genesis reservations add class5 for these transports and class6 for
these monitors, derived only from this authenticated record. The record has no
mutable Snapshot and no successor. Route mappings must equal the accepted kind31
bootstrap route. Reserved route transport keys can serve only their exact registered
role5 endpoint IDs and purposes. Draft input explicitly supplies
`authorityTransports` and `clockMonitors`; inspection displays both. Reserving a
transport or service binding does not confer an authority appointment.


## Healthy authority succession

| Kind | Name | Fields after kind and version |
| --- | --- | --- |
| 49 | EpochDeclaration | oldScope, nextEpoch, requester, NetworkAdminGrantId, Snapshot, fourSortedNominations |
| 50 | EpochHandoff | oldScope, terminalCheckpointDigest, declarationDigest, successorDescriptorBytes, successorGenesisDigest, successorStateDigest |
| 51 | EpochReady | successorScope, handoffPayloadDigest, successorGenesisDigest, successorStateDigest |
| 52 | EpochTransition | orderedRequestBytes, terminalCheckpoint46Bytes, oldHandoffEnvelope, newReadyEnvelopeOrNull, decidingCommitQc12Bytes, [targetedSuffixNode14Bytes] |

Each nomination is `[voterKey,profile117Ref,consent105Ref]`. Reconfigure parameters
are `[200,1,"Reconfigure",declaration49Bytes]`. The requester needs current
NetworkAdmin9 authority and the exact pre-state. Its expected references include
both immutable network policies, the administration chain and every current
registration129, profile117, consent105 and registrar13 chain. The four distinct
registered deployments must have unwithdrawn consent for the same ordered peer
transport contract. The installed profile requires four fresh voter identities;
overlapping or retired voters refuse. Consent and registration are not rewritten.
Permit is `[201,1,"Reconfigure",exactDependencies,declarationDigest,nextEpoch]`.
Refuse is `[201,1,"Reconfigure",[]]`; no Pending result exists.

Kind49 fits16KiB; kind52 fits128KiB; kind50 and51 statements fit2KiB. Kind50 needs
three old signatures over one exact successor. Kind51 needs three nominated new
signatures over the same handoff payload and installed state. A valid52 also
contains an actual old CommitQC deciding its terminal node or the exact bounded
no-op suffix. Kind46 remains unchanged. Equivalent valid deciding certificates
or suffixes do not change the unsigned terminal checkpoint identity.

A successful root stores `terminalDeclaration=[declaration49Bytes,intentDigest]`.
The successor preserves fields6-10 of the exact post-terminal root byte-for-byte,
sets the next epoch and height0, clears that terminal flag and stores
`epochOrigin=[oldScope,terminalHeight,terminalNode,terminalState,checkpointDigest,declarationDigest]`.
The original bootstrap state anchor remains independently pinned. Later state
commitments do not reinterpret historical admission evidence as fresh authority.

Old replicas store their halt before releasing terminal or handoff shares. New
replicas verify and store the full successor state before releasing ready shares,
and store the matching ready quorum before any vote. Requesters and serving
recipients verify terminal inclusion and consistency from their actual retained
floor and tree head. A durable seal immediately blocks old effects. Activation
preserves restrictive versions, request history and uncertain effects; it cannot
reset a stream, revoke privacy requirements or grant a replayed old permit.
The append-only verified epoch archive has a2MiB byte budget; no entry is evicted.

See [Authority committee replacement](AuthorityEpochs.md) for the installed
workflow and [Network recovery](NetworkRecovery.md) for exceptional new-identity
recovery. Recovery is never a substitute signature set for kind50 or51.

## Federated publication contract

[Federation](Federation.md) defines canonical records150..157,
the finite authority commands and complete foreign result proof. Bilateral trust
and explicit source sharing never create foreign membership or a local Mail
recipient. Imported content retains its source network/incarnation and exact
sharing generation; destination publication requires its own review.

Foreign-floor advancement and local domain state commit together. Each current
read, review or media effect requires a fresh bilateral proof; immutable byte
receipts do not advance authority. Healthy epoch adoption retains prior floors
and verifies the complete terminal/Ready chain. Exceptional recovery creates a
new identity requiring independent trust acceptance.


## Private route authority

Route metadata uses the ordinary kind/domain record envelope:
`[kind,1,N,I,generation,predecessorDigestOrNull,lookup,payload]`.

| Kind | Lookup | Payload |
| --- | --- | --- |
| 165 | Opaque route service ID | `[signedProfile,managerKey,managementGrant,withdrawn]` |
| 166 | Voucher ID | `[relay165,destination165,sponsorKey,grant102,possessionKey,action,[scopeKind,scopeId],maximumConnections,maximumBytes,expiresMs,creationIntent]` |
| 167 | Voucher ID | `[reservedConnections,reservedBytes,lastConnection,lastTranscript,lastIntent]` |
| 168 | Member ID | `[singleSignedOffer,inviterGrant102,creationIntent]` |

A route profile is an operator-signed envelope containing:

```
[200,1,"AuthorityRouteProfile",N,I,deployment,serviceKey,operatorKey,
 profile117,consent105,endpointId,identity,addressOrNull,domain,protocol,mode,
 relayIdOrNull,limits,maximumConnections,assurance,[notBeforeMs,expiresMs],manifestBytes]
identity = [serviceId,serverName,transportKey,leafDer,certificateAuthorityPem]
limits = [maximumBytes,maximumDurationMs,maximumIdleMs]
```

Domain is a canonical lowercase hexadecimal control-domain ID. Mode1 is a relay;
mode2 is a public endpoint; mode3 is an outbound attachment. Protocol0 is relay
transit;1 authority;2 content;3 media;4 mail;5 transfer;6 an authenticated foreign
Page read gate. The local manifest and consent bind exact keys, endpoint IDs,
limits and mounted service sockets. The exact manifest bytes must reproduce both
117 and105 references, including the endpoint address and TLS leaf. Certificate validation and exact leaf/key
pins both apply. A route never grants an application permission.

`RouteContext`, `RouteLookup`, `RouteInviteContext`, `RouteCandidateContext` and
`RouteVoucherContext` disclose only the checked caller's current dependency
closure. `RouteRegister`, `RouteWithdraw`, `RouteIssue`, `RoutePermit` and
`RouteInvite` are ordered mutations. A permit reserves one stream and its full
finite byte budget before the relay opens a destination. The relay also persists
a spent connection ID before returning readiness. An uncertain retry cannot
open another stream under the same reservation.

A retained live connection may use a fresh `RouteVoucherContext` result to
revalidate its current voucher, sponsor and exact relay/destination profiles.
That disclosure alone cannot admit a stream: the original verified Permit,
connection ID, transcript and immutable resource limits remain required.
Kind167 contains the latest reservation, not an inventory of live connections;
a later reservation cannot replace an earlier stream's retained admission.
Spent IDs remain durable through their original connection lifetime. Restart
retains spent IDs but never reconstructs a live connection from those records.

Current transit and endpoint permission each expire under the ordinary 5000-ms
challenge ceiling. Every forwarding write remains gated by a fully verified
current proof. Refresh changes only current permission; it cannot extend the
original transport duration, byte allowance, consent or application deadline.
No bytes are released through an expired or withdrawn permission.

`RouteReady` describes remaining total transport limits. Final-service TLS then
carries `[200,1,"EndpointReady",N,I,service,protocol]`, after endpoint permission
is current and before any application frame. The client checks all four context
fields against its pinned profile. It creates an application challenge only after
this readiness. Multiple framed requests carry submission, polling and history
on the same admitted channel. Every frame must match its selected protocol;
protocol1 still excludes diagnostics and management. A failed session closes;
reconnection requires a fresh Permit and cannot reset an unresolved operation.

An invitation is addressed to one candidate and creates only that candidate's
requester stream. Its existing administrator-signed acceptance payload is
countersigned by the candidate. `AuthorityRedeemMember` uses the membership
mutation parameters and result, with the candidate as requester and the current
inviter's admission capability as authority. The exact issued kind168 payload,
current inviter grant, candidate reader grant and all delegation dependencies
must match. Pending invitations never confer ordinary membership or audit rights.

`RouteReaderPermit` carries a signed `RouteBridgeRead` envelope. It binds the
network, incarnation, final endpoint, reader, exact grant, action, expiry, nonce
and exact inert `BridgeLease` packet. The endpoint obtains a fresh quorum result
before forwarding that packet. The authority checks current local foreign-Page
permission, publication revision and accepted foreign trust/floor. No unsigned
bridge administration is exposed by the reader protocol.
