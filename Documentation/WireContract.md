# Authority wire contract

This document specifies the replacement authority contract for HyperNet 0.8.0.
The 0.7.5 executables do not implement it. A specification or a valid signature
does not establish an operational Byzantine network. Activation requires the
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

GenesisGovernance is kind 15:
`[15, 1, network:Id, incarnation:Id, records:list(bytes)]`. Records contains the
exact canonical unsigned payloads for one initial NetworkPolicy, one
RecoveryPolicy, 1-16 initial TierPolicy records and 1-16 root Grant records.
They are sorted uniquely by `(kind, record lookup Id)` as defined in
PolicyContract. No other kind is allowed. Every record has the same network and
incarnation, generation one, null predecessor and null expectedSnapshot. The
whole bundle obeys the 262144-byte record ceiling. Its record digest is the
descriptor's `genesisGovernance`. The separately named policy and recoveryPolicy
digests must equal their exact records in this bundle.

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

## Requests, recipient challenges and executed results

An immutable intent is created before a recipient issues a challenge. This avoids
a circular dependency between request identity and challenge identity.

| Kind | Name | Fields in order |
| --- | --- | --- |
| 20 | Intent | network:Id, incarnation:Id, operation:Id, requester:Key, action:Label, resource:Id, revision:U64, profileGeneration:U64, minimumPolicyHeight:U64, expected:list([U64,Id,U64,Digest]), parameters:bytes |
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
   Result height is at least every required floor. A recent old permission cannot
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
`CLOCK_BOOTTIME`. The maximum end-to-end serving interval is 5000 ms from local
challenge creation. A delayed operation fails rather than extending this interval.
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
