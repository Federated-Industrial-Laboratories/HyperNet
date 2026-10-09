# HyperNet 0.8.0 policy, identity and lifecycle contract

This defines the HyperNet 0.8.0 replacement policy contract. The 0.7.5
executables do not implement these workflows. Cryptographic, persistence,
routing and installed-runtime qualification remain required. Semantic obligations
are in [PolicyVectors.json](PolicyVectors.json); canonical signature bytes are
specified by [WireContract.md](WireContract.md).

## Encoding and limits

Use the deterministic CBOR subset and signed envelope in
[WireContract.md](WireContract.md). The schemas below use fixed arrays;
field names are explanatory and do not appear on the wire. Every root record is
`[kind, 1, network, incarnation, generation, predecessor, ...body]`.
`network`, `incarnation` and digests are exactly 32 bytes. `generation` is an
unsigned 64-bit integer. A first persistent record has generation 1 and a null
predecessor; an update has predecessor equal to the immediately preceding record
digest and generation exactly previous + 1. Overflow refuses. A transient
request, preview, declaration or acceptance uses generation 0 and predecessor
null; its expected versions and unique operation ID are explicit body fields.
The transient kinds are 106, 115, 116 and 119-124. Every other kind below is a
persistent generation-controlled record, including immutable publication records.
Signatures cover the purpose-separated exact canonical record bytes using the
common envelope. A signature cannot be moved between record kinds or networks.
Only initial NetworkPolicy, RecoveryPolicy, TierPolicy and root Grant records
inside the exact descriptor-pinned GenesisGovernance bundle have null
expectedSnapshot. Its finite contents, initial administrator admission and
reference checks are defined in WireContract.md. These records have generation
one and null predecessors; they cannot hash the descriptor or their resulting
state. Later updates and ordinary new objects/grants use a certified current
Snapshot. Null is not a general first-generation authority exception.

Record lookup IDs are fixed, not supplied as alternate aliases: kinds 100 and
114 use network; 101 uses tier; 102 uses grant; 103 uses client; 104 uses object;
105,117,118 use deployment; 107 uses member; 108 uses device; 109 uses the exact
referenced DeviceBinding record digest; 110 uses audience; 111-113 use publication.
All transient kinds use operation. A VersionRef must match this lookup ID, kind,
generation and exact record digest together. Conflicting aliases are refused.

In JSON vector presentation, unsigned 64-bit values are canonical decimal
strings, bytes are lowercase hexadecimal, and enum names stand for the numeric
values defined here. The wire decoder accepts only the declared types and exact
arity. Missing fields, extra fields, unknown enum values, duplicate set elements,
noncanonical encodings and duplicate identity/key entries fail before signature
or authorisation evaluation. There is no administrator-defined executable rule.

| Type or collection | Bound and meaning |
| --- | --- |
| U64 | 0 through 18446744073709551615; never float, signed integer or wrapping arithmetic |
| Id, Digest, Nonce | Exactly 32 bytes; all-zero identifiers and nonces are refused |
| Ed25519Key | Exactly 32 bytes, validated by the qualified signature library |
| EncryptionKey | Exactly 32 bytes for the qualified X25519 recipient profile; key validation and format conversion use that library |
| DisplayLabel | 1-128 UTF-8 bytes; no NUL, C0/C1 controls or bidi override/isolate controls; no Unicode normalisation during signature verification |
| Tier rank | 0-65535, with at most 256 active tiers per network |
| Grant chain | At most 8 edges from its explicit root; at most 64 resource scopes and 32 action codes per grant |
| Route domains | At most 16 allowed relay-control domains and 16 destination-control domains |
| Audience | At most 256 accepted identity roots; at most 16 active devices per root and 1024 total frozen devices |
| Placement | At most 16 named hosts, 16 named volumes and 16 named backup destinations per object policy |
| Recovery | Initial profiles are owner 1-of-1, owner 2-of-3 keys, or shared 2-of-3 distinct principals |
| Policy transaction | At most 64 directly edited records; larger changes are distinct ordered transactions |
| Preview page | At most 128 impact entries; maximum 65536 entries across one snapshot-bound preview |
| Search | At most 16 literal terms, 128 UTF-8 bytes per term and 1024 total term bytes; 1-100 results; no raw SQL or FTS expression |

These are initial contract ceilings, not measured capacity claims. Configured
limits may be lower. Raising a ceiling changes the contract and requires the
affected parser, resource and installed-workflow qualification. No product claim
of 1024-recipient performance follows from accepting that structural bound.

Nested types have these exact array shapes:

- `Point = [epoch:U64, height:U64, state:Digest]`. It is meaningful only with a
  verified committed authority certificate and its matching network/incarnation.
  Comparing heights from unrelated incarnations or forks is invalid.
  Every input Point names a state committed before that input was created; no
  input embeds the resulting state digest of its own prospective commit.
- `VersionRef = [kind:U64, id:Id, generation:U64, digest:Digest]`.
- `Validity = [notBeforeMs:U64, expiresMs:U64]`, with notBefore < expires.
  Authority decisions use the shared ordered-time contract; local operation
  deadlines use the shared monotonic freshness contract. No local replica clock
  changes a deterministic permission result.
- `ResourceScope = [resourceKind:U64, id:Id]`. Resource kinds are Network=0,
  Namespace=1, Object=2, Service=3, Member=4, Deployment=5. Only Network scope
  may contain narrower scopes, and only for the same network. Namespace scope
  contains its own objects through the certified namespace binding. Every other
  scope is exact. No text prefix, path glob or inferred namespace ancestry exists.
- `Limits = [maxBytes:U64, maxObjects:U64, maxConnections:U64,
  maxConcurrentOperations:U64]`; zero permits none, never unlimited.
- `Placement = [hosts:[Id], volumes:[Id], backups:[Id], copies:U64]`.
  Lists are sorted unique. Copies must be 1-16 and cannot exceed consented hosts.
  A volume is identified by a registered handle, never an untrusted path.
- `Snapshot = [point:Point, dependencies:[VersionRef]]`; dependencies are
  sorted unique by (kind,id), at most 64. An unlisted relevant direct dependency
  invalidates a proposed authorisation or transition. A frozen roster guards its
  transitive identity/admission dependencies by exact deterministic recomputation
  at commit, not by omitting their current-state checks.
- `Impact = [category:U64, subject:Id, before:Digest|null,
  after:Digest|null, reason:U64]`. Categories are Role=0, Endpoint=1,
  Placement=2, Resource=3, Audience=4, Trust=5.
- All set-like enum lists are strictly increasing numeric values. ID lists use
  unsigned byte order. Compound lists use their declared tuple key. Ordered
  sequences such as predecessor chains are not sorted into a different meaning.

## Four independent policy axes

`NetworkPolicy` is kind 100. Body order:

```text
[enrolment, publicReading, minimumRoute, allowedRelayDomains,
 allowedPublicationModes, defaultPublicationMode, recoveryPolicy,
 limits, manualReviewDefault, policyAuthority, expectedSnapshot]
```

Enums and field types:

- Enrolment: InvitationOnly=0, ApprovedApplications=1. `publicReading` is a
  separate boolean and defaults false; enabling it never modifies object
  audiences. Open reading uses bounded guest read capability, not implicit
  anonymous member creation. Ordinary accepted members receive the reader
  grant explicitly recorded by the admission transaction.
- Route assurance: Organisational=0, Independent=1. Default is Independent.
  `allowedRelayDomains` is a nonempty sorted ID list. Both values require a
  registered relay and final-service authentication; Direct is not a value.
  Operational independence remains an explicitly declared deployment assumption.
- Publication mode: HostReadable=0, Sealed=1. Allowed modes is a nonempty set;
  default is HostReadable and must belong to that set. Sealed-only namespaces
  restrict the set to Sealed. These fields grant no access to any recipient.
- `recoveryPolicy` is a VersionRef to kind 114. `limits` is Limits.
  `manualReviewDefault` is true in the base profile. False is valid only where
  every affected namespace names a scoped automated-review capability and its
  exact approval mechanism; it never means unreviewed publication.
- `policyAuthority` is the sorted set of exact root Grant IDs, maximum 16.
  `expectedSnapshot` is Snapshot; it includes the prior network policy and
  recovery policy on update. Genesis instead uses the independently authenticated
  network trust descriptor and its accepted first policy digests.

Namespace and object restrictions are explicit policies, not implied by the
network default. `ObjectPolicy` (104) body is:

```text
[object, namespace, publisher, audiencePolicy, allowedModes, publicAudience,
 placement, minimumState, authorDisclosure, expectedSnapshot]
```

The first three are IDs; audiencePolicy is VersionRef to 110; allowedModes is
the finite mode set; publicAudience is boolean; placement is Placement;
minimumState is Point; authorDisclosure is Digest|null; expectedSnapshot is
Snapshot. Making an existing private object public or Sealed content
HostReadable requires an exact author-signed disclosure record digest and fresh
review. A policy edit alone cannot upload plaintext or widen an audience.

`ClientPolicy` (103) body is:

```text
[client, minimumRoute, acceptedRelayDomains, requiredPublicationModes,
 allowedPlacement, acceptedTrustDigest, permitNetworkSearch]
```

Client is Id; mode/domain fields are sets, allowedPlacement is Placement|null,
acceptedTrustDigest is Digest, and permitNetworkSearch is boolean. Null placement
means no additional client placement restriction, not removal of user/object
restrictions. An empty accepted set means refusal, not inherit-anything.

## Explicit grants and tier attenuation

`TierPolicy` (101) body is `[tier, rank, label, allowedActions, scopes,
maximumDelegationDepth, limits, expectedSnapshot]`. Tier is Id; label is DisplayLabel; rank U64 is
bounded above; allowedActions and scopes are sets. Depth is 0-8. The rank orders
administrative presentation only. Rank 0 has no implicit read, keys, recovery,
host access or consent override.

`Grant` (102) body is `[grant, issuer, subject, tier, actions, scopes,
validity, parentGrant, remainingDelegationDepth, limits, expectedSnapshot]`.
Grant is Id; issuer and subject are Ed25519Key; tier and non-null parentGrant are VersionRef;
actions/scopes are sets; validity is Validity; depth 0-8; limits is Limits.
A null parent is allowed only for a root grant explicitly accepted by current
governance. It is never inferred from rank or a missing parent lookup.

Initial action codes are:

```text
0 ReadPage             1 SearchCatalogue       2 PublishPage
3 ReviewPage           4 SharePublication      5 HostPages
6 RelayTransit         7 IndexPages            8 VoteAuthority
9 AdministerPolicy    10 AdmitMember          11 DelegateGrant
12 RevokeGrant        13 RegisterService      14 StoreMail
15 SendMail           16 ReadMail             17 StoreTransfer
18 SendTransfer       19 ReadTransfer         20 OpenSshSession
21 AdministerPlacement 22 AcceptFederation    23 RegisterRecipientDevice
24 ApproveRecipientRecovery 25 InspectAudit   26 ManageLocalRuntime
27 AcceptRecoveryPolicy 28 ApproveNetworkRecovery
29 ReviewSealedPage   30 FinaliseSealedPage   31 RevealPublicMetadata
```

No action grants another action implicitly. The same person's distinct keys are
distinct subjects. In particular, membership, relay transit, voting, publication
review, recipient enrolment and SSH never arise by tier comparison or puzzle
completion. Recovering keys or calling local management requires the separately
defined offline/local authority, even when a corresponding action is present.

To delegate, verify one complete current parent chain. The issuer must be the
parent subject and possess DelegateGrant in that chain; child action set, scope,
validity, limits and remaining depth must be subsets/reductions. Each edge consumes
one depth. Child depth must be <= parent depth - 1. The child tier policy must
also permit the requested actions/scopes. Unioning fragments from two chains
cannot manufacture one stronger child. A request may use any one fully valid
chain covering it, but cannot combine partial chains to satisfy a missing check.
Re-evaluate every ancestor's current admission, expiry, tier policy and revocation
at use. Duplicate grants, cycles, absent ancestors and exceeded depth deny.

Effective permission is the conjunction of grant, tier, network, object/audience,
application, user, treaty, route and local-consent restrictions relevant to the
operation. A dimension does not apply only when the operation schema explicitly
excludes it. Missing applicable state denies. No ordering of these checks may
turn denial into permission. For privacy assurance take the stronger requirement;
for accepted sets take intersection; for upper resource limits take minimum;
for expiry take earliest. Mandatory signature, quorum, exact approval, freshness,
placement-veto and confinement checks have no configurable false value.

## Preview and compare-and-commit

`PolicyPreview` (106) body is `[operation, requestDigest, snapshot,
effectiveDigest, impactDigest, impactCount, pageIndex, impacts,
nextPageToken, decision, reasons]`.
Operation is a fresh Id; digests are Digest; snapshot is Snapshot; counts/index
are U64; impacts is up to 128 Impact records; nextPageToken is Digest|null;
decision is Permit=0 or Refuse=1; reasons is a sorted set of refusal codes.

The effective view reports each setting's exact result and the contributing
default, network, user, object and consent record references. Each impact page
binds the same operation/request/snapshot/complete impactDigest and count. The
client verifies consecutive indexes, no duplicates and complete count before
presenting a change as fully reviewed. A changed dependency invalidates preview
and requires a fresh preview. Over 65536 impacts returns PreviewLimit without
applying any part of the proposal; narrowing scope is explicit.

Apply compares all relevant expected versions and requestDigest atomically at
the ordered commit point. It rechecks signatures, authority, consent and limits,
then durably commits the new records and mandatory audit entry together. Preview
is explanatory evidence, never a reusable authorisation or a lock reserving old
rights. A mutation may not report success if mandatory audit durability failed.

## Explicit disclosure

`AuthorDisclosure` is kind 124 with the transient common prefix. Its body is
`[operation, object, priorPolicy, audience, publicationMode, revision,
plaintextDigest, expectedSnapshot]`. Operation/object are Id; priorPolicy and
audience are VersionRef; mode is the finite publication mode; revision is U64;
plaintextDigest is the exact content SHA-256; expectedSnapshot is Snapshot.
The object publisher or its exact current sharing delegate signs it. It names
one revision and transition, not blanket future permission. An object policy
change references its record digest and rechecks its current signing authority,
expected predecessors and exact intended audience/mode before any disclosure.
The record remains private with the review material until deliberate publication.

## Recipient identity continuity

Record bodies and authorisation:

| Kind | Body, in wire order | Mandatory authority |
| --- | --- | --- |
| 107 RecipientRoot | `[member, rootKey, recoveryPolicyDigest, validFromState]` | Initial independently authenticated binding; subsequent accepted root continuity or explicit recipient recovery |
| 108 DeviceBinding | `[member, root, device, signingKey, encryptionKey, purposes, validity]` | Accepted root signature, or one valid attenuated device-enrolment delegate; possession is separate admission evidence |
| 109 DeviceAdmission | `[member, binding, scopes, validity, possessionDigest, expectedSnapshot]` | Current ordered network authority plus exact valid root-signed binding and both key-possession checks |
| 110 AudiencePolicy | `[audience, publisher, allowedRoots, excludedDevices, sharingDelegate, publicAudience, expectedSnapshot]` | Publisher or exact attenuated sharing delegate |
| 111 FrozenRoster | `[publication, revision, encryptionGeneration, audience, roots, devices, snapshot]` | Trusted reviewer finaliser validates every listed record and author intent |
| 120 RecipientRecovery | `[operation, member, priorRoot, replacementRoot, acceptedRecoveryPolicy, expectedSnapshot]` | Previously accepted recipient recovery policy; never merely network-admin authority |
| 121 RecipientAcceptance | `[operation, contact, previousRoot, acceptedRoot, recoveryDeclaration, trustContext]` | That contact's own authenticated trust store authority |
| 122 DevicePossession | `[operation, bindingDigest, enrolmentEndpoint, challengeDigest, expiresMs]` | Candidate signing key after recovering the fresh encrypted challenge with candidate encryption key |
| 123 DeviceChallenge | `[operation, bindingDigest, enrolmentEndpoint, nonce, expiresMs]` | Fresh single-use challenge issued by the authenticated enrolment endpoint |

Member/device/publication/audience/contact/endpoint are IDs. Root, binding,
audience and policy references are VersionRef, except explicit names ending
Digest. RecipientAcceptance's previousRoot and acceptedRoot are VersionRef;
recoveryDeclaration is Digest. RecipientRecovery's priorRoot and replacementRoot
are VersionRef; acceptedRecoveryPolicy is Digest. Root record's
recoveryPolicyDigest is the accepted recipient-specific custody policy Digest,
separate from network recovery. Roots is a sorted list of record Digests, devices a sorted list of
`[root:Digest, binding:Digest, admission:Digest]`. Each digest identifies one
complete immutable record, verified through bounded authenticated retrieval.
Compact digest references keep the 1024-device roster within the shared 262144
encoded-byte ceiling; that overall ceiling still takes precedence. Purpose values
are ReadSealed=0 and EnrolDevice=1. RecipientRoot's rootKey is Ed25519Key;
DeviceBinding keys have their separately named types. Revision and encryption
generation are U64, positive and increment without reuse. `sharingDelegate`
is VersionRef|null. `allowedRoots` is a sorted VersionRef set and
`excludedDevices` is a sorted ID set;
publicAudience is boolean. `validFromState` is Point. ReplacementRoot is the
exact digest-bound proposed root record, not a display name. RecipientRecovery's
acceptedRecoveryPolicy is Digest. `trustContext` is the digest of the exact
user-visible binding accepted independently of the directory response.

Key possession first completes and root-signs DeviceBinding. Kind 123 then binds
that immutable binding digest and a fresh random 32-byte nonce. Encrypt its exact
canonical record using the selected qualified recipient library to the candidate
encryption key. The endpoint keeps this challenge private and single-use for at
most 30 seconds. The device signs kind 122, whose challengeDigest is the common
record digest of the exact decrypted kind-123 record. The
endpoint checks it against its outstanding challenge before admitting the key.
The challenge ciphertext is not a durable key directory record. It conveys no
content access. DeviceAdmission includes the exact DevicePossession record digest.
DeviceBinding contains no possession reference, so this structure has no hash
cycle. Root authorisation, possession and network admission are separate
checks; passing one never substitutes for another. The concrete encryption
library and its possession test remain implementation qualification work.

Device and root state is Active or Revoked. A revoked binding never becomes
Active again. Replacement needs new keys, a new generation/predecessor and valid
user authority. An authority-signed substituted key, an unchanged member name or
a recovered network root cannot satisfy recipient continuity. Existing contacts
and publishers retain their accepted root digests and recovery-policy digests.
Without valid continuity, create and independently verify a new identity, then
deliberately reissue selected content. Automatic account-name matching is refused.

## Sealed publication and race ordering

`PublicationInner` (112) body is `[publication, object, revision,
encryptionGeneration, audience, rosterDigest, pageDigest, assetDigests,
format, publisher, reviewer, expectedSnapshot]`. Asset digests is a sorted list
of `[asset:Id, digest:Digest]`, maximum 64. Format is U64 value 2 for HyperNetPage/2; other values are refused.
Its referenced media remains HyperNetRaster/1 or HyperNetVector/1 as declared by
the exact page grammar; the content grammar stays inert.
This record and all private titles/captions/search terms are inside encryption.

`PublicationOuter` (113) body is `[publication, object, revision,
encryptionGeneration, audience, rosterDigest, ciphertextDigest,
ciphertextBytes, placement, opaqueConsentDigests, minimumState,
innerApprovalDigest, expectedSnapshot]`. Counts are U64; opaqueConsentDigests
is a sorted list of at most 16 Digests. The outer innerApprovalDigest identifies
the signed approval bytes carried inside encryption; it is not a plaintext body
digest. Both records bind the same publication, object, revision, generation,
audience and roster. Exact encrypted bytes are approved after encryption; the
outer record is never embedded inside the bytes it hashes.

Finalisation and publication require this order:

1. Obtain certified current policy, author intent, accepted roots/devices,
   reviewer authority and opaque-host consent. Freeze their exact versions.
2. The trusted reviewer endpoint inspects exact page/assets, signs inner approval,
   creates a fresh content key through the qualified library, encrypts the exact
   approved material and signs the resulting outer object. A publisher-provided
   ciphertext cannot stand in for reviewer finalisation.
3. Store ciphertext in bounded non-serving staging only on permitted hosts.
   Signed durable receipts are claims about storage, not serving authority.
4. At ordered commit, compare every relevant audience/device/root/admission,
   author sharing, reviewer grant, policy and host-consent version. Rebuild the
   exact root/device/admission arrays from current state and compare them to the
   frozen roster; this covers every entry without an unbounded expected-version
   list. An unrelated commit does not change those arrays. Recheck expiry,
   actual required placement evidence and exact inner/outer context. On mismatch,
   refuse StaleSnapshot; staged material remains non-serving and is discarded or
   re-finalised with a fresh encryption generation and key.
5. A read names exact publication instance, revision, ciphertext and asset
   manifests. Outer minimumState names an already committed prepublication state.
   The publication's executed-result certificate independently records its actual
   committed publication height. The read floor is the maximum of that height,
   the outer prior-state requirement and retained consumer floors, all on the
   same committed chain. An input does not contain its own resulting state digest.
   The client checks both outer and enclosed approval,
   accepted recipient roots and exact content hashes before rendering any bytes.

If removal commits first, a frozen roster containing that device cannot publish.
If publication commits first, the old revision was legitimately issued; removal
ends subsequent authority under the shared freshness deadline. Known revocation
stops an honest consumer immediately. Keys/plaintext already retained cannot be
recalled. Every later revision uses a current roster excluding removed devices
and a fresh key. A height from before removal never authorises new content at a
later minimumState, even inside the nominal freshness window.

A sealed-only target refuses plaintext before host upload, logs, staging, backup
or index. Reviewer delivery uses its explicitly authenticated encrypted endpoint.
Switching HostReadable to Sealed protects the new revision; prior disclosure is
reported. Switching Sealed to HostReadable requires exact author disclosure and
fresh review before plaintext leaves authorised endpoints. Public sealed content
is refused in the initial profile: public anonymous audiences cannot form the
bounded authenticated device roster this profile requires.

## Recovery governance and explicit successor acceptance

`RecoveryPolicy` (114) body is `[custody, threshold, principals, keys,
immutableShared, acceptedBy, expectedSnapshot]`.
Custody is OwnerSingle=0, OwnerThreshold=1 or SharedThreshold=2. Threshold is
respectively 1, 2 or 2. Principals is a sorted list of IDs of length respectively
1, 1 or 3. Keys is a sorted list of `[principal:Id, signingKey:Ed25519Key]` of
length respectively 1, 3 or 3. Keys must be distinct; SharedThreshold has exactly
one key per distinct independently enrolled principal. Three aliases for one
person are not three custody principals. The installed workflow records this
human custody assumption explicitly; software cannot prove who controls a key.
`immutableShared` may be true only for SharedThreshold. `acceptedBy` is the
sorted set of new-policy key fingerprints whose signatures accept this exact
policy, meeting its threshold. A key fingerprint is SHA-256 of the exact raw
32-byte public key; it is an identifier, never a signature or authority proof. Recovery keys remain offline and separate from
online administrator and consensus identities.

During healthy operation, current recovery-policy threshold signs an update,
proposed custody accepts the same bytes, and current BFT authority commits the
exact expected predecessor. Shared-to-owner or threshold reduction additionally
changes the network trust contract; affected clients explicitly accept it before
using new authority. A client that has not accepted refuses TrustChanged.
Immutable shared custody cannot weaken under the same network identity, even
with current threshold signatures. It requires a newly accepted network identity.
Old-policy authorisation and proposed-policy acceptance are two separately
verified signed envelopes over the exact same proposed kind-114 payload. The
first permits only old-policy signers and satisfies its threshold; the second
permits only proposed-policy signers and satisfies its threshold. Each has at
most three signatures even when the key sets are disjoint. The operation schema
supplies these explicit signer-authority contexts; signatures from both cohorts
are never pooled to satisfy either threshold. Genesis has only the proposed
acceptance envelope and the independently authenticated bootstrap binding.

`RecoveryDeclaration` (115) body is `[operation, predecessorNetwork,
predecessorIncarnation, predecessorCheckpoint, predecessorRecoveryPolicy,
successorNetwork, successorIncarnation, successorDescriptor,
historicalImportDigest, declarationNonce]`.
The successor network and incarnation are new distinct IDs. Descriptor is Digest;
historicalImportDigest is Digest|null; checkpoint is Point; the old policy is
VersionRef. Signers independently sign the same exact declaration. Duplicate
keys count once; SharedThreshold also counts distinct enrolled principals.
No hidden owner override, timeout or lost-key flag changes the threshold.

`RecoveryAcceptance` (116) body is `[operation, acceptingClient,
declarationDigest, successorDescriptor, independentlyVerifiedBinding,
observedConflictDigests]`. Binding is Digest of the explicit independently
authenticated trust decision. Conflict digests is a sorted list of at most 16;
nonempty causes RecoveryConflict and no automatic transition. More conflicts
also refuses. Merely verifying a threshold signature returns
AwaitingIndependentAcceptance, never an active successor connection.

Two declarations signed A+B and A+C can both meet 2-of-3 when A equivocates.
Neither timestamp, epoch, work score, mirror count nor a successfully decrypted
object chooses the successor. An observed conflict stops automated acceptance.
Explicit independent acceptance does not prove an unseen conflict impossible.
Old grants, invitations, host consents, treaties and rosters are not current in
the new network. Imports are quarantined historical objects until fresh authority
and exact author/host decisions permit new publication. Network recovery cannot
recover users' private decryption keys or erase old plaintext copies.

## Durable lifecycle and host consent

`HostConsent` (105) body is `[host, deployment, operator, roles, volumes,
exposure, placement, limits, allowOpaque, reviewerRoots, validity,
profileDigest, withdrawalGeneration]`.
Roles is a sorted set: Authority=0, PageStore=1, MediaStore=2, MailStore=3,
TransferStore=4, Relay=5, SearchIndex=6, Bridge=7, SshService=8. Volumes is
the sorted set of registered volume IDs. Exposure is a sorted list of at most
16 `[service:Id, endpoint:Id]` records; an endpoint resolves only through approved
configuration. AllowOpaque is boolean and reviewerRoots a sorted set of at most
16 reviewer identity roots. Its local operator signature is mandatory and cannot
be replaced by network Tier 0. Consent binds the complete reviewed profile
digest and expected withdrawalGeneration. No general filesystem/network grant
or arbitrary runtime arguments exist in these records.

`DesiredProfile` (117) body is `[deployment, softwareDigest, stateContract,
roles, volumes, exposure, limits, placement, expectedLocalGeneration]`.
StateContract is U64 value 1, identifying HyperNetRuntime/1; it does not
identify or accept a previous deployment's authority database schema; other types match HostConsent.
Hash the profile first, then obtain consent for that exact digest. The profile
contains no consent reference. A client-only profile has no roles, volumes or
exposure and needs no hosting consent. Each separately optional role needs its
own applicable authority and local consent; joining never enables a listener.

`LifecycleState` (118) body is `[deployment, desiredProfile, acceptedConsent, status,
withdrawalGeneration, activeGeneration, ownedResources, failureCode]`.
DesiredProfile is VersionRef; acceptedConsent is VersionRef|null. Null is allowed
for client-only profiles and non-serving Installed, Configured, AwaitingConsent,
Failed or Recovering states. A hosting role cannot start or serve with null
consent. Generation counters are U64; resources a sorted list
of at most 64 IDs; failureCode is a finite code or null. Status codes are
Installed=0, Configured=1, AwaitingConsent=2, Stopped=3, Starting=4, Ready=5,
Degraded=6, Failed=7, Withdrawn=8, Updating=9, Recovering=10.

For every change: validate expected local generation under the durable lifecycle
lock; persist intended generation/owned resources/withdrawal state and sync before
launching; prepare resources without serving; activate only if the same generation,
consent, withdrawal counter and verified software still apply. Commit activation
and report Ready only after confinement, current authority, quota/storage and
role-specific endpoint checks. Readiness itself never substitutes for a fresh
per-operation authority permit.

Withdrawal advances a durable tombstone before stopping work. An in-flight start
or update with the old generation cannot activate, even offline. Stop preserves
state and consent. Withdrawn requires explicit new local consent covering the
current tombstone and a new desired generation; old consent cannot restart it.
A crashed manager reconciles only exact labelled resources in its durable record.
Unknown labels, edited profiles and stale backups enter non-serving Recovering or
Failed. They do not delete unrelated resources or restart from guessed authority.
Reconfiguration never widens mounts, ports, quotas, opaque storage or placement
without the corresponding fresh consent. Preparation failure preserves the last
valid state only while its own consent and authority remain valid.

## Search scope and returned metadata

`SearchRequest` (119) body is `[operation, scope, terms, combination,
namespaces, resultLimit, cursor, retainedView, expectedSnapshot]`.
Scope is Local=0 or Network=1. Terms is the bounded UTF-8 literal list;
combination is All=0 or Any=1; namespaces a sorted list of at most 64 IDs;
limit U64 1-100; cursor Digest|null; retainedView is Current=0 or Historical=1.
Historical is local-only and visibly indicates absent current revocation claims.

Local means zero network attempts from query entry through suggestions, spelling,
empty results, failures, pagination and clear/reset. Missing local authority
returns a stale/locked result unless Historical was explicitly selected. It must
not connect just to refresh permissions in response to the query. Separately
initiated background synchronisation never receives query bytes or derived terms.
An explicit subsequent Network request is a new action that clearly names the
selected network and sends its query only through the mandatory reader connector.
No implicit combined mode or cross-network fan-out exists.

Persistent local indexes of Sealed content are encrypted and obey user placement.
Server indexes contain only currently approved HostReadable content and explicitly
permitted public metadata. Every returned title, snippet, count, suggestion,
facet, cursor and score is scoped by current access and minimumState before
release. Hidden objects do not affect visible ranking statistics. Cursors bind
query digest, exact effective scope, network, policy state and index generation;
changed scope/current authority invalidates them rather than retaining access.
Default diagnostics contain neither query text nor payload-derived terms.

## Conformance boundary

The finite refusal codes in vectors and signed results are:

```text
0 None                  1 MalformedRecord        2 LimitExceeded
3 MissingAuthority      4 GrantEscalation        5 GrantCycle
6 GrantRevoked          7 Expired                 8 PolicyIntersection
9 RouteAssurance       10 MissingConsent         11 PlacementDenied
12 StaleSnapshot       13 TrustChanged           14 RecipientContinuity
15 DeviceRevoked       16 KeyPossession          17 AudienceMismatch
18 ReviewMismatch      19 SealedPlaintext        20 PublicSealedUnsupported
21 BelowPolicyFloor    22 AuditUnavailable       23 RecoveryThreshold
24 RecoveryConflict    25 IndependentAcceptance  26 NewNetworkRequired
27 HistoricalOnly      28 GenerationConflict     29 Withdrawn
30 NotReady            31 SearchScope            32 CursorScope
33 PreviewLimit        34 UnknownDependency      35 InvalidDisclosure
36 InvalidSignature    37 WrongContext           38 KeyReuse
```

`None` accompanies Permit. A workflow may return Pending with
IndependentAcceptance, HistoricalOnly or NotReady and must describe its lack of
current authority. Refuse is a completed denial; Pending is never permission to
serve. Wire diagnostics use these codes and bounded record references; free text
is local explanatory rendering. When several independent conditions fail, report
the smallest numeric failure code after structural/signature verification has
completed. No error response includes secrets or payload-derived data.

The vectors specify expected policy decisions and externally visible effects.
They are design obligations until a named evaluator or installed implementation
executes them. Passing a policy evaluator cannot qualify cryptographic routines,
consensus safety, actual relay routing, secure persistence or independent custody.
Installed authority tests must execute recipient and recovery ordering. Storage
checks cover sealed and placement transitions; lifecycle checks cover races;
route checks observe all network paths; search checks observe disclosure and
cursor behaviour. Each uses these record identities and refusal semantics.
