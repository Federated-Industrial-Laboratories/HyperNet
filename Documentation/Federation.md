# Federation

Federation transfers explicitly shared, approved Pages between two independent
networks. Both administrators accept the same one-way treaty. The original
author opts in to sharing each exact publication, and a destination administrator
reviews the imported bytes before local members can read them. Imported Pages
remain separate from native Pages and cannot be exported onward. Reverse sharing
requires a separate treaty, author consent and destination review.

A treaty is not shared membership or shared administration. Neither network can
invite users, set permissions or approve native Pages on the other. Existing
`Members` publication alone never permits export. Trust in the remote authority
is explicit and limited to its treaty's native namespace and page profile.

## Establish the agreement

Provision both networks using [Authority.md](Authority.md), including their
dedicated online Federation signers and separate Federation storage prefixes.
Generate two further, distinct device identities for the bridge. Invite one to
each network with grant mask 9. Keep all four signing keys distinct. Bridge keys
must not be ordinary reader, author, administrator or replica credentials.

Exchange the network identities, authority signing public keys, bridge public
keys, intended namespaces, TLS names and CA fingerprints through an independently
authenticated channel. Do not accept trust roots obtained from page content,
discovery responses or redirects.

Prepare a UTF-8 JSON treaty with these fields, in this serialization order:

```text
version, agreementId, sourceNetwork, destinationNetwork, sourceAuthorityKey,
destinationAuthorityKey, sourceBridgeKey, destinationBridgeKey, sourceNamespace,
destinationNamespace, service, profile, expires
```

`version` is 1. `agreementId` is 16 random bytes in lowercase hexadecimal.
Network identities and public keys are 32-byte lowercase hexadecimal values.
The networks differ. Namespace labels use `[A-Za-z][A-Za-z0-9]{0,31}`.
`service` is `Pages`; `profile` is `HyperNetPage/1`. `expires` is a Unix timestamp
in the next seven days. The treaty digest is SHA-256 of ASCII
`HyperNet/FederationTreaty/1`, one zero byte, and the compact typed JSON bytes in
the field order above. The serializer emits unsigned decimal integers and no
whitespace; validated strings contain no characters requiring JSON escapes.

An administrator of each network submits `FederationAccept` with the identical
`treaty` object. Each authority checks that its configured signer equals the
pinned local authority key. Agreement identifiers are immutable. Acceptance of
identical active terms is idempotent; withdrawal cannot be reversed. Changed
terms or a later expiry need a new agreement identifier and new explicit consent.

The bridge owner signs a single bounded resource and endpoint consent document
with both bridge keys. Register its exact bytes and transport-certificate
fingerprints in both networks. Both registrations must have the same profile
digest. Start the separate confined bridge using [Bridge.md](Bridge.md).
Changing endpoints, CA bytes, identities, namespaces or resource limits requires
new owner consent and registration. Neither authority can widen that consent.

## Share, review and read

The author first publishes through the ordinary native Pages review procedure.
The author then submits `FederationShare` with the agreement ID and digest, the
page ID, exact publication version, descriptor digest and `allow: true`. The
authority checks current author membership and ownership. An administrator
cannot substitute for this author signature. The descriptor digest is SHA-256
of ASCII `HyperNet/FederationPage/1`, one zero byte, and compact typed
`PageDescriptor` JSON in the order defined in [Protocol.md](Protocol.md).

`allow: false` requires the same current publication bindings. If source review
authority is unavailable, export already stops but a failed sharing withdrawal
leaves the earlier opt-in intact. It can resume after review authority recovers.
Repeat the withdrawal after recovery or withdraw the native page as its author.

The bridge obtains a destination permit, fetches only the approved and explicitly
shared source inventory, and imports each verified proof bundle into destination
quarantine. `FederationQueue` lists pending metadata. `FederationInspect` returns
the original source signatures, author share and exact descriptor for manual
inspection. Inspection may expose an expired pending import to administrators;
it is labelled with its source evidence expiry and is never an ordinary read.

`FederationReview` binds the exact agreement, page, local version and descriptor
digest. `Approve` makes that descriptor readable while both networks remain
freshly authorised. `Reject` suppresses it. `FederationPageWithdraw` removes local
publication and pending review. Repeated imports of an unchanged descriptor only
refresh its evidence; they do not undo rejection or withdrawal, advance the page
version, consume mutation receipts or require another review. A changed source
publication requires a new author share and a new destination review. Until that
review succeeds, the replacement is unavailable to destination readers.

`FederationRead` returns the original native bundle, author share, destination
approval and both authority attestations. Clients verify all signatures, exact
descriptor bindings, local network, treaty and evidence expiry before rendering.
Display the source network and namespace separately from the local destination
namespace. Links never create a treaty or import content automatically.

The author can stop export with `FederationShare` and `allow: false` for the
current exact publication. Withdrawing the native publication, removing its
author or reviewer, or withdrawing the source treaty also stops new exports.
A destination administrator can withdraw its treaty or imported publication;
the bridge owner can withdraw consent locally or in either authority. Stop the
local bridge first when immediate local resource withdrawal is required.

## Commands

All commands use the signed `Request/1` envelope from [Protocol.md](Protocol.md).
The discriminator is `type`; the table lists the remaining fields. Optional
fields can be omitted or null. Read and review clients use ordinary membership;
bridge service calls also require their registered mTLS certificate.

| Command | Fields | Caller and result |
| --- | --- | --- |
| `FederationAccept` | `treaty` | Local administrator; immutable accepted terms |
| `FederationWithdraw` | `agreementId`, `expectedVersion` | Local administrator; permanent inactive agreement |
| `FederationAgreements` | None | Member; `entries`, local `authorityKey`, `authorityRevision` |
| `BridgeConsent` | `agreementId`, `profile`, `expires`, `certificate`, `document` | Named local bridge; registers dual-signed exact document |
| `BridgeWithdraw` | None | Own member, including revoked membership; disables local bridge consent |
| `FederationShare` | `agreementId`, `agreementDigest`, `pageId`, `publicationVersion`, `descriptorDigest`, `allow` | Original author; exact publication sharing decision |
| `FederationPermit` | `agreementId`, `profile` | Destination bridge; signed `admission` |
| `FederationExport` | `agreementId`, `profile`, `admission`, optional `pageId`, `includeBundle` | Source bridge; inventory or exact signed export |
| `FederationImport` | `agreementId`, `profile`, `admission`, `export`, optional `bundle`, optional `authorShare` | Destination bridge; imported page ID, local version and state |
| `FederationQueue` | `agreementId`, optional `after` | Local administrator; pending descriptors and versions |
| `FederationInspect` | `agreementId`, `pageId` | Local administrator; exact retained review object |
| `FederationReview` | `agreementId`, `pageId`, `expectedVersion`, `descriptorDigest`, `decision` | Local administrator; `Approve` or `Reject` |
| `FederationPageWithdraw` | `agreementId`, `pageId`, `expectedVersion` | Local administrator; suppresses exact current import |
| `FederationList` | `agreementId`, optional `after` | Local reader; fresh approved descriptors |
| `FederationRead` | `agreementId`, `pageId` | Local reader; independently verifiable fresh publication |

Agreement entries contain `treaty`, `digest`, `version`, `active` and the observed
`sourceRevision` floor. Service credentials see only their named treaties.
`FederationExport` without a page ID returns `entries`, `authorityRevision` and
`validUntil`. With a page ID it returns `descriptor`, `authorShare`, `bundle`
(null unless requested) and `export`. New or changed imports require both
`bundle` and `authorShare`; unchanged imports can omit them.

Queue and list results contain `entries`, `next`, `authorityRevision` and
`validUntil`. `after` is an exclusive page-ID cursor, with up to 32 entries per
reply. Queue entries include `pageId`, local `version`, `descriptor` and
`descriptorDigest`; list entries are source descriptors. Inspection returns
`treaty`, `agreementDigest`, `pageId`, local `version`, optional `pending`,
optional `published` and `sourceValidUntil`. Pending content contains
`descriptor`, `descriptorDigest`, `bundle` and `authorShare`.

Read results contain `treaty`, `agreementDigest`, `descriptor`, `bundle`,
`authorShare`, `approval`, `admission`, `export`, `authorityRevision` and
`validUntil`. `authorShare` is the original positive `FederationShare` envelope;
`approval` is the destination administrator's exact `FederationReview` envelope.
Their digests use the ordinary signed-request message defined in Protocol.md.

## Freshness and authority evidence

Each authority evidence object has `publicKey`, `payload` and `signature`.
`payload` is unpadded base64url encoding of strict JSON bytes. The Ed25519
signature is lowercase hexadecimal over a purpose domain followed by those
exact decoded bytes. Unknown fields, duplicate fields and trailing data fail.
The public key must equal the treaty's pinned authority key. Evidence digests
are SHA-256 of that domain plus payload, without signature bytes.

Admission uses ASCII `HyperNet/FederationAdmission/1` plus one zero byte. Its
payload fields, in serialization order, are:

```text
version, agreementDigest, sourceNetwork, destinationNetwork, sourceBridgeKey,
destinationBridgeKey, destinationProfile, requestId, authorityRevision,
issuedAt, validUntil
```

The destination issues it only after checking its own current treaty, bridge
membership, consent, certificate and quorum. Its lifetime is at most five
seconds, bounded further by the treaty, bridge membership and consent expiry.
`destinationProfile` binds the exact dual-signed consent file. `requestId` binds
the permit request. Version is 1; timestamps are Unix seconds.

Export uses ASCII `HyperNet/FederationExport/1` plus one zero byte. Its payload
fields, in serialization order, are:

```text
version, agreementDigest, admissionDigest, descriptor, authorShareDigest,
sourceProfile, authorityRevision, issuedAt, validUntil
```

The source verifies the admission and its own fresh treaty, bridge permission,
consent, certificate, approved native publication and exact author share.
`sourceProfile` must equal `destinationProfile`. It signs no later expiry than
the admission, source bridge consent, or relevant source membership. Evidence
is returned only after the same authoritative compare-and-swap commit succeeds.
The destination verifies both attestations and the proof bundle before import.
Import rejects source authority revision rollback and publication rollback.

Every ordinary read rechecks current local membership, treaty, bridge consent,
local reviewer and both evidence leases. The destination cannot extend the
source expiry. A local veto applies to subsequent reads immediately at the
authority check. A remote veto or partition stops fresh exports; existing
evidence expires within five seconds. Already delivered bytes cannot be recalled.
Trustworthy synchronized clocks are required. Future-issued evidence is rejected
without clock slack; latency or clock disagreement fails closed.

The bridge never holds voter credentials or an authority signing key. A bridge
compromise can withhold or replay still-valid evidence but cannot approve new
bytes or renew authority evidence. Each network trusts its own authority and
the explicitly pinned remote signer for these claims; the protocol does not
protect against a compromised authority signing key or malicious trusted quorum.

## Storage and limits

Federation uses schema 3. Its authority metadata and source revision floors share
the ordinary quorum and compare-and-swap history. Foreign bundles use
`/HyperNet/<network>/Federation/Foreign/`; author share envelopes use
`/HyperNet/<network>/Federation/Share/`. Native and imported objects remain
separate. Object reads use the exact authority snapshot revision; state and
blob writes commit atomically.

Each network supports eight lifetime treaty identifiers, 32 lifetime source
page IDs shared per treaty, 256 lifetime author share records across treaties,
32 lifetime foreign page IDs per treaty and 128 across all
treaties. Inactive agreements, suppressed page records and service history are
retained to prevent resurrection. Each foreign proof blob is at most 64 KiB;
the aggregate foreign-blob bound is 8 MiB. The existing 1 MiB authority metadata
bound and request/response limits also apply, so the first reached limit wins.
These are logical bounds, independent of etcd's historical MVCC disk usage.
Configure backend quota, compaction, backup retention and storage encryption.
Deleting or suppressing publication is not secure erasure from backups.

Upgrade every broker before enabling Federation, extend its database role, and
preserve its rollback floor. Native Pages and version-1/version-2 hosting retain
their existing consent semantics. After schema 3 is written, older executables
are not a supported downgrade path. See Authority.md for new-network recovery
when authoritative state or trust roots are lost.

## Installed verification

`Tests/FederationWorkflow.py` provisions two isolated three-voter TLS authority
clusters, a confined bridge and independent installed clients. It requires
rootless Podman, OpenSSL, Python cryptography and local etcd tools:

```sh
python3 -B Tests/FederationWorkflow.py --suite /Suite/Bin/HyperNetSuite \
  --node /Build/HyperNet --image IMAGE_ID --etcd-directory /Etcd \
  --seccomp /Package/Seccomp.json --output /Results/Federation.json
```

The fixture uses synthetic identities and content, then removes its containers,
networks and private files. It checks sharing, review, navigation, partition,
recovery and withdrawal. Add `--expiry-only` to focus on actual host and bridge
process termination, including processes deliberately stopped with a signal.
Public Internet qualification requires separately authorised external routing;
the local fixture alone does not establish Internet or remote failure-domain
coverage.
