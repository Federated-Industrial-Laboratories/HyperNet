# Mail protocol version 1

Mail authority commands use the signed `/V1/Command` envelope documented in
[Protocol](Protocol.md). All objects reject unknown and duplicate JSON fields.
Hexadecimal identifiers are lowercase. Binary encodings are unpadded URL-safe
base64. The authoritative field definitions are in `Source/MailTypes.rs` and
`Source/Types.rs`; alternate clients must preserve exact signed payload bytes.

A `SignedMailObject` contains `network`, `publicKey`, `payload` and `signature`.
The Ed25519 signature covers `domain || network[32] || publicKey[32] || payload`,
with decoded binary keys/network and decoded exact payload JSON. Domains include
the final NUL byte: `HyperNet/MailManifest/1`, `HyperNet/MailHost/1`,
`HyperNet/MailOperation/1`, `HyperNet/MailPermission/1`, `HyperNet/MailPolicy/1`
and `HyperNet/MailReceipt/1`. An object digest is SHA-256 of the same full
purpose-separated signature input, not the outer JSON or signature bytes.

Address IDs are SHA-256 of `HyperNet/MailAddress/1\0 || network[32] || owner[32]`.
Device IDs are SHA-256 of `HyperNet/MailDevice/1\0 || address[32] || requestKey[32]`.
A manifest payload contains `version`, `network`, `addressId`, `ownerKey`,
`generation`, `previousDigest`, `expires`, `devices`, `storageHosts`,
`requiredCopies`, `retentionSeconds`, `deleted`. Each device contains `deviceId`,
`requestKey`, `mlsSignatureKey`, `permissions`, `expires`. A deleted manifest has
no devices or hosts and zero required copies. Every positive manifest selects
at least one store and one device. New generations invalidate outstanding public
packages and claims for the affected mailbox; admitted historical ciphertext
retains its original signed manifests and permission.

## Authority commands

| Command | Command fields | Actor and result |
| --- | --- | --- |
| MailAddressCreate | manifest | Ordinary admitted member; addressId, generation, manifestDigest |
| MailAddressUpdate | addressId, expectedGeneration, manifest | Owner; same result |
| MailAddressDelete | addressId, expectedGeneration, manifest | Owner; same result |
| MailAddressGet | addressId | Admitted member/current mail child/owner; manifest, authorityRevision, validUntil |
| MailHostRegister | consent | Dedicated admitted host with matching mTLS; hostKey, generation, consentDigest |
| MailHostWithdraw | hostKey, expectedGeneration | Exact known host key; hostKey, generation, active:false |
| MailHosts | none | Directory reader; hosts, authoritySigner, authorityRevision, validUntil |
| MailKeyPackagesPublish | addressId, deviceId, manifestGeneration, packages | Read child; published, consumedReferences |
| MailKeyPackagesClaim | senderAddress, senderDevice, recipientAddress, recipientManifestDigest, claimId, expires | Send child; claim |
| MailKeyPackagesClaimStatus | senderAddress, senderDevice, claimId | Same Send child; claim or null |
| MailAuthorise | hostKey, operation | Exact mTLS store; signed permission; genuinely read-only |
| MailPolicySync | hostKey | Exact mTLS store; signed selected-address policy; genuinely read-only |

Each public key package has `deviceId`, `reference`, `expires`, `package`; the
last two binary fields represent an MLS reference and TLS-encoded KeyPackage.
A claim includes `version`, `network`, `senderAddress`, `senderDevice`, `claimId`,
`recipientAddress`, `recipientGeneration`, `recipientManifestDigest`, `expires`,
`packages`. It includes exactly one package for every current Read device.
Publishing byte-identical current packages is idempotent. `published` counts
new inventory only; `consumedReferences` reports exact retries already consumed
without restoring inventory. Rebinding consumed package bytes is rejected with
`MailKeyPackageConsumed`. Clients retain the associated private packages.

Directory freshness comes from a current authenticated authority response with
revision and validity bound. Manifests and host descriptors remain independently
signed. Pin the authority signer during trusted provisioning; directory discovery
alone must not silently replace an existing pin.

## Store requests

`POST /V1/Mail`, content type `application/json`, carries
`{"operation":SignedMailObject,"payload":base64-or-null}`. The payload is present
only for Put. Responses use `{ok,code,epoch:0,result}`; actual authority epoch and
revision are in the signed admission. TLS 1.3 is required; signed mail child
requests authenticate the user, while the store uses a separate mTLS identity
when consulting the authority.

Every operation contains `version`, `network`, `operationId`, `issuedAt`,
`hostKey`, `action`, `addressId`, `deviceId`, `messageId`, `manifestGeneration`,
`manifestDigest`, `payloadDigest`, `payloadBytes`, `after`, `route`. Address and
device always identify the acting mailbox (the sender for Put and Receipt).
Non-applicable optional fields are null. Requests are valid for at most 60 seconds
with up to 30 seconds future clock tolerance. Permissions have no future slack.

| Action | Required operation fields beyond actor identity | Result |
| --- | --- | --- |
| Put | route, messageId, payloadDigest, payloadBytes > 0 | signed Stored receipt |
| Receipt | original route, messageId, payloadDigest; payloadBytes 0 | receipt or null |
| List | optional after cursor; payloadBytes 0 | up to 32 signed receipts, next cursor or null |
| Fetch | messageId; payloadBytes 0 | payload, original signed operation, original signed admission, receipt |
| Acknowledge | messageId, payloadDigest; payloadBytes 0 | signed Received receipt |
| Delete | messageId, payloadDigest; payloadBytes 0 | signed Deleted receipt |

Put/Receipt require Send; List/Fetch/Acknowledge require Read; Delete requires
Delete. The owner can sign Delete with `deviceId == addressId`. No other owner
operation bypasses child read or send permissions. Every operation verifies the
current parent admission, actor manifest, scope, selected store and host consent.
Put additionally requires the current recipient manifest and complete live claim.

A route contains `version:1`, `profile:"HyperNetMailMls1"`, `network`, `messageId`
(16-byte hex), `replacement`, `senderAddress`, `senderDevice`, `recipientAddress`,
`recipientGeneration`, `recipientManifestDigest`, `claimId` (16-byte hex),
`expires`. A MailCiphertext JSON object contains `route`, `senderManifest`,
`recipientManifest`, `welcome`, `message`. The last two values encode MLS bytes.
The operation payload digest hashes the exact raw MailCiphertext JSON. The store
checks its route and independently signed manifest bindings; the recipient also
checks the original operation/admission, exact ciphertext digest, required MLS
receiving set, sender identity and encrypted route binding before displaying text.

A signed permission contains `version`, `network`, `authorityEpoch`,
`authorityRevision`, `hostKey`, `hostGeneration`, `operationDigest`, `addressId`,
`manifestGeneration`, `manifestDigest`, `issuedAt`, `expires`. It lasts at most
five seconds and is not reusable for a different operation. A receipt contains
`version`, `network`, `hostKey`, `hostGeneration`, `messageId`, `replacement`,
`payloadDigest`, `recipientAddress`, `recipientGeneration`, `status`, `recordedAt`,
`expires`. Historical admission is verified at its recorded acceptance time,
not presented as a current grant. Clients independently obtain current read
permission through the store before fetching it.

## Host consent and limits

A host consent contains `version`, `network`, `hostKey`, `generation`,
`services:["Mail"]`, `endpoint`, `address`, `caDigest`, `certificateDigest`,
`authorityEndpoint`, `authorityAddress`, `authoritySigner`, `memoryBytes`, `pids`,
`cpuQuota`, `cpuPeriod`, `stateBytes`, `expires`. Both endpoints are HTTPS origin
URLs and addresses are fixed literal socket addresses. Resource values bound the
worker with the fixed relay overhead specified in [MailStore](MailStore.md).

The profile permits 64 lifetime addresses, 16 lifetime hosts, eight devices and
four stores per address. Public inventory permits 32 packages/device, 256 total,
eight per publication and 4096 decoded bytes/package. There are at most 128 live
claims, 16 per sender and 32 per recipient. Up to 4096 consumed package hashes
and their binding metadata remain for seven days. The overall authority state
limit of 1 MiB may be reached sooner. State never evicts safety history silently.

A MailCiphertext is at most 128 KiB; a store request is at most 192 KiB. A store
retains at most 512 records, 64 per recipient, including deletion tombstones.
Its fixed state-file capacity may bind earlier. Retention is 60--604800 seconds;
manifest, device, claim and host lifetimes are bounded to seven days by their
signed parent policies. Expired data and confirmed removed placements are
pruned; temporary authority loss does not trigger destructive cleanup.

Clients must handle `MailUnavailable`, `MailPermissionDenied`, `MailOwnerMismatch`,
`MailGenerationConflict`, `MailClaimConflict`, `MailKeyPackagesUnavailable`,
`MailKeyPackageConsumed`, `MailQuotaExceeded`, `MailStaleOperation`,
`MailInvalidObject`, `MailPlacementDenied` and `MailMessageConflict`. Transport or
unavailable-authority responses never imply delivery. Preserve encrypted pending
state, query original receipts and retry exact accepted objects within current
permissions. Do not choose an unselected fallback host.
