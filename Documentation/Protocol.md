# Authority protocol

Clients send `POST /V1/Command` over TLS 1.3 with a pinned network CA and a
verified server name. HTTP redirects, TLS early data, public trust roots and
anonymous hosting are not supported. The content type is `application/json`.

The envelope has exactly four fields:

```json
{"network":"32-byte lowercase hexadecimal","publicKey":"32-byte lowercase hexadecimal","payload":"unpadded base64url bytes","signature":"64-byte lowercase hexadecimal"}
```

An Ed25519 signature covers these concatenated bytes, in this order:

1. The ASCII domain `HyperNet/Request/1` and one zero byte.
2. The 32 decoded network identity bytes.
3. The 32 decoded public key bytes.
4. The exact decoded payload bytes.

JSON is not canonicalised before signature verification. The payload is strict
UTF-8 JSON with these fields: `version` (integer 1), `requestId` (16 random bytes,
lowercase hexadecimal), `issuedAt` (Unix seconds), and `command`. Unknown fields,
duplicate fields and trailing data are rejected. Clients must preserve the exact
envelope when retrying a request. The maximum envelope is 96 KiB and the maximum
decoded payload is 64 KiB. Integer values are unsigned 64-bit values.

A timestamp can be at most 60 seconds old or 30 seconds ahead of authority time.
An exact mutation retry within that window returns its original committed result
and epoch after a current authority check. Reusing a mutation identifier with
different bytes is denied. Mutation records expire after that window; the
timestamp prevents replay after removal. Read-only `Status` and `Heartbeat`
commands always evaluate current state and do not retain replay receipts.

| Command | Additional fields | Permission |
| --- | --- | --- |
| `Status` | Optional `deviceKey` | Own active membership; administrator for another member |
| `Invite` | `verifier`, `deviceKey`, `grants`, `expires` | Administrator |
| `Redeem` | `secret` | Device named in the invitation |
| `Grant` | `deviceKey`, `grants`, `expires` | Administrator |
| `Revoke` | `deviceKey` | Administrator |
| `Consent` | `profile`, `grants`, `expires`, `certificate`, optional `document` | Separate hosting member, own device |
| `Withdraw` | None | Own member; permitted after network revocation |
| `Heartbeat` | `profile` | Active hosting consent and matching mTLS certificate |

The command discriminator is `type`. A status payload can therefore be:

```json
{"version":1,"requestId":"00000000000000000000000000000001","issuedAt":1780000000,"command":{"type":"Status"}}
```

Device keys are 32-byte lowercase hexadecimal Ed25519 public keys. Invitation
secrets are 32 random bytes; `verifier` is their SHA-256 digest in lowercase
hexadecimal. A secret is delivered separately through an authenticated channel.
The issuer records only its verifier. Invitations expire within seven days and
are bound to one device. The initial membership expires with the invitation.
An administrator can subsequently renew it with `Grant`. Same-device redemption
retries do not resurrect revoked or expired membership. Device revocation is
permanent; re-enrolment requires a new key.

The grant mask uses bit 0 for membership, bit 1 for hosting, bit 2 for
administration and bit 3 for Federation service. Accepted masks are 1, 3, 5, 7
and 9. Federation requires a separate member key with mask 9; it cannot combine
with hosting or administration. An administrator cannot remove the final active administrator.
`Grant` replaces the current mask and expiry; it does not add hidden privileges.

`profile` is the SHA-256 digest of the exact local hosting consent document.
`certificate` is the SHA-256 digest of the DER-encoded client leaf certificate.
Client certificates chain to the configured hosting transport CA. The authority
does not hold that CA's private key. Normal membership and enrolment use server
TLS plus device signatures. Hosting heartbeats additionally require mTLS bound
to the consent. Network permission and local consent must both include hosting.
Consent cannot outlive membership or exceed seven days. A heartbeat authorises
no more than five seconds of hosting, and every new operation needs fresh
authority. Local withdrawal stops the host immediately, independently of quorum.

Use distinct device keys for administration, ordinary reading/publishing, and
hosting. A retained consent record permanently identifies a service credential,
including after withdrawal or removal of its hosting grant. It cannot invoke
ordinary Pages client commands or administrative commands. A hosting grant without
administration also denotes a service credential. Administrator credentials cannot
register hosting consent, and a consented credential cannot receive administration.
An administrator without consent can retain the historical grant mask 7; that
mask does not permit the key to become a host.

A retained bridge-consent record has the same permanent service separation.
Neither hosting nor bridge consent can be used to change between service roles.
Federation commands and evidence use this request envelope, with the additional
purpose-separated signatures and bilateral checks in [Federation.md](Federation.md).

For Pages, `document` contains the unpadded base64url encoding of the exact signed
version-2 consent file, including its JSON whitespace and final newline. Its
SHA-256 must equal `profile`. The device signature and the network, device, expiry,
resources, Pages service, namespace set and cache quota must all validate. A
version-1 consent, or a registration without the document, permits no Pages
replication. Namespace names are case-sensitive ASCII labels matching
`[A-Za-z][A-Za-z0-9]{0,31}`. Labels are shared within a network; page authorship is
bound separately to the signing device.

Replies are JSON objects with `ok`, `code`, `epoch` and `result`. Successful
commands use code `Ok`. Errors contain static codes, without submitted values
or credential details. A status result contains `deviceKey`, `member`,
`consent`, and `authorityRevision`. Administrators also receive counts of
members and invitations. A heartbeat result contains `effectiveGrants`,
`leaseExpires`, `profile`, and `authorityRevision`. Mutation results identify
the affected device or invitation verifier, never an invitation secret.

The permission epoch advances with membership, invitation, consent and page
submission, review or withdrawal changes.
The authority revision orders every successful request, including freshness
checks. An unavailable quorum yields `AuthorityUnavailable`; it never permits
local fallback. A client must treat network failures, malformed replies and
unknown error codes as denial. TLS and signatures provide authentication, not
protection against an authorised administrator or a compromised endpoint.

## Page objects and review

`HyperNetPage/1` is the only page profile. The exact UTF-8 source starts with that
header and is limited to 16 KiB, 512 lines and 1,024 UTF-8 bytes per line. The
published grammar defines the narrower text and link rules. Source bytes are
validated before quarantine; no executable payload, asset import, HTML renderer,
script or external fetch is available. `audience` is exactly `Members` in this
profile. More restricted audiences need a separate permission and placement
contract; they are not implied by a namespace name.

Ordinary client Pages commands require active membership; human review additionally
requires administration. A separate [application grant](ApplicationProtocol.md)
can delegate exact native Page operations without creating membership. Hosting
credentials use the replica commands instead.
The following fields appear inside the `command` object beside `type`:

| Command | Fields | Result |
| --- | --- | --- |
| `PageSubmit` | `pageId`, `expectedVersion`, `namespace`, `audience`, `profile`, `digest`, `body` | Pending page ID, version, revision, digest and submission digest |
| `PageQueue` | Optional `namespace`, `after` | Pending metadata entries and next cursor |
| `PageInspect` | `pageId` | Author/admin view of current version, pending signed submission and published descriptor |
| `PageReview` | `pageId`, `expectedVersion`, `revision`, `digest`, `profile`, `author`, `namespace`, `audience`, `submissionDigest`, `decision` | New version, decision and any current published descriptor |
| `PageWithdraw` | `pageId`, `expectedVersion` | New version with no published page |
| `PageList` | Optional `namespace`, `after` | Visible published descriptors, next cursor and freshness context |
| `PageRead` | `pageId` | Current descriptor, signed bundle and freshness context |

Page IDs are 16 random bytes in lowercase hexadecimal. `digest` is SHA-256 of
the exact UTF-8 body. A new page starts with `expectedVersion: 0`; the author and
namespace become immutable. The revision of a submitted object is
`expectedVersion + 1`. The page version increases with submission, review and
withdrawal, so content revision numbers need not be consecutive. A mutation with
a stale expected version fails. The author can inspect the page after losing a
submission response, and exact request retries follow the mutation receipt rules.

New submissions enter quarantine. Their author and administrators can inspect
them; normal discovery, reading and replication cannot. Queue pagination returns
at most 32 entries sorted by page ID. Ordinary authors see only their submissions.
`after` is an exclusive page-ID cursor. Published discovery uses the same page size
and cursor ordering. Pagination observes current state on each request, not a
long-lived snapshot.

An approval is a distinct `PageReview` with `decision: "Approve"`. Manual review
is the default; application review requires an explicit scoped policy and mode.
`Reject` discards the pending object. Every review field must match the pending
submission, including its signature-message digest. Replacing an existing page
keeps its previous approved revision readable while the replacement is pending.
Rejection preserves that previous publication. Approval atomically publishes the
replacement. Author or administrator withdrawal removes both pending and published
objects and retains the version tombstone. An earlier signature cannot resurrect
the withdrawn revision. Application reviews additionally bind policy, mode and a
signed `reviewExpires` deadline. It must be later than authority time and at most
300 seconds ahead. Human reviews may omit this deadline; adapter-driven human
reviews should include it. The authority checks it again immediately before the
publication transaction. Archived proof verification does not revive a decision
whose live deadline has passed.

A `PageDescriptor` has these fields, in this order for inventory hashing:

```text
pageId, publicationVersion, revision, author, reviewer, namespace, audience,
profile, digest, submissionDigest, approvalDigest
```

`publicationVersion` is the version produced by approval. It stays unchanged while
a different draft is pending. `author` and `reviewer` are signing public keys.
`submissionDigest` and `approvalDigest` are SHA-256 of each exact request signature
message defined above, including its domain, network and public key.

A `PageBundle` contains exactly `submission` and `approval`, each an ordinary
signed request envelope. The body occurs only inside the signed `PageSubmit`.
Its approval envelope must contain a matching `PageReview` with `Approve`.
Verification checks both Ed25519 signatures, all descriptor bindings, profile,
grammar and body digest. The original request timestamps remain part of the
signed proof, but archived verification does not apply the live-request timestamp
window. A valid archived signature proves bytes; it does not prove current
publication or current permission.

Normal reading also requires a fresh authoritative published descriptor, an
currently authorised author and reviewer. Application signers require their live
grant and current owner rights. The fresh read checks
revocation and withdrawal at its authoritative linearization point. Replies carry
`authorityRevision` and `validUntil`, no later than five seconds after the check
or an applicable membership or application-grant expiry. Clients must verify the bundle and freshness
before rendering it. Previously read text cannot be recalled from a recipient.

The serialized submission envelope is limited to 48 KiB, the approval envelope
to 4 KiB, and the complete bundle to 56 KiB. The authority admits at most 256
lifetime page IDs, 16 per author, and four simultaneously pending pages per author.
Quarantine has a 4 MiB logical payload budget and published objects an 8 MiB
budget, independent of the authority metadata's existing 1 MiB limit. Capacity
failure grants no publication. Tombstones are not silently reused.

## Consenting replicas

Replicas connect outward through their fixed relay and have no incoming page
listener. They hold no etcd credentials. Version-2 consent explicitly enables
`services: ["Pages"]`, 1 to 16 namespace labels and a bounded volatile cache.
Version-1 hosts never poll these APIs. Each replica call additionally requires a
matching verified mTLS certificate and current hosting consent.

| Command | Fields | Result |
| --- | --- | --- |
| `PageSync` | `profile`, optional `knownInventory`, optional `fetch` page ID | Current scoped inventory, optional fetched bundle and assigned read tickets |
| `PageReplicaRequest` | `pageId`, `replicaDeviceKey`, `publicationVersion` | Reader-owned `ticketId`, descriptor and expiry |
| `PageReplicaResult` | `ticketId` | `state: "Pending"` or `state: "Ready"` with verified replica bytes |
| `ReplicaDeliver` | `profile`, `ticketId`, `bundle` | Delivery acknowledgement |

`PageSync` returns `profile`, `authorityRevision`, `validUntil`,
`inventoryDigest`, `entries`, `bundle`, and `requests`. `entries` is the full
currently visible, consented inventory, at most 256 descriptors, or null if its
digest equals `knownInventory`. It is sorted by page ID. `bundle` is the requested
page's approved bundle or null. `requests` contains at most four
`{ticketId, descriptor, expires}` objects assigned to that replica. The complete
reply is bounded to 256 KiB. A replica replaces its inventory and prunes incompatible
cache entries whenever a new inventory is supplied.

The inventory digest is SHA-256 of ASCII `HyperNet/Inventory/1`, one zero byte,
and the compact UTF-8 JSON entries array. Descriptors use the exact field order
listed above, ordinary unsigned decimal integers, and no whitespace. All string
values are validated ASCII without characters requiring JSON escapes. Replicas
recompute this digest; when entries are null the token must equal their previous
token. The inventory token is a change detector, not an offline publication grant.

To read from a replica, a client selects a host and the exact current publication
version, creates a ticket, then polls that ticket. Tickets last 15 seconds and are
limited to 16 globally, two per reader and four per host. This interval allows a
cache miss to be fetched; it is not an authorisation lease. A host verifies its
cached descriptor and signed bundle before `ReplicaDeliver`. The authority then
rechecks the reader, host, consent scope and exact publication. The reader's result
poll performs those checks again. Changed or withdrawn publication, expired or
revoked identities, and withdrawn hosting consent cause denial.

A ticket ID is the 32-byte request digest in canonical lowercase hexadecimal.
A pending result contains `state`, `ticketId` and `expires`. A ready result contains
`state`, `ticketId`, `descriptor`, `bundle`, `authorityRevision` and `validUntil`.
Only the ticket owner can receive it. No origin fallback occurs when a selected
replica is unavailable. An expired ticket requires a new request. A historical
approval, a cached file or a previous inventory never authorizes stale delivery.

Mail authority commands and the separate store endpoint are specified in
[Mail protocol](MailProtocol.md). Mail-only children are not general members;
private store admission is read-only and never enters authority receipts.

Recipient-accepted file offers and direct encrypted storage are specified in
[Transfer protocol](TransferProtocol.md). Separately accepted native SSH grants
and supervised service operation are specified in [SSH services](SshServices.md).
Neither feature grants cross-network access or general host administration.
