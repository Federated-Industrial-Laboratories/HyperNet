# Transfer protocol

All JSON uses camelCase and rejects unknown fields. Existing version-1 signed
requests use `POST /V1/Command`. Signed objects have `network`, `publicKey`,
`payload` and `signature`. The payload is unpadded base64url JSON; signatures are
Ed25519 over the domain followed by the decoded network (32 bytes), public key
(32 bytes) and exact payload bytes. Object digests are SHA-256 of that same input.
JSON reformatting changes the digest. Keys/digests are lowercase hexadecimal;
transfer, operation and request IDs are 16-byte random lowercase hexadecimal.

Transfer domains are `HyperNet/TransferHost/1`, `HyperNet/TransferOffer/1`,
`HyperNet/TransferAcceptance/1`, `HyperNet/TransferOperation/1`,
`HyperNet/TransferPermission/1`, `HyperNet/TransferPolicy/1` and
`HyperNet/TransferReceipt/1`; each ends with a NUL byte. Reusing a signature under
another domain is invalid.

## Authority commands

| Command | Fields | Result |
| --- | --- | --- |
| TransferHostRegister | consent | hostKey, generation, consentDigest |
| TransferHostWithdraw | hostKey, expectedGeneration | hostKey, active |
| TransferHosts | none | hosts: signed consent array |
| TransferOfferCreate | offer | transfer |
| TransferOfferGet | transferId | transfer |
| TransferOfferList | after: ID or null | transfers: up to 16 records, next: cursor or null |
| TransferOfferAccept | acceptance | transfer |
| TransferOfferCancel | transferId, offerDigest | transfer |
| TransferAuthorise | hostKey, operation | permission: signed object |
| TransferPolicySync | hostKey | policy: signed object |

Follow non-null next cursors to list the remaining participant records.

The host signs its consent. OfferCreate's request and nested offer must both
use the sender's admitted client key. Only the named recipient may accept; either
participant may cancel. TransferAuthorise and TransferPolicySync require the matching current
service identity and consented mTLS certificate. These two commands are read-only
linearizable quorum operations; their permissions are never mutation receipts.
Host withdrawal remains possible with the original identity after expiry.

The offer payload has `version:1`, `network`, `transferId`, `senderKey`,
`recipientKey`, `recipientEncryptionKey`, `payloadBytes`, `payloadDigest`,
`fileBytes`, `label` and `expires`. Encryption recipients are native age X25519
strings: lowercase canonical Bech32 with HRP `age`, a valid checksum and exactly
32 decoded key bytes. Bech32m and malformed encodings are rejected before an
offer is stored. A recipient must verify the encryption identity before acceptance.
Label and destination are 1-64 ASCII letters, digits, underscores or hyphens;
neither carries a path. Expiry is at most seven days after creation. The encrypted
payload is 1-8388608 bytes; fileBytes is smaller than payloadBytes.

Acceptance has `version:1`, `network`, `transferId`, `offerDigest`, `hostKey`,
`destination` and `expires`. It expires no later than its offer and selected host.
Acceptance cannot be changed or moved to another host; cancel and issue a new
offer for a different placement. A TransferRecord contains `offer` (signed),
`body` (decoded offer), `offerDigest`, `acceptance` (signed or null), `accepted`
(decoded or null) and `cancelled`. Exact repeated operations do not change
immutable content or revive cancellation. At most 32 unexpired offers belong to
one sender, with 256 globally. Cancelled records retain their slot until signed
offer expiry; expired records can be pruned. Signed expiry and monotonic authority
time reject delayed old offers after pruning.

## Direct store operations

Use the exact consented HTTPS address and certificate pin for `POST /V1/Transfer`.
Request content type is `application/json`; the body is `{operation,payload}`.
Operation is signed by the acting member. Payload is an unpadded base64url chunk
for Put, otherwise null. Ambient proxies, redirects and DNS fallback are excluded.

Operation fields are `version:1`, `network`, `operationId`, `issuedAt`, `hostKey`,
`transferId`, `offerDigest`, `action`, `offset`, `chunkBytes`, `chunkDigest`.
IssuedAt must be at most 30 seconds old and at most two seconds in the future.

| Action | Actor | Chunk fields |
| --- | --- | --- |
| Status | Sender or recipient | offset=0, chunkBytes=0, chunkDigest=null |
| Put | Sender | contiguous offset, 1-65536 bytes, exact SHA-256 |
| Commit | Sender | offset=0, chunkBytes=0, chunkDigest=null |
| Fetch | Recipient | offset, 1-65536 bytes, chunkDigest=null |
| Delete | Recipient | offset=0, chunkBytes=0, chunkDigest=null |

Every successful operation returns `receipt`. Fetch also returns `payload` and
`offset`. The signed receipt payload has `version:1`, `network`, `hostKey`,
`transferId`, `offerDigest`, `payloadDigest`, `payloadBytes`, `storedBytes`,
`status` and `recordedAt`. Status is Staging, Complete or Deleted. A fresh accepted
offer returns Staging with storedBytes=0. Put receipts confirm durable prefixes;
Commit confirms the full digest. In Deleted receipts, storedBytes records the
previous durable prefix, while retained payload bytes are zero. Delete is idempotent; subsequent uploads cannot
replace its tombstone. Receipt signatures alone are not permission to access data.

Authority permissions include `version:1`, `network`, `hostKey`, `hostGeneration`,
`authorityRevision`, `authorityEpoch`, `issuedAt`, `expires`, `operationDigest`
and the exact `transfer` record. Policy uses the same freshness/host fields and
`transfers` (currently authorised IDs), omitting operationDigest/transfer.
Stores verify the pinned authority signer, exact operation binding, expiry and
monotonic authority floors before accessing bytes. Failed quorum reads never
produce an empty authoritative inventory.

Replies use the ordinary `{ok,code,epoch,result}` envelope. Clients must inspect
ok and verify nested evidence before using result. Unknown failure detail is
reported as TransferUnavailable; authentication and quota errors never trigger
automatic placement fallback.
