# Transfer protocol

Transfer metadata and permissions use the canonical authority protocol. A
participant signs one ordinary `AuthorityDomain` intent (kind 20). Its selected
store contributes a fresh recipient challenge (kind 21), submits the ordered
request (kind 22), and independently verifies the quorum result before touching
ciphertext. The store never borrows the participant's signing key or stream.

The domain state contains two finite record kinds:

| Kind | Record | Lifecycle |
| --- | --- | --- |
| 134 | TransferService | Operator-signed profile registered by an admitted manager with capability 26; restrictive withdrawal increments its generation |
| 135 | TransferAgreement | Sender-signed immutable offer, one recipient acceptance, optional terminal cancellation |

Records bind network, incarnation, generation and predecessor. Result evidence
contains the exact applicable governance, deployment, service and agreement
records. Clients independently evaluate their contents and retain their version
floors. A quorum signature does not replace this validation.

`TransferContext`, `TransferRegister`, `TransferWithdraw`, `TransferService`,
`TransferServices`, `TransferOffer`, `TransferGet`, `TransferList`,
`TransferAccept` and `TransferCancel` are requester-side metadata operations.
The domain command codecs define their canonical arrays. Sender capability 18
and recipient capability 19 have explicit scopes; membership alone grants neither.
List results include a continuation cursor and enough exact context to validate
the returned records. Follow every non-null cursor for a complete inventory.

A signed `AuthorityTransferOffer` includes network, incarnation, a random 32-byte
identifier, sender, recipient, canonical native age X25519 public key, ciphertext
size and SHA256, plaintext size, non-sensitive label and absolute expiry in
milliseconds. The ciphertext is at most 8 MiB, including the encrypted file header.
The filename and plaintext digest occur only in that encrypted header.

Acceptance binds the exact offer and sender capability to one live role 4 service,
the recipient's current capability, a destination label and a bounded expiry.
The recipient verifies its retained age key before accepting. The host operator
separately consents to opaque storage. Acceptance reserves the whole encoded
storage entry, including chunk digests and tombstone overhead, against one usable
bank. Capacity is derived from the signed state admission and actual canonical
encoding. No fixed per-sender offer count or fractional storage quota is added.
Acceptance cannot select another store later; cancel and issue a new offer.

## Serving exchange

The private local exchange is a framed canonical array:

```text
[200, 1, "TransferExchange", signedIntent, payloadBytes, reconcile]
```

It is bounded by the authority wire limit (262144 bytes). The signed intent
contains `TransferExecute`, the agreement identifier, finite effect, offset,
byte count and an optional chunk digest. The serving identity is derived from
the committed accepted agreement and registered role 4 profile. It is never a
caller-selected destination or a generic authority capability.

| Effect | Participant | Extent |
| --- | --- | --- |
| Put | Sender | Next aligned 64 KiB chunk, or the exact final shorter chunk; signed SHA256 |
| Commit | Sender | No payload; complete ciphertext size and SHA256 must match |
| Fetch | Recipient | Bounded offset and 1-65536 bytes from committed ciphertext |
| Status | Either | No payload |
| Delete | Recipient | No payload; retains a terminal tombstone |

Each effect checks both participants' current authority, agreement expiry and
cancellation, current manager/registrar authority, exact deployment consent and
service withdrawal. An unavailable quorum cannot authorize an operation.

The store durably claims the exact immutable intent before its effect. A lost
response can be reconciled only against that same retained claim, using the
handler's idempotent operation. A new operation requires a new intent. Chunk
retries must reproduce the exact offset, extent and digest. Deletion cannot be
reversed by retrying an old upload. Conflicting or uncertain state fails closed.

A `TransferEffectReceipt` contains the original intent, recipient challenge,
ordered request, certified result and ancestry, optional history repair, signed
service completion and response. Its bound is 1048576 bytes. The completion binds
the exact result and response digest and a time within the verified permission.
A refusal has neither a completion signature nor an effect response.

The participant verifies the proof and service signature, learns its own current
stream status, retains received ciphertext, then durably records the reported
completion. An old receipt proves only the named completed operation. It never
becomes permission for a new effect, and it cannot roll back the client's epoch
or generation floors.

The installed local exchange uses an owned rootless container and its private
Unix socket. Remote reader transport requires the approved privacy relay route;
this protocol does not introduce a temporary direct reader network endpoint.
