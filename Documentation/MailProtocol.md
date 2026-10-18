# Mail protocol

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Mail is a finite `AuthorityDomain` application over the canonical authority wire
format. It uses ordinary requester streams, exact committed snapshots and
independently verified quorum results. It has no separate online authority
signer. Canonical definitions are in `AuthorityMailCommands.rs`,
`AuthorityDomainMail.rs`, `AuthorityMailObjects.rs` and `AuthorityMailRequest.rs`.

## Owner-signed objects

The mailbox envelope contains `network`, `publicKey`, `payload` and `signature`.
The payload is canonical JSON encoded as unpadded URL-safe Base64; the signature
is canonical lowercase hexadecimal Ed25519. Its input is
`HyperNet/MailManifest/1\0 || network[32] || publicKey[32] || exactPayload`.
The manifest digest hashes that same input. Address and device identifiers hash
`HyperNet/MailAddress/1\0 || network || owner` and
`HyperNet/MailDevice/1\0 || address || requestKey`, respectively.

Manifest fields are `version`, `network`, `addressId`, `ownerKey`, `generation`,
`previousDigest`, `expires`, `devices`, `storageHosts`, `requiredCopies`,
`retentionSeconds`, `deleted`. Each device names its derived `deviceId`, separate
`requestKey` and `mlsSignatureKey`, explicit `permissions` and `expires`.
Unknown fields, invalid identities, repeated keys and noncanonical encodings are
refused. Deleted manifests contain no devices or stores and require zero copies.

The MLS ciphertext profile remains `HyperNetMailMls1`. A letter contains a route,
its original signed sender and recipient manifests, an MLS Welcome and encrypted
MLS application message. Message and claim identifiers are32-byte digests.
Every message is bound to exactly one certified claim and one ciphertext digest.
Clients verify native package signatures, canonical references, credentials,
lifetimes and the complete owner-signed receiving set before encryption.

## Certified records

| Kind | Meaning |
| --- | --- |
|136 | Operator-signed Mail service profile, admitted manager and grant, withdrawal |
|137 | Exact owner-signed mailbox revision, admitted manager/grant and private policy |
|138 | Immutable native package for an exact mailbox revision |
|139 | One-use package claim, original evaluation time and immutable placement; optional single ciphertext binding |

Mailbox revisions advance consecutively. A claim begins at generation1 and its
single ciphertext binding produces generation2. Packages remain reserved after
claim expiry or abandonment. Reservations never silently evict identity or
one-use history. Overall authority state and record admission limits apply.

Commands cover MailContext, MailRegister, MailWithdraw, MailService, MailServices,
MailPublish, MailGet, MailPackage, MailInventory, MailClaim, MailClaimGet,
MailBind and MailExecute. Each command's canonical array and exact optional
fields are defined by `Command::value` and `Command::parse`; unknown commands or
fields are refused. Mutation responses are independently re-evaluated against
current certified domain and governance records by the requesting client.

`MailExecute` is
`[name,address,service,effect,message|null,claim|null,bytes,digest|null,after|null]`.
Put names both message and claim with the same identity and includes exact
ciphertext size/digest. Fetch and Delete name a message. List accepts an optional
exclusive message cursor. Nonapplicable fields must be null or zero as specified
by the finite parser. The challenge recipient is the exact current selected
role 3 service, while the signed requester is the authorized device.

## Local exchange and receipts

A packet is canonical CBOR
`[200,1,"MailExchange",signedOrdinaryIntent,ciphertextBytes,reconcile]`.
Only Put carries ciphertext. Reconciliation requires the recipient journal's
exact retained uncertain effect; it is not a new permission. The service obtains
its own fresh challenge and committed history through the private authority
control socket, retains the effect claim, then accesses its confined store.

The result is
`[201,1,"MailEffect",address,service,effect,message|null,status,body]`.
Stored and Deleted have empty bodies. Fetched contains the exact certified
ciphertext. Listed contains up to16 sorted entries
`[message,ciphertextDigest,bytes,expiresMs]`; the last ID is the next exclusive
cursor when the page is full. A full page may be followed by an empty page.

The typed Mail receipt includes the signed request, challenge, quorum result,
committed history and the service's purpose-bound signed completion. The client
validates all of these against its independent bootstrap and authenticated epoch
archive, refreshes its own stream status, and retains the local result before
acknowledging the remote completion. Historical receipts cannot authorize a new
effect or lower a retained prefix.

## Bounds and changes

A mailbox has at most eight devices and four explicitly selected stores.
Inventory discovery pages contain at most eight available packages. Each native
package is at most 4096 bytes; ciphertext is at most 128 KiB. A metadata response has
at most 23 domain records: two mailboxes, eight packages, twelve current or
historical placement stores and one claim. Governance dependencies and complete
encoded response bounds still apply; an excessive result is refused atomically.

Changing a mailbox invalidates its unconsumed public inventory for new claims.
New publications racing with claims or binds are resolved by committed order.
A bound claim cannot be delivered after either exact mailbox revision changes.
Existing ciphertext may be fetched only through a currently selected, consented
store and a current Read device. Its original recipient keys and signed manifests
remain the cryptographic authority for decrypting the old letter.
