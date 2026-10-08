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
envelope when retrying a request. The maximum envelope is 24 KiB and the maximum
decoded payload is 16 KiB. Integer values are unsigned 64-bit values.

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
| `Consent` | `profile`, `grants`, `expires`, `certificate` | Hosting member, own device |
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

The grant mask uses bit 0 for membership, bit 1 for hosting and bit 2 for
administration. Membership is required for every other grant. Unknown bits are
rejected. An administrator cannot remove the final active administrator.
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

Replies are JSON objects with `ok`, `code`, `epoch` and `result`. Successful
commands use code `Ok`. Errors contain static codes, without submitted values
or credential details. A status result contains `deviceKey`, `member`,
`consent`, and `authorityRevision`. Administrators also receive counts of
members and invitations. A heartbeat result contains `effectiveGrants`,
`leaseExpires`, `profile`, and `authorityRevision`. Mutation results identify
the affected device or invitation verifier, never an invitation secret.

The permission epoch advances with membership, invitation and consent changes.
The authority revision orders every successful request, including freshness
checks. An unavailable quorum yields `AuthorityUnavailable`; it never permits
local fallback. A client must treat network failures, malformed replies and
unknown error codes as denial. TLS and signatures provide authentication, not
protection against an authorised administrator or a compromised endpoint.
