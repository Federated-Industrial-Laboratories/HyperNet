# SSH service protocol

This profile uses the signed `POST /V1/Command` envelope from
[Protocol](Protocol.md). Network and signing keys are 32-byte lowercase hex;
grant IDs are 16-byte lowercase hex. Unknown object fields are refused. There is
no cross-network permission inheritance. Native OpenSSH transports application
I/O directly; the authority never proxies SSH sessions or receives private keys.

## Signed objects

Object signatures cover the ASCII domain (including its final NUL byte), network
bytes, public key bytes and exact decoded JSON payload bytes, in that order.
Payload encoding is unpadded base64url. Signatures use Ed25519. The outer envelope
contains `network`, `publicKey`, `payload` and `signature`.

`HyperNet/SshConsent/1\0` signs the complete operator specification described in
[SshServices](SshServices.md). Native host keys are canonical `ssh-ed25519 BASE64`
strings with no options or comment. Command and image digests are bare SHA256 hex;
`imageDigest` excludes the OCI `sha256:` prefix. `certificateDigest` hashes the
operator mutual TLS leaf certificate in DER form. A changed specification requires
a strictly newer generation. Authority and operator signers are distinct.

A grant is an object with `grantId`, `serviceKey`, `serviceGeneration`, `memberKey`,
`sshPublicKey`, `account`, `purpose`, `expires`, `accepted` and `revoked`.
`sshPublicKey` is canonical, and `account` is `HyperNetService`. Expiry is an
absolute Unix second. A grant request lasts at most the signed
`maximumSessionSeconds`, which cannot exceed 300 seconds. Accepted and revoked
are authority-managed fields. Creation verifies native key possession but does
not reserve permanent key ownership. Only explicit operator acceptance reserves
the key, after rechecking ownership conflicts. A revoked ID cannot be reused.

`HyperNet/SshLease/1\0` is signed by the distinct service authority key. Its fields
are `version` (1), `network`, `authorityEpoch`, `authorityRevision`, `serviceKey`,
`serviceGeneration`, `consentDigest`, `issuedAt`, `expires` and `grant` (the complete
accepted grant). `consentDigest` is SHA256 of the consent signing bytes; the
signature itself is not included. A lease expires within five seconds and never
later than its grant. The supervisor verifies all fields against its local grant
and consent before starting or continuing a session.

## Native key possession

`SshGrantCreate.sshKeyProof` is unpadded base64url encoding of a detached OpenSSH
SSHSIG binary object, without its textual armor. This profile requires version 1,
namespace `HyperNetSshKey1`, an empty reserved field, hash algorithm `sha512`, and
an `ssh-ed25519` signature. The SSHSIG public key must exactly match the request's
canonical native key. All fields are length-bounded and trailing bytes are refused.

The message supplied to OpenSSH signing is the exact concatenation of ASCII
`HyperNet/SshKeyProof/1` followed by a NUL byte, decoded 32-byte network ID,
decoded 32-byte requesting member key and decoded 32-byte native public key.
The standard SSHSIG signing structure hashes this message with SHA512 and binds
its namespace. The member's outer request signature separately covers the entire
grant specification, including the proof. A proof for another member or network
cannot be reused. The proof demonstrates private-key possession, not a grant or
operator approval. It can be reused by the same member for the same native key.

## Authority commands

All commands require a current signed request. Members can discover active
services; only the grant's member or operator can inspect its grant. A dedicated
operator has hosting rights and permanent role separation from other credentials.
Operator registration and acceptance require its exact mutual TLS certificate.

| Type | Additional fields | Result |
| --- | --- | --- |
| `SshServiceRegister` | `consent` signed object | service record |
| `SshServiceWithdraw` | `serviceKey`, `expectedGeneration` | withdrawal result |
| `SshServiceGet` | `serviceKey` | `service` record |
| `SshServices` | none | `services` records |
| `SshGrantCreate` | `grantId`, `serviceKey`, `serviceGeneration`, `sshPublicKey`, `account`, `purpose`, `expires`, `sshKeyProof` | `grant` |
| `SshGrantAccept` | `grantId` | accepted `grant` |
| `SshGrantRevoke` | `grantId` | revoked `grant` |
| `SshGrantGet` | `grantId` | `grant` |
| `SshAuthorise` | `serviceKey`, `grantId` | signed `lease` |

The service record contains signed `consent`, `consentDigest`, decoded `body` and
current `active` status. Clients must verify the signed object and equality with
the decoded body. Directory discovery does not grant access.

`SshAuthorise` is a read-only, linearizable authority operation. It requires the
service's current hosting identity and matching mutual TLS certificate. It checks
service consent, grant acceptance, member state, purpose, generation and expiry
on each request. Lost quorum cannot issue fresh permission. Supervisors retain
durable epoch/revision floors and use a monotonic deadline derived from each
lease's absolute expiry. A general authenticated member cannot call this endpoint
as an operator or create a server lease.

Errors use the common `ok`, `epoch`, `result` and `code` reply envelope. Refused
commands do not imply that a retry is safe with changed content. Keep the same
immutable grant request when reconciling a lost creation response. After expiry,
revocation or generation change, request and explicitly accept a new grant.

## Native transport boundary

The operator image fixes the account, executable, SSH host key and resource
bounds. The runtime checks the command hash and restrictions before listening.
OpenSSH authenticates only the exact native client key in the accepted grant.
There is no password, agent, remote command, forwarding, shell or PTY entitlement.
Independent clients must verify the current grant and consent, pin the native
host key, disable ambient SSH configuration and enforce absolute expiry.
Operators must retain the separate server supervision even when clients enforce
these restrictions. Client-side checks cannot constrain a malicious client.

Authority retains at most 32 unexpired grants per member and 256 globally.
Revoked grants remain until their original absolute expiry. Afterwards their
metadata can be pruned without reviving their signed expiry or old acceptance.
Native key ownership and role history are permanent, with at most 4096 distinct
native keys per network. The same admitted member can reuse its dedicated SSH
client key for fresh, separately accepted grants after old grants expire. Another
member cannot adopt that key. General membership, mail and authority identities
cannot use a reserved native SSH key.
