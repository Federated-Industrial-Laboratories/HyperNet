# Local application authority checks

[Application streams](ApplicationStreams.md) | [Application access](Applications.md)

Version 0.10.0 adds `checkAuthority-v2`, which lets a receiving application request
a fresh authority observation for one exact, active incoming application stream.
It requires matching Core and Suite builds that advertise this capability.
Version 0.9.1 payload-only companions remain compatible; a missing check socket
means the capability is unavailable. It does not stop their existing payload
workflows or permit a direct transport fallback.

An observation is an endpoint-signed local assertion after Core verifies a fresh
authority read and publishes its retained floor. It is not a portable quorum
certificate and does not authorise application membership, delegation or payload
operations. The receiving application still applies its own current policy. An
action digest correlates the result with immutable application content; Core does
not interpret that content or approve its semantics.

## Separate local channel

The companion exposes `Ingress/Checks.sock` beside `Ingress/Control.sock`.
The existing `/Application` mount exposes those ingress sockets only. SDK command
sockets, requester profiles, private keys and target maps remain outside the
endpoint. The endpoint initiates one persistent connection per binding to
`/Application/Checks.sock`. The connection does not consume an application slot.
The original `Control.sock` handshake and opaque duplex payload bytes do not
change. Socket ownership, private permissions and replacement checks apply to
both socket names.

The companion sends a challenge containing its fresh random instance identifier,
nonce, monotonically increasing control generation, binding digest and verified
host kernel boot identifier. Core verifies the binding and host boot, then signs
the complete challenge with its endpoint key. The signed ready record adds a
random endpoint runtime instance, the exact capability, transport facts and zero
monotonic/boottime namespace offsets. Both endpoints require the real clock source
to establish the host boot; a container-visible boot identifier alone is not
evidence. Core checks zero time-namespace offsets for private and signed clock
sources on this new path. Old payload workflows acquire no additional clock
requirement.

Disconnect invalidates queued and executing checks for that control connection.
A reconnect requires a fresh challenge and generation; no result is transferred
to the new channel. Only the existing endpoint key pinned in the accepted binding
can sign ready records and receipts.

## Canonical records

`Source/Authority/Domains/ApplicationStreamControl.rs` defines the canonical
contract mirrored by Suite. Frames use the existing four-byte, big-endian length
prefix and a maximum of 16 KiB. The payload is the canonical TrustWire array
`[200, 1, label, bytes(canonical JSON record)]`. JSON uses the field order emitted
by the canonical Rust schema, camelCase field names, exact integer and fixed
32-byte-array types, and no unknown fields. Decoding must reproduce the original
canonical bytes. Ready and receipt records use the existing TrustWire Ed25519
signed envelope around this payload. Other records travel only on the validated
local channel.

| Label | Contents |
| - | - |
| `ApplicationChecksChallenge` | Binding digest, companion instance, nonce, host boot, control generation. |
| `ApplicationChecksReady` | Exact challenge, endpoint instance, zero offsets, capability list and transport/privacy facts. |
| `ApplicationAuthorityCheck` | Binding, both instances, control generation, local connection ID, exact kind-173 session reference including generation and digest, nonce, action digest, companion-derived start and absolute deadline. |
| `ApplicationAuthorityCancel` | The entire exact check request; a nonce alone is insufficient. |
| `ApplicationAuthorityReceipt` | The entire request, typed disposition, optional certified observation, conservative absolute `notAfterBootMs`, and transport/privacy facts. |

The companion resolves the full session reference from the verified incoming
context. Native callers cannot supply another session reference. Every receipt
must match every request correlation field and the pinned binding. Any certified
observation must name the binding's network and incarnation. No numeric policy
action is introduced by this protocol.

## Fresh evaluation and lifetime

Core invokes the existing read-only `Stream::Permit` evaluator for that exact
live session. Before that separate fresh read, the endpoint prepares its own
deployment gate and the selected stream gate through their existing renewal
operations. Each gate can renew once when its old expiry would clip the original
caller deadline or its normal action headroom is due. This also applies when a
check arrived before the periodic renewal timer became due. Preparation rechecks
the exact live session, cancellation, control identity and current clock. It uses
the original caller and route deadlines; a fresh certified expiry can still be
shorter and remains binding. There is no renewal loop or added read capacity.

An unresolved ordinary request or fence remaining after readiness maintenance
makes the fresh read unavailable. The read never uses a readiness result as its
answer and never falls back to an ordinary authority mutation.
Verified refusals retain their structured disposition, refusal code, scope,
epoch, height, state digest, statement digest, evaluation time and original
statement expiry. Error strings are not authority evidence.

The native companion supplies a start time and absolute `CLOCK_BOOTTIME` deadline.
The latter may be no more than 5,000 ms after the former, and the start cannot be
in Core's future. The SDK separately enforces its original local call deadline.
Queueing, retries and reconnect never reset the inherited deadline. Core further
bounds transport waiting and local effects by the session's original lifetime,
application and endpoint gates, and local consent.

The authority challenge has a separate ceiling at the original companion start
plus 5,000 ms, even when the caller selects a 100 ms or one-second wait. Its duration
decreases by time already spent queued; it never starts a new five-second window.
The existing authority evaluation requires a window wider than its conservative
time uncertainty, while a result can still arrive within a shorter caller wait.
The longer challenge does not extend transport waiting, authorise a late effect or
permit delivery after the caller deadline.

Core verifies clock health before the read, while polling and at completion.
A renewable clock observation's short lifetime does not shorten the authority
challenge or the fixed caller wait. A fresh observation may replace it during the
read. The delivered receipt is capped by the observation verified at completion,
the original caller and stream bounds, current gates and local consent, the fresh
statement's original expiry with the existing allowance, and certified effect
bound. An expired or unavailable clock observation still refuses the check.

The live session must already have completed its payload handoff. After the fresh
read, Core rechecks current gates, clock evidence, connection/cancellation state
and forwarding state. The forwarding task independently marks completion even
while the serial authority requester is blocked. A completed or expired stream
cannot receive a permitted receipt merely because its JoinSet completion is still
queued.

| Disposition | Meaning |
| - | - |
| `permitted` | Fresh certified permit and all local checks succeeded; usable only before the conservative receipt deadline. |
| `denied` | Fresh certified refusal, with its refusal code and original signed-statement metadata retained. |
| `unavailable` | No usable fresh result, including requester contention, unavailable authority, invalid clock context or lost control state. |
| `expired` | The inherited caller deadline or conservative validity ended. |
| `notActive` | The exact stream is absent, not fully handed off, finished or no longer live. |

Only permitted and denied receipts carry certified observation metadata. Other
receipts retain the caller deadline for correlation; it does not confer authority.
If the caller deadline has elapsed before a result can be sent, no late success is
sent. A certified pending result is unavailable, not a refusal or permit.

## Bounds and cancellation

The channel admits at most four pending checks, with at most one per local
connection or session. The endpoint queue holds at most four items and executes
one authority read at a time. Its framed-reader queue also holds at most four
bounded frames. Overflow receives a bounded unavailable response; it cannot create
an unbounded task or authority queue. Termination, stream closure and permission
renewals precede check work in endpoint dispatch.

Cancellation binds the complete request and suppresses its result. Disconnect
invalidates all checks on that channel. A read already executing may finish its
bounded verification and floor publication; its cancelled result is discarded.
This preserves authority state without inventing an application effect or
reviving a cancelled operation.

## Directional transport and privacy facts

`transportProtection` is `tls13FinalService`: application admission binds the
final-service TLS 1.3 exporter. This says nothing about message-level end-to-end
encryption, plaintext retention or a remote model's access to content.

For a public mode-2 endpoint, `incomingPath` is `publicListener` and attachment
evidence is absent. This does not assert relay transit; the upstream route remains
unknown. For a mode-3 endpoint, `approvedAttachment` records the actual configured
and authenticated relay attachment, its relay service ID and the approved profile
digest. Such endpoints do not accept a public incoming application listener.

`physicalIndependenceVerified` and `profileCurrentnessAsserted` are false. An
attachment is not evidence of physical operator independence, and the original
attachment profile is not presented as a new current assurance claim. Outgoing
client routes and incoming endpoint paths must not be conflated. The application
must expose these limits separately from its selected privacy policy.
