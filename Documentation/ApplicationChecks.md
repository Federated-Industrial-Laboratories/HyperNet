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
operations. Each gate can renew once when its normal action headroom is due.
An exact established stream with an expired but still open cached gate can use
this same bounded readiness renewal. Forwarding remains paused until it succeeds;
the separate fresh action read is still required. Missing, replaced, closed,
unestablished or finished streams, and streams beyond their fixed forwarding
lifetime, cannot use this path. An expired caller or challenge window cannot be
restarted by renewal.
The caller deadline bounds waiting; it does not require a current gate to remain
valid for that entire wait. A current gate with sufficient action headroom needs
no preparation read. The separate fresh read and its receipt remain capped by
both gates, even when their expiry precedes the caller deadline. Preparation rechecks
the exact live session, cancellation, control identity and current clock. It uses
the original caller and route deadlines; a fresh certified expiry can still be
shorter and remains binding. There is no renewal loop or increase to the
four-check admission bound.
Readiness reads use the same challenge ceiling as the final check: the original
caller start plus five seconds. They do not restart that window when renewal
begins. A shorter caller wait still bounds transport, persistence and local use;
it does not shorten the signed challenge below the authority's existing
conservative uncertainty interval. Route, consent and fresh certified gate
expiries remain binding, and cancellation still prevents a completed check.

An unresolved ordinary request or fence remaining after readiness maintenance
makes the fresh read unavailable. The read never uses a readiness result as its
answer and never falls back to an ordinary authority mutation.
The endpoint admits at most four checks in total across its queue and in-flight
exchanges, including cancelled exchanges draining after a control reconnect.
The existing one-pending-check-per-stream rule remains. Fresh certification
exchanges can overlap on separate bounded workers; they receive only immutable
signed requests, history anchors, clock sources and captured absolute deadlines.
The endpoint actor alone issues and consumes challenges, owns requester state,
and publishes durable authority and domain state. Readiness preparation, endpoint
renewal, admission and cleanup keep their synchronous composition. Background
stream-permission renewal uses the same bounded immutable exchange workers as
action checks, with verification and publication still on the actor.

Fresh and ordered domain-result validation share the same governance replacement
step. It indexes the exact returned record identities and parses each retained
record once while selecting replacements. Unrelated retained records remain
unchanged. Current policy evaluation, retained-generation checks and durable
publication still run for each result; parsed permission decisions are not cached.

Checks run in finite rounds. The actor captures at most four checks already
available, performs every captured check's necessary gate preparation, then
revalidates and issues their fresh challenges. Before the first completion,
unused slots may accept later checks whose exact stream and endpoint gates are
already current. There are at most four total admissions per round, including
failed or deferred attempts; completing a check never opens another slot.
Later reads are clipped to the latest original deadline of the initial issued
batch, as well as their own caller, clock and gate bounds. They cannot extend
the round. A later check defers when an open gate is expired or reaches the same
readiness threshold used during preparation: twice its observed renewal cost
plus the existing dispatch allowance, retaining the accepted-proof fallback.
It also defers when the fixed round reaches that stream-read headroom threshold.
These checks precede challenge creation and never renew a gate in an active round.
Deferral holds at most one queue-head check, retaining
its original permit and request until the next ordinary round. No later check
bypasses that held head. Cancellation, changed identity, closed streams and
expired caller deadlines retain their existing refusal paths.
Before starting another round, a check may also wait behind the actor's retained
stream close. This applies only when the exact stored ordinary request is a close
of that cleanup's current session and proof, with no pending fence. The held FIFO
head retains its original request, permit and signed-close digest. Later checks
cannot bypass it. Existing lifecycle recovery and backoff resolve that same
ordinary operation; waiting neither recovers it nor issues a read challenge.
Cancellation or control loss releases the head to its normal checks. Waiting ends
at the original caller or cleanup deadline, whichever comes first, without a new
window. A different ordinary request, fence, unreadable state or absent cleanup
does not qualify for deferral. Once recovery clears the original ordinary slot,
the request still requires current readiness and a fresh action-bound read.
Both issue and completion retain their ordinary/fence exclusion guards.
While its workers remain, completion has a separate dispatch class; unrelated
synchronous admission, renewal and cleanup do not advance the actor's floor or
consume its permission tail before completion. Clock/currentness checks,
cancellation, control loss, original deadlines and termination remain active.
A round does not extend any caller, challenge or forwarding deadline. After it drains, lifecycle work
retains its fair turn before another round; sustained arrivals cannot refill a
round indefinitely. Independent authority progress can still overtake a read,
and an expired gate still refuses it.

A selected background `Stream::Permit` renewal for an established stream can
start a finite read round. Unestablished streams retain synchronous renewal so
their guarded handshake can finish even when an open gate needs renewal.
Existing exact-operation recovery finishes on the actor before its challenge is
issued. The renewal occupies one of at most four total exchanges; up to three
action checks can join through the same issue-only admission rules before the
first completion. Their original caller and current-gate bounds remain binding,
and they cannot extend the renewal round. A completed action check need not wait
for the renewal exchange to finish. Ordinary effects, endpoint renewal and
cleanup cannot run until all workers in that round drain.

Maintenance retains its exact session, forwarding instance, cancellation flag
and original selected end, further clipped by the fresh read and fixed forwarding
ends. The actor verifies the fresh result against current authority state and the
exact configured endpoint profile, then uses only its certified stream-renewal
token. An expired but open stream gate can renew; a closed, replaced, unestablished
or finished stream cannot. The separately owned endpoint gate is checked for
closure and is not renewed by this maintenance path. Forwarding continues to obey
both gates. Cancellation or shutdown drains the worker and discards its unconsumed
challenge. No application receipt is produced, and every later action still
requires its own fresh check. The existing transient retry and terminal-close
rules remain; a stale renewal cannot close a replacement stream.

Stream-renewal scheduling uses the observed cost of successful stream-permission
checks. Before the first such observation it retains the ordinary action-cost
fallback. Admission, cleanup and endpoint lookups do not replace an established
stream-renewal estimate. Cleanup keeps its separate action reservation, and
certified expiry remains the enforced limit regardless of scheduling estimates.

On completion the actor rechecks the current control generation, exact session,
forwarding state, gates, consent and clock before accepting evidence. Verification
uses the current domain records, generations, causal floor and retained history;
an unresolved ordinary request or fence still prevents acceptance. A response
that has been overtaken by the current floor is refused, without rolling the floor
back or retrying under a new deadline. Each challenge can be consumed once.
The request's signed minimum is the floor known when it was issued. Concurrent
requests with that same lower bound may each certify the same newer prefix;
publishing one does not invalidate another result that still satisfies the current
certified prefix, history and generation checks. Old or conflicting results and
history proofs bound to an earlier retained prefix remain refused.

A successfully verified and published `Stream::Permit` result also supplies
in-memory certified renewals bound to the exact session and receiving endpoint.
The stream decision includes the endpoint's route lookup and its expiry bound.
Endpoint renewal additionally requires the freshly verified registered profile
to match the local profile envelope exactly. It cannot use an unrelated result
or the last expiry observed by the client.

After all completion checks, the actor can renew those still-current gates; the
stream gate remains clipped to its fixed forwarding lifetime. The receipt is
first clipped against both old gates and the original read deadline; renewal
cannot extend that action's receipt. Denied, stale, cancelled or failed checks
supply no renewal, and completion never revives an expired or closed gate.
Gate-renewal timing updates only after a successful renewal. Existing bounded
check diagnostics distinguish missing, changed,
unestablished, finished, forwarding-expired, closed and gate-expired streams
without logging session identifiers or application payloads.

Check timing admits at most one sampled attempt per 1,000 ms, with a process
ceiling of 256 samples. Selection at admission preserves the same sample through
queue, preparation, worker exchange, actor finalization and durable acceptance;
it does not require the selected attempt to succeed. This spreads successful
samples across sustained work instead of exhausting the budget during startup.
Worker timestamps are captured
in the worker and reported after it rejoins the actor; output order is not event
order. The durable-acceptance span includes floor and domain-state publication
and their required checks, rather than only filesystem synchronization. Nested
domain-validation boundaries distinguish current-policy evaluation from response
authentication. Signature counters cover fresh-read validation, durable acceptance
and acknowledgement on the finalizing thread without resetting its counters.
They report actual strict verification time and cache activity, excluding worker,
replica and subsequent endpoint-proof extraction work. Errors
can leave later stages absent. Missing diagnostic timestamps do not alter an
operation's result, permission or deadline.
Background `StreamPermit` start/completion records now include its worker exchange
and any finalization wait. Their elapsed duration is not exclusive actor occupancy:
action checks can proceed in the same finite round.

A separate shared ceiling of 64 failure records covers unsuccessful check
outcomes and stream cleanup, including after timing samples stop. Check records
use fixed failure categories; pending ordinary and fence guards distinguish
issue from finalization without exposing retained requests. Cleanup records name
the failing recovery, retirement-context, target-parse or ordinary-close stage,
and whether the requester retains an ordinary request, a fence, both or neither.
An unsuccessful local state inspection reports `Unavailable`, never an empty
requester. This inspection runs only for a selected cleanup failure, does not
recover or change state, and cannot replace the original error. A cleanup stage
alone does not prove that an ordinary effect was submitted or committed.
No error prose, session identities or payloads enter these records. All records
use the existing bounded, nonblocking diagnostic writer; dropped records do not
establish success. Sampling, inspection and output do not change permission,
deadlines, pending-request exclusion or recovery behavior.

Cancellation and shutdown suppress receipts. Shutdown cancels and joins the
remaining exchanges under their original absolute ends, then discards the
actor-owned challenges; it does not detach authority work.

Verified refusals retain their structured disposition, refusal code, scope,
epoch, height, state digest, statement digest, evaluation time and original
statement expiry. Error strings are not authority evidence.

After consuming a verified read, Core sends a signed local cleanup acknowledgement
for that exact completed collection. Cleanup cannot authorize or repeat a check.
It does not wait for a reply; a lost or unsupported acknowledgement leaves the
original finite retention in place. See the [wire contract](WireContract.md)
for the bounded local acknowledgement and compatibility rules.

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
while the authority actor is processing maintenance or a completion. A completed or expired stream
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
connection or session. One admission permit follows each check through the
endpoint queue, its worker and finalization, so queued and in-flight work together
never exceed four, including across reconnects. The framed-reader queue also
holds at most four bounded frames. Overflow receives a bounded unavailable
response; it cannot create an unbounded task or authority queue. Finite
read rounds alternate with the existing bounded lifecycle rotation; completions
are drained before the next lifecycle turn. Termination closes gates and cancels
pending checks before joining workers.

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
