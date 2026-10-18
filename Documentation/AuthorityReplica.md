# Authority replica operator entrypoint

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

`HyperNet authority-replica` runs one fixed-committee Basic HotStuff signer as a
foreground Linux process inside mandatory OCI and Landlock confinement. Four
independently configured replicas exchange
mutually authenticated TLS messages; three matching executed-result signatures
are required by the separate Suite client. The application orders governance,
membership, deployment and service policy operations against committed state.
Certified checkpoints support bounded history compaction and catch-up by an
existing signer. The [installed runtime](Runtime.md) provides the consented
container lifecycle. [Committee replacement](AuthorityEpochs.md) preserves the
network's authority state through an explicit terminal transition and successor
activation.

Read-only policy discovery, Page views and route revalidation use three matching
fresh read signatures over the same current applied state. These reads do not
advance the ordered log or consume requester sequences. A replica with unapplied
commitment, a lock ahead of applied state or unavailable voting authority refuses
to sign. Read results retain the same finite clock and consumer history checks;
connection admission and host content effects remain ordered. See the
[wire contract](WireContract.md#fresh-quorum-reads) for the exact query whitelist,
proof and failure behavior.

## Inputs and independent trust

Prepare a complete accepted bootstrap with `HyperNetSuite network` and verify the
SHA256 of its exact bytes through an independently authenticated channel. Each
replica must use its assigned voter identity from that bootstrap. The private
identity JSON has `secretKey` and `publicKey` fields containing 32-byte lowercase
hexadecimal values. Never copy one voter signing key into another live signer;
the exclusive journal lock prevents concurrent access to one local journal, not
copies of the same key on other hosts.

A private runtime JSON contains these fields:

| Field | Required value |
| --- | --- |
| `listen` | Explicit local IP address and fixed TCP port |
| `peers` | Exactly four endpoint objects, one for each configured voter |
| `peers[].key` | The voter's 32-byte public key as a JSON integer array |
| `peers[].origin` | Its fixed HTTPS origin with a literal public or private IPv4/IPv6 address and port |
| `peers[].certificateSha256` | SHA256 of the exact DER TLS leaf certificate, as a 32-byte JSON integer array |
| `tls.certificate` | Absolute path to this replica's PEM certificate |
| `tls.privateKey` | Absolute path to its private PEM TLS key |
| `tls.certificateAuthority` | Absolute path to the approved PEM peer CA |
| `controlSocket` | Exactly `<deployment directory>/Control.sock` |
| `clock` | One explicit clock source, described below |

The current confined profile requires literal IP destinations, including public
IPv4 and IPv6. DNS lookup is unavailable within this profile.

TLS 1.3, mutual certificate verification and each exact leaf pin are required.
The peer endpoints must cover the bootstrap voter keys exactly. Runtime messages
cannot supply replacement destinations. The control socket is private to the
same Unix user; it is an administrative/service interface, not a reader route.

The ordinary host clock source is:

```json
{"kind":"Private","path":"/absolute/private/ClockHealth.json"}
```

It reads an owner-only observation written by `HyperNet authority-clock monitor`.
For a read-only container mount, use the monitor's signed export instead:

```json
{"kind":"Signed","path":"/absolute/export/ClockHealth.cbor","publicKey":"<independently pinned monitor public key>","kernelBoot":"<current host kernel boot identifier>"}
```

The monitor key must differ from every voter key. The signed export authenticates
its source, boot binding and short observation lifetime; the runtime also rejects
shifted time namespaces. Obtain the monitor key and host boot binding outside the
container. There is no fallback between sources or to an unverified local clock.
An unavailable, stale or insufficiently bounded observation prevents voting and
permission acceptance. See the `authority-clock --help` commands for observation
and export setup. Initialisation parses credentials but does not require a live
clock or contact a peer.

## Initialise, run and retain restart floors

Prepare the approved rootless OCI profile with a read-only root, subordinate-only
user namespace, no capabilities, no-new-privileges, the required syscall filter
and finite resource limits. Use a canonical deployment path beneath `/State` in
that environment, with a private parent directory of mode `0700`. Supply TLS
credentials under `/Config` and mount the dedicated clock export directory there
read-only. The runtime grants only the explicit TLS inputs, clock directory,
state and configured TCP ports, and verifies its confinement canaries before
creating threads or opening its signer journal. Host daemon execution refuses.

Run initialisation as a short-lived command in that same final path layout.
Runtime paths are immutable; moving a host `/tmp` deployment to `/State` does not
rewrite its control socket or credentials. Offline status and boot refresh can
use the same short-lived container layout. Bootstrap, identity and runtime inputs
must be private owned regular files. Paths must not permit ancestor replacement. Keep the TLS
private key and journal private. Initialisation creates the deployment directory.
An exact retry of a completed initialization returns the retained state without
recreating it. A changed input or interrupted incomplete directory refuses.

Both initialization and startup require `--authorization`, naming the exact
operator-approved `Manifest.cbor`, DesiredProfile, signed HostConsent and withdrawal
file produced by the installed runtime. Mount this directory read-only as a
directory so atomic withdrawal replacement remains visible. The completion
record pins the original operator and complete consent; substituting another
self-signed operator does not permit startup. TLS inputs must match their
consented digests. Each peer leaf also binds its Ed25519 transport identity to
the immutable runtime bootstrap reservation. The monitor is independently reserved.
Consent expiration or withdrawal stops an active signer,
including direct `run` execution without the outer manager.

```sh
HyperNet authority-replica initialise \
  --bootstrap /Config/Bootstrap.cbor \
  --bootstrap-digest VERIFIED_SHA256 \
  --key /Config/VoterIdentity.json \
  --config /Config/ReplicaRuntime.json \
  --authorization /Authorization \
  --directory /State/Replica

HyperNet authority-replica status \
  --directory /State/Replica --minimum-generation 1

HyperNet authority-replica run \
  --directory /State/Replica --minimum-generation 1 \
  --authorization /Authorization

HyperNet authority-replica live-status \
  --directory /State/Replica --minimum-generation RETAINED_GENERATION
```

Initialisation writes the authenticated bootstrap, signer identity and initial
journal, then publishes one completion record containing the exact runtime
configuration and its digest. It opens no listener and starts no peer work. An
incomplete deployment is non-serving; the command never silently repairs it by
recreating signer state.

`run` first requires the OCI security profile and installs Landlock while still
single-threaded. It then requires a fresh valid clock observation. It prints
`Starting`, serves in the foreground, and stops on SIGINT or SIGTERM. `Starting` is not proof of quorum
readiness. A successful Suite `authority-inspection inspect` verifies the actual
executed-result certificate. Graceful shutdown prints `Stopped` with the final
journal `generation`, applied and committed heights, and configuration digest.
Retain that generation independently and pass it as `--minimum-generation` on the
next run. Do not substitute `1` after a signer has progressed.

`live-status` queries the running signer through the same-UID local socket,
without acquiring its journal lock. It reports local generation, heights and
clock status with quorum explicitly `NotProbed`. It cannot authorize a service
effect or replace a fresh Suite quorum inspection.

`status` opens the stopped signer journal exclusively and prints `Offline` with
its generation. It refuses while another process owns the journal. `clockReady`
is a local clock observation, not a network readiness assertion. A missing,
corrupt or below-floor journal fails closed; none of these commands initialise a
replacement. Following abrupt process loss, inspect the retained journal with
the last independently retained floor before restarting.

The independently retained generation is a lower bound, not complete rollback
protection. A historical snapshot may exceed that bound while omitting votes
written afterward. Local checksums cannot detect that rollback, nor rollback of
all local files and the operator's floor. Protect restart generations outside the
signer storage and preserve the complete current journal. Never restore a
historical signer snapshot as an ordinary restart or lower a floor to make it
open. Suspected durable-state loss requires an explicit protocol recovery
procedure; this entrypoint does not provide one. When moving a signer, preserve
its current journal and stop the previous instance. Capacity exhaustion is an
explicit refusal; do not delete history to restore service.

A view timer is armed once per entered view and is consumed on expiry. Its
duration is 1000 ms+250 ms*floor(log2(view)); WISH retransmission continues while
awaiting the next authenticated entry. Restart uses the retained view number.
The finite-u64 profile reaches at most 16.75 seconds and refuses counter overflow;
it provides no arbitrary-delay or five-second request-completion guarantee.
An expired recipient challenge always needs a fresh explicit request.

New proposal candidates reach application validation only after three authenticated
current-view reports are retained. Proposal creation still verifies their full
quorum and dependencies. Transport acknowledgements with no reply receiver do not
generate another signature or trigger proposal work; queued local protocol work,
new reports and clock ticks continue to drive progress.

## Checkpoint storage and catch-up

Every 32 applied positions, a replica durably retains its exact application state
and signs a checkpoint statement. Three matching voter signatures certify it.
The statement binds the applied node, complete state digest and append-only
history root. Commit evidence and verified ancestry bind that anchor to the
decided branch. A checkpoint signature does not grant application permissions.

Compaction retains the signer's current view, locks, exact voting obligations,
unexpired replies and required ancestry. A durable retired-view floor prevents
new signatures for removed votes. Entry into view v retires signatures through
max(previousFloor,v-2), before allocating the next report, even when no checkpoint
exists yet. Complete safety dependencies and current/previous-view certificates
remain available, and valid late Commit certificates can still be applied.
Two pending checkpoint states and the latest certified checkpoint are retained.
Application pauses when both candidates await certification; voting can continue
within the reserved pending-storage capacity. A durable application cursor scans
at most 64 ancestry headers per turn and executes at most one position per turn.
It retains the actual deciding certificate throughout discovery and application.
Exact requests on that committed suffix are removed from submission gossip and
proposal candidates while application catches up; speculative requests and new
challenges remain eligible, and consensus view progression remains independent.
Outstanding safety obligations or unavailable expiry evidence can defer reclamation.

Execution claims for the current committed but unapplied node may remain in one
transient bucket, with one claim per committee signer and at most four complete
196608-byte peer payloads in total. These claims cannot install dependencies or
trigger repair. Only an exact match to the locally durable execution contributes
to a result quorum; a conflicting signer cannot select the result or suppress
other matching claims. A changed target discards the old bucket. Restart or
eviction uses the existing bounded result-query recovery.

`Objects/` holds immutable node, command, certificate, executed-result and
application-state bodies. Current application, checkpoint and candidate roots
name their exact state digest. Identical roots share one stored object and one
allocation charge. Resolved state bytes remain shared in memory; journal
transactions do not repeat those bodies.
The journal contains their exact identities, hashes, lengths and allocation charges.
The pending profile permits 4096 nodes, 20480 objects and 256 MiB; ordinary
requests use at most 3584 nodes, 17920 objects and 224 MiB. The remaining capacity
is reserved for certified repair and explicit inert progress. Three phase
certificates per retained node are reserved before a vote. At most 64 executed
reply bundles are retained, each within the 196608-byte peer payload bound.
Canonical result bytes are limited to 188416 bytes; oversized application effects
must produce a finite capacity refusal. An inert command produces no reply bundle.

A128 MiB maintenance allowance bounds reply bundles, archive transfers and
staging. Journal storage is separate: each journal has at most 224 MiB encoded
metadata and225 MiB allocated bytes, plus its atomic replacement. Application
states and checkpoint candidates are at most 8 MiB each. Their unique objects use
the existing pending object and byte limits. Before application execution, one
complete maximum-size state allocation is reserved while old roots remain
durable. A new checkpoint candidate aliases that same state object.
Allocation charges round up the object header and body to
at least 4096 bytes using the filesystem fragment size (at most 65536), plus a
256-byte index charge. Unsupported allocation units or excess actual file blocks
refuse publication. These are this storage profile's allocation limits, not a
promise about arbitrary filesystem metadata or total process memory.

Immutable objects are synchronized before the archive and journal name them.
Restart validates all referenced objects before collecting unreferenced files;
missing or altered committed objects refuse restart. Immutable Page inputs use
the same journal object store and allocation limits. A learned certified command
can be retained while its declared inputs are unavailable, but it cannot produce
a vote or application result until authenticated repair restores them. Pending
checkpoint transfers pin their exact input closure; expiry releases those pins
and durably collects unreferenced partial inputs. Preserve the complete
journal directory, including `Objects/`, when retaining signer state.

Signer snapshot format3 accepts only descriptor-backed state bodies. Inline-state
snapshots from earlier internal formats are incompatible; no in-place conversion
is provided. Never initialise over an existing signer directory or discard it to
resolve this incompatibility. Package state compatibility must be established
before activation. The private state-object kind is not a peer repair object;
authorised checkpoint transfer retains its existing proof and chunk protocol.

Use persistent storage that honors file and directory synchronization. Proposal
persistence, scheduling and delivery must fit the one-second proposal admission
bound for progress. Slow durable writes can exhaust that interval even while the
clock observation remains healthy. Compare `ProposalClockAge`, queue delay and
storage timing diagnostics under the intended workload. A successful startup or
short storage sample does not establish sustained availability. Preserve the
durability and freshness requirements when correcting a storage bottleneck.

`History.bin` retains at most 131072 committed node digests, approximately 4 MiB
plus its header. The journal binds its exact size and root. Archive writes are
synchronized before that journal generation is published. Restart verifies the
committed prefix and discards only an uncommitted suffix. Missing committed
history, corruption or a conflicting prefix refuses restart. Preserve this file
with the complete current signer journal; deleting it is not a repair procedure.

Each peer has two bounded send lanes within one 128-message/4-MiB mailbox.
Recovery reserves 16 slots and 2 MiB from that aggregate budget and uses a
separate connection within the existing two-connection peer cap. Retired queued
broadcasts are removed against the current durable retransmission set; queued
submissions and repair requests are tied to their current local obligations.
Requested responses are coalesced by response type and leave the queue after
the three-second transport interval unless a repeated request refreshes them.
The same exact requested response can be regenerated. These queue rules change
neither consensus evidence nor client deadlines.

Each authenticated HTTP connection can carry successive messages within its
original three-second total lifetime, including the TLS handshake. Reuse does
not reset that deadline. The client retains at most two idle connections per
peer, matching the two send lanes. The two-connection peer cap, global ingress
cap, bounded message bodies and exact TLS identity checks still apply.

Repeated result polls send peer queries at most once per request digest per
250 ms. At most 32 pending query timings are retained; expired entries release
capacity. A complete locally assembled proof returns immediately. This limit
does not renew a challenge or alter the requested operation.

Normal operation writes bounded diagnostic categories to standard error. Local
capacity, event-queue refusal, closed responses and transport timeouts have
distinct codes. Driver queue delays and completed work of at least 250 ms are
reported separately from idle waiting. An independent runtime task reports work
still active after one second; its observation can itself be delayed by host
resource pressure. Each category emits at most once per five seconds, with the
next record counting suppressed observations. Completed slow turns include
storage sync count, total and maximum sync time, file and directory counts, and
successful journal commits. Decoded peer turns include the numeric message kind.
Activity summaries include the suspend-aware boot time when available, allowing
local request timings to be compared with the reported storage interval.
Each summary also includes up to 32 view-timing records. These record first
accepted-command/proposal observation, durable votes and QCs, committed position,
durable execution, matching execution quorum and first local result selection.
Acceptance is successful driver admission, not arrival at the control socket.
`replyReady` means the result has been constructed for the local caller; it does
not attest delivery through the control socket. Each phase is cumulative elapsed
nanoseconds from the first accepted command, or the proposal when acceptance was
not observed. The original starting boot time permits external correlation;
unobserved phases and unavailable boot time are null. Repeated messages do not
restart observations. Completed local selections are reported at the next
summary; other views are reported as incomplete after five seconds without new
phases. Controlled shutdown flushes remaining records. At most 32 acceptance
timestamps and 32 view records remain in memory; saturation counts lost timing
observations without delaying authority work. No command digest is logged.
A proposal rejected by the existing one-second clock-age bound reports
`ProposalClockAge` and its measured age. Records contain fixed categories,
durations and view numbers, without request contents, keys or private errors.
Shutdown and final journal-reopen markers distinguish protocol shutdown from
validation of the stopped journal. These observations do not alter deadlines,
proof requirements or admission limits.

Envelope signature counters in numeric activity diagnostics describe strict
verification attempts, verification time, cache lookups, hits and evictions.
They cover the synchronous turn's thread and contain no payloads or identifiers.
Queued-proof classification has its own non-overlapping synchronous turn, including
inputs that are deferred or do not form a batch.
These timings can overlap application-state parsing; they must not be added to
other overlapping timings as independent costs.

Before a checkpoint is available, requested repair can walk a longer certified
branch by importing smaller complete QC-rooted subclosures. It keeps the original
target and re-fetches transient upper records as needed, without exceeding the
32-record active staging bound or publishing unauthorised fragments.

A lagging signer requests a certified checkpoint and bounded state/history
chunks from a configured peer. It verifies the complete state, history root,
its own retained prefix and local safety obligations before atomic installation.
The donor retains one snapshot per remote peer, at most three snapshots of
8388608 bytes each, within the maintenance staging allowance. A fixed 120-second
lease binds each transfer; retries do not renew it. Publishing a newer checkpoint
does not replace an active snapshot. If the old snapshot is already unavailable,
an exact authenticated replacement response can select a newer certified
checkpoint. The receiver uses a new transfer ID and keeps its original deadline.
Delayed responses from the previous transfer cannot advance the replacement.

Partial, unsolicited or conflicting transfers grant no voting authority. This
path requires the signer's existing journal and never creates replacement locks
or resets its generation floor. A divergent lock remains intact with its full
verified local ancestry to a shared authenticated prefix. Installation preserves
exact local votes and the retired-view floor; only ordinary phase processing can
later move that lock. One of the existing 4096 node slots is reserved for a new
certified anchor. Incomplete safety ancestry or an excessive retained closure
refuses installation. A missing signer journal requires explicit committee
replacement or recovery, which this entrypoint does not provide.

The independent Suite client uses this same certified history to reconnect an
older durable floor to a current result. Catch-up never resets that floor or
extends a recipient challenge. Checkpoint compaction preserves the complete
application stream ledger.

Each admitted requester has a permanent stream, with at most 256 streams and
1048576 encoded bytes including reserved refusals. Initial streams belong only
to the subjects of authenticated genesis root grants. A request never creates
its own stream. Ordinary signed requests bind a generation, generation identity,
sequence and explicit acknowledgement. Acknowledgement retires the older result;
it never makes its sequence executable again. Receipt capacity is reserved before
a permitted domain change and committed atomically with that change. A finite
capacity refusal can itself be retained and subsequently acknowledged.

`AuthorityStreamStatus` returns only the requester's current completion metadata,
never the retained result body. An absent stream is a permitted, non-allocating
status result. `AuthorityStreamFence` compares exact certified metadata and starts
a new generation; its exact retry preserves later work in that generation. A
mutation timeout does not imply non-execution and does not authorise automatic
acknowledgement or fencing.

Admission requires the current admitted generation. A request admitted before a
fence can still be present in committed ancestry: execution advances normally
with a finite refusal and preserves the newer stream. Missing streams return
code 3, retired sequences code 21, sequence gaps code 12, and generation or
occupied-sequence conflicts code 28. Applicable current authority, context and
freshness refusals use the smallest finite code. Invalid stream classifications
change neither domain records nor the stream. A fresh replay still requires
current authority before disclosing a retained body; a disclosure refusal does
not replace the original completion metadata. Status uses only finite refusals
7, 21 or 37 and always returns the exact kind 56 metadata shape. Policy floors
refer to the preceding applied state, before the request advances its height.

## Refresh a signed clock binding after host reboot

A signed source deliberately retains the previous host boot identifier until an
explicit update. Start the existing monitor on the new host boot with its same
key and export path. With the replica stopped, use the previously retained
configuration digest and signer generation. Obtain fresh consent from the same
operator for the exact manifest with only its clock boot changed. The existing
consent interval and all identity, resource and permission fields remain unchanged;
only boot and consecutive predecessor metadata change. The installed manager provides this workflow through
[`runtime transition`](Runtime.md#stopped-consent-renewal-reboot-and-software-replacement).
The lower-level command accepts only the exact next signed manifest generation:

```sh
HyperNet authority-replica refresh-clock-boot \
  --directory /State/Replica \
  --minimum-generation RETAINED_GENERATION \
  --expected-config-digest RETAINED_CONFIG_SHA256 \
  --host-kernel-boot AUTHENTICATED_HOST_BOOT \
  --authorization /Authorization
```

This operation permits only the signed source's `kernelBoot` value to change to
the explicitly supplied host boot identifier. Obtain this identifier from the
host monitor; a container's local boot identifier need not equal the host's. The
operation requires a fresh authenticated observation under the same monitor key
and path, holds the exclusive signer
journal lock, and atomically replaces the authoritative configuration record.
The journal is preserved. Its result supplies the new `configDigest` and
`configGeneration`; retain them independently. It cannot change a peer, signing
key, listening address, monitor key, clock source kind or any other setting.
Epoch-appointed replicas retain and verify their original nomination separately
from the current operational consent. This same stopped recovery preserves their
appointment and signer state. `apply-consent` handles an exact approved operational
successor; it never changes committee membership.

A private source needs no configuration change after reboot; its monitor must
still publish a current observation.

## Qualification scope

The maintained ignored test
`authority_replica::tests::normal_cli_refuses_unconfined_run_before_opening_signer`
requires `HYPERNET_TEST_CORE`. It initialises through the normal executable, holds
the signer journal, then verifies that an unconfined `run` receives the specific
OCI refusal before journal acquisition or listener creation. The journal remains
unchanged. Pure protocol and independent Suite interoperability tests exercise
the underlying engine separately; they are not installed node qualification.
The confined process workflow, signed clock handoff and independent failure
domains require their own qualification.
