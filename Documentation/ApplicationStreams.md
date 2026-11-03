# Application streams

[Documentation](ReadMe.md) | [Private routes](PrivateRoutes.md) | [Application access](Applications.md)

Application streams connect approved applications through the existing relay and
nested TLS transport. A service has an opaque protocol name, such as
`example.events/1`, and an exact local socket binding. Applications receive a
duplex byte stream and separately verified peer context. HyperNet does not parse
HTTP, model requests or file formats carried inside that stream.

Protocol 7 requires matching Core and Suite support. Protocols 1 through 6 keep
their domain contracts. An older endpoint refuses protocol 7; there is no direct
connection or weaker protocol fallback. Upgrade the authority committee together
before registering new stream records. Do not operate a committee whose members
interpret application renewal or stream records differently.

Version 0.9.1 requires Service-only terminal grants for stream management and
connection. Network and mixed-purpose grants refuse these operations. The legacy
numbers 29/30 also identify sealed-page permissions under a separate, disjoint
scope rule. Read [permission scopes](PermissionScopes.md) before upgrading an
existing service or application; same-rights renewal cannot repair a broad grant.

## Permission boundaries

A route voucher permits transit. An application capability permits use of one
service. These are separate checks. The receiving application must also apply
its own policy to every operation.

Service registration requires action 29 with scope `(3, service ID)`, plus exact
signatures from the application owner and endpoint operator. Connecting requires
action 30 with the same service scope. The registered endpoint must be a current,
consented protocol 7 route. Its owner, operator, deployment, local binding,
protocol, resource limits and finite validity are bound by the registration.

The caller signs a fresh endpoint challenge inside final-service TLS. The proof
binds its application principal, exact capability and service generations, slot,
session generation, nonce, protocol, byte/time limits and TLS exporter. Relay
possession keys cannot substitute for the application principal. A proof copied
from another TLS connection cannot open this connection.

The endpoint checks current application permission before releasing payloads.
Endpoint deployment permission and each application session have separate gates.
Both must remain current for buffered or new writes to pass. A permission renewal
does not extend the original session deadline or replenish its byte allowance.

## Prepare the local service

Use the Suite's `streams offer`, `inspect-offer`, `accept`, `register` and
`endpoint-config` commands. The accepted artifact contains the exact owner and
operator consent; the configuration command emits Core's version 2
`ServiceConfig.json`. Follow the
[Suite application-stream guide](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/ApplicationStreams.md)
for complete arguments, profile selection and the local SDK.

Start the companion with the accepted binding before importing the endpoint.
The companion exposes two separate private interfaces:

- `Control.sock` serves the local application's connect, accept, status and cancel
  requests. It belongs to the native application's account.
- `Ingress/Control.sock` accepts only the confined endpoint's payload connections.
  `Ingress/Binding.json` identifies the exact service and local binding.
- Matching capability-enabled companions also expose `Ingress/Checks.sock` for
  [fresh local authority checks](ApplicationChecks.md). This optional control
  channel does not consume an application slot or change the payload protocol.

The installed rootless endpoint maps only `Ingress` to `/Application`. It cannot
reach the SDK command socket, requester profile, signing keys or target map.
Native companions use a subordinate-owned ingress helper so directory mode 0700
and socket mode 0600 remain effective across the container UID boundary. The
endpoint retains the rootless `nomap` user namespace; its UID 1000 corresponds to
UID 1001 in Podman's parent user namespace. Host setup checks that exact mapping
and binding. It does not change directory ownership or broaden permissions.

Use the normal service setup with the new explicit binding:

```sh
HyperNet runtime services setup \
  --directory /Private/Endpoint \
  --configuration /Private/EndpointInput \
  --operator-key /Private/Operator.json \
  --host-consent /Private/HostConsent.json \
  --authority-directory /Private/Authority \
  --clock-directory /Private/Clock \
  --application-directory /Private/Companion/Ingress
```

If the authority runs on another machine, start Suite's generic
`network authority-connector --profile /Private/AuthorityClient.json
--ipc-directory /Private/AuthorityConnector` from its own joined profile.
Use `--authority-connector-directory /Private/AuthorityConnector/Ingress`
in place of `--authority-directory`. The companion and authority connector use
separate requester profiles. Their private keys and SDK sockets are not mounted
inside the endpoint.

Core pins the connector's exact network, incarnation, accepted bootstrap and
public route digest in local consent. Restart refuses a changed binding. The
connector forwards existing protocol 1 control frames through the retained
HyperNet authority route; Core continues to verify original signatures, quorum
proofs, clocks and deadlines. An expired route requires an explicit same-target
voucher update through an independently valid authority route. A stopped
connector or unavailable route fails closed.

The remaining setup inputs and artifact names follow [ServiceRuntime.md](ServiceRuntime.md).
Preview the exact manifest and local mount, record local consent, obtain the
normal activation request, then start the service. An attached route uses an
outbound relay connection and has no public application listener. Keep its
relay identity and numeric egress endpoint in the existing consent allowlist.

Size the relay's attachment pool for all attached endpoints. Two endpoints that
each park up to eight connections need room for at least sixteen attachments.
The same `maximumConnections` setting bounds the reader pool separately; choose
it to cover the intended concurrent client and authority connections too.
Set this limit in the explicit route consent;
adding an endpoint does not increase an existing relay's capacity automatically.

The local handshake includes a fresh companion nonce and endpoint-signed peer
context. The companion verifies the endpoint key, exact binding, service,
principal proof and nonce before returning a stream from `accept()`. Application
bytes cannot supply or override that context. Directory/socket replacement,
unexpected UID, an invalid signature or a changed binding refuses the handoff.

## Operate finite streams

Each stream keeps bounded buffers and one shared activity timer. Progress in
either direction keeps the connection active. Directional EOF closes that write
half and permits the opposite half to drain. Cancellation, revocation, expiry,
shutdown and hard failures close the whole connection. A stalled receiver cannot
accumulate an entire response in relay memory.

The route ceiling remains 1 GiB and one hour per connection; a service or caller
may select lower limits. Ciphertext, framing and handshake overhead also consume
transport allowance. Applications should leave headroom and split larger logical
objects into smaller resumable ranges. An application must identify immutable
content and verify it before publication. Native HyperNet Transfer retains its
separate format and limits.

The companion serialises authority operations for its retained requester. It
offers at most 16 active connections and bounded command/accept queues. Use its
structured status and recent error categories to distinguish permission,
capacity, local service and transport failures. Do not log payloads or treat a
historical receipt as present permission.

## Renewal, retirement and recovery

Each service/principal pair has 16 reusable slots. A new session binds the next
generation. A slot can be reused after the endpoint has fenced and retired the
old session, or after its original absolute expiry. A client close alone cannot
reopen a slot while old endpoint bytes might remain live. Restart never restores
spent allowance or revives a closed generation.

The endpoint rotates seven lifecycle work classes: endpoint renewal, session
renewal, completed handshakes, attached arrivals, public arrivals, completed
forwarding and cleanup. After each selected lifecycle event, one queued authority
check can run before another lifecycle event. Checks alone do not wait for an
idle class. The check queue keeps its original order and capacity. An expired or
cancelled check retains its original outcome; selection never renews its budget.
A continuously ready lifecycle class receives a turn within fourteen work
dispatches, even under continuous checks. Due sessions are ordered by their last
renewal turn; new arrivals and serviced sessions cannot overtake older due
sessions. With at most C active sessions, each continuously due session receives
a renewal turn within 14*C work dispatches. These are dispatch bounds, not latency
promises: an in-flight authority operation is not preempted, and each operation
keeps its original deadline and exact recovery contract. An unresolved ordinary
request or fence still prevents a fresh authority check.

Bounded process-local timing separates authority-check queue delay from work in
the endpoint actor. The first 256 verified enqueues retain one numeric sample
through enqueue, dequeue, any endpoint/session preparation, the fresh read and
the final disposition. Early expired and inactive results also retain their
outcome. Elapsed time is measured from enqueue; the original caller start and
deadline are recorded separately. The five actor operation classes (incoming
permission, handshake permission, stream admission, stream permit and cleanup)
each record at most 64 start/end pairs with their original deadline. Stream
admission includes exact recovery, inspection and admission; its elapsed time
does not identify the cost of an individual authority exchange. Endpoint renewal
keeps its existing independent samples and records its call deadline.

Admission records can reference the existing local session sample, which also
marks application acceptance and forwarding completion. These numbers do not
identify a connection in another process. There are at most 2304 added timing
records per process, each below 384 bytes; together with deadline fields on the
existing renewal records, added output stays below 1 MiB. Counters never reset
on reconnect. No account/session identifiers, payloads or arbitrary error text
are recorded. Diagnostic clock or output failures do not change authority
results. One writer thread handles stderr outside the actor. Producers use a
non-waiting send to a 32-record queue; each record is at most 512 bytes (16 KiB
of queued record bytes, plus one writer-held record). Oversize records, full or
closed queues and writer startup failures drop diagnostics. Timestamps are
captured before enqueueing. A stalled sink can therefore lose samples or leave
partial timings; diagnostics are not a complete audit trail. Timing does not
extend deadlines or certify throughput or availability.

One completed stream can wait for measured renewal and action headroom. Its local
gate closes immediately. The single held cleanup record counts against relay
attachment replenishment. Public listeners retain their existing queued/admitted
session limit and separately bounded parser pool, plus at most one closed-session
cleanup record. Cleanup preparation visits the endpoint gate and each session
present at completion at most once, then attempts the exact close. Later arrivals
cannot restart that pass. With C sessions at completion, cleanup receives its
close attempt within 14*(C+2) work dispatches, or reaches its original deadline
sooner. Cleanup retains its first deadline; it does not extend a session or
certified permission. Gates still stop traffic at certified expiry, and expired
or disconnected checks cannot obtain fresh authority. An expired or failed
cleanup emits a bounded category diagnostic.
After a failed attempt, the one held retirement waits one second before another
turn, measured from attempt completion. It keeps its original deadline and target;
expiry releases only this local cleanup record. An uncertain signed close remains
in the durable requester's exact recovery slot. Its original outcome must resolve
before a new retirement context or close can be prepared. This scheduling order
cannot guarantee availability while that mutation is unresolved.

The caller can close a stream before the endpoint retires it, advancing its record
generation. The endpoint obtains `StreamRetirementContext` under its intrinsic
ownership to learn the current session, service and route records. This disclosure
does not require a live connection grant and supplies no forwarding permission.
The endpoint closes only the same original proof generation and signed-proof
digest; a retired or reused slot is left unchanged. A competing close can refuse
the exact mutation again, so the original-outcome and bounded-retry rules still
apply. Existing current-permission and exact-close checks remain mandatory.

This additive read requires an authority committee that supports
`StreamRetirementContext`. An older committee refuses the unsupported query;
the endpoint does not substitute an ordinary mutation or another authority path.
The slot then remains unavailable until its existing retirement or expiry rules
permit reuse. Upgrade the committee before relying on this retirement recovery.

Current session state is kind 173; service state is kind 172. Closing and
retirement replace the bounded current slot record. No authority mutation is
performed per payload frame, token or file chunk. Admission reserves capacity
for restrictive operations before accepting a new slot.

A voucher can renew under the same identifier only after its old admission
expires. Renewal preserves sponsor, possession identity, routes, action, scope
and grant identity. Version 2 vouchers retain cumulative usage baselines;
renewal cannot reset a live voucher's quota, and old exact references refuse.
The companion updates only its own retained route copies. Application identity
renewal follows the separately signed same-rights contract in
[ApplicationProtocol.md](ApplicationProtocol.md).

The service owner can inspect its exact registration and withdraw it even when
normal connect permission has expired. Withdrawal is permanent for that service
identifier. A changed endpoint, local binding or rights envelope requires new
consent. Reconcile uncertain operations through retained requester state; never
delete floors or profiles to recover permission.

History is retained in quota-bounded immutable segments with indexed Merkle
proofs. See [AuthorityReplica.md](AuthorityReplica.md) for migration, quota
inspection and recovery. A physical storage limit remains a refusal boundary;
retaining old-client continuity does not imply unlimited storage.
