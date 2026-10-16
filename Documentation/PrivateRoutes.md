# Private remote routes

A reader connects to one approved relay. A fresh TLS 1.3 channel inside that
connection authenticates the final application service before the reader sends
application credentials. The relay can observe the source address, selected
service, timing and ciphertext lengths. It cannot decrypt the inner channel.

The destination sees the relay connection or its own outbound attachment. No
source address header, proxy header or source address claim is added. A route
contains a numeric relay address and a pinned final identity. It contains no
alternate direct destination. Failure closes the connection; it does not select
a direct route, another trust root or weaker privacy policy.

The saved profile contains the complete kind166 voucher record. `RouteOpen`
carries only its canonical `VersionRef`. The relay retrieves and rechecks that
exact current record before reserving a stream.

## Privacy profiles

- `Independent` requires distinct declared relay and destination control domains.
  This protects the destination from learning the reader address only when those
  operators are independent and do not collude. Signed declarations do not prove
  operational independence or resist global traffic correlation.
- `Organisation` excludes the reader address from the destination connection.
  A shared operator can still correlate both ends.

A reader's saved minimum applies to every connection. An existing session cannot
silently change from `Independent` to `Organisation`. Route TLS is separate from
sealed publication encryption and does not conceal content from its authorised
serving host.

## Transport and permissions

Both TLS layers use ordinary WebPKI certificate verification and the exact
registered Ed25519 transport key and leaf. Endpoint names are certificate names;
connections use consented numeric addresses without DNS, process proxy settings
or redirects. TLS resumption and early data are disabled.

Relay proof keys are separate from membership and application keys. The relay
issues a fresh challenge. The proof binds the exact network, incarnation, relay,
final service, voucher, nonces and TLS exporter. A recorded proof cannot open a
new TLS channel. Current quorum approval reserves the voucher's stream and byte
allowance before forwarding. A durable local spent-connection record prevents
reusing that admitted connection after a retry or restart.

The relay rechecks current deployment consent, sponsor rights, revocation,
registered endpoints and remaining admission. Traffic permission does not grant
Page, mail, transfer or federation access. The final service still checks the
application's signed request and current authority.

Buffers remain transient. Both directions share one reserved ciphertext byte
allowance. Original monotonic duration, idle and consent limits bound the whole
connection. Closing either direction closes both. A retry cannot replenish bytes
or restart those limits.

A live connection retains its original verified Permit, voucher, connection ID,
transcript and exact relay and destination profiles. Fresh `RouteVoucherContext`
proofs revalidate current transit permission for that admitted connection. They
cannot admit another connection or restore one after closure or restart. The
spent marker remains durable through the original connection lifetime, even
when a short permission proof expires. Later usage records for other streams do
not replace the retained admission of this stream.

Each renewal uses a fresh challenge with the ordinary 5000-ms maximum. Forwarding
requires a currently verified permission before each write, including buffered
bytes. The transport guard sits beneath TLS so that reads cannot bypass it by
flushing queued ciphertext or sending alerts. Expiry, withdrawal or a changed
profile stops forwarding. A new proof can
replace current permission; it cannot extend an old proof or the connection's
original duration, idle or byte limits. The endpoint revalidates its deployment
permission separately. Application access still requires its own current proof.

`RouteReady` reports remaining total transport time after relay admission. The
client applies that duration from receipt while retaining its original connection
limit. Inside final-service TLS, `EndpointReady` confirms the exact network,
incarnation, service and protocol after current endpoint permission is checked.
Only then does the client create its application challenge. Submission, polling
and history use the same bounded channel and original application deadline.
Before issuing a challenge, a reader can fetch and verify the current certified
checkpoint and its continuity proof over that same channel. This historical
evidence stays temporary and confers no permission. After the fresh result,
the reader verifies its exact suffix and advances its floor through normal
result acceptance. Preparation does not reset transport time, idle or byte limits.
Every frame is checked against the endpoint's selected protocol. An I/O failure
closes the channel; an unresolved operation cannot silently reconnect or replay.

For protocols 1 through 5, one bounded task handles the session's validated
frames while the authority requester refreshes its shared endpoint permission.
Ordinary requests do not wait for maintenance dispatch while that permission
remains current. Protocol 6 also requires a fresh reader authority check for each
request. Neither path extends the application's own permission or deadline.

TLS acceptance runs independently of the single authority requester. Three
separate allowances each use the configured connection limit: concurrent TLS and
channel-proof parsing; queued, waiting or forwarding readers; and pending or
parked attachments. Classification after channel authentication acquires the
appropriate reader or attachment slot. Occupied reader slots therefore cannot
exclude replacement attachments from parsing, and attachment setup cannot
reserve reader slots. All parsing retains the original finite setup deadline.
The installed descriptor allowance is four times that limit plus 64: three
inbound pools, one destination per forwarding reader, and fixed runtime overhead.
Transient accept failures, including descriptor or socket-buffer exhaustion,
defer acceptance by one dispatch interval. Existing streams and shutdown remain
active; the listener does not spin, enlarge a pool or reset a connection deadline.
Acceptance resumes when resources become available. Fatal listener errors still
stop the service.
Renewal scheduling uses the latest successful measurement of the corresponding
renewal operation and the dispatch interval. Unrelated authority operations do
not permanently increase that estimate. Queued admission separately reserves
the latest measured action cost. Due renewals take priority between authority jobs. Cold reader
admission separates voucher context from the final Permit so renewal can run
between them. A retained exact voucher can supply context, but it never replaces
the current Permit required before forwarding. One waiting reader admission step
can follow renewal, including a reader that arrived during the renewal. An
unrelated background attachment cannot consume that turn. The forwarding guard
still enforces its certified expiry while that step runs.

If a measured cost would require renewing a newly accepted proof immediately,
the scheduler leaves the first half of that proof's actual remaining lifetime
for useful work. A viable earlier renewal start remains unchanged. This changes
dispatch timing only: insufficient authority capacity still pauses or refuses
I/O at expiry. It never extends a proof or a connection deadline.

Route metadata that is byte-identical to successfully persisted state does not
require another disk replacement. Changed metadata and every new spent connection
still require durable publication. A failed replacement cannot count as a saved
copy or suppress the next write.

Queue time counts against the original admission deadline; excess connections
close. Fixed-category, bounded diagnostics distinguish capacity refusal, TLS or
request rejection, authority admission, admitted permission expiry, unavailable
attachments, forwarding failure and transient listener failure without logging
peer addresses or content.
These category counters remain active after the timing sample allowance is spent.
At most 64 connection samples per process also report fixed stages,
elapsed monotonic time and boot-time timestamps. Relay timings start when channel authentication finishes
and the request enters the admission queue. Endpoint timings start at acceptance.
They distinguish queue delay, voucher inspection, permission reservation, egress
connection, readiness and final TLS without logging identities or request data.
Each sampled connection also reports at most 32 application-frame sequences
and four relay permission renewals. Endpoint stages separate request arrival, dispatch,
local response and final flush. Renewal stages identify expired permission and
resumption after a fresh proof. Each endpoint activation also reports its first
64 permission renewals, including old and new boot-time expiry and fixed failure
codes. These samples do not contain application data.
Before announcing readiness, an endpoint refreshes permission that is too close
to expiry for its measured renewal budget. If permission expires between dispatch
and readiness, the bound channel waits for renewal within its original limits. Closed permission still
refuses. Sampled readiness stages distinguish binding, byte-budget and write failures.

Connection limits bound resources; they do not guarantee concurrent throughput.
The authority must finish fresh permission checks within their certified
lifetimes. An operation that takes longer than prior measurements can still
pause forwarding. Capacity planning must include these checks as well as
application requests; changing a connection limit does not extend a proof.

## Installed roles

Role 5 has three modes under one runtime:

| Mode | Connection behaviour |
| --- | --- |
| Relay | Accept a reader and connect to an exact registered public endpoint, or consume one approved outbound attachment. |
| Public endpoint | Accept inner TLS and expose one explicitly selected application socket. |
| Attached endpoint | Maintain a bounded pool of fresh outbound TLS connections to its selected relay. No inbound host listener is published. |

An attachment authenticates the registered endpoint service key with a fresh
channel proof. Each attachment serves one reader stream. Reconnection obtains
current authority and new channel authentication. After its single successful
Permit, a reader can wait for a missing or expired attachment within its original
setup and total transport deadlines. The waiting reader retains its existing
slot, exact target envelope, transcript, byte allowance and spent reservation.
A pending replacement for that target receives the bounded reader fairness turn.
Deadline expiry drops the waiting reader; it never opens a new reservation or
resets a budget.
The attachment lookup certifies both the endpoint and relay permission closures.
Its response must include the exact current relay record and local consent;
that same certificate bounds admission of the parked connection.

A parked attachment carries identity, not permission to forward. It remains inert
within its original idle and transport deadlines and both profiles' consent
lifetimes. Pairing requires the reader's original successful Permit, current
transit permission and the exact registered target envelope. A changed key,
generation or withdrawal prevents pairing. If a
waiting reader's initial permission expires, pairing first verifies the existing
reservation through a fresh VoucherContext with the same voucher and exact relay
and target envelopes. No renewal occurs while no matching attachment is available.
Both the reader's setup deadline and the selected attachment's original deadlines
are checked again after renewal. An attachment that expires during renewal can be
replaced within the same reader deadline. Neither peer receives Ready before these
checks, and both Ready writes remain bounded by the original setup deadline.
Keeping an idle socket does not renew permission; active forwarding needs the
fresh checks above.

Each endpoint exposes exactly one protocol:

| Protocol | Exposed operation |
| --- | --- |
| 1 | Authority submission, result polling, health, ancestry and checkpoint history. Local diagnostics and management controls are excluded. |
| 2 | Signed content exchange with one installed Page store. |
| 3 | Signed media exchange with one installed media store. |
| 4 | Signed mail exchange with one installed mail store. |
| 5 | Signed transfer exchange with one installed transfer store. |
| 6 | A signed reader `RouteBridgeRead` for one exact `BridgeLease`, after a current quorum check of that reader's capability. Unsigned bridge administration and `BridgeSync` are excluded. |

Protocol 0 identifies an opaque relay. It does not expose an application socket.

The role uses a rootless container, a read-only configuration, no capabilities,
resource limits, a dedicated UID, local consent guards and Landlock. The
application mount contains only the selected service's private control socket.
The requester and recipient journals stay in the route service's own private
state. They are not mounted into another application.

The route workload cannot reach arbitrary Internet addresses. Numeric egress
passes through a separate, minimal rootless helper using an owned private Unix
socket. The helper accepts a manifest endpoint identifier, never a caller-supplied
address. It has no TLS keys, membership keys or application data mounts. Its
filesystem access includes only its socket directory, fixed egress configuration,
public consent and withdrawal metadata, and the fixed clock metadata paths.
Confinement and its boundary checks run before worker threads or sockets exist.
The read-only consent directory preserves observation of atomic withdrawals. Its
fixed numeric destination allowlist is part of the trusted implementation; its
Landlock network restriction operates on ports. This does not claim an IP filter
inside the helper process.

## Configuration and local consent

Prepare these exact files in a private configuration directory:

```text
Bootstrap.cbor
Certificate.pem
CertificateAuthority.pem
Manifest.cbor
RouteProfile.cbor
Service.key
ServiceConfig.json
Transport.key
```

`RouteProfile.cbor` is the operator-signed registered profile. It binds the exact
network and incarnation, deployment, service and transport identities, deployment
profile and consent references, mode, application protocol, control domain,
endpoint, lifetime, stream count and traffic limits. Registry metadata stores no
transport private key.

`Service.key` is the dedicated service signing seed. `Transport.key` is its
separate TLS private key. The leaf and certificate authority files must match
the signed route profile. The manifest admits the exact own TLS endpoint and
any numeric outbound endpoints. An attached endpoint retains its own TLS
identity in the manifest but does not open or publish an inbound listener.

A relay or public endpoint uses this service configuration:

```json
{"version":1,"relayIdentity":null,"relayAddress":null}
```

An attached endpoint supplies the exact approved `relayIdentity` and numeric
`relayAddress` in those fields. The relay leaf, key and address must also match
an admitted outbound manifest endpoint.

Import, inspect and consent using the normal installed service lifecycle:

```sh
HyperNet runtime services setup --directory /Private/Route \
  --configuration /Private/RouteConfiguration \
  --operator-key /Private/Operator.key --host-consent /Private/HostConsent.cbor \
  --authority-directory /Private/Authority --clock-directory /Private/Clock
HyperNet runtime services preview --directory /Private/Route
HyperNet runtime services consent --directory /Private/Route --profile-digest DIGEST
```

For endpoint protocols 2 through 6, add
`--route-service /Private/InstalledApplication` during setup. The imported
application must belong to the same network and incarnation and have the exact
corresponding service role. Setup generates the immutable socket binding,
egress configuration and seccomp configuration. These generated files join the
operator's exact local consent.

Register the signed route profile through the authority client. Obtain the
normal exact activation request before starting the role:

```sh
HyperNet runtime services start --directory /Private/Route \
  --activation-request /Private/Activation.cbor
HyperNet runtime services status --directory /Private/Route
HyperNet runtime services stop --directory /Private/Route
```

A local withdrawal takes effect before container cleanup. Registry withdrawal
also prevents new certified routes. In-flight streams stop when current permission expires or a restrictive
change is observed; no permission change recalls previously disclosed content. Keep the role's state directory across restarts. Do not reconstruct
consumed vouchers or requester journals from a stale copy.

A signed clock observation that passes all other validation but reaches its
fixed expiry suspends the installed route service. The service closes its
permission gates, connections and listeners, and drains ingress and forwarding
tasks. Existing streams cannot resume. While suspended, local withdrawal,
generation, consent, activation and configuration checks remain mandatory.
The original monotonic consent deadline continues to run.

After a fresh observation, the same confined process reconciles its exact
persisted requester operation and obtains current authority confirmation of the
unchanged route profile before accepting new connections. This does not repeat
activation, restore consumed voucher capacity, or extend a connection or
permission deadline. Invalid clocks, changed authorization or configuration,
unrecoverable journals and expired consent stop the service. Fixed
`Suspended` and `FreshObservation` diagnostics contain no connection identifiers.
