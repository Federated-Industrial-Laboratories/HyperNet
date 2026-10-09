# Runtime and connection contract

This is the HyperNet 0.8.0 replacement contract. Native runtime management and
offline client preparation implement a bounded subset; their operation manuals
state the current capabilities. The remaining authority and routing requirements
are not an installed Byzantine-network claim. Policy, wire and authority requirements remain
mandatory when these workflows are implemented. Runtime preparation can precede
network availability; it cannot relax privacy or authority requirements.

## Local management boundary

Core owns the native runtime command and a private local management API. Suite
may present that API but is not a server dependency. Routine operator workflows
must not require development scripts, manual certificate assembly or test helpers.
Build and qualification tooling may use Python independently.

The local API uses an owner-only Unix-domain socket, checks peer credentials,
and accepts only fixed typed operations. It is not remotely bound or reachable
through a reader relay. A network grant cannot replace local operator consent.
Requests contain an operation ID, exact desired-profile digest and expected local
generation. Management credentials cannot be reused as ordinary reader keys.
There is no remote shell, arbitrary command, arbitrary path or plugin evaluation.

| Operation | Required outcome |
| --- | --- |
| Initialise | Prepare private software/state boundaries and a draft profile; expose no port |
| Preview | Show effective policy, provenance, exact resource delta and unmet requirements |
| Consent | Sign the exact local role, endpoints, storage, quotas and expiry |
| Start | Recheck current generation, consent, authority and isolation before serving |
| Status | Distinguish process state, readiness, quorum, clock health, storage and consent |
| Stop | Stop only the named deployment; preserve durable state and consent |
| Withdraw | Durably prohibit restart and revoke local operation independently of quorum |
| Renew | Accept an explicit unchanged or narrower renewal within its approved window |
| Update | Verify software and state compatibility, preview delta, then switch atomically |
| Restore | Prepare non-serving state; reconcile current certified history before service |
| Diagnose | Create a bounded redacted local preview; export only by explicit action |

Profile, consent and lifecycle record fields are in
[PolicyContract.md](PolicyContract.md). A generation is never reused. An unchanged
retry returns the same recorded outcome; a changed request with the same operation
ID is refused. Ordinary mutations require the exact current local generation.
For an unchanged immutable profile, Withdraw is a strictly restrictive veto: it
accepts an observed generation from one through the current generation, while
rejecting future generations and a different profile digest. It advances the
current generation under the same lock. A queued veto therefore still stops a
concurrent activation that committed after the operator observed its generation.
A durable withdrawal wins a concurrent start through this profile transaction. Shutdown and failure recovery do not erase this
tombstone. Reactivation requires a new consent and generation.

The manager supervises only resources carrying its deployment identifier and
matching recorded configuration digest. Labels alone do not authorise taking over
an unrelated process, container, socket or volume. Recovery cross-checks the
resource identity and retained journal. Unexpected resources produce a diagnostic
refusal. It never deletes unrelated state to resolve a naming collision.

## Readiness and persistence

Lifecycle states are Installed, Configured, AwaitingConsent, Stopped, Starting,
Ready, Degraded, Failed, Withdrawn, Updating and Recovering. A running process can be non-serving. Ready requires current
authority, valid consent, verified confinement, available dependencies and enough
reserved capacity. Missing quorum, unhealthy clocks, expired consent or an
unverified restore prevent affected operations. Degraded status names which
operations remain usable rather than advertising universal readiness.

Persist a transaction's intended generation and exact dependencies before
activation. Prepare filesystem objects and bounded resources, verify them, then
commit the generation. On restart, reconcile the journal with only those exact
resources. An interrupted preparation cannot become an active permissive profile.
If authority expires during preparation, discard the activation permission and
obtain a fresh check. Reserving storage does not reserve future authority.

The software prefix, authority safety journal, local lifecycle journal and content
volumes have separate ownership. Service processes receive only their declared
handles and credentials. Rootless confinement, resource limits and network egress
restriction remain required. There is no shared runtime-manager key that can
decrypt every mailbox or sealed page.

Installation is inert. Boot/logout behaviour is explicitly selected during
activation through supported Linux service management. Automatic consent renewal
is disabled by default. A selected renewal window cannot add roles, paths,
endpoints, volumes, recipients or budget. Expiry does not become permanent consent.

## Reader provisioning and route coverage

A client-only installation needs no host runtime, inbound listener, storage
contribution or voter key. Offline provisioning imports independently authenticated
network and relay identities into a private profile. It does not redeem an
invitation or grant membership. Online joining requires the approved relay path.
Until that connector is implemented and available, online joining is unavailable;
there is no transitional direct-reader mode.

Offline bootstrap binds the descriptor, initial governance, recovery-policy
acceptance and planned relay/admission identities under one independently pinned
bundle digest. It does not include a usable relay voucher or register a service.
An online bootstrap additionally requires a narrow expiring relay voucher.
The voucher has a distinct relay key/purpose and byte, stream, duration and replay
bounds. It conveys no membership, content, hosting or voting right. The invitation
secret is sent only inside the authenticated inner final-service channel.

The common connector owns every reader network operation: bootstrap, admission,
authority/discovery, catalogue/search, page/media, mail/forms, transfers, refresh,
retry and error recovery. A caller supplies a registered service identity and
operation purpose, not an arbitrary URL. Redirects, proxy environment variables,
diagnostic callbacks and image references cannot bypass this connector.

One approved relay carries the inner TLS 1.3 stream to the selected service.
The client verifies that service against its pinned descriptor before sending
application credentials. The relay cannot terminate the inner channel. Disable
early data and original-address forwarding, including Forwarded, X-Forwarded-For
and PROXY headers. Relays have bounded transient buffers; no persistent queue or
backup is implied. Unavailable routes fail closed with a specific local reason.

For NAT hosting, the authenticated outward service attachment identifies a single
registered service and generation. Pair only authorised streams with that exact
attachment. It cannot expose arbitrary LAN addresses, ports or host files.
Reconnect requires fresh route admission and endpoint authentication; it cannot
reuse an old stream as a new consent or revive a revoked attachment.

Independent and organisational relay profiles have different guarantees. The
first assumes no relevant shared control or collusion between relay and service.
The second conceals the address at the service connection while trusting the
common operator with correlation. Signatures identify declared operators; they
cannot prove operational independence. A client's stronger minimum refuses an
incompatible route during initial connection, retry, reconnection and policy
change. No session silently weakens assurance.

Connection inspection reports observed endpoints, declared logical route,
authenticated identities, encryption termination, selected privacy assumptions,
authority freshness and exact publication provenance. It does not claim a proven
physical Internet path or geographic location. Host-readable/sealed status is
displayed separately from transport encryption.

## Audit and diagnostics

Every security mutation atomically records a bounded authority audit event with
its committed decision: actor reference, operation/result digests, scope, policy
generation and refusal/success code. Failure to persist that required event
prevents a success response. Bulk payload and local operational events do not
belong in the permanent authority log.

Operational events contain fixed codes, component, generation, capacity and
bounded timing counters. Exclude secrets, invitation material, page/mail bodies,
form values, query terms, full URLs and complete browsing histories. Identifiers
and timing remain private metadata. Escape terminal controls during display.
Bound bytes, age, collection depth and capture duration; reserve failure-reporting
space. Operational event loss is counted and visible.

Diagnostics are local and previewable. An explicit export writes only the selected
redacted data to an operator-selected local destination. No provider upload,
automatic network probe or direct reader connection is part of diagnosis.
Hash chains and signatures provide attributable evidence under stated trust
assumptions. Retained external or authority-committed heads are needed to detect
tail removal; a local signature cannot prove that an emitter reported everything.

## Software replacement and qualification

Verify a signed inventory before extraction. Update metadata must bind target,
platform, version floor, expiry, root rotation and state compatibility; archive
signatures alone are insufficient. Dependency selection and complete update
metadata integration must be qualified before any TUF compliance claim.

An update cannot grant new host rights. Prepare verified software, preview the
exact delta, check authority admissibility, stop the affected profile, switch and
verify readiness. Automatic rollback may use only a compatible state contract
and must preserve all security floors. Incompatible prerelease replacement uses
fresh profiles and explicit enrolment; old instances retain their own state.

Required installed acceptance includes native service boot/logout/restart,
withdrawal/start races, consent expiry, clock uncertainty, full disk, interrupted
activation/update, missing quorum, route outage, endpoint substitution, stale
restore and redacted diagnostic export. Independent failure domains and real
remote privacy coverage require deployment evidence. Four local containers
demonstrate neither four compromise domains nor an Internet anonymity guarantee.
