# Installed authority runtime

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

`HyperNet runtime` manages one already appointed authority voter per deployment.
Four deployments use the same accepted bootstrap and distinct appointed voter
keys. Their Basic HotStuff committee requires three replicas for authority
results. Setup does not create membership or appoint voters. The separate
[provisioning commands](RuntimeProvisioning.md) create and validate transport
identities, certificates, clock inputs and strict peer configurations. An
authority deployment exposes no reader endpoint.

The supported installed profile is Linux, rootless Podman, `slirp4netns`, delegated cgroup v2,
Landlock ABI6 or later and seccomp. It uses explicit IPv4 addresses and one owned
NAT bridge per deployment. IPv6 installation and SELinux-enabled operation require
platform qualification. Mandatory confinement failures stop activation.
Outbound service helpers require `slirp4netns` in `/usr/bin` or `/bin` on the host.
The OCI image does not supply this host networking dependency.

## Inputs and setup

Obtain the fully accepted bootstrap and authenticate its complete SHA256 digest
independently. A draft bootstrap cannot initialise a voter. Supply the existing
appointed voter identity, four-peer configuration, matching TLS credentials and
a signed clock witness from a separately pinned monitor. The monitor export
must occupy its own public directory, containing observations only. The runtime
mounts that directory read-only so atomic witness replacements remain visible.
Keep the monitor signing key in its separate private directory.

The imported configuration uses the strict schema in
[AuthorityReplica.md](AuthorityReplica.md). Its peer origins contain literal
IPv4 addresses and exact certificate pins. Input TLS paths name local files.
The signed clock path names the host export. Setup rewrites only local workload
paths and the listening address to the fixed container layout; the preview shows
the exact resulting configuration. Peers retain their configured addresses,
ports, identities and certificate pins. NAT or firewall forwarding must make the
advertised peer origins reach the corresponding published port.

Use a private existing parent directory. Choose distinct non-overlapping private
subnets for deployments on the same host. Replace the example addresses and
paths with the intended deployment inputs:

```sh
HyperNet runtime setup --directory /Private/AuthorityOne \
  --image sha256:<verified-image-digest> \
  --bootstrap /Private/Bootstrap.cbor \
  --bootstrap-digest <independently-authenticated-sha256> \
  --voter-key /Private/VoterOne.json \
  --replica-config /Private/ReplicaOne.json \
  --peer-certificate /Private/PeerOne.pem /Private/PeerTwo.pem \
    /Private/PeerThree.pem /Private/PeerFour.pem \
  --bind 192.0.2.10 --port 24443 --subnet 10.89.132.0 \
  --memory-bytes 536870912 --pids 64 --cpu-quota 100000 \
  --state-bytes 1073741824 --lifetime-seconds 3600
HyperNet runtime preview --directory /Private/AuthorityOne
```

Setup reads and validates inputs, copies them into a new private directory and
creates the local operator identity. It starts no processes or network listeners.
It imports no administrator or recovery private keys. It does not invoke a
certificate authority or change the accepted authority appointment.

Supply exactly four leaf PEM certificates matching the runtime peer pins. Each
Ed25519 transport key must match its voter mapping in the authenticated bootstrap.
The separately signed clock monitor must also be reserved by that bootstrap.
The operator cannot reuse a service, voter, monitor or transport key. Setup
stores the canonical CBOR manifest in `Authorization/Manifest.cbor`; JSON remains
a local input and display representation. The exact signed consent binds the
canonical manifest, fixed workload handles and separately ordered peer list.

The default resource allocation is 512 MiB RAM, 64 PIDs and one CPU period of 100000
microseconds with a matching quota. CPU quota is configurable. These are workload
allocations, separate from authority policy limits. Size production resources for
the expected traffic and measured durable-storage latency. Four colocated voters
share storage and scheduling risks; four processes do not establish operational
independence.

`stateBytes` is an available-space admission requirement, not a filesystem quota.
Its default 1 GiB leaves headroom above the engine's bounded object, result,
maintenance, metadata and archive profile; the minimum is 1 GiB. This includes
225 MiB journal allocation and an atomic replacement, 256 MiB pending objects,
128 MiB maintenance and metadata/archive headroom. The engine
continues to enforce its individual storage limits. A deployment requires the
configured available capacity at each start. Ordinary filesystems may have other
consumers and filesystem overhead. The runtime does not claim total disk-quota
isolation.

## Consent and activation

Preview returns `generation` and `profileDigest`. Review the complete resource
manifest, peer exposure, role and expiry. Each mutation requires a new128-bit
operation ID, the observed lifecycle generation and exact profile digest:

```sh
HyperNet runtime consent --directory /Private/AuthorityOne \
  --operation-id <32-hex-digits> --expected-generation <generation> \
  --profile-digest <profile-digest>
HyperNet runtime serve --directory /Private/AuthorityOne
```

Keep `serve` in a foreground session. Its private `Management.sock` accepts only
the same local UID. In another terminal, inspect the new generation and activate:

```sh
HyperNet runtime status --directory /Private/AuthorityOne
HyperNet runtime start --directory /Private/AuthorityOne \
  --operation-id <new-32-hex-digits> --expected-generation <generation> \
  --profile-digest <profile-digest> --minimum-signer-generation 1
```

Consent is a signed105 record bound to the exact desired117 profile, appointment,
transport configuration, signed clock, lifetime and resource manifest. The
operator key never enters the workload. Before mounting credentials, activation creates a stopped, network-free image
inspection container. It checks the single `/HyperNet` payload against the
installed executable through bounded archive output; it never executes that
container or extracts archive paths. Every workload uses the fixed `/HyperNet`
entrypoint. Activation then uses a bounded, network-free container to initialise
the signer, followed by the fixed confined replica entrypoint.
A completed exact initialisation resumes without recreating state. An incomplete
or changed signer deployment refuses activation and retains its data.

The first voter starts without requiring an existing quorum. A live status reply
reports signer generation, view, committed/applied heights and clock readiness.
`quorum: NotProbed` and `ready: false` mean the runtime has made no fresh authority
query. They do not assert quorum failure. `Running` or process presence alone
is not authority readiness. Use an independently validating Suite authority
operation to establish that a current quorum can answer that operation.

This profile runs the `Authority` role. The separate `runtime services` commands
manage explicitly admitted Page, Media, Mail, Transfer, Route, Bridge and SSH services. See
[ServiceRuntime](ServiceRuntime.md) for their exact consent and activation workflow.
Reader join, mail and Pages are unavailable through the authority runtime profile.

## Stop, restart and withdrawal

```sh
HyperNet runtime stop --directory /Private/AuthorityOne \
  --operation-id <new-32-hex-digits> --expected-generation <generation> \
  --profile-digest <profile-digest>
HyperNet runtime status --directory /Private/AuthorityOne
```

Stop retains the signer journal and consent. It inspects the stopped signer
exclusively and records its latest generation outside the workload. Retain that
generation independently, together with the bootstrap and profile pins. A later
start requires `--minimum-signer-generation` at least as high as the retained
floor. A stale signer journal cannot satisfy a newer floor. Files colocated on
one disk cannot prove that the entire disk was not rolled back; an independently
retained floor is still required.

Graceful supervisor exit stops its owned containers. Abrupt supervisor loss does
not renew consent. The confined replica and its guard enforce expiry and observe
the local withdrawal tombstone independently. The guard checks wall-clock
rollback and a suspend-aware boot-clock deadline. A new supervisor reconciles the
recorded resource identities; it does not automatically restart the voter.

```sh
HyperNet runtime withdraw --directory /Private/AuthorityOne \
  --operation-id <new-32-hex-digits> --expected-generation <observed-generation> \
  --profile-digest <profile-digest>
```

Withdrawal needs no quorum or active supervisor. It durably increases the
independent tombstone before attempting stop. It can use an older observed
lifecycle generation for the exact immutable profile, so a concurrent activation
cannot defeat a restrictive veto. Ordinary mutations require an exact generation.
Withdrawal is terminal for this profile and cannot be undone by restoring only
`State.json`. Signer data is preserved. After stopped-state inspection, withdrawal also removes the exact owned bridge.
Changed or unresolved resource identities remain recorded for explicit recovery.
No unrelated resource is removed.

A retained operation ID cannot name changed input. Repeat the exact original
withdrawal command after interrupted cleanup. The permanent tombstone remains
restrictive even if resource cleanup fails. The bounded retry window retains the
64 most recent receipts and any pending operation. Earlier commands fail their
stale expected generation after compaction; compaction never resets lifecycle
or signer generations. Already stopped or withdrawn deployments cannot allocate
repeated emergency operations.

The lifetime remains finite. Use the reviewed stopped successor workflow below
to renew consent, recover a host boot or change the installed software. It never
recreates a signer to bypass expiry or a restart refusal. Live replacement is
not supported.

Each replica retains at most 32 pending submissions and proposes eligible requests
in their first local admission order. Duplicate submissions retain their original
position. A future request does not block eligible work, and completed, committed
or expired entries leave both the request index and its ordering queue. A durable
proposal for the current view and terminal progress keep their existing priority.
Queue order does not extend any challenge or guarantee completion before expiry.

## Recovery and diagnostics

`diagnose` previews bounded local lifecycle state and fixed failure categories.
An explicit `--output` export requires the exact `--preview-digest` and creates a
new private file. It opens no network connection, runs no container command and
collects no logs. [Diagnostics](Diagnostics.md) documents its fields and freshness
limits. `status` checks exact owned resource identities and
uses the private control socket of the recorded replica; it is not a reader API.
Neither command exports keys or protected authority records. Failed inert
initialisation or stopped-state inspection records bounded private logs under
`Diagnostics/` before its exact temporary container is removed.
Failed authority startup retains `Diagnostics/AuthorityFailure.json` before
cleanup, when the recorded container identity and configuration still verify.
The private record contains running, exit, OOM and PID observations plus up to
32 KiB each of standard output and standard error from the last 64 log lines.
Diagnostic capture failure does not prevent stopping the owned workload. These
private logs are excluded from the redacted diagnostic preview and export.

Replica diagnostics include an `ActivitySummary` at most once every five
seconds of completed work. It reports the view range, elapsed interval, elapsed
time inside driver turns, storage synchronisation time and journal commit counts.
It also reports quorum-certificate signature-check time, check counts and exact
proof reuse counts, complete application-state validation time and reuse counts,
metadata encoding time and maximum encoded size. Expired challenge counts include
the maximum non-negative age at proposal evaluation. These aggregate counters
carry no timestamps or operation identifiers. Ordinary turns below the slow-turn threshold contribute to these totals. Counters contain
no request contents, paths or identities. These timings help distinguish storage
cost from other driver work; they do not establish clock health or quorum status.

Each execution thread retains at most 256 successful quorum-certificate proofs
within a 256 KiB byte allowance. Exact proof bytes can reuse signature arithmetic.
Parsing, scope, voter membership and signer ordering are checked on every use.
This transient cache stores no permission decision and grants no current authority;
view, branch, input, epoch and application checks remain separate.

Each policy application retains one successfully validated immutable state for
its fixed authority configuration. Reuse requires identical complete state bytes;
other bytes receive full validation, and a failed validation cannot replace the
entry. The retained encoding obeys the existing 8 MiB application-state bound.
Execution clones the validated state before mutation. Current permission,
revocation, request, epoch and clock checks run for each operation; this entry
contains no reusable permission result and is empty after restart.

The runtime publishes a completed configuration tree atomically. Pending
preparation can resume, but published state is never deleted or replaced. Every
container action uses its immutable Podman ID and inspected configuration.
Unrelated name collisions, changed mounts, extra network attachments and changed
security settings refuse action. Recovery from a create/record interruption uses
the private exact CID receipt only for conservative cleanup, never adoption or
restart of an altered container.

The maintained installed workflow driver is `Tests/RuntimeWorkflow.py`. Supply
an isolated accepted bootstrap, appointed key, normal configuration and signed
clock; the driver does not fabricate PKI, grants or authority state. Its local
lifecycle results do not replace four-deployment quorum and Internet-path
qualification.

## Publish a local withdrawal

After `runtime withdraw` durably records the local veto, export its operator assertion:

```sh
HyperNet runtime withdrawal-receipt --directory /Private/AuthorityOne
```

The result names `Authorization/WithdrawalReceipt.cbor`. Its exact signature binds
network, incarnation, deployment, operator, permanent operational resource digest
and withdrawal counter. The resource digest preserves identity and rights across
stopped operational successors, including one not yet admitted by the network.
Supply it to the Suite's deployment withdrawal command. This local command does
not contact authority or clear the veto. `cleanupComplete: false` reports remaining
owned resources; retry the original Withdraw operation for cleanup. Publish the
restrictive network withdrawal even when cleanup remains incomplete. The assertion
is signed operator evidence, not independent proof of physical host shutdown.


## Replace an authority committee

`runtime setup --future-epoch N` creates an explicitly non-serving future
installation. It requires four fresh voter and transport identities and an
independently authenticated signed clock. Committed nominations, complete state
installation and both old and new quorums are required before it can start.
Use `runtime epoch terminal`, `handoff`, `prepare` and `activate` as described in
[Authority committee replacement](AuthorityEpochs.md). Every offline operation
requires stopped workloads and preserves the independent signer-generation floor.
Epoch appointments retain their original committed nomination. A stopped operational
successor may renew its finite consent or host boot while preserving every appointed
identity, peer, resource and permission. The replica verifies the original nomination
against its retained appointment and the exact signed successor against its current
profile. This does not appoint a voter or change committee membership.

The authority's private signer source is `Launch/State/Authority`, mounted at
`/State`; its isolated sibling `Launch/State/Control` is mounted at
`/State/Control`. SELinux keeps signer state private and labels only the control
directory for sharing with approved local services. Older prepared layouts refuse
startup and require an explicit offline migration; live state is not moved.

## Stopped consent renewal, reboot and software replacement

Stop the workload and exit its foreground manager, or disable its managed unit.
Inspect the installed profile before preparing a successor. Proposal files are
private owner files outside the repository. Preparation changes no consent:

```sh
HyperNet runtime transition prepare --directory /Private/AuthorityOne \
  --valid-until NEW_ABSOLUTE_UNIX_SECONDS --refresh-host-boot \
  --output /Private/Successor.json
HyperNet runtime transition preview --directory /Private/AuthorityOne \
  --proposal /Private/Successor.json
HyperNet runtime transition apply --directory /Private/AuthorityOne \
  --proposal /Private/Successor.json --preview-digest REVIEWED_SHA256 \
  --operation-id NEW_32_HEX_DIGITS
```

Omit `--valid-until` to retain the existing finite interval. Omit
`--refresh-host-boot` when its binding has not changed. Start the existing pinned
clock monitor first after a host reboot. The successor requires a fresh signed
observation for the actual host boot before it updates an initial or epoch-appointed
replica. Exact predecessor profile and consent hashes, consecutive manifest
generations and the reviewed proposal bind the operation. Identities, rights,
resources, endpoint pins, volumes, placement, journals, content, tombstones and
signer floors remain unchanged. Expired consent can be renewed while stopped;
withdrawn consent cannot.

A durable `Transition.json` blocks normal activation until all local configuration
and retained state agree. After interruption, run the exact proposed executable:

```sh
HyperNet runtime transition recover --directory /Private/AuthorityOne \
  --operation-id SAME_32_HEX_DIGITS
```

Recovery completes that same operation. It never rolls journals or generations
back. If consent expires or the package trust floor advances before completion,
use `transition recover --historical` with the same operation ID. This completes
signed local metadata only and executes no candidate binary or container. It
sets a durable non-serving recovery marker, preserving signer and service journals.
A software transition also requires a fresh package cutover before serving.
Prepare, review and apply a fresh successor next; its trusted code verifies the
retained signed intermediate consent chain before atomically updating the replica.
An expired intermediate never becomes permission to run. Stop and withdrawal remain available during recovery. Withdrawal wins over
a partially applied successor. Receipt export remains available in that state and
binds the permanent resource identity, so it can withdraw the currently admitted
generation even when a local successor has not yet reached the network. Keep the proposal, previous installed prefix, original release public key, signed
target policy and signature, and package trust directory until completion; do not manually replace state files.

For software replacement, first install the signed candidate through the normal
package workflow and retain its accepted update floor. Add these options when
preparing the stopped successor with the currently consented installed executable:

```sh
  --installed-prefix /Private/Packages/Candidate \
  --image sha256:EXACT_INSTALLED_IMAGE_DIGEST \
  --trust-directory /Private/PackageTrust --public-key /Private/ReleasePublic.pem \
  --policy /Private/Target.json --policy-signature /Private/Target.json.sig
```

Run `transition apply` and fresh `recover` using Candidate/Bin/HyperNet. Historical
metadata recovery uses an already trusted executable and never launches candidate
code. The original trusted verifier is pinned in the reviewed proposal; candidate
Python code is not executed. The exact currently retained package target, signature, complete installed
files, binary, image and validity are verified. The existing package trust lock
remains held through local activation, with freshness rechecked before commit.
An older signed prefix cannot bypass the retained update floor. No failed cutover
automatically restores an older journal or package target.

The result remains stopped. The runtime retains each signed operational successor
under `OperationalOffers/GenerationNNNN.cbor`. After initial admission, synchronise
that directory using Suite `authority-inspection deployments synchronise` with the
ordinary location, registrar key, clock and socket flags plus `--grant GRANT` and
`--offers-directory /Private/AuthorityOne/OperationalOffers`. The command obtains
current registrar authority and commits missing generations in order. Expired
unchanged-rights intermediates are historical records only; a fresh final admission
and fresh service activation are still required. Operational successors preserve existing domain definitions
and publication approvals; they do not extend independently shorter domain leases.

## Managed Linux boot and logout

Session mode remains the default. To permit managed boot explicitly, prepare and
apply a stopped successor with `--session-policy managed`, or select that policy
at initial setup. Its finite consent uses `CurrentHost`: every launch verifies a
fresh signed observation from the pinned monitor against the actual kernel boot.
It does not accept a foreign boot or shifted time namespace.

```sh
HyperNet runtime managed preview --directory /Private/AuthorityOne \
  --clock-monitor /Private/Monitor --minimum-signer-generation RETAINED_FLOOR
HyperNet runtime managed enable --directory /Private/AuthorityOne \
  --clock-monitor /Private/Monitor --minimum-signer-generation RETAINED_FLOOR \
  --preview-digest REVIEWED_SHA256 --enable-linger
HyperNet runtime managed status --directory /Private/AuthorityOne
HyperNet runtime managed disable --directory /Private/AuthorityOne
```

Enable installs only the reviewed user units and starts the monitor dependency
before the ordinary runtime. If recording completion fails after startup, enable
attempts to disable and stop its owned runtime unit and reports that cleanup's
outcome with the original audit error. Explicit user lingering permits boot activation and
continuation after logout; the host may require its administrator to enable it.
Finite consent, confinement, exact image, signer floors and normal authority checks
still apply. A failed dependency leaves the runtime stopped with an understandable
systemd result. Inspect readiness separately from unit activation. Disable stops
the unit and removes automatic startup, retaining consent and the user's lingering
setting because other services may depend on it. After a successor, review and
enable its new exact unit; stale unit profiles refuse to run. When other workloads
still use the current monitor unit, `--clock-executable` can retain its already
approved executable while changing the workload independently.
