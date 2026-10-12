# Installed authority runtime

`HyperNet runtime` manages one already appointed authority voter per deployment.
Four deployments use the same accepted bootstrap and distinct appointed voter
keys. Their Basic HotStuff committee requires three replicas for authority
results. The runtime does not create membership, appoint voters, issue transport
certificates or expose a reader endpoint.

The supported installed profile is Linux, rootless Podman, delegated cgroup v2,
Landlock ABI6 or later and seccomp. It uses explicit IPv4 addresses and one owned
NAT bridge per deployment. IPv6 installation and SELinux-enabled operation require
platform qualification. Mandatory confinement failures stop activation.

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

The default resource allocation is512MiB RAM,64PIDs and one CPU period of100000
microseconds with a matching quota. CPU quota is configurable. These are workload
allocations, separate from authority policy limits. Size production resources for
the expected traffic and measured durable-storage latency. Four colocated voters
share storage and scheduling risks; four processes do not establish operational
independence.

`stateBytes` is an available-space admission requirement, not a filesystem quota.
Its default1GiB leaves headroom above the engine's bounded object, result,
maintenance, metadata and archive profile; the minimum is1GiB. This includes
225MiB journal allocation and an atomic replacement,256MiB pending objects,
128MiB maintenance and metadata/archive headroom. The engine
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
manage explicitly admitted Page, Media, Mail, Transfer and SSH services. See
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

A new operation cannot reuse an ID with changed input. Repeat the exact original
withdrawal command after interrupted or failed cleanup. It resumes exact resource
cleanup using the same receipt and permanent tombstone, even when receipt capacity
is exhausted. A completed withdrawal returns its retained success. Other failed
or interrupted operations preserve their failure disposition. There are120 ordinary mutation
receipts and two reserved terminal stop/withdraw slots. They fit the bounded
local journal without discarding operation-ID bindings. An already stopped or
withdrawn deployment cannot consume fresh emergency receipts indefinitely.

The lifetime is finite. Consent renewal, live update, unattended boot and
installed host-reboot reconsent are not supported. A changed signed-clock boot
binding therefore requires explicit operator recovery; it never causes the
runtime to recreate the signer. Preserve the existing journal and its independent
floor when arranging new consent. Do not initialise the same voter key into a
fresh journal to bypass expiry or a restart refusal.

## Recovery and diagnostics

`diagnose` reports only local lifecycle state and fixed failure categories. It
opens no network connection. `status` checks exact owned resource identities and
uses the private control socket of the recorded replica; it is not a reader API.
Neither command exports keys or protected authority records. Failed inert
initialisation or stopped-state inspection records bounded private logs under
`Diagnostics/` before its exact temporary container is removed.
Failed authority startup retains `Diagnostics/AuthorityFailure.json` before
cleanup, when the recorded container identity and configuration still verify.
The private record contains running, exit, OOM and PID observations plus up to
32 KiB each of standard output and standard error from the last 64 log lines.
Diagnostic capture failure does not prevent stopping the owned workload.

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
network, incarnation, deployment, operator,117profile digest and withdrawal counter.
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
Epoch-appointed consent is immutable; clock-boot changes require a fresh committed
replacement rather than rewriting117/129 or bypassing the local approval.

The authority's private signer source is `Launch/State/Authority`, mounted at
`/State`; its isolated sibling `Launch/State/Control` is mounted at
`/State/Control`. SELinux keeps signer state private and labels only the control
directory for sharing with approved local services. Older prepared layouts refuse
startup and require an explicit offline migration; live state is not moved.
