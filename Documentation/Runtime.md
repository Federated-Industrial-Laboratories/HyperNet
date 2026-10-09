# Native runtime management

The installed `Bin/HyperNet runtime` command prepares and supervises a dedicated
rootless Linux deployment. Core operates independently of HyperNetSuite. Setup
generates private configuration, identities and transport certificates through
the maintained OpenSSL executable. It starts no container or network listener.

The available serving profile uses three trusted etcd voters, one authority
broker, one consenting nonvoting Pages host and its fixed-destination gate. This
is crash-fault infrastructure. It does not provide Byzantine authority, private
reader relays, sealed Pages or the replacement authority protocol. A prepared
offline 0.8.0 client trust profile does not authenticate this serving profile.

## Prepare and inspect

Install and verify the signed package as described in [Packages](Packages.md).
Use a private parent directory and independently verified etcd and etcdctl
executables. The manager pins their complete file digests. Group-writable
executables are refused. Current dependencies are `/usr/bin/podman`,
`/usr/bin/openssl`, delegated cgroup v2, subordinate UID/GID mappings, seccomp,
Landlock ABI 6 or later and the native Linux ABI recorded in the package.

Choose the authority's explicit IPv4 ingress address and port. The example uses
a loopback test address; remote access requires its intended address and
firewall. This generator colocates all three voters; it does not configure
independent physical failure domains. The three voter management
ports always bind loopback. Two adjacent private /24 container networks must be
free. All workload resources carry a random deployment identity.

```sh
Bin/HyperNet runtime setup --directory /Private/Network \
  --image sha256:VerifiedImageDigest \
  --etcd /Private/Dependencies/etcd \
  --etcdctl /Private/Dependencies/etcdctl \
  --bind 127.0.0.1 --port 32543 --voter-port-base 32551 \
  --subnet 10.89.132.0 --lifetime-seconds 3600 --session-policy Session
Bin/HyperNet runtime preview --directory /Private/Network
```

The runtime path must be absolute, privately owned, short enough for its Unix
socket and free of symbolic components and control characters. Setup refuses an
existing destination. Its output supplies the profile digest and local generation.
Preview reports roles, endpoints, resource deltas, expiry, backend guarantees and
unmet prerequisites. No inherited proxy configuration or arbitrary command is
accepted. An initialisation failure leaves a non-serving directory for inspection;
it does not overwrite an existing deployment.

The authority, host and operator use separate signing identities. CA and root
administration keys remain outside every workload mount. Workload configuration
and persistent state use dedicated subordinate identities. The native manager
never receives a mailbox or confidential-page decryption key. Setup records
whether the kernel has SELinux enabled. Activation requires the same kernel and
Podman mode; private relabelling is requested only in that mode. Mount paths,
permissions, options and confinement labels remain part of exact inspection.

## Consent and activate a session

Each mutation requires a fresh 16-byte hexadecimal operation ID, the expected
local generation and the exact previewed profile digest. The ID is not a secret.
Use the generation returned by the previous successful operation or Status.
Repeat exactly the same request to resolve an uncertain result; changing a
recorded ID's input is refused. Accepted IDs and request digests are persisted
before effects. A crash leaves an explicit `InterruptedOperation` receipt;
retrying it returns that failure and does not repeat the uncertain action. Stop
can reconcile its owned resources before a fresh operation ID is used.
Each profile admits at most 120 ordinary mutation
receipts, then reserves one final Stop and one terminal Withdraw receipt. Fresh
Stop requests for an already stopped deployment and fresh Withdraw requests for
an already withdrawn profile are refused without another state write. Exact
recorded retries remain available; receipts are never evicted to reuse IDs.

Withdrawal is a restrictive local veto on this immutable profile. It accepts an
earlier positive generation for the same exact profile, so queued withdrawal
still stops a concurrently completed activation. Future generations and changed
profiles are refused. Other mutations require the exact current generation.

```sh
Bin/HyperNet runtime consent --directory /Private/Network \
  --operation-id 00000000000000000000000000000001 \
  --expected-generation 1 --profile-digest ProfileDigest
Bin/HyperNet runtime serve --directory /Private/Network
```

`serve` stays in the foreground. Leave it attached to the selected terminal
session. From another terminal, start the exact consented deployment:

```sh
Bin/HyperNet runtime start --directory /Private/Network \
  --operation-id 00000000000000000000000000000002 \
  --expected-generation 2 --profile-digest ProfileDigest
Bin/HyperNet runtime status --directory /Private/Network
```

Start requires the running local supervisor. Its socket is owner-only and checks
the kernel-reported peer UID. The manager has a finite typed API; requests cannot
select executable commands, filesystem destinations or arbitrary network URLs.
The socket uses a four-byte big-endian length followed by a bounded JSON request.
Request fields are `operation`, `operationId`, `expectedGeneration` and
`profileDigest`. Read-only requests use null mutation fields. Responses contain
`ok` and either `result` or `error`. Unknown fields and operations are refused.

The canonical HostConsent signature binds the exact DesiredProfile digest.
The local endpoint identifier commits the complete generated configuration,
including registered paths, executable hashes and resource settings. The runtime
journal is a separate private transactional representation; it is not a certified
authority LifecycleState or a Byzantine evidence object.

Workload preparation publishes its configuration tree only after every file and
ownership change is durable. Interrupted preparation resumes without deleting
retained voter data. Container inspection checks the exact registered network
identities, attachments and addresses. An added or changed route prevents
readiness and automatic lifecycle changes to that container. Restore its
consented topology before normal Stop reconciliation can proceed.

Bootstrap records bounded stages and reconciles the exact intended etcd users,
roles and permissions after interruption. Once authentication is enabled, missing
or changed rights cause refusal; the runtime does not restore revoked grants.
A committed initial authority namespace can resume only when its exact initial
bytes, revision history and retained cluster floor match. A retained invitation
secret makes initial host enrolment repeatable, while changed membership or
withdrawn consent causes refusal. These recovery checks preserve voter data.

Start persists its intended generation before creating resources. It checks
consent, generated-file integrity, software digests, rootless isolation and
fresh authority/host observations. Status distinguishes readiness from process
existence and reports the trusted backend explicitly. It checks local clock
rollback; distributed clock-uncertainty qualification is unavailable.

Every container has a consent-bounded Podman timeout. Authority and voter
processes also run behind a native deadline guard which checks absolute time,
clock rollback and the suspend-aware boot clock every 100 ms. Host and gate
processes enforce their signed consent deadline. These checks remain active
after the manager dies. Graceful SIGHUP, SIGINT or SIGTERM to the foreground
supervisor stops its owned workloads. Abrupt supervisor loss can leave workloads
active until their consent deadline; another local command can inspect and stop
them. There is no implicit boot enablement,
lingering session, automatic renewal or unattended service promise. A replacement
supervisor does not automatically reactivate retained state.

## Stop, withdraw and diagnose

Use the same mutation arguments with `stop` to preserve consent and durable
state. Start can reactivate this exact profile before expiry. Use `withdraw` to
persist a withdrawal counter before stopping work. Withdrawal does not depend on
network quorum. This profile cannot be reactivated; create a fresh profile and
give fresh consent. Old consent never clears its tombstone.

Separate generation and withdrawal floors detect replacement of the lifecycle
journal with an older copy. Restoring every local file, including the floors, cannot be detected
without an independently retained anchor. Copying runtime directories is not a
supported restoration procedure. A failed or interrupted activation remains
non-serving until exact resource reconciliation succeeds. Container names or
labels alone do not authorise taking over or deleting an unrelated resource.
A private immutable container-ID receipt can reconcile interrupted creation for
cleanup only. Start never starts that recovered resource: it requires successful
cleanup and creates new containers from the exact consented arguments.

```sh
Bin/HyperNet runtime diagnose --directory /Private/Network
```

Diagnose reports bounded local state and finite failure codes. It makes no
network probe and does not include private keys, bodies, invitation material or
raw logs. Redirecting this output is an explicit local export. Status can make
an authenticated authority health request; Diagnose remains local.

Voter databases have a 64 MiB backend quota each, bounded retained WAL/snapshot
counts and dedicated directories. This is not a filesystem project quota or a
complete disk-exhaustion guarantee. Activation checks at least 512 MiB of available space and setup reserves 1 MiB
for failure reporting. Reserve additional space for WALs, snapshots, logs and
recovery before activation. Pages on the current nonvoting host remain
a volatile bounded cache. Durable publication placement requires a different
storage contract. Mail, media, transfer, relay, bridge and SSH role setup,
renewal, software replacement and restoration are explicitly unavailable through
this management interface.

The maintained installed test driver is `Tests/RuntimeWorkflow.py`. Its
`--selection Lifecycle` checks the session, consent, withdrawal and expiry
workflow. `--selection Recovery` checks interrupted preparation, authentication,
initial authority creation and enrolment, plus changed network attachments.
`--selection All` runs both. Recovery uses only native setup for identities and
configuration; its explicit local journal fault injections model lost completion
writes without changing authority data or grants.
