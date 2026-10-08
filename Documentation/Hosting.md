# Confined hosting

A host has no authority-voter credentials and no administrative vote. It holds a
device identity, a client transport certificate and a signed local consent
document. Hosting requires both local consent and a current authority lease.
Network administration cannot enlarge the signed local permissions or resources.

The current host maintains membership and hosting readiness. It does not yet
store pages, mail or transferred files. Its writable state is bounded tmpfs and
is recreated on restart. Authority storage has a separate durable deployment;
see [Authority.md](Authority.md).

## Required Linux profile

The launcher requires rootless Podman, a maintained OCI runtime, subordinate UID
and GID ranges, delegated cgroup v2 CPU/memory/PID controllers, and Landlock ABI 6
or newer. It refuses a missing restriction. There is no unconfined fallback.
The launcher requires Podman's subordinate-only `nomap` namespace mapping.

The workload uses a subordinate-only user namespace (`nomap`). Container UID zero
maps to a subordinate host ID, not the login account or host root. All capability
sets are empty; no-new-privileges and seccomp are mandatory. The image is read-only.
Only dedicated configuration files are mounted, read-only, at `/Config`.
`/State` is a size-limited, non-executable tmpfs. Home directories, agent sockets,
display sockets, the container runtime socket, GPUs and host devices are not
mounted. Standard streams are the only inherited descriptors. Core dumping is
disabled before private keys are loaded, including dumping through a piped host
crash collector. The launcher also sets the core-file size limit to zero.

Landlock denies filesystem access outside the explicit state and read grants,
limits TCP bind/connect ports and restricts cross-domain signalling and abstract
Unix sockets. It is installed on the initial thread before the async runtime;
descendant threads inherit it. Startup checks the actual UID mapping, capability
sets, seccomp mode, cgroup limits and read-only root. A known readable image file
must become unreadable with `EACCES`, UDP socket creation must fail, an ungranted
TCP bind must fail, and state read/write must succeed.

Landlock TCP rules restrict ports, not destination addresses. The host therefore
joins an internal network with no default route. A separate relay joins that
network and an explicitly selected egress network. It accepts traffic only from
the host's internal address and forwards only to the literal endpoint in the
signed consent. TLS terminates at the authority; the relay has no identity keys,
CA signing key or decryption key. The host pins the network CA and verifies the
original authority DNS name. The relay listens on the same port as that endpoint.
UDP, raw IP and packet sockets are denied by an extension of Podman's maintained
seccomp profile.

The relay is part of the network isolation boundary. Its implementation and
container runtime remain trusted to enforce the fixed destination. Compromise
of the relay can disrupt traffic; its egress network is not a per-address kernel
firewall. Containers and Landlock share the host kernel and do not claim virtual
machine isolation.

## Signed local consent

The document has exactly two fields, `payload` and `signature`. `payload` contains
unpadded base64url UTF-8 JSON. An Ed25519 signature covers the ASCII bytes
`HyperNet/Consent/1`, a zero byte, then those exact decoded payload bytes. The
profile identifier is SHA-256 of the complete document file, including any
trailing newline. Do not reformat a document after registering its profile.

The payload fields are:

| Field | Meaning |
| --- | --- |
| `version` | Integer 1 |
| `network`, `deviceKey` | Lowercase hexadecimal network and signing-key identities |
| `grants` | Integer 2, hosting only |
| `expires` | Unix seconds, within seven days of signing/activation |
| `memoryBytes` | 64 MiB through 8 GiB |
| `pids` | 16 through 512 |
| `cpuQuota`, `cpuPeriod` | 1000 through 800000 microseconds per period of 100000 |
| `stateBytes` | 1 MiB through 256 MiB of tmpfs |
| `authorityEndpoint` | HTTPS DNS endpoint at the root path, without user information, query or fragment |
| `authorityAddress` | Literal IP address and port for the fixed relay destination |

The endpoint URL port and destination port must agree. IPv6 literal destinations
use `[address]:port`. The isolated host-to-relay network currently uses IPv4.
Host resource limits are checked against the signature after their effective
cgroup values are read. The writable filesystem must be tmpfs with a capacity
no greater than `stateBytes`.

Consent version 1 also selects a separate fixed relay allowance: 128 MiB memory,
32 PIDs, half a CPU, 8 MiB tmpfs, 16 simultaneous connections and an aggregate
1 MiB/s byte rate in both directions, with an initial 8 KiB scheduling quantum.
Each direction of a connection is limited to 16 MiB. Idle reads expire after ten
seconds and blocked writes after five seconds. These are application rate bounds;
the container's cgroups independently limit CPU, memory and PIDs. Container logs
are capped at 1 MiB per container. Container image storage and the operator's
configuration files are installation overhead, outside the runtime tmpfs quota.

Use the independent HyperNetSuite `host-consent` command to sign the document,
then register its exact profile and client leaf-certificate digest using the
authority `Consent` command. Membership needs the hosting grant before consent
can be registered. Consent does not create membership or an administrative role.

## Build and package

Build requires Rust, a GNAT Ada compiler and the ordinary C linker tools. Set
`GNAT_GCC` if GNAT's `gcc` is not the compiler on `PATH`. Verify the pure policy
contracts with GNATprove using `Tools/PolicyCheck.sh`; `GNATPROVE` can select its
executable. Runtime code keeps Ada language checks enabled. Proved postconditions
do not enable Ada assertion exceptions across the C ABI. The boundary contains
only fixed-width scalar values and has no callbacks, pointers or mutable state.

```sh
cargo build --locked --release
bash Tools/Check.sh
bash Tools/PolicyCheck.sh /tmp/HyperNetPolicyProof
bash Tools/Package.sh target/release /tmp/HyperNetPackage
```

`Package.sh` copies the trusted binaries and their dynamic libraries into a
scratch OCI image. It does not download a base image. It writes `ImageId.txt` and
the derived `Seccomp.json` beside the container build input. The output directory
must not already exist. Run this tool only on trusted build outputs: dependency
inspection uses the platform's `ldd`. Local image IDs pin the exact installed
image; signed distribution packages are a separate release capability. This
packager currently reads Debian/Ubuntu library ownership records and includes
their notices, versions and source-package inventory. Read
[LibraryLicences.md](../Packaging/LibraryLicences.md) before distributing an image.

## Initialise and operate

Prepare a private configuration directory containing these regular files:

| File | Content |
| --- | --- |
| `Host.json` | Configuration shown below |
| `Consent.json` | Exact signed consent document |
| `Identity.json` | Suite device identity, `secretKey` and `publicKey` |
| `Ca.pem` | Authority network CA certificate |
| `Client.pem`, `ClientKey.pem` | Hosting client certificate and private key |

```json
{
  "network": "ReplaceWithNetworkIdentity",
  "endpoint": "https://authority.example:8443/",
  "caCertificate": "/Config/Ca.pem",
  "identity": "/Config/Identity.json",
  "clientCertificate": "/Config/Client.pem",
  "clientKey": "/Config/ClientKey.pem",
  "consentFile": "/Config/Consent.json",
  "stateDirectory": "/State",
  "relayAddress": "192.0.2.1:8443"
}
```

`Initialise` replaces `relayAddress` with the newly allocated internal relay
address and uses the fixed file paths above. It copies only the six named files.
The original configuration directory stays under the operator's control.
The staged copies become private to the subordinate container ID.

```sh
bash Tools/Host.sh Initialise /Private/HostProfile /Private/HostConfig \
  "$(cat /tmp/HyperNetPackage/ImageId.txt)" podman
bash Tools/Host.sh Start /Private/HostProfile
bash Tools/Host.sh Status /Private/HostProfile
bash Tools/Host.sh Stop /Private/HostProfile
bash Tools/Host.sh Restart /Private/HostProfile
bash Tools/Host.sh Withdraw /Private/HostProfile
```

The last `Initialise` argument names an existing egress network. Select a network
that can reach the consented authority address. Each host receives its own
internal network; other workloads should not be attached to that network.
`Start` launching a process is not a readiness acknowledgement. `Status` displays
the container state and its latest lease status. Hosting is active only while
the process runs, `active` is true and `leaseExpires` is still in the future.

A host requests a fresh heartbeat every second, with a two-second request
deadline. Authority denial, quorum loss, malformed replies or transport errors
clear readiness. A lease lasts at most five seconds. Epoch rollback is rejected
within the running process. Backwards wall-clock movement stops the host.
Every later service operation must obtain fresh authority; the status file is
not a reusable service capability.

`Withdraw` writes a local tombstone, kills both host and relay, and removes their
containers. This path does not need network access, a functioning authority or a
quorum. A withdrawn profile cannot restart. Create a new profile with fresh
consent to resume hosting. The separate authority `Withdraw` command records the
withdrawal remotely; perform local withdrawal first when the host must stop
immediately. Stopping and restarting a non-withdrawn profile retains its signed
consent and identity but reacquires all runtime readiness from the authority.

Commands for the same profile use one persistent lifecycle lock. Withdrawal
waits for an in-progress startup or restart, then removes both containers before
it succeeds. Every queued or later startup checks the tombstone while holding
that same lock and refuses to restart a withdrawn profile. Initialisation and
failed-initialisation cleanup use the lock too. The lock remains in the private
directory formed by appending `Lifecycle` to the profile path.

To remove a stopped profile, remove its named internal network and private
profile directory. Container-owned staged files may require `podman unshare`
for removal. Remove the adjacent `Lifecycle` directory only after all commands
for that profile have exited; deleting an in-use lock could allow overlapping
operations. Never remove the operator's source identity or unrelated Podman
images, networks or containers as part of host removal.

## Installed integration check

`Tools/Check.sh` runs formatting, strict Clippy diagnostics, locked Rust tests,
shell syntax checks and the deterministic launcher concurrency regression.
`HYPERNET_JOBS` selects a bounded parallel build count;
the default is four. `Tools/PolicyCheck.sh` separately proves the policy contracts.

The installed workflow uses an independently built Suite, the packaged node,
etcd 3.6.15 tools, rootless Podman, OpenSSL and Python with `cryptography`:

```sh
python3 Tests/TrustWorkflow.py \
  --suite /Installed/HyperNetSuite \
  --node /Installed/HyperNet \
  --image "$(cat /tmp/HyperNetPackage/ImageId.txt)" \
  --etcd-directory /Installed/Etcd \
  --seccomp /tmp/HyperNetPackage/Seccomp.json \
  --output /tmp/HyperNetWorkflow.json
```

The test needs a free local TCP port 28443 and the unused container subnet
`10.89.72.0/24`. It creates three mutually authenticated voters, a broker and
independent device identities; exercises admission, denial, consent, withdrawal,
restart, quorum loss and stale restoration; and removes its private fixtures.
Its report contains result names and binary digests, not private credentials.
This single-host test does not demonstrate independent physical failure domains
or qualification of a public Internet deployment.

Add `--lifecycle-only` to exercise concurrent restart and withdrawal against real
containers, plus authority restart and stop, without repeating unrelated API
and recovery scenarios. The test pauses relay creation at a controlled barrier,
queues local withdrawal, then verifies that no host or relay survives completion.
