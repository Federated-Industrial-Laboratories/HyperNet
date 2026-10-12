# Consenting Linux hosts

Use a dedicated rootless operator account with subordinate UID/GID mappings,
rootless Podman, delegated cgroup v2 CPU/memory/PID controllers, seccomp and
Landlock ABI6 or newer. The installed profile uses explicit IPv4 addresses.
Unsupported confinement stops activation. It does not start an unconfined daemon.

Authority deployment is documented in [Runtime](Runtime.md). Page, Media, Mail,
Transfer, Bridge and SSH roles use [ServiceRuntime](ServiceRuntime.md) and their
role-specific manuals. A hardware operator separately approves exact software,
image, local paths, resources, endpoints, storage and finite lifetime. Membership
and a hosting grant cannot substitute for that local consent.

## Isolation and storage

Workloads have private process and IPC namespaces, no capabilities, no-new-privileges
and a read-only pinned image. Only exact role-specific state, clock observations,
configuration and private control paths are mounted. Operator and administrator
private keys do not enter the workload. A Page cannot add mounts, routes or host
commands. SSH uses a separately consented fixed command and maintained OpenSSH.

Store identity keys, journals, immutable objects, consent records and receipt
floors in private persistent directories. Volatile scratch is limited to work
that can be reconstructed from retained state. The bounded `/Work` tmpfs contains
scratch only; it is not the durable state volume. A machine restart cannot safely
recreate a missing signer journal. Follow explicit recovery and reconsent when
clock boot bindings change.

Resource limits are selected by the operator and checked against the admitted
manifest. Size ordinary workloads with measured traffic and storage latency in
mind. State admission checks available space and each engine enforces its own
bounds; this is not a whole-host filesystem quota. Containers share the host
kernel and do not provide the isolation of separate physical machines.

Role1 hosts may reserve a separate [durable content partition](DurableContent.md).
Its placement and physical reservation rules apply in addition to runtime limits.

## Local control

Preview the complete profile before consenting. Start the foreground supervisor
explicitly, inspect its status and complete an authenticated operation to verify
readiness. Process presence alone is not current permission or quorum readiness.
Stop retains private state. Withdrawal persists a local veto before cleanup and
works without a quorum. Changed resource identities remain for explicit diagnosis;
unrelated containers, networks and images are never removed.

## Build and qualification

Build with Rust, a GNAT Ada compiler and standard C linker tools. `GNAT_GCC` selects
the compiler and `GNATPROVE` selects the prover. The pure Ada media-range boundary
has scalar inputs and no allocation, callbacks or mutable state. Runtime builds
retain Ada language checks without assertion exceptions crossing the C ABI.

Run `Tools/Check.sh` for source checks and maintained regressions. Use
`Tools/PolicyCheck.sh /Private/PolicyProof` for the SPARK contract. Package using
`Tools/Package.sh` and verify the signed result as described in [Packages](Packages.md).
[Qualification](Qualification.md) explains the native platform checks and their
limits. Native AArch64, macOS and SELinux-enabled operation remain pending.
