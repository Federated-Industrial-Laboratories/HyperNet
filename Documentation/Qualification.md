# Native Linux qualification

Runtime support is conditional on measured capabilities, not a distribution name
or a successful compiler invocation. The initial architecture is native x86-64.
AArch64 remains a candidate until native hardware completes the same checks.
Windows, macOS, graphics adapters and arbitrary SSH shells are not claimed.

The host must provide rootless Podman, a maintained OCI runtime, subordinate-only
`nomap` UID/GID mappings, delegated cgroup v2 CPU/memory/PID controllers, seccomp
and Landlock ABI 6 or later. There is no unconfined fallback. Initial launchers
use GNU userland tools and IPv4 /24 private Podman networks. Images carry their
own dynamic runtime libraries; the native kernel still defines confinement.

Run `Tools/Qualify.py --image sha256:Digest --output Report.json` as the dedicated
rootless operator. It writes a new private structured report naming the image,
native architecture, kernel, Podman/runtime, controller availability and measured
restrictions. It creates one owned container, with no network and no host state
mount, a read-only root, no capabilities, finite resources and bounded tmpfs.
The installed daemon must demonstrate filesystem, UDP and ungranted TCP denial
while retaining its explicitly permitted state access. Owned resources are removed
on completion; failure and cleanup failure are reported as failures.

The measured profile is 256 MiB memory, 32 PIDs, one CPU and 8 MiB of temporary
state. Missing requirements or failed enforcement stop qualification. This probe
is a necessary platform check, not a protocol security audit or a complete network
deployment test. Real installation, authenticated operation, stop/restart,
current-contract replacement and recovery must also pass before a platform is advertised.

Dedicated configuration and state mounts use private SELinux relabelling (`:Z`)
on supporting runtimes. Keep SELinux enforcing during qualification. Each mount
must be a dedicated profile resource; never supply a home directory or unrelated
shared directory. No automatic host policy or kernel changes are made.

An Internet release additionally needs a security assessment of the deployed
protocol composition, key lifecycle and confinement, with the published supported
profile matrix. Private qualification packages and earlier Internet-path checks
are not a public release or universal Linux support claim.

## Qualification records

Each qualification report must identify the exact runtime, image and native host.
Evidence for an earlier executable does not qualify a rewritten contract. Record
signed installation, authenticated Pages operation, current-schema restart and
recovery, confinement and withdrawal for each advertised platform.

The current target families are Ubuntu, Debian and Fedora on native x86_64 with
the required kernel and rootless runtime capabilities. Native AArch64 remains
pending. Core qualification does not establish Suite graphics support or native
Windows/macOS support. A public release additionally requires its own complete
platform and security assessment.
