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
compatible upgrade and recovery must also pass before a platform is advertised.

Dedicated configuration and state mounts use private SELinux relabelling (`:Z`)
on supporting runtimes. Keep SELinux enforcing during qualification. Each mount
must be a dedicated profile resource; never supply a home directory or unrelated
shared directory. No automatic host policy or kernel changes are made.

An Internet release additionally needs a security assessment of the deployed
protocol composition, key lifecycle and confinement, with the published supported
profile matrix. Private qualification packages and earlier Internet-path checks
are not a public release or universal Linux support claim.

## Measured native profiles

Version 0.7.0 has the following native x86_64 evidence. Each row passed signed
installation and the actual confinement probe. Authenticated Pages coverage
includes three TLS authority voters, invitation redemption, quarantine and manual
approval, consented replication, replica restart and revocation after authority
restart. The Ubuntu 24.04 run also exercised a real 0.6.0 to 0.7.0 upgrade and
compatible rollback while retaining approved content, revoked membership,
consent, resource policy and monotonic authority floors.

| Distribution | Native kernel | Podman | Landlock ABI | Additional enforcement |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04 x86_64 | 7.0.0-34-generic | 4.9.3 | 8 | seccomp and cgroup v2 |
| Ubuntu 26.04 x86_64 | 7.0.0-38-generic | 5.7.0 | 8 | seccomp and cgroup v2 |
| Debian 13 x86_64 | 6.12.111+deb13-amd64 | 5.4.2 | 6 | seccomp and cgroup v2 |
| Fedora 44 x86_64 | 6.19.10-300.fc44.x86_64 | 5.8.1 | 7 | SELinux enforcing, seccomp and cgroup v2 |

These results describe the listed kernels and configured prerequisites. They do
not qualify a distribution's older default kernel or every service on each
platform. Rootless networking also requires the selected runtime's maintained
network helper, such as pasta or slirp4netns, and its DNS helper when enabled.
Install those distribution packages before operating networked profiles. Missing
network prerequisites do not justify host networking or weaker confinement.

The adjacent client has its own independent native package matrix. Full mail,
transfer, SSH, federation and adapter workflows retain their separately recorded
qualification scope; the table above does not expand that scope. General Core
bundles exclude custom SSH command overlays. Native AArch64, other distribution
families, Windows and macOS remain unqualified. No public release, production
Internet deployment, power-loss recovery guarantee or external security
certification follows from this private qualification.
