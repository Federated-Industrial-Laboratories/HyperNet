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

Rootless systemd resource delegation also requires an active user D-Bus socket.
On Debian, install `dbus-user-session` before starting the operator's login
session. If it was installed during that session, run
`systemctl --user daemon-reload` and `systemctl --user start dbus.socket`, then
repeat the failed qualification. Do not accept a cgroup fallback with missing
resource bounds.

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

The 0.7.5 private qualification uses authority schema 9 and `HyperNetPage/2`.
The following measured profiles passed signed Core/Suite installation, Core
confinement and authenticated Pages operation. All use native x86_64 execution
and the crun OCI runtime.

| Distribution | Execution environment | Native kernel | Podman | Landlock ABI |
| --- | --- | --- | --- | --- |
| Ubuntu 24.04.4 LTS | Physical host | 7.0.0-34-generic | 4.9.3 | 8 |
| Debian 13.7 | KVM guest with its own kernel | 6.12.111+deb13-amd64 | 5.4.2 | 6 |
| Fedora 44 Cloud Edition | KVM guest with its own kernel, SELinux enforcing | 6.19.10-300.fc44.x86_64 | 5.8.1 | 7 |

The Debian and Fedora guests share one physical x86_64 host. They establish
native guest-kernel behaviour, not independent physical hardware coverage.
Each profile passed quarantine, manual approval, consented replica reads,
revocation and stop/restart checks. Ubuntu additionally passed current-schema
crash recovery, monotonic rollback-floor checks and refusal of a stale
full-quorum snapshot. A verified current-build replacement preserved approved
content and revoked membership; crash recovery also retained quarantined drafts.
Older schemas remain unsupported; these checks do not establish an upgrade path
from a prior schema.

Distribution names alone do not qualify another host. Native AArch64 remains
pending. Core qualification does not establish Suite graphics support or native
Windows/macOS support. A public release requires its own complete platform and
security assessment.


## Installed client workflows

`Tests/BrowserWorkflow.py` runs an independently installed HyperNetSuite against
a disposable three-voter authority. It checks the 32-entry catalogue boundary,
namespace and quarantine exclusions, explicit addresses, retained view state,
changed-publication refresh, bounded input, navigation errors and cancellation
during quorum loss. Its command arguments match `Tests/PagesWorkflow.py`: supply
the trusted installed client, node executable, image ID, etcd directory, seccomp
file and a private output-report path.

`Tests/FederationWorkflow.py` checks native-to-foreign browser navigation through
explicitly accepted treaties, exact identity matching, refresh and shared Back
history. Both workflows use synthetic content and remove their own resources.
The browser remains a Suite feature; these tests add no frontend dependency to
the daemon or authority protocol.

`Tests/FormsWorkflow.py` uses the same arguments and an installed Suite package
with its `Tools/FormsConsumer.py`. It adds two confined mail stores and separate
Pages and mail credentials. It checks approved form publication, verified
contacts, independent receiver acceptance, typed browser input, separate send
confirmation, cancellation, partial delivery, restart, immutable retry and
duplicate intake. The browser check uses a pseudoterminal and restores its
attributes. Its fixtures are synthetic and are removed on exit.

`Tests/MediaWorkflow.py` checks installed isolated PNG/SVG import, quarantine,
resumable immutable chunks, store restart, required copies, moderator attestation,
application disclosure scope, explicit reads and withdrawal. It uses two dedicated
confined media hosts. The viewer has its own native terminal qualification.

`Tests/MediaFederationWorkflow.py` checks exact media bytes across two independent
networks and a consented bridge, destination placement and review, and source
withdrawal. Supply `--media-address` for an existing private host-interface IPv4
address reachable from both test egress networks. The fixture binds only that
address on TCP ports 30553 and 30554; it makes no interface or firewall changes.
Every store and relay is confined, and all fixture resources are removed on exit.
