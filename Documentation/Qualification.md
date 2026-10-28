# Native Linux qualification

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Support depends on measured kernel and runtime capabilities. A compiler pass or
a distribution name is insufficient. The 0.9.0 candidate uses native Ubuntu 24.04
x86_64 with GNU libc 2.39 and the enforced kernel/runtime controls below. The
published 0.8.0 release retains its separate historical evidence. See the
[release notes](ReleaseNotes.md) for the candidate changes and measured scope.
Native AArch64, macOS and SELinux-enabled operation remain pending.
Windows and arbitrary SSH shells are outside the current installed profile.

The host needs rootless Podman, a maintained OCI runtime, subordinate-only user
mapping, delegated cgroup v2 CPU/memory/PID controllers, seccomp and Landlock ABI6
or newer. Missing enforcement stops activation. Images carry their runtime
libraries; the host kernel and native manager dependencies still matter.

Rootless resource delegation needs a functioning user session and D-Bus socket.
Check those prerequisites before diagnosing a workload limit. Test ordinary
traffic with appropriate headroom; capacity-negative fixtures belong in separate
checks. A test allocation does not define a production limit.

## Platform probe

Select an existing private persistent work directory owned by the operator:

```sh
python3 Tools/Qualify.py --image sha256:ImageDigest \
  --work-directory /Private/QualificationWork --output /Private/Qualification.json
```

The probe creates one finite, network-free container with a read-only root,
no capabilities, bounded scratch and explicit CPU/memory/PID limits. It verifies
filesystem, UDP and ungranted TCP denial while permitting its selected state
access. Its report identifies the image, native architecture, kernel, runtime and
measured restrictions. Owned resources are removed; cleanup failure fails the
probe. This checks confinement, not consensus safety or a complete application.

## Installed workflows

`Tests/RuntimeWorkflow.py` exercises one appointed voter's installed lifecycle
using supplied independently authenticated bootstrap, voter identity, peer
configuration and certificates. Supply `--work-directory` for private persistent
fixture state and `--output` for its report. Consult `--help` for the exact input
set. This single-voter lifecycle check makes no quorum or physical-independence
claim.

Before qualifying a complete deployment, exercise the installed four-replica
network, current client operations, requester/recipient interruption recovery,
service stop/restart, restrictive withdrawal and certified authority replacement.
Check real mailbox delivery, exact Page/media review, explicitly confirmed Forms,
recipient-selected file transfers and the consented OpenSSH command. Federation
requires two independently accepted network identities and the real consented
bridge path. Review source-bound results and preserve failures with their original
candidate identities.

Run `Tools/Check.sh` on the candidate and the applicable native workflows after
integration. Keep tools, build caches, reports and recoverable state on persistent
storage. Temporary scratch is disposable only after its durable result is retained.
The check uses `${XDG_STATE_HOME:-$HOME/.local/state}/HyperNet/Tests` for fixtures.
Set `HYPERNET_TEST_DIRECTORY` to choose another absolute, canonical, private
directory. Its ancestors must prevent replacement by other accounts, and its
length must leave room for Unix socket fixture names. The check validates these
requirements before building; a short directory directly beneath the user's home
can avoid workspace permission and socket path limits.
Do not report earlier releases or userspace distribution containers as qualification
of the current authority implementation or a different native kernel.

## Installation and lifecycle scope

Qualify the binaries and immutable image from a verified signed installation.
An archive signature establishes integrity; installation additionally requires
the current signed target policy and retained update trust described in
[Packages](Packages.md) and [UpgradeRecovery](UpgradeRecovery.md). Bind results
to the exact binary, image and archive digests. A source build or an image that
only contains the same executable does not establish the package installation
workflow.

Session mode is the default. Explicit managed mode adds reviewed Linux user units
and a pinned clock-monitor dependency for boot and logout operation. Consent
renewal, session boot rebinding and software replacement use the stopped successor
workflow in [Runtime](Runtime.md). Automatic consent renewal and live software
replacement remain unsupported. Side-by-side installation alone does not activate
a successor. An interrupted installation must preserve the previous prefix and
the retained update floor; an older executable must not lower authority or
lifecycle floors.

Exercise exact successor retry, certified network synchronisation and interrupted
recovery with retained identities and state. Check managed enable, readiness and
disable separately from physical reboot and logout. Successful unit activation
does not establish those physical lifecycle observations or current quorum.

[Diagnostics](Diagnostics.md) supplies local redacted preview and exact export
for authority and service profiles. Exercise these commands without a network,
including a busy lifecycle lock, invalid input, changed preview and an existing
output destination. Diagnostic output does not establish current quorum or
readiness.

## Capacity and deployment evidence

Use a declared workload, duration and stopping condition. Record first and repeat
Page/search latency separately, including CLI and route setup costs. State the
corpus size, Page/media bytes, concurrency and whether caches were already warm.
Report complete proof or bundle sizes separately from payload size. Interface
counters include framing, control traffic and possibly loopback; they do not
establish physical Internet traffic without a corresponding capture boundary.

Record process or cgroup CPU usage, memory peaks, throttling and OOM events.
The authority's ActivitySummary reports elapsed work and signature-check timing;
it is not a process CPU meter. Distinguish observed memory peaks from configured
limits, and forwarding buffers from TLS, kernel, parsing and queue allocations.
Record logical and allocated disk bytes, naming any excluded journals or staging
areas. Small-corpus metadata amplification is not a large-corpus storage forecast.

Measure the interval from a committed revocation to an authenticated refusal.
A timeout, relay refusal or dropped connection alone does not prove application
revocation. Measure recovery work and remaining availability for the exact faults
injected. Reuse source-bound evidence where the relevant implementation is
unchanged; do not relabel an earlier executable as a current candidate.

One sequential reader and four voters on one machine establish only that tested
profile. Neither a configured connection ceiling nor four local voters proves
throughput, independent failure domains or operator independence. Native platform
and graphics limits remain explicit. The Linux release does not establish independent operator separation or an
independent security assessment. See [release notes](ReleaseNotes.md) for its scope.
