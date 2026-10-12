# Native Linux qualification

Support depends on measured kernel and runtime capabilities. A compiler pass or
a distribution name is insufficient. The current development platform is native
x86_64 Linux. Native AArch64, macOS and SELinux-enabled operation remain pending.
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
Do not report earlier releases or userspace distribution containers as qualification
of the current authority implementation or a different native kernel.
