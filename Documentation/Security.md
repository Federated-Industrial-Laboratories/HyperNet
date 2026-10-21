# Security

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

## Report a vulnerability

Report suspected security defects privately to contact@federatedindustrial.com.
Do not post credentials, private content or exploit details in a public issue.
Include the runtime version, package and image digests, affected feature, native
platform and a minimal synthetic reproduction when available. Review diagnostic
exports before sharing them; private runtime logs can contain sensitive data.

HyperNet 0.8.0 is a Linux release with no independent security certification. Maintainers may request additional private evidence and
coordinate a fix. Signatures, passing tests and approval policy do not establish
that software has no security defects.

## Trust boundaries

- Authenticate the complete network bootstrap and publisher keys through an
  independent channel. A key supplied beside an archive cannot establish its
  own trust. Keep package trust separate from network membership.
- Membership, administration, voting, review, hosting and confidential access
  require separate capabilities. A network administrator cannot expand local
  host consent or replace a recipient's private keys.
- Hosts use rootless confinement with exact mounts, network rules and resource
  controls. They still share the host kernel. The operator account and operating
  system remain trusted; containers are not independent physical machines.
- Authority requires the actual consensus protocol and durable state. Three
  signatures without verified history are insufficient. Four colocated replicas
  share failure risks.
- Ordinary approved hosts can read the content they serve. Sealed Pages protect
  content separately for authorised readers. Revocation protects later access;
  it cannot erase plaintext already retained by an authorised party.
- Independent reader privacy depends on separately operated, noncolluding relay
  and destination services. An organisation controlling both can correlate
  activity. A route must not silently weaken the reader's selected policy.
- HyperPages contain no scripts. Forms require explicit submission; media is
  bounded and reviewed. A Page cannot grant a host command, local path or network
  permission merely by containing a link or component.

## Operate and recover safely

Keep keys, profiles, journals, receipt floors and encrypted backups on private
persistent storage outside the installation. A private Git repository is not a
secret store. Do not delete or recreate a journal to bypass a stale-state refusal.
A whole-disk rollback cannot be detected by a floor on that same disk; retain the
independent references required by the recovery procedure.

Unsupported kernel controls fail closed. Do not disable SELinux, seccomp,
Landlock, cgroup limits, clock checks or certificate verification to make an
installation start. Renew finite consent through its reviewed lifecycle.
A failed or expired clock observation is not permission to accept stale authority.

A compromised publisher key requires an independently authenticated replacement.
Healthy committee replacement and exceptional recovery after authority loss have
different procedures. Total authority loss creates a new network identity that
clients must explicitly accept; it cannot silently restore old access.

Read [hosting](Hosting.md), [authority](Authority.md), [private routes](PrivateRoutes.md),
[package trust](UpgradeRecovery.md) and [network recovery](NetworkRecovery.md) for
these contracts. [Qualification](Qualification.md) states the current platform and
deployment limits. Use [diagnostics](Diagnostics.md) for a redacted local report.
