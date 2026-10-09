# Security reporting and support

Report suspected security defects privately to the repository maintainers through
the organisation's established authenticated private contact channel. Do not post
credentials, private content or exploit details in a public issue. Include the
runtime version, package/image digest, affected feature, native platform and a
minimal synthetic reproduction when available.

The maintainers can request additional private evidence and coordinate a fix.
Do not treat a signature, passing tests or an approval policy as certification.
Packages require an independently trusted publisher key and a supported native
confinement profile. Current runtime and recovery limits are documented in
[Qualification](Qualification.md), [Packages](Packages.md) and
[Authority](Authority.md).

An unsupported kernel or security profile fails closed. Do not disable SELinux,
seccomp, Landlock, cgroup limits or certificate verification to bypass a failure.
Keep profiles, trust material and encrypted backups outside the installation.
A compromised publisher key requires an independently authenticated replacement;
a key shipped beside a package cannot establish its own trust.
