<p align="center">
  <img src=".github/assets/header.svg" width="720" alt="HyperNet. Permissioned network infrastructure. Graphite wordmark and connected nodes on a silver engineering grid.">
</p>

<p align="center">Permissioned networks for pages, private communication and shared services.</p>

<p align="center">
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNet/releases/tag/v0.10.1">Linux 0.10.1</a> |
  <a href="Documentation/Installation.md">Install</a> |
  <a href="Documentation/Hosting.md">Host</a> |
  <a href="Documentation/ReadMe.md">Documentation</a> |
  <a href="Documentation/Security.md">Security</a> |
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNetSuite">HyperNetSuite</a>
</p>

HyperNet lets a group run its own network for publishing Pages, exchanging
encrypted mail and files, and sharing services. Each network decides who can
join and what its members can do. Hosts choose which services they provide and
how much storage, compute and network access they allow.

Pages are reviewed publications with text, layout, forms and images. Separate
networks can share approved Pages through federation while keeping their own
membership and administration.

This repository provides the authority, hosting services and local runtime
manager. [HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite)
provides the separate native graphical browser, terminal viewer and command-line
clients. Reading a Page does not require running a host or authority replica.

> [!NOTE]
> **Linux 0.10.1** uses the native Ubuntu x86_64 release profile and its documented limits.
> Other Linux distributions depend on compatible libraries and the required
> kernel and runtime capabilities. AArch64, macOS and SELinux-enabled operation
> remain unqualified. This release has no independent security certification.
> Read the [release notes](Documentation/ReleaseNotes.md) and
> [deployment limits](Documentation/Qualification.md) before choosing a deployment.

Version 0.10.1 corrects permission readiness for short application checks without
extending their original deadlines or reusing authority evidence. It remains
compatible with Suite 0.10.0.

Version 0.10.0 adds [application context and fresh authority checks](Documentation/ApplicationChecks.md)
with bounded caller deadlines and explicit transport facts. Existing version 1
payload workflows remain compatible.

Version 0.9.1 fixes overlapping stream and sealed-page permission scopes.
Read [the migration guide](Documentation/PermissionScopes.md) before upgrading;
network-wide grants no longer authorise those effects.

## Capabilities

| Area | Function |
| --- | --- |
| Pages | Publish reviewed revisions with responsive layouts, colours, forms and static media. HyperPages contain no scripts. |
| Confidential content | Share sealed publications with selected readers and hosts that agree to store encrypted content. |
| Mail | Exchange encrypted letters with owner-controlled addresses, separate devices and recipient-selected storage. |
| File exchange | Offer encrypted files for a recipient to accept, with durable delivery receipts. |
| Shared services | Offer approved, fixed-command OpenSSH services without granting arbitrary shell access. |
| Search | Search approved network catalogues or an explicitly selected local catalogue. Private local queries stay local. |
| Federation | Share publications through network agreements, author opt-in and destination review. |
| Hosting | Choose software, storage, exposure, resources and lifetime. A host can withdraw without waiting for a quorum. |
| Application streams | Connect application services through consented, relay-only duplex streams with separate identities, scoped permissions and fresh action-bound authority observations. |
| Administration | Manage replicated policy and permissions, scoped application access, audit, backups and recovery. |

Normal remote reader traffic uses authenticated, pinned TLS routes. SSH is a
separate service capability, not the transport required to browse Pages or send
mail. A relay hides the reader's address from the destination connection;
privacy from the destination operator additionally depends on independently
operated, noncolluding infrastructure. See [private routes](Documentation/PrivateRoutes.md).

## Start here

**Use a network.** Install [HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite),
preview its sample Pages, then follow its invitation and connection guides.
The browser and terminal client use the same Page format and permission checks.

**Operate a network.** Follow [installation](Documentation/Installation.md),
[host requirements](Documentation/Hosting.md) and
[network preparation](Documentation/RuntimeProvisioning.md). A working network
needs accepted trust, four appointed authority replicas, current clock
observations and explicitly admitted services. Installing the binary alone
creates none of these.

**Integrate an application.** Start with [application access](Documentation/Applications.md)
and the [protocol reference](Documentation/Protocol.md). Applications use separate
identities and restricted grants; they do not receive a user's private keys.

## Install

Download the [Linux 0.10.1 release](https://github.com/Federated-Industrial-Laboratories/HyperNet/releases/tag/v0.10.1)
or build from source. For a signed package, follow the
[package installation guide](Documentation/Packages.md): verification requires
independently accepted publisher trust and the current signed update policy.
Packages include the matching immutable OCI image.

### Build from source

Use Linux, a Rust toolchain supporting edition 2024, a GNAT compiler with Ada 2022
support, and C linker and archive tools. GNATprove is needed for the separate
SPARK proof check. The [installation guide](Documentation/Installation.md)
distinguishes build tools, package tools and host requirements.

From a trusted source checkout:

```sh
export CARGO_TARGET_DIR="$HOME/.local/state/HyperNetBuild"
cargo build --locked --release
"$CARGO_TARGET_DIR/release/HyperNet" --help
```

This builds the manager and confinement helper. It does not install a service,
open a listener or create a network. `GNAT_GCC` selects an Ada-capable compiler
when the default `gcc` lacks Ada support. Dependencies are locked in `Cargo.lock`.

Keep build outputs, package trust and live data in separate directories.

## Operate a host

| Task | Guide |
| --- | --- |
| Prepare identities, certificates and clock inputs | [Network preparation](Documentation/RuntimeProvisioning.md) |
| Preview, consent to and start an authority | [Authority runtime](Documentation/Runtime.md) |
| Add Page, Media, Mail, Transfer, Route, Bridge or SSH hosting | [Service runtime](Documentation/ServiceRuntime.md) |
| Inspect a failure without exporting private state | [Diagnostics](Documentation/Diagnostics.md) |
| Renew consent, recover after reboot or change software | [Stopped transitions](Documentation/Runtime.md#stopped-consent-renewal-reboot-and-software-replacement) |
| Enable explicit boot and logout operation | [Managed lifecycle](Documentation/Runtime.md#managed-linux-boot-and-logout) |
| Preserve content and recover from loss | [Content backups](Documentation/Backups.md) and [network recovery](Documentation/NetworkRecovery.md) |

Hosts require rootless Podman, delegated cgroup v2, seccomp and Landlock ABI 6 or
newer. Missing mandatory isolation prevents activation. Containers share the
host kernel; four replicas on one machine do not provide independent failure
domains. Native AArch64, macOS and SELinux-enabled operation remain pending;
Windows is outside the current supported profile.

## Trust and security

Four appointed authority replicas run permissioned Basic HotStuff. Decisions
require the protocol's ordered history, durable voting state and a quorum of
three. Collecting three signatures alone is insufficient. Membership does not
confer hosting, review, voting or confidential-content access.

Rust implements the runtime and protocols. A narrow Ada/SPARK boundary checks
media extents. These implementation choices, signatures and passing tests do not
constitute an independent security assessment. Read [security](Documentation/Security.md)
for reporting and trust boundaries, and [authority](Documentation/Authority.md)
for permissions and recovery.

## Documentation and development

The [release notes](Documentation/ReleaseNotes.md) describe the 0.10.1 scope and
known limits. The [documentation index](Documentation/ReadMe.md) provides reading routes for
operators, authors and application developers, plus the complete reference library.
[Source layout](Documentation/SourceLayout.md) maps implementation modules.
[Qualification](Documentation/Qualification.md) describes focused checks and the
limits of deployment evidence. [Dependencies](Documentation/Dependencies.md) and
[system-library licences](Packaging/LibraryLicences.md) cover third-party software.

Licensed under the [MIT License](Licence.txt).
