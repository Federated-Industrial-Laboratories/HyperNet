<h1 align="center">HyperNet</h1>

<p align="center">Permissioned networks for pages, private communication and shared services.</p>

<p align="center">
  <a href="Documentation/Installation.md">Install</a> |
  <a href="Documentation/Hosting.md">Host</a> |
  <a href="Documentation/ReadMe.md">Documentation</a> |
  <a href="Documentation/Security.md">Security</a> |
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNetSuite">HyperNetSuite</a>
</p>

HyperNet connects consenting hosts to provide reviewed publications, encrypted
mail and file exchange. Networks control admission and assign explicit
permissions for reading, publishing, reviewing, storage and administration.
Federation lets separate networks share approved publications without combining
their memberships or handing over administrative authority.

This repository provides the authority, hosting services and local runtime
manager. [HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite)
provides the separate native graphical browser, terminal viewer and command-line
clients. Reading a Page does not require running a host or authority replica.

> [!NOTE]
> HyperNet is in development. The current runtime version is 0.7.5; a public
> production release is not available. Native x86_64 Linux is the current
> development platform. See [platform and deployment limits](Documentation/Qualification.md)
> before planning a deployment.

## Capabilities

| Area | Function |
| --- | --- |
| Pages | Immutable, reviewed publications with responsive layout, colours, forms and static media. HyperPages contain no scripts; viewers generate decorative motion locally. |
| Confidential content | Sealed publications for explicitly authorised readers; storage hosts separately consent to opaque content. |
| Mail | Encrypted letters, owner-controlled addresses, separate devices and recipient-selected storage. |
| File exchange | Encrypted transfers with exact recipient acceptance and durable delivery receipts. |
| Shared services | Separately consented fixed-command OpenSSH services, without granting arbitrary shell access. |
| Search | Approved network catalogues and explicitly selected local search; confidential local terms are not automatically forwarded. |
| Federation | Bilateral agreements, author opt-in and destination review for shared publications. |
| Hosting | Exact local consent for software, storage, exposure, resources and lifetime; withdrawal works without a quorum. |
| Administration | Replicated policy and capability changes, scoped application access, audit, backup and explicit recovery. |

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

## Build from source

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

[Signed offline packages](Documentation/Packages.md) provide verified installation
with independently accepted publisher trust. They include the matching immutable
OCI image. Build outputs, package trust and live data use separate directories.

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

The [documentation index](Documentation/ReadMe.md) provides reading routes for
operators, authors and application developers, plus the complete reference library.
[Source layout](Documentation/SourceLayout.md) maps implementation modules.
[Qualification](Documentation/Qualification.md) describes focused checks and the
limits of deployment evidence. [Dependencies](Documentation/Dependencies.md) and
[system-library licences](Packaging/LibraryLicences.md) cover third-party software.

Licensed under the [MIT License](Licence.txt).
