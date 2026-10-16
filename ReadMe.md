# HyperNet

HyperNet is private, permissioned network infrastructure with explicitly
consenting hosts and independently verified authority results. HyperNetSuite is
a separate terminal and command-line client; the infrastructure does not depend
on that frontend.

Four appointed authority replicas run permissioned Basic HotStuff. A result
requires the protocol's ordered history, durable voting state and three valid
replica signatures. Membership, administration, review, hosting and confidential
access are separate capabilities. Operator consent binds exact software,
resources, exposure and lifetime; local withdrawal remains effective without a
quorum.

Rust implements protocol validation, cryptographic integration, journals and
runtime management. A narrow Ada/SPARK boundary checks media extents without
allocation or mutable state. Network transports use TLS1.3 and explicitly pinned
identities. Service workloads run under rootless Podman, delegated cgroup v2,
seccomp and Landlock. They share the host kernel.

Build with Rust, GNAT and ordinary C linker tools. Select persistent output
locations outside the source tree:

```sh
export CARGO_TARGET_DIR=/Private/HyperNetBuild
cargo build --locked --release
bash Tools/PolicyCheck.sh /Private/PolicyProof
bash Tools/Package.sh "$CARGO_TARGET_DIR/release" /Private/HyperNetPackage
```

Set `GNAT_GCC` and `GNATPROVE` when the tools are outside `PATH`. Dependencies are
locked in `Cargo.lock`. See [Hosting](Documentation/Hosting.md) for supported
confinement requirements and [Packages](Documentation/Packages.md) for independently
verified installation. Installation does not start a service or grant authority.

- [Authority](Documentation/Authority.md): independent trust, explicit capabilities and durable results.
- [Tier administration](Documentation/Tiers.md): exact policy history and reviewed capability changes.
- [Network policies](Documentation/NetworkPolicies.md): ordered policy and recovery custody changes.
- [Search](Documentation/Search.md): approved catalogues, explicit indexing consent and local retained content.
- [Authority replicas](Documentation/AuthorityReplica.md): pinned peers and consensus operation.
- [Runtime](Documentation/Runtime.md): setup, preview, local consent and authority lifecycle.
- [Native provisioning](Documentation/RuntimeProvisioning.md): local identities, pinned certificates and accepted replica inputs.
- [Package updates](Documentation/UpgradeRecovery.md): signed installation, retained trust and stopped cutover.
- [Operational audit](Documentation/OperationalAudit.md): bounded signed events and explicitly pinned witnesses.
- [Service runtime](Documentation/ServiceRuntime.md): exact hosting consent and serving activation.
- [Private routes](Documentation/PrivateRoutes.md): pinned relay transport, public endpoints and outbound attachments.
- [Authority epochs](Documentation/AuthorityEpochs.md): certified healthy replacement.
- [Network recovery](Documentation/NetworkRecovery.md): exceptional recovery and independently accepted identity.
- [Pages](Documentation/Pages.md): inert publication, manual review and current approval.
- [Content backups](Documentation/Backups.md): consented cold storage, retention and current-authority restore.
- [HyperPage](Documentation/HyperPage.md): bounded layout, colour and client-side motion.
- [Media](Documentation/PageMedia.md): exact raster/vector bytes and explicit disclosure.
- [Federation](Documentation/Federation.md): bilateral consent, author opt-in and destination review.
- [Bridges](Documentation/Bridge.md): confined exchanges between independent networks.
- [Private mail](Documentation/Mail.md): separate identities and recipient-selected ciphertext storage.
- [Transfers](Documentation/Transfers.md): explicit acceptance and durable encrypted delivery.
- [SSH services](Documentation/SshServices.md): separately consented fixed-command OpenSSH services.
- [Applications](Documentation/Applications.md): restricted independent credentials and review policy.
- [Protocol](Documentation/Protocol.md): canonical signed objects and exact retries.
- [Qualification](Documentation/Qualification.md): native checks and platform limits.
- [Security](Documentation/Security.md): private reporting and trust boundaries.

Private reader routes use fresh TLS channels to an approved relay and the final
service. Independent privacy depends on separate, noncolluding operators; an
organisation operating both ends can correlate connections. Sealed publications
protect content separately. Native AArch64, macOS and SELinux-enabled operation
remain pending qualification.

Licensed under the [MIT License](Licence.txt).
