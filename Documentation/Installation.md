# Installation and first deployment

[Documentation](ReadMe.md) | [Project](../ReadMe.md) | [Next: Host requirements](Hosting.md)

For public packages, start with the [Linux 0.8.0 download and installation steps](ReleaseNotes.md).

Install HyperNet to operate authority replicas or consenting services. To browse,
send mail or exchange files as a network member, use the separate
[HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite).
A client does not need the Core host runtime.

Install the public Linux package or build from source. Signed offline packages
require independently accepted publisher trust. Installation does not create a
network; follow the deployment steps below after checking the release limits.

## Requirements by task

| Task | Requirements |
| --- | --- |
| Build the binaries | Linux; Rust with edition 2024 support; GNAT with Ada 2022 support; C linker tools and `ar`. |
| Check the Ada contract | GNATprove and its project tools, separately from the runtime compiler. |
| Build the OCI image | Rootless Podman, Bash, GNU coreutils and Debian-format library ownership records (`dpkg-query`). |
| Verify or install a signed bundle | Trusted bundle helpers, Python 3.11 or later, OpenSSH `ssh-keygen` with Ed25519 SSHSIG support, matching native architecture and host ABI. |
| Run a host | Rootless Podman and OCI runtime, subordinate UID/GID mappings, delegated cgroup v2 CPU/memory/PID controllers, seccomp and Landlock ABI 6 or newer. |
| Prepare network identities | Maintained OpenSSL at `/usr/bin/openssl`, private persistent storage and independently authenticated peer information. |
| Keep authority time | A separately pinned monitor and chrony configured with authenticated NTS sources. |
| Use managed startup | A working Linux systemd user manager, explicit managed consent and user lingering. |

The installed native manager also needs the shared libraries and GNU libc version
identified by its package manifest. OpenSSL is a separate provisioning tool, not
a native-manager shared-library dependency. Image libraries do not
replace the host kernel or native manager dependencies. Current native development
is on x86_64 Linux; consult [qualification](Qualification.md) for unverified platforms.
A distribution name alone does not establish that confinement is available.

## Build a trusted checkout

Run from the repository root as an ordinary account. Keep build output outside
the checkout:

```sh
export CARGO_TARGET_DIR="$HOME/.local/state/HyperNetBuild"
cargo build --locked --release
"$CARGO_TARGET_DIR/release/HyperNet" --version
"$CARGO_TARGET_DIR/release/HyperNet" runtime --help
```

The output contains `HyperNet` and `HyperNetGate`. The build invokes `gcc` for the
Ada boundary by default. If Ada support is installed under a different compiler
name, set `GNAT_GCC` to that executable before building. `AR` selects an alternate
archiver. This build does not start workloads or write network identity state.

The proof check is a separate command:

```sh
bash Tools/PolicyCheck.sh "$HOME/.local/state/HyperNetPolicyProof"
```

Set `GNATPROVE` when the prover is outside `PATH`. A successful binary build does
not mean that this proof check ran. Contributor source checks are described in
[qualification](Qualification.md); they are not a prerequisite for opening an
already verified installation's help.

## Prepare or install a package

For a development image, use a new output directory on a build host with
Debian-format library records:

```sh
bash Tools/Package.sh "$CARGO_TARGET_DIR/release" \
  "$HOME/.local/state/HyperNetPackage"
```

The packager copies trusted binaries and their runtime libraries into a minimal
OCI image and records its immutable ID. It refuses an existing output directory.
This is image preparation, not signed installation or network activation.

To distribute or install a signed bundle, follow [Packages](Packages.md). Obtain
the publisher key through an independent authenticated channel, initialise the
separate package trust directory and verify the exact signed update policy.
Installation uses a new private prefix and retains update floors. Do not run an
unverified helper extracted from the archive it is meant to verify.

## Set up the network

There are two separate responsibilities: a network administrator assigns
capabilities, and each hardware operator consents to its own deployment. One
cannot silently take over the other's role. Complete these steps with the
operators involved:

1. Check [host isolation and storage](Hosting.md). Select private persistent
   directories and reachable peer endpoints. Keep live state outside both the
   checkout and installation prefix.
2. Use [network preparation](RuntimeProvisioning.md) for locally owned keys,
   certificate requests, independently verified peer inputs and clock monitors.
   Follow the linked Suite bootstrap procedure to appoint four authorities and
   accept the recovery policy.
3. On each authority host, follow [Runtime](Runtime.md) to import the accepted
   inputs, review the exact deployment, consent and start. Verify current quorum
   with the separate Suite; process presence is not readiness.
4. Admit the required services and follow [Service runtime](ServiceRuntime.md).
   Page storage, media, mail, transfers and remote routes are separate roles with
   their own permissions, resources and finite consent.
5. Configure [private routes](PrivateRoutes.md) before inviting remote readers.
   Give readers independently authenticated bootstrap information and their
   explicit invitations through the Suite workflow.

Examples use `/Private/...` as placeholder paths, documentation-range addresses
and labels such as `<authenticated-bootstrap-digest>`. Replace every placeholder
with the verified output from its preceding step. Do not paste an incomplete
example into a shell or manufacture a digest to satisfy a command.

A private parent directory must have safe ownership and permissions throughout
its ancestor path. Avoid temporary directories for identities, journals, receipt
floors and recovery records. Do not recreate missing state under an existing
identity to make a stopped service start.

## Normal operation and removal

Use [Runtime](Runtime.md) and [Service runtime](ServiceRuntime.md) for status,
stop, withdrawal and managed startup. Consent expires; renewal uses a reviewed
stopped successor, not an automatic extension. A host reboot changes clock boot
bindings and requires the documented lifecycle handling.

Use [Diagnostics](Diagnostics.md) for a redacted local preview. Sharing that
preview is separate from collecting it. Retain exact interrupted operations
until their outcome is known.

Package replacement follows [Upgrade recovery](UpgradeRecovery.md); it does not
change a live deployment by itself. Stop deployments before removing an
installation with the package helper. Removal preserves profiles, private data
and loaded images. Inspect continued use before deleting an image or retained
state separately.
