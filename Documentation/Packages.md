# Signed offline packages

HyperNet packages install independently of HyperNetSuite. The initial package
carries an immutable OCI image, launchers, operator documentation and dependency
notices. It contains no network keys, certificates, profiles, voter database or
personal state. The daemon continues to require its confined rootless OCI
profile; installing a package does not start a service or open an ingress port.

Use a trusted copy of `Tools/Bundle.py`, Python 3.11 or later and OpenSSH
`ssh-keygen` with Ed25519 SSHSIG support. The default verifier is
`/usr/bin/ssh-keygen`; an independently trusted alternative can be supplied using
`--ssh-keygen` before the operation. Keep the publisher's public key through a
separate authenticated channel. A key delivered only beside an untrusted archive
is not an independent trust anchor. No default publisher key is embedded.

## Prepare a private candidate

Build the binaries and image using [Hosting](Hosting.md). The packager reads
Debian-format build-host library inventories; installation on another Linux
family does not require `dpkg`. Copied runtime libraries and their loader stay
inside the OCI image. The native host needs Python, OpenSSH tools, Bash, GNU
core utilities, `jq`, `flock` and the qualified Podman/kernel profile.

```sh
python3 Tools/Bundle.py Create \
  --package /Private/HyperNetPackage \
  --output /Private/HyperNet.tar \
  --signing-key /Offline/Publisher
```

Create accepts trusted build outputs only. It inspects the local image without
starting it, verifies its architecture and compares its actual binaries with the
supplied build files. Package version identifies the actual HyperNet runtime;
the current runtime is 0.7.5. Other runtime contracts are rejected.
The helper generates no signing identity. Select and protect the operator's own
offline signing key; no signing secret enters the package.

The detached signature covers the entire exact archive under SSHSIG namespace
`HyperNetBundle1`. Manifest format 1 identifies product, runtime version, native
architecture, immutable image ID, binary hashes, the exact authority schema and every
payload file's SHA-256, size and mode. Archives are uncompressed USTAR, at most
512 MiB, with at most 512 payload files and at most 256 MiB per file. Archives
contain only one initial manifest and explicitly inventoried regular files.

System-library source accompaniment remains a pre-distribution requirement.
[LibraryLicences](../Packaging/LibraryLicences.md) describes the exact source
package and patch inventory. Creating or signing a private candidate does not
supply those source packages or constitute public release qualification.

## Verify and install

Run verification from an independently trusted helper, before running any tool
from a downloaded package:

```sh
python3 Tools/Bundle.py Verify \
  --archive /Incoming/HyperNet.tar \
  --signature /Incoming/HyperNet.tar.sig \
  --public-key /Trust/Publisher.pub
python3 Tools/Bundle.py Install \
  --archive /Incoming/HyperNet.tar \
  --signature /Incoming/HyperNet.tar.sig \
  --public-key /Trust/Publisher.pub \
  --prefix /Private/HyperNetCurrent
```

The helper copies inputs into private temporary files and verifies the signature
before reading archive metadata. It refuses duplicate paths, links, devices,
traversal, unlisted files, missing files, unsupported metadata and hash or mode
mismatches. Installation requires a new private prefix on Linux and the matching
native architecture. It loads the signed OCI archive, checks the actual image ID
and architecture, then atomically publishes the new installation without replacing
an existing prefix. No archive-supplied program is run during verification.

Installations are side by side. Select another new prefix for an update; no
implicit `Current` link, automatic update, service activation or system-wide
configuration change occurs. `Manifest.json` and `ImageId.txt` identify the selected
runtime. The original archive and signature are retained under `Package` for later
verification. A successful image load can remain if installation subsequently
fails; inspect that exact image ID before any separate cleanup.

## Verify, switch and remove

```sh
python3 Tools/Bundle.py VerifyInstalled \
  --prefix /Private/HyperNetCurrent --public-key /Trust/Publisher.pub
python3 Tools/Qualify.py \
  --image sha256:ImageDigest --output /Private/Qualification.json
```

VerifyInstalled rechecks the retained archive against the independently supplied
key and compares every installed file, mode and directory with its signed
inventory. It does not trust a modified local manifest. Qualify uses the native
kernel and a disposable bounded container to verify actual confinement. A
userspace container on another distribution is not a native kernel qualification.

Stop the relevant profile through its existing launcher before changing its image.
All workload and relay containers must be removed by Stop, including exited
containers. Select a fully verified installation and inspect the current network
state schema before using the switch operation:

```sh
python3 Tools/Upgrade.py --kind Authority \
  --profile /Private/AuthorityProfile \
  --installation /Private/HyperNetUpdated \
  --public-key /Trust/Publisher.pub \
  --expected-image sha256:PreviousImageDigest --state-schema 9
```

Kinds are Authority, Host, Bridge, MailStore and TransferStore. The operation holds
the same lifecycle lock as their launchers, checks the expected old image and
signed authority schema, and changes only `Control.json.image`. It does not
start a service or modify resources, endpoints, credentials, consent, withdrawal
markers, durable state or floors. Run Start explicitly and confirm real readiness
with an authenticated operation before directing clients to the new process.
Keep the consented authority endpoint stable across container recreation. An
automatically allocated private container address is not a stable service address.

`--state-schema` is the operator's inspected value, not independent proof of the
quorum's current schema. The authority checks the real quorum state again at
startup and refuses incompatible state. The current package requires schema9.
There is no legacy schema acceptance or migration. Use a fresh development
installation when replacing an incompatible prerelease contract. The switch
operation can change an image only within the current schema. Never restore old
state, grants, voter snapshots or revision floors to make an old executable start.

SSH profiles cannot use image switching: their signed consent binds the exact
image and fixed command. Package the new SSH service image and obtain fresh
operator consent and a fresh grant through the existing SSH provisioning workflow.
No generic package update can bypass that binding. The signed offline bundle
currently accepts the general Core image from `Tools/Package.sh`. Custom fixed-command
SSH overlays from `Tools/SshPackage.sh` require their separate trusted image
distribution and fresh consent; they are not part of this default bundle profile.

Stop using an installation before removing its files:

```sh
python3 Tools/Bundle.py Remove \
  --prefix /Private/HyperNetCurrent --public-key /Trust/Publisher.pub
```

Remove verifies the original signature and the complete installed inventory first.
Modified, missing, linked or unexpected files cause refusal. It removes only that
installation's managed files. Profiles, certificates, durable state, lifecycle
locks and loaded OCI images remain. Remove an image separately only after all
other installations and profiles have stopped using its immutable ID. Installation
prefixes must never be used for application data or profile directories.
