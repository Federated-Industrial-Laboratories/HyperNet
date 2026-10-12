# Signed offline packages

HyperNet packages install independently of HyperNetSuite. The initial package
carries the native `Bin/HyperNet` manager, an immutable OCI image, launchers,
operator documentation and dependency notices. The native executable has the same
SHA-256 digest as HyperNet inside the signed image. It contains no network keys, certificates, profiles, voter database or
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
inside the OCI image. The native manager uses host-maintained shared libraries.
The signed manifest declares its ELF interpreter, required libraries and minimum
GNU libc version; installation refuses an older libc or missing interpreter.
The native host also needs OpenSSL 3 and the qualified Podman/kernel profile.
Package operations use Python, OpenSSH tools, Bash and the documented native
runtime prerequisites. Authority ordering is provided by the installed HyperNet
replicas.
See [Runtime](Runtime.md) for inert native setup and explicit local activation.

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
architecture, immutable image ID, binary hashes, native host ABI, the exact
authority schema and every
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
native architecture and declared host ABI. It loads the signed OCI archive, checks the actual image ID
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
python3 Tools/Qualify.py --work-directory /Private/QualificationWork \
  --image sha256:ImageDigest --output /Private/Qualification.json
```

VerifyInstalled rechecks the retained archive against the independently supplied
key and compares every installed file, mode and directory with its signed
inventory. It does not trust a modified local manifest. Qualify uses the native
kernel and a disposable bounded container to verify actual confinement. A
userspace container on another distribution is not a native kernel qualification.

Every installed deployment binds its exact binary and image in signed operator consent.
An executable change requires fresh consent and current governance approval.
Authority replacement uses the terminal and Ready workflow in
[AuthorityEpochs.md](AuthorityEpochs.md); services use the installed service
lifecycle in [ServiceRuntime.md](ServiceRuntime.md). Package installation alone
cannot change a running deployment or its authority floor.

The current package declares authority schema1 for the canonical authority
contract. Incompatible prerelease state requires an explicit fresh deployment;
there is no compatibility parser or implicit migration. Never restore old state,
grants, checkpoints or floors to make another executable start.

The default offline bundle contains the Core image from `Tools/Package.sh`.
Custom fixed-command SSH images from `Tools/SshPackage.sh` require independently
trusted image distribution and fresh operator consent.

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
