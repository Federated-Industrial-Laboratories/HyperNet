# Linux 0.8.0

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

HyperNet 0.8.0 is the first public Linux release. Download the native x86_64
package from [GitHub Releases](https://github.com/Federated-Industrial-Laboratories/HyperNet/releases/tag/v0.8.0).

HyperNet provides four-replica Byzantine authority, consented rootless hosting,
relay-only reader routes, durable content archives and replicated administration.
It serves reviewed Pages, encrypted Mail and Transfers, scoped search and
separately consented OpenSSH services. Federation shares approved publications
between independently accepted network identities.

## Platform and release scope

The packaged profile is native Ubuntu 24.04 x86_64 with GNU libc 2.39 or newer.
Other Linux distributions need the exact ELF loader and libraries recorded in
`Manifest.json`; they are not separately qualified by this release. Native ARM,
macOS and Windows are not qualified. SELinux-enabled hosting remains unqualified.
Hosting additionally requires rootless Podman, subordinate UID/GID mappings,
delegated cgroup v2 CPU/memory/PID controls, seccomp and Landlock ABI 6 or newer.
Ubuntu 24.04 alone does not guarantee those kernel controls. Missing enforcement
prevents activation. Four replicas on one machine share that machine's failures.

The release includes requester/recipient clock refresh corrections across durable
writes and profile-lock ownership fixes. Existing proof deadlines, pending
requests and completed effects remain enforced. Source regressions and signed
installation checks cover this release. Earlier installed network, recovery,
Mail, Transfer and graphical checks remain relevant to the unchanged runtime
implementation; they do not become measurements of a different executable.

This release has no independent security certification. Saturation, long-running
soak tests, full screen-reader use and independent operator/failure-domain
qualification are outside the measured scope. Large file downloads remain slow:
a prior 1 MiB relay download took 12.246 seconds. Native administration is not
included; use the documented CLI. Read the security and platform guides before
planning an exposed deployment.

## Download and authenticate

Download all five package inputs from the release: `HyperNet-0.8.0-linux-x86_64.tar`,
its `.sig`, `HyperNet-0.8.0-linux-x86_64.target.json`, its `.sig`, and `Publisher.pub`.
`SHA256SUMS` and `SHA256SUMS.sig` cover the downloadable artifacts.
The release also supplies `HyperNet-0.8.0-system-sources.tar.xz`: exact Ubuntu
source packages and patches for the libraries copied into the OCI image. Keep
this source archive and the library notices with redistributed binary packages.
Its README describes source verification and rebuilding.

Use `Tools/Bundle.py` and `Tools/PackageTrust.py` from an independently trusted
checkout of the `v0.8.0` tag. Python 3.11 or newer and OpenSSH `ssh-keygen` with
Ed25519 SSHSIG support are required. Do not execute tools extracted from an
unverified archive. Authenticate the publisher through a separate trusted channel
before accepting this release root:

```text
Root generation: 1
Root pin: 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e
```

The canonical public key is also recorded in [PublisherKey.txt](PublisherKey.txt).
This hexadecimal pin uses the package tool's canonical-key format, not OpenSSH's
base64 fingerprint. A key and signature downloaded together cannot establish
publisher identity by themselves.

From the download directory, using the trusted checkout's helper:

```sh
python3 /Trusted/HyperNet/Tools/Bundle.py KeyPin --public-key Publisher.pub
sha256sum --check SHA256SUMS
```

Compare the computed pin with the independently accepted pin above. Checksums
alone detect corruption, not publisher identity. Verify the signed checksum file
with an independently trusted public key when checking the source accompaniment:

```sh
printf 'ReleasePublisher %s\n' "$(cat Publisher.pub)" > ReleaseSigners
ssh-keygen -Y verify -f ReleaseSigners -I ReleasePublisher \
  -n HyperNetRelease1 -s SHA256SUMS.sig < SHA256SUMS
```

## Fresh installation

Use a new private installation prefix. Initialise trust once per product;
Core and Suite use separate trust directories even with the same publisher.
These commands are for a fresh installation, not replacement of existing trust.

```sh
install -d -m 0700 "$HOME/.local/share/HyperNet" "$HOME/.local/opt"
python3 /Trusted/HyperNet/Tools/Bundle.py TrustInit \
  --trust-directory "$HOME/.local/share/HyperNet/PackageTrust" \
  --public-key Publisher.pub \
  --root-pin 6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e \
  --root-generation 1 --version-floor 0.8.0 --state-contract HyperNet080Authority2
python3 /Trusted/HyperNet/Tools/Bundle.py Install \
  --archive HyperNet-0.8.0-linux-x86_64.tar \
  --signature HyperNet-0.8.0-linux-x86_64.tar.sig --public-key Publisher.pub \
  --trust-directory "$HOME/.local/share/HyperNet/PackageTrust" \
  --policy HyperNet-0.8.0-linux-x86_64.target.json \
  --policy-signature HyperNet-0.8.0-linux-x86_64.target.json.sig \
  --prefix "$HOME/.local/opt/HyperNet-0.8.0"
python3 /Trusted/HyperNet/Tools/Bundle.py VerifyInstalled \
  --prefix "$HOME/.local/opt/HyperNet-0.8.0" --public-key Publisher.pub
"$HOME/.local/opt/HyperNet-0.8.0/Bin/HyperNet" --help
```

The signed target has a finite validity interval recorded in its `notBefore` and
`expires` fields. An expired target needs a newly authorised policy; do not bypass
expiry or reset retained trust. Installation starts no network services and
creates no membership. Keep profiles, keys, consent and data outside the prefix.

## Existing installations

The published generation-1 target is for fresh release trust. It cannot migrate
an existing installation from a different publisher: root rotation must increase
the retained generation, and a migration target must match that new generation
and exceed the retained sequence. Existing development installations need a
separately authorised compatible migration target from the accepted publisher.

Preserve profiles, journals, backups, retained floors and original package trust.
Do not reset trust or create a replacement trust directory to bypass those floors.
Earlier packages are not automatically upgraded or activated. Follow
[upgrade and recovery](UpgradeRecovery.md) for independent root authentication,
state compatibility, migration targets and side-by-side installation.
