# Offline package updates

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Installation, activation and private state have separate lifecycles. The signed
package workflow is described in [Packages](Packages.md). An update requires the
current offline target policy below; it never starts a runtime, reuses obsolete
consent or changes an authority floor. Preserve existing software and state while
preparing a new private prefix.

## Offline update trust

Use an independently authenticated copy of both `Tools/Bundle.py` and its adjacent
`Tools/PackageTrust.py`. The finite offline update profile uses OpenSSH signatures;
it is not TUF and has no download service or automatic key discovery. Archive
signatures and update signatures use separate namespaces. The locally accepted
root is separate from the signed target; this profile uses its one pinned
Ed25519 key for both signatures, without delegated online signing roles.

Initialise one private persistent trust directory for this product and native
architecture. Keep it outside all installation prefixes and user-data profiles.
Authenticate the complete root pin and root generation independently. `KeyPin`
only computes a pin; possession of a downloaded key does not authenticate it.
The pin is lowercase SHA256 of the canonical `ssh-ed25519 BASE64` line, including
its final newline. It is not OpenSSH's displayed base64 fingerprint.

```sh
python3 Tools/Bundle.py KeyPin --public-key /Trust/Publisher.pub
python3 Tools/Bundle.py TrustInit --trust-directory /Private/CorePackageTrust \
  --public-key /Trust/Publisher.pub --root-pin <independently-authenticated-sha256> \
  --root-generation 1 --version-floor 0.7.5 --state-contract HyperNet080Authority2
```

The state contract is fixed by this product; an arbitrary operator-supplied label
cannot mark incompatible state as compatible. The current authority contract uses
immutable references for signer-state bodies. Incompatible inline-state packages
and retained package trust are refused; they cannot activate this layout in place.
Suite uses a different contract and trust directory. Current prerelease binaries retain version0.7.5; signed update
sequences distinguish their exact builds and cannot move backwards.

After creating a signed archive, the publisher authorises its exact target:

```sh
python3 Tools/Bundle.py Authorise --archive HyperNet.tar \
  --signature HyperNet.tar.sig --public-key /Trust/Publisher.pub \
  --signing-key /Offline/Publisher --output Target.json \
  --root-generation 1 --sequence <next-sequence> --version-floor 0.7.5 \
  --state-contract HyperNet080Authority2 \
  --not-before <unix-seconds> --expires <unix-seconds>
```

Authorise first verifies the archive and its complete inventory. Its detached
`Target.json.sig` signature uses `HyperNetUpdate1`. The canonical policy
binds product, native architecture, version and minimum version, state contract,
root generation and pin, sequence, validity interval, archive size and SHA256,
and the exact manifest SHA256. The signing key must match the supplied public key.
Policy and signature files are bounded. Install verifies their signature before
parsing the policy. It has no fallback when the policy or retained trust is absent.

```sh
python3 Tools/Bundle.py Install --archive HyperNet.tar \
  --signature HyperNet.tar.sig --public-key /Trust/Publisher.pub \
  --trust-directory /Private/CorePackageTrust \
  --policy Target.json --policy-signature Target.json.sig \
  --prefix /Private/HyperNetNext
python3 Tools/Bundle.py TrustInspect --trust-directory /Private/CorePackageTrust
```

Install holds the exclusive trust lock while checking and publishing the package.
The target must meet the retained version floor, current root and exact state
contract. A larger sequence advances the floor; an equal sequence is allowed only
for the identical complete target policy and archive. Changing an expiry or root
generation requires a new sequence. The retained minimum version also advances to
the installed target's version. The sequence, target digest and time/version
floors are synchronised to disk before the new prefix is published. Expiry is
checked again immediately before publication. Existing prefixes are never replaced.

The local wall clock must be correct. A clock earlier than the retained observation
refuses installation. This does not provide authenticated time or prove that a
publisher has not withheld a newer target. Expiry bounds acceptance of old target
metadata; offline operation cannot discover the latest available release.

## Root rotation and interrupted installation

Obtain the new root pin and generation through an independent authenticated
channel. Inspect the current trust digest, then perform an explicit comparison:

```sh
python3 Tools/Bundle.py TrustInspect --trust-directory /Private/CorePackageTrust
python3 Tools/Bundle.py TrustRotate --trust-directory /Private/CorePackageTrust \
  --expected-trust-digest <inspected-trust-digest> \
  --public-key /Trust/NewPublisher.pub --root-pin <independently-authenticated-new-pin> \
  --root-generation <current-generation-plus-one>
```

Rotation refuses a changed trust snapshot or unchanged key. It advances exactly
one root generation and preserves sequence, target and version floors. The next
install needs a newly signed target with a larger sequence under the new root.
A package cannot rotate its own root, and an old-key signature cannot adopt a new
key. Keep old public keys only for verifying retained historical installations.

An interruption after the floor is committed leaves that floor in force. Retry
the exact same still-valid policy and archive into the same unused prefix or a
different new prefix. If the prefix was already published, verify that installation
instead of overwriting it. If the policy has expired, obtain a fresh target at a
larger sequence. Never delete or restore older trust state to make a retry pass.
An interrupted staged directory may remain; remove only that known incomplete
scratch directory after confirming no package operation is active.

Back up the complete trust directory independently and retain its latest digest,
sequence, target and root generation. Owner-only files, locking and atomic writes
cannot detect rollback of the entire disk together with its floors. Corrupt or
missing trust state refuses installation; recovery requires independently retained
current state. Old installations and external application state remain untouched.

Use VerifyInstalled before selecting an installation and after interrupted
publication. Verify, VerifyInstalled and Remove check historical integrity only;
they do not assert freshness or lower the retained update floor. Package removal
leaves runtime profiles, state, trust directories and loaded images untouched.
Changing the executable of a deployment requires fresh consent and the certified
replacement procedure in [AuthorityEpochs](AuthorityEpochs.md) where applicable.
There is no automatic runtime switch, rollback or state migration.

`AdmitInstalled` is the runtime's activation check. It additionally requires the
exact retained target and a currently valid signed policy, returning the current
trust digest while holding the trust lock. The runtime retains that same lock
through cutover and checks freshness again. It does not execute a verifier from
an unauthenticated candidate prefix.

`InspectInstalledTarget` checks historical integrity against the previously
accepted public key and exact signed target. Its result always states
`activationAllowed: false`. It does not read, replace or lower current package
trust. Interrupted non-serving metadata recovery can use this result after
expiry or a later root/sequence change. The runtime retains restrictive recovery
markers; starting workloads still requires a fresh reviewed successor admitted
against current package trust. Historical verification is never activation.
