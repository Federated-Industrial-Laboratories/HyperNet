# Local runtime diagnostics

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

The installed runtime can preview a redacted snapshot of one authority or service
installation and explicitly export those exact bytes. These commands inspect
recorded local state only. They do not start Podman, inspect processes, contact a
socket, probe a peer, collect logs or upload anything.

```sh
HyperNet runtime diagnose --directory /Private/Authority
HyperNet runtime diagnose --directory /Private/Authority \
  --preview-digest SHA256_FROM_PREVIEW --output /Private/AuthorityDiagnostic.json

HyperNet runtime services diagnose --directory /Private/Service
HyperNet runtime services diagnose --directory /Private/Service \
  --preview-digest SHA256_FROM_PREVIEW --output /Private/ServiceDiagnostic.json
```

Preview returns `DiagnosticPreview`, `previewDigest` and `snapshot`. Review that
snapshot before sharing. Export collects it again and requires the same digest.
The new file contains the snapshot alone, encoded as compact UTF-8 JSON followed
by a newline. The digest is the lowercase SHA-256 of those exact bytes. Success
returns `DiagnosticExported` and the digest, without the output path.

Publication creates a mode 0600 file atomically in a private directory owned by
the current user. Existing files, symbolic links, symbolic-link traversal and
`..` are refused. Export never replaces a file or appends to it. Sending the file
to another party is a separate action.

## Scope and redaction

The `HyperNetDiagnostics/1` report contains the product/version, selected component,
`SelectedLocalRuntime` scope and `Recorded` or `UnavailableOrInvalid` availability.
`networkUsed`, `networkProbed`, `currentAuthority` and `readinessProbed` are always
false. When state is available, its `recorded` object contains only:

- Role, fixed lifecycle-state category and fixed failure category.
- Local generation, withdrawal generation and resource count.
- Initialisation, retained-consent and withdrawal flags.
- An authority pending-operation flag; null for services, whose local state does
  not record this field. A service failure category is also null.

Service generation is the installed profile's fixed local generation 1; its
withdrawal generation is 0 or 1. A service's category is `AwaitingLocalConsent`,
`Consented` or `Withdrawn`; a recorded container does not establish that it is
running. Authority state preserves known lifecycle categories, including
`Recovering`, `ClockUnavailable` and `EpochPrepared`. Unknown status or failure
strings become `Unknown`, without echoing their contents.

No report includes network, deployment, signer, operator, service or operation
identifiers, paths, endpoints, keys, profile digests, resource names, receipts,
timestamps, payloads, query terms or arbitrary error text. Version, role,
generations and resource counts remain operational information; inspect the
preview before sharing.

Collection uses the existing lifecycle `Lock`, acquired without waiting for a
busy operation. The lock may be created if absent. It reads only the selected
installation's bounded profile, state and independent local floors. Authority
inputs are `Profile.json`, `State.json`, `Generation.json` (each at most 262144
bytes) and `Authorization/Withdrawal.json` (64 bytes). Service inputs are
`ServiceProfile.json`, `ServiceState.json` (262144 bytes each) and its 64-byte
withdrawal file. Profiles are validated locally. Collection does not follow their
artifact or key paths, read signer journals, inspect mounted volumes, read
private diagnostic logs or repair persistent state.

The snapshot is consistent with cooperating local lifecycle writers while its
lock is held. It is not an authority certificate or a physical host attestation.
Retained consent can be expired or revoked; `Running` is a historical lifecycle
category, not a live check. Local floors cannot detect rollback of the whole disk
without an independently retained reference.

## Refusals and unavailable state

Busy, missing, unsafe or invalid state produces `UnavailableOrInvalid` with a null
`recorded` object. It does not expose paths or underlying errors. Retry after a
known lifecycle operation finishes, or use private operator inspection to examine
local ownership, permissions and state. No missing value means permission.

`DiagnosticSnapshotChanged` refuses export when the selected bytes changed since
preview. Preview again and inspect the new state. Equivalent redacted snapshots
have the same digest even when excluded information differs; the digest binds
the exported summary, not hidden source bytes or completeness.
`DiagnosticPreviewDigestInvalid` requires a 64-character lowercase hexadecimal
digest. `DiagnosticOutputUnavailable` covers existing, unsafe, nonprivate or
unwritable destinations without revealing their paths or underlying errors.

`status` and `preview` provide more detailed private operator information and may
perform different checks. Their outputs and retained `Diagnostics/` logs are not
part of this export. See [Runtime](Runtime.md) and
[ServiceRuntime](ServiceRuntime.md) for lifecycle recovery. The independent Suite
provides `network diagnose` for a local reader profile.
