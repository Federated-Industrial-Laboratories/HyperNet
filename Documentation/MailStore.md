# Mail store operation

A Mail service is an installed role3 workload with a dedicated Ed25519 service
identity. Its operator signs the host consent and Mail profile, each bound to the exact
canonical deployment manifest.
Network registration, local operator consent and serving activation are separate
requirements. The owner selects this service key in each mailbox manifest.

## Profile and registration

Prepare an admitted manifest with one Mail role, a writable state volume,
`allowOpaque` consent and explicit resource limits. Its Mail role has no bind or
outbound endpoints. The profile names the exact volume, preallocated state size,
maximum ciphertext size and maximum lifetime. `HyperNetSuite mail profile` signs
these values as the deployment operator; `mail register` publishes the result
through an admitted manager with StoreMail14 and ManageService26 capabilities.
The registered deployment's registrar and consent must also remain current.

A ciphertext is at most128KiB. The profile may choose a smaller maximum with a
clear workload reason. Lifetime is at most seven days. Each of the two storage
banks must fit its header and at least one maximum-sized entry. State admission
must fit the chosen volume and role limits. The role's memory admission must be
at least three times the state file size, accounting for decoding and atomic
bank replacement. Storage capacity refusal preserves existing state.

Prepare the exact configuration artifacts:

| File | Purpose |
| --- | --- |
| Bootstrap.cbor | Fully accepted, independently pinned bootstrap |
| Manifest.cbor | Exact canonical admitted deployment manifest |
| Service.key | Dedicated Mail service's raw32-byte private seed |
| MailProfile.cbor | Signed role3 storage profile |
| ServiceConfig.json | Fixed paths below |

```json
{
  "bootstrapFile": "/Config/Bootstrap.cbor",
  "manifestFile": "/Config/Manifest.cbor",
  "profileFile": "/Config/MailProfile.cbor",
  "identityFile": "/Config/Service.key",
  "stateFile": "/State/MailState.bin",
  "controlSocket": "/Authority/Control.sock",
  "clockWitnessFile": "/Clock/ClockHealth.cbor",
  "listenSocket": "/State/Control/Control.sock"
}
```

Keys and configuration use owned private files. The operator key is never
mounted into the service. The authority mount contains only its isolated Control
directory; authority keys and replica state remain inaccessible.

## Installed lifecycle

Use [ServiceRuntime](ServiceRuntime.md) for setup, preview, explicit local
consent, activation and supervised start. The same command family provides
status, stop, withdrawal, receipt export and healthy-epoch adoption:

```sh
HyperNet runtime services setup --directory /Private/MailService \
  --configuration /Private/MailInputs --operator-key /Private/Operator.json \
  --host-consent /Private/HostConsent.cbor \
  --authority-directory /Private/Authority --clock-directory /Private/Clock
HyperNet runtime services preview --directory /Private/MailService
HyperNet runtime services consent --directory /Private/MailService \
  --profile-digest REVIEWED_PROFILE_DIGEST
HyperNet runtime services start --directory /Private/MailService \
  --activation-request /Private/MailActivation.cbor
```

Start remains supervised in the foreground. The workload is PID1 under UID1000
in its own subordinate user namespace. Rootless OCI, a read-only image, separate
PID/IPC namespaces, no capabilities, no-new-privileges, seccomp, Landlock and
signed resource limits remain mandatory. Unsupported confinement fails closed.
The current activation deadline is enforced independently of new mail traffic.

The service accepts only same-UID private Unix socket packets. A local operator
can forward a bounded packet without exposing the subordinate-owned directory:

```sh
HyperNet runtime services exchange --directory /Private/MailService \
  --packet /Private/MailPacket.cbor --receipt /Private/MailReceipt.cbor
```

The client must verify the returned typed receipt independently. Exchange is not
a public gateway. There is no automatic direct route or network fallback.

## Persistence and withdrawal

The requester and recipient journals separately retain quorum history and exact
effect claims. The ciphertext file has two checksummed committed banks. A write
syncs the new bank before success, then clears the obsolete bank. Deletion stores
a tombstone until expiry; an exact replay cannot resurrect its ciphertext.
Clock floors persist for reads as well as mutations.

Stop preserves these files. Ordinary start never recreates a missing journal or
adopts an arbitrary ciphertext file. Withdrawal first persists the local veto,
then removes owned resources; cleanup failure cannot restore permission. Publish
the separate restrictive domain withdrawal with `HyperNetSuite mail withdraw`.
A withdrawn installation cannot be renewed in place.

Healthy committee replacement requires stopping the service and explicitly
sealing and activating both retained journals. They must accept the same verified
successor before restart. A new control directory is chosen explicitly; it does
not change the independently accepted network identity. See
[AuthorityEpochs](AuthorityEpochs.md). Keep uncertain backup files offline rather
than restoring them as a live service with rolled-back effects or deletion state.
