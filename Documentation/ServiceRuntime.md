# Installed service runtime

`HyperNet runtime services` manages one consenting Page, Media, Mail, Transfer, Bridge or SSH service.
The service has separate requester and recipient journals. The requester makes
its own authority queries; the recipient retains a manager's activation and
remote effect claims. Neither journal is the manager's private requester state.

The host requires rootless Podman, cgroup v2, seccomp and Landlock ABI6 or newer.
Each workload uses UID1000 in its own subordinate user namespace, private PID/IPC
namespaces, a read-only pinned image, no capabilities and no-new-privileges.
Resource limits come from the exact admitted manifest. State admission and
individual file limits are not a filesystem quota for the host's whole disk.

## Import and consent

Prepare one private configuration directory containing the fixed artifacts:

| Role | Input files |
| --- | --- |
| SSH, role8 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, SshProfile.cbor, SshdConfig, AuthorizedKeys, SshHostKey |
| Transfer, role4 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, TransferProfile.cbor |
| Mail, role3 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, MailProfile.cbor |
| Page, role1 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, PageProfile.cbor |
| Media, role2 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, MediaProfile.cbor |
| Bridge, role7 | Bootstrap.cbor, Manifest.cbor, Service.key, ServiceConfig.json, BridgeProfile.cbor, Certificate.pem, CertificateAuthority.pem, Transport.key |

`Service.key` is the dedicated role's raw32-byte signing seed. The operator key
is separate and never mounted into the workload. Setup adds the fixed hardened
Seccomp.json artifact. The exact file membership and every digest are included
in the operator's local consent. Consult [SshServices](SshServices.md),
[PageStore](PageStore.md), [MediaStore](MediaStore.md), [MailStore](MailStore.md), [TransferStore](TransferStore.md) or [Bridge](Bridge.md) for the fixed
configuration paths and schemas.

```sh
HyperNet runtime services setup --directory /Private/Service \
  --configuration /Private/ServiceInputs --operator-key /Private/Operator.json \
  --host-consent /Private/HostConsent.cbor \
  --authority-directory /Private/Authority --clock-directory /Private/Clock
HyperNet runtime services preview --directory /Private/Service
HyperNet runtime services consent --directory /Private/Service \
  --profile-digest REVIEWED_PROFILE_SHA256
```

Setup imports inert configuration. Review the role, artifacts, software/image,
resources, lifetime and exact exposure before consenting. The local authority
must belong to the independently accepted network. Only its isolated Control
directory is mounted; no authority signer key or replica journal is available
to the service. The signed clock witness has its own read-only mount.
The clock directory must contain `ClockHealth.cbor` directly.

## Activate and supervise

The deployment must already have current network admission and its domain's
signed profile. An explicitly authorised manager prepares an exact activation
request through Suite `authority-inspection deployments activation-request`.
The request binds the deployment, role, local generation and consent. Export it
without transferring the manager's key or private journal to the service.

```sh
HyperNet runtime services start --directory /Private/Service \
  --activation-request /Private/ActivationRequest.cbor
```

Keep this foreground command running. Initial preparation creates the two
retained journals explicitly; ordinary startup opens them without resetting
missing or conflicting state. Before any serving effect, the service obtains a
fresh quorum proof and durably records the recipient claim. Local consent and
fresh domain permissions remain separate requirements. SSH and Bridge listeners
use their exact signed IPv4 endpoints. Bridge also has explicit counterpart
routes and separately consented local media controls. Media, Mail and Transfer expose only private local
sockets. The Page replica uses its own authority requester and has no reader
listener. These local templates provide no TCP listener or direct remote-reader
fallback.

After healthy committee activation, SSH, Page and Bridge requesters obtain fresh
own-stream status from the current committee before allocating or resuming an
ordinary request. Retained prior-epoch metadata cannot satisfy this check. The
refresh preserves exact pending requests; it does not replace their signatures
or extend a serving lease.

`status` reports process presence, consent and retained resource ownership.
`ServiceStarting` and `running: true` do not assert readiness or current network
permission. Failed runtime dependencies report a bounded, terminal-escaped
excerpt of their standard error. Request bytes and standard output are not
included in that error.

Export the historical activation report while running or after stop:

```sh
HyperNet runtime services activation-receipt --directory /Private/Service \
  --output /Private/ActivationReceipt.cbor
```

The manager verifies and imports that report with Suite's `activation-complete`
command. A verified report that connects to the manager's retained state can be
recorded locally; reconciliation with newer authority state requires a fresh
own-stream query. A historical receipt acknowledges the recorded effect and
cannot authorise another effect. `serviceReadiness: NotProbed` remains explicit.

## Stop, withdraw and retain

```sh
HyperNet runtime services stop --directory /Private/Service
HyperNet runtime services withdraw --directory /Private/Service
HyperNet runtime services withdrawal-receipt --directory /Private/Service \
  --output /Private/WithdrawalReceipt.cbor
```

Stop removes only resources whose recorded identities and configurations match.
It retains service data and both journals. A later start still needs a fresh
quorum response to its exact manager request. Foreground exit stops owned
resources; abrupt loss does not extend the workload's finite lifetime.

Withdrawal durably publishes the local veto before cleanup. Failed cleanup
cannot restore permission. Withdrawal is permanent for this installed profile.
Its signed receipt states whether cleanup completed; publish the restrictive
network withdrawal separately. Historical report export does not revive consent.

## Local exchange and authority changes

The Media, Mail, Transfer or Bridge client can pass a bounded packet through the installed
service without receiving its private socket directory or sharing a member key:

```sh
HyperNet runtime services exchange --directory /Private/Service \
  --packet /Private/Packet.cbor --receipt /Private/ServiceReceipt.cbor
```

The installed role selects its exact packet and receipt format. The response
requires independent client verification. There is no public proxy
and no automatic route discovery. See [AuthorityEpochs](AuthorityEpochs.md) for
the explicit stopped-service retained/seal/activate workflow. Both journals must
accept the same certified successor before restart. Selecting the new private
control route is an explicit local operation and never changes the trust pin.

A stopped Bridge also supports `requester-status --output FILE` and
`requester-fence --expected FILE --output FILE`. Both commands take its installed
`--directory`. Status exports the complete certified canonical metadata; fencing
requires that exact inspected comparison and an explicit operator invocation.
Current local consent remains required. The finite helper has no network
attachment, media mount, activation or listener. It leaves the Bridge stopped
and retains unknown outcomes, original Permits, recipient claims and cached
restrictions. See [Bridge](Bridge.md#operate-and-recover) for retry semantics
and the required response to unauthenticated pending cache state.
