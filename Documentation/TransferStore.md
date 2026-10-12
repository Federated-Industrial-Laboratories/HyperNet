# Transfer store operation

A transfer store is a separately consented role 4 runtime. Its service key,
operator key, deployment manager and participants have distinct authority. The
service is not enrolled as an ordinary member. The operator signs the exact
`AuthorityTransferProfile`; an admitted manager with capability 26 registers it
against the current deployment and host consent.

The profile identifies one writable volume, persistent byte admission, maximum
payload and maximum lifetime. It requires explicit opaque-content consent. One
complete encoded transfer must fit in a bank; the declared working set must fit
the role's memory admission. The runtime uses two durable banks within the exact
preallocated file. It validates size, ownership, single-link identity and an
exclusive lock before opening existing state. A damaged file cannot silently
become a new empty store.

## Configuration and setup

Prepare an owned private configuration directory containing `Bootstrap.cbor`,
`Manifest.cbor`, `Service.key`, `ServiceConfig.json` and `TransferProfile.cbor`.
`Service.key` is the raw 32-byte Ed25519 seed of the role 4 identity. The signed
bootstrap must already have been independently accepted. The manifest and
operator-signed transfer profile must exactly match the registered deployment.

`ServiceConfig.json` has exactly these paths:

```json
{
  "bootstrapFile": "/Config/Bootstrap.cbor",
  "manifestFile": "/Config/Manifest.cbor",
  "profileFile": "/Config/TransferProfile.cbor",
  "identityFile": "/Config/Service.key",
  "stateFile": "/State/TransferState.bin",
  "controlSocket": "/Authority/Control.sock",
  "clockWitnessFile": "/Clock/ClockHealth.cbor",
  "listenSocket": "/State/Control/Control.sock"
}
```

This installed profile declares no network endpoints or outbound routes. Its
only serving socket is private to the container. The separate authority control
mount contains no replica keys or authority state. The signed clock and exact
artifact acceptance are mounted read-only. Runtime state contains independent
requester and recipient journals; participant keys never enter it.

Run `HyperNet runtime services setup` with `--directory`, `--configuration`,
`--operator-key`, `--host-consent`, `--authority-directory` and `--clock-directory`.
The configuration directory contains the five artifacts listed above. The clock
directory contains the signed `ClockHealth.cbor` observation. Review
`runtime services preview`, record exact local consent, then prepare the
manager's activation request. Start with
`runtime services start --directory PROFILE --activation-request REQUEST`.
Start remains foreground. The runtime becomes active only after its separate
recipient journal verifies and durably claims that exact activation.

`runtime services status`, `stop` and `withdraw` operate on the selected profile.
Withdrawal records a local no-restart restriction and terminates the runtime;
submit the restrictive transfer-service withdrawal to authority separately.
Local withdrawal does not claim that remote authority or retained copies changed.
Activation and withdrawal receipts are available through their corresponding
`runtime services` commands. `Tools/TransferStore.sh` delegates to this same CLI.

Rootless namespaces, UID 1000, read-only root, no capabilities, no-new-privileges,
Landlock, seccomp, private PID/IPC and declared cgroup limits are mandatory.
Unsupported profiles fail closed. Guard checks bind the exact configuration,
local consent, generation, withdrawal, signed clock and absolute boot deadline.
The external runtime deadline also bounds a stopped process.

## Exchange and retained data

An independently signed participant packet can be forwarded without exposing its
key or host namespace internals:

```sh
HyperNet runtime services exchange --directory PROFILE --packet Packet.cbor --receipt Receipt.cbor
```

The wrapper verifies ownership and the running container, then forwards bounded
stdin to the fixed private socket under the service UID. It writes the bounded
receipt to a new private file. HyperNetSuite can use `--service-directory PROFILE`
to perform this exchange or export/import packet files explicitly.

Each accepted transfer consumes its complete encoded reservation. Put writes a
new bank and flushes it before publishing the bank header, then clears the old
bank. Commit checks complete ciphertext integrity. Delete clears ciphertext and
retains bounded chunk identities so an already claimed operation can be
reconciled without resurrecting data. Expired entries are pruned during later
successful effects; idle storage is not represented as secure physical erasure.
Backups, recipient copies and media remnants are outside deletion's guarantee.

Restore only a matching protected storage snapshot and its recipient journal
under the network's recovery rules. Never reset a floor or journal to make old
ciphertext usable. There is no automatic destructive recovery command.
