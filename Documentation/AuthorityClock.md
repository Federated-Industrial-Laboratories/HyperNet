# Authority clock observation

The local clock monitor measures a bounded system-clock error using a configured
chrony Unix socket. It sends only `tracking`, `sources`, `authdata` and `ntpdata`.
It does not adjust the system clock. The trusted chrony configuration must use
NTS for every source; the selected and combined sources must report authenticated
samples. Authentication identifies the source but does not prove its accuracy.

Create a private owner directory containing `ClockConfig.json`:

```json
{
  "chronyc": "/usr/bin/chronyc",
  "socket": "/run/chrony/chronyd.sock"
}
```

Both paths must be absolute and canonical. The executable and all containing
directories must resist replacement by another account. The local socket must
belong to root or the operator and must not be writable by other accounts.
The configuration must be a private owner file; its directory must be private.
A comma-separated socket or network fallback is rejected.

```sh
HyperNet authority-clock observe --directory /Private/Clock
HyperNet authority-clock status --directory /Private/Clock
HyperNet authority-clock monitor --directory /Private/Clock
```

`observe` publishes one observation. `status` reports current readiness.
`monitor` refreshes observations until stopped and reports readiness changes.
Only one monitor may own the directory at a time. A failed measurement does not
extend the previous observation's validity. Stopping the monitor therefore makes
its observation unusable after its original one-second lifetime.

Observation files use atomic replacement without a durable filesystem flush.
Their authority ends at the original boot-clock deadline; restoring an old file
cannot renew it. Missing or incomplete files refuse readiness. Monitor identities,
configuration, authority journals and client history floors retain their durable
storage requirements. Publication checks freshness again before reporting success.
An observation opened before replacement remains readable after the old file is
unlinked. Its original signature, monitor and boot pins, bounds and expiry still
apply. Readers reject multiple hard links; private observations also retain their
owner and permission checks. This exception applies only to clock observations.

The profile accepts chrony 4.5 and 4.6 CSV report shapes. It checks source
identity, reference age, authentication, leap state and frequency uncertainty.
The error bound includes system offset, root dispersion, half root delay,
measurement duration, wall/boot-clock progression, upward rounding and holdover.
It must remain within 250 milliseconds. The measurement itself is limited to
500 milliseconds, and its reference sample must be at most 120 seconds old.
The holdover calculation assumes a maximum 1000 ppm oscillator error.

The host kernel, monitor, configuration and selected time source are trusted for
these guarantees. A restored file from another boot, stale observation, clock
step, unsupported leap transition or unknown report shape refuses. Never mount
a privileged chrony command socket into an untrusted service container. The
host-owner observation interface requires the same operating-system UID.

For a rootless container, add `exportDirectory` to `ClockConfig.json`. Use a new
absolute directory beneath the private monitor directory, such as
`/Private/Clock/Public`. Initialise its separate signing identity once:

```sh
HyperNet authority-clock initialise-export --directory /Private/Clock
HyperNet authority-clock monitor --directory /Private/Clock
```

Initialisation reports the public monitor key and current host kernel boot ID.
The private `ClockSigner.json` stays outside the export directory. Only the
export directory is mounted read-only into the replica. Its signed
`ClockHealth.cbor` is readable across subordinate UID mappings; it contains no
signing key or chrony credentials. Do not mount the monitor's parent directory
or chrony socket into the container.

The replica clock configuration selects one explicit source:

```json
{
  "kind": "Signed",
  "path": "/Clock/ClockHealth.cbor",
  "publicKey": "INDEPENDENTLY_PINNED_MONITOR_KEY",
  "kernelBoot": "CURRENT_HOST_KERNEL_BOOT_ID"
}
```

The alternative `Private` source has only `kind` and `path` and requires a
private observation file owned by the reading UID. There is no fallback between
the two sources. A signed source verifies its exact monitor key, host boot,
canonical schema, original one-second lifetime and local wall/boot progression.
Signatures do not increase the observation lifetime or make the time source
more accurate. The host supervisor must pin the current host boot on each
deployment start; a container-specific boot ID is not a substitute. The reader
and monitor must share the same boot-clock scale. Time-namespace offsets are
unsupported and fail progression checks.

```sh
HyperNet authority-clock verify-export \
  --observation /Clock/ClockHealth.cbor \
  --monitor-key INDEPENDENTLY_PINNED_MONITOR_KEY \
  --kernel-boot CURRENT_HOST_KERNEL_BOOT_ID
```

This verifies the same observation used by replica admission. Changing the file,
using another monitor or boot, stopping refresh, or exceeding the error bound
refuses readiness. Initialisation never replaces an existing monitor identity.
