# Confined federation bridge

A bridge transfers explicitly shared Pages between two independent networks.
It has two dedicated service identities, each with grant mask 9, and no incoming
listener. Both administrators accept the same one-way treaty. The source author
must share each exact publication, and the destination administrator must review
it before local members can read it. See [Federation.md](Federation.md) for the
wire protocol, limits and authority configuration.

The bridge is separate from ordinary hosting. Ordinary host consent cannot enable
federation. Bridge identities cannot publish Pages,
review submissions or administer either network. Neither bridge identity is an
authority voter or an authority attestation signer.

## Boundary and resource consent

The bridge requires the same rootless Podman, cgroup v2, subordinate UID mapping,
seccomp and Landlock profile as [Hosting.md](Hosting.md). It refuses missing
restrictions. Its image and configuration are read-only; writable state is a
bounded, non-executable tmpfs. It mounts no home directory, runtime socket,
display socket or host devices. Both signing identities and both client TLS
credentials are loaded before filesystem confinement. Core dumps are disabled.

One private internal network connects the bridge to two fixed relays. Each relay
accepts only the bridge's private address, and forwards only to its consented
literal IP address and port. Each has an explicitly selected egress network.
The relays have no signing, CA or TLS identity keys. Separate TLS clients verify
each original authority DNS name against only that endpoint's pinned CA; they
use TLS 1.3 and disable proxies, redirects and endpoint discovery. The consent
also binds the SHA-256 digest of the exact CA PEM file bytes.

The relays remain part of the isolation boundary. Their egress networks are not
per-address kernel firewalls. Container isolation shares the host kernel and
does not claim virtual machine isolation. A consenting bridge operator can
observe transferred plaintext in its process memory.

Bridge consent is one exact document signed by both service identities. Its
JSON object contains `payload`, `sourceSignature` and `destinationSignature`.
The payload is unpadded base64url JSON. Both signatures cover
`HyperNet/BridgeConsent/2`, a zero byte and the exact decoded payload bytes.
Its profile is SHA-256 of the complete document file, including any final newline.
Register that same file on both networks; do not reformat it afterward.

The payload is:

```json
{
  "version": 2,
  "service": "FederationPages",
  "agreementId": "ReplaceWithTreatyAgreementId",
  "treatyDigest": "ReplaceWithTypedTreatyDigest",
  "mediaProfiles": [],
  "mediaSourceHosts": [],
  "mediaDestinationHosts": [],
  "mediaMaxBytes": 0,
  "mediaRequiredCopies": 0,
  "media": [],
  "sourceNamespace": "Public",
  "destinationNamespace": "Guests",
  "source": {
    "network": "ReplaceWithSourceNetwork",
    "deviceKey": "ReplaceWithSourceBridgePublicKey",
    "authorityKey": "ReplaceWithSourceAuthoritySigningPublicKey",
    "authorityEndpoint": "https://source.example:8443/",
    "authorityAddress": "192.0.2.10:8443",
    "caCertificateDigest": "ReplaceWithSourceCaPemSha256"
  },
  "destination": {
    "network": "ReplaceWithDestinationNetwork",
    "deviceKey": "ReplaceWithDestinationBridgePublicKey",
    "authorityKey": "ReplaceWithDestinationAuthoritySigningPublicKey",
    "authorityEndpoint": "https://destination.example:8443/",
    "authorityAddress": "192.0.2.20:8443",
    "caCertificateDigest": "ReplaceWithDestinationCaPemSha256"
  },
  "expires": 1,
  "memoryBytes": 134217728,
  "pids": 32,
  "cpuQuota": 50000,
  "cpuPeriod": 100000,
  "stateBytes": 1048576
}
```

Replace the example identities, endpoint addresses and expiry. Network and key
identities, CA digests and the treaty digest are 32-byte lowercase hexadecimal
values; `agreementId` is 16 bytes. All four device and authority keys must differ.
The networks must differ. Namespace labels begin with an ASCII letter, contain
only ASCII letters and digits, and have at most 32 bytes. There are no wildcards.
The exact treaty fixes both namespaces, both networks, all four keys, Pages as
the service, `HyperNetPage/2` as the grammar, and the maximum expiry.

Consent expires within seven days and no later than the treaty or either service
membership. The resource ranges are 64 MiB through 8 GiB of bridge memory, 16
through 512 PIDs, CPU quota 1000 through 800000 microseconds per 100000-microsecond
period, and 1 MiB through 256 MiB of writable tmpfs. Effective cgroup and tmpfs
limits are checked against the signature. The bridge writes status only; it does
not persist page bodies. It retains at most 32 descriptors in memory, with at
most four page transfers in progress.

Consent additionally selects two fixed relay allowances. Each relay receives
128 MiB memory, 32 PIDs, half a CPU, 8 MiB tmpfs, 16 simultaneous connections and
an aggregate 1 MiB/s byte rate in both directions. Each connection direction is
limited to 16 MiB; idle reads expire after ten seconds and blocked writes after
five seconds. The bridge specification above therefore permits 384 MiB total
memory, 96 PIDs, one and a half CPUs and 17 MiB tmpfs across all three containers.
Logs are capped at 1 MiB per container. Image and private configuration storage
are installation overhead outside these runtime quotas.

Enabled media repeats the exact treaty's five media fields. Each `media` route
contains `network`, `hostKey`, `endpoint`, `address`, `caDigest`,
`certificateDigest` and `authoritySigner`, equal to the registered store consent.
Provide `MediaCa0.pem` through `MediaCa5.pem` in consent-route order as needed.
Each route adds a separately isolated relay with 128 MiB memory, 32 tasks, half a
CPU and 8 MiB tmpfs. It permits four connections at 1 MiB/s and 128 KiB per
connection direction. The helper generates runtime media route entries and pins
their relay addresses. The bridge never receives unrestricted network egress.

## Sign and register

Create separate Suite profiles for each bridge identity, including its network's
client TLS certificate. Admit each identity with grant mask 9. Configure each
broker's dedicated federation signing key and accept the exact treaty on both
networks before registration.

Use the independent Suite to inspect the treaty, sign local consent and register
that exact document on each network:

```sh
HyperNetSuite federation treaty Treaty.json
HyperNetSuite federation sign-consent --spec Specification.json \
  --treaty Treaty.json --source-identity SourceIdentity.json \
  --destination-identity DestinationIdentity.json --output Consent.json
HyperNetSuite --config SourceDevice/Profile.json federation register \
  --consent Consent.json --certificate SOURCE_CLIENT_DER_SHA256
HyperNetSuite --config DestinationDevice/Profile.json federation register \
  --consent Consent.json --certificate DESTINATION_CLIENT_DER_SHA256
```

The certificate argument hashes the DER-encoded client leaf certificate, while
the consent's CA field hashes the exact CA PEM file. Their roles differ. The
signing command is offline and reports the exact profile digest. Registration
checks the document, current membership, treaty, transport binding and expiry;
it cannot create a membership or enlarge the treaty.

## Initialise and operate

Prepare a private configuration directory with exactly these required files:

| File | Content |
| --- | --- |
| `Bridge.json` | Runtime configuration below |
| `Consent.json` | Exact dual-signed consent document |
| `Treaty.json` | The accepted treaty |
| `SourceIdentity.json`, `DestinationIdentity.json` | Separate Suite service identities |
| `SourceCa.pem`, `DestinationCa.pem` | Each network's pinned CA certificate |
| `SourceClient.pem`, `DestinationClient.pem` | Separate client TLS certificates |
| `SourceClientKey.pem`, `DestinationClientKey.pem` | Corresponding TLS private keys |

```json
{
  "consentFile": "/Config/Consent.json",
  "treatyFile": "/Config/Treaty.json",
  "stateDirectory": "/State",
  "media": [],
  "source": {
    "network": "ReplaceWithSourceNetwork",
    "endpoint": "https://source.example:8443/",
    "identity": "/Config/SourceIdentity.json",
    "caCertificate": "/Config/SourceCa.pem",
    "clientCertificate": "/Config/SourceClient.pem",
    "clientKey": "/Config/SourceClientKey.pem",
    "relayAddress": "192.0.2.1:8443"
  },
  "destination": {
    "network": "ReplaceWithDestinationNetwork",
    "endpoint": "https://destination.example:8443/",
    "identity": "/Config/DestinationIdentity.json",
    "caCertificate": "/Config/DestinationCa.pem",
    "clientCertificate": "/Config/DestinationClient.pem",
    "clientKey": "/Config/DestinationClientKey.pem",
    "relayAddress": "192.0.2.2:8443"
  }
}
```

`Initialise` copies only these named files, gives their staged copies to the
subordinate container ID, and rewrites all paths and both internal relay
addresses. The source directory stays under the operator's control. Use the
immutable image ID produced by [Package.sh](../Tools/Package.sh).

```sh
bash Tools/Bridge.sh Initialise /Private/BridgeProfile /Private/BridgeConfig \
  "$(cat /tmp/HyperNetPackage/ImageId.txt)" SourceEgress DestinationEgress
bash Tools/Bridge.sh Start /Private/BridgeProfile
bash Tools/Bridge.sh Status /Private/BridgeProfile
bash Tools/Bridge.sh Stop /Private/BridgeProfile
bash Tools/Bridge.sh Restart /Private/BridgeProfile
bash Tools/Bridge.sh Withdraw /Private/BridgeProfile
```

The egress arguments name existing Podman networks. The destination defaults to
the source egress network; omitting both selects `podman`. Each must reach only
its required authority destination for successful operation. Do not attach other
workloads to the bridge's private internal network.

`Start` acknowledges container creation. `Status` reports the process state and
its latest JSON status, including `active`, `code`, `objects`, `leaseExpires`,
`sourceEpoch`, `destinationEpoch`, `agreementId`, `profile` and confinement
measurements. Readiness requires a running process, `active` set to true and an
unexpired `leaseExpires`. `objects` counts refreshed imports, including pending
or suppressed items; it does not mean those objects have destination approval.
An empty permitted inventory can be active with zero objects.

Each round obtains a fresh bilateral inventory. Each group of at most four pages
then obtains new destination permits and source exports concurrently. Imports
are ordered by source authority revision to prevent rollback. An unchanged
descriptor renews evidence without retransmitting its page bundle. Changes or
restarts require full proof and bundle verification. The bridge waits half a
second between rounds and bounds each HTTP operation to two seconds. A network
must complete its selected page inventory within the signed freshness interval;
higher latency or contention can reduce practical capacity below 32 pages.
Readiness fails closed instead of extending an expired lease.

Source exports and destination permits last at most five seconds. Both proofs
bind the same exact consent profile. Importing and reading recheck current local
permission and remote signed evidence. A broken path, consent withdrawal, quorum
loss or invalid reply clears bridge readiness; previously imported content stops
being readable when its evidence expires. Backwards wall-clock movement stops
the process. Destination review remains independent, and imported content cannot
be re-exported as native content. Already delivered bytes cannot be recalled.

`Withdraw` serializes against startup, writes a local tombstone, kills all three
containers and removes them without contacting either network. A withdrawn
profile cannot restart. For remote withdrawal, use `federation withdraw-consent`
with each service's Suite profile. Stop locally first when immediate termination
is required. A normal stop and restart retains consent but discards volatile
state and obtains fresh authority decisions before reporting readiness.

Remove a stopped profile's named internal network and private profile directory
when no longer needed. Subordinate-owned configuration files may require
`podman unshare` for removal. Remove the adjacent `Lifecycle` directory only when
all lifecycle commands have exited. Do not remove the original identities or
unrelated Podman images, networks or containers.

Container supervisors enforce the remaining signed consent lifetime for each
process, including every relay. Relays also close their listeners and existing
streams at the absolute expiry, or on backwards clock movement. A stopped,
failed or unresponsive service cannot extend a sibling relay beyond its runtime
limit. Existing profiles should be reinitialised to add the relay deadline;
starting them with the updated launcher still applies the container timeout.
