# Static page media

Page media uses dedicated hosts, permissions and storage. An approved page binds
each asset's profile, dimensions, exact byte length, digest, host identities and
required copies. The page also binds alternative text and local motion presets.
The network transfers static assets. Viewers generate all animation frames locally.

`HyperNetRaster/1` contains exact row-major RGB bytes. `HyperNetVector/1` contains
bounded typed geometry. The [HyperPage contract](HyperPage.md) defines both profiles.
Media stores validate the complete canonical object before sealing it. They never
parse image codecs, SVG, XML, fonts, stylesheets or executable content.

## Authority configuration

Use current authority state schema 9. Existing schemas are rejected. Every broker
that serves media needs a `pageMediaSigningKey` configuration path. Its Ed25519
identity must differ from membership, TLS, federation, mail and service identities.
The isolated authority helper expects `PageMediaSigningKey.json` beside its config.
Media permissions never accept a mail, transfer or page-read signing domain.

The administrator sets `PageMediaPolicySet {minimumCopies}` to a value from 1 to 3.
The default is 1. A submitted manifest must require at least this floor. Approval
requires both the manifest count and the current administrator floor. Counts are
host identities; two hosts on one physical machine do not prove independent uptime.

## Host consent and isolation

A separate member identity with exactly `Member | Host` registers a signed
`PageMediaHostRegister {consent}` request over its registered mutual TLS identity.
Renewal cannot reduce capacity, namespace scope or retention below outstanding
reservations. Withdraw the host consent to stop service before those limits end.
The consent uses domain `HyperNet/PageMediaHost/1`, one zero byte, the network
identity, signer identity and exact payload bytes, as defined for service objects.
Its strict camelCase fields are:

- `version: 1`, `network`, `hostKey`, `generation`, `services: ["PageMedia"]`.
- `endpoint`, `address`, `caDigest`, `certificateDigest` for the store listener.
- `authorityEndpoint`, `authorityAddress`, `authoritySigner` for its fixed broker.
- `memoryBytes`, `pids`, `cpuQuota`, `cpuPeriod`, `stateBytes`, `expires`.
- `namespaces`, a sorted nonempty list of at most 16 page namespaces.
- `retentionSeconds`, from 1 through 604800 seconds, measured from reservation.

Endpoints are HTTPS roots. The signing identity differs from its TLS key. State
capacity is 8 through 64 MiB in 4096-byte units. Resource bounds match the confined
transfer store. Consent expires within seven days. Renewal increments generation;
previous generation receipts do not satisfy approval until the objects are checked
again at the renewed host.

`Tools/PageMediaStore.sh` provides Initialise, Start, Stop, Restart, Status, Renew
and Withdraw operations. It creates one restricted worker and a fixed-destination
broker relay. The worker has a read-only root, no capabilities, private namespaces,
resource limits, seccomp and Landlock. Only `/State/PageMediaState.bin` is writable.
Configuration is loaded before confinement. The preallocated state file is private,
owned, not linked, locked and exactly the consented size. A two-bank checksum and
fsync protocol recovers the last committed state without accepting damaged storage
as a new empty store.

The configuration file is `PageMediaStore.json`:

```json
{"network":"NETWORK_HEX","identity":"/Config/Identity.json","consentFile":"/Config/Consent.json","authorityCa":"/Config/AuthorityCa.pem","certificate":"/Config/Client.pem","privateKey":"/Config/ClientKey.pem","caCertificate":"/Config/Ca.pem","stateFile":"/State/PageMediaState.bin","listen":"0.0.0.0:8443","relayAddress":"192.0.2.1:8443"}
```

The helper pins all mounted names and supplies the actual isolated relay address.
Its authority relay overhead is separately bounded at 128 MiB memory, 32 tasks
and 0.5 CPU. `pageMediaCacheBytes` in ordinary page-host consent stays zero: those
workers do not receive media storage rights. A PageMedia identity is required.

## Upload, review and read

`PageSubmit` atomically reserves the manifest against live namespace-scoped hosts.
No payload enters authority metadata. Each reservation charges its full logical
bytes plus 4096 bytes of metadata allowance to every selected host. The aggregate
allowance is at most one quarter of the host file capacity minus 64 KiB. This
leaves room for base64, receipts, metadata and two durable banks. No deduplication
reduces a logical charge. Each author has at most eight pending assets and 8 MiB
reserved pending bytes. The authority tracks at most 256 active asset references.

Unfinished uploads expire within 24 hours. All media expires by the shortest
consented retention or selected host expiry. A new source revision needs a new
reservation. An expired or withdrawn reference cannot silently revive through a
fresh upload request.

The store accepts only `POST /V1/PageMedia`, with JSON `{operation,payload}`.
`operation` is a signed envelope in domain `HyperNet/PageMediaOperation/1`.
`payload` is unpadded base64url for Put, and null for other actions. The operation
contains these strict fields:

```text
version, network, operationId, issuedAt, hostKey, agreementId, admission,
pageId, revision, assetId, sourceDigest, action, offset, chunkBytes, chunkDigest
```

Native references use null `agreementId` and `admission`. Put and Fetch use aligned
32768-byte chunks; only the final chunk may be shorter. Status and Seal require
zero offset and count and null chunk digest. Put binds its exact chunk digest.
Each request obtains a fresh authority permission for this exact signed operation.
A permission lives at most five seconds and is bounded by every applicable consent,
reference and membership deadline. The SPARK policy checks chunk range arithmetic.

Status supports resume. Repeating the same offset with the same bytes succeeds;
changing those bytes fails. Seal checks exact length, dimensions, profile and SHA-256
before returning a durable Complete receipt. Receipts use the independent domain
`HyperNet/PageMediaReceipt/1`; permissions and cleanup policies use their respective
`HyperNet/PageMediaPermission/1` and `HyperNet/PageMediaPolicy/1` domains.

The author registers a sealed receipt with `PageMediaReceipt`, binding agreement,
page, revision and asset. Before approval, a reviewer retrieves every asset, verifies
all bytes independently, examines its static representation and registers a Fetch
receipt in a signed `PageMediaReceipt` command. That command is the reviewer's
attestation of inspection. The final chunk receipt alone is not proof that a human
examined the content. Applications need explicit `MediaInspect` consent in addition
to page review rights. A storage receipt by itself cannot approve content.

Readers need a currently approved referring revision. Applications need explicit
`MediaRead`; publishers need `MediaSubmit`. A digest by itself grants no access.
The original author can explicitly fill another selected host for an approved
revision, under the reserved quota. Ordinary readers cannot upload replicas.
Withdrawal denies fresh permission immediately. Existing leases are at most five
seconds and end sooner at a pending upload deadline or a publication signer's
membership, application or application-owner expiry. Foreign publication access
also ends at the local reviewer's expiry and the source export deadline.
Downloaded or hostile copies cannot be erased remotely. Cleanup retains
an object only while its exact referring revision remains valid and unexpired.
Authority outages deny reads and uploads without treating them as deletion consent.

## Federation

Federation treaty version 2 and bridge consent version 2 explicitly name media
profiles, source and destination host identities, per-page bytes and required
copies. Empty media scope grants no media rights. The source page manifest remains
unchanged; destination placements are separately bound by the treaty. Each media
route pins its network, host identity, HTTPS endpoint, address, CA, certificate and
media authority signer. The bridge uses an isolated fixed relay for each route.

Source Fetch requires current source publication, author sharing consent, bridge
consent and a fresh destination admission. Destination Put and Seal require the
current imported revision and its fresh source export proof. The bridge transfers
bounded static chunks and independently validates complete bytes before upload.
Destination approval requires its own complete copies and moderator inspection.
A source outage or withdrawal makes the destination reference unavailable after
its short export lease; retained physical bytes do not become independently public.
Neither treaty nor bridge consent version 1 acquires these permissions.
