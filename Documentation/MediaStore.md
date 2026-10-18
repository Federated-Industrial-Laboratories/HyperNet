# Media store operation

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

A media store is a separately consented role 2 runtime. Its service identity is
separate from the deployment manager, operator, author and reviewer. The operator
signs an `AuthorityPageHostProfile` for the exact admitted deployment, volume,
namespaces, retention, physical state bytes and maximum individual asset size.
An authorised manager registers that profile against current host consent.

The store accepts only finite `PageMediaAuthorise` requests for the exact asset
and selected host references. Uploads, reviewer inspections and reader fetches
require separate current permissions. A complete-copy receipt proves that the
selected host validated and stored those immutable bytes; it is not approval
of the Page or media's visual content. The designated reviewer inspects the
complete asset and submits its explicit decision separately.

## Fixed configuration

Prepare a private directory containing exactly `Bootstrap.cbor`, `Manifest.cbor`,
`Service.key`, `ServiceConfig.json` and `MediaProfile.cbor`. The key is the role 2
identity's raw 32-byte Ed25519 seed. The bootstrap must already have been
independently accepted, and its file digest must match the manifest. The
operator-signed profile must match the exact registered deployment.

`ServiceConfig.json` contains only these fixed paths:

```json
{
  "bootstrapFile": "/Config/Bootstrap.cbor",
  "manifestFile": "/Config/Manifest.cbor",
  "profileFile": "/Config/MediaProfile.cbor",
  "identityFile": "/Config/Service.key",
  "stateFile": "/State/MediaState.bin",
  "controlSocket": "/Authority/Control.sock",
  "clockWitnessFile": "/Clock/ClockHealth.cbor",
  "listenSocket": "/State/Control/Control.sock"
}
```

Use the shared [installed service workflow](ServiceRuntime.md) to import,
preview, consent, activate, stop or withdraw this profile. The clock directory
contains `ClockHealth.cbor` directly. The installed role declares no network
endpoints or TCP egress. It runs as PID 1 under UID 1000 in a rootless namespace,
with a read-only image, private state, Landlock, seccomp and the signed cgroup
limits. Only the authority's isolated control socket is mounted; its keys and
replica journal are never shared. Participant and reviewer keys remain with
clients.

## Upload, inspect and read

An upload names a bounded byte range and its raw SHA256 digest in the signed
request. The store checks those exact bytes before seeking a fresh quorum proof.
It durably claims the recipient effect before writing. Chunks must be contiguous;
an exact retry may repeat existing bytes but cannot replace them. Each chunk is
at most 32768 bytes. Bitmap and restricted-vector asset limits remain those of
the canonical [media format](PageMedia.md).

The final chunk triggers the complete existing asset decoder and whole-asset
SHA256 check. Only successful complete validation creates a signed copy receipt.
An invalid final chunk leaves the previous committed partial upload intact.
Inspection and read requests return ranges only from complete validated assets,
with the immutable complete-copy receipt. Static asset bytes remain outside
consensus. Animation presets run in the client; rendered frames are never sent
by this store.

Clients can export a signed packet or invoke the installed wrapper:

```sh
HyperNet runtime services exchange --directory /Private/Media \
  --packet /Private/Packet.cbor --receipt /Private/Receipt.cbor
```

The wrapper transfers only a bounded packet through the exact running service's
private socket. A packet is `[200,1,"MediaExchange",signedIntent,chunkBytes,reconcile]`.
Read and inspection packets contain no chunk bytes. The result requires independent
client verification of the quorum proof, exact effect, selected host signature,
range and digest. A receipt reports a historical effect and grants no new access.
An uncertain claimed request requires explicit exact reconciliation; a new effect
requires a new intent. No direct remote-reader route is supplied.

## Storage and recovery

`state_bytes` is the total physical preallocated media file. Two banks preserve
the previous committed state until its successor is flushed. Each bank's usable
serialized extent is half the physical file minus its 64-byte commit header.
Admission also accounts for the canonical state header, complete asset bytes,
metadata and signed copy receipt; it never treats both banks as payload capacity.
The declared working set must fit the service's memory admission.

Startup validates ownership, mode, exact size, single-link identity, exclusive
lock and committed checksums. An interrupted unpublished bank is discarded only
when the other committed state remains valid. Corruption cannot silently create
an empty store. Completed receipts survive restart and exact chunk retries.
Expired entries are pruned during subsequent successful effects; this does not
claim physical erasure of backups or media remnants.

Retain the media file with its recipient journal and independently accepted
bootstrap. Do not reset a journal to regain access to old data. Healthy committee
replacement uses the stopped-service epoch workflow for both requester and
recipient journals. Durable placement and sealed hosting are separate contracts;
this local store does not promise either merely by writing a copy receipt.
