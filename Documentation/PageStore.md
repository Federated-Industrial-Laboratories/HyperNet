# Approved Page host

The installed role 1 Page host stores exact immutable source or opaque content
under an explicit durable content policy. Replica tickets name existing native
source placements and durable acknowledgements. It runs as the confined
service UID after current runtime activation. It has no public reader listener,
bind endpoint or outbound network endpoint. Its only authority connection is
an authenticated private control socket. Reader relay routes have a separate
privacy and admission contract.

The operator-signed `PageProfile.cbor` selects the exact admitted deployment,
service identity, writable volume, namespaces, physical state bytes, maximum
bundle size and retention. A manager must register it with current `HostPages`
and local runtime management rights. The daemon verifies the retained profile
against every certified maintenance result, and fresh operations stop after
host withdrawal or loss of the required grant or deployment consent.

## Preparation and startup

Use the installed service preparation and activation workflow. Preparation
creates the separate requester and recipient journals. A content-enabled host
reserves the partitions specified by its signed profile; see
[DurableContent.md](DurableContent.md). Legacy metadata profiles reserve
`/State/PageState.bin` within their admitted physical size. Startup verifies
both journals have completed the same authority epoch. The recipient journal
retains runtime activation and finite content effects. The requester journal
retains metadata maintenance where configured. Authority private keys and replica state are not mounted
into this service.

The fixed configuration fields are:

| Field | Confined path |
| --- | --- |
| `bootstrapFile` | `/Config/Bootstrap.cbor` |
| `manifestFile` | `/Config/Manifest.cbor` |
| `profileFile` | `/Config/PageProfile.cbor` |
| `identityFile` | `/Config/Service.key` |
| `stateFile` | `/State/PageState.bin` |
| `controlSocket` | `/Authority/Control.sock` |
| `clockWitnessFile` | `/Clock/ClockHealth.cbor` |

The configuration has no public listener. A content-enabled host exposes its
private local ContentExchange control socket. A successful activation confirms
permission to start; a signed copy acknowledgement confirms durable storage.
Successful retrieval requires a separate current finite read.

## Synchronisation and delivery

`PageSync` returns certified publication metadata, signed author and reviewer
statements, and exact content placement/copy/withdrawal records. It carries no
PageSource or PageBundle bytes. Hosts without a durable content policy can
maintain this metadata, but cannot receive new durable body placements.

Readers obtain current publication and host context with `PageReplicaContext`
under their own `ReadPage` grant, then create a short-lived `PageReplicaRequest`.
The requested host must be in the author's exact kind159 placement and have a
valid signed kind160 durable acknowledgement. The ticket can therefore resolve
immediately to that existing acknowledgement. This is not proof of a recent
successful retrieval. The reservation lasts at most sixty seconds and consumes
current reader/host concurrency budgets. Each operation checks current rights
and retains a1250-ms margin before ticket expiry.

`PageReplicaDeliver` remains an explicit metadata-only acknowledgement from the
exact selected host. It requires that host's existing exact signed copy receipt.
`PageReplicaResult` returns the ticket, publication and placement metadata, with
no body sidecar. The Suite uses its explicit private ContentRoutes mapping to
read from the ticket's exact host, verifies the signed source hash and metadata,
and reconstructs the exact author/reviewer Bundle. Only successful retrieval
reports `PageReplicaRetrieved` and can create an output file. Host loss, damaged
bytes, withdrawal or absent routes refuse retrieval; a ticket cannot substitute
for current serving authority.

Pending metadata operations retain their exact signed request. Restart resumes
that request, and an unknown outcome is not silently replaced or fenced. The
normal certified stream status and refusal rules control advancement. New
content effects use the durable recipient claim and explicit reconciliation
path; a retry cannot substitute another placement, host, effect or extent.

## Storage and interruption

Content-enabled hosts reserve their signed metadata, data, staging and quarantine
partitions before receiving bytes. Exact content objects live outside authority
state. Completion validates the source and declared assets/forms before signing
the durable receipt. Reads reconcile the stored digest before releasing bytes.
Withdrawal metadata precedes purge, and repair remains within the same exact
consented placement.

The metadata cache uses two committed banks with generation, length and checksum.
A torn successor recovers the last committed bank; damage without a recoverable
bank is an error. Legacy metadata maintenance no longer refills bundle bytes
from authority. Bridge caches have their own signed physical budget and retain
only explicitly transferred bodies. Cached bytes never extend publication,
ticket, host consent or grant validity.
