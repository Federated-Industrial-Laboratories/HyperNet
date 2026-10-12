# Approved Page host

The installed role 1 Page host maintains immutable approved bundles for its
consented namespaces and fulfils exact reader tickets. It runs as the confined
service UID after current runtime activation. It has no direct reader listener,
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
creates the separate requester and recipient journals and reserves
`/State/PageState.bin` to the exact admitted physical size. Startup verifies
both journals have completed the same authority epoch. The recipient journal
retains runtime activation; the requester journal retains the host's own finite
maintenance commands. Authority private keys and replica state are not mounted
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

The configuration has no `listenSocket`. A successful activation confirms
permission to start; a successfully delivered reader ticket confirms the complete
Page-host workflow.

## Synchronisation and delivery

`PageSync` selects current approved metadata and exact bundles for the host's
consented namespaces. The host verifies the quorum result, independently
re-evaluates the finite operation, checks complete publication provenance and
hashes, and commits bytes only through its durable requester permission. It
retains metadata and bundle bytes together before they can be used for delivery.

Readers obtain current publication and host context with `PageReplicaContext`
under their own `ReadPage` grant, then create a short-lived `PageReplicaRequest`.
The reservation lasts at most sixty seconds to cover the separate context,
queue, fetch, delivery and result operations. Every operation still uses its
own proof of at most five seconds and checks current permissions and the
ticket's remaining lifetime; the reservation grants no reusable permission.
This context operation grants no hosting or administration rights. The host
prioritises its current `PageReplicaQueue`, fetches an absent approved bundle,
and commits `PageReplicaDeliver` for the exact ticket. `PageReplicaResult`
returns the delivered bundle and exact media metadata under the reader's current
permission. A ticket or cached digest by itself cannot release content.

The host saves the exact pending request and retains the bundle needed to repeat
it. Restart resumes this request before new maintenance. A request with an
unknown result is not silently replaced or fenced. The normal authority status
and refusal rules determine when its stream can advance.
An expired ticket that has not yet been signed for delivery is skipped. If a
prepared delivery is refused, the host retains that outcome and obtains current
certified stream status. It resumes fresh maintenance only when status proves
that exact generation, sequence and intent originally finished with refusal,
and the durable floor releases the exact next slot. This also applies after a
restart, before selecting pending work. Unknown outcomes and unconsumed permits
remain pending; the host never automatically fences or substitutes their request.
Queue and synchronisation refusals still stop the service.
Completed maintenance reuses its exact retained completion and current-epoch
stream metadata for the next sequence. Initial use, an epoch change or an
unresolved disclosure refusal still requires certified status. Every maintenance
operation retains its own fresh challenge, quorum verification and local consent
checks; completing one operation does not authorise the next.

## Storage and interruption

The preallocated file contains two committed banks. Each bank has a fixed header
with generation, length and checksum. Publication syncs the new body before its
header, then retires the old bank. A torn successor recovers the last committed
bank; damage without a recoverable bank is an error, not an empty cache.

Physical admission, canonical encoding and the declared memory working set bound
storage. Optional expired or least recently used bundles can be removed to make
room. Bundles required by the exact pending delivery remain pinned, including
across interruption. If the pinned inputs and authenticated metadata cannot fit,
the host refuses the update instead of dropping recovery state. A fresh delivery
also checks the local retention deadline. Cached bytes do not extend publication,
ticket, consent or grant validity.
