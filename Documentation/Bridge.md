# Bridge service

A role7 bridge connects its own network's current authority to explicitly
consented counterpart bridges. Install a separate service in each network.
Never lend one network's member, authority or service key to the other.
[Federation.md](Federation.md) defines bilateral acceptance, publication and
canonical proof contracts.

Before each bilateral lease, the source Anchor exchange certifies the selected
Page or bounded inventory metadata with its own role7 identity. This prepares a
cold cache before destination Admission starts. Source Export then uses that
prepared authenticated context, with current exact-dependency checks at commit;
it does not issue another general agreement lookup inside the fresh proof chain.
Page-specific destination Admission returns the agreed media hosts, their current
consent and governance dependencies, namespace placement policy and any existing
qualified import state. The Bridge verifies this certified context before Import,
including after restart. It cannot supply unsigned records to fill its cache.
Inventory packets bind the exact certified share IDs and their final cursor.
Withdrawn rights or changed publications refuse the protected operation rather
than reusing a historical export grant.

Admission, Export, Import, grant-free media authorisation and media maintenance
receipts use a fixed challenge budget of at most 15000 ms. Each dependent step
inherits the earliest certified expiry. Ordinary reader and reviewer operations,
context lookups and stream controls retain the 5000-ms budget. The longer
maintenance profile allows serial decisions but increases the maximum interval
before an unknown remote revocation stops an already issued permission. Known
revocation and local withdrawal still refuse immediately. Retries never extend
an existing signed challenge. A multi-Page sync obtains separate bounded chains
for each Page or media extent; it has no single global freshness lease.

## Prepare the service

Use a dedicated role7 service identity and operator-signed manifest. The manifest
has one writable state volume, one explicit IPv4 TLS listener and literal
counterpart endpoint addresses/ports. Each counterpart includes its service key,
transport public key and exact TLS leaf. Ports are unprivileged. The profile
names the exact accepted treaty IDs and digests, selected volume and physical
state budget. Host admission, current manager26, registrar13 and local operator
consent remain separate checks.

TLS is version1.3 with mutually verified certificates and exact consented leaves.
Use a CA accepted for both endpoint certificates, or a bounded CA bundle accepted
by both operators. Certificates must authenticate the literal endpoint addresses.
The service has no proxy, redirect, DNS-discovered URL or Page-provided route.
TLS private keys remain only in the service's own private configuration.

Create a private configuration directory containing exactly:

```text
Bootstrap.cbor
BridgeProfile.cbor
Certificate.pem
CertificateAuthority.pem
Manifest.cbor
Service.key
ServiceConfig.json
Transport.key
```

`Service.key` is the raw32-byte role7 signing seed. `Bootstrap.cbor` is the
independently accepted own-network bootstrap. The other keys are distinct
according to the manifest's permanent role rules. ServiceConfig.json is:

```json
{
  "bootstrapFile": "/Config/Bootstrap.cbor",
  "manifestFile": "/Config/Manifest.cbor",
  "profileFile": "/Config/BridgeProfile.cbor",
  "identityFile": "/Config/Service.key",
  "stateFile": "/State/BridgeState.bin",
  "controlSocket": "/Authority/Control.sock",
  "clockWitnessFile": "/Clock/ClockHealth.cbor",
  "listenSocket": "/State/Control/Control.sock",
  "certificateFile": "/Config/Certificate.pem",
  "transportKeyFile": "/Config/Transport.key",
  "certificateAuthorityFile": "/Config/CertificateAuthority.pem",
  "mediaHosts": []
}
```

For media, mediaHosts is a sorted list of lowercase32-byte local role2 service
keys in hexadecimal. Each must have an explicit `--media-service
HOSTKEY=INSTALLED_DIRECTORY` setup argument. Setup checks the exact installed
role2 profile and own network/incarnation. The service receives only that
store's isolated Control directory at `/Media/HOSTKEY/Control`; it receives no
store state, member key or authority key. Generated MediaBindings.json binds the
exact source directories/profile digests to local operator consent. Container
fingerprints also bind the actual mounts.

Only the Bridge confinement profile admits these exact media Control directories.
Parent directories, store state and substituted paths remain inaccessible. Other
service profiles do not gain media mounts.

## Install, consent and activate

Use `HyperNet runtime services setup` with `--directory`, `--configuration`,
`--operator-key`, `--host-consent`, `--authority-directory` and `--clock-directory`.
The authority directory supplies only its private Control directory. The clock
directory supplies the signed ClockHealth.cbor witness. Add the explicit media
service mappings when applicable.

Review `runtime services preview`. Consent to its exact profile digest using
`runtime services consent`. Start with the manager's exact quorum activation
request using `runtime services start --activation-request`. The service stays
under foreground supervision. It opens no listener until local consent,
confinement and activation succeed. `status`, `stop`, `withdraw`,
`activation-receipt` and `withdrawal-receipt` use the same installed lifecycle as
other finite services.

The rootless container uses a private network with the consented published
listener, no shared host PID namespace, a read-only root, denied capabilities,
seccomp and Landlock. Only role7 gets its explicit TCP egress. Its dedicated UID
is1000, with private requester/recipient journals and fixed state paths. The
bridge's own clock, local withdrawal and activation are rechecked throughout
operation. Storage is physically preallocated; working memory includes the
old/new bank and encoding budget.

## Operate and recover

The Suite `federation bridge sync` command asks the destination bridge to import
shared Pages. The bridge issues current local Admission and remote Export,
imports the exact bundle, fetches source media, checks the complete asset digest
and decoder, then uploads to the treaty's destination stores. Each store returns
its own whole-asset copy receipt. This leaves the Page pending local review.
`federation inspect`, `review-sign`, `review`, `read` and `media inspect/read`
retain the separate local participant's rights and exact inspected revision.

The installed local operator exchange is:

```text
HyperNet runtime services exchange --directory SERVICE \
  --packet PACKET --receipt RESPONSE
```

The bridge Control socket accepts these canonical packets:

```text
[200,1,"BridgeLease",agreementId,sourcePage16?,native141?,afterShareId?,
 localTrust150Bytes,localFloor157Bytes,includeBundle]
[200,1,"BridgeSync",agreementId,sourcePage16?]
```

Responses are respectively
`[201,1,"BridgeLease",proofBytes,objectSidecar]` and
`[201,1,"BridgeSync",qualifiedPageIds]`. The private socket requires the same
UID and existing private-directory/socket checks. A lease is inert until the
participant independently verifies it and its local authority permits the
requested operation. No unsigned local packet grants member authority.

Peer TLS accepts only finite Anchor, Export and Media packets from the treaty's
exact counterpart. Destination coordination obtains an Admission before asking
the source for Export; the source does not call back into the waiting destination.
Every proof/effect has its own existing monotonic deadline. A multi-Page local
sync is bounded by service consent validity, without replacing those per-effect
freshness checks.

The bridge retains authenticated metadata, exact immutable bundles, its requester
stream and the current upload payload. A restart resumes the retained operation;
it cannot skip an uncertain effect or silently choose another request. If its
original rights or proof expire, inspect its exact requester state while stopped:

```sh
HyperNet runtime services stop --directory /Private/Bridge
HyperNet runtime services requester-status --directory /Private/Bridge \
  --output /Private/BridgeExpected.cbor
```

The status prints the current generation and original completion, when known.
Its output file contains the complete certified canonical own-stream metadata.
Review that exact snapshot before choosing to fence the old requester generation:

```sh
HyperNet runtime services requester-fence --directory /Private/Bridge \
  --expected /Private/BridgeExpected.cbor --output /Private/BridgeFenced.cbor
```

The comparison includes the entire metadata, including the retained completion;
the generation number alone is insufficient. Changed metadata refuses a new
fence. Inspect it again and make a new explicit decision. If a fence response is
lost, repeat the command with the same expected file: the journal retains the
exact signed fence. A completed retry checks its exact certified predecessor
instead of creating another generation.

Fencing permits a later request in a new generation. It does not establish
whether an old operation occurred, repeat an effect, restore withdrawn rights,
or extend a foreign proof. Unknown outcomes and known original Permits remain
in the requester journal. Recipient claims, cached restrictions and immutable
payloads remain intact. The exact signed request for an archived original
Permit preserves authentication of its predecessor cache after an interrupted
publication. Those references authenticate historical bytes only: current
generation floors still reject stale results and permissions. Cache records
without current or exact original-Permit authentication block fencing; preserve
that state. Never delete journals or reset a service identity to bypass an
uncertain outcome.

These commands require current local consent and an initialised, stopped role7
service. Their finite confined helper has no network attachment, media control
mount, activation or listener. It signs only its own stream controls and checks
the existing authority proofs, local withdrawal and clock bounds. A successful
fence leaves the service stopped. Start it normally with its manager activation
request before issuing another sync.

Historical bytes remain inert. Local `withdraw` prevents subsequent service work
without needing an online counterpart.

Stop the service before `runtime services epoch retained/seal/activate`. Migrate
both requester and recipient journals to the same certified own-network
committee, then select that committee's exact private authority directory.
Counterpart epoch adoption is a separate FederationForeignSeal/ForeignActivate
operation over its own accepted150/157 state. A changed incarnation is a new
independent trust decision.

TLS handshakes and frame reads run independently of the local coordinator. The
admitted connection and concurrent-operation limits bound pending ingress; the
remaining signed memory budget can reduce that count. One requester journal
still serializes all authority effects. Waiting for the other bridge does not
prevent an authenticated inbound request from reaching that journal.

The current media upload extent is committed inside the same physical two-bank
state file before its request is retained. A restart uses those exact bytes and
an explicit idempotent recipient reconciliation. A retry within one exchange
keeps the original monotonic deadline. Reconciliation cannot extend an expired
foreign proof or create another intent for an uncertain effect.
