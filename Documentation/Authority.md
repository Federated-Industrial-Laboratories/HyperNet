# Authority operation

HyperNet separates trusted administration from ordinary hosting. A broker
accepts signed commands, enforces permission and consent, and commits authority
state through etcd. Three explicitly trusted etcd voters provide crash-fault
ordering and durable replication. Ordinary hosts have no etcd credentials,
administrative vote, CA signing key or access to the authority database.

This profile tolerates one unavailable voter in a three-voter cluster. It does
not tolerate a malicious voter or a compromised broker as Byzantine faults.
Separate machines, power and storage are needed for independent failure domains.
Three processes on one machine exercise the protocol but do not provide that
hardware availability. Broker ingress can run on multiple confined systems;
each uses its own local rollback floor and state lock. Clients explicitly select
a broker endpoint. Automatic client endpoint discovery is not provided.

## Provision the trust roots

Create independent CA keys for the public authority endpoint, hosting transport
certificates, and etcd peer/client transport. Keep these keys offline. Use a
maintained OpenSSL installation to issue certificates with explicit server or
client extended-key usage. A hosting transport certificate is not membership:
the matching device must also redeem an invitation, hold a hosting grant, and
record its local consent and certificate fingerprint.

Configure etcd 3.6.15 or a subsequently qualified compatible maintenance release.
Run three voters with unique peer identities, persistent private storage, mutual
TLS for peers and clients, and `--tls-min-version=TLS1.3`. Restrict peer ingress
to the registered voters and client ingress to the authority brokers. Use etcd
authentication and grant each broker identity read/write permission only on
`/HyperNet/<network>/Authority` and the prefix `/HyperNet/<network>/Pages/`.
Federation also requires read/write access to `/HyperNet/<network>/Federation/`.
Keep the root administrative credential outside
the broker container. The broker also checks the cluster's registered voting
membership; three, five or seven voters are accepted. Learners do not count.

The broker uses a dedicated etcd namespace and performs a linearizable read
before every operation. A compare-and-swap transaction checks the exact state
revision before committing. Invitations, grants, revocations, consent, page
publication and idempotency receipts therefore share one ordered history. No serializable read,
local permission cache, timestamp merge or unilateral fallback grants access.
The broker installs a TLS-1.3-only cipher provider for its etcd client as well as
its ingress listener; dependency feature unification cannot re-enable TLS 1.2.
Loss of quorum returns an unavailable result, including for status and existing
hosting heartbeats. A connection failure after a commit is an uncertain result;
retry the same signed request within its validity window.

## Initialise a network

Generate a 32-byte random network identifier and an administrator Ed25519 device
key with an independent compatible client. Protect private key files with mode
0600. Create a mode-0700 directory for the broker's rollback floor. Store the
following JSON configuration in a private configuration directory:

```json
{
  "network": "replace-with-64-lowercase-hexadecimal-characters",
  "listen": "0.0.0.0:8443",
  "stateDirectory": "/State",
  "certificate": "/Config/AuthorityCertificate.pem",
  "privateKey": "/Config/AuthorityKey.pem",
  "clientCa": "/Config/HostingCa.pem",
  "etcdEndpoints": ["https://10.20.0.11:2379", "https://10.20.0.12:2379", "https://10.20.0.13:2379"],
  "etcdCa": "/Config/VoterCa.pem",
  "etcdCertificate": "/Config/BrokerCertificate.pem",
  "etcdKey": "/Config/BrokerKey.pem",
  "etcdServerName": "Voter.example"
}
```

The addresses are deployment examples, not defaults. The endpoint IP addresses
avoid a resolver inside the restricted process. `etcdServerName` must match an
explicit SAN in every configured voter certificate. Voters use one common
verified service name and separate private transport keys. Do not use a public
CA bundle or disable certificate verification. The listen address is explicit;
publish it only through the deployment's configured ingress limits.

For initialisation, use a configuration with the real host-side paths to these
files and the initial private state directory. This command opens no ingress
listener:

```sh
HyperNet initialise --config /Private/InitialAuthority.json --admin-key PUBLIC_KEY_HEX
```

It atomically creates a previously absent network namespace and records the
cluster identity, revision and observed time in `AuthorityFloor.json`. It refuses
to replace an existing namespace. The administrator's public key is not a secret;
its private key remains in the client. The initial administrator has membership,
hosting and administration permission bits without an expiry. Hosting consent
nevertheless requires a separate device key without administration permission.
Subsequent membership renewals are limited to seven days.

Prepare a configuration directory containing `Authority.json`,
`AuthorityCertificate.pem`, `AuthorityKey.pem`, `HostingCa.pem`, `VoterCa.pem`,
`BrokerCertificate.pem` and `BrokerKey.pem`. Only those named files are copied.
Keep CA private keys and etcd root-administrator credentials outside that
directory and outside the broker.

Federation requires a separate online Ed25519 signing identity. Add
`"federationSigningKey": "/Config/FederationSigningKey.json"` to `Authority.json`
and place `FederationSigningKey.json` in the configuration directory. Its private
JSON format is `{"secretKey":"32-byte lowercase hex","publicKey":"32-byte lowercase hex"}`.
The installer copies that exact named file and rewrites its container path.
For direct network initialisation, use the actual host-side path instead.
The key must never be an administrator, member, hosting or bridge identity.
Publish its public key through an independently authenticated channel for treaty
verification. Every broker serving a treaty must use the treaty's pinned local
signer. Protect this key as authority material; compromise permits false local
attestations. It is not a CA key and cannot mint transport certificates.

The state directory must already contain its initialised `AuthorityFloor.json`
and, optionally, `Authority.lock`. `Initialise` assigns this dedicated directory
to the subordinate container identity; it remains the live persistent state
directory. It does not copy an old floor on each restart. Keep any independent
backup separately and configure the directory's storage quota before use.

```sh
bash Tools/Authority.sh Initialise /Private/AuthorityProfile \
  /Private/AuthorityConfig /Private/AuthorityState \
  "$(cat /tmp/HyperNetPackage/ImageId.txt)" AuthorityNetwork \
  127.0.0.1:28443:8443
bash Tools/Authority.sh Start /Private/AuthorityProfile
bash Tools/Authority.sh Status /Private/AuthorityProfile
bash Tools/Authority.sh Stop /Private/AuthorityProfile
bash Tools/Authority.sh Restart /Private/AuthorityProfile
```

`AuthorityNetwork` is an existing operator-selected container network that
reaches the configured voters. The publication argument is explicit; the example
publishes only to local clients. Choose the deployment's intended ingress address
and port, with its firewall and admission limits, for remote clients. The final
port must equal the broker's configured listen port. Launching a process does
not establish readiness: inspect its status and complete an authenticated status
request before directing clients to it.

All commands for a profile hold the same persistent lifecycle lock, including
initialisation, startup, restart, status and stop. The private lock directory
appends `Lifecycle` to the profile path. Keep it across ordinary operations and
failed initialisation. Remove it only when uninstalling the profile after every
command using that profile has exited.

The broker profile has 512 MiB memory, 64 PIDs, one CPU, a 256-descriptor limit,
a 64 KiB per-file size limit and a 1 MiB log cap. It uses the same rootless
subordinate-only namespace, read-only image, seccomp, Landlock and capability
restrictions as hosting. The state mount is dedicated and persistent. It needs
an external aggregate storage quota; per-file limits cannot impose a directory
quota against a compromised process. Voter storage requires its own independent
quota and backup policy.

The daemon disables core dumping before loading private keys, including dumping
through a piped host crash collector. The launcher additionally sets the core
size limit to zero. The relay and host apply the same process-local protection.

A direct unconfined
`HyperNet authority --config /Config/Authority.json` invocation refuses to start.
The daemon requires the OCI, cgroup, seccomp and Landlock profile and tests denial
canaries before opening its listener. A second broker needs a trusted copy of a
floor from the healthy existing network, then advances its own floor. Do not
delete a floor to make a recovery error disappear.

The private broker state mount contains a small floor file and a lock; authority
history is stored on the voters. An ordinary host uses its separately bounded state mount.
The broker must not share either state or transport credentials with a host.

## Operate membership and hosting

Use an independently built client implementing [Protocol.md](Protocol.md).
Create a device key before requesting its invitation. An administrator submits
the secret's SHA-256 verifier, that device's public key, exact grant mask and
expiry. Transfer the invitation through an independently authenticated channel
and verify the network's CA and identity before redemption. Reissuing an identical
invitation verifier and scope is idempotent; it cannot renew or reopen it.
Revoking or expiring its issuer prevents redemption of unused invitations.

Hosting is a separate owner action. The device records a signed local consent
document for the exact profile and resources, and submits that document's digest
and transport-certificate fingerprint to the authority. The nonvoting host
requires a current authority heartbeat and enforces the intersection of network
grant and local consent. A grant alone cannot widen the local runtime profile.
Version-1 consent enables heartbeat operation only. Version-2 consent can
add the Pages replica service for an exact namespace list and bounded volatile
cache; see [Hosting.md](Hosting.md). This consent covers heartbeat and Pages only.
[Mail](MailStore.md), [transfers](TransferStore.md) and [SSH](SshServices.md) use
separate service identities and consent contracts.

Use separate keys for administrators, readers/authors and hosting services.
Any retained hosting-consent record permanently designates that key as a service
identity, including after withdrawal or removal of its hosting grant. Such a key
cannot use ordinary Pages commands or administration commands, and `Grant` cannot
add administration to it. A hosting grant without administration also designates
a service identity. These checks prevent a host from reading outside its signed
namespace scope through the ordinary reader API. An unconsented administrator
can manage Pages with the initial permission mask; it cannot register hosting
consent until administration is removed.

Federation bridges have a separate permission bit and dual-signed consent.
Invite each side with grant mask 9, using two distinct service keys. A bridge
cannot become an ordinary replica or an administrator, and cannot read native
Pages through client commands. Retained bridge consent preserves that separation
after withdrawal or grant removal. See [Federation.md](Federation.md) for the
bilateral treaty, author opt-in and independent destination approval procedures.

Use `Grant` to replace a device's grant mask and expiry. Use `Revoke` to remove
its membership permanently. Re-enrolment uses a new device key. The final active
administrator cannot be removed or stripped of administration, but keys still
need an independent secure backup. Use `Withdraw` to invalidate hosting consent.
Local emergency withdrawal must stop the host process first and can then notify
the authority; quorum is not required to stop local hosting.

A hosting heartbeat is valid for at most five seconds. The host stops on a
negative reply, known revocation, consent withdrawal, lease expiry or loss of
authority. A partition cannot reveal a remote revocation instantly. There is no
claim of instant global revocation during a partition. New sensitive operations
need fresh authority. Systems need trustworthy wall clocks; broker clocks must
remain within two seconds of the highest recorded observation. A larger backward
step stops authorisation until time is corrected. Client requests have their
separate 60-second past and 30-second future tolerance.

## Publish and replicate Pages

Authors submit bounded `HyperNetPage/1` text into quarantine. Only its author or
an administrator can inspect a pending object. An administrator must explicitly
approve the exact author signature, content digest, namespace, audience and
revision. A pending replacement leaves the previous approved object readable;
rejection discards the pending replacement. Withdrawal removes pending and
published objects and retains an ordered version tombstone. Every mutation uses
the expected current version, so a delayed approval cannot restore withdrawn
content. The complete command and proof formats are in [Protocol.md](Protocol.md).

The authority state contains manifests and replica tickets. Submitted envelopes
and approved proof bundles use separate etcd keys under `Pages/Quarantine/`,
`Pages/Published/` and `Pages/Delivery/`. Blob reads use the revision of the fresh
authority snapshot. Publication, withdrawal and delivery commit their blob
changes and authority state in one compare-and-swap transaction. Hosts never
connect to this database.

Normal discovery and reading expose only current publications whose author and
administrative reviewer are still authorised. Readers verify both retained
signatures and the fresh authoritative publication descriptor. The signed proof
alone is not permission to serve a page. Replies have at most five seconds of
freshness; permission and publication are checked again for each new read.
Downloaded text cannot be recalled from its recipient.

Version-2 hosts poll a fresh namespace-scoped inventory and remove obsolete cache
entries. Replica reads use an explicitly selected host and a short rendezvous
ticket. The host delivers its verified cached bundle through the broker, which
rechecks the reader, host consent and exact current publication both on delivery
and on release to the reader. An unavailable replica does not trigger an origin
fallback. Hosting withdrawal or loss of authority stops new replication work;
old cached approval bytes never authorise a later read.

## Restart and recover

Stop the broker with SIGTERM or SIGINT, preserve its private state, and restart
the same confined installation. The broker checks a fresh quorum read against
its stored cluster identity and revision before accepting requests. Expired,
revoked or withdrawn authority stays denied across process restarts.

Replace a lost voter using the maintained etcd member replacement procedure while
a healthy quorum still exists. Remove the failed member, add and synchronise its
replacement as a learner, then promote it. Preserve the existing cluster identity
and verify health before returning it to service. Do not restart a stale voter
directory as a new independent cluster. Keep voter snapshots and certificate
backups in administrator-controlled encrypted storage with explicit retention.

If the whole quorum is lost, fail closed. Restoring an old snapshot under the
old network identity can resurrect revoked authority and is unsupported. Establish
a new network identity and fresh roots through an independently authenticated
recovery channel, then issue new device-bound invitations. A restored cluster
identity mismatch or revision rollback is a hard failure. A snapshot is an aid
to recovering reviewed non-authoritative data, not permission to restore grants
or author sharing. Fresh network identity requires fresh treaties and explicit
author opt-ins; do not transplant prior sharing permissions or withdrawal floors.
The guard cannot protect against an administrator who replaces both the entire
trusted cluster and every client's trust material and rollback floor.

## Bounds and upgrade contract

The initial authority profile supports 1,024 lifetime member identities and
1,024 lifetime invitation verifiers. Revoked and redeemed records are retained
to prevent resurrection. At most 2,048 unexpired request receipts are retained,
and the serialised authority state cannot exceed 1 MiB. Whichever bound is met
first causes an explicit capacity error. These are small-network limits, not
unlimited federation claims. Increasing or compacting them requires a reviewed
state migration that preserves revocation and invitation history.

Each non-administrative device is limited to 64 outstanding mutation receipts;
64 global slots are reserved for administrative mutations. Read-only commands
do not consume these receipts. A client receiving `RateLimited` must wait for
its outstanding receipts to expire before issuing more mutations.

Pages add at most 256 lifetime page identifiers, 16 per author and four pending
submissions per author. Quarantine and published objects have independent logical
budgets of 4 MiB and 8 MiB. A proof bundle is at most 56 KiB. Replica tickets are
limited to 16 globally, two per reader and four per host, and expire after
15 seconds. These are logical live-data bounds, not an etcd disk quota. Configure
a backend quota and maintained compaction/defragmentation policy for historical
MVCC versions. Deletion does not guarantee secure erasure from storage or backups.

Ingress permits at most 32 simultaneous connections. It bounds headers, envelope
and payload sizes, handshake time, body time and authority execution time. Each
connection serves one command. These bounds limit resource use; they do not make
the service immune to denial of service. Deployment ingress and voter storage
quotas remain necessary. Logs contain readiness and static operational failures,
not invitation secrets or request bodies. There is no third-party telemetry.

The request wire protocol remains version 1. Version 0.7.0 brokers accept state
schemas 1 through 7. Pages and version-2 consent use at least schema 2; successful
Federation commands use at least schema 4, retaining monotonic author sharing
generations and withdrawal tombstones. Missing feature maps default to empty
for earlier schemas. Mail introduces schema 5. Every successful normal mail
command writes schema 5, including MailHosts and MailAddressGet directory reads.
MailAuthorise and MailPolicySync are separate read-only paths. Later Pages,
Federation and hosting operations preserve the newer schema.

Upgrade every authority broker to version 0.4.0 or a subsequently qualified
compatible release before permitting the first successful mail command. This
includes brokers serving only existing Pages or Federation traffic: they share
the authority state and version 0.3.1 cannot read schema 5. Do not use MailHosts
as an early rollout probe while older brokers are running. First update all
brokers with their existing private rollback floors, check ordinary membership
and existing services, then provision the separate mail signer and enable mail.
Configure the same pinned mail authority signer on each broker serving that
network, separately from the Federation signer and all member/mail identities.
[Mail store operation](MailStore.md) describes the private signer file and host
transport trust provisioning. Mail metadata uses the existing exact authority
RBAC key; it requires no ciphertext or inbox prefix.

Transfers and SSH introduce schema 6. Upgrade every broker to 0.5.0 or a
qualified compatible release before any successful transfer or SSH command,
including directory queries. Version 0.4.0 cannot read schema 6. These features
use a separate `serviceSigningKey` identity shared by the compatible brokers,
distinct from member, mail, Federation and native SSH keys. Provision the private
`ServiceSigningKey.json` through `Tools/Authority.sh`. Existing rollback floors
and authority RBAC keys remain in use; file payloads never enter etcd. Later
mail and other feature commands preserve schema 6. Disabling services does not
make a schema-6 namespace readable by older binaries. Native SSH key histories
remain reserved after withdrawal, expiry or revocation, including invitations
that existed before those keys acquired their scoped role.

Applications introduce schema 7. Upgrade every broker to 0.6.0 or a qualified
compatible release before any successful application command, including get and
list. Earlier brokers cannot read schema 7. Applications use existing member
approval and distinct request keys; no new authority signer is required. Other
feature commands preserve schema 7. See [Applications](Applications.md) for
record bounds, key separation and the strict reclamation clock floor.

Extend broker etcd roles to the required Pages and Federation prefixes before
enabling those respective features, and configure the dedicated Federation signer
on each broker serving bilateral agreements. Once schema 5 has been committed,
disabling mail or removing its signer does not restore compatibility with older
executables. Roll forward with a compatible binary. Never delete feature fields,
reset the schema version or restore an older snapshot to attempt a downgrade;
these actions discard security history and conflict with durable rollback floors.

Before upgrading, migrate any administrator key previously used for hosting to
a separate administrator identity without a consent history. Create and verify
that identity using a still-authorised administrator, then remove administration
from the service key. Previously consented administrators fail closed under the
new separation rules. If no independent administrator remains after an upgrade,
use the independent new-network recovery procedure above; modifying authoritative
records outside the protocol is not a supported recovery method.

Unsupported state and wire versions are refused.
Keep `Cargo.lock`, run the documented build and validation before installing an
update, and retain the prior executable for rollback only while its state format
remains compatible. An update must not broaden mounts, endpoints, role or resource
limits without renewed local consent. No automatic updater or certificate issuer
runs inside either daemon.
[Offline packages](Packages.md) describes stopped-profile image switching and
compatible rollback. Version 0.7.0 retains authority schema 7; no state migration
is required solely for that update.

References: [etcd security model](https://etcd.io/docs/v3.6/op-guide/security/),
[etcd runtime reconfiguration](https://etcd.io/docs/v3.6/op-guide/runtime-configuration/),
[etcd disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/),
and [etcd-client API](https://docs.rs/etcd-client/0.20.0/etcd_client/).

## Voter transport failover

Each configured voter has an independent authenticated channel. A failed RPC
moves to the next configured endpoint with the same verified request, bounded
by two seconds per attempt and seven seconds overall. Surviving endpoint reads
remain linearizable and every response retains cluster, revision and time-floor
checks. A lost transaction response is resolved through the existing durable
request receipt or the command's explicit idempotency rules. Application errors,
rollback evidence and invalid state do not trigger transport fallback. Startup
membership and health also try configured alternate endpoints. This supplies
transport failover, not a substitute for quorum or an automatic broker failover.

Private mail optionally uses an independent `mailSigningKey` and public metadata
in the authority key. [Mail store operation](MailStore.md) describes provisioning;
message ciphertext and local delivery receipts never enter authority storage.
