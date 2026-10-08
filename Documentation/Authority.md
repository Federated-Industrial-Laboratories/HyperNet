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
`/HyperNet/<network>/Authority`. Keep the root administrative credential outside
the broker container. The broker also checks the cluster's registered voting
membership; three, five or seven voters are accepted. Learners do not count.

The broker uses a dedicated etcd namespace and performs a linearizable read
before every operation. A compare-and-swap transaction checks the exact state
revision before committing. Invitations, grants, revocations, consent and
idempotency receipts therefore share one ordered history. No serializable read,
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
hosting and administration permissions without an expiry. Subsequent membership
renewals are limited to seven days.

Prepare a configuration directory containing `Authority.json`,
`AuthorityCertificate.pem`, `AuthorityKey.pem`, `HostingCa.pem`, `VoterCa.pem`,
`BrokerCertificate.pem` and `BrokerKey.pem`. Only those named files are copied.
Keep CA private keys and etcd root-administrator credentials outside that
directory and outside the broker.

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
The host does not provide shell, content, mail or transfer services in this
protocol version; those require separate protocols and permissions.

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
to recovering reviewed non-authoritative data, not permission to restore grants.
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

Ingress permits at most 32 simultaneous connections. It bounds headers, envelope
and payload sizes, handshake time, body time and authority execution time. Each
connection serves one command. These bounds limit resource use; they do not make
the service immune to denial of service. Deployment ingress and voter storage
quotas remain necessary. Logs contain readiness and static operational failures,
not invitation secrets or request bodies. There is no third-party telemetry.

State schema and wire protocol are version 1. Unsupported versions are refused.
Keep `Cargo.lock`, run the documented build and validation before installing an
update, and retain the prior executable for rollback only while its state format
remains compatible. An update must not broaden mounts, endpoints, role or resource
limits without renewed local consent. No automatic updater or certificate issuer
runs inside either daemon.

References: [etcd security model](https://etcd.io/docs/v3.6/op-guide/security/),
[etcd runtime reconfiguration](https://etcd.io/docs/v3.6/op-guide/runtime-configuration/),
[etcd disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/),
and [etcd-client API](https://docs.rs/etcd-client/0.20.0/etcd_client/).
