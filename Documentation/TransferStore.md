# Transfer store operation

A transfer store is a separate rootless service with its own Ed25519 identity,
transport certificate, consent and bounded persistent file. Do not use a Pages,
Bridge or administrator identity. Invite the service with `MEMBER | HOST` (3),
redeem it, then register its signed `TransferHostConsent` through the authority. The
permanent service history prevents using that key for Pages or administration.
Withdrawal or expiry of one service role does not erase this history.

## Authority and transport provisioning

Generate a separate authority transfer signing identity in a private
`ServiceSigningKey.json` file and add `serviceSigningKey` to `Authority.json` before
initialising the broker. Every broker must use the current authority state-8
contract; other state versions are refused without migration. To enable the
service on a current network, stop each broker,
provision its separate signing file and update its confined configuration before
restarting. Never
replace a signer silently: existing host consents pin it. `Tools/Authority.sh`
accepts the optional service signer independently of mail and federation and remaps it to
`/Config/ServiceSigningKey.json`. Public transfer metadata uses the existing exact
`/HyperNet/<network>/Authority` RBAC key; no payload prefix is permitted.

Issue a dedicated TLS certificate with `serverAuth` and `clientAuth` usages. The
same service certificate authenticates its public TLS listener and authority
mTLS, but its private key must differ from the Ed25519 service signing key. The
authority's hosting-client trust bundle must trust this issuer. The public
certificate must cover the advertised endpoint's DNS name. Pin the SHA-256 of
the DER leaf certificate and the SHA-256 of the exact PEM root file in consent.
Keep the CA private key outside all runtime directories.

The consent pins the public HTTPS endpoint/address, authority endpoint/address,
authority signing public key, generation, lifetime and worker resources. Endpoint
paths are `/`; redirects, ambient proxies and DNS fallback are disabled. A
fixed-destination relay is the only worker egress. Publish only the transfer TLS
port and restrict management paths independently. A public endpoint may map to
a different internal listener port.

## Install and operate

Prepare a private configuration directory containing `TransferStore.json`,
`Consent.json`, `Identity.json`, `AuthorityCa.pem`, `Ca.pem`, `Client.pem` and
`ClientKey.pem`. `Consent.json` is the exact registered signed consent.
`AuthorityCa.pem` trusts the authority listener; `Ca.pem` is the exact root file
advertised for the transfer listener. Private keys must be owner-readable only.
The launcher sets all paths and the relay address; the input JSON has this shape:

```json
{
  "network": "<64 lowercase hexadecimal digits>",
  "listen": "0.0.0.0:8443",
  "identity": "/Config/Identity.json",
  "consentFile": "/Config/Consent.json",
  "authorityCa": "/Config/AuthorityCa.pem",
  "certificate": "/Config/Client.pem",
  "privateKey": "/Config/ClientKey.pem",
  "caCertificate": "/Config/Ca.pem",
  "stateFile": "/State/TransferState.bin",
  "relayAddress": "127.0.0.1:8443"
}
```

Use the immutable image produced by `Tools/Package.sh`. The profile and dedicated
state directory must both be new; the state directory must be outside the profile.
The external publication port must equal the consented public address port and
the target port must equal the configured listener:

```sh
bash Tools/TransferStore.sh Initialise /Private/TransferProfile /Private/TransferConfig \
  /Private/TransferState sha256:<image-id> TransferEgress 0.0.0.0:29443:8443
bash Tools/TransferStore.sh Start /Private/TransferProfile
bash Tools/TransferStore.sh Status /Private/TransferProfile
bash Tools/TransferStore.sh Stop /Private/TransferProfile
bash Tools/TransferStore.sh Start /Private/TransferProfile
```

The launcher preallocates every block of `TransferState.bin` and assigns it to the
subordinate UID used by `--userns=nomap`. Never change it to the login UID or add
unrelated files. Only this single file is mounted writable. Landlock permits
read/write on that file but denies truncation and directory creation;
`RLIMIT_FSIZE` prevents growth beyond consent. Rootless OCI, read-only root,
seccomp, no capabilities, no-new-privileges, private PID/IPC namespaces and cgroup
limits remain mandatory. No architecture-specific virtual-machine dependency is
introduced. Unsupported kernel or resource profiles fail closed.

Consent `memoryBytes`, `cpuQuota`/`cpuPeriod`, and `pids` bound the worker. Protocol
version 1 additionally consents to a fixed relay overhead of 128 MiB memory,
0.5 CPU and 32 PIDs, with an 8 MiB volatile state limit. These are additional,
not included in the worker numbers. The private state file alone is the signed
persistent `stateBytes` bound. Small rotating runtime logs and private launcher
configuration occupy separate operator-controlled profile storage; they contain
no file payloads or private file names.

Both worker and relay receive an external OCI runtime timeout equal to remaining
consent. Expiry therefore terminates them even if the process is stopped with
SIGSTOP. The worker also checks absolute expiry itself. An expired profile
cannot restart. `Stop` and `Start` preserve acknowledged state while consent is
valid. `Withdraw` persists a local no-restart marker, kills both processes and
retains encrypted state:

```sh
bash Tools/TransferStore.sh Withdraw /Private/TransferProfile
```

Local withdrawal does not claim that the authority or other copies have changed.
Also submit `TransferHostWithdraw` through an authorised client when reachable.
For renewed consent, register the exact next generation and prepare a new private
configuration directory with its signed consent and certificates. Run
`bash Tools/TransferStore.sh Renew /Private/TransferProfile /Private/RenewedConfig`, then
Start. Renew stops both processes and preserves the private state file. It
requires the same network, host identity, authority signer, endpoints, listener
port and state size. New worker limits and transport certificates require fresh
signed consent. Renew explicitly clears a prior local withdrawal. An interrupted
configuration replacement leaves `RenewalPending`; Start refuses until an
operator restores a complete consistent configuration. Never clear that marker
without resolving the interrupted replacement. The standard Initialise command
refuses existing state so it cannot accidentally adopt another transfer file.
Export or erase
retained files only under the owner's storage policy; no automatic destructive
recovery command is provided. See [Encrypted file transfers](Transfers.md) before restoring backups.

Authority TransferHostWithdraw cancels accepted offers on this host. Local
Withdraw retains encrypted storage but does not submit authority cancellation.
A renewed profile cannot revive an expired or cancelled offer.
