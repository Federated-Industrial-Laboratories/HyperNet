# Consented SSH services

An SSH service runs one explicitly accepted session in a dedicated rootless
container. Membership alone gives no shell access. The member, service operator,
service identity, native client key and native host key remain separate identities.
Current authority comes from the configured consensus quorum and retained proof
history; [SshProtocol](SshProtocol.md) defines the canonical objects.

## Supported command profile

The host requires rootless Podman, cgroup v2, seccomp and Landlock ABI6 or newer.
The workload runs as UID1000, `HyperNetService`, inside a subordinate-only user
namespace and its own PID namespace. All capabilities are removed. Its read-only
image contains one operator-selected executable at `/Service/Command`.

OpenSSH disables passwords, PAM, interactive authentication, PTYs, startup files,
environment injection, tunnels, forwarding and remote command selection. The
selected program receives standard input and can return standard output/error.
Its command SHA256, native host key and endpoint are signed by the operator and
bound to the exact admitted runtime manifest. Native host keys and accepted
native user keys retain their identity class permanently, including after expiry.

A member needs explicit capability20 for the service and must prove possession
of its native Ed25519 key. The service operator separately inspects and accepts
the requested purpose, key and expiry. Sessions last at most300seconds, with the
operator choosing a shorter limit if appropriate. There is at most one accepted
unexpired session per service. A different session requires explicit acceptance.

## Package the selected program

`Tools/SshPackage.sh` extends an immutable HyperNet image with trusted local
OpenSSH build products, the selected executable and its licence. It neither
downloads dependencies nor installs them on the host. The qualified server
profile uses OpenSSH10.6p1, built without PAM, SELinux or Kerberos integration:

```sh
./configure --prefix=/OpenSSH --sysconfdir=/Config --libexecdir=/OpenSSH/Libexec \
  --with-privsep-user=HyperNetService --with-privsep-path=/Empty \
  --without-pam --without-selinux --without-kerberos5
make
bash Tools/SshPackage.sh sha256:BASE_IMAGE_ID OpenSSHBuild ServiceCommand ServiceLicence.txt SshPackage 10.6p1
```

Verify the official source archive before building. The packager records copied
library versions, hashes and licence notices; its version comparison is not a
signature verification. Use the resulting immutable image in the signed role8
runtime manifest. Rebuild and qualify security updates as a newly consented
image. Audit the selected program and its input handling before accepting it.

## Establish the service and session

Admit the exact deployment through the installed deployment workflow, including
its operator, role8 service, transport and clock identities, endpoints, limits,
volumes and signed host consent. A currently admitted administrator or member
needs explicit deployment-scoped26 to configure the service. Historical
registrar13 does not replace this permission.

The Suite exposes the workflow under `authority-inspection ssh`. Each online
command takes the independently accepted bootstrap and its SHA256, a private
requester directory, signing key, pinned clock witness and private authority
control socket. Initialize that requester's floor explicitly first. Use a
separate profile for every distinct requester identity.

1. `profile` signs the reviewed deployment profile digest, canonical manifest,
   native host public key, fixed command file, endpoint, purpose and session limit
   with the exact operator key.
2. `register` submits that signed profile with the manager's explicit26 grant.
3. `service` or paged `list` discovers the current profile under member20.
4. `request` submits a new32-byte session ID, purpose, expiry and native client
   key. The selected maintained OpenSSH installation signs the possession proof;
   the private native key is never sent to authority.
5. The operator uses `session` to inspect the exact request and `accept` to grant
   local consent. A member can restrict its own request with `revoke`.
6. `withdraw` permanently withdraws the service. Operator withdrawal and session
   revocation remain available after expiry; they do not restore permissions.

Use `--help` on those commands for their exact required paths and pins. These
local management commands do not create a direct remote-reader route. Remote
reader access requires the qualified scope-safe relay workflow.

## Confined configuration

The installed role8 runtime starts as an inert PID1. Before serving, it validates
the operator's exact local artifact acceptance and obtains a fresh quorum
activation under a manager's explicit26. Activation has its own recipient store;
the SSH service's maintenance requests use its distinct requester store. Ordinary
startup only opens preinitialized state and refuses missing or conflicting floors.

The read-only `/Config` mount contains `Bootstrap.cbor`, `Manifest.cbor`,
`Service.key` (raw32-byte service signing seed), `ServiceConfig.json`,
`SshProfile.cbor`, `SshdConfig`, `AuthorizedKeys` and `SshHostKey`. Every artifact
is included in the exact local acceptance. `AuthorizedKeys` contains only
`restrict ssh-ed25519 BASE64` for the accepted native client key. `SshdConfig`
must exactly match the packaged restrictions with its selected port and address.

```json
{
  "bootstrapFile": "/Config/Bootstrap.cbor",
  "manifestFile": "/Config/Manifest.cbor",
  "profileFile": "/Config/SshProfile.cbor",
  "identityFile": "/Config/Service.key",
  "stateDirectory": "/State/Requester",
  "controlSocket": "/Authority/Control.sock",
  "clockWitnessFile": "/Clock/ClockHealth.cbor",
  "grantId": "SESSION_ID_HEX",
  "nativeUserKey": "NATIVE_ED25519_PUBLIC_KEY_HEX",
  "listen": "0.0.0.0:2222"
}
```

The port and IP family must equal the signed profile endpoint. The private
control socket is mounted alone, with no authority keys or replica state. Its
owned private directory, socket permissions and peer UID are checked. Clock
witnesses are signed by the manifest's pinned monitor for its pinned kernel
boot. `/Authorization` supplies exact live consent, generation and withdrawal.
`/State` is the dedicated private mount for requester, recipient and activation
receipts; it cannot be replaced with a newly empty directory on normal restart.

## Supervision and withdrawal

The supervisor independently verifies each fresh quorum lease before launching
or extending OpenSSH. It durably claims the effect before applying it. Its
`CLOCK_BOOTTIME` timer invokes an explicit async-signal-safe exit handler, so a
blocked event loop cannot keep the namespace alive. PID1 exit makes the kernel
terminate all descendants.
Revocation, lost quorum, an invalid clock or proof, local withdrawal and expiry
stop the service. The installed runtime also enforces the absolute consent
lifetime and supports local emergency withdrawal without a quorum.

The supervisor can read only its fixed configuration, authorization, clock and
control mounts, and write its dedicated private state. Fresh executable wrappers
then reduce access again. The SSH parser retains its native host key and static
restrictions; the forced program loses those keys, authority state, control
socket, clock and authorization mounts. It receives only its bounded `/Work`,
required executable libraries and inherited I/O, with no outbound TCP.

Host or image control lies outside this workload isolation guarantee. It must
not be treated as permission to install or execute unaudited programs. See
[Runtime](Runtime.md) for the installed setup, consent, activation, diagnosis,
stop and withdrawal workflow.

`Tools/SshService.sh` forwards to the installed `HyperNet runtime services`
commands. Use `setup`, `preview`, `consent`, `start`, `status`, `stop`, `withdraw`,
`activation-receipt` and `withdrawal-receipt`; each command's `--help` describes
its exact inputs. Setup imports a private configuration directory containing
`Bootstrap.cbor`, `Manifest.cbor`, `Service.key`, `ServiceConfig.json`,
`SshProfile.cbor`, `SshHostKey`, `SshdConfig` and `AuthorizedKeys`. Start requires
an independently prepared `--activation-request`. It remains in the foreground
while the confined service runs.

The SSH endpoint uses native OpenSSH authentication. Its host key is the exact
native key in the operator-signed `SshProfile.cbor`, verified against
`SshHostKey` before startup. The manifest's generic TLS transport identity is
reserved deployment metadata; it is not a TLS listener or an authentication pin
for the SSH connection. An SSH route must verify the native profile key.
