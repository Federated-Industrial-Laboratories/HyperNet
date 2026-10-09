# Consented SSH services

HyperNet 0.5 supervises one explicitly accepted SSH grant in a dedicated rootless
container. It uses native OpenSSH with a pinned Ed25519 host key. Membership,
operator service identity, native client key, native host key and authority signer
have separate roles. A network invitation never gives shell access.

## Supported profile

The Linux host must support the same rootless Podman, cgroup v2, seccomp and
Landlock requirements as [Hosting](Hosting.md). The service account is
`HyperNetService`, UID 1000 inside a subordinate-only user namespace. All
capabilities are dropped. The read-only image contains one operator-selected
executable at `/Service/Command`; the client cannot replace it with a command
string. Its SHA256 and immutable image digest are part of signed consent.

Each grant binds the member, native Ed25519 client key, account, purpose and
current consent generation. The service operator must explicitly accept it.
Only one accepted, unexpired grant can exist for a service. A grant lasts at most
300 seconds. A new grant or consent requires a new dedicated runtime profile;
there is no automatic renewal into a different privilege or command.

OpenSSH disables passwords, PAM, interactive authentication, PTYs, user startup
files, environment injection, tunnels, agent forwarding, X11 and socket forwarding.
The forced program receives only explicitly supplied standard input and can
return standard output/error. The server ignores a requested remote command.
The supplied Suite closes input by default and escapes terminal output.

The supervisor polls the authority for a signed lease of at most five seconds.
Each lease binds the complete accepted grant and consent digest. A durable,
two-bank 8192-byte file retains observed authority epoch, revision and clock floors.
Withdrawal, revocation, lost quorum, invalid replies or expiry stop the supervisor.
Its PID namespace then destroys every descendant, including detached children.
An independent Podman timeout enforces absolute grant expiry even if the
supervisor is suspended. Local emergency withdrawal works without the authority.

Fresh wrappers progressively restrict filesystem and TCP access. The SSH parser
can read its host key and static restrictions. The forced program cannot read
that key, membership credentials, authority transport credentials or durable
supervisor state, and cannot initiate outbound TCP. It can use only its
bounded volatile `/Work` directory, required libraries and inherited I/O.
This is not permission to execute untrusted programs: operators must audit the
selected executable and its input handling. Operator control of the host or image
remains outside the service isolation boundary.

## Package the fixed command

`Tools/SshPackage.sh` extends an immutable HyperNet base image with trusted local
OpenSSH build products and the explicitly selected command. It never downloads
or installs software on the host. The qualified server profile is OpenSSH 10.6p1,
compiled without PAM, SELinux or Kerberos integration. Obtain its official archive,
verify its published digest and retain the verification record. Build it with:

```sh
./configure --prefix=/OpenSSH --sysconfdir=/Config --libexecdir=/OpenSSH/Libexec \
  --with-privsep-user=HyperNetService --with-privsep-path=/Empty \
  --without-pam --without-selinux --without-kerberos5
make
bash Tools/SshPackage.sh sha256:BASE_IMAGE_ID OpenSSHBuild ServiceCommand ServiceLicence.txt SshPackage 10.6p1
```

Use the resulting immutable `SshPackage/ImageId.txt` and SHA256 of `ServiceCommand`
in consent (omit the image ID's `sha256:` prefix in `imageDigest`). The packager copies required shared libraries and records their
package versions, hashes and notices. It includes OpenSSH and command licences.
The caller must supply trusted build products; the version check is not a
signature verification of those products. Monitor OpenSSH and system-library
security updates, rebuild and qualify a new image, and issue new consent rather
than changing a running image. The Suite selects its maintained OpenSSH client
separately; it does not require this server image or source tree.

## Provision identity, consent and grant

Configure the authority's distinct `serviceSigningKey` as described in
[Authority](Authority.md). Invite a new operator signing identity with
`MEMBER | HOST` (3). Give it a separate mutual TLS credential trusted by the
authority's hosting CA. Do not reuse a Pages, Mail, Transfer, Bridge, administrator,
native SSH or member identity. Keep the native SSH host key separate from all
other signing and transport keys.

A consent specification contains version 1, network, serviceKey, generation,
endpoint (`ssh://service.example:2222/`), literal address (`192.0.2.10:2222`),
canonical `sshHostKey` (`ssh-ed25519 BASE64`), account (`HyperNetService`), purpose,
commandDigest, imageDigest, authorityEndpoint, authorityAddress, authoritySigner,
certificateDigest (SHA256 of mutual TLS leaf DER), memoryBytes, pids, cpuQuota,
cpuPeriod, stateBytes, maximumSessionSeconds and expires. Limits match the
transfer hosting profile: 128 MiB-8 GiB memory, 32-512 PIDs, CPU period 100000,
quota 1000-800000, state 9-64 MiB in 4096-byte units. The separate fixed relay
allowance is 128 MiB, 32 PIDs, 0.5 CPU and 8 MiB volatile storage.

```sh
HyperNetSuite --config Operator.json services consent --spec ServiceSpec.json --output Consent.json
HyperNetSuite --config Operator.json services register --consent Consent.json
HyperNetSuite --config Member.json services request --service-key SERVICE_KEY --authority-key AUTHORITY_KEY --ssh-public-key Client.pub --ssh-binary /opt/OpenSSH/Bin/ssh --identity Client --purpose ExactPurpose --expires UNIX_TIME --output GrantRequest.json
HyperNetSuite --config Operator.json services status --grant-id GRANT_ID
HyperNetSuite --config Operator.json services accept --grant-id GRANT_ID
```

The member supplies a dedicated native private key locally. The Suite uses the
selected OpenSSH installation's sibling `ssh-keygen` to prove possession without
sending the private key to authority. Unaccepted requests do not permanently
reserve native keys. Acceptance rechecks ownership and records the reservation.
Inspect the exact member, native client key, purpose and expiry before acceptance.
Retrieve the accepted grant with `services status`, then save its `grant` object
as `Grant.json`. All files below belong in a new private configuration directory:

- `Consent.json`: the signed consent envelope.
- `Grant.json`: the accepted grant object, not its CLI wrapper.
- `Identity.json`: the operator's private HyperNet signing identity.
- `AuthorityCa.pem`, `Client.pem`, `ClientKey.pem`: the authority CA and operator's
  mutual TLS leaf/chain and private key.
- `SshHostKey`: the private native OpenSSH Ed25519 host key matching consent.
- `SshService.json`: network and runtime settings shown below.

```json
{"network":"NETWORK_HEX","identity":"/Config/Identity.json","consentFile":"/Config/Consent.json","grantFile":"/Config/Grant.json","authorityCa":"/Config/AuthorityCa.pem","certificate":"/Config/Client.pem","privateKey":"/Config/ClientKey.pem","stateDirectory":"/State","listen":"0.0.0.0:2222","relayAddress":"192.0.2.1:8443"}
```

## Start, stop and withdraw

Use new dedicated profile and state directories. The helper creates private
static restrictions and a fixed state file; it rewrites only internal runtime
paths and the fixed relay address. Select an existing egress network that reaches
the exact signed authority address. Bind publication to the intended interface
and consented public port:

```sh
bash Tools/SshService.sh Initialise SshRuntime SshConfig SshState sha256:SSH_IMAGE_ID EgressNetwork 192.0.2.10:2222:2222
bash Tools/SshService.sh Start SshRuntime
bash Tools/SshService.sh Status SshRuntime
bash Tools/SshService.sh Stop SshRuntime
bash Tools/SshService.sh Restart SshRuntime
bash Tools/SshService.sh Withdraw SshRuntime
```

Check status and logs after starting: container creation alone does not prove
current authorisation or a ready SSH listener. Restart reuses only the same
unexpired grant and durable floor. `/Work` is volatile and disappears on stop;
keep application output through explicitly agreed client I/O. The fixed floor
is included in the signed state limit. There are no host home, agent, Docker,
Podman or general host-filesystem mounts.

`Withdraw` writes a permanent local stop marker and kills both service and relay.
It cannot be reversed by `Start` or `Restart`. Also revoke the grant or withdraw
service consent at authority when connectivity is available:

```sh
HyperNetSuite --config Operator.json services revoke --grant-id GRANT_ID
HyperNetSuite --config Operator.json services withdraw --expected-generation 1
```

Retain the private state and withdrawal marker until the grant has expired.
Once stopped permanently, remove the profile's labelled internal network and
retire its credentials according to local policy. Never restore old state into
a different grant or consent. No cross-network SSH authorisation is implied. The [wire contract](SshProtocol.md)
describes independent application integration.
The profile is an initial bounded service interface, not production deployment
certification or a general cluster command scheduler.
