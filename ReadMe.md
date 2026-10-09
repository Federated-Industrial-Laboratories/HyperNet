# HyperNet

HyperNet provides an initial permissioned network authority and confined hosting
runtime. Device-bound invitations admit members; trusted voting authorities order
grants and revocation. Host owners separately sign exact resource limits and can
withdraw local consent without waiting for the network.

Rust implements transport, bounded protocol handling and durable authority
integration. A narrow Ada/SPARK function evaluates permission intersections and
expiry. A maintained etcd quorum supplies replicated administration. Ordinary
hosts hold no voting or database credentials. TLS 1.3 and device signatures bind
requests to a network identity.

Build with Rust, GNAT, protobuf's `protoc` and C linker tools:

```sh
cargo build --locked --release
bash Tools/PolicyCheck.sh /tmp/HyperNetPolicyProof
bash Tools/Package.sh target/release /tmp/HyperNetPackage
```

Set `GNAT_GCC`, `GNATPROVE` and `PROTOC` when the corresponding tools are outside
`PATH`. Build dependencies are locked in `Cargo.lock`. The confined Linux profile
requires rootless Podman, delegated cgroup v2 limits and Landlock ABI 6 or later.
Unsupported hosting profiles fail closed.

- [Offline packages](Documentation/Packages.md): independently verified installation,
  current-contract image updates and state-preserving removal.
- [Native qualification](Documentation/Qualification.md): measured Linux confinement.
- [Security reporting](Documentation/Security.md): private reporting and trust limits.
- [Authority operation](Documentation/Authority.md): trust roots, voters,
  membership, durable state and recovery.
- [Confined hosting](Documentation/Hosting.md): signed consent, isolation,
  resource limits, installation and local withdrawal.
- [Pages](Documentation/Pages.md): inert components and exact-content approval.
- [HyperPage](Documentation/HyperPage.md): bounded layout, colours and local controls.
- [Federation](Documentation/Federation.md): bilateral treaties, author opt-in,
  separate import review and signed freshness evidence.
- [Confined bridges](Documentation/Bridge.md): dual-signed endpoint consent and
  bounded outward-only transfer between independent networks.
- [Private mail](Documentation/Mail.md): scoped mail identities, one-use device
  key packages and persistent ciphertext only on selected hosts.
- [Mail store operation](Documentation/MailStore.md): consent, bounded storage
  and confinement.
- [Encrypted file transfers](Documentation/Transfers.md): explicit acceptance,
  selected stores, resumable upload and verified delivery.
- [Transfer store operation](Documentation/TransferStore.md): consented resources
  and durable bounded storage.
- [SSH services](Documentation/SshServices.md): separate grants and supervised
  OpenSSH endpoints.
- [Scoped applications](Documentation/Applications.md): distinct page identities,
  bounded delegation and explicit review policy.
- [Authority protocol](Documentation/Protocol.md): independent client interface.
- [Requirements](Documentation/Requirements.md): the broader product scope.

[HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite)
is an independently built and packaged client. The daemon does not depend on it.
This version maintains trusted membership, hosting readiness and manually approved
Pages with scoped replication. Federation transfers exact author-approved native
publications between explicitly consenting networks, with independent destination
review. It grants no shared membership or administration and cannot re-export
foreign imports. Local vetoes apply on fresh authority checks; remote vetoes and
partitions stop new reads after at most five seconds of existing evidence.
Private mail uses independent client end-to-end encryption and explicit selected
storage. Encrypted file transfers require explicit recipient acceptance and
selected storage. Separately consented OpenSSH services run a fixed command in
an isolated account; current grants supervise their whole process lifetime.
Arbitrary full-shell services are outside this initial profile.
Scoped applications use independent request identities for selected native Pages.
Optional review delegation binds exact resources, expiry and operator policy;
manual review remains the default.

The implementation is not yet a qualified production Internet release. The
replication profile assumes trusted administrators and crash faults; it does not
provide Byzantine consensus. Containers share the host kernel. See the operation
manuals for the precise deployment and recovery limits.

Licensed under the [MIT License](Licence.txt).
