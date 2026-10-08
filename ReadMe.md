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

- [Authority operation](Documentation/Authority.md): trust roots, voters,
  membership, durable state and recovery.
- [Confined hosting](Documentation/Hosting.md): signed consent, isolation,
  resource limits, installation and local withdrawal.
- [Pages](Documentation/Pages.md): inert text and exact-content approval.
- [Authority protocol](Documentation/Protocol.md): independent client interface.
- [Requirements](Documentation/Requirements.md): the broader product scope.

[HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite)
is an independently built and packaged client. The daemon does not depend on it.
This version maintains trusted membership, hosting readiness and manually approved
Pages with scoped replication. Mail, transfers, federation and shell services
remain future capabilities.

The implementation is not yet a qualified production Internet release. The
replication profile assumes trusted administrators and crash faults; it does not
provide Byzantine consensus. Containers share the host kernel. See the operation
manuals for the precise deployment and recovery limits.

Licensed under the [MIT License](Licence.txt).
