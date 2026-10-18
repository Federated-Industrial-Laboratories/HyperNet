# Source layout

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

`Source/Main.rs` declares the Rust modules and command entry point. Source files
are grouped by responsibility. Tests stay beside the implementation they exercise.

| Directory | Responsibility |
| --- | --- |
| Authority | Certified requests, proofs, history, streams and recovery |
| Authority/Deployments | Runtime deployment records and activation |
| Authority/Domains | Domain commands and results |
| Authority/Epochs | Epoch transitions and evidence |
| Authority/Governance | Membership, applications, grants, tiers and policy |
| Authority/Recipients | Recipient identity continuity |
| Consensus | Replication, voting, persistence and fresh reads |
| Runtime | Consent, confinement, lifecycle, installation and audit |
| Routing | Private relay connections and route authorisation |
| Hosting | Content stores and federation bridges |
| Pages, Media, Mail, Transfers, Services | Domain services and their contracts |
| Backup, Federation, Sealed | Archives, federation and confidential publication |
| HyperPage | Inert markup, component, form and media schemas |
| Protocol | Trust bootstrap, canonical wire values and signatures |
| Search | Search text contracts |
| Policy, Storage, Transport | Local policy interface, state and transport |

Directory placement does not change Rust module names, wire formats or storage
paths. Explicit module paths in the declaring source file identify each child.
`Tools/NetworkGate.rs` uses the same confinement module as the runtime.
