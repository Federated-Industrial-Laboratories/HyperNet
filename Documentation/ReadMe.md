# Documentation

[Project](../ReadMe.md) | [Installation](Installation.md) | [Security](Security.md) | [HyperNetSuite](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite)

[Linux 0.9.1 release and downloads](ReleaseNotes.md)

[0.9.1 permission scopes and migration](PermissionScopes.md)

These manuals cover the HyperNet infrastructure: network authority, consenting
hosts, storage, routes and service operation. The separate
[Suite manuals](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/ReadMe.md)
cover the graphical browser, terminal viewer, mail and client commands.

## Choose a starting point

| Goal | Reading order |
| --- | --- |
| Browse or use an existing network | Use the Suite's installation, local preview and network-connection guides. No Core host is required. |
| Operate a new network | [Installation](Installation.md), [security](Security.md), [host requirements](Hosting.md), [authority](Authority.md), [network preparation](RuntimeProvisioning.md), then [runtime](Runtime.md). |
| Offer storage or a service | [Hosting consent](Hosting.md), [service runtime](ServiceRuntime.md), then the relevant service manual below. |
| Write or review Pages | [Pages](Pages.md), [HyperPage format](HyperPage.md), [media](PageMedia.md), then the Suite's authoring and review commands. |
| Integrate another application | [Application access](Applications.md), [protocol overview](Protocol.md), [application protocol](ApplicationProtocol.md), then the exact domain contract. |
| Diagnose or recover a deployment | [Diagnostics](Diagnostics.md), [runtime](Runtime.md), [package updates](UpgradeRecovery.md); use [network recovery](NetworkRecovery.md) only for exceptional authority loss. |

## Operate the network

| Manual | What it covers |
| --- | --- |
| [Installation](Installation.md) | Build and package requirements, installation boundaries and the first-deployment sequence. |
| [Hosting](Hosting.md) | Local operator consent, mandatory confinement, persistent storage and resource selection. |
| [Authority](Authority.md) | Independent trust, separate roles, replicated decisions and retained state. |
| [Network preparation](RuntimeProvisioning.md) | Native identities, certificate requests, pinned peer inputs and clock configuration. |
| [Authority runtime](Runtime.md) | Setup, preview, consent, startup, status, stop, withdrawal, renewal and managed operation. |
| [Service runtime](ServiceRuntime.md) | Import, activate, supervise and recover a separately consented service. |
| [Clock observation](AuthorityClock.md) | Authenticated time sources, signed observations and clock failure handling. |
| [Application streams](ApplicationStreams.md) | Reusable authenticated duplex streams, local SDK binding and finite session lifecycle. |
| [Private routes](PrivateRoutes.md) | Relays, application endpoints, outbound attachments and privacy limits. |
| [Network policies](NetworkPolicies.md) | Participation, privacy, publication and recovery-custody policy changes. |
| [Tier administration](Tiers.md) | Explicit grants and policy history; tier labels do not grant authority. |
| [Operational audit](OperationalAudit.md) | Bounded signed events, retention and separately pinned witnesses. |
| [Diagnostics](Diagnostics.md) | Local redacted snapshots and explicit export without collecting private logs. |
| [Signed packages](Packages.md) | Bundle verification, independently accepted trust, installation and removal. |
| [Package updates](UpgradeRecovery.md) | Signed update targets, retained floors and interrupted installation. |
| [Committee replacement](AuthorityEpochs.md) | Certified handoff from a functioning committee to its successor. |
| [Network recovery](NetworkRecovery.md) | New-network recovery after authority loss and independent client acceptance. |
| [Content backups](Backups.md) | Consented encrypted archives and restoration under current authority. |
| [Qualification](Qualification.md) | Native platform requirements, representative checks and evidence boundaries. |

## Publications, communication and storage

| Feature | Behaviour | Host operation |
| --- | --- | --- |
| Pages | [Publication and review](Pages.md), [declarative markup](HyperPage.md) | [Page store](PageStore.md), [durable content](DurableContent.md) |
| Media | [Static assets and local motion](PageMedia.md) | [Media store](MediaStore.md) |
| Search | [Network catalogues and local search](Search.md) | Indexing requires separate host consent and permission. |
| Federation | [Bilateral sharing and destination review](Federation.md) | [Bridge service](Bridge.md) |
| Mail | [Private mail and recipient-selected storage](Mail.md) | [Mail store](MailStore.md) |
| Transfers | [Recipient-approved encrypted transfer](Transfers.md) | [Transfer store](TransferStore.md) |
| SSH | [Separately consented fixed-command services](SshServices.md) | Uses the service lifecycle and a separately prepared OpenSSH image. |
| Applications | [Scoped credentials and explicit disclosure](Applications.md) | An application grant does not grant host or administrator access. |

Sealed publication commands belong to the
[Suite's confidential-publication guide](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/SealedPages.md).
Storage consent and current recipient permissions still apply; encryption does
not bypass publication review.

## Protocol and implementation reference

These documents define contracts and schemas. Use the operation manuals above
for commands and the current supported workflow; a requirement is not evidence
that a deployment has been tested.

| Reference | Subject |
| --- | --- |
| [Requirements](Requirements.md) | Product requirements and client independence. |
| [Contract index](Contracts.md) | Relationship between the policy, wire, authority and runtime contracts. |
| [Protocol overview](Protocol.md) | Canonical objects, exact retries and domain boundaries. |
| [Wire contract](WireContract.md) | Signed envelopes, field encodings, proofs and bounds. |
| [Authority contract](AuthorityContract.md) | Consensus, fresh reads, durable voting and recovery rules. |
| [Policy contract](PolicyContract.md) | Capabilities, version references and restrictive state. |
| [Runtime contract](RuntimeContract.md) | Management, consent, readiness and connection requirements. |
| [Authority replica](AuthorityReplica.md) | Native signer configuration, persistence and protocol operation. |
| [Mail protocol](MailProtocol.md) | Mailbox manifests, one-use packages, claims and encrypted delivery. |
| [Transfer protocol](TransferProtocol.md) | Offers, acceptance, encrypted chunks and effect receipts. |
| [SSH protocol](SshProtocol.md) | Key possession, fixed-command leases and supervision. |
| [Application protocol](ApplicationProtocol.md) | Application registration, delegation and restrictive grants. |
| [Source layout](SourceLayout.md) | Implementation modules and their responsibilities. |
| [Dependencies](Dependencies.md) | Locked components and licences. |
| [System-library licences](../Packaging/LibraryLicences.md) | Runtime library notices and source accompaniment. |

## Terms and command conventions

| Term | Meaning |
| --- | --- |
| Bootstrap | Independently authenticated initial network identity, policy and appointed authorities. |
| Authority replica | One of the four appointed voters maintaining ordered network state. A storage host has no vote by default. |
| Grant | Explicit permission for named actions and scope. Membership and tier labels are separate. |
| Operator consent | The hardware operator's approval of exact local software, resources, exposure and finite lifetime. |
| Profile | A validated configuration describing one specific client, host, service or route. Profiles are not interchangeable credentials. |
| Receipt | Evidence of an exact recorded result or effect; it is not permission for a new action. |
| Retained floor | Durable minimum accepted history or generation used to reject older state. |
| Sealed Page | A reviewed encrypted publication decrypted by authorised readers. |
| Withdrawal | A durable restrictive decision. Stopping a process alone does not withdraw consent. |

Commands are run from a trusted checkout or installed package unless stated
otherwise. `/Private/...`, example addresses and angle-bracket values are
placeholders, not usable credentials or pre-created files. Substitute the exact
independently verified outputs from the preceding steps. Keep live state outside
the checkout and installation. Protect secret inputs; never put them in issues
or shared command captures.

A process can be running while its quorum, permissions or clock are unavailable.
A historical receipt does not establish present readiness. A timeout does not
prove that an operation failed: retain its exact identity and use its documented
recovery path.
