# HyperNet 0.8.0 contracts

These documents define the replacement network contract. Native authority commands
use the four-replica consensus protocol and require three matching executed-result
signatures. The operation manuals describe current requester, serving-recipient,
committee-replacement and recovery workflows. Specification and implementation
alone do not establish deployment qualification. Complete relay coverage, sealed
publication and the remaining platform qualification are separate requirements.

| Contract | Defines |
| --- | --- |
| [Wire](WireContract.md) | Canonical bytes, signature purpose, exact requests, recipient challenges and executed-result proofs |
| [Authority](AuthorityContract.md) | Four-replica Basic HotStuff phases, durable votes/locks, time/freshness and recovery boundaries |
| [Policy](PolicyContract.md) | Independent policies, tiers, recipient continuity, sealed revisions, custody, consent and lifecycle |
| [Runtime](RuntimeContract.md) | Native management, readiness, complete relay coverage, diagnostics and software replacement |

[Wire vectors](WireVectors.json) contain exact canonical bytes and synthetic
certificate acceptance/refusal examples. Their keys are public test fixtures.
[Policy vectors](PolicyVectors.json) define semantic transition obligations;
they are not claims that all operational checks have run.

Four independent choices configure the same runtime:

| Policy | Default | Supported alternative |
| --- | --- | --- |
| Participation | Invitation-only, explicit reader grant | Approved applications or explicitly public host-readable publications |
| Reader privacy | Approved independent relay | Approved organisational relay under its narrower declared guarantee |
| Hosted Pages | Exact approved host-readable content | Bounded sealed publications for authenticated recipient devices |
| Recovery | Offline owner custody, preferably two of three keys | Two of three distinct custodians, without an owner-only bypass |

Explicit capabilities determine authority. Tier numbers, admission, storage
contribution and computational work confer no additional privilege. Configuration
cannot disable signature verification, quorum rules, local consent, user placement
vetoes, exact approval, bounded parsing or client privacy minima.

Each epoch uses a fixed four-member Basic HotStuff committee. The installed
replacement workflow terminates the old epoch and requires its certified handoff,
complete retained state and successor readiness quorum. Its supported boundary
is four fresh authority identities on distinct admitted deployments; it does not
permit arbitrary overlapping membership changes. Missing old authority requires
exceptional new-network recovery and independent acceptance. See
[committee replacement](AuthorityEpochs.md) and [network recovery](NetworkRecovery.md).
Clock-health assurance, persistence and installed interoperability must be
qualified for the actual deployment; signatures alone cannot establish them.

Online client joining requires the same approved relay connector used for all
other reader requests. Offline provisioning alone does not grant membership.
No temporary direct-reader fallback is permitted while a runtime is incomplete.

Policy changes protect future authorised operations. They cannot erase plaintext
already retained by a reader or host. Recovery proposes a new identity requiring
independently authenticated acceptance; threshold signatures do not establish a
globally unique successor. Missing or conflicting authority causes refusal.

Core and Suite carry identical common contract documents and vectors while
remaining independently built products. New implementations must exercise these
contracts through their normal installed interfaces. Unchanged earlier evidence
retains its original software and configuration identity.
